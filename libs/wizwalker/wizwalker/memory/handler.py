from __future__ import annotations

import asyncio
import inspect
import json
import struct
import time
from contextlib import nullcontext, suppress
from functools import wraps
from typing import Any
import warnings

from loguru import logger

from wizwalker import (
    HookAlreadyActivated,
    HookHeartbeatFailure,
    HookNotActive,
    HookNotReady,
    MemoryReadError,
    await_cleanup_preserving_cancellation,
    await_critical_operation,
    preserve_cleanup_errors,
    propagate_cleanup_control_flow,
)
from .hooks import (
    ChatHook,
    ChatSendHook,
    ClientHook,
    MouselessCursorMoveHook,
    PlayerHook,
    PlayerStatHook,
    QuestHook,
    RootWindowHook,
    RenderContextHook,
    MovementTeleportHook,
    DropsToggleHook,
    MemoryHook
)
from .memory_reader import MemoryReader, Primitive


def _log_hook_timing(phase: str, started: float, *, outcome: str = "ok", **details):
    payload = {
        "component": "wizwalker",
        "event": "hook_timing",
        "phase": phase,
        "outcome": outcome,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        **details,
    }
    log = getattr(logger, "info", None) or getattr(logger, "debug", None)
    if log is not None:
        log(f"HOOK_TIMING {json.dumps(payload, sort_keys=True, default=str)}")


class _AsyncReentrantLock:
    """Task-reentrant lock for nested aggregate and per-hook lifecycle calls."""

    def __init__(self):
        self._lock = asyncio.Lock()
        self._owner = None
        self._depth = 0

    async def __aenter__(self):
        task = asyncio.current_task()
        if task is self._owner:
            self._depth += 1
            return self
        await self._lock.acquire()
        self._owner = task
        self._depth = 1
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if asyncio.current_task() is not self._owner:
            raise RuntimeError("Hook lifecycle lock released by a non-owner task")
        self._depth -= 1
        if self._depth == 0:
            self._owner = None
            self._lock.release()


# noinspection PyUnresolvedReferences
class HookHandler(MemoryReader):
    """
    Manages hooks
    """

    AUTOBOT_PATTERN = (
        rb"\x48\x89\x5C\x24.\x48\x89\x74\x24.\x48\x89\x7C\x24."
        rb"\x55\x41\x54\x41\x55\x41\x56\x41\x57"
        rb"\x48\x8D\xAC\x24....\x48\x81\xEC...."
        rb"\x48\x8B\x05....\x48\x33\xC4\x48\x89\x85...."
        rb"\x4C\x8B\xF1.......\x80......\x0F\x84...."
    )
    # rounded down
    AUTOBOT_SIZE = 4100
    _HOOK_READINESS_HEARTBEAT_INTERVAL = 10.0
    _AGENT_CORE_HOOK_NAMES = frozenset(
        ("client", "player", "quest", "player_stat", "root_window", "render_context")
    )
    _AGENT_FEATURE_HOOK_NAMES = frozenset(
        ("movement_teleport", "mouseless_cursor", "chat", "chat_send", "dance_game_moves")
    )

    def __init__(self, process: pymem.Pymem, client):
        super().__init__(process)

        self.client = client

        self._autobot_address = None
        self._autobot_lock = None
        self._original_autobot_bytes = b""
        self._autobot_pos = 0

        # TODO: Is this signature correct?
        self._active_hooks: dict[type, MemoryHook] = {}
        self._base_addrs = {}
        self._agent_feature_exports = {}
        self._agent_feature_hook_exports: dict[str, set[str]] = {}
        self._legacy_hook_exports: dict[type, set[str]] = {}

        self._hook_cache = {}
        self._cached_hook_allocations: dict[tuple[type, str], int] = {}
        self._core_hook_heartbeat_task = None
        self._hook_heartbeat_failure_task = None
        self._hook_heartbeat_failure_notified = False
        self._last_core_hook_heartbeat_error = None
        self._close_lock = _AsyncReentrantLock()
        self._closing = False

    def _is_terminal_process_error(self, error: BaseException) -> bool:
        checker = getattr(self._backend, "is_closed_process_error", None)
        return bool(callable(checker) and checker(error))

    def _ensure_hook_activation_allowed(self) -> None:
        if self._closing or bool(getattr(self.client, "_detach_started", False)):
            raise RuntimeError("Hook activation is unavailable after detach has started.")
        if self._hook_heartbeat_failure_notified:
            raise RuntimeError(
                "Hook activation is unavailable after hook health failed; "
                "rediscover the client into a new generation."
            )

    async def _get_open_autobot_address(self, size: int) -> int:
        if self._autobot_pos + size > self.AUTOBOT_SIZE:
            raise RuntimeError("Somehow went over autobot size")

        addr = self._autobot_address + self._autobot_pos
        self._autobot_pos += size

        logger.debug(
            f"Allocating autobot address {addr}; autobot position is now {self._autobot_pos}"
        )
        return addr

    async def _get_autobot_address(self):
        addr = await self.pattern_scan(
            self.AUTOBOT_PATTERN, module="WizardGraphicalClient.exe"
        )
        if addr is None:
            raise RuntimeError("Pattern scan failed for autobot pattern")

        self._autobot_address = addr

    # noinspection PyTypeChecker
    async def _prepare_autobot(self):
        if self._autobot_address is None:
            await self._get_autobot_address()

            # we only need to write back the pattern
            self._original_autobot_bytes = await self.read_bytes(
                self._autobot_address, len(self.AUTOBOT_PATTERN)
            )
            logger.debug(
                f"Got original bytes {self._original_autobot_bytes} from autobot"
            )
            await self.write_bytes(self._autobot_address, b"\x00" * self.AUTOBOT_SIZE)

    async def _rewrite_autobot(self):
        if self._autobot_address is not None:
            compare_bytes = await self.read_bytes(
                self._autobot_address, len(self.AUTOBOT_PATTERN)
            )
            # Give some time for execution point to leave hooks
            await asyncio.sleep(0.5)

            # Only write if the pattern isn't there
            if compare_bytes != self._original_autobot_bytes:
                logger.debug(
                    f"Rewriting bytes {self._original_autobot_bytes} to autobot"
                )
                await self.write_bytes(
                    self._autobot_address, self._original_autobot_bytes
                )

    async def _allocate_autobot_bytes(self, size: int) -> int:
        address = await self._get_open_autobot_address(size)

        return address

    async def close(self):
        async with self._close_lock:
            self._closing = True
            cleanup_errors = []
            local_hooks = [
                (hook_type, hook)
                for hook_type, hook in self._active_hooks.items()
                if not isinstance(hook, str)
            ]
            for hook_type, hook in local_hooks:
                try:
                    await hook.unhook()
                except Exception as error:
                    if self._is_terminal_process_error(error):
                        self._forget_legacy_hook(hook_type, hook)
                    else:
                        cleanup_errors.append(error)
                else:
                    self._forget_legacy_hook(hook_type, hook)

            remote_features = [
                (hook_type, hook_name)
                for hook_type, hook_name in self._active_hooks.items()
                if isinstance(hook_name, str)
                and hook_name in self._agent_feature_hook_exports
            ]
            for hook_type, hook_name in remote_features:
                try:
                    await self._run_cleanup_in_executor(
                        self._backend.deactivate_feature_hook,
                        hook_name,
                    )
                except Exception as error:
                    if self._is_terminal_process_error(error):
                        self._forget_agent_feature_hook(
                            hook_type,
                            hook_name,
                            self._agent_feature_hook_exports.get(hook_name, set()),
                        )
                    else:
                        cleanup_errors.append(error)
                else:
                    self._forget_agent_feature_hook(
                        hook_type,
                        hook_name,
                        self._agent_feature_hook_exports.get(hook_name, set()),
                    )

            remote_core_hooks = [
                (hook_type, hook_name)
                for hook_type, hook_name in self._active_hooks.items()
                if isinstance(hook_name, str)
                and hook_name not in self._agent_feature_hook_exports
            ]
            if remote_core_hooks:
                core_cleanup_confirmed = False
                try:
                    await self._run_cleanup_in_executor(
                        self._backend.deactivate_core_hooks,
                    )
                except Exception as error:
                    if self._is_terminal_process_error(error):
                        core_cleanup_confirmed = True
                    else:
                        cleanup_errors.append(error)
                else:
                    core_cleanup_confirmed = True

                if core_cleanup_confirmed:
                    core_names = {hook_name for _, hook_name in remote_core_hooks}
                    for hook_type, hook_name in remote_core_hooks:
                        if self._active_hooks.get(hook_type) == hook_name:
                            self._active_hooks.pop(hook_type, None)
                    for addr_name, hook_name in list(self._base_addrs.items()):
                        if hook_name in core_names:
                            self._base_addrs.pop(addr_name, None)

            local_cleanup_pending = any(
                not isinstance(hook, str) for hook in self._active_hooks.values()
            )
            if not local_cleanup_pending:
                try:
                    await self._free_cached_hook_allocations()
                except Exception as error:
                    cleanup_errors.append(error)

                # The shared legacy codecave can only be restored after every
                # local jump into it has been removed. Keep its ownership until
                # that write is confirmed so a failed close remains retryable.
                try:
                    await self._rewrite_autobot()
                except Exception as error:
                    if self._is_terminal_process_error(error):
                        self._autobot_pos = 0
                        self._autobot_address = None
                    else:
                        cleanup_errors.append(error)
                else:
                    self._autobot_pos = 0
                    self._autobot_address = None

            has_remote_ownership = any(
                isinstance(hook, str) for hook in self._active_hooks.values()
            )
            if has_remote_ownership:
                self._ensure_core_hook_heartbeat()
            else:
                await self._stop_core_hook_heartbeat()

            if not self._active_hooks:
                self._base_addrs = {}
                self._agent_feature_exports = {}
                self._agent_feature_hook_exports = {}
                self._legacy_hook_exports = {}

            if cleanup_errors:
                primary_error, *secondary_errors = cleanup_errors
                preserve_cleanup_errors(
                    primary_error,
                    secondary_errors,
                    operation="hook handler close",
                )
                raise primary_error

    def _register_cached_hook_allocation(
        self, hook_type: type, cache_name: str, address: int
    ) -> None:
        """Retain ownership of a reusable hook allocation until final close."""
        self._cached_hook_allocations[(hook_type, cache_name)] = address

    async def _free_cached_hook_allocations(self) -> None:
        cleanup_errors = []
        for cache_key, address in list(self._cached_hook_allocations.items()):
            try:
                await self.free(address)
            except Exception as error:
                if self._is_terminal_process_error(error):
                    self._forget_cached_hook_allocation(cache_key, address)
                else:
                    cleanup_errors.append(error)
            else:
                self._forget_cached_hook_allocation(cache_key, address)
        if cleanup_errors:
            primary_error, *secondary_errors = cleanup_errors
            preserve_cleanup_errors(
                primary_error,
                secondary_errors,
                operation="cached hook allocation cleanup",
            )
            raise primary_error

    def _forget_cached_hook_allocation(
        self, cache_key: tuple[type, str], address: int
    ) -> None:
        self._cached_hook_allocations.pop(cache_key, None)
        hook_type, cache_name = cache_key
        hook_cache = self._hook_cache.get(hook_type)
        if hook_cache is not None and hook_cache.get(cache_name) == address:
            hook_cache.pop(cache_name, None)

    async def _check_for_autobot(self):
        if self._autobot_lock is None:
            self._autobot_lock = asyncio.Lock()

        # this is so it isn't prepared more than once at the same time
        async with self._autobot_lock:
            await self._prepare_autobot()

    async def _rollback_unused_legacy_storage(self) -> None:
        """Restore shared legacy storage after pre-publication cancellation."""
        if any(not isinstance(hook, str) for hook in self._active_hooks.values()):
            return
        await self._free_cached_hook_allocations()
        await self._rewrite_autobot()
        self._autobot_pos = 0
        self._autobot_address = None

    def _check_if_hook_active(self, hook_type) -> bool:
        return hook_type in self._active_hooks

    def _get_hook_by_type(self, hook_type) -> MemoryHook:
        return self._active_hooks.get(hook_type, None)

    async def _activate_legacy_hook(
        self, hook_type, hook, exports, *, initialize=None
    ):
        """Install a Python-owned hook without creating an ownership gap.

        ``MemoryHook.hook()`` can allocate exports, write a codecave, and begin
        replacing the target instruction before it raises.  Publish the hook
        object first so failed rollback is still retryable through ``close``.
        A successfully rolled-back object is removed again before the original
        initialization error is propagated.
        """
        self._active_hooks[hook_type] = hook
        self._legacy_hook_exports[hook_type] = set(exports)
        try:
            await hook.hook()
            resolved = {
                addr_name: getattr(hook, attribute_name)
                for addr_name, attribute_name in exports.items()
            }
            self._base_addrs.update(resolved)
            if initialize is not None:
                await initialize()
        except BaseException as activation_error:
            async def rollback():
                await hook.unhook()
                self._forget_legacy_hook(hook_type, hook)

            _, cleanup_error = await await_cleanup_preserving_cancellation(
                rollback(),
                activation_error,
                operation="legacy hook activation",
            )
            if cleanup_error is not None:
                hook_label = getattr(hook_type, "__name__", type(hook).__name__)
                logger.opt(exception=cleanup_error).error(
                    f"Failed to roll back partially installed {hook_label}"
                )
            raise

        return hook

    async def _deactivate_legacy_hook(self, hook_type, exports):
        """Remove a Python-owned hook only after its teardown is confirmed."""
        hook = self._active_hooks[hook_type]
        await hook.unhook()
        self._forget_legacy_hook(hook_type, hook)

    def _forget_legacy_hook(self, hook_type, hook) -> None:
        if self._active_hooks.get(hook_type) is hook:
            self._active_hooks.pop(hook_type, None)
        for addr_name in self._legacy_hook_exports.pop(hook_type, set()):
            self._base_addrs.pop(addr_name, None)

    def _uses_agent_core_hooks(self) -> bool:
        return bool(getattr(self._backend, "supports_core_hooks", False))

    def _uses_agent_feature_hooks(self) -> bool:
        return bool(getattr(self._backend, "supports_feature_hooks", False))

    async def _activate_agent_feature_hook(
        self, hook_type, hook_name: str, exports, *, initialize=None
    ):
        generation_operation = getattr(self._backend, "generation_operation", None)
        with (
            generation_operation()
            if callable(generation_operation)
            else nullcontext()
        ):
            return await self._activate_agent_feature_hook_leased(
                hook_type,
                hook_name,
                exports,
                initialize=initialize,
            )

    async def _activate_agent_feature_hook_leased(
        self, hook_type, hook_name: str, exports, *, initialize=None
    ):
        total_started = time.perf_counter()
        activate_started = time.perf_counter()
        # Publish durable local ownership before the RPC can make the hook live.
        self._active_hooks[hook_type] = hook_name
        self._agent_feature_hook_exports[hook_name] = set(exports)
        try:
            await self.run_in_executor(self._backend.activate_feature_hook, hook_name)
        except BaseException as activation_error:
            async def rollback():
                await self._run_cleanup_in_executor(
                    self._backend.deactivate_feature_hook,
                    hook_name,
                )
                self._forget_agent_feature_hook(hook_type, hook_name, exports)

            _, cleanup_error = await await_cleanup_preserving_cancellation(
                rollback(),
                activation_error,
                operation=f"remote feature hook {hook_name} activation",
            )
            if cleanup_error is not None:
                # The reservation and hook/session owner remain published for
                # exact-generation retry or authoritative process exit.
                logger.opt(exception=cleanup_error).error(
                    f"Failed to roll back remote feature hook {hook_name}"
                )
            _log_hook_timing(
                "feature_hook.activate_rpc",
                activate_started,
                outcome="error",
                hook=hook_name,
            )
            _log_hook_timing(
                "feature_hook.total",
                total_started,
                outcome="error",
                hook=hook_name,
            )
            raise
        _log_hook_timing(
            "feature_hook.activate_rpc", activate_started, hook=hook_name
        )
        self._ensure_core_hook_heartbeat()
        resolved = {}
        try:
            for addr_name, export_name in exports.items():
                export_started = time.perf_counter()
                resolved[addr_name] = await self.run_in_executor(
                    self._backend.read_feature_hook_export, export_name
                )
                _log_hook_timing(
                    "feature_hook.read_export",
                    export_started,
                    hook=hook_name,
                    export=export_name,
                )
            for addr_name, export_name in exports.items():
                self._base_addrs[addr_name] = resolved[addr_name]
                self._agent_feature_exports[addr_name] = export_name
            if initialize is not None:
                await self._await_hook_readiness_with_heartbeats(initialize())
        except BaseException as activation_error:
            _log_hook_timing(
                "feature_hook.read_exports",
                total_started,
                outcome="error",
                hook=hook_name,
            )
            cleanup_started = time.perf_counter()
            async def rollback():
                try:
                    await self._run_cleanup_in_executor(
                        self._backend.deactivate_feature_hook,
                        hook_name,
                    )
                except BaseException as error:
                    if self._is_terminal_process_error(error):
                        self._forget_agent_feature_hook(hook_type, hook_name, exports)
                        if not self._active_hooks:
                            await self._stop_core_hook_heartbeat()
                    raise
                self._forget_agent_feature_hook(hook_type, hook_name, exports)
                if not self._active_hooks:
                    await self._stop_core_hook_heartbeat()

            _, cleanup_error = await await_cleanup_preserving_cancellation(
                rollback(),
                activation_error,
                operation=f"remote feature hook {hook_name} initialization",
            )
            if cleanup_error is not None:
                if not self._is_terminal_process_error(cleanup_error):
                    logger.opt(exception=cleanup_error).error(
                        f"Failed to roll back remote feature hook {hook_name}"
                    )
                _log_hook_timing(
                    "feature_hook.cleanup",
                    cleanup_started,
                    outcome="error",
                    hook=hook_name,
                )
            else:
                _log_hook_timing(
                    "feature_hook.cleanup", cleanup_started, hook=hook_name
                )
            raise
        _log_hook_timing("feature_hook.total", total_started, hook=hook_name)

    def _forget_agent_feature_hook(self, hook_type, hook_name: str, exports):
        if self._active_hooks.get(hook_type) == hook_name:
            self._active_hooks.pop(hook_type, None)
        self._agent_feature_hook_exports.pop(hook_name, None)
        for addr_name in exports:
            self._base_addrs.pop(addr_name, None)
            self._agent_feature_exports.pop(addr_name, None)

    async def _deactivate_agent_feature_hook(self, hook_type, hook_name: str, exports):
        await self._run_cleanup_in_executor(
            self._backend.deactivate_feature_hook,
            hook_name,
        )
        self._forget_agent_feature_hook(hook_type, hook_name, exports)
        if not self._active_hooks:
            await self._stop_core_hook_heartbeat()

    async def _read_feature_hook_export(self, addr_name: str, hook_name: str):
        address = self._base_addrs.get(addr_name)
        if address is None or addr_name not in self._agent_feature_exports:
            raise HookNotActive(hook_name)
        return address

    async def _activate_agent_core_hook(
        self,
        hook_type,
        hook_name: str,
        addr_name: str,
        *,
        wait_for_ready: bool,
        timeout: float,
    ):
        generation_operation = getattr(self._backend, "generation_operation", None)
        with (
            generation_operation()
            if callable(generation_operation)
            else nullcontext()
        ):
            # Publish ownership before the RPC can install the remote hook.
            self._active_hooks[hook_type] = hook_name
            self._base_addrs[addr_name] = hook_name
            try:
                await self.run_in_executor(
                    self._backend.activate_core_hook,
                    hook_name,
                )
                self._ensure_core_hook_heartbeat()
                if wait_for_ready:
                    await self._await_hook_readiness_with_heartbeats(
                        self._wait_for_core_hook(hook_name, timeout)
                    )
            except BaseException as activation_error:
                async def rollback():
                    try:
                        await self._deactivate_agent_core_hook(
                            hook_type, hook_name, addr_name
                        )
                    except BaseException as error:
                        if self._is_terminal_process_error(error):
                            if self._active_hooks.get(hook_type) == hook_name:
                                self._active_hooks.pop(hook_type, None)
                            if self._base_addrs.get(addr_name) == hook_name:
                                self._base_addrs.pop(addr_name, None)
                            if not self._active_hooks:
                                await self._stop_core_hook_heartbeat()
                        raise

                _, cleanup_error = await await_cleanup_preserving_cancellation(
                    rollback(),
                    activation_error,
                    operation=f"remote core hook {hook_name} activation",
                )
                if cleanup_error is not None and not self._is_terminal_process_error(
                    cleanup_error
                ):
                    logger.opt(exception=cleanup_error).error(
                        f"Failed to roll back remote core hook {hook_name}"
                    )
                raise

    async def _deactivate_agent_core_hook(self, hook_type, hook_name: str, addr_name: str):
        await self._run_cleanup_in_executor(
            self._backend.deactivate_core_hook,
            hook_name,
        )
        self._active_hooks.pop(hook_type)
        del self._base_addrs[addr_name]
        if not self._active_hooks:
            await self._stop_core_hook_heartbeat()

    def _ensure_core_hook_heartbeat(self):
        if (
            self._core_hook_heartbeat_task is None
            or self._core_hook_heartbeat_task.done()
        ):
            self._core_hook_heartbeat_task = asyncio.create_task(
                self._core_hook_heartbeat_loop()
            )

    async def _core_hook_heartbeat_loop(self):
        while True:
            await asyncio.sleep(10)
            if not await self._heartbeat_core_hooks_once():
                return

    def _expected_agent_hooks(self, names: frozenset[str]) -> set[str]:
        return {
            hook_name
            for hook_name in self._active_hooks.values()
            if isinstance(hook_name, str) and hook_name in names
        }

    def _validate_hook_heartbeat_response(
        self,
        scope: str,
        response,
        expected_hooks: set[str],
    ) -> None:
        if (
            not isinstance(response, dict)
            or set(response) != {"session_id", "hooks"}
            or not isinstance(response.get("hooks"), list)
        ):
            raise ValueError(
                f"The native agent returned an invalid {scope} hook heartbeat response."
            )
        expected_session = getattr(self._backend, "session_id", None)
        response_session = response.get("session_id")
        if (
            not isinstance(response_session, str)
            or not response_session
            or (
                isinstance(expected_session, str)
                and response_session != expected_session
            )
        ):
            raise ValueError(
                f"The native agent returned a {scope} heartbeat for another session."
            )
        active_hooks = set()
        for item in response["hooks"]:
            if not isinstance(item, dict) or set(item) != {
                "session_id",
                "hook",
                "active",
            }:
                raise ValueError(
                    f"The native agent returned an invalid {scope} hook heartbeat entry."
                )
            hook_name = item.get("hook")
            active = item.get("active")
            item_session = item.get("session_id")
            if (
                not isinstance(hook_name, str)
                or not hook_name
                or active is not True
                or hook_name in active_hooks
                or item_session != response_session
            ):
                raise ValueError(
                    f"The native agent returned an invalid {scope} hook heartbeat entry."
                )
            active_hooks.add(hook_name)
        if active_hooks != expected_hooks:
            raise RuntimeError(
                f"The native agent reported the wrong active {scope} hook set "
                f"(expected {sorted(expected_hooks)!r}, got {sorted(active_hooks)!r})."
            )

    def _notify_hook_heartbeat_failure(self, failure: HookHeartbeatFailure) -> None:
        if self._hook_heartbeat_failure_notified:
            return
        self._hook_heartbeat_failure_notified = True
        callback = getattr(self.client, "_on_hook_heartbeat_failure", None)
        if not callable(callback):
            return

        async def deliver() -> None:
            result = callback(failure)
            if inspect.isawaitable(result):
                await result

        task = asyncio.create_task(deliver())
        self._hook_heartbeat_failure_task = task
        context = getattr(self._backend, "generation_context", None)
        register = getattr(context, "register_generation_task", None)
        if callable(register):
            register(task)

        def consume(completed: asyncio.Task) -> None:
            if self._hook_heartbeat_failure_task is completed:
                self._hook_heartbeat_failure_task = None
            if completed.cancelled():
                return
            error = completed.exception()
            if error is not None:
                logger.opt(exception=error).error(
                    "Native hook heartbeat recovery callback failed"
                )

        task.add_done_callback(consume)

    async def _heartbeat_current_hook_snapshot(self):
        """Renew and validate one stable lifecycle snapshot.

        The public lifecycle lock normally provides stability. Readiness can
        hold that lock indefinitely, so its renewal task calls this directly
        while the owning activation task keeps the snapshot immutable.
        """
        if self._hook_heartbeat_failure_notified:
            return self._last_core_hook_heartbeat_error
        scope = "core"
        expected_core_hooks = self._expected_agent_hooks(
            self._AGENT_CORE_HOOK_NAMES
        )
        expected_feature_hooks = self._expected_agent_hooks(
            self._AGENT_FEATURE_HOOK_NAMES
        )
        expected_hooks = expected_core_hooks
        has_agent_hooks = bool(expected_core_hooks or expected_feature_hooks)
        try:
            if self._uses_agent_core_hooks() and has_agent_hooks:
                response = await self.run_in_executor(
                    self._backend.heartbeat_core_hooks
                )
                self._validate_hook_heartbeat_response(
                    scope, response, expected_hooks
                )
            scope = "feature"
            expected_hooks = expected_feature_hooks
            if self._uses_agent_feature_hooks() and has_agent_hooks:
                response = await self.run_in_executor(
                    self._backend.heartbeat_feature_hooks
                )
                self._validate_hook_heartbeat_response(
                    scope, response, expected_hooks
                )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if self._closing or bool(
                getattr(self.client, "_detach_started", False)
            ):
                return None
            failure = HookHeartbeatFailure(
                scope,
                error,
                expected_hooks=expected_hooks,
            )
            self._last_core_hook_heartbeat_error = failure
            return failure
        self._last_core_hook_heartbeat_error = None
        return None

    async def _renew_hooks_during_readiness(self, stop: asyncio.Event):
        while True:
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._HOOK_READINESS_HEARTBEAT_INTERVAL,
                )
                return None
            except asyncio.TimeoutError:
                pass
            failure = await self._heartbeat_current_hook_snapshot()
            if failure is not None:
                self._notify_hook_heartbeat_failure(failure)
                return failure

    async def _await_hook_readiness_with_heartbeats(self, awaitable):
        """Keep the Rust lease alive while a hook waits for game state."""
        async def capture_outcome(operation):
            try:
                return True, await operation
            except BaseException as error:
                return False, error

        work = asyncio.create_task(capture_outcome(awaitable))
        stop = asyncio.Event()
        renewal = asyncio.create_task(
            capture_outcome(self._renew_hooks_during_readiness(stop))
        )
        primary_error = None

        async def drain_readiness_tasks():
            await asyncio.gather(work, renewal, return_exceptions=True)
            cleanup_errors = []
            for task in (work, renewal):
                if task.cancelled():
                    continue
                succeeded, outcome = task.result()
                if (
                    not succeeded
                    and outcome is not primary_error
                    and (
                        not isinstance(outcome, asyncio.CancelledError)
                        or bool(getattr(outcome, "cleanup_errors", ()))
                    )
                ):
                    cleanup_errors.append(outcome)
            if cleanup_errors:
                first_error, *secondary_errors = cleanup_errors
                preserve_cleanup_errors(
                    first_error,
                    secondary_errors,
                    operation="hook readiness task drain",
                )
                raise first_error

        try:
            done, _ = await asyncio.wait(
                (work, renewal),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if renewal in done:
                renewal_succeeded, failure = renewal.result()
                if not renewal_succeeded:
                    raise failure
                if failure is not None:
                    raise failure
            work_succeeded, outcome = work.result()
            if not work_succeeded:
                raise outcome
            return outcome
        except BaseException as error:
            primary_error = error
            raise
        finally:
            stop.set()
            if not work.done():
                work.cancel()
            if not renewal.done():
                renewal.cancel()
            if primary_error is None:
                await await_critical_operation(
                    drain_readiness_tasks(),
                    operation="hook readiness task drain",
                )
            else:
                await await_cleanup_preserving_cancellation(
                    drain_readiness_tasks(),
                    primary_error,
                    operation="hook readiness task drain",
                )

    async def _heartbeat_core_hooks_once(self):
        if self._closing or bool(getattr(self.client, "_detach_started", False)):
            return False
        failure = None
        async with self._close_lock:
            if self._closing or bool(
                getattr(self.client, "_detach_started", False)
            ):
                return False
            if self._hook_heartbeat_failure_notified:
                return False
            failure = await self._heartbeat_current_hook_snapshot()

        # Application recovery can call close(), which needs the same lock.
        # Always schedule delivery after the complete heartbeat transaction
        # releases lifecycle ownership.
        if failure is not None:
            self._notify_hook_heartbeat_failure(failure)
            return False
        return True

    async def _stop_core_hook_heartbeat(self):
        task = self._core_hook_heartbeat_task
        self._core_hook_heartbeat_task = None
        if task is None:
            return
        task.cancel()
        if task is asyncio.current_task():
            return
        with suppress(asyncio.CancelledError):
            await task

    def cancel_core_hook_heartbeat(self):
        task = self._core_hook_heartbeat_task
        self._core_hook_heartbeat_task = None
        if task is not None:
            task.cancel()

    async def _read_hook_base_addr(self, addr_name: str, hook_name: str):
        addr = self._base_addrs.get(addr_name)
        if addr is None:
            raise HookNotActive(hook_name)
        if self._uses_agent_core_hooks():
            value = await self.run_in_executor(
                self._backend.read_core_hook_base, addr
            )
            if value == 0:
                raise HookNotReady(hook_name)
            return value

        try:
            return await self.read_typed(addr, Primitive.int64)
        except MemoryReadError as error:
            raise HookNotReady(hook_name) from error

    async def _wait_for_core_hook(self, hook_name: str, timeout: float = None):
        async def _wait():
            while True:
                value = await self.run_in_executor(
                    self._backend.read_core_hook_base, hook_name
                )
                if value != 0:
                    return
                await asyncio.sleep(0.5)

        try:
            await asyncio.wait_for(_wait(), timeout)
        except asyncio.TimeoutError as error:
            raise TimeoutError("Hook value took too long") from error

    # wait for an addr to be set and not 0
    async def _wait_for_value(self, address: int, timeout: int = None):
        async def _wait_for_value_task():
            while True:
                try:
                    value = await self.read_typed(address, Primitive.int64)
                    logger.debug(
                        f"Waiting for address {hex(address)}; got value {value}"
                    )
                except MemoryReadError:
                    pass
                else:
                    if value != 0:
                        logger.debug(f"Address {hex(address)} is set")
                        break
                    else:
                        logger.debug(f"Address {hex(address)} is not set yet; sleeping")
                        await asyncio.sleep(0.5)

        try:
            await asyncio.wait_for(_wait_for_value_task(), timeout)
        except asyncio.TimeoutError as error:
            raise TimeoutError("Hook value took too long") from error

    # TODO: make this faster
    async def activate_all_hooks(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        if self._uses_agent_core_hooks():
            generation_operation = getattr(
                self._backend,
                "generation_operation",
                None,
            )
            with (
                generation_operation()
                if callable(generation_operation)
                else nullcontext()
            ):
                return await self._activate_all_hooks_leased(
                    wait_for_ready=wait_for_ready,
                    timeout=timeout,
                )
        return await self._activate_all_hooks_leased(
            wait_for_ready=wait_for_ready,
            timeout=timeout,
        )

    async def _activate_all_hooks_leased(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate all hooks but mouseless

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        total_started = time.perf_counter()
        if self._uses_agent_core_hooks():
            if self._active_hooks:
                duplicate = next(iter(self._active_hooks))
                raise HookAlreadyActivated(duplicate.__name__.removesuffix("Hook"))
            mappings = (
                (PlayerHook, "player", "player_struct"),
                (QuestHook, "quest", "quest_struct"),
                (PlayerStatHook, "player_stat", "player_stat_struct"),
                (ClientHook, "client", "current_client"),
                (RootWindowHook, "root_window", "current_root_window"),
                (RenderContextHook, "render_context", "current_render_context"),
            )
            for hook_type, hook_name, addr_name in mappings:
                self._active_hooks[hook_type] = hook_name
                self._base_addrs[addr_name] = hook_name
            core_started = time.perf_counter()
            try:
                await self.run_in_executor(self._backend.activate_core_hooks)
            except BaseException as activation_error:
                async def rollback_core_rpc():
                    await self._run_cleanup_in_executor(
                        self._backend.deactivate_core_hooks,
                    )
                    for hook_type, hook_name, addr_name in mappings:
                        if self._active_hooks.get(hook_type) == hook_name:
                            self._active_hooks.pop(hook_type, None)
                        if self._base_addrs.get(addr_name) == hook_name:
                            self._base_addrs.pop(addr_name, None)

                await await_cleanup_preserving_cancellation(
                    rollback_core_rpc(),
                    activation_error,
                    operation="remote core hook activation",
                )
                _log_hook_timing(
                    "activate_all.core_rpc", core_started, outcome="error"
                )
                _log_hook_timing(
                    "activate_all.total", total_started, outcome="error", backend="agent"
                )
                raise
            _log_hook_timing("activate_all.core_rpc", core_started)
            try:
                register_started = time.perf_counter()
                _log_hook_timing(
                    "activate_all.register_core_mappings",
                    register_started,
                    hook_count=len(mappings),
                )
                if self._uses_agent_feature_hooks():
                    await self._activate_agent_feature_hook(
                        MovementTeleportHook,
                        "movement_teleport",
                        {"teleport_helper": "teleport_helper"},
                    )
                self._ensure_core_hook_heartbeat()
                if wait_for_ready:
                    async def wait_for_hook(hook_name):
                        ready_started = time.perf_counter()
                        try:
                            await self._wait_for_core_hook(hook_name, timeout)
                        except BaseException:
                            _log_hook_timing(
                                "activate_all.wait_ready",
                                ready_started,
                                outcome="error",
                                hook=hook_name,
                            )
                            raise
                        _log_hook_timing(
                            "activate_all.wait_ready", ready_started, hook=hook_name
                        )

                    wait_tasks = [
                        asyncio.create_task(wait_for_hook(hook_name))
                        for hook_name in (
                            "player",
                            "player_stat",
                            "client",
                            "root_window",
                            "render_context",
                        )
                    ]
                    try:
                        await self._await_hook_readiness_with_heartbeats(
                            asyncio.gather(*wait_tasks)
                        )
                    except BaseException as readiness_error:
                        for task in wait_tasks:
                            task.cancel()
                        await await_cleanup_preserving_cancellation(
                            asyncio.gather(*wait_tasks, return_exceptions=True),
                            readiness_error,
                            operation="aggregate remote hook readiness task drain",
                        )
                        raise
            except BaseException as activation_error:
                cleanup_started = time.perf_counter()
                async def rollback_aggregate():
                    cleanup_errors = []
                    if MovementTeleportHook in self._active_hooks:
                        try:
                            await self._deactivate_agent_feature_hook(
                                MovementTeleportHook,
                                "movement_teleport",
                                ("teleport_helper",),
                            )
                        except BaseException as cleanup_error:
                            cleanup_errors.append(cleanup_error)
                            logger.opt(exception=cleanup_error).error(
                                "Failed to roll back movement teleport after core hook "
                                "activation failed"
                            )
                    try:
                        await self._run_cleanup_in_executor(
                            self._backend.deactivate_core_hooks,
                        )
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
                        logger.opt(exception=cleanup_error).error(
                            "Failed to roll back remote core hooks after activation failed"
                        )
                    else:
                        core_names = {hook_name for _, hook_name, _ in mappings}
                        for hook_type, hook_name, addr_name in mappings:
                            if self._active_hooks.get(hook_type) == hook_name:
                                self._active_hooks.pop(hook_type, None)
                            if self._base_addrs.get(addr_name) == hook_name:
                                self._base_addrs.pop(addr_name, None)
                        for addr_name, hook_name in list(self._base_addrs.items()):
                            if hook_name in core_names:
                                self._base_addrs.pop(addr_name, None)
                    if not self._active_hooks:
                        await self._stop_core_hook_heartbeat()
                    if cleanup_errors:
                        primary_cleanup, *secondary_cleanup = cleanup_errors
                        preserve_cleanup_errors(
                            primary_cleanup,
                            secondary_cleanup,
                            operation="aggregate remote hook rollback",
                        )
                        raise primary_cleanup

                await await_cleanup_preserving_cancellation(
                    rollback_aggregate(),
                    activation_error,
                    operation="aggregate remote hook activation",
                )
                _log_hook_timing(
                    "activate_all.cleanup",
                    cleanup_started,
                    outcome="ok" if not self._active_hooks else "incomplete",
                )
                _log_hook_timing(
                    "activate_all.total", total_started, outcome="error", backend="agent"
                )
                raise
            _log_hook_timing(
                "activate_all.total", total_started, backend="agent"
            )
            return
        legacy_hooks = (
            (
                "player",
                lambda: self.activate_player_hook(wait_for_ready=False),
                self.deactivate_player_hook,
            ),
            ("quest", self.activate_quest_hook, self.deactivate_quest_hook),
            (
                "player_stat",
                lambda: self.activate_player_stat_hook(wait_for_ready=False),
                self.deactivate_player_stat_hook,
            ),
            (
                "client",
                lambda: self.activate_client_hook(wait_for_ready=False),
                self.deactivate_client_hook,
            ),
            (
                "root_window",
                lambda: self.activate_root_window_hook(wait_for_ready=False),
                self.deactivate_root_window_hook,
            ),
            (
                "render_context",
                lambda: self.activate_render_context_hook(wait_for_ready=False),
                self.deactivate_render_context_hook,
            ),
            (
                "movement_teleport",
                lambda: self.activate_movement_teleport_hook(wait_for_ready=False),
                self.deactivate_movement_teleport_hook,
            ),
            (
                "drops_toggle",
                lambda: self.activate_drops_toggle_hook(wait_for_ready=False),
                self.deactivate_drops_toggle_hook,
            ),
        )
        activated_hooks = []
        try:
            for hook_name, activate, deactivate in legacy_hooks:
                hook_started = time.perf_counter()
                await activate()
                activated_hooks.append((hook_name, deactivate))
                _log_hook_timing(
                    "activate_all.legacy_hook", hook_started, hook=hook_name
                )

            if wait_for_ready:
                async def wait_for_value(attribute_name, address):
                    ready_started = time.perf_counter()
                    await self._wait_for_value(address, timeout)
                    _log_hook_timing(
                        "activate_all.wait_ready",
                        ready_started,
                        hook=attribute_name,
                    )

                wait_tasks = []
                for attribute_name in [
                    "player_struct",
                    "player_stat_struct",
                    "current_client",
                    "current_root_window",
                    "current_render_context",
                ]:
                    value = self._base_addrs[attribute_name]
                    wait_tasks.append(
                        asyncio.create_task(wait_for_value(attribute_name, value))
                    )

                try:
                    await asyncio.gather(*wait_tasks)
                except BaseException as readiness_error:
                    for task in wait_tasks:
                        task.cancel()
                    await await_cleanup_preserving_cancellation(
                        asyncio.gather(*wait_tasks, return_exceptions=True),
                        readiness_error,
                        operation="aggregate legacy hook readiness task drain",
                    )
                    raise
        except BaseException as activation_error:
            cleanup_started = time.perf_counter()
            async def rollback_legacy_aggregate():
                cleanup_errors = []
                for hook_name, deactivate in reversed(activated_hooks):
                    try:
                        unlocked_deactivate = getattr(
                            deactivate,
                            "__wrapped__",
                            None,
                        )
                        if callable(unlocked_deactivate):
                            await unlocked_deactivate(self)
                        else:
                            await deactivate()
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
                        logger.opt(exception=cleanup_error).error(
                            f"Failed to roll back {hook_name} after hook activation failed"
                        )
                if cleanup_errors:
                    primary_cleanup, *secondary_cleanup = cleanup_errors
                    preserve_cleanup_errors(
                        primary_cleanup,
                        secondary_cleanup,
                        operation="aggregate legacy hook rollback",
                    )
                    raise primary_cleanup

            await await_cleanup_preserving_cancellation(
                rollback_legacy_aggregate(),
                activation_error,
                operation="aggregate legacy hook activation",
            )
            _log_hook_timing(
                "activate_all.cleanup", cleanup_started, backend="legacy"
            )
            _log_hook_timing(
                "activate_all.total", total_started, outcome="error", backend="legacy"
            )
            raise
        _log_hook_timing("activate_all.total", total_started, backend="legacy")

    async def activate_player_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate player hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(PlayerHook):
            raise HookAlreadyActivated("Player")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                PlayerHook,
                "player",
                "player_struct",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        player_hook = PlayerHook(self)
        await self._activate_legacy_hook(
            PlayerHook,
            player_hook,
            {"player_struct": "player_struct"},
            initialize=(
                lambda: self._wait_for_value(player_hook.player_struct, timeout)
            ) if wait_for_ready else None,
        )

    async def deactivate_player_hook(self):
        """
        Deactivate player hook
        """
        if not self._check_if_hook_active(PlayerHook):
            raise HookNotActive("Player")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                PlayerHook, "player", "player_struct"
            )

        await self._deactivate_legacy_hook(PlayerHook, ("player_struct",))

    async def read_current_player_base(self) -> int:
        """
        Read player base address

        Returns:
            The player base address
        """
        return await self._read_hook_base_addr("player_struct", "Player")

    async def activate_quest_hook(
        self, *, wait_for_ready: bool = False, timeout: float = None
    ):
        """
        Activate quest hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(QuestHook):
            raise HookAlreadyActivated("Quest")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                QuestHook,
                "quest",
                "quest_struct",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        quest_hook = QuestHook(self)
        await self._activate_legacy_hook(
            QuestHook,
            quest_hook,
            {"quest_struct": "cord_struct"},
            initialize=(
                lambda: self._wait_for_value(quest_hook.cord_struct, timeout)
            ) if wait_for_ready else None,
        )

    async def deactivate_quest_hook(self):
        """
        Deactivate quest hook
        """
        if not self._check_if_hook_active(QuestHook):
            raise HookNotActive("Quest")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                QuestHook, "quest", "quest_struct"
            )

        await self._deactivate_legacy_hook(QuestHook, ("quest_struct",))

    async def read_current_quest_base(self) -> int:
        """
        Read quest base address

        Returns:
            The quest base address
        """
        return await self._read_hook_base_addr("quest_struct", "Quest")

    async def activate_player_stat_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate player stat hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(PlayerStatHook):
            raise HookAlreadyActivated("Player stat")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                PlayerStatHook,
                "player_stat",
                "player_stat_struct",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        player_stat_hook = PlayerStatHook(self)
        await self._activate_legacy_hook(
            PlayerStatHook,
            player_stat_hook,
            {"player_stat_struct": "stat_addr"},
            initialize=(
                lambda: self._wait_for_value(player_stat_hook.stat_addr, timeout)
            ) if wait_for_ready else None,
        )

    async def deactivate_player_stat_hook(self):
        """
        Deactivate player stat hook
        """
        if not self._check_if_hook_active(PlayerStatHook):
            raise HookNotActive("Player stat")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                PlayerStatHook, "player_stat", "player_stat_struct"
            )

        await self._deactivate_legacy_hook(
            PlayerStatHook, ("player_stat_struct",)
        )

    async def read_current_player_stat_base(self) -> int:
        """
        Read player stat base address

        Returns:
            The player stat base address
        """
        return await self._read_hook_base_addr("player_stat_struct", "Player stat")

    async def activate_client_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate client hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(ClientHook):
            raise HookAlreadyActivated("Client")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                ClientHook,
                "client",
                "current_client",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        client_hook = ClientHook(self)
        await self._activate_legacy_hook(
            ClientHook,
            client_hook,
            {"current_client": "current_client_addr"},
            initialize=(
                lambda: self._wait_for_value(client_hook.current_client_addr, timeout)
            ) if wait_for_ready else None,
        )

    async def deactivate_client_hook(self):
        """
        Deactivate client hook
        """
        if not self._check_if_hook_active(ClientHook):
            raise HookNotActive("Client")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                ClientHook, "client", "current_client"
            )

        await self._deactivate_legacy_hook(ClientHook, ("current_client",))

    async def read_current_client_base(self) -> int:
        """
        Read cureent client base address

        Returns:
            The current client base address
        """
        return await self._read_hook_base_addr("current_client", "Client")

    async def activate_root_window_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate root window hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(RootWindowHook):
            raise HookAlreadyActivated("Root window")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                RootWindowHook,
                "root_window",
                "current_root_window",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        root_window_hook = RootWindowHook(self)
        await self._activate_legacy_hook(
            RootWindowHook,
            root_window_hook,
            {"current_root_window": "current_root_window_addr"},
            initialize=(
                lambda: self._wait_for_value(
                    root_window_hook.current_root_window_addr, timeout
                )
            ) if wait_for_ready else None,
        )

    async def deactivate_root_window_hook(self):
        """
        Deactivate root window hook
        """
        if not self._check_if_hook_active(RootWindowHook):
            raise HookNotActive("Root window")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                RootWindowHook, "root_window", "current_root_window"
            )

        await self._deactivate_legacy_hook(
            RootWindowHook, ("current_root_window",)
        )

    async def read_current_root_window_base(self) -> int:
        """
        Read current root window base address

        Returns:
            The current root window base address
        """
        return await self._read_hook_base_addr("current_root_window", "Root window")

    async def activate_render_context_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate render context hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(RenderContextHook):
            raise HookAlreadyActivated("Render context")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                RenderContextHook,
                "render_context",
                "current_render_context",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        render_context_hook = RenderContextHook(self)
        await self._activate_legacy_hook(
            RenderContextHook,
            render_context_hook,
            {"current_render_context": "current_render_context_addr"},
            initialize=(
                lambda: self._wait_for_value(
                    render_context_hook.current_render_context_addr, timeout
                )
            ) if wait_for_ready else None,
        )

    async def deactivate_render_context_hook(self):
        """
        Deactivate render context hook
        """
        if not self._check_if_hook_active(RenderContextHook):
            raise HookNotActive("Render context")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                RenderContextHook, "render_context", "current_render_context"
            )

        await self._deactivate_legacy_hook(
            RenderContextHook, ("current_render_context",)
        )

    async def read_current_render_context_base(self) -> int:
        """
        Read current render context base address

        Returns:
            The current render context base address
        """
        return await self._read_hook_base_addr(
            "current_render_context", "Render context"
        )

    async def activate_movement_teleport_hook(
            self, *, wait_for_ready: bool = False, timeout: float = None
    ):
        """
        Activate movement teleport hook

        wait_for_ready is useless for this hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(MovementTeleportHook):
            raise HookAlreadyActivated("Movement teleport")
        if self._uses_agent_feature_hooks():
            return await self._activate_agent_feature_hook(
                MovementTeleportHook,
                "movement_teleport",
                {"teleport_helper": "teleport_helper"},
            )

        await self._check_for_autobot()

        movement_teleport_hook = MovementTeleportHook(self)
        await self._activate_legacy_hook(
            MovementTeleportHook,
            movement_teleport_hook,
            {"teleport_helper": "teleport_helper"},
        )

    async def deactivate_movement_teleport_hook(self):
        """
        Deactivate movement teleport hook
        """
        if not self._check_if_hook_active(MovementTeleportHook):
            raise HookNotActive("Movement teleport")
        if self._uses_agent_feature_hooks():
            return await self._deactivate_agent_feature_hook(
                MovementTeleportHook,
                "movement_teleport",
                ("teleport_helper",),
            )

        await self._deactivate_legacy_hook(
            MovementTeleportHook, ("teleport_helper",)
        )

    async def read_teleport_helper(self) -> int:
        """
        Read teleport helper base address

        Returns:
            The teleport helper base address
        """
        addr = self._base_addrs.get("teleport_helper")
        if addr is None:
            raise HookNotActive("Movement teleport")

        if self._uses_agent_feature_hooks():
            return await self._read_feature_hook_export(
                "teleport_helper", "Movement teleport"
            )

        return addr

    async def activate_drops_toggle_hook(
        self, *, wait_for_ready: bool = False, timeout: float = None
    ):
        
        if self._check_if_hook_active(DropsToggleHook):
            raise HookAlreadyActivated("Drops toggle")

        await self._check_for_autobot()

        drops_toggle_hook = DropsToggleHook(self)
        await self._activate_legacy_hook(
            DropsToggleHook,
            drops_toggle_hook,
            {"disable_drops_bool": "disable_drops_bool"},
        )

    async def deactivate_drops_toggle_hook(self):

        if not self._check_if_hook_active(DropsToggleHook):
            raise HookNotActive("Drops toggle")

        await self._deactivate_legacy_hook(
            DropsToggleHook, ("disable_drops_bool",)
        )

    async def read_disable_drops_bool(self) -> int:
        addr = self._base_addrs.get("disable_drops_bool")

        if addr is None:
            raise HookNotActive("Drops toggle")

        return addr

    # nothing to wait for in this hook
    async def activate_mouseless_cursor_hook(self):
        """
        Activate mouseless cursor hook
        """
        if self._check_if_hook_active(MouselessCursorMoveHook):
            raise HookAlreadyActivated("Mouseless cursor")
        if self._uses_agent_feature_hooks():
            await self._activate_agent_feature_hook(
                MouselessCursorMoveHook,
                "mouseless_cursor",
                {"mouse_position": "mouse_position"},
                initialize=lambda: self.write_mouse_position(0, 0),
            )
            return

        await self._check_for_autobot()

        mouseless_cursor_hook = MouselessCursorMoveHook(self, self._hook_cache)
        await self._activate_legacy_hook(
            MouselessCursorMoveHook,
            mouseless_cursor_hook,
            {"mouse_position": "mouse_pos_addr"},
            initialize=lambda: self.write_mouse_position(0, 0),
        )

    async def deactivate_mouseless_cursor_hook(self):
        """
        Deactivate mouseless cursor hook
        """
        if not self._check_if_hook_active(MouselessCursorMoveHook):
            raise HookNotActive("Mouseless cursor")
        if self._uses_agent_feature_hooks():
            return await self._deactivate_agent_feature_hook(
                MouselessCursorMoveHook,
                "mouseless_cursor",
                ("mouse_position",),
            )

        await self._deactivate_legacy_hook(
            MouselessCursorMoveHook, ("mouse_position",)
        )

    # TODO: 2.0 switch this to a helper object like movement teleport and quest
    async def write_mouse_position(self, x: int, y: int):
        """
        Write mouse position to memory

        Args:
            x: x position of mouse
            y: y position of mouse
        """
        addr = self._base_addrs.get("mouse_position")
        if addr is None:
            raise HookNotActive("Mouseless cursor")

        if self._uses_agent_feature_hooks():
            await self.run_in_executor(
                self._backend.set_feature_mouse_position, x, y
            )
            return

        packed_position = struct.pack("<ii", x, y)

        await self.write_bytes(addr, packed_position)

    async def activate_chat_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """Activate the chat hook to capture incoming directed chat messages.

        The hook fires on every incoming MSG_DirectedChat, extracting the
        sender's GID and message text to persistent export buffers.

        Keyword Args:
            wait_for_ready: Wait for the first message to arrive
            timeout: How long to wait (None for no timeout)
        """
        if self._check_if_hook_active(ChatHook):
            raise HookAlreadyActivated("Chat")
        if self._uses_agent_feature_hooks():
            await self._activate_agent_feature_hook(
                ChatHook,
                "chat",
                {
                    "chat_owner": "chat_owner",
                    "recv_source_gid": "recv_source_gid",
                    "recv_message_buf": "recv_message_buf",
                    "recv_message_len": "recv_message_len",
                    "recv_counter": "recv_counter",
                },
                initialize=(
                    lambda: self._wait_for_value(
                        self._base_addrs["recv_counter"], timeout
                    )
                ) if wait_for_ready else None,
            )
            return

        await self._check_for_autobot()

        chat_hook = ChatHook(self)
        await self._activate_legacy_hook(
            ChatHook,
            chat_hook,
            {
                "chat_owner": "chat_owner_addr",
                "recv_source_gid": "recv_source_gid",
                "recv_message_buf": "recv_message_buf",
                "recv_message_len": "recv_message_len",
                "recv_counter": "recv_counter",
            },
            initialize=(
                lambda: self._wait_for_value(chat_hook.recv_counter, timeout)
            ) if wait_for_ready else None,
        )

    async def deactivate_chat_hook(self):
        """Deactivate the chat hook."""
        if not self._check_if_hook_active(ChatHook):
            raise HookNotActive("Chat")
        if self._uses_agent_feature_hooks():
            return await self._deactivate_agent_feature_hook(
                ChatHook,
                "chat",
                (
                    "chat_owner",
                    "recv_source_gid",
                    "recv_message_buf",
                    "recv_message_len",
                    "recv_counter",
                ),
            )

        await self._deactivate_legacy_hook(
            ChatHook,
            (
                "chat_owner",
                "recv_source_gid",
                "recv_message_buf",
                "recv_message_len",
                "recv_counter",
            ),
        )

    async def read_chat_owner_base(self) -> int:
        """Read the chat owner (chat module) base address.

        Returns:
            The chat module base address
        """
        if self._uses_agent_feature_hooks():
            return await self._read_feature_hook_export("chat_owner", "Chat")
        return await self._read_hook_base_addr("chat_owner", "Chat")

    async def activate_chat_send_hook(self):
        """Activate the chat send hook on the main game loop.

        This hooks the game's main loop so that send_msg() executes
        on the main thread where chat operations are safe.
        """
        if self._check_if_hook_active(ChatSendHook):
            raise HookAlreadyActivated("Chat send")
        if self._uses_agent_feature_hooks():
            return await self._activate_agent_feature_hook(
                ChatSendHook,
                "chat_send",
                {
                    "send_trigger": "send_trigger",
                    "send_struct": "send_struct",
                    "buddy_trigger": "buddy_trigger",
                    "buddy_obj": "buddy_obj",
                },
            )

        await self._check_for_autobot()

        hook = ChatSendHook(self)
        await self._activate_legacy_hook(
            ChatSendHook,
            hook,
            {
                "send_trigger": "send_trigger",
                "send_struct": "send_struct",
                "buddy_trigger": "buddy_trigger",
                "buddy_obj": "buddy_obj",
            },
        )

    async def deactivate_chat_send_hook(self):
        """Deactivate the chat send hook."""
        if not self._check_if_hook_active(ChatSendHook):
            raise HookNotActive("Chat send")
        if self._uses_agent_feature_hooks():
            return await self._deactivate_agent_feature_hook(
                ChatSendHook,
                "chat_send",
                ("send_trigger", "send_struct", "buddy_trigger", "buddy_obj"),
            )

        await self._deactivate_legacy_hook(
            ChatSendHook,
            ("send_trigger", "send_struct", "buddy_trigger", "buddy_obj"),
        )


def _serialize_public_hook_lifecycle(method, *, activating: bool):
    @wraps(method)
    async def serialized(self, *args, **kwargs):
        async with self._close_lock:
            if activating:
                self._ensure_hook_activation_allowed()
            try:
                return await method(self, *args, **kwargs)
            except BaseException as activation_error:
                if activating and not isinstance(activation_error, Exception):
                    await await_cleanup_preserving_cancellation(
                        self._rollback_unused_legacy_storage(),
                        activation_error,
                        operation=f"{method.__name__} legacy storage rollback",
                    )
                raise

    return serialized


# Public hook entry points remain available for compatibility, so serialize
# them centrally with close even when callers bypass Client.activate_hooks().
for _method_name in tuple(vars(HookHandler)):
    if not (
        _method_name == "activate_all_hooks"
        or _method_name.startswith("activate_") and _method_name.endswith("_hook")
        or _method_name.startswith("deactivate_") and _method_name.endswith("_hook")
    ):
        continue
    _method = getattr(HookHandler, _method_name)
    setattr(
        HookHandler,
        _method_name,
        _serialize_public_hook_lifecycle(
            _method,
            activating=_method_name.startswith("activate_"),
        ),
    )
