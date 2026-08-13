from __future__ import annotations

import asyncio
import json
import struct
import time
from contextlib import suppress
from typing import Any
import warnings

from loguru import logger

from wizwalker import HookAlreadyActivated, HookNotActive, HookNotReady, MemoryReadError
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

        self._hook_cache = {}
        self._core_hook_heartbeat_task = None
        self._last_core_hook_heartbeat_error = None

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
        if self._uses_agent_core_hooks():
            feature_names = {
                "movement_teleport",
                "mouseless_cursor",
                "chat",
                "chat_send",
                "dance_game_moves",
            }
            first_error = None
            for hook_type, hook_name in list(self._active_hooks.items()):
                if hook_name in feature_names:
                    try:
                        await self.run_in_executor(
                            self._backend.deactivate_feature_hook, hook_name
                        )
                    except Exception as error:
                        if first_error is None:
                            first_error = error
            if any(hook_name not in feature_names for hook_name in self._active_hooks.values()):
                try:
                    await self.run_in_executor(self._backend.deactivate_core_hooks)
                except Exception as error:
                    if first_error is None:
                        first_error = error
            if first_error is not None:
                self._ensure_core_hook_heartbeat()
                raise first_error
            await self._stop_core_hook_heartbeat()
            self._active_hooks = {}
            self._base_addrs = {}
            self._agent_feature_exports = {}
            return
        for hook in self._active_hooks.values():
            await hook.unhook()

        await self._rewrite_autobot()

        self._active_hooks = {}
        self._autobot_pos = 0
        self._autobot_address = None
        self._base_addrs = {}

    async def _check_for_autobot(self):
        if self._autobot_lock is None:
            self._autobot_lock = asyncio.Lock()

        # this is so it isn't prepared more than once at the same time
        async with self._autobot_lock:
            await self._prepare_autobot()

    def _check_if_hook_active(self, hook_type) -> bool:
        return hook_type in self._active_hooks

    def _get_hook_by_type(self, hook_type) -> MemoryHook:
        return self._active_hooks.get(hook_type, None)

    def _uses_agent_core_hooks(self) -> bool:
        return bool(getattr(self._backend, "supports_core_hooks", False))

    def _uses_agent_feature_hooks(self) -> bool:
        return bool(getattr(self._backend, "supports_feature_hooks", False))

    async def _activate_agent_feature_hook(self, hook_type, hook_name: str, exports):
        total_started = time.perf_counter()
        activate_started = time.perf_counter()
        try:
            await self.run_in_executor(self._backend.activate_feature_hook, hook_name)
        except BaseException:
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
        except Exception:
            _log_hook_timing(
                "feature_hook.read_exports",
                total_started,
                outcome="error",
                hook=hook_name,
            )
            cleanup_started = time.perf_counter()
            await self.run_in_executor(
                self._backend.deactivate_feature_hook, hook_name
            )
            _log_hook_timing(
                "feature_hook.cleanup", cleanup_started, hook=hook_name
            )
            raise
        self._active_hooks[hook_type] = hook_name
        for addr_name, export_name in exports.items():
            self._base_addrs[addr_name] = resolved[addr_name]
            self._agent_feature_exports[addr_name] = export_name
        self._ensure_core_hook_heartbeat()
        _log_hook_timing("feature_hook.total", total_started, hook=hook_name)

    async def _deactivate_agent_feature_hook(self, hook_type, hook_name: str, exports):
        await self.run_in_executor(self._backend.deactivate_feature_hook, hook_name)
        self._active_hooks.pop(hook_type)
        for addr_name in exports:
            self._base_addrs.pop(addr_name, None)
            self._agent_feature_exports.pop(addr_name, None)
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
        await self.run_in_executor(self._backend.activate_core_hook, hook_name)
        self._active_hooks[hook_type] = hook_name
        self._base_addrs[addr_name] = hook_name
        self._ensure_core_hook_heartbeat()
        if wait_for_ready:
            await self._wait_for_core_hook(hook_name, timeout)

    async def _deactivate_agent_core_hook(self, hook_type, hook_name: str, addr_name: str):
        await self.run_in_executor(self._backend.deactivate_core_hook, hook_name)
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
            await self._heartbeat_core_hooks_once()

    async def _heartbeat_core_hooks_once(self):
        try:
            if self._uses_agent_core_hooks():
                await self.run_in_executor(self._backend.heartbeat_core_hooks)
            if self._uses_agent_feature_hooks():
                await self.run_in_executor(self._backend.heartbeat_feature_hooks)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._last_core_hook_heartbeat_error = error
        else:
            self._last_core_hook_heartbeat_error = None

    async def _stop_core_hook_heartbeat(self):
        task = self._core_hook_heartbeat_task
        self._core_hook_heartbeat_task = None
        if task is None:
            return
        task.cancel()
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
            core_started = time.perf_counter()
            try:
                await self.run_in_executor(self._backend.activate_core_hooks)
            except BaseException:
                _log_hook_timing(
                    "activate_all.core_rpc", core_started, outcome="error"
                )
                _log_hook_timing(
                    "activate_all.total", total_started, outcome="error", backend="agent"
                )
                raise
            _log_hook_timing("activate_all.core_rpc", core_started)
            mappings = (
                (PlayerHook, "player", "player_struct"),
                (QuestHook, "quest", "quest_struct"),
                (PlayerStatHook, "player_stat", "player_stat_struct"),
                (ClientHook, "client", "current_client"),
                (RootWindowHook, "root_window", "current_root_window"),
                (RenderContextHook, "render_context", "current_render_context"),
            )
            try:
                register_started = time.perf_counter()
                for hook_type, hook_name, addr_name in mappings:
                    self._active_hooks[hook_type] = hook_name
                    self._base_addrs[addr_name] = hook_name
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

                    await asyncio.gather(
                        *(
                            wait_for_hook(hook_name)
                            for hook_name in (
                                "player",
                                "player_stat",
                                "client",
                                "root_window",
                                "render_context",
                            )
                        )
                    )
            except Exception:
                cleanup_started = time.perf_counter()
                if MovementTeleportHook in self._active_hooks:
                    try:
                        await self.run_in_executor(
                            self._backend.deactivate_feature_hook,
                            "movement_teleport",
                        )
                    finally:
                        self._active_hooks.pop(MovementTeleportHook, None)
                        self._base_addrs.pop("teleport_helper", None)
                        self._agent_feature_exports.pop("teleport_helper", None)
                try:
                    await self.run_in_executor(self._backend.deactivate_core_hooks)
                finally:
                    self._active_hooks = {}
                    self._base_addrs = {}
                    self._agent_feature_exports = {}
                    await self._stop_core_hook_heartbeat()
                _log_hook_timing(
                    "activate_all.cleanup", cleanup_started, outcome="ok"
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
            ("player", lambda: self.activate_player_hook(wait_for_ready=False)),
            ("quest", self.activate_quest_hook),
            ("player_stat", lambda: self.activate_player_stat_hook(wait_for_ready=False)),
            ("client", lambda: self.activate_client_hook(wait_for_ready=False)),
            ("root_window", lambda: self.activate_root_window_hook(wait_for_ready=False)),
            (
                "render_context",
                lambda: self.activate_render_context_hook(wait_for_ready=False),
            ),
            (
                "movement_teleport",
                lambda: self.activate_movement_teleport_hook(wait_for_ready=False),
            ),
            (
                "drops_toggle",
                lambda: self.activate_drops_toggle_hook(wait_for_ready=False),
            ),
        )
        try:
            for hook_name, activate in legacy_hooks:
                hook_started = time.perf_counter()
                await activate()
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

                await asyncio.gather(*wait_tasks)
        except BaseException:
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
        await player_hook.hook()

        self._active_hooks[PlayerHook] = player_hook
        self._base_addrs["player_struct"] = player_hook.player_struct

        if wait_for_ready:
            await self._wait_for_value(player_hook.player_struct, timeout)

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

        hook = self._active_hooks.pop(PlayerHook)
        await hook.unhook()

        del self._base_addrs["player_struct"]

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
        await quest_hook.hook()

        self._active_hooks[QuestHook] = quest_hook
        self._base_addrs["quest_struct"] = quest_hook.cord_struct

        if wait_for_ready:
            await self._wait_for_value(quest_hook.cord_struct, timeout)

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

        hook = self._active_hooks.pop(QuestHook)
        await hook.unhook()

        del self._base_addrs["quest_struct"]

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
        await player_stat_hook.hook()

        self._active_hooks[PlayerStatHook] = player_stat_hook
        self._base_addrs["player_stat_struct"] = player_stat_hook.stat_addr

        if wait_for_ready:
            await self._wait_for_value(player_stat_hook.stat_addr, timeout)

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

        hook = self._active_hooks.pop(PlayerStatHook)
        await hook.unhook()

        del self._base_addrs["player_stat_struct"]

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
        await client_hook.hook()

        self._active_hooks[ClientHook] = client_hook
        self._base_addrs["current_client"] = client_hook.current_client_addr

        if wait_for_ready:
            await self._wait_for_value(client_hook.current_client_addr, timeout)

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

        hook = self._active_hooks.pop(ClientHook)
        await hook.unhook()

        del self._base_addrs["current_client"]

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
        await root_window_hook.hook()

        self._active_hooks[RootWindowHook] = root_window_hook
        self._base_addrs[
            "current_root_window"
        ] = root_window_hook.current_root_window_addr

        if wait_for_ready:
            await self._wait_for_value(
                root_window_hook.current_root_window_addr, timeout
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

        hook = self._active_hooks.pop(RootWindowHook)
        await hook.unhook()

        del self._base_addrs["current_root_window"]

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
        await render_context_hook.hook()

        self._active_hooks[RenderContextHook] = render_context_hook
        self._base_addrs[
            "current_render_context"
        ] = render_context_hook.current_render_context_addr

        if wait_for_ready:
            await self._wait_for_value(
                render_context_hook.current_render_context_addr, timeout
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

        hook = self._active_hooks.pop(RenderContextHook)
        await hook.unhook()

        del self._base_addrs["current_render_context"]

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
        await movement_teleport_hook.hook()

        self._active_hooks[MovementTeleportHook] = movement_teleport_hook
        self._base_addrs[
            "teleport_helper"
        ] = movement_teleport_hook.teleport_helper

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

        hook = self._active_hooks.pop(MovementTeleportHook)
        await hook.unhook()

        del self._base_addrs["teleport_helper"]

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
        await drops_toggle_hook.hook()

        self._active_hooks[DropsToggleHook] = drops_toggle_hook
        self._base_addrs["disable_drops_bool"] = drops_toggle_hook.disable_drops_bool

    async def deactivate_drops_toggle_hook(self):

        if not self._check_if_hook_active(DropsToggleHook):
            raise HookNotActive("Drops toggle")

        drops_toggle_hook = self._active_hooks.pop(DropsToggleHook)
        await drops_toggle_hook.unhook()

        del self._base_addrs["disable_drops_bool"]

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
            )
            await self.write_mouse_position(0, 0)
            return

        await self._check_for_autobot()

        mouseless_cursor_hook = MouselessCursorMoveHook(self, self._hook_cache)
        await mouseless_cursor_hook.hook()

        self._active_hooks[MouselessCursorMoveHook] = mouseless_cursor_hook
        self._base_addrs["mouse_position"] = mouseless_cursor_hook.mouse_pos_addr

        await self.write_mouse_position(0, 0)

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

        hook = self._active_hooks.pop(MouselessCursorMoveHook)
        await hook.unhook()

        del self._base_addrs["mouse_position"]

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
            )
            if wait_for_ready:
                await self._wait_for_value(
                    await self._read_feature_hook_export("recv_counter", "Chat"),
                    timeout,
                )
            return

        await self._check_for_autobot()

        chat_hook = ChatHook(self)
        await chat_hook.hook()

        self._active_hooks[ChatHook] = chat_hook
        self._base_addrs["chat_owner"] = chat_hook.chat_owner_addr
        self._base_addrs["recv_source_gid"] = chat_hook.recv_source_gid
        self._base_addrs["recv_message_buf"] = chat_hook.recv_message_buf
        self._base_addrs["recv_message_len"] = chat_hook.recv_message_len
        self._base_addrs["recv_counter"] = chat_hook.recv_counter

        if wait_for_ready:
            await self._wait_for_value(chat_hook.recv_counter, timeout)

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

        hook = self._active_hooks.pop(ChatHook)
        await hook.unhook()

        del self._base_addrs["chat_owner"]
        del self._base_addrs["recv_source_gid"]
        del self._base_addrs["recv_message_buf"]
        del self._base_addrs["recv_message_len"]
        del self._base_addrs["recv_counter"]

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
        await hook.hook()

        self._active_hooks[ChatSendHook] = hook
        self._base_addrs["send_trigger"] = hook.send_trigger
        self._base_addrs["send_struct"] = hook.send_struct
        self._base_addrs["buddy_trigger"] = hook.buddy_trigger
        self._base_addrs["buddy_obj"] = hook.buddy_obj

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

        hook = self._active_hooks.pop(ChatSendHook)
        await hook.unhook()

        del self._base_addrs["send_trigger"]
        del self._base_addrs["send_struct"]
        del self._base_addrs["buddy_trigger"]
        del self._base_addrs["buddy_obj"]
