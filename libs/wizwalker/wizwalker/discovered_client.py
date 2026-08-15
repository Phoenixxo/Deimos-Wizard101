from __future__ import annotations

import asyncio
import concurrent.futures
import json
import threading
import time
from contextlib import contextmanager
from functools import partial
from typing import Any

from .errors import (
    await_cleanup_preserving_cancellation,
    preserve_cleanup_errors,
    propagate_cleanup_control_flow,
    settle_critical_operation,
)
from .memory import DeimosNativeMemoryBackend, MemoryReader
from .telemetry import (
    ReadOnlyTelemetryReader,
    ReadOnlyTelemetrySnapshot,
)


_INSTANCE_NOT_SUPPLIED = object()


def _log_hook_timing(phase: str, started: float, *, outcome: str = "ok", **details):
    payload = {
        "component": "wizwalker",
        "event": "hook_timing",
        "phase": phase,
        "outcome": outcome,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        **details,
    }
    try:
        from loguru import logger as timing_logger
    except ImportError:
        return
    log = getattr(timing_logger, "info", None) or getattr(timing_logger, "debug", None)
    if log is not None:
        log(f"HOOK_TIMING {json.dumps(payload, sort_keys=True, default=str)}")


class WindowRectangle:
    def __init__(self, x1: int, y1: int, x2: int, y2: int):
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2

    def __iter__(self):
        return iter((self.x1, self.x2, self.y1, self.y2))

    def __repr__(self) -> str:
        return f"<Rectangle ({self.x1}, {self.y1}, {self.x2}, {self.y2})>"

    def center(self) -> tuple[int, int]:
        return (
            ((self.x2 - self.x1) // 2) + self.x1,
            ((self.y2 - self.y1) // 2) + self.y1,
        )

    def scale_to_client(self, parents, factor: float) -> "WindowRectangle":
        x1_sum = self.x1 + sum(parent.x1 for parent in parents)
        y1_sum = self.y1 + sum(parent.y1 for parent in parents)
        return type(self)(
            int(x1_sum * factor),
            int(y1_sum * factor),
            int(((self.x2 - self.x1) * factor) + (x1_sum * factor)),
            int(((self.y2 - self.y1) * factor) + (y1_sum * factor)),
        )


class NativeMouseHandler:
    def __init__(self, client: "DiscoveredClient"):
        self.client = client
        self.click_lock: asyncio.Lock | None = None
        self.click_predelay = 0.02
        self._ref_lock: asyncio.Lock | None = None
        self._ref_count = 0

    async def __aenter__(self):
        if self._ref_lock is None:
            self._ref_lock = asyncio.Lock()
        async with self._ref_lock:
            if self._ref_count == 0:
                await self._activate_mouseless()
            self._ref_count += 1
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._ref_lock is None:
            self._ref_lock = asyncio.Lock()
        async with self._ref_lock:
            self._ref_count -= 1
            if self._ref_count == 0:
                await self._deactivate_mouseless()

    async def _activate_mouseless(self) -> None:
        async with self.client._hook_lifecycle_lock:
            await self._activate_mouseless_locked()

    async def _activate_mouseless_locked(self) -> None:
        handler, created = await self.client._ensure_hook_handler()
        try:
            if "mouseless_cursor" not in handler._active_hooks.values():
                await handler.activate_mouseless_cursor_hook()
        except BaseException as activation_error:
            if created and handler is self.client.hook_handler:
                await await_cleanup_preserving_cancellation(
                    self.client._close_hook_session_locked(),
                    activation_error,
                    operation="mouseless hook activation",
                )
            raise

    async def _deactivate_mouseless(self) -> None:
        async with self.client._hook_lifecycle_lock:
            if (
                self.client.hook_handler is not None
                and "mouseless_cursor" in self.client.hook_handler._active_hooks.values()
            ):
                await self.client.hook_handler.deactivate_mouseless_cursor_hook()

    async def activate_mouseless(self) -> None:
        if self._ref_lock is not None or self._ref_count > 0:
            raise RuntimeError("You can't mix managed mouseless with unmanaged mouseless")
        await self._activate_mouseless()

    async def deactivate_mouseless(self) -> None:
        if self._ref_lock is not None or self._ref_count > 0:
            raise RuntimeError("You can't mix managed mouseless with unmanaged mouseless")
        await self._deactivate_mouseless()

    async def set_mouse_position_to_window(self, window, **kwargs) -> None:
        scaled_rect = await window.scale_to_client()
        await self.set_mouse_position(*scaled_rect.center(), **kwargs)

    async def click_window(self, window, **kwargs) -> None:
        scaled_rect = await window.scale_to_client()
        await self.click(*scaled_rect.center(), **kwargs)

    async def click_window_with_name(self, name: str, **kwargs) -> None:
        possible_windows = await self.client.root_window.get_windows_with_name(name)
        if not possible_windows:
            raise ValueError(f"Window with name {name} not found.")
        if len(possible_windows) > 1:
            raise ValueError(f"Multiple windows with name {name}.")
        await self.click_window(possible_windows[0], **kwargs)

    async def set_mouse_position(
        self,
        x: int,
        y: int,
        *,
        convert_from_client: bool = True,
        use_post: bool = False,
    ):
        if self.client.hook_handler is None:
            raise RuntimeError(
                "Mouseless input is not active. Use the mouse handler as an async context manager."
            )
        screen_x, screen_y = x, y
        if convert_from_client:
            response = await self.client._agent_call(
                self.client._agent_manager.client_to_screen,
                self.client.client_id,
                x,
                y,
            )
            point = response.get("point") if isinstance(response, dict) else None
            if not isinstance(point, dict) or not all(
                isinstance(point.get(axis), int) for axis in ("x", "y")
            ):
                raise ValueError(
                    "The native agent returned an invalid client-to-screen coordinate."
                )
            screen_x, screen_y = point["x"], point["y"]
        result = await self.client.hook_handler.write_mouse_position(screen_x, screen_y)
        await self.client._agent_call(
            partial(
                self.client._agent_manager.move_mouse,
                convert_from_client=convert_from_client,
                use_post=use_post,
            ),
            self.client.client_id,
            x,
            y,
        )
        return result

    async def click(
        self,
        x: int,
        y: int,
        *,
        right_click: bool = False,
        sleep_duration: float = 0.0,
        use_post: bool = False,
    ) -> None:
        if self.click_lock is None:
            self.click_lock = asyncio.Lock()
        async with self.click_lock:
            await self.set_mouse_position(x, y, use_post=use_post)
            await asyncio.sleep(self.click_predelay)
            await self.client._agent_call(
                partial(
                    self.client._agent_manager.click_mouse,
                    right_click=right_click,
                    sleep_duration=sleep_duration,
                    convert_from_client=True,
                    use_post=use_post,
                ),
                self.client.client_id,
                x,
                y,
            )
            await self.set_mouse_position(-100, -100, use_post=use_post)


class DiscoveredClient:
    """Read-only client identity reported by the native helper agent."""

    _HOOK_MEMORY_OBJECT_ATTRIBUTES = (
        "stats",
        "body",
        "duel",
        "quest_position",
        "client_object",
        "root_window",
        "render_context",
        "game_client",
        "social_systems_manager",
        "chat_owner",
        "_teleport_helper",
    )
    _HOOK_MEMORY_CACHE_ATTRIBUTES = (
        "_world_view_window",
        "_character_registry_addr",
        "_quest_client_manager_addr",
        "_je_instruction_forward_backwards",
    )
    _HOOKED_CLIENT_METHODS = frozenset(
        {
            "zone_name",
            "get_base_entity_list",
            "get_base_entities_with_predicate",
            "get_base_entities_with_name",
            "get_base_entities_with_display_name",
            "get_world_view_window",
            "get_template_ids",
            "quest_manager",
            "character_registry",
            "quest_id",
            "goal_id",
            "in_battle",
            "is_loading",
            "is_in_dialog",
            "is_in_npc_range",
            "backpack_space",
            "wait_for_zone_change",
            "current_energy",
            "teleport",
            "_teleport_object",
            "_get_je_instruction_forward_backwards",
        }
    )

    def __init__(
        self,
        agent_manager: Any,
        descriptor: dict[str, Any],
        *,
        generation_context: Any = None,
    ):
        self._agent_manager = agent_manager
        self._running = True
        self._detach_started = False
        self._session_id: str | None = None
        self._session_instance_id: object | None = None
        self._hook_session_id: str | None = None
        self._hook_session_instance_id: object | None = None
        self.hook_handler = None
        self._telemetry_reader: ReadOnlyTelemetryReader | None = None
        self._session_generation = 0
        self._session_cleanup_tasks: set[asyncio.Task[None]] = set()
        self._lifecycle_cleanup_tasks: set[asyncio.Task[None]] = set()
        self._lifecycle_retry_requested = False
        self._pending_session_cleanup_ids: set[str] = set()
        self._pending_session_cleanups: dict[tuple[str, object], str] = {}
        self._session_cleanup_inflight: dict[
            tuple[str, object], concurrent.futures.Future[None]
        ] = {}
        self._last_session_cleanup_error: BaseException | None = None
        self._hook_heartbeat_failure_handler = None
        self._external_cleanup_blockers: set[str] = set()
        # Even when status cannot report an instance ID, every session is bound
        # to a stable local generation token.  An unknown token is never
        # silently rebound when a later recovery reports an identity.
        manager_instance_id = getattr(agent_manager, "cleanup_instance_id", None)
        self._agent_instance_id: object = (
            manager_instance_id
            if isinstance(manager_instance_id, str) and manager_instance_id
            else object()
        )
        self._cleanup_helper_instance_id: object = self._agent_instance_id
        self._terminal_agent_instances: set[object] = set()
        self._agent_generation_changed_with_owned_resources = False
        self._operation_instance_id: object = self._agent_instance_id
        self._generation_fence = None
        self._generation_context = None
        # Session cleanup may be requested by an asyncio task and by the
        # no-running-loop retirement thread at the same time.  This lock only
        # guards the ownership maps; exact session-generation attempts join a
        # shared Future so no state lock is held while a native RPC is blocked.
        self._session_cleanup_lock = threading.Lock()
        self._attach_lock = asyncio.Lock()
        self._hook_attach_lock = asyncio.Lock()
        self._hook_lifecycle_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._mouse_handler = NativeMouseHandler(self)
        self._cache_handler = None
        self._template_ids = None
        self._world_view_window = None
        self._character_registry_addr = None
        self._quest_client_manager_addr = None
        self._je_instruction_forward_backwards = None
        self._update(descriptor)
        if generation_context is not None:
            if (
                not callable(getattr(generation_context, "owns", None))
                or not generation_context.owns(agent_manager)
            ):
                raise ValueError("The generation context belongs to another manager.")
            if generation_context.is_process_quarantined(self):
                generation_context.reconcile_process_identity(self)
            if generation_context.is_process_quarantined(self):
                self.begin_detach()
                raise RuntimeError(
                    "The selected process still owns quarantined hooks from a retired "
                    "helper generation. Wait for exact process exit before hooking it again."
                )
            self._set_agent_instance(generation_context.instance_id)
            self._set_generation_fence(
                generation_context.fence,
                generation_context.generation_token,
                generation_context,
            )
            generation_context.register_client(self)

    def _set_agent_instance(
        self,
        instance_id: object,
        *,
        previous_replaced: bool = False,
    ) -> None:
        """Record the helper generation used for future native sessions."""
        if instance_id is None:
            raise ValueError("The native helper generation token must not be None.")
        previous_instance = self._agent_instance_id
        if previous_instance != instance_id and (
            self._session_id is not None
            or self._hook_session_id is not None
            or self.hook_handler is not None
            or self._pending_session_cleanup_ids
        ):
            self._agent_generation_changed_with_owned_resources = True
        if previous_replaced and previous_instance != instance_id:
            self._terminal_agent_instances.add(previous_instance)
        self._agent_instance_id = instance_id
        self._cleanup_helper_instance_id = instance_id

    def _set_cleanup_helper_instance(
        self,
        instance_id: object,
        *,
        previous_replaced: bool,
    ) -> None:
        if (
            previous_replaced
            and self._agent_instance_id != instance_id
        ):
            self._terminal_agent_instances.add(self._agent_instance_id)
        self._cleanup_helper_instance_id = instance_id

    def _set_generation_fence(
        self,
        fence,
        generation_token: object,
        generation_context=None,
    ) -> None:
        if generation_token is None:
            raise ValueError("The native operation generation token must not be None.")
        self._generation_fence = fence
        self._generation_context = generation_context
        self._operation_instance_id = generation_token
        if self._running and self._session_generation == 0:
            self._operation_instance_id = generation_token

    def _set_hook_heartbeat_failure_handler(self, handler) -> None:
        """Install the application-owned recovery route for this client."""
        self._hook_heartbeat_failure_handler = handler

    async def _on_hook_heartbeat_failure(self, failure) -> None:
        """Deliver one hook-generation failure without coupling WizWalker to Deimos."""
        handler = self._hook_heartbeat_failure_handler
        if handler is not None:
            await handler(self, failure)

    def _call_agent_blocking(self, call, *args, **kwargs):
        fence = self._generation_fence
        if fence is None:
            raise RuntimeError(
                "Native client work requires the manager-scoped generation fence. "
                "Create clients through ClientHandler."
            )
        return fence.call(self._operation_instance_id, call, *args, **kwargs)

    def _call_cleanup_agent_blocking(self, call, *args, **kwargs):
        context = self._generation_context
        expected_helper_instance_id = args[-1] if args else None
        if context is None or expected_helper_instance_id is None:
            raise RuntimeError(
                "Native cleanup requires manager-scoped cleanup admission."
            )
        return context.call_cleanup(
            expected_helper_instance_id,
            call,
            *args,
            **kwargs,
        )

    def _call_live_agent_blocking(self, call, *args, **kwargs):
        self._require_running()
        generation = self._session_generation
        result = self._call_agent_blocking(call, *args, **kwargs)
        if not self._running or generation != self._session_generation:
            raise RuntimeError(
                "The Wizard101 client was retired while its agent operation was running. "
                "Rediscover it before trying again."
            )
        return result

    @contextmanager
    def _live_result_operation(self):
        """Lease this host epoch through synchronous response conversion."""
        self._require_running()
        generation = self._session_generation
        fence = self._generation_fence
        if fence is None:
            raise RuntimeError(
                "Native client work requires the manager-scoped generation fence."
            )
        with fence.operation(self._operation_instance_id):
            yield
            self._require_running()
            if generation != self._session_generation:
                raise RuntimeError(
                    "The Wizard101 client was retired while converting a native result."
                )
            fence.call(self._operation_instance_id, lambda: None)

    @property
    def has_hook_cleanup_ownership(self) -> bool:
        return self.hook_handler is not None or self._hook_session_id is not None

    def _confirm_replaced_process_exit(self) -> None:
        """Release quarantined ownership only after exact identity disappears."""
        hook_handler = self.hook_handler
        if hook_handler is not None:
            hook_handler.cancel_core_hook_heartbeat()
        self.hook_handler = None
        self._hook_session_id = None
        self._hook_session_instance_id = None
        self._session_id = None
        self._session_instance_id = None
        self._telemetry_reader = None
        for attribute in self._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            self.__dict__.pop(attribute, None)
        for attribute in self._HOOK_MEMORY_CACHE_ATTRIBUTES:
            setattr(self, attribute, None)
        with self._session_cleanup_lock:
            self._pending_session_cleanups.clear()
            self._pending_session_cleanup_ids.clear()
            self._last_session_cleanup_error = None

    @property
    def cleanup_complete(self) -> bool:
        """Whether this client has no remaining native teardown obligation."""
        return (
            self.hook_handler is None
            and self._hook_session_id is None
            and self._session_id is None
            and not self._pending_session_cleanup_ids
            and not any(not task.done() for task in self._session_cleanup_tasks)
            and not any(not task.done() for task in self._lifecycle_cleanup_tasks)
            and not self._external_cleanup_blockers
        )

    def retain_cleanup_blocker(self, owner: str) -> None:
        """Prevent hook/session teardown while an external code owner is live."""
        self._external_cleanup_blockers.add(owner)

    def release_cleanup_blocker(self, owner: str) -> None:
        self._external_cleanup_blockers.discard(owner)

    def __getattr__(self, name: str):
        if name not in self._HOOKED_CLIENT_METHODS:
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute {name!r}"
            )

        self._require_running()
        from .client import Client

        return getattr(Client, name).__get__(self, type(self))

    def _update(self, descriptor: dict[str, Any]) -> None:
        self.validate_descriptor(descriptor)
        client_id = descriptor.get("client_id")
        process = descriptor.get("process")
        assert isinstance(client_id, str)
        assert isinstance(process, dict)
        old_identity = self.process.get("identity") if hasattr(self, "process") else None
        old_process_id = self.process_id if hasattr(self, "process_id") else None
        if hasattr(self, "process") and (
            old_identity != process.get("identity")
            or old_process_id != process["pid"]
        ):
            if self.hook_handler is not None or self._hook_session_id is not None:
                self._mark_closed()
                raise RuntimeError(
                    "The native client process identity changed while a hook session "
                    "was owned. Retire it and rediscover the replacement client."
                )
            telemetry_session_id = self._detach_session()
            self._schedule_session_close(telemetry_session_id)
        self.client_id = client_id
        self.process = process
        self.process_id = process["pid"]
        self._is_foreground = bool(descriptor.get("is_foreground", False))
        self.screen_order = int(descriptor.get("screen_order", 0))
        self._running = True
        self._detach_started = False

    @staticmethod
    def validate_descriptor(descriptor: Any) -> None:
        """Validate a complete discovery generation before publishing any of it."""
        if not isinstance(descriptor, dict):
            raise ValueError(
                "The native agent returned an invalid client discovery descriptor."
            )
        client_id = descriptor.get("client_id")
        process = descriptor.get("process")
        screen_order = descriptor.get("screen_order")
        if (
            not isinstance(client_id, str)
            or not client_id
            or not isinstance(process, dict)
            or not isinstance(process.get("pid"), int)
            or isinstance(process.get("pid"), bool)
            or process["pid"] <= 0
            or not isinstance(descriptor.get("is_foreground"), bool)
            or not isinstance(screen_order, int)
            or isinstance(screen_order, bool)
            or screen_order < 0
        ):
            raise ValueError(
                "The native agent returned an invalid client discovery descriptor."
            )
        identity = process.get("identity")
        if (
            not isinstance(identity, dict)
            or identity.get("pid") != process["pid"]
            or isinstance(identity.get("pid"), bool)
            or not isinstance(identity.get("creation_time_100ns"), str)
            or not identity["creation_time_100ns"]
            or not isinstance(identity.get("executable_path"), str)
            or not identity["executable_path"]
        ):
            raise ValueError(
                "The native agent returned a client without a matching process identity."
            )

    def begin_detach(self) -> None:
        """Make this generation externally unusable while teardown is in flight."""
        if self._detach_started:
            return
        self._detach_started = True
        self._running = False
        self._is_foreground = False
        self._session_generation += 1
        if self.hook_handler is not None:
            try:
                self.hook_handler.cancel_core_hook_heartbeat()
            except Exception as error:
                self._last_session_cleanup_error = error
        # Do not leave a path from the public client object to cached addresses
        # or memory-object wrappers while hook cleanup remains privately owned.
        for attribute in self._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            self.__dict__.pop(attribute, None)
        for attribute in self._HOOK_MEMORY_CACHE_ATTRIBUTES:
            setattr(self, attribute, None)
        self._template_ids = None
        self._cache_handler = None

    def _mark_closed(self) -> None:
        self.begin_detach()
        telemetry_session_id = self._detach_session()
        self._schedule_session_close(telemetry_session_id)
        if self.hook_handler is None:
            hook_session_id = self._detach_hook_session()
            self._schedule_session_close(hook_session_id)
        else:
            self._schedule_lifecycle_close()

    def _has_live_process_session(self) -> bool:
        self._require_running()
        session_ids = tuple(
            session_id
            for session_id in (self._hook_session_id, self._session_id)
            if session_id is not None
        )
        for session_id in session_ids:
            try:
                status = self._call_agent_blocking(
                    self._agent_manager.process_status, session_id
                )
            except Exception as error:
                if getattr(error, "code", None) in {
                    "process_exited",
                    "process_not_found",
                    "session_not_found",
                }:
                    continue
                raise
            if isinstance(status, dict) and status.get("state") == "open":
                return True
        return False

    def is_running(self) -> bool:
        return self._running

    def _require_running(self) -> None:
        if not self._running:
            raise RuntimeError(
                "This Wizard101 client belongs to a retired native session generation. "
                "Rediscover it before issuing agent operations."
            )

    def _window_state(self) -> dict[str, Any]:
        self._require_running()
        response = self._call_live_agent_blocking(
            self._agent_manager.client_window_state, self.client_id
        )
        if not isinstance(response, dict):
            raise ValueError("The native agent returned an invalid window state response.")
        return response

    @property
    def title(self) -> str:
        with self._live_result_operation():
            title = self._window_state().get("title")
            if not isinstance(title, str):
                raise ValueError("The native agent returned an invalid window title.")
            return title

    @title.setter
    def title(self, value: str) -> None:
        self._require_running()
        self._call_live_agent_blocking(
            self._agent_manager.set_client_window_title, self.client_id, value
        )

    @property
    def is_foreground(self) -> bool:
        with self._live_result_operation():
            try:
                is_foreground = self._window_state().get("is_foreground")
            except Exception as error:
                if (
                    getattr(error, "code", None)
                    in {"client_not_found", "window_not_found"}
                    and self._has_live_process_session()
                ):
                    return self._is_foreground
                raise
            if not isinstance(is_foreground, bool):
                raise ValueError("The native agent returned an invalid foreground state.")
            self._is_foreground = is_foreground
            return is_foreground

    @is_foreground.setter
    def is_foreground(self, value: bool) -> None:
        if value:
            with self._live_result_operation():
                response = self._call_live_agent_blocking(
                    self._agent_manager.focus_client_window, self.client_id
                )
                if (
                    not isinstance(response, dict)
                    or response.get("is_foreground") is not True
                ):
                    raise RuntimeError(
                        "The native agent could not focus this Wizard101 client."
                    )
                self._is_foreground = True

    @property
    def window_rectangle(self) -> WindowRectangle:
        with self._live_result_operation():
            rectangle = self._window_state().get("rectangle")
            if not isinstance(rectangle, dict) or not all(
                isinstance(rectangle.get(edge), int)
                for edge in ("left", "top", "right", "bottom")
            ):
                raise ValueError("The native agent returned an invalid window rectangle.")
            return WindowRectangle(
                rectangle["right"],
                rectangle["top"],
                rectangle["left"],
                rectangle["bottom"],
            )

    @property
    def overlay_geometry(self) -> dict[str, int | bool]:
        with self._live_result_operation():
            state = self._window_state()
            origin = state.get("client_origin")
            size = state.get("client_size")
            if not isinstance(origin, dict) or not all(
                isinstance(origin.get(axis), int)
                and not isinstance(origin.get(axis), bool)
                for axis in ("x", "y")
            ):
                raise ValueError("The native agent returned an invalid client-area origin.")
            if not isinstance(size, dict) or not all(
                isinstance(size.get(axis), int)
                and not isinstance(size.get(axis), bool)
                for axis in ("width", "height")
            ):
                raise ValueError("The native agent returned an invalid client-area size.")
            if size["width"] <= 0 or size["height"] <= 0:
                raise ValueError("The native agent returned an empty client area.")
            return {
                "left": origin["x"],
                "top": origin["y"],
                "width": size["width"],
                "height": size["height"],
                "is_foreground": bool(state.get("is_foreground", False)),
            }

    async def _agent_call(self, call, *args):
        self._require_running()
        session_generation = self._session_generation
        result = await asyncio.get_running_loop().run_in_executor(
            None, partial(self._call_agent_blocking, call, *args)
        )
        if not self._running or session_generation != self._session_generation:
            raise RuntimeError(
                "The Wizard101 client was retired while its agent operation was running. "
                "Rediscover it before trying again."
            )
        return result

    async def send_key(self, key, seconds: float = 0):
        virtual_key = int(getattr(key, "value", key))
        return await self._agent_call(
            self._agent_manager.send_key,
            self.client_id,
            virtual_key,
            seconds,
        )

    async def send_hotkey(self, modifiers, key):
        modifier_values = [int(getattr(modifier, "value", modifier)) for modifier in modifiers]
        virtual_key = int(getattr(key, "value", key))
        return await self._agent_call(
            self._agent_manager.send_hotkey,
            self.client_id,
            modifier_values,
            virtual_key,
        )

    def _expected_identity(self) -> dict[str, Any]:
        identity = self.process.get("identity")
        if (
            not isinstance(identity, dict)
            or isinstance(identity.get("pid"), bool)
            or identity.get("pid") != self.process_id
            or not isinstance(identity.get("creation_time_100ns"), str)
            or not identity["creation_time_100ns"]
            or not isinstance(identity.get("executable_path"), str)
            or not identity["executable_path"]
        ):
            raise ValueError(
                "The native agent returned a client without a matching process identity. "
                "Rediscover the client before opening a read-only telemetry session."
            )
        return identity

    def _detach_session(self) -> str | None:
        """Invalidate the current session before any potentially blocking cleanup."""
        self._session_generation += 1
        session_id = self._session_id
        session_instance_id = self._session_instance_id
        self._session_id = None
        self._session_instance_id = None
        self._telemetry_reader = None
        if session_id is not None:
            self._register_session_cleanup(
                session_id,
                kind="telemetry",
                instance_id=session_instance_id,
            )
        return session_id

    def _detach_hook_session(self) -> str | None:
        session_id = self._hook_session_id
        session_instance_id = self._hook_session_instance_id
        self._hook_session_id = None
        self._hook_session_instance_id = None
        if session_id is not None:
            self._register_session_cleanup(
                session_id,
                kind="hook",
                instance_id=session_instance_id,
            )
        hook_handler = self.hook_handler
        self.hook_handler = None
        for attribute in self._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            self.__dict__.pop(attribute, None)
        for attribute in self._HOOK_MEMORY_CACHE_ATTRIBUTES:
            setattr(self, attribute, None)
        if hook_handler is not None:
            try:
                hook_handler.cancel_core_hook_heartbeat()
            except Exception as error:
                self._last_session_cleanup_error = error
        return session_id

    def _build_hook_memory_objects(self, handler) -> dict[str, Any]:
        from .memory.memory_objects import (
            CurrentActorBody,
            CurrentChatOwner,
            CurrentClientObject,
            CurrentDuel,
            CurrentGameClient,
            CurrentGameStats,
            CurrentQuestPosition,
            CurrentRenderContext,
            CurrentRootWindow,
            CurrentSocialSystemsManager,
            TeleportHelper,
        )
        return {
            "stats": CurrentGameStats(handler),
            "body": CurrentActorBody(handler),
            "duel": CurrentDuel(handler),
            "quest_position": CurrentQuestPosition(handler),
            "client_object": CurrentClientObject(handler),
            "root_window": CurrentRootWindow(handler),
            "render_context": CurrentRenderContext(handler),
            "game_client": CurrentGameClient(handler),
            "social_systems_manager": CurrentSocialSystemsManager(handler),
            "chat_owner": CurrentChatOwner(handler),
            "_teleport_helper": TeleportHelper(handler),
        }

    def _register_session_cleanup(
        self,
        session_id: str,
        *,
        kind: str,
        instance_id: object = _INSTANCE_NOT_SUPPLIED,
    ) -> None:
        with self._session_cleanup_lock:
            cleanup_instance = instance_id
            if cleanup_instance is _INSTANCE_NOT_SUPPLIED or (
                cleanup_instance is None
                and not self._agent_generation_changed_with_owned_resources
            ):
                cleanup_instance = self._agent_instance_id
            key = (session_id, cleanup_instance)
            self._pending_session_cleanups.setdefault(key, kind)
            self._pending_session_cleanup_ids.add(session_id)

    def _forget_session_cleanup_locked(
        self,
        key: tuple[str, object],
    ) -> None:
        self._pending_session_cleanups.pop(key, None)
        session_id = key[0]
        if not any(
            pending_key[0] == session_id
            for pending_key in self._pending_session_cleanups
        ):
            self._pending_session_cleanup_ids.discard(session_id)
        if not self._pending_session_cleanups:
            self._last_session_cleanup_error = None

    def _close_session_key_blocking(
        self,
        key: tuple[str, object],
    ) -> None:
        """Close one exact session-generation obligation with single-flight joining."""
        with self._session_cleanup_lock:
            kind = self._pending_session_cleanups.get(key)
            if kind is None:
                return
            inflight = self._session_cleanup_inflight.get(key)
            if inflight is None:
                inflight = concurrent.futures.Future()
                self._session_cleanup_inflight[key] = inflight
                owns_attempt = True
            else:
                owns_attempt = False

        if not owns_attempt:
            inflight.result()
            return

        session_id, owner_instance = key
        try:
            current_instance = self._cleanup_helper_instance_id
            if owner_instance != current_instance:
                if (
                    kind == "telemetry"
                    and owner_instance in self._terminal_agent_instances
                ):
                    with self._session_cleanup_lock:
                        self._forget_session_cleanup_locked(key)
                    inflight.set_result(None)
                    return
                if owner_instance in self._terminal_agent_instances:
                    raise RuntimeError(
                        "Native cleanup belongs to a replaced helper generation; "
                        "the old session remains quarantined."
                    )
                raise RuntimeError(
                    "Native cleanup belongs to a different or unverified helper "
                    "generation; the old session ID will not be sent to the "
                    "current helper."
                )

            generation_close = getattr(
                self._agent_manager,
                "close_process_for_instance",
                None,
            )
            if not isinstance(owner_instance, str) or not callable(generation_close):
                raise RuntimeError(
                    "Native cleanup cannot atomically verify its helper generation; "
                    "the session will remain owned."
                )
            self._call_cleanup_agent_blocking(
                generation_close, session_id, owner_instance
            )
        except Exception as error:
            if getattr(error, "code", None) in {
                "process_exited",
                "process_not_found",
                "session_not_found",
            }:
                with self._session_cleanup_lock:
                    self._forget_session_cleanup_locked(key)
                inflight.set_result(None)
                return
            with self._session_cleanup_lock:
                self._last_session_cleanup_error = error
            inflight.set_exception(error)
            raise
        else:
            with self._session_cleanup_lock:
                self._forget_session_cleanup_locked(key)
            inflight.set_result(None)
        finally:
            with self._session_cleanup_lock:
                if self._session_cleanup_inflight.get(key) is inflight:
                    self._session_cleanup_inflight.pop(key, None)

    def _close_session_blocking(self, session_id: str) -> None:
        with self._session_cleanup_lock:
            keys = tuple(
                key
                for key in self._pending_session_cleanups
                if key[0] == session_id
            )
        cleanup_errors = []
        for key in keys:
            try:
                self._close_session_key_blocking(key)
            except Exception as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            first_error, *later_errors = cleanup_errors
            preserve_cleanup_errors(
                first_error,
                later_errors,
                operation=f"native session {session_id} cleanup",
            )
            raise first_error

    async def _close_session(self, session_id: str) -> None:
        if session_id not in self._pending_session_cleanup_ids:
            return
        try:
            await asyncio.get_running_loop().run_in_executor(
                None,
                self._close_session_blocking,
                session_id,
            )
        except BaseException as error:
            # The blocking owner updates durable state.  In particular, an
            # asyncio cancellation must not re-add an obligation after the
            # executor later confirms its close.
            if session_id in self._pending_session_cleanup_ids:
                self._last_session_cleanup_error = error
            raise

    def _schedule_session_close(self, session_id: str | None) -> None:
        if session_id is None:
            return
        if session_id not in self._pending_session_cleanup_ids:
            self._register_session_cleanup(session_id, kind="unknown")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            def close_in_background() -> None:
                try:
                    self._close_session_blocking(session_id)
                except Exception as error:
                    self._last_session_cleanup_error = error

            threading.Thread(target=close_in_background, daemon=True).start()
            return

        task = loop.create_task(self._close_session(session_id))
        self._session_cleanup_tasks.add(task)

        def remember_cleanup_result(completed: asyncio.Task[None]) -> None:
            self._session_cleanup_tasks.discard(completed)
            if not completed.cancelled():
                error = completed.exception()
                if error is not None:
                    self._last_session_cleanup_error = error

        task.add_done_callback(remember_cleanup_result)

    def _schedule_lifecycle_close(self) -> None:
        """Start retired-client teardown without surrendering retry ownership."""
        if any(not task.done() for task in self._lifecycle_cleanup_tasks):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # ClientHandler retains retired clients and will await close later.
            return
        task = loop.create_task(self.close())
        self._lifecycle_cleanup_tasks.add(task)

        def remember_cleanup_result(completed: asyncio.Task[None]) -> None:
            self._lifecycle_cleanup_tasks.discard(completed)
            if not completed.cancelled():
                error = completed.exception()
                if error is not None:
                    self._last_session_cleanup_error = error

        task.add_done_callback(remember_cleanup_result)

    def _retry_cleanup_after_generation_publish(self) -> None:
        """Retry direct-client cleanup after the same helper is republished."""
        if self._agent_instance_id != self._cleanup_helper_instance_id:
            return
        active = tuple(
            task for task in self._lifecycle_cleanup_tasks if not task.done()
        )
        if active:
            if self._lifecycle_retry_requested:
                return
            self._lifecycle_retry_requested = True

            def retry_when_drained(_completed: asyncio.Task[None]) -> None:
                if any(
                    not task.done() for task in self._lifecycle_cleanup_tasks
                ):
                    return
                self._lifecycle_retry_requested = False
                if (
                    not self.cleanup_complete
                    and self._agent_instance_id == self._cleanup_helper_instance_id
                ):
                    self._schedule_lifecycle_close()

            for task in active:
                task.add_done_callback(retry_when_drained)
            return
        if not self.cleanup_complete:
            self._schedule_lifecycle_close()

    async def _await_session_cleanup(self) -> None:
        pending_cleanup = tuple(self._session_cleanup_tasks)
        cleanup_errors = []
        if pending_cleanup:
            results = await asyncio.gather(*pending_cleanup, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    cleanup_errors.append(result)
        for session_id in tuple(self._pending_session_cleanup_ids):
            try:
                await self._close_session(session_id)
            except BaseException as error:
                cleanup_errors.append(error)
        for index, error in enumerate(cleanup_errors):
            if isinstance(error, Exception):
                continue
            prior_errors = cleanup_errors[:index]
            later_errors = cleanup_errors[index + 1 :]
            preserve_cleanup_errors(
                error,
                later_errors,
                operation="native process session cleanup",
            )
            if prior_errors:
                interrupted_error, *earlier_errors = prior_errors
                preserve_cleanup_errors(
                    interrupted_error,
                    earlier_errors,
                    operation="native process session cleanup",
                )
                propagate_cleanup_control_flow(
                    interrupted_error,
                    error,
                    operation="native process session cleanup",
                )
            raise error
        if cleanup_errors and self._pending_session_cleanup_ids:
            first_error, *later_errors = cleanup_errors
            preserve_cleanup_errors(
                first_error,
                later_errors,
                operation="native process session cleanup",
            )
            raise first_error
        if self._pending_session_cleanup_ids:
            if self._last_session_cleanup_error is not None:
                raise self._last_session_cleanup_error
            raise RuntimeError("Native process session cleanup is still pending.")

    async def attach_telemetry(self) -> ReadOnlyTelemetryReader:
        """Open an identity-checked, read-only process session when needed."""
        if not self._running:
            raise RuntimeError(
                "This Wizard101 client has closed. Rediscover it before reading telemetry."
            )
        if self._telemetry_reader is not None:
            return self._telemetry_reader

        async with self._attach_lock:
            if self._telemetry_reader is not None:
                return self._telemetry_reader

            await self._await_session_cleanup()

            session_generation = self._session_generation
            process_id = self.process_id
            identity_json = json.dumps(
                self._expected_identity(),
                separators=(",", ":"),
                sort_keys=True,
            )
            loop = asyncio.get_running_loop()
            session, cancellation = await settle_critical_operation(
                loop.run_in_executor(
                    None,
                    partial(
                        self._call_agent_blocking,
                        self._agent_manager.open_process,
                        process_id,
                        expected_identity_json=identity_json,
                    ),
                ),
                operation="open read-only process session",
            )
            session_id = (
                session.get("session_id")
                if isinstance(session, dict)
                else None
            )
            if not isinstance(session_id, str) or not session_id:
                invalid_session = ValueError(
                    "The native agent opened the Wizard101 process without "
                    "returning a valid read-only session ID."
                )
                if cancellation is not None:
                    preserve_cleanup_errors(
                        cancellation,
                        (invalid_session,),
                        operation="cancelled read-only process session open",
                    )
                    raise cancellation from invalid_session
                raise invalid_session

            if cancellation is not None:
                self._register_session_cleanup(
                    session_id,
                    kind="telemetry",
                    instance_id=self._agent_instance_id,
                )
                await await_cleanup_preserving_cancellation(
                    self._close_session(session_id),
                    cancellation,
                    operation="cancelled read-only process session open",
                )
                raise cancellation

            if (
                not self._running
                or session_generation != self._session_generation
                or process_id != self.process_id
            ):
                if not self._running:
                    activation_error = RuntimeError(
                        "This Wizard101 client closed while its read-only "
                        "telemetry session was opening."
                    )
                else:
                    activation_error = RuntimeError(
                        "The Wizard101 client changed identity while its read-only "
                        "telemetry session was opening. Rediscover it and try again."
                    )
                self._register_session_cleanup(
                    session_id,
                    kind="telemetry",
                    instance_id=self._agent_instance_id,
                )
                await await_cleanup_preserving_cancellation(
                    self._close_session(session_id),
                    activation_error,
                    operation="stale telemetry session initialization",
                )
                raise activation_error

            try:
                backend = DeimosNativeMemoryBackend(
                    self._agent_manager,
                    session_id,
                    expected_instance_id=(
                        self._agent_instance_id
                        if isinstance(self._agent_instance_id, str)
                        else None
                    ),
                    generation_fence=self._generation_fence,
                    generation_token=self._operation_instance_id,
                    generation_context=self._generation_context,
                )
                telemetry_reader = ReadOnlyTelemetryReader(MemoryReader(backend))
            except BaseException as activation_error:
                self._register_session_cleanup(
                    session_id,
                    kind="telemetry",
                    instance_id=self._agent_instance_id,
                )
                await await_cleanup_preserving_cancellation(
                    self._close_session(session_id),
                    activation_error,
                    operation="telemetry reader construction",
                )
                raise
            self._session_id = session_id
            self._session_instance_id = self._agent_instance_id
            self._telemetry_reader = telemetry_reader
            return self._telemetry_reader

    async def telemetry_snapshot(self) -> ReadOnlyTelemetrySnapshot:
        """Capture the currently available hook-free telemetry fields."""
        reader = await self.attach_telemetry()
        return await reader.snapshot(
            client_id=self.client_id,
            process_id=self.process_id,
        )

    async def _ensure_hook_handler(self):
        """Open an identity-checked mutation session without activating hooks."""
        total_started = time.perf_counter()
        if not self._running:
            _log_hook_timing(
                "client.ensure_hook_handler", total_started, outcome="error"
            )
            raise RuntimeError(
                "This Wizard101 client has closed. Rediscover it before activating hooks."
            )
        if self.hook_handler is not None:
            _log_hook_timing(
                "client.ensure_hook_handler", total_started, created=False, cached=True
            )
            return self.hook_handler, False

        async with self._hook_attach_lock:
            if self.hook_handler is not None:
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, created=False, cached=True
                )
                return self.hook_handler, False
            if self._generation_context is None:
                raise RuntimeError(
                    "Native hook activation requires a manager-scoped generation context."
                )
            reservation_created = self._generation_context.reserve_hook_owner(
                self,
                self._operation_instance_id,
            )
            try:
                await self._await_session_cleanup()
            except BaseException:
                if reservation_created and self.cleanup_complete:
                    self._generation_context.release_cleanup_owner(self)
                raise
            session_generation = self._session_generation
            process_id = self.process_id
            identity_json = json.dumps(
                self._expected_identity(),
                separators=(",", ":"),
                sort_keys=True,
            )
            loop = asyncio.get_running_loop()
            open_started = time.perf_counter()
            try:
                session, cancellation = await settle_critical_operation(
                    loop.run_in_executor(
                        None,
                        partial(
                            self._call_agent_blocking,
                            self._agent_manager.open_hook_process,
                            process_id,
                            expected_identity_json=identity_json,
                        ),
                    ),
                    operation="open hook process session",
                )
            except BaseException as error:
                if reservation_created and getattr(error, "code", None) in {
                    "identity_mismatch",
                    "process_exited",
                    "process_not_found",
                }:
                    self._generation_context.release_cleanup_owner(self)
                _log_hook_timing(
                    "client.open_hook_session", open_started, outcome="error"
                )
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, outcome="error"
                )
                raise
            _log_hook_timing("client.open_hook_session", open_started)
            session_id = session.get("session_id") if isinstance(session, dict) else None
            if not isinstance(session_id, str) or not session_id:
                if reservation_created:
                    self._generation_context.release_cleanup_owner(self)
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, outcome="error"
                )
                invalid_session = ValueError(
                    "The native agent opened the Wizard101 process without "
                    "returning a valid hook session ID."
                )
                if cancellation is not None:
                    preserve_cleanup_errors(
                        cancellation,
                        (invalid_session,),
                        operation="cancelled hook process session open",
                    )
                    raise cancellation from invalid_session
                raise invalid_session

            if cancellation is not None:
                self._register_session_cleanup(
                    session_id,
                    kind="hook",
                    instance_id=self._agent_instance_id,
                )
                await await_cleanup_preserving_cancellation(
                    self._close_session(session_id),
                    cancellation,
                    operation="cancelled hook process session open",
                )
                if reservation_created and self.cleanup_complete:
                    self._generation_context.release_cleanup_owner(self)
                raise cancellation
            if (
                not self._running
                or session_generation != self._session_generation
                or process_id != self.process_id
            ):
                activation_error = RuntimeError(
                    "The Wizard101 client changed while its hook session was opening. "
                    "Rediscover it and try again."
                )
                cleanup_started = time.perf_counter()
                self._register_session_cleanup(
                    session_id,
                    kind="hook",
                    instance_id=self._agent_instance_id,
                )
                async def rollback_stale_session():
                    await self._close_session(session_id)
                    if reservation_created and self.cleanup_complete:
                        self._generation_context.release_cleanup_owner(self)

                await await_cleanup_preserving_cancellation(
                    rollback_stale_session(),
                    activation_error,
                    operation="stale hook session initialization",
                )
                _log_hook_timing(
                    "client.close_stale_hook_session", cleanup_started
                )
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, outcome="error"
                )
                raise activation_error

            from .memory.handler import HookHandler

            build_started = time.perf_counter()
            try:
                handler = HookHandler(
                    DeimosNativeMemoryBackend(
                        self._agent_manager,
                        session_id,
                        expected_instance_id=(
                            self._agent_instance_id
                            if isinstance(self._agent_instance_id, str)
                            else None
                        ),
                        generation_fence=self._generation_fence,
                        generation_token=self._operation_instance_id,
                        generation_context=self._generation_context,
                    ),
                    self,
                )
                memory_objects = self._build_hook_memory_objects(handler)
            except BaseException as activation_error:
                self._register_session_cleanup(
                    session_id,
                    kind="hook",
                    instance_id=self._agent_instance_id,
                )
                async def rollback_construction():
                    await self._close_session(session_id)
                    if reservation_created and self.cleanup_complete:
                        self._generation_context.release_cleanup_owner(self)

                await await_cleanup_preserving_cancellation(
                    rollback_construction(),
                    activation_error,
                    operation="hook memory object construction",
                )
                _log_hook_timing(
                    "client.build_memory_objects", build_started, outcome="error"
                )
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, outcome="error"
                )
                raise
            _log_hook_timing("client.build_memory_objects", build_started)
            self._hook_session_id = session_id
            self._hook_session_instance_id = self._agent_instance_id
            self.hook_handler = handler
            self.__dict__.update(memory_objects)
            _log_hook_timing("client.ensure_hook_handler", total_started, created=True)
            return handler, True

    async def activate_hooks(self, wait_for_ready: bool = True) -> None:
        """Open a mutation session and activate the core hooks."""
        async with self._hook_lifecycle_lock:
            await self._activate_hooks_locked(wait_for_ready=wait_for_ready)

    async def _activate_hooks_locked(self, wait_for_ready: bool = True) -> None:
        total_started = time.perf_counter()
        session_generation = self._session_generation
        process_id = self.process_id
        ensure_started = time.perf_counter()
        try:
            handler, created = await self._ensure_hook_handler()
        except BaseException:
            _log_hook_timing(
                "client.ensure_hook_handler_call", ensure_started, outcome="error"
            )
            _log_hook_timing("client.activate_hooks", total_started, outcome="error")
            raise
        _log_hook_timing(
            "client.ensure_hook_handler_call", ensure_started, created=created
        )
        try:
            activate_started = time.perf_counter()
            await handler.activate_all_hooks(wait_for_ready=wait_for_ready)
            _log_hook_timing("client.activate_all_hooks", activate_started)
            identity_started = time.perf_counter()
            if (
                not self._running
                or session_generation != self._session_generation
                or process_id != self.process_id
                or handler is not self.hook_handler
            ):
                if not self._running:
                    raise RuntimeError(
                        "This Wizard101 client closed while its core hooks were activating."
                    )
                raise RuntimeError(
                    "The Wizard101 client changed identity while its core hooks "
                    "were activating. Rediscover it and try again."
                )
            _log_hook_timing("client.validate_identity", identity_started)
        except BaseException as activation_error:
            _log_hook_timing("client.activate_hooks", total_started, outcome="error")
            if created and handler is self.hook_handler:
                cleanup_started = time.perf_counter()
                await await_cleanup_preserving_cancellation(
                    self._close_hook_session_locked(),
                    activation_error,
                    operation="client hook activation",
                )
                _log_hook_timing("client.cleanup_failed_activation", cleanup_started)
            raise
        _log_hook_timing("client.activate_hooks", total_started)

    @property
    def mouse_handler(self):
        return self._mouse_handler

    @property
    def cache_handler(self):
        if self._cache_handler is None:
            from .file_readers import CacheHandler

            self._cache_handler = CacheHandler()
        return self._cache_handler

    async def _close_hook_session_locked(self) -> None:
        hook_handler = self.hook_handler
        if hook_handler is not None:
            if (
                self._hook_session_instance_id is None
                and not self._agent_generation_changed_with_owned_resources
            ):
                # Compatibility for callers/tests that populated a session
                # before generation tracking existed.  This inference is only
                # allowed while no helper transition occurred with resources
                # still owned.
                self._hook_session_instance_id = self._agent_instance_id
            if (
                self._hook_session_instance_id
                != self._cleanup_helper_instance_id
            ):
                error = RuntimeError(
                    "Native hook cleanup belongs to a replaced helper generation; "
                    "the old hook session will remain owned for explicit recovery."
                )
                self._last_session_cleanup_error = error
                raise error
            await hook_handler.close()
        hook_session_id = self._detach_hook_session()
        if hook_session_id is not None:
            await self._close_session(hook_session_id)

    async def close(self) -> None:
        self.begin_detach()
        if self._external_cleanup_blockers:
            raise RuntimeError(
                "Native client cleanup is blocked by retained external ownership: "
                + ", ".join(sorted(self._external_cleanup_blockers))
            )
        current_task = asyncio.current_task()
        scheduled_cleanup = tuple(
            task
            for task in self._lifecycle_cleanup_tasks
            if task is not current_task
        )
        if scheduled_cleanup:
            # A retirement-triggered teardown owns the same close transaction.
            # Let it finish first; if it failed, the transaction below retries
            # only the state it retained.
            await asyncio.gather(*scheduled_cleanup, return_exceptions=True)
        async with self._close_lock:
            async with self._hook_lifecycle_lock:
                await self._close_hook_session_locked()
            session_id = self._detach_session()
            if session_id is not None:
                await self._close_session(session_id)
            await self._await_session_cleanup()
            if not self._pending_session_cleanup_ids:
                self._last_session_cleanup_error = None
            resources_released = (
                self.hook_handler is None
                and self._hook_session_id is None
                and self._session_id is None
                and not self._pending_session_cleanup_ids
                and not any(
                    not task.done() for task in self._session_cleanup_tasks
                )
            )
            if resources_released and self._generation_context is not None:
                self._generation_context.release_cleanup_owner(self)

    def __repr__(self) -> str:
        return (
            f"<DiscoveredClient client_id={self.client_id!r} "
            f"process_id={self.process_id} running={self._running}>"
        )
