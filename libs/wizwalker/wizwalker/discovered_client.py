from __future__ import annotations

import asyncio
import json
import threading
import time
from functools import partial
from typing import Any

from .memory import DeimosNativeMemoryBackend, MemoryReader
from .telemetry import (
    ReadOnlyTelemetryReader,
    ReadOnlyTelemetrySnapshot,
    _TelemetryReadContext,
)


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
        handler, created = await self.client._ensure_hook_handler()
        try:
            if "mouseless_cursor" not in handler._active_hooks.values():
                await handler.activate_mouseless_cursor_hook()
        except BaseException:
            if created and handler is self.client.hook_handler:
                session_id = self.client._detach_hook_session()
                if session_id is not None:
                    await self.client._close_session(session_id)
            raise

    async def _deactivate_mouseless(self) -> None:
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

    def __init__(self, agent_manager: Any, descriptor: dict[str, Any]):
        self._agent_manager = agent_manager
        self._running = True
        self._session_id: str | None = None
        self._hook_session_id: str | None = None
        self.hook_handler = None
        self._telemetry_reader: ReadOnlyTelemetryReader | None = None
        self._session_generation = 0
        self._session_cleanup_tasks: set[asyncio.Task[None]] = set()
        self._last_session_cleanup_error: BaseException | None = None
        self._attach_lock = asyncio.Lock()
        self._hook_attach_lock = asyncio.Lock()
        self._mouse_handler = NativeMouseHandler(self)
        self._cache_handler = None
        self._template_ids = None
        self._world_view_window = None
        self._character_registry_addr = None
        self._quest_client_manager_addr = None
        self._je_instruction_forward_backwards = None
        self._update(descriptor)

    def __getattr__(self, name: str):
        if name not in self._HOOKED_CLIENT_METHODS:
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute {name!r}"
            )

        from .client import Client

        return getattr(Client, name).__get__(self, type(self))

    def _update(self, descriptor: dict[str, Any]) -> None:
        client_id = descriptor.get("client_id")
        process = descriptor.get("process")
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("The native agent returned a client without a valid client ID.")
        if not isinstance(process, dict) or not isinstance(process.get("pid"), int):
            raise ValueError(
                "The native agent returned a client without valid process metadata."
            )
        old_identity = self.process.get("identity") if hasattr(self, "process") else None
        old_process_id = self.process_id if hasattr(self, "process_id") else None
        if hasattr(self, "process") and (
            old_identity != process.get("identity")
            or old_process_id != process["pid"]
        ):
            self._schedule_session_close(self._detach_session())
            self._schedule_session_close(self._detach_hook_session())
        self.client_id = client_id
        self.process = process
        self.process_id = process["pid"]
        self._is_foreground = bool(descriptor.get("is_foreground", False))
        self.screen_order = int(descriptor.get("screen_order", 0))
        self._running = True

    def _mark_closed(self) -> None:
        self._running = False
        self._is_foreground = False
        self._schedule_session_close(self._detach_session())
        self._schedule_session_close(self._detach_hook_session())

    def _has_live_process_session(self) -> bool:
        session_ids = tuple(
            session_id
            for session_id in (self._hook_session_id, self._session_id)
            if session_id is not None
        )
        for session_id in session_ids:
            try:
                status = self._agent_manager.process_status(session_id)
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

    def _window_state(self) -> dict[str, Any]:
        response = self._agent_manager.client_window_state(self.client_id)
        if not isinstance(response, dict):
            raise ValueError("The native agent returned an invalid window state response.")
        return response

    @property
    def title(self) -> str:
        title = self._window_state().get("title")
        if not isinstance(title, str):
            raise ValueError("The native agent returned an invalid window title.")
        return title

    @title.setter
    def title(self, value: str) -> None:
        self._agent_manager.set_client_window_title(self.client_id, value)

    @property
    def is_foreground(self) -> bool:
        try:
            is_foreground = self._window_state().get("is_foreground")
        except Exception as error:
            if (
                getattr(error, "code", None) in {"client_not_found", "window_not_found"}
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
            response = self._agent_manager.focus_client_window(self.client_id)
            if not isinstance(response, dict) or response.get("is_foreground") is not True:
                raise RuntimeError("The native agent could not focus this Wizard101 client.")
            self._is_foreground = True

    @property
    def window_rectangle(self) -> WindowRectangle:
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
        state = self._window_state()
        origin = state.get("client_origin")
        size = state.get("client_size")
        if not isinstance(origin, dict) or not all(
            isinstance(origin.get(axis), int) and not isinstance(origin.get(axis), bool)
            for axis in ("x", "y")
        ):
            raise ValueError("The native agent returned an invalid client-area origin.")
        if not isinstance(size, dict) or not all(
            isinstance(size.get(axis), int) and not isinstance(size.get(axis), bool)
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
        return await asyncio.get_running_loop().run_in_executor(None, partial(call, *args))

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
        self._session_id = None
        self._telemetry_reader = None
        return session_id

    def _detach_hook_session(self) -> str | None:
        session_id = self._hook_session_id
        self._hook_session_id = None
        if self.hook_handler is not None:
            self.hook_handler.cancel_core_hook_heartbeat()
        self.hook_handler = None
        for attribute in self._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            self.__dict__.pop(attribute, None)
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
        signature_addresses: dict[bytes, int] = {}

        def dynamic_address(method_name: str):
            async def resolve() -> int:
                context = _TelemetryReadContext(handler, signature_addresses)
                return await getattr(context, method_name)()

            return resolve

        return {
            "stats": CurrentGameStats(handler, dynamic_address("game_stats")),
            "body": CurrentActorBody(handler, dynamic_address("actor_body")),
            "duel": CurrentDuel(handler),
            "quest_position": CurrentQuestPosition(handler),
            "client_object": CurrentClientObject(
                handler,
                dynamic_address("root_client_object"),
            ),
            "root_window": CurrentRootWindow(handler),
            "render_context": CurrentRenderContext(handler),
            "game_client": CurrentGameClient(handler),
            "social_systems_manager": CurrentSocialSystemsManager(handler),
            "chat_owner": CurrentChatOwner(handler),
            "_teleport_helper": TeleportHelper(handler),
        }

    def _close_session_blocking(self, session_id: str) -> None:
        try:
            self._agent_manager.close_process(session_id)
        except Exception as error:
            if getattr(error, "code", None) not in {
                "process_exited",
                "process_not_found",
                "session_not_found",
            }:
                raise

    async def _close_session(self, session_id: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            self._close_session_blocking,
            session_id,
        )

    def _schedule_session_close(self, session_id: str | None) -> None:
        if session_id is None:
            return
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

            session_generation = self._session_generation
            process_id = self.process_id
            identity_json = json.dumps(
                self._expected_identity(),
                separators=(",", ":"),
                sort_keys=True,
            )
            loop = asyncio.get_running_loop()
            session = await loop.run_in_executor(
                None,
                partial(
                    self._agent_manager.open_process,
                    process_id,
                    expected_identity_json=identity_json,
                ),
            )
            session_id = (
                session.get("session_id")
                if isinstance(session, dict)
                else None
            )
            if not isinstance(session_id, str) or not session_id:
                raise ValueError(
                    "The native agent opened the Wizard101 process without "
                    "returning a valid read-only session ID."
                )

            if (
                not self._running
                or session_generation != self._session_generation
                or process_id != self.process_id
            ):
                await self._close_session(session_id)
                if not self._running:
                    raise RuntimeError(
                        "This Wizard101 client closed while its read-only "
                        "telemetry session was opening."
                    )
                raise RuntimeError(
                    "The Wizard101 client changed identity while its read-only "
                    "telemetry session was opening. Rediscover it and try again."
                )

            self._session_id = session_id
            backend = DeimosNativeMemoryBackend(
                self._agent_manager,
                session_id,
            )
            self._telemetry_reader = ReadOnlyTelemetryReader(
                MemoryReader(backend)
            )
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
                session = await loop.run_in_executor(
                    None,
                    partial(
                        self._agent_manager.open_hook_process,
                        process_id,
                        expected_identity_json=identity_json,
                    ),
                )
            except BaseException:
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
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, outcome="error"
                )
                raise ValueError(
                    "The native agent opened the Wizard101 process without "
                    "returning a valid hook session ID."
                )
            if (
                not self._running
                or session_generation != self._session_generation
                or process_id != self.process_id
            ):
                cleanup_started = time.perf_counter()
                await self._close_session(session_id)
                _log_hook_timing(
                    "client.close_stale_hook_session", cleanup_started
                )
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, outcome="error"
                )
                raise RuntimeError(
                    "The Wizard101 client changed while its hook session was opening. "
                    "Rediscover it and try again."
                )

            from .memory.handler import HookHandler

            build_started = time.perf_counter()
            handler = HookHandler(
                DeimosNativeMemoryBackend(self._agent_manager, session_id),
                self,
            )
            try:
                memory_objects = self._build_hook_memory_objects(handler)
            except BaseException:
                await self._close_session(session_id)
                _log_hook_timing(
                    "client.build_memory_objects", build_started, outcome="error"
                )
                _log_hook_timing(
                    "client.ensure_hook_handler", total_started, outcome="error"
                )
                raise
            _log_hook_timing("client.build_memory_objects", build_started)
            self._hook_session_id = session_id
            self.hook_handler = handler
            self.__dict__.update(memory_objects)
            _log_hook_timing("client.ensure_hook_handler", total_started, created=True)
            return handler, True

    async def activate_hooks(self, wait_for_ready: bool = True) -> None:
        """Open a mutation session and activate the core hooks."""
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
        except BaseException:
            _log_hook_timing("client.activate_hooks", total_started, outcome="error")
            if created and handler is self.hook_handler:
                cleanup_started = time.perf_counter()
                session_id = self._detach_hook_session()
                if session_id is not None:
                    await self._close_session(session_id)
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

    async def close(self) -> None:
        hook_handler = self.hook_handler
        hook_session_id = self._detach_hook_session()
        try:
            if hook_handler is not None:
                await hook_handler.close()
        finally:
            if hook_session_id is not None:
                await self._close_session(hook_session_id)
        session_id = self._detach_session()
        if session_id is not None:
            await self._close_session(session_id)
        pending_cleanup = tuple(self._session_cleanup_tasks)
        if pending_cleanup:
            await asyncio.gather(*pending_cleanup)
        if self._last_session_cleanup_error is not None:
            raise self._last_session_cleanup_error

    def __repr__(self) -> str:
        return (
            f"<DiscoveredClient client_id={self.client_id!r} "
            f"process_id={self.process_id} running={self._running}>"
        )
