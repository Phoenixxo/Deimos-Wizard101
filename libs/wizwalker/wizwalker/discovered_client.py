from __future__ import annotations

import asyncio
import json
import threading
from functools import partial
from typing import Any

from .errors import UnsupportedClientOperation
from .memory import DeimosNativeMemoryBackend, MemoryReader
from .telemetry import ReadOnlyTelemetryReader, ReadOnlyTelemetrySnapshot


class DiscoveredClient:
    """Read-only client identity reported by the native helper agent."""

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
        self._update(descriptor)

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
        self.is_foreground = bool(descriptor.get("is_foreground", False))
        self.screen_order = int(descriptor.get("screen_order", 0))
        self._running = True

    def _mark_closed(self) -> None:
        self._running = False
        self.is_foreground = False
        self._schedule_session_close(self._detach_session())
        self._schedule_session_close(self._detach_hook_session())

    def is_running(self) -> bool:
        return self._running

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
        return session_id

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

    async def activate_hooks(self, wait_for_ready: bool = True) -> None:
        """Open a mutation session and activate the core hooks."""
        if not self._running:
            raise RuntimeError(
                "This Wizard101 client has closed. Rediscover it before activating hooks."
            )
        if self.hook_handler is not None:
            await self.hook_handler.activate_all_hooks(
                wait_for_ready=wait_for_ready
            )
            return

        async with self._hook_attach_lock:
            if self.hook_handler is not None:
                await self.hook_handler.activate_all_hooks(
                    wait_for_ready=wait_for_ready
                )
                return
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
                    self._agent_manager.open_hook_process,
                    process_id,
                    expected_identity_json=identity_json,
                ),
            )
            session_id = session.get("session_id") if isinstance(session, dict) else None
            if not isinstance(session_id, str) or not session_id:
                raise ValueError(
                    "The native agent opened the Wizard101 process without "
                    "returning a valid hook session ID."
                )
            if (
                not self._running
                or session_generation != self._session_generation
                or process_id != self.process_id
            ):
                await self._close_session(session_id)
                raise RuntimeError(
                    "The Wizard101 client changed while its hook session was opening. "
                    "Rediscover it and try again."
                )

            from .memory.handler import HookHandler

            handler = HookHandler(
                DeimosNativeMemoryBackend(self._agent_manager, session_id),
                self,
            )
            try:
                await handler.activate_all_hooks(wait_for_ready=wait_for_ready)
                if (
                    not self._running
                    or session_generation != self._session_generation
                    or process_id != self.process_id
                ):
                    if not self._running:
                        raise RuntimeError(
                            "This Wizard101 client closed while its core hooks "
                            "were activating."
                        )
                    raise RuntimeError(
                        "The Wizard101 client changed identity while its core hooks "
                        "were activating. Rediscover it and try again."
                    )
            except BaseException:
                handler.cancel_core_hook_heartbeat()
                await self._close_session(session_id)
                raise
            self._hook_session_id = session_id
            self.hook_handler = handler

    @property
    def mouse_handler(self):
        raise UnsupportedClientOperation("mouseless input")

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
