from __future__ import annotations

from typing import Any

from .errors import UnsupportedClientOperation


class DiscoveredClient:
    """Read-only client identity reported by the native helper agent."""

    def __init__(self, agent_manager: Any, descriptor: dict[str, Any]):
        self._agent_manager = agent_manager
        self._running = True
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
        self.client_id = client_id
        self.process = process
        self.process_id = process["pid"]
        self.is_foreground = bool(descriptor.get("is_foreground", False))
        self.screen_order = int(descriptor.get("screen_order", 0))
        self._running = True

    def _mark_closed(self) -> None:
        self._running = False
        self.is_foreground = False

    def is_running(self) -> bool:
        return self._running

    async def activate_hooks(self, wait_for_ready: bool = True) -> None:
        raise UnsupportedClientOperation("hook activation")

    @property
    def mouse_handler(self):
        raise UnsupportedClientOperation("mouseless input")

    async def close(self) -> None:
        # Legacy Client.close() releases hook resources; it does not terminate
        # Wizard101. Discovery-only clients own no equivalent resources yet.
        return None

    def __repr__(self) -> str:
        return (
            f"<DiscoveredClient client_id={self.client_id!r} "
            f"process_id={self.process_id} running={self._running}>"
        )
