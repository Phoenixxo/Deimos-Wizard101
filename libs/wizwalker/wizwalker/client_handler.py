import asyncio
import sys
from copy import copy
from functools import cached_property
from pathlib import Path
from typing import Any, List, Optional, Type

from .discovered_client import DiscoveredClient
from .errors import UnsupportedClientOperation

if sys.platform == "win32":
    from wizwalker import utils

    from .client import Client

    _DEFAULT_CLIENT_CLASS = Client
else:
    utils = None
    Client = DiscoveredClient
    _DEFAULT_CLIENT_CLASS = DiscoveredClient


class ClientHandler:
    """Manage legacy Windows clients or agent-discovered Wine clients."""

    def __init__(
        self,
        *,
        client_cls: Type[Any] = _DEFAULT_CLIENT_CLASS,
        agent_manager: Any = None,
    ):
        self.client_cls = (
            DiscoveredClient
            if agent_manager is not None and client_cls is _DEFAULT_CLIENT_CLASS
            else client_cls
        )
        self.agent_manager = agent_manager

        self._managed_handles = []
        self._managed_client_ids = []
        self._retired_clients: List[Any] = []
        self.clients: List[Any] = []

    @property
    def _uses_native_discovery(self) -> bool:
        return self.agent_manager is not None

    @staticmethod
    def _legacy_utils():
        if utils is None:
            raise UnsupportedClientOperation("legacy Windows client discovery")
        return utils

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __repr__(self):
        return f"<WizWalker {self.clients=}>"

    @cached_property
    def install_location(self) -> Path:
        """Wizard101 install location for the legacy Windows backend."""
        return self._legacy_utils().get_wiz_install()

    @staticmethod
    def start_wiz_client():
        """Start a new client through the legacy Windows launcher."""
        ClientHandler._legacy_utils().start_instance()

    def get_foreground_client(self) -> Optional[Any]:
        if self._uses_native_discovery:
            self._refresh_native_clients(add_new=False)
        for client in self.clients:
            if client.is_foreground:
                return client
        return None

    def _list_native_descriptors(self) -> list[dict[str, Any]]:
        response = self.agent_manager.list_clients()
        clients = response.get("clients") if isinstance(response, dict) else None
        if not isinstance(clients, list):
            raise ValueError(
                "The native agent returned an invalid client discovery response."
            )

        client_ids = set()
        for descriptor in clients:
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
                or client_id in client_ids
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
            client_ids.add(client_id)
        return clients

    def _refresh_native_clients(self, *, add_new: bool) -> List[Any]:
        descriptors = self._list_native_descriptors()
        descriptors_by_id = {
            descriptor.get("client_id"): descriptor
            for descriptor in descriptors
            if isinstance(descriptor, dict)
            and isinstance(descriptor.get("client_id"), str)
        }
        existing_by_id = {
            client.client_id: client
            for client in self.clients
            if isinstance(client, DiscoveredClient)
            or isinstance(getattr(client, "client_id", None), str)
        }

        for client_id, client in existing_by_id.items():
            descriptor = descriptors_by_id.get(client_id)
            if descriptor is None:
                client._mark_closed()
            else:
                client._update(descriptor)

        new_clients = []
        if add_new:
            for descriptor in descriptors:
                client_id = descriptor.get("client_id")
                if client_id in self._managed_client_ids:
                    continue
                new_client = self.client_cls(self.agent_manager, descriptor)
                self._managed_client_ids.append(client_id)
                self.clients.append(new_client)
                new_clients.append(new_client)
        return new_clients

    def get_new_clients(self) -> List[Any]:
        """Return clients discovered since the handler began managing clients."""
        if self._uses_native_discovery:
            return self._refresh_native_clients(add_new=True)

        all_handles = self._legacy_utils().get_all_wizard_handles()
        new_clients = []
        for handle in all_handles:
            if handle not in self._managed_handles:
                self._managed_handles.append(handle)
                new_client = self.client_cls(handle)
                self.clients.append(new_client)
                new_clients.append(new_client)
        return new_clients

    def remove_dead_clients(self) -> List[Any]:
        """Remove and return clients that are no longer running."""
        if self._uses_native_discovery:
            self._refresh_native_clients(add_new=False)

        clients_proxy = copy(self.clients)
        dead_clients = []
        for client in clients_proxy:
            if not client.is_running():
                dead_clients.append(client)
                self.clients.remove(client)
                self._retired_clients.append(client)
        return dead_clients

    def get_ordered_clients(self) -> List[Any]:
        """Return clients ordered by their top-to-bottom, left-to-right position."""
        if self._uses_native_discovery:
            self._refresh_native_clients(add_new=False)
            return sorted(self.clients, key=lambda client: client.screen_order)
        return self._legacy_utils().order_clients(self.clients)

    async def activate_all_client_hooks(self, wait_for_ready: bool = True):
        """Activate hooks for all legacy clients."""
        hook_tasks = []
        for client in self.clients:
            hook_tasks.append(
                asyncio.create_task(
                    client.activate_hooks(wait_for_ready=wait_for_ready)
                )
            )
        if wait_for_ready:
            for task in hook_tasks:
                await task

    async def activate_all_client_mouseless(self):
        """Activate mouseless input for all legacy clients."""
        for client in self.clients:
            await client.mouse_handler.activate_mouseless()

    async def close(self):
        """Release resources owned by all managed clients."""
        clients = [*self.clients, *self._retired_clients]
        self._retired_clients.clear()
        for client in clients:
            await client.close()
