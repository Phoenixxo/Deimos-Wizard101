import asyncio
import json
import sys
import time
from copy import copy
from functools import cached_property
from pathlib import Path
from typing import Any, List, Optional, Type

from .discovered_client import DiscoveredClient
from .errors import (
    UnsupportedClientOperation,
    await_cleanup_preserving_cancellation,
    preserve_cleanup_errors,
)
from .generation import (
    NativeGenerationContext,
    NativeGenerationDrainTimeout,
    manager_generation_context,
)

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
        agent_instance_id: str | None = None,
        generation_context: NativeGenerationContext | None = None,
        hook_heartbeat_failure_handler=None,
    ):
        self.client_cls = (
            DiscoveredClient
            if agent_manager is not None and client_cls is _DEFAULT_CLIENT_CLASS
            else client_cls
        )
        self.agent_manager = agent_manager
        manager_instance_id = getattr(agent_manager, "cleanup_instance_id", None)
        self._agent_instance_id: object = (
            agent_instance_id
            if agent_instance_id is not None
            else (
                manager_instance_id
                if isinstance(manager_instance_id, str) and manager_instance_id
                else object()
            )
        )

        self._managed_handles = []
        self._managed_client_ids = []
        self._retired_clients: List[Any] = []
        self._retired_cleanup_lock = asyncio.Lock()
        self._retired_cleanup_retry_at: dict[Any, float] = {}
        self._retired_cleanup_retry_delay = 1.0
        self.clients: List[Any] = []
        self._hook_heartbeat_failure_handler = hook_heartbeat_failure_handler
        if agent_manager is None:
            if generation_context is not None:
                raise ValueError("A generation context requires an agent manager.")
            self._generation_context = None
            self._generation_fence = None
            self._agent_generation_token = None
        else:
            self._generation_context = generation_context or manager_generation_context(
                agent_manager, self._agent_instance_id
            )
            if not self._generation_context.owns(agent_manager):
                raise ValueError("The generation context belongs to another manager.")
            self._generation_fence = self._generation_context.fence
            self._agent_instance_id = self._generation_context.instance_id
            self._agent_generation_token = self._generation_context.generation_token
            self._generation_context.register_handler(self)
        self._quarantined_hook_clients = (
            self._generation_context.quarantined_hook_clients
            if self._generation_context is not None
            else {}
        )

    def _bind_agent_instance(
        self,
        client: Any,
        *,
        previous_replaced: bool = False,
    ) -> Any:
        setter = getattr(client, "_set_agent_instance", None)
        if callable(setter):
            setter(
                self._agent_instance_id,
                previous_replaced=previous_replaced,
            )
        fence_setter = getattr(client, "_set_generation_fence", None)
        if callable(fence_setter) and self._generation_fence is not None:
            fence_setter(
                self._generation_fence,
                self._agent_generation_token,
                self._generation_context,
            )
            assert self._generation_context is not None
            self._generation_context.register_client(client)
        heartbeat_setter = getattr(
            client, "_set_hook_heartbeat_failure_handler", None
        )
        if callable(heartbeat_setter):
            heartbeat_setter(self._hook_heartbeat_failure_handler)
        return client

    def set_hook_heartbeat_failure_handler(self, handler) -> None:
        """Route future and existing native hook health failures."""
        self._hook_heartbeat_failure_handler = handler
        for client in self.cleanup_clients:
            setter = getattr(client, "_set_hook_heartbeat_failure_handler", None)
            if callable(setter):
                setter(handler)

    async def begin_agent_replacement(
        self,
        *,
        timeout_seconds: float = 5.0,
        schedule_client_cleanup: bool = True,
        cleanup_blocker: str | None = None,
    ) -> None:
        """Reject queued stale work and drain dispatched calls before restart."""
        if self._generation_context is None:
            raise UnsupportedClientOperation("native helper generation replacement")
        self._generation_context.begin_replacement(
            self._agent_generation_token,
            schedule_client_cleanup=schedule_client_cleanup,
            cleanup_blocker=cleanup_blocker,
        )
        tasks_drained = await self._generation_context.cancel_and_drain_generation_tasks(
            timeout_seconds
        )
        if not tasks_drained:
            raise NativeGenerationDrainTimeout(
                "Timed out draining native generation tasks; the generation "
                "remains fenced and replacement was not started."
            )
        drained = await asyncio.to_thread(
            self._generation_fence.wait_for_drain, timeout_seconds
        )
        if not drained:
            raise NativeGenerationDrainTimeout(
                "Timed out waiting for old helper operations to finish; the "
                "generation remains fenced and replacement was not started."
            )

    def note_agent_instance(
        self,
        instance_id: str,
        *,
        previous_replaced: bool = False,
    ) -> None:
        """Advance future native work to a confirmed helper generation."""
        if not isinstance(instance_id, str) or not instance_id:
            raise ValueError("The native helper instance ID must be a non-empty string.")
        if self._generation_context is not None:
            self._generation_context.publish(
                instance_id, previous_replaced=previous_replaced
            )
        else:
            raise UnsupportedClientOperation("native helper generation publication")

    def _adopt_agent_instance(
        self,
        instance_id: str,
        generation_token: object,
        *,
        previous_replaced: bool,
    ) -> None:
        self._agent_instance_id = instance_id
        self._agent_generation_token = generation_token

    @property
    def agent_instance_id(self) -> object:
        return self._agent_instance_id

    @property
    def agent_generation_token(self) -> object:
        return self._agent_generation_token

    def is_agent_generation_current(self, instance_id: object) -> bool:
        return (
            self._generation_context is not None
            and self._generation_context.generation_token == instance_id
            and self._generation_fence is not None
        )

    def require_agent_generation(self, instance_id: object) -> None:
        if self._generation_fence is None:
            raise UnsupportedClientOperation("native helper generation validation")
        self._generation_fence.call(instance_id, lambda: None)

    def bind_agent_manager(self, instance_id: object | None = None):
        if self._generation_context is None:
            raise UnsupportedClientOperation("native helper generation binding")
        return self._generation_context.bind_manager(instance_id)

    @property
    def generation_context(self) -> NativeGenerationContext | None:
        return self._generation_context

    @property
    def _uses_native_discovery(self) -> bool:
        return self.agent_manager is not None

    def client_identity(self, client: Any) -> int | str:
        """Return the public identity used to manage one client."""
        if self._uses_native_discovery:
            client_id = getattr(client, "client_id", None)
            if not isinstance(client_id, str) or not client_id:
                raise ValueError("The native client does not have a valid client ID.")
            return client_id
        window_handle = getattr(client, "window_handle", None)
        if not isinstance(window_handle, int) or isinstance(window_handle, bool):
            raise ValueError("The Windows client does not have a valid window handle.")
        return window_handle

    @property
    def managed_identities(self) -> tuple[int | str, ...]:
        identities = (
            self._managed_client_ids
            if self._uses_native_discovery
            else self._managed_handles
        )
        return tuple(identities)

    def manage_client(
        self,
        identity: int | str,
        *,
        expected_instance_id: object | None = None,
    ):
        """Create and retain one client selected by its public identity."""
        if self._uses_native_discovery:
            assert self._generation_context is not None
            expected = (
                self._agent_generation_token
                if expected_instance_id is None
                else expected_instance_id
            )
            runtime = self._generation_context.bind_manager(expected)
            with runtime.operation():
                if identity in self.managed_identities:
                    for client in self.clients:
                        if self.client_identity(client) == identity:
                            return client
                    raise ValueError("The selected client is already being managed.")

                descriptors = self._list_native_descriptors(_runtime=runtime)
                self._reconcile_quarantined_processes(runtime)
                descriptor = next(
                    (
                        candidate
                        for candidate in descriptors
                        if candidate.get("client_id") == identity
                    ),
                    None,
                )
                if descriptor is None:
                    raise ValueError(
                        "The selected Wizard101 client is no longer available."
                    )
                if self._process_identity(descriptor) in self._quarantined_hook_clients:
                    raise RuntimeError(
                        "The selected process still owns quarantined hooks from a retired "
                        "helper generation. Wait for exact process exit before hooking it "
                        "again."
                    )

                client = self._bind_agent_instance(
                    self.client_cls(self.agent_manager, descriptor)
                )

                def publish_client():
                    if identity in self._managed_client_ids:
                        for existing in self.clients:
                            if self.client_identity(existing) == identity:
                                mark_closed = getattr(client, "_mark_closed", None)
                                if callable(mark_closed):
                                    mark_closed()
                                return existing
                        raise RuntimeError(
                            "The selected client became managed without a live owner."
                        )
                    self._managed_client_ids.append(identity)
                    self.clients.append(client)
                    return client

                try:
                    return runtime.commit(publish_client)
                except BaseException:
                    mark_closed = getattr(client, "_mark_closed", None)
                    if callable(mark_closed):
                        mark_closed()
                    raise

        if identity in self.managed_identities:
            for client in self.clients:
                if self.client_identity(client) == identity:
                    return client
            raise ValueError("The selected client is already being managed.")
        if not isinstance(identity, int) or isinstance(identity, bool):
            raise ValueError("The selected Windows client handle is invalid.")
        client = self.client_cls(identity)
        self._managed_handles.append(identity)

        self.clients.append(client)
        return client

    def release_client(self, client: Any) -> None:
        """Stop managing a client without closing it implicitly."""
        identity = self.client_identity(client)
        cleanup_complete = getattr(client, "cleanup_complete", True)
        needs_native_cleanup = self._uses_native_discovery and (
            not cleanup_complete
            or bool(getattr(client, "has_hook_cleanup_ownership", False))
        )
        if self._uses_native_discovery:
            begin_detach = getattr(client, "begin_detach", None)
            if callable(begin_detach):
                begin_detach()
        if needs_native_cleanup:
            if (
                self._generation_context is not None
                and bool(getattr(client, "has_hook_cleanup_ownership", False))
            ):
                self._generation_context.quarantine_cleanup_owner(client)
        managed = (
            self._managed_client_ids
            if self._uses_native_discovery
            else self._managed_handles
        )
        if identity in managed:
            managed.remove(identity)
        if client in self.clients:
            self.clients.remove(client)
        if (
            self._uses_native_discovery
            and needs_native_cleanup
            and not cleanup_complete
            and client not in self._retired_clients
        ):
            self._retired_clients.append(client)
        if client in self._retired_clients:
            if cleanup_complete:
                self._retired_clients.remove(client)
                self._retired_cleanup_retry_at.pop(client, None)

    @property
    def cleanup_clients(self) -> tuple[Any, ...]:
        """Clients whose teardown ownership is retained, visible or retired."""
        return tuple(dict.fromkeys((*self.clients, *self._retired_clients)))

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
            assert self._generation_context is not None
            runtime = self._generation_context.bind_manager(
                self._agent_generation_token
            )
            with runtime.operation():
                self._refresh_native_clients(add_new=False, _runtime=runtime)
                for client in self.clients:
                    if client.is_foreground:
                        return client
                return None
        for client in self.clients:
            if client.is_foreground:
                return client
        return None

    def _list_native_descriptors(
        self,
        expected_instance_id: object | None = None,
        *,
        _runtime=None,
    ) -> list[dict[str, Any]]:
        expected = (
            self._agent_generation_token
            if expected_instance_id is None
            else expected_instance_id
        )
        if self._generation_context is None:
            raise RuntimeError("Native discovery requires a bound generation fence.")
        runtime = _runtime or self._generation_context.bind_manager(expected)
        with runtime.operation():
            response = runtime.list_clients()
            clients = response.get("clients") if isinstance(response, dict) else None
            if not isinstance(clients, list):
                raise ValueError(
                    "The native agent returned an invalid client discovery response."
                )

            client_ids = set()
            normalized_clients = []
            for descriptor in clients:
                DiscoveredClient.validate_descriptor(descriptor)
                client_id = descriptor.get("client_id")
                if client_id in client_ids:
                    raise ValueError(
                        "The native agent returned an invalid client discovery descriptor."
                    )
                client_ids.add(client_id)
                process = descriptor["process"]
                normalized_process = dict(process)
                normalized_process["identity"] = dict(process["identity"])
                normalized_clients.append(
                    {
                        "client_id": client_id,
                        "process": normalized_process,
                        "is_foreground": descriptor["is_foreground"],
                        "screen_order": descriptor["screen_order"],
                    }
                )
            return normalized_clients

    @staticmethod
    def _process_identity(value: Any) -> tuple[Any, Any, Any] | None:
        process = (
            value.get("process")
            if isinstance(value, dict)
            else getattr(value, "process", None)
        )
        identity = process.get("identity") if isinstance(process, dict) else None
        if not isinstance(identity, dict):
            return None
        path = identity.get("executable_path")
        return (
            identity.get("pid"),
            identity.get("creation_time_100ns"),
            path.casefold() if isinstance(path, str) else path,
        )

    def _release_quarantine_for(self, client: Any) -> None:
        if self._generation_context is not None:
            self._generation_context.release_cleanup_owner(client)

    def _forget_retired_client(self, client: Any) -> None:
        if client in self._retired_clients:
            self._retired_clients.remove(client)
        self._retired_cleanup_retry_at.pop(client, None)

    def _reconcile_quarantined_processes(self, runtime=None) -> None:
        """Release ownership only after an authoritative exact-identity probe."""
        if self._generation_fence is None:
            return
        status_call = getattr(self.agent_manager, "process_identity_status", None)
        if not callable(status_call):
            # Older helpers cannot prove exit independently of top-level
            # windows, so quarantine must remain fail-closed.
            return
        runtime = runtime or self._generation_context.bind_manager(
            self._agent_generation_token
        )
        for identity, owners in tuple(self._quarantined_hook_clients.items()):
            expected_identity = {
                "pid": identity[0],
                "creation_time_100ns": identity[1],
                "executable_path": identity[2],
            }
            with runtime.operation():
                response = runtime.process_identity_status(
                    int(identity[0]),
                    json.dumps(expected_identity, separators=(",", ":")),
                )
                state = response.get("state") if isinstance(response, dict) else None
            if state not in {"exited", "replaced"}:
                continue
            def publish_exit() -> None:
                for client in tuple(owners):
                    confirm_exit = getattr(
                        client,
                        "_confirm_replaced_process_exit",
                        None,
                    )
                    if callable(confirm_exit):
                        confirm_exit()
                self._quarantined_hook_clients.pop(identity, None)
                for client in tuple(owners):
                    if getattr(client, "cleanup_complete", False):
                        assert self._generation_context is not None
                        self._generation_context.release_cleanup_owner(client)

            runtime.commit(publish_exit)

    def _refresh_native_clients(
        self,
        *,
        add_new: bool,
        _runtime=None,
    ) -> List[Any]:
        assert self._generation_context is not None
        runtime = _runtime or self._generation_context.bind_manager(
            self._agent_generation_token
        )
        with runtime.operation():
            descriptors = self._list_native_descriptors(_runtime=runtime)
            self._reconcile_quarantined_processes(runtime)
            missing_client_has_live_session: dict[Any, bool] = {}
            descriptors_by_id = {
                descriptor["client_id"]: descriptor for descriptor in descriptors
            }
            existing_by_id = {
                client.client_id: client
                for client in self.clients
                if isinstance(client, DiscoveredClient)
                or isinstance(getattr(client, "client_id", None), str)
            }
            unmatched_descriptors = {
                self._process_identity(descriptor): descriptor
                for descriptor in descriptors
                if descriptor["client_id"] not in existing_by_id
            }
            for client_id, client in existing_by_id.items():
                if not client.is_running():
                    continue
                descriptor = descriptors_by_id.get(client_id)
                if descriptor is None:
                    descriptor = unmatched_descriptors.get(
                        self._process_identity(client)
                    )
                if descriptor is None:
                    # Native liveness belongs in the drainable operation phase,
                    # never in the short atomic publication callback below.
                    missing_client_has_live_session[client] = (
                        client._has_live_process_session()
                    )
            rebound_ids = {
                descriptor["client_id"]
                for client_id, client in existing_by_id.items()
                if client.is_running()
                for descriptor in (
                    descriptors_by_id.get(client_id)
                    or unmatched_descriptors.get(self._process_identity(client)),
                )
                if descriptor is not None
                and self._process_identity(descriptor) == self._process_identity(client)
            }
            prepared_new_clients = {}
            try:
                if add_new:
                    for descriptor in descriptors:
                        client_id = descriptor["client_id"]
                        if (
                            self._process_identity(descriptor)
                            in self._quarantined_hook_clients
                        ):
                            continue
                        if (
                            client_id in self._managed_client_ids
                            or client_id in rebound_ids
                        ):
                            continue
                        prepared_new_clients[client_id] = self._bind_agent_instance(
                            self.client_cls(self.agent_manager, descriptor)
                        )
                return runtime.commit(
                    self._publish_native_refresh,
                    descriptors,
                    add_new=add_new,
                    missing_client_has_live_session=missing_client_has_live_session,
                    prepared_new_clients=prepared_new_clients,
                )
            except BaseException:
                for client in prepared_new_clients.values():
                    mark_closed = getattr(client, "_mark_closed", None)
                    if callable(mark_closed):
                        mark_closed()
                raise

    def _publish_native_refresh(
        self,
        descriptors: list[dict[str, Any]],
        *,
        add_new: bool,
        missing_client_has_live_session: dict[Any, bool],
        prepared_new_clients: dict[str, Any],
    ) -> List[Any]:
        """Apply one validated discovery snapshot under the fence commit lock."""
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

        unmatched_descriptors = {}
        for descriptor in descriptors:
            identity = self._process_identity(descriptor)
            if (
                identity is not None
                and descriptor.get("client_id") not in existing_by_id
            ):
                unmatched_descriptors[identity] = descriptor
        rebound_ids = set()

        for client_id, client in existing_by_id.items():
            # A detach transaction is terminal for this object even when the
            # same discovery descriptor remains visible while cleanup retries.
            if not client.is_running():
                continue
            descriptor = descriptors_by_id.get(client_id)
            if descriptor is None:
                descriptor = unmatched_descriptors.get(self._process_identity(client))
            if descriptor is None:
                if not missing_client_has_live_session.get(client, False):
                    client._mark_closed()
            else:
                if self._process_identity(descriptor) != self._process_identity(client):
                    client._mark_closed()
                    if client in self.clients:
                        self.clients.remove(client)
                    if client not in self._retired_clients:
                        self._retired_clients.append(client)
                    if client_id in self._managed_client_ids:
                        self._managed_client_ids.remove(client_id)
                    continue
                replacement_id = descriptor["client_id"]
                if replacement_id != client_id:
                    self._managed_client_ids = [
                        replacement_id if managed_id == client_id else managed_id
                        for managed_id in self._managed_client_ids
                    ]
                client._update(descriptor)
                rebound_ids.add(replacement_id)

        new_clients = []
        if add_new:
            for descriptor in descriptors:
                client_id = descriptor.get("client_id")
                if self._process_identity(descriptor) in self._quarantined_hook_clients:
                    continue
                if client_id in self._managed_client_ids or client_id in rebound_ids:
                    continue
                new_client = prepared_new_clients[client_id]
                self._managed_client_ids.append(client_id)
                self.clients.append(new_client)
                new_clients.append(new_client)
        published = set(new_clients)
        for client in prepared_new_clients.values():
            if client not in published:
                mark_closed = getattr(client, "_mark_closed", None)
                if callable(mark_closed):
                    mark_closed()
        return new_clients

    def retire_native_clients(
        self,
        *,
        schedule_cleanup: bool = True,
        cleanup_blocker: str | None = None,
    ) -> tuple[Any, ...]:
        """Atomically hide one native runtime generation and retain cleanup ownership."""
        if not self._uses_native_discovery:
            raise UnsupportedClientOperation("native client generation retirement")

        retiring = tuple(self.clients)
        known_generation = tuple(self.cleanup_clients)
        self.clients.clear()
        self._managed_client_ids.clear()
        for client in known_generation:
            retain_blocker = getattr(client, "retain_cleanup_blocker", None)
            if cleanup_blocker is not None and callable(retain_blocker):
                retain_blocker(cleanup_blocker)
            if schedule_cleanup:
                client._mark_closed()
            else:
                client.begin_detach()
        for client in retiring:
            # Visible clients may still publish a just-opened session after
            # retirement observes them. Retain them unconditionally until the
            # close transaction proves completion.
            if client not in self._retired_clients:
                self._retired_clients.append(client)
        for client in known_generation:
            if (
                client not in retiring
                and not getattr(client, "cleanup_complete", True)
                and client not in self._retired_clients
            ):
                self._retired_clients.append(client)
        # Include obligations that were already retired by an earlier failed
        # detach. They are exactly the L05 state most likely to be missed by a
        # generation change and must block duplicate hook activation too.
        for client in self.cleanup_clients:
            if getattr(client, "has_hook_cleanup_ownership", False):
                assert self._generation_context is not None
                self._generation_context.quarantine_cleanup_owner(client)
        return retiring

    def _retire_for_context_replacement(
        self,
        *,
        schedule_cleanup: bool = True,
        cleanup_blocker: str | None = None,
    ) -> None:
        if self._uses_native_discovery:
            self.retire_native_clients(
                schedule_cleanup=schedule_cleanup,
                cleanup_blocker=cleanup_blocker,
            )

    def get_new_clients(self) -> List[Any]:
        """Return clients discovered since the handler began managing clients."""
        if self._uses_native_discovery:
            return self._refresh_native_clients(add_new=True)

        all_handles = self._legacy_utils().get_all_wizard_handles()
        new_clients = []
        for handle in all_handles:
            if handle not in self._managed_handles:
                new_clients.append(self.manage_client(handle))
        return new_clients

    def remove_dead_clients(self) -> List[Any]:
        """Remove and return clients that are no longer running."""
        if self._uses_native_discovery:
            assert self._generation_context is not None
            runtime = self._generation_context.bind_manager(
                self._agent_generation_token
            )
            with runtime.operation():
                self._refresh_native_clients(add_new=False, _runtime=runtime)
                return runtime.commit(self._publish_dead_client_removal)

        return self._publish_dead_client_removal()

    def _publish_dead_client_removal(self) -> List[Any]:
        clients_proxy = copy(self.clients)
        dead_clients = []
        for client in clients_proxy:
            if not client.is_running():
                dead_clients.append(client)
                self.clients.remove(client)
                self._retired_clients.append(client)
                identity = self.client_identity(client)
                managed = (
                    self._managed_client_ids
                    if self._uses_native_discovery
                    else self._managed_handles
                )
                if identity in managed:
                    managed.remove(identity)
        return dead_clients

    def get_ordered_clients(self) -> List[Any]:
        """Return clients ordered by their top-to-bottom, left-to-right position."""
        if self._uses_native_discovery:
            assert self._generation_context is not None
            runtime = self._generation_context.bind_manager(
                self._agent_generation_token
            )
            with runtime.operation():
                self._refresh_native_clients(add_new=False, _runtime=runtime)
                ordered = sorted(
                    self.clients,
                    key=lambda client: client.screen_order,
                )
                runtime.require_current()
                return ordered
        return self._legacy_utils().order_clients(self.clients)

    async def activate_all_client_hooks(self, wait_for_ready: bool = True):
        """Activate hooks for all legacy clients."""
        async def capture_activation(client):
            try:
                await client.activate_hooks(wait_for_ready=wait_for_ready)
            except BaseException as error:
                return client, error
            return client, None

        hook_tasks = []
        for client in self.clients:
            operation = (
                capture_activation(client)
                if wait_for_ready
                else client.activate_hooks(wait_for_ready=False)
            )
            task = asyncio.create_task(operation)
            hook_tasks.append(task)
            if self._generation_context is not None:
                self._generation_context.register_generation_task(task)
        if wait_for_ready:
            cancelled_by_aggregate = set()

            async def drain_and_rollback_hook_tasks(primary_error):
                await asyncio.gather(*hook_tasks, return_exceptions=True)
                cleanup_errors = []
                successful_clients = []
                for task in hook_tasks:
                    if task.cancelled():
                        continue
                    client, error = task.result()
                    if error is None:
                        successful_clients.append(client)
                    elif error is not primary_error:
                        if task in cancelled_by_aggregate and isinstance(
                            error, asyncio.CancelledError
                        ):
                            preserve_cleanup_errors(
                                primary_error,
                                (
                                    error,
                                    *tuple(getattr(error, "cleanup_errors", ())),
                                ),
                                operation=(
                                    "aggregate client hook activation child drain"
                                ),
                            )
                        else:
                            cleanup_errors.append(error)

                for client in reversed(successful_clients):
                    try:
                        deactivate = getattr(client, "deactivate_hooks", None)
                        if callable(deactivate):
                            await deactivate()
                        else:
                            close = getattr(client, "close", None)
                            if not callable(close):
                                raise RuntimeError(
                                    "An activated client does not expose hook cleanup."
                                )
                            await close()
                            self.release_client(client)
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
                if cleanup_errors:
                    first_error, *secondary_errors = cleanup_errors
                    preserve_cleanup_errors(
                        first_error,
                        secondary_errors,
                        operation="aggregate client hook activation rollback",
                    )
                    raise first_error

            pending = set(hook_tasks)
            try:
                while pending:
                    done, pending = await asyncio.wait(
                        pending,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    failed_task = next(
                        (
                            task
                            for task in hook_tasks
                            if task in done
                            and (
                                task.cancelled()
                                or task.result()[1] is not None
                            )
                        ),
                        None,
                    )
                    if failed_task is not None:
                        if failed_task.cancelled():
                            failed_task.result()
                        raise failed_task.result()[1]
            except BaseException as activation_error:
                for task in hook_tasks:
                    if not task.done():
                        cancelled_by_aggregate.add(task)
                        task.cancel()
                await await_cleanup_preserving_cancellation(
                    drain_and_rollback_hook_tasks(activation_error),
                    activation_error,
                    operation="aggregate client hook activation",
                )
                raise

    async def activate_all_client_mouseless(self):
        """Activate mouseless input for all legacy clients."""
        activated_clients = []
        try:
            for client in self.clients:
                await client.mouse_handler.activate_mouseless()
                activated_clients.append(client)
        except BaseException as activation_error:
            async def rollback_mouseless():
                cleanup_errors = []
                for client in reversed(activated_clients):
                    try:
                        await client.mouse_handler.deactivate_mouseless()
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
                if cleanup_errors:
                    first_error, *secondary_errors = cleanup_errors
                    preserve_cleanup_errors(
                        first_error,
                        secondary_errors,
                        operation="aggregate mouseless rollback",
                    )
                    raise first_error

            await await_cleanup_preserving_cancellation(
                rollback_mouseless(),
                activation_error,
                operation="aggregate mouseless activation",
            )
            raise

    async def close(self):
        """Release resources owned by all managed clients."""
        first_error = None
        for client in tuple(self.clients):
            try:
                await client.close()
            except Exception as error:
                if first_error is None:
                    first_error = error
        if self._uses_native_discovery:
            try:
                await self.retry_retired_cleanup(force=True)
            except Exception as error:
                if first_error is None:
                    first_error = error
        else:
            for client in tuple(self._retired_clients):
                try:
                    await client.close()
                except Exception as error:
                    if first_error is None:
                        first_error = error
                else:
                    self._retired_clients.remove(client)
        if first_error is not None:
            raise first_error

    async def retry_retired_cleanup(self, *, force: bool = False) -> None:
        """Converge retired native cleanup with bounded, single-flight retries."""
        if not self._uses_native_discovery or not self._retired_clients:
            return

        first_error = None
        async with self._retired_cleanup_lock:
            now = time.monotonic()
            for client in tuple(self._retired_clients):
                if (
                    not force
                    and now < self._retired_cleanup_retry_at.get(client, 0.0)
                ):
                    continue
                try:
                    await client.close()
                except Exception as error:
                    self._retired_cleanup_retry_at[client] = (
                        time.monotonic() + self._retired_cleanup_retry_delay
                    )
                    if first_error is None:
                        first_error = error
                else:
                    if getattr(client, "cleanup_complete", True):
                        if client in self._retired_clients:
                            self._retired_clients.remove(client)
                        self._retired_cleanup_retry_at.pop(client, None)
                        self._release_quarantine_for(client)
                    else:
                        error = RuntimeError(
                            "Native client cleanup returned without releasing every resource."
                        )
                        self._retired_cleanup_retry_at[client] = (
                            time.monotonic() + self._retired_cleanup_retry_delay
                        )
                        if first_error is None:
                            first_error = error
        if first_error is not None:
            raise first_error
