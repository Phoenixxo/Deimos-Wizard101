from __future__ import annotations

import asyncio
import json
import threading
import time
import weakref
from contextlib import contextmanager
from typing import Any, Iterator


class NativeGenerationUnavailable(RuntimeError):
    """Raised when native work cannot safely select a helper generation."""

    code = "generation_unavailable"
    operation = "agent.generation"


class NativeGenerationDrainTimeout(NativeGenerationUnavailable):
    """Raised when old native calls do not converge before replacement."""

    code = "generation_drain_timeout"


class NativeGenerationFence:
    """Serialize helper replacement against generation-bound native calls.

    The fence is deliberately synchronous because native calls run in executor
    threads.  Closing it rejects work that was queued but had not started yet;
    draining it lets the recovery coroutine wait for calls already dispatched
    to the old helper before replacing the manager's connection.
    """

    def __init__(self, instance_id: object) -> None:
        self._condition = threading.Condition()
        self._instance_id = instance_id
        self._accepting = True
        self._inflight = 0

    @property
    def instance_id(self) -> object:
        with self._condition:
            return self._instance_id

    @contextmanager
    def operation(self, expected_instance_id: object) -> Iterator[None]:
        with self._condition:
            if not self._accepting or expected_instance_id != self._instance_id:
                raise NativeGenerationUnavailable(
                    "This native operation belongs to a retired helper generation. "
                    "Rediscover the Wizard101 client before trying again."
                )
            self._inflight += 1
        try:
            yield
        finally:
            with self._condition:
                self._inflight -= 1
                if self._inflight == 0:
                    self._condition.notify_all()

    def begin_replacement(self, expected_instance_id: object) -> None:
        with self._condition:
            if expected_instance_id != self._instance_id:
                raise NativeGenerationUnavailable(
                    "The helper generation changed before recovery could fence it."
                )
            self._accepting = False

    def wait_for_drain(self, timeout_seconds: float) -> bool:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._inflight:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def publish(self, instance_id: object) -> None:
        if instance_id is None:
            raise ValueError("The native generation token must not be None.")
        with self._condition:
            if self._inflight:
                raise NativeGenerationUnavailable(
                    "A replacement helper cannot be published while old operations remain."
                )
            self._instance_id = instance_id
            self._accepting = True
            self._condition.notify_all()

    def call(
        self,
        expected_instance_id: object,
        call: Any,
        *args,
        allow_retired_result: bool = False,
        **kwargs,
    ):
        with self.operation(expected_instance_id):
            result = call(*args, **kwargs)
            with self._condition:
                if not allow_retired_result and (
                    not self._accepting
                    or expected_instance_id != self._instance_id
                ):
                    raise NativeGenerationUnavailable(
                        "The native operation completed after its helper generation "
                        "was retired; its result was discarded."
                    )
            return result

    def commit(self, expected_instance_id: object, call: Any, *args, **kwargs):
        """Atomically publish local state for one still-current generation.

        Composite operations normally release the condition lock while native
        work runs so recovery can close the generation promptly.  Their final
        in-memory publication is different: replacement must either happen
        before the publication (and reject it) or after it (and retire what it
        published).  Holding the condition for this deliberately short callback
        provides that ordering without letting new native work slip through.
        """
        with self._condition:
            if not self._accepting or expected_instance_id != self._instance_id:
                raise NativeGenerationUnavailable(
                    "This native operation belongs to a retired helper generation. "
                    "Its result was not published."
                )
            return call(*args, **kwargs)


class BoundAgentManager:
    """Manager view permanently bound to one helper-generation token."""

    def __init__(self, manager: Any, fence: NativeGenerationFence, token: object):
        self._manager = manager
        self._fence = fence
        self.generation_token = token

    @contextmanager
    def operation(self) -> Iterator["BoundAgentManager"]:
        """Keep this generation leased through a composite result conversion."""
        with self._fence.operation(self.generation_token):
            yield self
            self.require_current()

    def require_current(self) -> None:
        """Reject publication after this binding's generation was retired."""
        self._fence.call(self.generation_token, lambda: None)

    def commit(self, call: Any, *args, **kwargs):
        """Atomically publish a converted result for this host epoch."""
        return self._fence.commit(self.generation_token, call, *args, **kwargs)

    def __getattr__(self, name: str):
        value = getattr(self._manager, name)
        if not callable(value):
            return value

        def generation_bound_call(*args, **kwargs):
            return self._fence.call(self.generation_token, value, *args, **kwargs)

        return generation_bound_call


class NativeGenerationContext:
    """One shared generation epoch for every route using an AgentManager."""

    def __init__(self, manager: Any, instance_id: object) -> None:
        self._manager_ref = self._manager_reference(manager)
        self._helper_instance_id = instance_id
        self._generation_token = object()
        self.fence = NativeGenerationFence(self._generation_token)
        self._clients: weakref.WeakSet[Any] = weakref.WeakSet()
        self._handlers: weakref.WeakSet[Any] = weakref.WeakSet()
        self._generation_tasks: set[asyncio.Task[Any]] = set()
        self._ownership_lock = threading.Lock()
        self.quarantined_hook_clients: dict[tuple[Any, Any, Any], set[Any]] = {}

    @staticmethod
    def _manager_reference(manager: Any):
        try:
            return weakref.ref(manager)
        except TypeError:
            # PyO3 classes need not opt into Python weak references. The
            # registry explicitly releases this fallback at application exit.
            return lambda: manager

    def owns(self, manager: Any) -> bool:
        return self._manager_ref() is manager

    @property
    def instance_id(self) -> object:
        return self._helper_instance_id

    @property
    def generation_token(self) -> object:
        return self._generation_token

    def register_handler(self, handler: Any) -> None:
        self._handlers.add(handler)

    def register_client(self, client: Any) -> None:
        self._clients.add(client)

    def register_generation_task(self, task: asyncio.Task[Any]) -> None:
        self._generation_tasks.add(task)

        def release(completed: asyncio.Task[Any]) -> None:
            self._generation_tasks.discard(completed)
            if not completed.cancelled():
                completed.exception()

        task.add_done_callback(release)

    async def cancel_and_drain_generation_tasks(
        self,
        timeout_seconds: float,
    ) -> bool:
        current = asyncio.current_task()
        pending = tuple(
            task
            for task in self._generation_tasks
            if task is not current and not task.done()
        )
        for task in pending:
            task.cancel()
        if not pending:
            return True
        _, stubborn = await asyncio.wait(pending, timeout=timeout_seconds)
        return not stubborn

    @staticmethod
    def process_identity(value: Any) -> tuple[Any, Any, Any] | None:
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

    def quarantine_cleanup_owner(self, client: Any) -> None:
        """Strongly retain every hook owner for one exact process identity."""
        identity = self.process_identity(client)
        if identity is None:
            return
        with self._ownership_lock:
            self.quarantined_hook_clients.setdefault(identity, set()).add(client)

    def reserve_hook_owner(
        self,
        client: Any,
        expected_generation_token: object | None = None,
    ) -> bool:
        """Atomically grant one client mutation ownership of an exact process."""
        identity = self.process_identity(client)
        if identity is None:
            raise NativeGenerationUnavailable(
                "Hook activation requires an exact process identity."
            )
        token = (
            self._generation_token
            if expected_generation_token is None
            else expected_generation_token
        )

        def reserve() -> bool:
            with self._ownership_lock:
                owners = self.quarantined_hook_clients.setdefault(identity, set())
                if owners and client not in owners:
                    raise NativeGenerationUnavailable(
                        "The selected process already has a native hook owner. "
                        "Wait for its confirmed cleanup before activating another."
                    )
                if client in owners:
                    return False
                owners.add(client)
                return True

        return self.fence.commit(token, reserve)

    def is_process_quarantined(self, value: Any) -> bool:
        identity = self.process_identity(value)
        return bool(
            identity is not None
            and self.quarantined_hook_clients.get(identity)
        )

    def reconcile_process_identity(self, value: Any) -> bool:
        """Authoritatively release all owners after exact process exit/reuse."""
        identity = self.process_identity(value)
        if identity is None:
            return False
        with self._ownership_lock:
            owners = tuple(self.quarantined_hook_clients.get(identity, ()))
        if not owners:
            return True
        manager = self._manager_ref()
        status_call = getattr(manager, "process_identity_status", None)
        if not callable(status_call):
            return False
        runtime = self.bind_manager(self._generation_token)
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
                return False

            def publish_exit() -> None:
                for client in owners:
                    confirm = getattr(client, "_confirm_replaced_process_exit", None)
                    if callable(confirm):
                        confirm()
                with self._ownership_lock:
                    self.quarantined_hook_clients.pop(identity, None)
                for client in owners:
                    for handler in tuple(self._handlers):
                        forget = getattr(handler, "_forget_retired_client", None)
                        if callable(forget):
                            forget(client)

            runtime.commit(publish_exit)
            return True

    @property
    def registered_clients(self) -> tuple[Any, ...]:
        return tuple(self._clients)

    def bind_manager(self, expected_instance_id: object | None = None) -> BoundAgentManager:
        token = (
            self._generation_token
            if expected_instance_id is None
            else expected_instance_id
        )
        manager = self._manager_ref()
        if manager is None:
            raise NativeGenerationUnavailable(
                "The native manager was released before the operation could run."
            )
        return BoundAgentManager(manager, self.fence, token)

    def call_cleanup(
        self,
        expected_helper_instance_id: object,
        call: Any,
        *args,
        **kwargs,
    ):
        """Admit exact-helper cleanup into the current host drain epoch."""
        if expected_helper_instance_id != self._helper_instance_id:
            raise NativeGenerationUnavailable(
                "Native cleanup belongs to a replaced helper generation; "
                "the old session remains quarantined."
            )
        token = self._generation_token
        return self.fence.call(
            token,
            call,
            *args,
            allow_retired_result=True,
            **kwargs,
        )

    def begin_replacement(
        self,
        expected_instance_id: object,
        *,
        schedule_client_cleanup: bool = True,
        cleanup_blocker: str | None = None,
    ) -> None:
        self.fence.begin_replacement(expected_instance_id)
        for handler in tuple(self._handlers):
            retire = getattr(handler, "_retire_for_context_replacement", None)
            if callable(retire):
                retire(
                    schedule_cleanup=schedule_client_cleanup,
                    cleanup_blocker=cleanup_blocker,
                )
        for client in tuple(self._clients):
            retain_blocker = getattr(client, "retain_cleanup_blocker", None)
            if cleanup_blocker is not None and callable(retain_blocker):
                retain_blocker(cleanup_blocker)
            if bool(getattr(client, "has_hook_cleanup_ownership", False)):
                self.quarantine_cleanup_owner(client)
            if schedule_client_cleanup:
                mark_closed = getattr(client, "_mark_closed", None)
                if callable(mark_closed):
                    mark_closed()
            else:
                begin_detach = getattr(client, "begin_detach", None)
                if callable(begin_detach):
                    begin_detach()

    def close_for_shutdown(self, timeout_seconds: float) -> bool:
        """Reject new native work and prove every admitted operation drained."""
        self.fence.begin_replacement(self._generation_token)
        return self.fence.wait_for_drain(timeout_seconds)

    def release_cleanup_owner(self, client: Any) -> None:
        identity = self.process_identity(client)
        with self._ownership_lock:
            owners = self.quarantined_hook_clients.get(identity)
            if owners is not None:
                owners.discard(client)
                if not owners:
                    self.quarantined_hook_clients.pop(identity, None)
        for handler in tuple(self._handlers):
            forget = getattr(handler, "_forget_retired_client", None)
            if callable(forget):
                forget(client)

    def publish(self, instance_id: str, *, previous_replaced: bool) -> None:
        generation_token = object()
        self.fence.publish(generation_token)
        self._helper_instance_id = instance_id
        self._generation_token = generation_token
        for client in tuple(self._clients):
            note_cleanup_helper = getattr(
                client,
                "_set_cleanup_helper_instance",
                None,
            )
            if callable(note_cleanup_helper):
                note_cleanup_helper(
                    instance_id,
                    previous_replaced=previous_replaced,
                )
        for owners in tuple(self.quarantined_hook_clients.values()):
            for client in tuple(owners):
                retry_cleanup = getattr(
                    client,
                    "_retry_cleanup_after_generation_publish",
                    None,
                )
                if callable(retry_cleanup):
                    retry_cleanup()
        for handler in tuple(self._handlers):
            adopted = getattr(handler, "_adopt_agent_instance", None)
            if callable(adopted):
                adopted(
                    instance_id,
                    self._generation_token,
                    previous_replaced=previous_replaced,
                )


_CONTEXTS_LOCK = threading.Lock()
_MANAGER_CONTEXTS: dict[int, NativeGenerationContext] = {}


def manager_generation_context(
    manager: Any,
    instance_id: object,
) -> NativeGenerationContext:
    """Return the single registered generation context for ``manager``."""
    key = id(manager)
    with _CONTEXTS_LOCK:
        context = _MANAGER_CONTEXTS.get(key)
        if context is not None:
            if context._manager_ref() is None:
                context = NativeGenerationContext(manager, instance_id)
                _MANAGER_CONTEXTS[key] = context
                return context
            if not context.owns(manager):
                raise RuntimeError("Native manager identity registry collision.")
            if context.instance_id != instance_id:
                raise NativeGenerationUnavailable(
                    "The native manager is already bound to a different helper generation."
                )
            return context
        context = NativeGenerationContext(manager, instance_id)
        _MANAGER_CONTEXTS[key] = context
        return context


def release_manager_generation_context(manager: Any) -> None:
    """Release one manager registry entry after all native work is drained."""
    key = id(manager)
    with _CONTEXTS_LOCK:
        context = _MANAGER_CONTEXTS.get(key)
        if context is not None and context.owns(manager):
            _MANAGER_CONTEXTS.pop(key, None)
