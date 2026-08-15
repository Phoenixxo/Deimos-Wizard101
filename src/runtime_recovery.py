"""Recovery helpers for the native Wine agent and delayed client hooks."""

from __future__ import annotations

import asyncio
import inspect
import json
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Hashable, Iterable

from wizwalker.errors import (
    await_cleanup_preserving_cancellation,
    await_critical_operation,
    settle_critical_operation,
)


_RECOVERABLE_LIFECYCLE_CODES = {
    "agent_exited",
    "handshake_failed",
    "health_check_failed",
    "launch_failed",
    "monitoring_failed",
    "stale_recovery_failed",
}
_RECOVERABLE_PROTOCOL_CODES = {"io", "timeout", "transport_error"}
_CHARACTER_NOT_READY_MESSAGES = (
    "has not selected a character yet",
    "has not published its client-object tree yet",
)
_TERMINAL_HOOK_PROCESS_CODES = frozenset(("process_exited", "process_not_found"))


class AutoHookClientNotReady(RuntimeError):
    """A launched client is visible but has not entered a playable character yet."""


class FeatureUnavailableError(RuntimeError):
    """Raised before a feature starts when the selected runtime cannot support it."""

    def __init__(self, feature_name: str, missing_capabilities: set[str]):
        missing = sorted(missing_capabilities)
        self.code = "capability_required"
        self.operation = f"feature.{feature_name.casefold().replace(' ', '_')}"
        self.details = {"missing_capabilities": missing}
        super().__init__(
            f"{feature_name} is not available for this client yet. "
            f"Missing runtime capabilities: {', '.join(missing)}."
        )


class ClientTelemetryTransition(RuntimeError):
    """The selected client changed memory generations during a display read."""


class GenerationTaskDrainTimeout(RuntimeError):
    """Generation-bound tasks did not stop before the recovery deadline."""

    code = "generation_task_drain_timeout"
    operation = "agent.generation.task_drain"


@dataclass(frozen=True)
class GenerationCommandEnvelope:
    generation: object
    command: Any


@dataclass(frozen=True)
class GenerationRuntimeState:
    """Generation-local GUI state after a helper replacement."""

    epoch: int
    paused_task_names: set[str] | None = None
    previous_client_count: int | None = None
    last_known_handle_count: int = 0
    last_prewarm_zone: str | None = None
    sigil_leader_pid: int | None = None
    questing_leader_pid: int | None = None
    freecam_status: bool = False


def reset_generation_runtime_state(
    window_config_applied: set[Any],
    launching_status: dict[Any, Any],
    epoch: int,
) -> GenerationRuntimeState:
    """Clear caches that must never migrate across helper generations."""
    window_config_applied.clear()
    launching_status.clear()
    return GenerationRuntimeState(epoch=epoch)


class GenerationTaggedQueue:
    """Thread-safe GUI queue that stamps commands at producer time."""

    def __init__(self, generation: object = None) -> None:
        self._queue: queue.Queue[GenerationCommandEnvelope] = queue.Queue()
        self._generation = generation
        self._lock = threading.Lock()

    def set_generation(self, generation: object) -> None:
        with self._lock:
            self._generation = generation

    def put(self, command: Any, *args, **kwargs) -> None:
        with self._lock:
            envelope = GenerationCommandEnvelope(self._generation, command)
        self._queue.put(envelope, *args, **kwargs)

    def put_for_generation(
        self,
        command: Any,
        generation: object,
        *args,
        **kwargs,
    ) -> None:
        self._queue.put(
            GenerationCommandEnvelope(generation, command),
            *args,
            **kwargs,
        )

    def put_nowait(self, command: Any) -> None:
        self.put(command, block=False)

    def get_nowait(self) -> GenerationCommandEnvelope:
        return self._queue.get_nowait()

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()


def generation_command_is_current(
    envelope: GenerationCommandEnvelope,
    current_generation: object,
    *,
    recovery_ready: bool,
    generation_agnostic: bool = False,
) -> bool:
    """Reject client commands stamped before replacement publication."""
    return generation_agnostic or (
        recovery_ready and envelope.generation == current_generation
    )


class AgentRecoveryCoordinator:
    """Single-flight ownership for the complete helper replacement transaction."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._ready = True
        self._in_progress = False
        self._active: asyncio.Task[bool] | None = None
        self._shutdown = False

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def in_progress(self) -> bool:
        return self._in_progress

    async def run(self, transaction: Callable[[], Awaitable[bool]]) -> bool:
        async with self._lock:
            if self._shutdown:
                return False
            active = self._active
            if active is None:
                self._in_progress = True
                self._ready = False
                active = asyncio.create_task(self._execute(transaction))
                self._active = active
        # A caller being cancelled must not tear down or outlive the admitted
        # recovery transaction that every concurrent caller joined.
        return await await_critical_operation(
            active,
            operation="shared native recovery transaction",
        )

    async def _execute(self, transaction: Callable[[], Awaitable[bool]]) -> bool:
        current = asyncio.current_task()
        try:
            recovered = bool(await transaction())
            if recovered and not self._shutdown:
                self._ready = True
                return True
            return False
        finally:
            async with self._lock:
                if self._active is current:
                    self._active = None
                    self._in_progress = False

    async def shutdown(self, *, timeout_seconds: float = 5.0) -> bool:
        """Cancel and drain the owned transaction before manager teardown."""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        async with self._lock:
            self._shutdown = True
            self._ready = False
            active = self._active
            if active is None:
                return True
            active.cancel()
        done, _ = await asyncio.wait({active}, timeout=timeout_seconds)
        if not done:
            return False
        try:
            active.result()
        except (asyncio.CancelledError, Exception):
            pass
        return True


class AgentRecoveryRetryDriver:
    """Retry one retained fail-closed transaction with bounded backoff."""

    def __init__(
        self,
        coordinator: AgentRecoveryCoordinator,
        *,
        delays: tuple[float, ...] = (1.0, 2.0, 4.0, 8.0, 10.0),
        delay: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        shutdown_requested: Callable[[], bool] = lambda: False,
    ) -> None:
        if not delays or any(value < 0 for value in delays):
            raise ValueError("Recovery retry delays must be non-negative and non-empty.")
        self._coordinator = coordinator
        self._delays = delays
        self._delay = delay
        self._shutdown_requested = shutdown_requested
        self._active: asyncio.Task[bool] | None = None

    @property
    def active(self) -> asyncio.Task[bool] | None:
        return self._active

    def schedule(
        self,
        transaction: Callable[[], Awaitable[bool]],
        *,
        on_retry: Callable[[int, float], Any] | None = None,
        on_error: Callable[[BaseException], Any] | None = None,
    ) -> asyncio.Task[bool]:
        if self._active is not None and not self._active.done():
            return self._active
        task = asyncio.create_task(
            self._run(transaction, on_retry=on_retry, on_error=on_error)
        )
        self._active = task

        def clear(completed: asyncio.Task[bool]) -> None:
            if self._active is completed:
                self._active = None

        task.add_done_callback(clear)
        return task

    async def _run(
        self,
        transaction: Callable[[], Awaitable[bool]],
        *,
        on_retry: Callable[[int, float], Any] | None,
        on_error: Callable[[BaseException], Any] | None,
    ) -> bool:
        attempt = 0
        while not self._shutdown_requested() and not self._coordinator.ready:
            delay_seconds = self._delays[min(attempt, len(self._delays) - 1)]
            attempt += 1
            if on_retry is not None:
                on_retry(attempt, delay_seconds)
            await self._delay(delay_seconds)
            if self._shutdown_requested():
                return False
            try:
                if await self._coordinator.run(transaction):
                    return True
            except asyncio.CancelledError:
                raise
            except Exception as error:
                if on_error is not None:
                    on_error(error)
        return self._coordinator.ready


async def restart_resilient_task(
    task_name: str,
    completed_task: asyncio.Task[Any],
    tasks: dict[str, asyncio.Task[Any]],
    task_factory: Callable[[], Awaitable[Any]],
    coordinator: AgentRecoveryCoordinator,
    *,
    delay_seconds: float = 0.5,
    delay: Callable[[float], Awaitable[Any]] = asyncio.sleep,
) -> asyncio.Task[Any] | None:
    """Restart only if recovery did not take ownership while we were waiting."""
    if not coordinator.ready or coordinator.in_progress:
        return None
    await delay(delay_seconds)
    if (
        tasks.get(task_name) is not completed_task
        or not coordinator.ready
        or coordinator.in_progress
    ):
        return None
    replacement = asyncio.create_task(task_factory())
    tasks[task_name] = replacement
    return replacement


async def cancel_and_drain_tasks(
    tasks: Iterable[asyncio.Task[Any] | None],
    *,
    timeout_seconds: float = 5.0,
) -> None:
    """Cancel generation-bound work and wait until callbacks cannot publish."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    current = asyncio.current_task()
    pending = tuple(
        dict.fromkeys(
            task
            for task in tasks
            if task is not None and task is not current and not task.done()
        )
    )
    for task in pending:
        task.cancel()
    if pending:
        _, stubborn = await asyncio.wait(pending, timeout=timeout_seconds)
        if stubborn:
            raise GenerationTaskDrainTimeout(
                f"Timed out draining {len(stubborn)} generation-bound task(s); "
                "the helper generation remains fenced."
            )


async def drain_and_restart_snapshot_tasks(
    tasks: Iterable[asyncio.Task[Any] | None],
    restart: Callable[[], Any],
) -> bool:
    """Drain stale client snapshots, then rebuild their group exactly once."""
    active = tuple(
        dict.fromkeys(
            task for task in tasks if task is not None and not task.done()
        )
    )
    if not active:
        return False
    await cancel_and_drain_tasks(active)
    restart()
    return True


async def try_drain_tasks(
    tasks: Iterable[asyncio.Task[Any] | None],
    *,
    timeout_seconds: float = 5.0,
) -> bool:
    """Return false while a fail-closed teardown must retain task ownership."""
    try:
        await cancel_and_drain_tasks(tasks, timeout_seconds=timeout_seconds)
    except GenerationTaskDrainTimeout:
        return False
    return True


async def await_generation_control_dispatch(task: asyncio.Task[Any]) -> bool:
    """Await a tracked control dispatch without killing its persistent loop.

    Recovery cancels generation-bound dispatch children.  ``shield`` prevents
    that child cancellation from canceling the long-lived queue consumer; a
    real cancellation of the consumer still propagates for application close.
    """
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
        return False
    return True


async def rollback_failed_manual_activation(
    client_handler: Any,
    resizing_manager: Any,
    client: Any,
    identity: Hashable,
    *,
    primary_error: BaseException | None = None,
) -> None:
    """Tear down resize hooks before closing and releasing a failed manual hook."""
    async def cleanup_transaction() -> None:
        begin_detach = getattr(client, "begin_detach", None)
        if callable(begin_detach):
            begin_detach()
        resizing_manager.suspend_client(identity)
        await resizing_manager.teardown_client(identity)
        await client.close()
        client_handler.release_client(client)

    if primary_error is None:
        await cleanup_transaction()
        return

    _, cleanup_error = await await_cleanup_preserving_cancellation(
        cleanup_transaction(),
        primary_error,
        operation=f"client {identity} activation",
    )
    if cleanup_error is not None:
        # Keep the activation error as the public failure for ordinary cleanup
        # errors. Cancellation/control-flow dominance is handled by the helper.
        raise primary_error


async def read_consistent_hook_snapshot(
    client: Any,
    read_snapshot: Callable[[], Awaitable[Any]],
) -> Any:
    """Discard a display snapshot if its hook-backed objects changed mid-read."""
    handler = getattr(client, "hook_handler", None)
    if handler is None:
        return await read_snapshot()

    async def generation() -> tuple[int, int]:
        return (
            await handler.read_current_client_base(),
            await handler.read_current_player_base(),
        )

    before = await generation()
    snapshot = await read_snapshot()
    after = await generation()
    if before != after:
        raise ClientTelemetryTransition(
            "Wizard101 changed zones while Deimos was reading client telemetry."
        )
    return snapshot


def client_supports_operations(client: Any, *operation_names: str) -> bool:
    """Return whether a client exposes every operation required by a UI action."""
    for operation_name in operation_names:
        try:
            operation = getattr(client, operation_name)
        except AttributeError:
            return False
        if not callable(operation):
            return False
    return True


def require_agent_capabilities(
    manager: Any,
    feature_name: str,
    *required_capabilities: str,
) -> None:
    """Preserve legacy Windows behavior while gating managed-runtime features."""
    if manager is None or not required_capabilities:
        return
    available = set(manager.capabilities())
    missing = set(required_capabilities) - available
    if missing:
        raise FeatureUnavailableError(feature_name, missing)


def task_is_active(task: Any) -> bool:
    """Treat completed tasks as inactive even when they were not cancelled."""
    return task is not None and not task.done()


async def run_guarded_feature(
    operation: Awaitable[Any],
    *,
    on_failure: Callable[[BaseException], None],
    on_finish: Callable[[], Any] | None = None,
) -> bool:
    """Contain a feature failure so it cannot terminate shared application tasks."""
    try:
        await operation
        return True
    except asyncio.CancelledError:
        raise
    except Exception as error:
        on_failure(error)
        return False
    finally:
        if on_finish is not None:
            finish_result = on_finish()
            if inspect.isawaitable(finish_result):
                await finish_result


def require_auto_hook_character_ready(snapshot: Any) -> None:
    """Reject auto-hooking until read-only telemetry sees a selected character."""
    fields = getattr(snapshot, "fields", None)
    if not isinstance(fields, dict) or "character_identity" not in fields:
        raise ValueError(
            "The read-only telemetry snapshot did not include character identity."
        )

    field = fields["character_identity"]
    if getattr(field, "available", False):
        return

    diagnostic = getattr(field, "error", None)
    technical_message = str(
        getattr(diagnostic, "technical_message", "")
    ).casefold()
    if any(message in technical_message for message in _CHARACTER_NOT_READY_MESSAGES):
        raise AutoHookClientNotReady(
            "Wizard101 is still loading the selected character."
        )

    message = getattr(diagnostic, "message", None)
    raise RuntimeError(
        message or "Deimos could not confirm that this Wizard101 client is ready."
    )


def error_diagnostics(
    error: BaseException,
    *,
    _seen: set[int] | None = None,
) -> dict[str, Any]:
    """Return the structured native context attached to a Python exception."""
    if _seen is None:
        _seen = set()
    if id(error) in _seen:
        return {
            "type": type(error).__name__,
            "message": str(error),
            "repeated": True,
        }
    _seen.add(id(error))
    diagnostics: dict[str, Any] = {
        "type": type(error).__name__,
        "message": str(error),
    }
    for name in (
        "technical_message",
        "code",
        "operation",
        "request_id",
        "native_context",
        "details",
    ):
        value = getattr(error, name, None)
        if value not in (None, "", {}):
            diagnostics[name] = value
    cleanup_errors = tuple(getattr(error, "cleanup_errors", ()))
    if cleanup_errors:
        diagnostics["cleanup_errors"] = [
            error_diagnostics(cleanup_error, _seen=_seen)
            for cleanup_error in cleanup_errors
        ]
    interrupted_error = getattr(error, "interrupted_error", None)
    if isinstance(interrupted_error, BaseException):
        diagnostics["interrupted_error"] = error_diagnostics(
            interrupted_error,
            _seen=_seen,
        )
    return diagnostics


def format_error_diagnostics(error: BaseException) -> str:
    """Format native diagnostics without assuming every value is JSON-native."""
    return json.dumps(error_diagnostics(error), sort_keys=True, default=str)


def is_recoverable_agent_error(error: BaseException) -> bool:
    """Identify connection and lifecycle failures that a restart may repair."""
    error_type = type(error).__name__
    if error_type in {
        "NativeGenerationUnavailable",
        "NativeGenerationDrainTimeout",
        "GenerationTaskDrainTimeout",
    }:
        return True
    code = getattr(error, "code", None)
    if error_type == "AgentLifecycleError":
        return code in _RECOVERABLE_LIFECYCLE_CODES
    if error_type == "AgentProtocolError":
        return code in _RECOVERABLE_PROTOCOL_CODES
    return False


def classify_hook_heartbeat_failure(error: BaseException) -> str:
    """Choose helper replacement, clean process retirement, or hook quarantine."""
    cause = getattr(error, "cause", error)
    if is_recoverable_agent_error(cause):
        return "helper"
    if getattr(cause, "code", None) in _TERMINAL_HOOK_PROCESS_CODES:
        return "process_terminal"
    return "hook_session"


def _instance_id(response: Any) -> str | None:
    if not isinstance(response, dict):
        return None
    identity = response.get("identity")
    if not isinstance(identity, dict):
        return None
    instance_id = identity.get("instance_id")
    return instance_id if isinstance(instance_id, str) and instance_id else None


@dataclass(frozen=True)
class RecoveryOutcome:
    attempted: bool
    recovered: bool
    instance_changed: bool = False
    response: dict[str, Any] | None = None
    error: BaseException | None = None
    reason: str | None = None


class AgentRuntimeRecovery:
    """Serialize and bound attempts to restore an AgentManager connection."""

    def __init__(
        self,
        manager: Any,
        *,
        cooldown_seconds: float = 2.0,
        maximum_attempts: int = 3,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        if maximum_attempts < 1:
            raise ValueError("maximum_attempts must be positive")
        self._manager = manager
        self._cooldown_seconds = cooldown_seconds
        self._maximum_attempts = maximum_attempts
        self._clock = clock
        self._lock = asyncio.Lock()
        self._next_attempt_at = 0.0
        self._attempts = 0
        self._instance_id: str | None = None

    def remember(self, response: Any) -> None:
        instance_id = _instance_id(response)
        if instance_id is not None:
            self._instance_id = instance_id

    @property
    def instance_id(self) -> str | None:
        """The last helper generation confirmed by status or recovery."""
        return self._instance_id

    def confirm_healthy(self) -> None:
        """Reset the recovery budget after a real agent operation succeeds."""
        self._attempts = 0

    async def recover(self, error: BaseException) -> RecoveryOutcome:
        if self._manager is None or not is_recoverable_agent_error(error):
            return RecoveryOutcome(False, False, reason="error is not recoverable")

        async with self._lock:
            now = self._clock()
            if self._attempts >= self._maximum_attempts:
                return RecoveryOutcome(False, False, reason="recovery limit reached")
            if now < self._next_attempt_at:
                return RecoveryOutcome(False, False, reason="recovery cooldown active")

            self._next_attempt_at = now + self._cooldown_seconds
            self._attempts += 1
            loop = asyncio.get_running_loop()
            start_future = loop.run_in_executor(None, self._manager.start)
            try:
                response, cancellation = await settle_critical_operation(
                    start_future,
                    operation="native helper restart",
                )
            except Exception as recovery_error:
                return RecoveryOutcome(
                    True,
                    False,
                    error=recovery_error,
                    reason="agent restart failed",
                )
            if cancellation is not None:
                raise cancellation

            previous_instance = self._instance_id
            current_instance = _instance_id(response)
            if current_instance is None:
                return RecoveryOutcome(
                    True,
                    False,
                    error=ValueError(
                        "The recovered helper agent did not return a valid instance identity."
                    ),
                    reason="agent restart returned invalid identity",
                )
            self._instance_id = current_instance
            return RecoveryOutcome(
                True,
                True,
                instance_changed=(
                    previous_instance is not None
                    and current_instance is not None
                    and previous_instance != current_instance
                ),
                response=response if isinstance(response, dict) else None,
            )


@dataclass(frozen=True)
class AutoHookRetryDecision:
    attempt: int
    retry: bool
    delay_seconds: float | None


@dataclass
class _AutoHookState:
    failures: int
    next_attempt_at: float
    exhausted: bool = False


class AutoHookRetryPolicy:
    """Delay initial hooks and bound retries while a new game client settles."""

    def __init__(
        self,
        *,
        initial_delay_seconds: float = 3.0,
        retry_delays: tuple[float, ...] = (2.0, 5.0, 10.0),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if initial_delay_seconds < 0 or any(delay < 0 for delay in retry_delays):
            raise ValueError("hook retry delays must not be negative")
        self._initial_delay_seconds = initial_delay_seconds
        self._retry_delays = retry_delays
        self._clock = clock
        self._states: dict[Hashable, _AutoHookState] = {}

    def register(self, identity: Hashable) -> None:
        self._states.setdefault(
            identity,
            _AutoHookState(0, self._clock() + self._initial_delay_seconds),
        )

    def ready(self, identity: Hashable) -> bool:
        state = self._states.get(identity)
        if state is None:
            return True
        return not state.exhausted and self._clock() >= state.next_attempt_at

    def record_failure(self, identity: Hashable) -> AutoHookRetryDecision:
        state = self._states.setdefault(identity, _AutoHookState(0, self._clock()))
        state.failures += 1
        retry_index = state.failures - 1
        if retry_index >= len(self._retry_delays):
            state.exhausted = True
            return AutoHookRetryDecision(state.failures, False, None)
        delay = self._retry_delays[retry_index]
        state.next_attempt_at = self._clock() + delay
        return AutoHookRetryDecision(state.failures, True, delay)

    def defer(self, identity: Hashable, delay_seconds: float = 5.0) -> float:
        """Delay a readiness check without consuming the hook-failure budget."""
        if delay_seconds < 0:
            raise ValueError("hook readiness delay must not be negative")
        state = self._states.setdefault(identity, _AutoHookState(0, self._clock()))
        state.next_attempt_at = self._clock() + delay_seconds
        return delay_seconds

    def clear(self, identity: Hashable) -> None:
        self._states.pop(identity, None)

    def clear_all(self) -> None:
        self._states.clear()

    def retain(self, identities: set[Hashable]) -> None:
        self._states = {
            identity: state
            for identity, state in self._states.items()
            if identity in identities
        }
