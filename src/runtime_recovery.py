"""Recovery helpers for the native Wine agent and delayed client hooks."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Hashable


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


def error_diagnostics(error: BaseException) -> dict[str, Any]:
    """Return the structured native context attached to a Python exception."""
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
    return diagnostics


def format_error_diagnostics(error: BaseException) -> str:
    """Format native diagnostics without assuming every value is JSON-native."""
    return json.dumps(error_diagnostics(error), sort_keys=True, default=str)


def is_recoverable_agent_error(error: BaseException) -> bool:
    """Identify connection and lifecycle failures that a restart may repair."""
    error_type = type(error).__name__
    code = getattr(error, "code", None)
    if error_type == "AgentLifecycleError":
        return code in _RECOVERABLE_LIFECYCLE_CODES
    if error_type == "AgentProtocolError":
        return code in _RECOVERABLE_PROTOCOL_CODES
    return False


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
            try:
                response = await asyncio.to_thread(self._manager.start)
            except Exception as recovery_error:
                return RecoveryOutcome(
                    True,
                    False,
                    error=recovery_error,
                    reason="agent restart failed",
                )

            previous_instance = self._instance_id
            current_instance = _instance_id(response)
            self._instance_id = current_instance or previous_instance
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
