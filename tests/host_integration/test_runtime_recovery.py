from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from wizwalker.errors import MemoryReadError

from src.runtime_recovery import (
    AgentRuntimeRecovery,
    AutoHookClientNotReady,
    AutoHookRetryPolicy,
    ClientTelemetryTransition,
    FeatureUnavailableError,
    client_supports_operations,
    error_diagnostics,
    is_recoverable_agent_error,
    require_auto_hook_character_ready,
    require_agent_capabilities,
    read_consistent_hook_snapshot,
    run_guarded_feature,
    task_is_active,
)
from src.utils import try_task_coro


AgentLifecycleError = type("AgentLifecycleError", (RuntimeError,), {})
AgentProtocolError = type("AgentProtocolError", (RuntimeError,), {})
MemoryError = type("MemoryError", (RuntimeError,), {})


def native_error(error_type, code: str):
    error = error_type("human-readable message")
    error.code = code
    error.operation = "client.list"
    error.technical_message = "technical context"
    error.details = {"exit_code": "3"}
    return error


def ready(instance_id: str):
    return {
        "disposition": "started",
        "identity": {"instance_id": instance_id},
    }


class FakeManager:
    def __init__(self, responses):
        self.responses = list(responses)
        self.start_calls = 0

    def start(self):
        self.start_calls += 1
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class RuntimeRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_consistent_hook_snapshot_rejects_a_zone_generation_change(self):
        class HookHandler:
            def __init__(self):
                self.client_bases = iter((0x1000, 0x2000))

            async def read_current_client_base(self):
                return next(self.client_bases)

            async def read_current_player_base(self):
                return 0x3000

        client = SimpleNamespace(hook_handler=HookHandler())

        with self.assertRaises(ClientTelemetryTransition):
            await read_consistent_hook_snapshot(
                client,
                AsyncMock(return_value=("Zone/One", "position")),
            )

    async def test_consistent_hook_snapshot_returns_a_stable_generation(self):
        handler = SimpleNamespace(
            read_current_client_base=AsyncMock(return_value=0x1000),
            read_current_player_base=AsyncMock(return_value=0x2000),
        )
        client = SimpleNamespace(hook_handler=handler)
        read = AsyncMock(return_value=("Zone/Two", "position"))

        self.assertEqual(
            await read_consistent_hook_snapshot(client, read),
            ("Zone/Two", "position"),
        )
        self.assertEqual(handler.read_current_client_base.await_count, 2)
        self.assertEqual(handler.read_current_player_base.await_count, 2)

    async def test_memory_read_failures_retry_background_toggle_tasks(self):
        attempts = 0

        async def zone_sensitive_task():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise MemoryReadError("Wizard101 is changing zones.")

        with patch("src.utils.asyncio.sleep", new=AsyncMock()):
            await try_task_coro(zone_sensitive_task, [])

        self.assertEqual(attempts, 2)

    def test_native_error_diagnostics_preserve_actionable_context(self):
        diagnostics = error_diagnostics(
            native_error(AgentLifecycleError, "agent_exited")
        )

        self.assertEqual(diagnostics["type"], "AgentLifecycleError")
        self.assertEqual(diagnostics["code"], "agent_exited")
        self.assertEqual(diagnostics["operation"], "client.list")
        self.assertEqual(diagnostics["technical_message"], "technical context")
        self.assertEqual(diagnostics["details"], {"exit_code": "3"})

    def test_only_agent_transport_and_lifecycle_failures_are_recoverable(self):
        self.assertTrue(
            is_recoverable_agent_error(
                native_error(AgentLifecycleError, "agent_exited")
            )
        )
        self.assertTrue(
            is_recoverable_agent_error(
                native_error(AgentProtocolError, "transport_error")
            )
        )
        self.assertFalse(
            is_recoverable_agent_error(
                native_error(MemoryError, "memory_required_match_not_found")
            )
        )

    async def test_recovery_reports_when_the_agent_instance_changes(self):
        manager = FakeManager([ready("replacement")])
        recovery = AgentRuntimeRecovery(manager, cooldown_seconds=0)
        recovery.remember(ready("original"))

        outcome = await recovery.recover(
            native_error(AgentLifecycleError, "agent_exited")
        )

        self.assertTrue(outcome.attempted)
        self.assertTrue(outcome.recovered)
        self.assertTrue(outcome.instance_changed)
        self.assertEqual(manager.start_calls, 1)

    async def test_recovery_stops_after_bounded_restart_failures(self):
        failures = [RuntimeError("restart failed") for _ in range(3)]
        manager = FakeManager(failures)
        recovery = AgentRuntimeRecovery(
            manager,
            cooldown_seconds=0,
            maximum_attempts=3,
        )
        source = native_error(AgentLifecycleError, "agent_exited")

        for _ in range(3):
            outcome = await recovery.recover(source)
            self.assertTrue(outcome.attempted)
            self.assertFalse(outcome.recovered)

        exhausted = await recovery.recover(source)
        self.assertFalse(exhausted.attempted)
        self.assertEqual(exhausted.reason, "recovery limit reached")
        self.assertEqual(manager.start_calls, 3)

    async def test_successful_restart_needs_a_real_health_confirmation(self):
        manager = FakeManager([ready("same"), ready("same"), ready("same")])
        recovery = AgentRuntimeRecovery(
            manager,
            cooldown_seconds=0,
            maximum_attempts=3,
        )
        recovery.remember(ready("same"))
        source = native_error(AgentLifecycleError, "agent_exited")

        for _ in range(3):
            self.assertTrue((await recovery.recover(source)).recovered)
        self.assertEqual(
            (await recovery.recover(source)).reason,
            "recovery limit reached",
        )

        recovery.confirm_healthy()
        manager.responses.append(ready("same"))
        self.assertTrue((await recovery.recover(source)).recovered)


class AutoHookRetryPolicyTests(unittest.TestCase):
    def test_unsupported_client_operations_are_detected_before_ui_mutation(self):
        client = SimpleNamespace(camera_elastic=lambda: None)

        self.assertTrue(client_supports_operations(client, "camera_elastic"))
        self.assertFalse(
            client_supports_operations(client, "camera_elastic", "camera_freecam")
        )

    def test_completed_toggle_tasks_are_not_treated_as_active(self):
        active = SimpleNamespace(done=lambda: False)
        completed = SimpleNamespace(done=lambda: True)

        self.assertTrue(task_is_active(active))
        self.assertFalse(task_is_active(completed))
        self.assertFalse(task_is_active(None))

    def test_character_readiness_is_checked_before_auto_hooking(self):
        ready_snapshot = SimpleNamespace(
            fields={"character_identity": SimpleNamespace(available=True, error=None)}
        )
        require_auto_hook_character_ready(ready_snapshot)

        loading_snapshot = SimpleNamespace(
            fields={
                "character_identity": SimpleNamespace(
                    available=False,
                    error=SimpleNamespace(
                        message="Wizard101 telemetry is not ready.",
                        technical_message=(
                            "Wizard101 has not selected a character yet."
                        ),
                    ),
                )
            }
        )
        with self.assertRaisesRegex(
            AutoHookClientNotReady,
            "still loading the selected character",
        ):
            require_auto_hook_character_ready(loading_snapshot)

    def test_non_readiness_telemetry_failures_remain_actionable(self):
        snapshot = SimpleNamespace(
            fields={
                "character_identity": SimpleNamespace(
                    available=False,
                    error=SimpleNamespace(
                        message="The telemetry signature is outdated.",
                        technical_message="signature did not match",
                    ),
                )
            }
        )

        with self.assertRaisesRegex(RuntimeError, "signature is outdated"):
            require_auto_hook_character_ready(snapshot)

    def test_new_clients_settle_then_receive_bounded_retries(self):
        now = [100.0]
        policy = AutoHookRetryPolicy(
            initial_delay_seconds=3,
            retry_delays=(2, 5),
            clock=lambda: now[0],
        )
        policy.register("client-1")

        self.assertFalse(policy.ready("client-1"))
        now[0] = 103.0
        self.assertTrue(policy.ready("client-1"))

        first = policy.record_failure("client-1")
        self.assertEqual((first.attempt, first.retry, first.delay_seconds), (1, True, 2))
        self.assertFalse(policy.ready("client-1"))

        now[0] = 105.0
        self.assertTrue(policy.ready("client-1"))
        second = policy.record_failure("client-1")
        self.assertEqual((second.attempt, second.retry, second.delay_seconds), (2, True, 5))

        now[0] = 110.0
        exhausted = policy.record_failure("client-1")
        self.assertEqual((exhausted.attempt, exhausted.retry), (3, False))
        self.assertFalse(policy.ready("client-1"))

    def test_character_readiness_deferral_does_not_consume_failure_budget(self):
        now = [100.0]
        policy = AutoHookRetryPolicy(initial_delay_seconds=0, clock=lambda: now[0])
        policy.register("client-1")

        self.assertEqual(policy.defer("client-1", 5), 5)
        self.assertFalse(policy.ready("client-1"))
        now[0] = 105.0
        self.assertTrue(policy.ready("client-1"))
        self.assertEqual(policy.record_failure("client-1").attempt, 1)

    def test_stale_client_retry_state_is_pruned(self):
        policy = AutoHookRetryPolicy(initial_delay_seconds=0)
        policy.register("client-1")
        policy.register("client-2")
        policy.retain({"client-2"})

        self.assertTrue(policy.ready("client-1"))
        decision = policy.record_failure("client-2")
        self.assertEqual(decision.attempt, 1)


class GuardedFeatureTests(unittest.IsolatedAsyncioTestCase):
    def test_managed_runtime_features_are_capability_gated(self):
        manager = SimpleNamespace(capabilities=lambda: ["memory.mutation.v1"])

        require_agent_capabilities(
            manager,
            "Speed hack",
            "memory.mutation.v1",
        )
        with self.assertRaises(FeatureUnavailableError) as raised:
            require_agent_capabilities(
                manager,
                "Questing",
                "memory.mutation.v1",
                "client.input.v1",
            )

        self.assertEqual(raised.exception.code, "capability_required")
        self.assertEqual(
            raised.exception.details,
            {"missing_capabilities": ["client.input.v1"]},
        )

    def test_legacy_windows_features_do_not_require_agent_capabilities(self):
        require_agent_capabilities(None, "Questing", "client.input.v1")

    async def test_feature_failure_is_reported_and_contained(self):
        failures = []
        finished = []

        async def unsupported_feature():
            raise RuntimeError("feature is not available")

        succeeded = await run_guarded_feature(
            unsupported_feature(),
            on_failure=failures.append,
            on_finish=lambda: finished.append(True),
        )

        self.assertFalse(succeeded)
        self.assertEqual(str(failures[0]), "feature is not available")
        self.assertEqual(finished, [True])

    async def test_feature_cancellation_remains_cancellation(self):
        finished = []

        async def cancelled_feature():
            raise asyncio.CancelledError

        with self.assertRaises(asyncio.CancelledError):
            await run_guarded_feature(
                cancelled_feature(),
                on_failure=lambda error: self.fail(str(error)),
                on_finish=lambda: finished.append(True),
            )

        self.assertEqual(finished, [True])

    async def test_async_feature_cleanup_is_awaited(self):
        finished = []

        async def successful_feature():
            return None

        async def finish():
            await asyncio.sleep(0)
            finished.append(True)

        self.assertTrue(await run_guarded_feature(
            successful_feature(),
            on_failure=lambda error: self.fail(str(error)),
            on_finish=finish,
        ))
        self.assertEqual(finished, [True])


if __name__ == "__main__":
    unittest.main()
