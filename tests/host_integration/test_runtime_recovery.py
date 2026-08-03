from __future__ import annotations

import unittest

from src.runtime_recovery import (
    AgentRuntimeRecovery,
    AutoHookRetryPolicy,
    error_diagnostics,
    is_recoverable_agent_error,
)


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

    def test_stale_client_retry_state_is_pruned(self):
        policy = AutoHookRetryPolicy(initial_delay_seconds=0)
        policy.register("client-1")
        policy.register("client-2")
        policy.retain({"client-2"})

        self.assertTrue(policy.ready("client-1"))
        decision = policy.record_failure("client-2")
        self.assertEqual(decision.attempt, 1)


if __name__ == "__main__":
    unittest.main()
