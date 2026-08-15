from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from wizwalker.errors import MemoryReadError

from src.runtime_recovery import (
    AgentRuntimeRecovery,
    AgentRecoveryCoordinator,
    AgentRecoveryRetryDriver,
    AutoHookClientNotReady,
    AutoHookRetryPolicy,
    ClientTelemetryTransition,
    FeatureUnavailableError,
    GenerationTaskDrainTimeout,
    cancel_and_drain_tasks,
    client_supports_operations,
    drain_and_restart_snapshot_tasks,
    error_diagnostics,
    format_error_diagnostics,
    is_recoverable_agent_error,
    require_auto_hook_character_ready,
    require_agent_capabilities,
    read_consistent_hook_snapshot,
    rollback_failed_manual_activation,
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
    async def test_retained_resize_owner_retries_twice_before_one_replacement(self):
        events = []

        class OrderedManager(FakeManager):
            def start(self):
                events.append("manager.start")
                return super().start()

        manager = OrderedManager([ready("helper-b")])
        recovery = AgentRuntimeRecovery(manager, cooldown_seconds=0)
        recovery.remember(ready("helper-a"))
        coordinator = AgentRecoveryCoordinator()
        retained_resize_owners = {"client-a"}
        cleanup_blockers = {"client-a"}
        attempts = 0

        async def transaction():
            nonlocal attempts
            attempts += 1
            events.append(f"resize.teardown.{attempts}")
            if attempts < 3:
                return False
            retained_resize_owners.clear()
            cleanup_blockers.clear()
            events.append("client.cleanup")
            transport = native_error(AgentProtocolError, "transport_error")
            return (await recovery.recover(transport)).recovered

        self.assertFalse(await coordinator.run(transaction))
        self.assertEqual(retained_resize_owners, {"client-a"})
        self.assertEqual(cleanup_blockers, {"client-a"})
        self.assertEqual(manager.start_calls, 0)

        driver = AgentRecoveryRetryDriver(
            coordinator,
            delays=(0,),
        )
        retry = driver.schedule(transaction)
        self.assertIs(driver.schedule(transaction), retry)
        self.assertTrue(await retry)

        self.assertEqual(attempts, 3)
        self.assertEqual(retained_resize_owners, set())
        self.assertEqual(cleanup_blockers, set())
        self.assertEqual(manager.start_calls, 1)
        self.assertEqual(
            events,
            [
                "resize.teardown.1",
                "resize.teardown.2",
                "resize.teardown.3",
                "client.cleanup",
                "manager.start",
            ],
        )

    async def test_client_timeout_then_helper_failure_cannot_restart_until_drain(self):
        manager = FakeManager([ready("helper-b")])
        recovery = AgentRuntimeRecovery(manager, cooldown_seconds=0)
        recovery.remember(ready("helper-a"))
        retained_blockers = {"client-a"}
        release = asyncio.Event()
        started = asyncio.Event()

        async def stubborn_client_work():
            started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue

        pending = asyncio.create_task(stubborn_client_work())
        await started.wait()
        transport = native_error(AgentProtocolError, "transport_error")

        async def recover_after_pending_drain():
            try:
                await cancel_and_drain_tasks((pending,), timeout_seconds=0.01)
            except GenerationTaskDrainTimeout:
                return False
            retained_blockers.discard("client-a")
            return (await recovery.recover(transport)).recovered

        self.assertFalse(await recover_after_pending_drain())
        self.assertEqual(manager.start_calls, 0)
        self.assertEqual(retained_blockers, {"client-a"})
        self.assertFalse(pending.done())

        release.set()
        await asyncio.wait_for(pending, 1)
        self.assertTrue(await recover_after_pending_drain())
        self.assertEqual(manager.start_calls, 1)
        self.assertEqual(retained_blockers, set())

    def test_client_close_call_paths_use_ordered_resize_cleanup(self):
        source = (Path(__file__).resolve().parents[2] / "Deimos.py").read_text()
        command_prefix = "case deimosgui.GUICommandType."
        for command in ("UnhookClient", "KillClient", "RelaunchClient"):
            segment = source.split(f"{command_prefix}{command}:", 1)[1]
            segment = segment.split(command_prefix, 1)[0]
            self.assertIn("rollback_failed_manual_activation", segment)
            self.assertNotIn("await c.close()", segment)
            if command != "UnhookClient":
                self.assertIn("_failed_manual_hook_handles.add(handle)", segment)

        kill_helper = source.split("def _kill_process_by_handle", 1)[1].split(
            "def _build_hooked_clients_info", 1
        )[0]
        self.assertIn("wizlaunch.kill_instance(", kill_helper)
        self.assertIn("_runtime_binding=runtime_binding", kill_helper)

        auto_cleanup = source.split(
            "async def _release_failed_auto_hook", 1
        )[1].split("async def _auto_hook_client", 1)[0]
        self.assertIn("rollback_failed_manual_activation", auto_cleanup)
        self.assertNotIn("await client.close()", auto_cleanup)

        retry_loop = source.split(
            "last_prewarm_zone = generation_state.last_prewarm_zone", 1
        )[1].split(
            "if walker.clients and foreground_client", 1
        )[0]
        self.assertIn("for failed_client in walker.cleanup_clients:", retry_loop)
        disconnect_cleanup = source.split(
            "# Client process likely closed", 1
        )[1].split("# Record which tasks were active", 1)[0]
        self.assertNotIn(
            "_failed_manual_hook_handles.discard(identity)",
            disconnect_cleanup,
        )

        tool_finish = source.split("async def tool_finish():", 1)[1].split(
            "@logger.catch()", 1
        )[0]
        guard = tool_finish.index("if resize_cleanup_error is not None:")
        close = tool_finish.index("await asyncio.wait_for(p.close()")
        self.assertLess(guard, close)
        self.assertIn("if close_errors:", tool_finish)
        self.assertIn("raise close_errors[0]", tool_finish)

        pre_update = source.split("async def _do_apply_update():", 1)[1].split(
            "async def mass_key_press", 1
        )[0]
        cleanup_failure = pre_update.index(
            "Update cancelled because client hook cleanup did not finish."
        )
        updater_handoff = pre_update.index("updater.apply_and_relaunch(path)")
        self.assertLess(cleanup_failure, updater_handoff)
        self.assertIn("return", pre_update[cleanup_failure:updater_handoff])

        recovery = source.split(
            "async def _recover_agent_runtime", 1
        )[1].split("async def _get_all_wizard_handles", 1)[0]
        retirement = recovery.index("walker.retire_native_clients(")
        reconnect = recovery.index("runtime_recovery.recover(error)")
        self.assertLess(retirement, reconnect)
        self.assertNotIn("walker = ClientHandler", recovery)
        self.assertIn("owned_client_identities()", recovery)
        self.assertIn('retain_cleanup_blocker("resize_hook")', recovery)
        self.assertIn('release_cleanup_blocker("resize_hook")', recovery)
        self.assertIn("_schedule_agent_recovery_retry(error)", recovery)
        self.assertIn("_recovery_retry_driver.schedule(", recovery)
        self.assertIn("for pending_tasks in _pending_hook_failure_tasks.values()", recovery)
        pending_drain = recovery.index(
            "for pending_tasks in _pending_hook_failure_tasks.values()"
        )
        pending_clear = recovery.index("_pending_hook_failure_tasks.clear()")
        self.assertLess(pending_drain, pending_clear)

    def test_hook_heartbeat_failures_are_routed_transactionally(self):
        source = (Path(__file__).resolve().parents[2] / "Deimos.py").read_text()
        callback = source.split(
            "async def _handle_hook_heartbeat_failure", 1
        )[1].split(
            "walker.set_hook_heartbeat_failure_handler", 1
        )[0]
        self.assertIn("classify_hook_heartbeat_failure(failure)", callback)
        helper_branch = callback.split('if disposition == "helper":', 1)[1].split(
            "try:\n            identity", 1
        )[0]
        self.assertIn("await _recover_agent_runtime", helper_branch)
        self.assertIn("return", helper_branch)
        self.assertIn("walker.release_client(client)", callback)
        self.assertIn('retain_cleanup_blocker("hook_task_drain")', callback)
        self.assertIn("await try_drain_tasks(owned_tasks)", callback)
        self.assertIn("_pending_hook_failure_tasks[identity]", callback)
        self.assertIn(
            "for pending_tasks in _pending_hook_failure_tasks.values()",
            callback,
        )
        self.assertIn("rollback_failed_manual_activation", callback)
        self.assertIn("_restart_always_on_tasks", callback)
        self.assertIn("forget_terminated_client(identity)", callback)
        self.assertIn("_failed_hook_handles.add(identity)", callback)
        self.assertIn("GUICommandType.UpdateEntityListData", callback)
        self.assertIn("GUICommandType.UpdateHighlightBox", callback)
        self.assertIn('("Auto PotionStatus", "Disabled")', callback)
        self.assertIn('("No DropsStatus", "Disabled")', callback)
        self.assertIn('("Title", "Client: None")', callback)
        self.assertIn('("Zone", "Zone: ")', callback)
        self.assertIn('("xyz", "Position (XYZ): ")', callback)
        self.assertIn('("pry", "Orientation (PRY): ")', callback)
        self.assertIn("_send_hooked_clients_update()", callback)
        self.assertIn(
            "walker.set_hook_heartbeat_failure_handler(_handle_hook_heartbeat_failure)",
            source,
        )

    async def test_manual_activation_cleanup_retries_before_eventual_release(self):
        events = []

        class ResizingManager:
            def __init__(self):
                self.fail_teardown = True

            def suspend_client(self, identity):
                events.append(("suspend", identity))

            async def teardown_client(self, identity):
                events.append(("teardown", identity))
                if self.fail_teardown:
                    self.fail_teardown = False
                    raise RuntimeError("resize hook still busy")

        class Client:
            def begin_detach(self):
                events.append(("begin_detach", "client"))

            async def close(self):
                events.append(("close", "client"))

        handler = SimpleNamespace(
            release_client=lambda client: events.append(("release", client))
        )
        resizing = ResizingManager()
        client = Client()

        with self.assertRaisesRegex(RuntimeError, "resize hook still busy"):
            await rollback_failed_manual_activation(
                handler, resizing, client, "window-1"
            )
        self.assertEqual(
            events,
            [
                ("begin_detach", "client"),
                ("suspend", "window-1"),
                ("teardown", "window-1"),
            ],
        )

        await rollback_failed_manual_activation(
            handler, resizing, client, "window-1"
        )
        self.assertEqual(
            events[-5:],
            [
                ("begin_detach", "client"),
                ("suspend", "window-1"),
                ("teardown", "window-1"),
                ("close", "client"),
                ("release", client),
            ],
        )

    async def test_manual_activation_retains_primary_when_resize_rollback_fails(self):
        activation_error = RuntimeError("client initialization failed")
        cleanup_error = RuntimeError("resize rollback failed")
        resizing = SimpleNamespace(
            suspend_client=lambda _identity: None,
            teardown_client=AsyncMock(side_effect=cleanup_error),
        )
        client = SimpleNamespace(
            begin_detach=lambda: None,
            close=AsyncMock(),
        )
        handler = SimpleNamespace(release_client=lambda _client: None)

        with self.assertRaisesRegex(
            RuntimeError, "client initialization failed"
        ) as caught:
            await rollback_failed_manual_activation(
                handler,
                resizing,
                client,
                "window-2",
                primary_error=activation_error,
            )

        self.assertIs(caught.exception, activation_error)
        self.assertEqual(caught.exception.cleanup_errors, (cleanup_error,))
        client.close.assert_not_awaited()
        formatted = format_error_diagnostics(caught.exception)
        self.assertIn("client initialization failed", formatted)
        self.assertIn("resize rollback failed", formatted)

    async def test_cleanup_cancellation_remains_control_flow_with_primary_as_cause(self):
        activation_error = RuntimeError("client initialization failed")
        cancellation = asyncio.CancelledError("cleanup interrupted")
        resizing = SimpleNamespace(
            suspend_client=lambda _identity: None,
            teardown_client=AsyncMock(side_effect=cancellation),
        )
        client = SimpleNamespace(begin_detach=lambda: None, close=AsyncMock())

        with self.assertRaises(asyncio.CancelledError) as caught:
            await rollback_failed_manual_activation(
                SimpleNamespace(release_client=lambda _client: None),
                resizing,
                client,
                "window-3",
                primary_error=activation_error,
            )

        self.assertIs(caught.exception, cancellation)
        self.assertIs(caught.exception.__cause__, activation_error)
        self.assertIs(caught.exception.interrupted_error, activation_error)
        client.close.assert_not_awaited()

    async def test_snapshot_tasks_are_drained_before_one_rebuild(self):
        stale_cancelled = asyncio.Event()
        rebuilds = []
        remaining_clients = ["remaining-client"]

        async def stale_snapshot():
            try:
                await asyncio.sleep(60)
            finally:
                stale_cancelled.set()

        stale = asyncio.create_task(stale_snapshot())
        await asyncio.sleep(0)

        def restart():
            rebuilds.append(tuple(remaining_clients))

        self.assertTrue(
            await drain_and_restart_snapshot_tasks((stale,), restart)
        )
        self.assertTrue(stale.done())
        self.assertTrue(stale.cancelled())
        self.assertTrue(stale_cancelled.is_set())
        self.assertEqual(rebuilds, [("remaining-client",)])
        self.assertFalse(
            await drain_and_restart_snapshot_tasks((stale,), restart)
        )
        self.assertEqual(rebuilds, [("remaining-client",)])

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

    def test_nested_cleanup_diagnostics_are_structured_for_user_visible_logs(self):
        primary = RuntimeError("activation failed")
        first_cleanup = RuntimeError("feature rollback failed")
        second_cleanup = RuntimeError("session close failed")
        primary.cleanup_errors = (first_cleanup, second_cleanup)

        diagnostics = error_diagnostics(primary)

        self.assertEqual(
            [item["message"] for item in diagnostics["cleanup_errors"]],
            ["feature rollback failed", "session close failed"],
        )

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

    async def test_recovery_rejects_a_success_response_without_an_identity(self):
        manager = FakeManager([{"disposition": "started"}])
        recovery = AgentRuntimeRecovery(manager, cooldown_seconds=0)
        recovery.remember(ready("original"))

        outcome = await recovery.recover(
            native_error(AgentLifecycleError, "agent_exited")
        )

        self.assertTrue(outcome.attempted)
        self.assertFalse(outcome.recovered)
        self.assertEqual(outcome.reason, "agent restart returned invalid identity")
        self.assertIsInstance(outcome.error, ValueError)
        self.assertEqual(manager.start_calls, 1)

        manager.responses.append(ready("replacement"))
        retried = await recovery.recover(
            native_error(AgentLifecycleError, "agent_exited")
        )
        self.assertTrue(retried.recovered)
        self.assertTrue(retried.instance_changed)

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
