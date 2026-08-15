from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
import sys
import threading
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
for import_root in (REPOSITORY_ROOT, WIZWALKER_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


from wizwalker.errors import HookHeartbeatFailure  # noqa: E402
from wizwalker.client_handler import ClientHandler  # noqa: E402
from wizwalker.memory.backends import MemoryBackend  # noqa: E402
from wizwalker.memory.handler import HookHandler  # noqa: E402
from src.runtime_recovery import (  # noqa: E402
    AgentRecoveryCoordinator,
    classify_hook_heartbeat_failure,
)


class HeartbeatBackend(MemoryBackend):
    supports_core_hooks = True
    supports_feature_hooks = True

    def __init__(self):
        self.process = self
        self.session_id = "hook-session"
        self.core_response = {
            "session_id": self.session_id,
            "hooks": [],
        }
        self.feature_response = {
            "session_id": self.session_id,
            "hooks": [],
        }
        self.core_error = None
        self.feature_error = None
        self.core_calls = 0
        self.feature_calls = 0
        self.activation_calls = 0

    def is_running(self):
        return True

    def read_bytes(self, address, size):
        return bytes(size)

    def module_base(self, module_name):
        return None

    def heartbeat_core_hooks(self):
        self.core_calls += 1
        if self.core_error is not None:
            raise self.core_error
        return self.core_response

    def heartbeat_feature_hooks(self):
        self.feature_calls += 1
        if self.feature_error is not None:
            raise self.feature_error
        return self.feature_response

    def activate_core_hook(self, hook):
        self.activation_calls += 1
        return {"hook": hook, "active": True}


class OverlapBackend(HeartbeatBackend):
    supports_feature_hooks = False

    def __init__(self):
        super().__init__()
        self.remote_hooks = set()
        self.hook_ready = True
        self.activation_started = threading.Event()
        self.release_activation = threading.Event()
        self.deactivation_started = threading.Event()
        self.release_deactivation = threading.Event()

    def activate_core_hook(self, hook):
        self.activation_started.set()
        if not self.release_activation.wait(2):
            raise TimeoutError("activation was not released")
        self.remote_hooks.add(hook)
        return {"hook": hook, "active": True}

    def deactivate_core_hook(self, hook):
        self.deactivation_started.set()
        if not self.release_deactivation.wait(2):
            raise TimeoutError("deactivation was not released")
        self.remote_hooks.discard(hook)
        return {"hook": hook, "deactivated": True}

    def read_core_hook_base(self, hook):
        return 0x1000 if self.hook_ready and hook in self.remote_hooks else 0

    def heartbeat_core_hooks(self):
        self.core_calls += 1
        return {
            "session_id": self.session_id,
            "hooks": [
                {
                    "session_id": self.session_id,
                    "hook": hook,
                    "active": True,
                }
                for hook in sorted(self.remote_hooks)
            ],
        }


class HeartbeatClient:
    def __init__(self):
        self._detach_started = False
        self.failures = []
        self.delivered = asyncio.Event()
        self.release = asyncio.Event()

    async def _on_hook_heartbeat_failure(self, failure):
        self.failures.append(failure)
        self.delivered.set()
        await self.release.wait()


class HookHeartbeatRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.backend = HeartbeatBackend()
        self.client = HeartbeatClient()
        self.handler = HookHandler(self.backend, self.client)

    async def asyncTearDown(self):
        self.client.release.set()
        task = self.handler._hook_heartbeat_failure_task
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)
        self.handler.cancel_core_hook_heartbeat()

    async def test_core_transport_failure_notifies_once_and_latches(self):
        error_type = type("AgentProtocolError", (RuntimeError,), {})
        transport = error_type("helper A disconnected")
        transport.code = "transport_error"
        transport.operation = "memory.core_hook.heartbeat_all"
        self.backend.core_error = transport
        self.handler._active_hooks[object] = "client"

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        failure = self.client.failures[0]
        self.assertIsInstance(failure, HookHeartbeatFailure)
        self.assertIs(failure.cause, transport)
        self.assertEqual(classify_hook_heartbeat_failure(failure), "helper")

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        self.assertEqual(len(self.client.failures), 1)
        self.assertEqual(self.backend.core_calls, 1)

    async def test_valid_exact_response_keeps_the_generation_healthy(self):
        self.handler._active_hooks[object] = "player"
        self.backend.core_response = {
            "session_id": self.backend.session_id,
            "hooks": [
                {
                    "session_id": self.backend.session_id,
                    "hook": "player",
                    "active": True,
                }
            ],
        }

        self.assertTrue(await self.handler._heartbeat_core_hooks_once())
        self.assertIsNone(self.handler._last_core_hook_heartbeat_error)
        self.assertEqual(self.client.failures, [])

    async def test_core_only_state_validates_the_empty_feature_scope(self):
        self.handler._active_hooks[object] = "player"
        self.backend.core_response = {
            "session_id": self.backend.session_id,
            "hooks": [
                {
                    "session_id": self.backend.session_id,
                    "hook": "player",
                    "active": True,
                }
            ],
        }

        self.assertTrue(await self.handler._heartbeat_core_hooks_once())
        self.assertEqual(self.backend.core_calls, 1)
        self.assertEqual(self.backend.feature_calls, 1)

        self.backend.feature_response = {
            "session_id": self.backend.session_id,
            "hooks": [
                {
                    "session_id": self.backend.session_id,
                    "hook": "chat",
                    "active": True,
                }
            ],
        }
        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        self.assertEqual(self.client.failures[0].scope, "feature")

    async def test_feature_only_state_validates_the_empty_core_scope(self):
        self.handler._active_hooks[object] = "chat"
        self.backend.feature_response = {
            "session_id": self.backend.session_id,
            "hooks": [
                {
                    "session_id": self.backend.session_id,
                    "hook": "chat",
                    "active": True,
                }
            ],
        }

        self.assertTrue(await self.handler._heartbeat_core_hooks_once())
        self.assertEqual(self.backend.core_calls, 1)
        self.assertEqual(self.backend.feature_calls, 1)

        self.backend.core_response = {
            "session_id": self.backend.session_id,
            "hooks": [
                {
                    "session_id": self.backend.session_id,
                    "hook": "client",
                    "active": True,
                }
            ],
        }
        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        self.assertEqual(self.client.failures[0].scope, "core")

    def test_strict_response_validation_matches_the_rust_contract(self):
        session = self.backend.session_id
        valid_player = {
            "session_id": session,
            "hook": "player",
            "active": True,
        }
        invalid_responses = {
            "bare string": {"session_id": session, "hooks": ["player"]},
            "inactive": {
                "session_id": session,
                "hooks": [{**valid_player, "active": False}],
            },
            "duplicate": {
                "session_id": session,
                "hooks": [valid_player, dict(valid_player)],
            },
            "missing": {"session_id": session, "hooks": []},
            "unexpected": {
                "session_id": session,
                "hooks": [
                    valid_player,
                    {**valid_player, "hook": "client"},
                ],
            },
            "wrong inner session": {
                "session_id": session,
                "hooks": [{**valid_player, "session_id": "wrong"}],
            },
            "wrong outer session": {
                "session_id": "wrong",
                "hooks": [{**valid_player, "session_id": "wrong"}],
            },
            "malformed entry": {
                "session_id": session,
                "hooks": [{"session_id": session, "hook": "player"}],
            },
            "extra outer field": {
                "session_id": session,
                "hooks": [valid_player],
                "extra": True,
            },
        }
        for label, response in invalid_responses.items():
            with self.subTest(label=label):
                with self.assertRaises((ValueError, RuntimeError)):
                    self.handler._validate_hook_heartbeat_response(
                        "core", response, {"player"}
                    )

        self.handler._validate_hook_heartbeat_response(
            "core",
            {"session_id": session, "hooks": []},
            set(),
        )

    async def test_heartbeat_waits_for_activation_publication(self):
        backend = OverlapBackend()
        client = HeartbeatClient()
        client.release.set()
        handler = HookHandler(backend, client)
        activation = asyncio.create_task(
            handler.activate_client_hook(wait_for_ready=False)
        )
        self.assertTrue(
            await asyncio.to_thread(backend.activation_started.wait, 1)
        )
        heartbeat = asyncio.create_task(handler._heartbeat_core_hooks_once())
        await asyncio.sleep(0)
        self.assertFalse(heartbeat.done())
        self.assertEqual(backend.core_calls, 0)

        backend.release_activation.set()
        await activation
        self.assertTrue(await heartbeat)
        self.assertEqual(client.failures, [])
        handler.cancel_core_hook_heartbeat()

    async def test_heartbeat_waits_for_deactivation_publication(self):
        backend = OverlapBackend()
        backend.release_activation.set()
        client = HeartbeatClient()
        client.release.set()
        handler = HookHandler(backend, client)
        await handler.activate_client_hook(wait_for_ready=False)

        deactivation = asyncio.create_task(handler.deactivate_client_hook())
        self.assertTrue(
            await asyncio.to_thread(backend.deactivation_started.wait, 1)
        )
        heartbeat = asyncio.create_task(handler._heartbeat_core_hooks_once())
        await asyncio.sleep(0)
        self.assertFalse(heartbeat.done())

        backend.release_deactivation.set()
        await deactivation
        self.assertTrue(await heartbeat)
        self.assertEqual(client.failures, [])
        self.assertEqual(backend.core_calls, 0)

    async def test_long_readiness_wait_renews_the_stable_hook_snapshot(self):
        backend = OverlapBackend()
        backend.release_activation.set()
        backend.hook_ready = False
        client = HeartbeatClient()
        client.release.set()
        handler = HookHandler(backend, client)
        handler._HOOK_READINESS_HEARTBEAT_INTERVAL = 0.01

        activation = asyncio.create_task(
            handler.activate_client_hook(wait_for_ready=True, timeout=2)
        )
        for _ in range(100):
            if backend.core_calls >= 2:
                break
            await asyncio.sleep(0.01)

        self.assertFalse(activation.done())
        self.assertGreaterEqual(backend.core_calls, 2)
        self.assertEqual(client.failures, [])
        backend.hook_ready = True
        await activation
        self.assertIsNone(handler._last_core_hook_heartbeat_error)
        handler.cancel_core_hook_heartbeat()

    async def test_partial_feature_set_failure_is_isolated_and_actionable(self):
        self.handler._active_hooks[object] = "client"
        self.handler._active_hooks[str] = "chat"
        self.handler._active_hooks[bytes] = "chat_send"
        self.backend.core_response = {
            "session_id": self.backend.session_id,
            "hooks": [
                {
                    "session_id": self.backend.session_id,
                    "hook": "client",
                    "active": True,
                }
            ],
        }
        self.backend.feature_response = {
            "session_id": self.backend.session_id,
            "hooks": [
                {
                    "session_id": self.backend.session_id,
                    "hook": "chat",
                    "active": True,
                }
            ],
        }

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        failure = self.client.failures[0]
        self.assertEqual(failure.scope, "feature")
        self.assertEqual(failure.expected_hooks, {"chat", "chat_send"})
        self.assertEqual(classify_hook_heartbeat_failure(failure), "hook_session")
        self.assertEqual(self.backend.core_calls, 1)
        self.assertEqual(self.backend.feature_calls, 1)

    async def test_invalid_session_response_is_a_hook_session_failure(self):
        self.handler._active_hooks[object] = "player"
        self.backend.core_response = {
            "session_id": "another-session",
            "hooks": [{"hook": "player", "active": True}],
        }

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        failure = self.client.failures[0]
        self.assertEqual(failure.scope, "core")
        self.assertEqual(classify_hook_heartbeat_failure(failure), "hook_session")

    async def test_terminal_process_exit_does_not_request_helper_restart(self):
        terminal = RuntimeError("Wizard101 exited")
        terminal.code = "process_exited"
        self.backend.core_error = terminal
        self.handler._active_hooks[object] = "client"

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        self.assertEqual(
            classify_hook_heartbeat_failure(self.client.failures[0]),
            "process_terminal",
        )

    async def test_detach_race_suppresses_failure_delivery(self):
        self.backend.core_error = RuntimeError("late heartbeat failure")
        self.handler._active_hooks[object] = "client"
        self.client._detach_started = True

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await asyncio.sleep(0)
        self.assertEqual(self.client.failures, [])
        self.assertEqual(self.backend.core_calls, 0)

    async def test_callback_survives_heartbeat_task_cancellation(self):
        self.backend.core_error = RuntimeError("hook lease disappeared")
        self.handler._active_hooks[object] = "client"
        self.handler._ensure_core_hook_heartbeat()

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        callback_task = self.handler._hook_heartbeat_failure_task
        self.handler.cancel_core_hook_heartbeat()
        await asyncio.sleep(0)
        self.assertFalse(callback_task.cancelled())
        self.client.release.set()
        await callback_task

    async def test_latched_failure_rejects_activation_before_callback_finishes(self):
        self.backend.core_error = RuntimeError("hook lease disappeared")
        self.handler._active_hooks[object] = "player"

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        await self.client.delivered.wait()
        self.handler._active_hooks.clear()
        self.handler._base_addrs.clear()
        self.backend.core_error = None

        with self.assertRaisesRegex(RuntimeError, "hook health failed"):
            await self.handler.activate_client_hook(wait_for_ready=False)
        self.assertEqual(self.backend.activation_calls, 0)

    async def test_simultaneous_helper_failures_join_one_recovery(self):
        coordinator = AgentRecoveryCoordinator()
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def transaction():
            nonlocal calls
            calls += 1
            started.set()
            await release.wait()
            return True

        first = asyncio.create_task(coordinator.run(transaction))
        await started.wait()
        second = asyncio.create_task(coordinator.run(transaction))
        await asyncio.sleep(0)
        release.set()
        self.assertEqual(await asyncio.gather(first, second), [True, True])
        self.assertEqual(calls, 1)
        self.assertTrue(coordinator.ready)

    async def test_failed_recovery_leaves_coordinator_fail_closed(self):
        coordinator = AgentRecoveryCoordinator()
        calls = 0

        async def transaction():
            nonlocal calls
            calls += 1
            return False

        self.assertFalse(await coordinator.run(transaction))
        self.assertFalse(coordinator.ready)
        self.assertEqual(calls, 1)

    async def test_client_handler_updates_existing_and_future_callback_routes(self):
        manager = SimpleNamespace(cleanup_instance_id="helper-a")

        class Client:
            cleanup_complete = True
            has_hook_cleanup_ownership = False

            def _set_agent_instance(self, instance_id, *, previous_replaced=False):
                self.instance_id = instance_id

            def _set_generation_fence(self, fence, token, context):
                self.context = context

            def _set_hook_heartbeat_failure_handler(self, handler):
                self.heartbeat_handler = handler

        first_route = object()
        second_route = object()
        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-a",
            hook_heartbeat_failure_handler=first_route,
        )
        existing = handler._bind_agent_instance(Client())
        handler.clients.append(existing)
        self.assertIs(existing.heartbeat_handler, first_route)

        handler.set_hook_heartbeat_failure_handler(second_route)
        future = handler._bind_agent_instance(Client())
        self.assertIs(existing.heartbeat_handler, second_route)
        self.assertIs(future.heartbeat_handler, second_route)


if __name__ == "__main__":
    unittest.main()
