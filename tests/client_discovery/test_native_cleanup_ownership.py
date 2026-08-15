from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import threading
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"

if str(WIZWALKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WIZWALKER_ROOT))

from wizwalker import ClientHandler, DiscoveredClient  # noqa: E402
from wizwalker.memory import DeimosNativeMemoryBackend  # noqa: E402
from wizwalker.memory.handler import HookHandler  # noqa: E402
from tests.client_discovery.test_client_handler import (  # noqa: E402
    FakeAgentManager,
    NativeWindowError,
    bound_client,
    descriptor,
)
from src.runtime_recovery import try_drain_tasks  # noqa: E402


class _HookHandler:
    def __init__(self) -> None:
        self.close_calls = 0
        self.cancel_calls = 0

    async def close(self) -> None:
        self.close_calls += 1

    def cancel_core_hook_heartbeat(self) -> None:
        self.cancel_calls += 1


class NativeCleanupOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_client_failures_share_stubborn_task_cleanup_barrier(self):
        manager = FakeAgentManager(
            [[descriptor("client-a", 448), descriptor("client-b", 449)]]
        )
        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id=manager.cleanup_instance_id,
        )
        first, second = handler.get_new_clients()
        hook_handlers = []
        for index, client in enumerate((first, second), start=1):
            hooks = _HookHandler()
            hook_handlers.append(hooks)
            client.hook_handler = hooks
            client._hook_session_id = f"hook-{index}"
            client._hook_session_instance_id = client._agent_instance_id
            client.retain_cleanup_blocker("hook_task_drain")
            handler.release_client(client)

        release = asyncio.Event()

        async def stubborn_shared_snapshot():
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue

        shared_task = asyncio.create_task(stubborn_shared_snapshot())
        await asyncio.sleep(0)
        first_barrier = (shared_task,)
        second_barrier = tuple(dict.fromkeys((*first_barrier, shared_task)))
        self.assertFalse(
            await try_drain_tasks(first_barrier, timeout_seconds=0.01)
        )
        self.assertFalse(
            await try_drain_tasks(second_barrier, timeout_seconds=0.01)
        )
        with self.assertRaisesRegex(RuntimeError, "external ownership"):
            await handler.retry_retired_cleanup(force=True)
        self.assertEqual([hooks.close_calls for hooks in hook_handlers], [0, 0])
        self.assertEqual(handler.clients, [])

        release.set()
        await asyncio.wait_for(shared_task, 1)
        self.assertTrue(
            await try_drain_tasks(second_barrier, timeout_seconds=0.01)
        )
        for client in (first, second):
            client.release_cleanup_blocker("hook_task_drain")
        await handler.retry_retired_cleanup(force=True)

        self.assertEqual([hooks.close_calls for hooks in hook_handlers], [1, 1])
        self.assertEqual(handler.cleanup_clients, ())

    async def test_external_task_drain_blocker_prevents_native_teardown_until_exit(self):
        manager = FakeAgentManager([[descriptor("client-a", 448)]])
        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id=manager.cleanup_instance_id,
        )
        client = handler.get_new_clients()[0]
        hook_handler = _HookHandler()
        client.hook_handler = hook_handler
        client._hook_session_id = "hook-a"
        client._hook_session_instance_id = client._agent_instance_id
        client.retain_cleanup_blocker("hook_task_drain")
        handler.release_client(client)

        started = asyncio.Event()
        release = asyncio.Event()

        async def stubborn_client_read():
            started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue

        task = asyncio.create_task(stubborn_client_read())
        await started.wait()
        self.assertFalse(
            await try_drain_tasks((task,), timeout_seconds=0.01)
        )
        with self.assertRaisesRegex(RuntimeError, "external ownership"):
            await handler.retry_retired_cleanup(force=True)
        self.assertEqual(handler.clients, [])
        self.assertIn(client, handler.cleanup_clients)
        self.assertEqual(hook_handler.close_calls, 0)
        self.assertNotIn(("close_process", "hook-a"), manager.calls)

        release.set()
        await asyncio.wait_for(task, 1)
        self.assertTrue(
            await try_drain_tasks((task,), timeout_seconds=0.01)
        )
        client.release_cleanup_blocker("hook_task_drain")
        await handler.retry_retired_cleanup(force=True)

        self.assertEqual(hook_handler.close_calls, 1)
        self.assertNotIn(client, handler.cleanup_clients)

    async def test_unrelated_registration_and_close_progress_during_blocking_rpc(self):
        manager = FakeAgentManager([])
        client = bound_client(manager, descriptor("client-a", 448))
        loop = asyncio.get_running_loop()
        second_closed = threading.Event()
        original_close = manager.close_process_for_instance

        def close_for_instance(session_id, instance_id):
            if session_id == "session-a":
                def register_and_close_second():
                    client._register_session_cleanup(
                        "session-b",
                        kind="telemetry",
                    )
                    asyncio.create_task(client._close_session("session-b"))

                loop.call_soon_threadsafe(register_and_close_second)
                if not second_closed.wait(1):
                    raise TimeoutError("event-loop cleanup callback was deadlocked")
            else:
                second_closed.set()
            return original_close(session_id, instance_id)

        manager.close_process_for_instance = close_for_instance
        client._register_session_cleanup("session-a", kind="telemetry")

        await client._close_session("session-a")
        await asyncio.sleep(0)

        self.assertTrue(second_closed.is_set())
        self.assertEqual(client._pending_session_cleanup_ids, set())

    async def test_known_generation_uses_atomic_generation_checked_close(self):
        class GenerationManager(FakeAgentManager):
            def close_process_for_instance(self, session_id, instance_id):
                self.calls.append(
                    ("close_process_for_instance", session_id, instance_id)
                )

        manager = GenerationManager([[descriptor("client-a", 448)]])
        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-a",
        )
        client = handler.get_new_clients()[0]
        client._register_session_cleanup("session-a", kind="telemetry")

        await client._close_session("session-a")

        self.assertIn(
            ("close_process_for_instance", "session-a", "helper-a"),
            manager.calls,
        )
        self.assertNotIn(("close_process", "session-a"), manager.calls)

    async def test_reused_session_id_keeps_generation_obligations_distinct(self):
        class ReusedSessionManager:
            cleanup_instance_id = "helper-a"

            def __init__(self):
                self.current_instance = "helper-a"
                self.calls = []

            def close_process_for_instance(self, session_id, instance_id):
                if instance_id != self.current_instance:
                    error = RuntimeError("helper generation changed")
                    error.code = "identity_mismatch"
                    raise error
                self.calls.append((self.current_instance, session_id))

        manager = ReusedSessionManager()
        old_client = bound_client(manager, descriptor("client-a", 448))
        old_client._register_session_cleanup("same-id", kind="telemetry")

        manager.current_instance = "helper-b"
        context = old_client._generation_context
        context.begin_replacement(context.generation_token)
        self.assertTrue(context.fence.wait_for_drain(0.1))
        context.publish("helper-b", previous_replaced=True)
        fresh_client = DiscoveredClient(
            manager,
            descriptor("client-b", 449),
            generation_context=context,
        )
        fresh_client._register_session_cleanup("same-id", kind="telemetry")

        await old_client._close_session("same-id")
        await fresh_client._close_session("same-id")

        self.assertEqual(manager.calls, [("helper-b", "same-id")])
        self.assertEqual(old_client._pending_session_cleanup_ids, set())
        self.assertEqual(fresh_client._pending_session_cleanup_ids, set())

    async def test_terminal_session_error_prunes_obligation(self):
        class TerminalManager(FakeAgentManager):
            def close_process(self, session_id):
                self.calls.append(("close_process", session_id))
                raise NativeWindowError("session_not_found")

        manager = TerminalManager([])
        client = bound_client(manager, descriptor("client-a", 448))
        client._register_session_cleanup("gone", kind="telemetry")

        await client._close_session("gone")

        self.assertEqual(client._pending_session_cleanup_ids, set())
        self.assertIsNone(client._last_session_cleanup_error)

    async def test_session_close_is_single_flight_and_idempotent(self):
        started = threading.Event()
        release = threading.Event()

        class BlockingManager(FakeAgentManager):
            def close_process(self, session_id):
                self.calls.append(("close_process", session_id))
                started.set()
                if not release.wait(1):
                    raise TimeoutError("test did not release close")

        manager = BlockingManager([])
        client = bound_client(manager, descriptor("client-a", 448))
        client._register_session_cleanup("session-a", kind="telemetry")

        first = asyncio.create_task(client._close_session("session-a"))
        self.assertTrue(await asyncio.to_thread(started.wait, 1))
        second = asyncio.create_task(client._close_session("session-a"))
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(first, second)

        self.assertEqual(
            manager.calls.count(("close_process", "session-a")),
            1,
        )
        await client._close_session("session-a")
        self.assertEqual(
            manager.calls.count(("close_process", "session-a")),
            1,
        )

    async def test_successful_subresources_are_not_replayed_after_later_failure(self):
        class PartialManager(FakeAgentManager):
            def __init__(self):
                super().__init__([])
                self.fail_telemetry = True

            def close_process(self, session_id):
                self.calls.append(("close_process", session_id))
                if session_id == "telemetry-a" and self.fail_telemetry:
                    raise NativeWindowError("transport_error")

        manager = PartialManager()
        client = bound_client(manager, descriptor("client-a", 448))
        hook_handler = _HookHandler()
        client.hook_handler = hook_handler
        client._hook_session_id = "hook-a"
        client._hook_session_instance_id = client._agent_instance_id
        client._session_id = "telemetry-a"
        client._session_instance_id = client._agent_instance_id

        with self.assertRaisesRegex(NativeWindowError, "transport_error"):
            await client.close()

        self.assertEqual(hook_handler.close_calls, 1)
        self.assertEqual(manager.calls.count(("close_process", "hook-a")), 1)
        self.assertEqual(client._pending_session_cleanup_ids, {"telemetry-a"})

        manager.fail_telemetry = False
        await client.close()
        self.assertEqual(hook_handler.close_calls, 1)
        self.assertEqual(manager.calls.count(("close_process", "hook-a")), 1)
        self.assertEqual(manager.calls.count(("close_process", "telemetry-a")), 2)

    async def test_confirmed_generation_change_prunes_only_read_only_handle(self):
        manager = FakeAgentManager([[descriptor("client-a", 448)]])
        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-old",
        )
        client = handler.get_new_clients()[0]
        client._session_id = "telemetry-old"
        client._session_instance_id = client._agent_instance_id
        client.begin_detach()
        handler._retired_clients.append(client)
        handler.clients.clear()

        handler.note_agent_instance("helper-new", previous_replaced=True)
        await handler.retry_retired_cleanup(force=True)

        self.assertNotIn(client, handler._retired_clients)
        self.assertNotIn(("close_process", "telemetry-old"), manager.calls)

    async def test_hook_cleanup_is_quarantined_after_generation_change(self):
        manager = FakeAgentManager([[descriptor("client-a", 448)]])
        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-old",
        )
        client = handler.get_new_clients()[0]
        hook_handler = _HookHandler()
        client.hook_handler = hook_handler
        client._hook_session_id = "hook-old"
        client._hook_session_instance_id = client._agent_instance_id
        client.begin_detach()
        handler._retired_clients.append(client)
        handler.clients.clear()

        handler.note_agent_instance("helper-new", previous_replaced=True)
        with self.assertRaisesRegex(RuntimeError, "replaced helper generation"):
            await handler.retry_retired_cleanup(force=True)

        self.assertIn(client, handler._retired_clients)
        self.assertIs(client.hook_handler, hook_handler)
        self.assertEqual(hook_handler.close_calls, 0)
        self.assertNotIn(("close_process", "hook-old"), manager.calls)

    async def test_mixed_hook_teardown_fences_each_rpc_during_replacement(self):
        class FeatureOne:
            pass

        class FeatureTwo:
            pass

        class Core:
            pass

        class ReplacingManager:
            cleanup_instance_id = "helper-a"

            def __init__(self):
                self.current_instance = "helper-a"
                self.rpc_calls = []

            @staticmethod
            def _identity_error():
                error = RuntimeError("helper generation changed")
                error.code = "identity_mismatch"
                return error

            def deactivate_feature_hook_for_instance(
                self,
                session_id,
                hook,
                expected_instance_id,
            ):
                if self.current_instance != expected_instance_id:
                    raise self._identity_error()
                self.rpc_calls.append(
                    (self.current_instance, session_id, "feature", hook)
                )
                if hook == "movement_teleport":
                    self.current_instance = "helper-b"
                return {"hook": hook, "active": False}

            def deactivate_core_hooks_for_instance(
                self,
                session_id,
                expected_instance_id,
            ):
                if self.current_instance != expected_instance_id:
                    raise self._identity_error()
                self.rpc_calls.append(
                    (self.current_instance, session_id, "core-all")
                )
                return {"hooks": []}

            def close_process_for_instance(self, session_id, expected_instance_id):
                if self.current_instance != expected_instance_id:
                    raise self._identity_error()
                self.rpc_calls.append(
                    (self.current_instance, session_id, "close")
                )

        manager = ReplacingManager()
        client = bound_client(manager, descriptor("client-a", 448))
        backend = DeimosNativeMemoryBackend(
            manager,
            "reused-session-id",
            expected_instance_id="helper-a",
            generation_fence=client._generation_fence,
            generation_token=client._operation_instance_id,
            generation_context=client._generation_context,
        )
        hook_handler = HookHandler(backend, client)
        hook_handler._active_hooks = {
            FeatureOne: "movement_teleport",
            FeatureTwo: "chat",
            Core: "client",
        }
        hook_handler._agent_feature_hook_exports = {
            "movement_teleport": {"teleport_helper"},
            "chat": {"chat_owner"},
        }
        client.hook_handler = hook_handler
        client._hook_session_id = "reused-session-id"
        client._hook_session_instance_id = "helper-a"

        with self.assertRaisesRegex(RuntimeError, "generation changed"):
            await client.close()

        self.assertEqual(
            manager.rpc_calls,
            [
                (
                    "helper-a",
                    "reused-session-id",
                    "feature",
                    "movement_teleport",
                )
            ],
        )
        self.assertNotIn(FeatureOne, hook_handler._active_hooks)
        self.assertEqual(hook_handler._active_hooks[FeatureTwo], "chat")
        self.assertEqual(hook_handler._active_hooks[Core], "client")
        self.assertIs(client.hook_handler, hook_handler)
        self.assertEqual(client._hook_session_id, "reused-session-id")

    async def test_core_cleanup_never_reaches_replacement_with_reused_session_id(self):
        class Core:
            pass

        class ReusedIdManager:
            cleanup_instance_id = "helper-a"

            def __init__(self):
                self.current_instance = "helper-b"
                self.rpc_calls = []

            def deactivate_core_hooks_for_instance(
                self,
                session_id,
                expected_instance_id,
            ):
                if self.current_instance != expected_instance_id:
                    error = RuntimeError("helper generation changed")
                    error.code = "identity_mismatch"
                    raise error
                self.rpc_calls.append(
                    (self.current_instance, session_id, "core-all")
                )

        manager = ReusedIdManager()
        client = bound_client(manager, descriptor("client-a", 448))
        backend = DeimosNativeMemoryBackend(
            manager,
            "same-id",
            expected_instance_id="helper-a",
            generation_fence=client._generation_fence,
            generation_token=client._operation_instance_id,
            generation_context=client._generation_context,
        )
        hook_handler = HookHandler(backend, client)
        hook_handler._active_hooks = {Core: "client"}
        client.hook_handler = hook_handler
        client._hook_session_id = "same-id"
        client._hook_session_instance_id = "helper-a"

        with self.assertRaisesRegex(RuntimeError, "generation changed"):
            await client.close()

        self.assertEqual(manager.rpc_calls, [])
        self.assertEqual(hook_handler._active_hooks[Core], "client")

    async def test_unverified_generation_change_never_routes_unknown_session(self):
        manager = FakeAgentManager([[descriptor("client-a", 448)]])
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        client._session_id = "unknown-owner"
        client._session_instance_id = client._agent_instance_id
        client.begin_detach()
        handler._retired_clients.append(client)
        handler.clients.clear()

        handler.note_agent_instance("newly-reported", previous_replaced=False)
        with self.assertRaisesRegex(RuntimeError, "unverified helper generation"):
            await handler.retry_retired_cleanup(force=True)

        self.assertIn(client, handler._retired_clients)
        self.assertEqual(client._pending_session_cleanup_ids, {"unknown-owner"})
        self.assertNotIn(("close_process", "unknown-owner"), manager.calls)

    async def test_retired_cleanup_retries_and_releases_only_after_success(self):
        current = descriptor("client-a", 448)

        class RetryManager(FakeAgentManager):
            def __init__(self):
                super().__init__([[current]])
                self.fail_close = True

            def close_process(self, session_id):
                self.calls.append(("close_process", session_id))
                if self.fail_close:
                    raise NativeWindowError("transport_error")

        manager = RetryManager()
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        client._session_id = "telemetry-a"
        client._session_instance_id = client._agent_instance_id
        handler.retire_native_clients()
        await asyncio.gather(
            *tuple(client._lifecycle_cleanup_tasks),
            return_exceptions=True,
        )

        self.assertIn(client, handler._retired_clients)
        manager.fail_close = False
        await handler.retry_retired_cleanup(force=True)
        self.assertNotIn(client, handler._retired_clients)
        self.assertEqual(client._pending_session_cleanup_ids, set())

    async def test_release_cannot_drop_a_retired_cleanup_obligation(self):
        manager = FakeAgentManager([[descriptor("client-a", 448)]])
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        client._register_session_cleanup("still-owned", kind="telemetry")
        client.begin_detach()
        handler.clients.remove(client)
        handler._retired_clients.append(client)

        handler.release_client(client)

        self.assertIn(client, handler._retired_clients)
        self.assertIn(client, handler.cleanup_clients)

    async def test_release_moves_a_detaching_visible_owner_to_retired_cleanup(self):
        manager = FakeAgentManager([[descriptor("client-a", 448)]])
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        client._register_session_cleanup("still-owned", kind="telemetry")
        client.begin_detach()

        handler.release_client(client)

        self.assertNotIn(client, handler.clients)
        self.assertIn(client, handler._retired_clients)
        self.assertIn(client, handler.cleanup_clients)

    async def test_handler_shutdown_aggregates_and_retains_only_failed_owner(self):
        class AggregateManager(FakeAgentManager):
            def close_process(self, session_id):
                self.calls.append(("close_process", session_id))
                if session_id == "failed":
                    raise NativeWindowError("transport_error")

        manager = AggregateManager([])
        handler = ClientHandler(agent_manager=manager)
        failed = bound_client(manager, descriptor("failed", 448))
        succeeded = bound_client(manager, descriptor("succeeded", 544))
        for client, session_id in ((failed, "failed"), (succeeded, "succeeded")):
            handler._bind_agent_instance(client)
            client._session_id = session_id
            client._session_instance_id = client._agent_instance_id
            client.begin_detach()
            handler._retired_clients.append(client)

        with self.assertRaisesRegex(NativeWindowError, "transport_error"):
            await handler.close()

        self.assertIn(failed, handler._retired_clients)
        self.assertNotIn(succeeded, handler._retired_clients)
        self.assertIn(("close_process", "failed"), manager.calls)
        self.assertIn(("close_process", "succeeded"), manager.calls)


class BackgroundCleanupOwnershipTests(unittest.TestCase):
    def test_background_failure_remains_owned_for_later_async_retry(self):
        attempted = threading.Event()

        class BackgroundManager(FakeAgentManager):
            def __init__(self):
                super().__init__([])
                self.fail_close = True

            def close_process(self, session_id):
                self.calls.append(("close_process", session_id))
                attempted.set()
                if self.fail_close:
                    raise NativeWindowError("background transport failure")

        manager = BackgroundManager()
        client = bound_client(manager, descriptor("client-a", 448))
        client._session_id = "background-a"
        client._session_instance_id = client._agent_instance_id
        session_id = client._detach_session()
        client._schedule_session_close(session_id)
        self.assertTrue(attempted.wait(1))

        self.assertEqual(client._pending_session_cleanup_ids, {"background-a"})
        manager.fail_close = False
        asyncio.run(client.close())
        self.assertEqual(client._pending_session_cleanup_ids, set())
        self.assertEqual(
            manager.calls.count(("close_process", "background-a")),
            2,
        )


if __name__ == "__main__":
    unittest.main()
