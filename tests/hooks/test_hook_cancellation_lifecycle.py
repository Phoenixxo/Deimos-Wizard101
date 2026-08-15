from __future__ import annotations

import asyncio
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wizwalker.extensions.wizsprinter.resolution_hook import ResolutionForcer
from wizwalker.client_handler import ClientHandler
from wizwalker.errors import await_cleanup_preserving_cancellation
from wizwalker.memory.backends import MemoryBackend
from wizwalker.memory.handler import HookHandler
from wizwalker.memory.hooks import ChatSendHook, ClientHook, MemoryHook

from src.runtime_recovery import (
    AgentRecoveryCoordinator,
    AgentRuntimeRecovery,
    rollback_failed_manual_activation,
)

from tests.hooks.test_core_hook_compatibility import (
    AgentCoreHookBackend,
    BlockingHookManager,
    bound_client,
    descriptor,
)
from tests.hooks.test_feature_hook_compatibility import AgentFeatureHookBackend


async def wait_for_thread_event(event: threading.Event) -> None:
    ready = await asyncio.to_thread(event.wait, 2)
    if not ready:
        raise TimeoutError("test synchronization event was not reached")


class HookCancellationLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_pre_rpc_cancellation_never_publishes_or_dispatches(self):
        backend = AgentFeatureHookBackend()
        handler = HookHandler(backend, client=object())
        lock_held = asyncio.Event()
        release_lock = asyncio.Event()

        async def hold_lifecycle_lock():
            async with handler._close_lock:
                lock_held.set()
                await release_lock.wait()

        holder = asyncio.create_task(hold_lifecycle_lock())
        await lock_held.wait()
        activation = asyncio.create_task(handler.activate_chat_send_hook())
        await asyncio.sleep(0)
        activation.cancel("cancelled before rpc")
        release_lock.set()

        with self.assertRaises(asyncio.CancelledError):
            await activation
        await holder

        self.assertEqual(backend.calls, [])
        self.assertEqual(handler._active_hooks, {})

    async def test_inflight_feature_rpc_settles_before_repeated_cancel_rollback(self):
        backend = AgentFeatureHookBackend()
        activation_started = threading.Event()
        release_activation = threading.Event()
        cleanup_started = threading.Event()
        release_cleanup = threading.Event()

        def activate(hook):
            activation_started.set()
            if not release_activation.wait(2):
                raise TimeoutError("activation was not released")
            backend.active.add(hook)
            return {"hook": hook, "active": True}

        def deactivate(hook):
            cleanup_started.set()
            if not release_cleanup.wait(2):
                raise TimeoutError("cleanup was not released")
            backend.active.discard(hook)
            return {"hook": hook, "deactivated": True}

        backend.activate_feature_hook = activate
        backend.deactivate_feature_hook = deactivate
        handler = HookHandler(backend, client=object())
        activation = asyncio.create_task(handler.activate_chat_send_hook())

        await wait_for_thread_event(activation_started)
        activation.cancel("first cancellation")
        await asyncio.sleep(0.02)
        self.assertFalse(cleanup_started.is_set())

        release_activation.set()
        await wait_for_thread_event(cleanup_started)
        activation.cancel("second cancellation")
        release_cleanup.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("first cancellation",))
        self.assertEqual(backend.active, set())
        self.assertNotIn(ChatSendHook, handler._active_hooks)
        self.assertIsNone(handler._core_hook_heartbeat_task)

    async def test_cancelled_feature_cleanup_failure_remains_owned_and_diagnostic(self):
        backend = AgentFeatureHookBackend()
        activation_started = threading.Event()
        release_activation = threading.Event()
        cleanup_error = RuntimeError("cancel rollback failed")

        def activate(hook):
            activation_started.set()
            if not release_activation.wait(2):
                raise TimeoutError("activation was not released")
            backend.active.add(hook)
            return {"hook": hook, "active": True}

        def deactivate(_hook):
            raise cleanup_error

        backend.activate_feature_hook = activate
        backend.deactivate_feature_hook = deactivate
        handler = HookHandler(backend, client=object())
        activation = asyncio.create_task(handler.activate_chat_send_hook())

        await wait_for_thread_event(activation_started)
        activation.cancel("cancel activation")
        release_activation.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("cancel activation",))
        self.assertEqual(caught.exception.cleanup_errors, (cleanup_error,))
        self.assertEqual(handler._active_hooks.get(ChatSendHook), "chat_send")
        self.assertEqual(backend.active, {"chat_send"})

    async def test_readiness_cancellation_removes_core_hook_and_heartbeat(self):
        backend = AgentCoreHookBackend()
        backend.bases["client"] = 0
        handler = HookHandler(backend, client=object())
        activation = asyncio.create_task(
            handler.activate_client_hook(wait_for_ready=True)
        )

        for _ in range(100):
            if "client" in backend.active:
                break
            await asyncio.sleep(0.001)
        self.assertIn("client", backend.active)

        activation.cancel("readiness cancelled")
        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("readiness cancelled",))
        self.assertEqual(backend.active, set())
        self.assertNotIn(ClientHook, handler._active_hooks)
        self.assertIsNone(handler._core_hook_heartbeat_task)

    async def test_readiness_work_is_drained_before_hook_rollback(self):
        backend = AgentFeatureHookBackend()
        readiness_started = asyncio.Event()
        readiness_drained = asyncio.Event()
        rollback_observed_drained_work = []
        original_deactivate = backend.deactivate_feature_hook

        def deactivate(hook):
            rollback_observed_drained_work.append(readiness_drained.is_set())
            return original_deactivate(hook)

        backend.deactivate_feature_hook = deactivate
        handler = HookHandler(backend, client=object())

        async def never_ready():
            readiness_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                readiness_drained.set()

        activation = asyncio.create_task(
            handler._activate_agent_feature_hook(
                ChatSendHook,
                "chat_send",
                {},
                initialize=never_ready,
            )
        )
        await readiness_started.wait()
        activation.cancel("readiness owner cancelled")

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("readiness owner cancelled",))
        self.assertTrue(readiness_drained.is_set())
        self.assertEqual(rollback_observed_drained_work, [True])
        self.assertEqual(backend.active, set())
        self.assertIsNone(handler._core_hook_heartbeat_task)

    async def test_readiness_drain_failure_is_attached_to_cancellation(self):
        backend = AgentFeatureHookBackend()
        readiness_started = asyncio.Event()
        drain_error = RuntimeError("readiness cancellation cleanup failed")
        handler = HookHandler(backend, client=object())

        async def failing_cancel_drain():
            readiness_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                raise drain_error

        activation = asyncio.create_task(
            handler._activate_agent_feature_hook(
                ChatSendHook,
                "chat_send",
                {},
                initialize=failing_cancel_drain,
            )
        )
        await readiness_started.wait()
        activation.cancel("readiness cancelled with drain failure")

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(
            caught.exception.args,
            ("readiness cancelled with drain failure",),
        )
        self.assertIn(drain_error, caught.exception.cleanup_errors)
        self.assertEqual(backend.active, set())

    async def test_readiness_preserves_cancelled_child_diagnostics(self):
        backend = AgentFeatureHookBackend()
        readiness_started = asyncio.Event()
        child_cleanup_error = RuntimeError("admitted readiness rpc cleanup failed")
        child_cancellation = asyncio.CancelledError("readiness child cancelled")
        child_cancellation.cleanup_errors = (child_cleanup_error,)
        handler = HookHandler(backend, client=object())

        async def diagnostic_cancel():
            readiness_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                raise child_cancellation

        activation = asyncio.create_task(
            handler._activate_agent_feature_hook(
                ChatSendHook,
                "chat_send",
                {},
                initialize=diagnostic_cancel,
            )
        )
        await readiness_started.wait()
        activation.cancel("readiness owner cancelled")

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("readiness owner cancelled",))
        self.assertIn(child_cancellation, caught.exception.cleanup_errors)
        self.assertIn(child_cleanup_error, caught.exception.cleanup_errors)
        self.assertEqual(backend.active, set())

    async def test_aggregate_core_rpc_cancellation_rolls_back_every_mapping(self):
        backend = AgentCoreHookBackend()
        activation_started = threading.Event()
        release_activation = threading.Event()

        def activate_all():
            activation_started.set()
            if not release_activation.wait(2):
                raise TimeoutError("aggregate activation was not released")
            backend.active.update(
                {"client", "player", "quest", "player_stat", "root_window", "render_context"}
            )
            return {"hooks": sorted(backend.active)}

        backend.activate_core_hooks = activate_all
        handler = HookHandler(backend, client=object())
        activation = asyncio.create_task(
            handler.activate_all_hooks(wait_for_ready=False)
        )
        await wait_for_thread_event(activation_started)
        activation.cancel("aggregate cancelled")
        release_activation.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("aggregate cancelled",))
        self.assertEqual(backend.active, set())
        self.assertEqual(handler._active_hooks, {})
        self.assertEqual(handler._base_addrs, {})
        self.assertIsNone(handler._core_hook_heartbeat_task)

    async def test_legacy_partial_hook_cleanup_drains_under_repeated_cancellation(self):
        handler = HookHandler(AgentCoreHookBackend(), client=object())
        hook_started = asyncio.Event()
        cleanup_started = asyncio.Event()
        release_cleanup = asyncio.Event()

        class PartialHook:
            live = False

            async def hook(self):
                self.live = True
                hook_started.set()
                await asyncio.Event().wait()

            async def unhook(self):
                cleanup_started.set()
                await release_cleanup.wait()
                self.live = False

        hook = PartialHook()
        activation = asyncio.create_task(
            handler._activate_legacy_hook(PartialHook, hook, {})
        )
        await hook_started.wait()
        activation.cancel("legacy cancellation")
        await cleanup_started.wait()
        activation.cancel("repeated cancellation")
        release_cleanup.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("legacy cancellation",))
        self.assertFalse(hook.live)
        self.assertNotIn(PartialHook, handler._active_hooks)

    async def test_inflight_allocation_is_published_to_cleanup_before_cancellation(self):
        class BlockingAllocationBackend(MemoryBackend):
            supports_allocation = True

            def __init__(self):
                self.process = self
                self.allocation_started = threading.Event()
                self.release_allocation = threading.Event()
                self.freed = []

            def is_running(self):
                return True

            def allocate(self, _size):
                self.allocation_started.set()
                if not self.release_allocation.wait(2):
                    raise TimeoutError("allocation was not released")
                return 0xCAFE

            def free(self, address):
                self.freed.append(address)

        class AllocationHook(MemoryHook):
            async def hook(self):
                await self.alloc(8)

        backend = BlockingAllocationBackend()
        handler = HookHandler(backend, client=object())
        hook = AllocationHook(handler)
        activation = asyncio.create_task(
            handler._activate_legacy_hook(AllocationHook, hook, {})
        )
        await wait_for_thread_event(backend.allocation_started)
        activation.cancel("allocation cancelled")
        backend.release_allocation.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("allocation cancelled",))
        self.assertEqual(backend.freed, [0xCAFE])
        self.assertEqual(hook._allocated_addresses, [])
        self.assertNotIn(AllocationHook, handler._active_hooks)

    async def test_cancellation_during_hook_session_open_closes_late_session(self):
        class BlockingOpenManager(BlockingHookManager):
            def __init__(self):
                super().__init__()
                self.open_started = threading.Event()
                self.release_open = threading.Event()

            def open_hook_process(self, pid, expected_identity_json=None):
                self.open_started.set()
                if not self.release_open.wait(2):
                    raise TimeoutError("session open was not released")
                return {"session_id": f"hook-{pid}"}

        manager = BlockingOpenManager()
        client = bound_client(manager, descriptor("client-a", 448))
        opening = asyncio.create_task(client._ensure_hook_handler())
        await wait_for_thread_event(manager.open_started)
        opening.cancel("session construction cancelled")
        manager.release_open.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await opening

        self.assertEqual(
            caught.exception.args,
            ("session construction cancelled",),
        )
        self.assertEqual(manager.closed_sessions, ["hook-448"])
        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertEqual(client._pending_session_cleanup_ids, set())
        self.assertTrue(client.cleanup_complete)

    async def test_resize_install_cancellation_drains_both_partial_hooks(self):
        second_hook_started = asyncio.Event()
        cleanup_started = asyncio.Event()
        release_cleanup = asyncio.Event()
        live_hooks = set()

        class FakeSetModeHook:
            def __init__(self, _handler):
                pass

            async def hook(self):
                live_hooks.add("setmode")

            async def unhook(self):
                live_hooks.discard("setmode")

        class FakeVideoHook:
            def __init__(self, _handler):
                pass

            async def hook(self):
                live_hooks.add("video")
                second_hook_started.set()
                await asyncio.Event().wait()

            async def unhook(self):
                cleanup_started.set()
                await release_cleanup.wait()
                live_hooks.discard("video")

        handler = SimpleNamespace(_check_for_autobot=lambda: asyncio.sleep(0))
        forcer = ResolutionForcer(SimpleNamespace(hook_handler=handler))
        with (
            patch(
                "wizwalker.extensions.wizsprinter.resolution_hook.SetModeResHook",
                FakeSetModeHook,
            ),
            patch(
                "wizwalker.extensions.wizsprinter.resolution_hook.VideoManagerHook",
                FakeVideoHook,
            ),
        ):
            installing = asyncio.create_task(forcer.install())
            await second_hook_started.wait()
            installing.cancel("resize install cancelled")
            await cleanup_started.wait()
            installing.cancel("resize cleanup cancelled again")
            release_cleanup.set()

            with self.assertRaises(asyncio.CancelledError) as caught:
                await installing

        self.assertEqual(caught.exception.args, ("resize install cancelled",))
        self.assertEqual(live_hooks, set())
        self.assertFalse(forcer.installed)

    async def test_no_wait_activation_cleanup_ignores_repeated_cancellation(self):
        cleanup_started = asyncio.Event()
        release_cleanup = asyncio.Event()
        events = []

        class ResizingManager:
            def suspend_client(self, identity):
                events.append(("suspend", identity))

            async def teardown_client(self, identity):
                events.append(("teardown", identity))
                cleanup_started.set()
                await release_cleanup.wait()

        class Client:
            def begin_detach(self):
                events.append(("begin_detach", "client"))

            async def close(self):
                events.append(("close", "client"))

        client = Client()
        handler = SimpleNamespace(
            release_client=lambda released: events.append(("release", released))
        )
        primary = asyncio.CancelledError("activation owner cancelled")

        async def owned_activation():
            try:
                raise primary
            except BaseException as error:
                await rollback_failed_manual_activation(
                    handler,
                    ResizingManager(),
                    client,
                    "window-4",
                    primary_error=error,
                )
                raise

        activation = asyncio.create_task(owned_activation())
        await cleanup_started.wait()
        activation.cancel("cleanup cancellation")
        await asyncio.sleep(0)
        activation.cancel("cleanup cancellation repeated")
        release_cleanup.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertIs(caught.exception, primary)
        self.assertEqual(
            events,
            [
                ("begin_detach", "client"),
                ("suspend", "window-4"),
                ("teardown", "window-4"),
                ("close", "client"),
                ("release", client),
            ],
        )

    async def test_recovery_restart_settles_before_repeated_cancellation(self):
        restart_started = threading.Event()
        release_restart = threading.Event()

        class BlockingManager:
            start_calls = 0

            def start(self):
                self.start_calls += 1
                restart_started.set()
                if not release_restart.wait(2):
                    raise TimeoutError("restart was not released")
                return {
                    "disposition": "started",
                    "identity": {"instance_id": "helper-b"},
                }

        agent_error_type = type("AgentLifecycleError", (RuntimeError,), {})
        agent_error = agent_error_type("helper exited")
        agent_error.code = "agent_exited"
        manager = BlockingManager()
        recovery = AgentRuntimeRecovery(manager, cooldown_seconds=0)
        restarting = asyncio.create_task(recovery.recover(agent_error))

        await wait_for_thread_event(restart_started)
        restarting.cancel("first restart cancellation")
        await asyncio.sleep(0)
        restarting.cancel("second restart cancellation")
        release_restart.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await restarting

        self.assertEqual(caught.exception.args, ("first restart cancellation",))
        self.assertEqual(manager.start_calls, 1)

    async def test_cleanup_completion_race_keeps_owner_cancellation_dominant(self):
        cleanup_started = asyncio.Event()
        release_cleanup = asyncio.Event()
        primary = RuntimeError("activation failed")

        async def cleanup():
            cleanup_started.set()
            await release_cleanup.wait()

        async def activation_owner():
            await await_cleanup_preserving_cancellation(
                cleanup(),
                primary,
                operation="completion race cleanup",
            )
            raise primary

        owner = asyncio.create_task(activation_owner())
        await cleanup_started.wait()
        release_cleanup.set()
        asyncio.get_running_loop().call_soon(
            owner.cancel,
            "owner cancellation at cleanup completion",
        )

        with self.assertRaises(asyncio.CancelledError) as caught:
            await owner

        self.assertEqual(
            caught.exception.args,
            ("owner cancellation at cleanup completion",),
        )
        self.assertIs(caught.exception.__cause__, primary)

    async def test_aggregate_client_hook_cancellation_drains_every_child(self):
        handler = ClientHandler(client_cls=object)
        first_finished = asyncio.Event()
        second_started = asyncio.Event()
        second_drained = asyncio.Event()
        cleanup_events = []

        class Client:
            def __init__(self, index, *, blocks=False):
                self.window_handle = 100 + index
                self.blocks = blocks

            async def activate_hooks(self, **_kwargs):
                if not self.blocks:
                    first_finished.set()
                    return
                second_started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    second_drained.set()

            async def close(self):
                cleanup_events.append(("close", self.window_handle))

        first = Client(0)
        second = Client(1, blocks=True)
        handler.clients = [first, second]
        handler._managed_handles = [first.window_handle, second.window_handle]
        activation = asyncio.create_task(
            handler.activate_all_client_hooks(wait_for_ready=True)
        )
        await asyncio.gather(first_finished.wait(), second_started.wait())
        activation.cancel("aggregate hook owner cancelled")
        activation.cancel("aggregate hook owner cancelled again")

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(
            caught.exception.args,
            ("aggregate hook owner cancelled",),
        )
        self.assertTrue(second_drained.is_set())
        self.assertEqual(cleanup_events, [("close", first.window_handle)])
        self.assertEqual(handler.clients, [second])

    async def test_aggregate_client_hook_failure_rolls_back_successful_sibling(self):
        handler = ClientHandler(client_cls=object)
        failure = RuntimeError("second client activation failed")
        first_finished = asyncio.Event()
        cleanup_events = []

        class SuccessfulClient:
            window_handle = 201

            async def activate_hooks(self, **_kwargs):
                first_finished.set()

            async def close(self):
                cleanup_events.append("first closed")

        class FailingClient:
            window_handle = 202

            async def activate_hooks(self, **_kwargs):
                await first_finished.wait()
                raise failure

        first = SuccessfulClient()
        second = FailingClient()
        handler.clients = [first, second]
        handler._managed_handles = [first.window_handle, second.window_handle]
        with self.assertRaisesRegex(
            RuntimeError,
            "second client activation failed",
        ) as caught:
            await handler.activate_all_client_hooks(wait_for_ready=True)

        self.assertIs(caught.exception, failure)
        self.assertEqual(cleanup_events, ["first closed"])
        self.assertEqual(handler.clients, [second])

    async def test_aggregate_preserves_exact_child_cancellation_diagnostics(self):
        handler = ClientHandler(client_cls=object)
        first_finished = asyncio.Event()
        child_cleanup_error = RuntimeError("child rpc settlement failed")
        child_cancellation = asyncio.CancelledError("child activation cancelled")
        child_cancellation.cleanup_errors = (child_cleanup_error,)
        cleanup_events = []

        class SuccessfulClient:
            window_handle = 301

            async def activate_hooks(self, **_kwargs):
                first_finished.set()

            async def close(self):
                cleanup_events.append("first closed")

        class CancelledClient:
            window_handle = 302

            async def activate_hooks(self, **_kwargs):
                await first_finished.wait()
                raise child_cancellation

        first = SuccessfulClient()
        second = CancelledClient()
        handler.clients = [first, second]
        handler._managed_handles = [first.window_handle, second.window_handle]

        with self.assertRaises(asyncio.CancelledError) as caught:
            await handler.activate_all_client_hooks(wait_for_ready=True)

        self.assertIs(caught.exception, child_cancellation)
        self.assertEqual(caught.exception.cleanup_errors, (child_cleanup_error,))
        self.assertEqual(cleanup_events, ["first closed"])
        self.assertEqual(handler.clients, [second])

    async def test_aggregate_client_hook_failure_reports_sibling_drain_error(self):
        handler = ClientHandler(client_cls=object)
        failure = RuntimeError("first client activation failed")
        sibling_cleanup_error = RuntimeError("sibling activation drain failed")
        sibling_started = asyncio.Event()
        captured_child_cancellations = []

        class FailingClient:
            async def activate_hooks(self, **_kwargs):
                await sibling_started.wait()
                raise failure

        class SiblingClient:
            async def activate_hooks(self, **_kwargs):
                sibling_started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError as cancellation:
                    cancellation.cleanup_errors = (sibling_cleanup_error,)
                    captured_child_cancellations.append(cancellation)
                    raise

        handler.clients = [FailingClient(), SiblingClient()]
        with self.assertRaisesRegex(
            RuntimeError,
            "first client activation failed",
        ) as caught:
            await handler.activate_all_client_hooks(wait_for_ready=True)

        self.assertIs(caught.exception, failure)
        self.assertIn(
            captured_child_cancellations[0],
            caught.exception.cleanup_errors,
        )
        self.assertIn(sibling_cleanup_error, caught.exception.cleanup_errors)

    async def test_aggregate_hook_rollback_failure_retains_client_ownership(self):
        handler = ClientHandler(client_cls=object)
        activation_error = RuntimeError("second activation failed")
        cleanup_error = RuntimeError("first client close failed")
        first_finished = asyncio.Event()

        class SuccessfulClient:
            window_handle = 401

            async def activate_hooks(self, **_kwargs):
                first_finished.set()

            async def close(self):
                raise cleanup_error

        class FailingClient:
            window_handle = 402

            async def activate_hooks(self, **_kwargs):
                await first_finished.wait()
                raise activation_error

        first = SuccessfulClient()
        second = FailingClient()
        handler.clients = [first, second]
        handler._managed_handles = [first.window_handle, second.window_handle]

        with self.assertRaisesRegex(
            RuntimeError,
            "second activation failed",
        ) as caught:
            await handler.activate_all_client_hooks(wait_for_ready=True)

        self.assertIs(caught.exception, activation_error)
        self.assertIn(cleanup_error, caught.exception.cleanup_errors)
        self.assertEqual(handler.clients, [first, second])
        self.assertEqual(handler.managed_identities, (401, 402))

    async def test_mouseless_cancellation_rolls_back_prior_clients_in_reverse(self):
        handler = ClientHandler(client_cls=object)
        second_started = asyncio.Event()
        rollback_started = asyncio.Event()
        release_rollback = asyncio.Event()
        live = []
        events = []

        class MouseHandler:
            def __init__(self, name, *, blocks=False):
                self.name = name
                self.blocks = blocks

            async def activate_mouseless(self):
                events.append(("activate", self.name))
                if self.blocks:
                    second_started.set()
                    await asyncio.Event().wait()
                live.append(self.name)

            async def deactivate_mouseless(self):
                events.append(("deactivate", self.name))
                rollback_started.set()
                await release_rollback.wait()
                live.remove(self.name)

        first = SimpleNamespace(mouse_handler=MouseHandler("first"))
        second = SimpleNamespace(
            mouse_handler=MouseHandler("second", blocks=True)
        )
        handler.clients = [first, second]
        activation = asyncio.create_task(handler.activate_all_client_mouseless())
        await second_started.wait()
        activation.cancel("mouseless owner cancelled")
        await rollback_started.wait()
        activation.cancel("mouseless cleanup cancelled again")
        release_rollback.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await activation

        self.assertEqual(caught.exception.args, ("mouseless owner cancelled",))
        self.assertEqual(live, [])
        self.assertEqual(
            events,
            [
                ("activate", "first"),
                ("activate", "second"),
                ("deactivate", "first"),
            ],
        )

    async def test_cancelled_recovery_waiter_settles_shared_transaction(self):
        coordinator = AgentRecoveryCoordinator()
        transaction_started = asyncio.Event()
        release_transaction = asyncio.Event()
        transaction_finished = asyncio.Event()

        async def transaction():
            transaction_started.set()
            await release_transaction.wait()
            transaction_finished.set()
            return True

        waiter = asyncio.create_task(coordinator.run(transaction))
        await transaction_started.wait()
        waiter.cancel("recovery waiter cancelled")
        await asyncio.sleep(0)
        self.assertFalse(waiter.done())
        self.assertTrue(coordinator.in_progress)
        waiter.cancel("recovery waiter cancelled again")
        release_transaction.set()

        with self.assertRaises(asyncio.CancelledError) as caught:
            await waiter

        self.assertEqual(caught.exception.args, ("recovery waiter cancelled",))
        self.assertTrue(transaction_finished.is_set())
        self.assertFalse(coordinator.in_progress)
        self.assertTrue(coordinator.ready)


if __name__ == "__main__":
    unittest.main()
