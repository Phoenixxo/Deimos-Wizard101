from __future__ import annotations

import asyncio
import gc
from pathlib import Path
import sys
import threading
import unittest
import weakref


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
if str(WIZWALKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WIZWALKER_ROOT))

from wizwalker import ClientHandler, DiscoveredClient  # noqa: E402
from wizwalker.generation import NativeGenerationDrainTimeout  # noqa: E402
from wizwalker.memory import DeimosNativeMemoryBackend, MemoryReader  # noqa: E402
from src.runtime_recovery import (  # noqa: E402
    AgentRuntimeRecovery,
    AgentRecoveryCoordinator,
    GenerationTaggedQueue,
    GenerationTaskDrainTimeout,
    await_generation_control_dispatch,
    cancel_and_drain_tasks,
    generation_command_is_current,
    require_agent_capabilities,
    reset_generation_runtime_state,
    restart_resilient_task,
)


def descriptor(client_id: str, pid: int, created: str = "100") -> dict:
    return {
        "client_id": client_id,
        "process": {
            "pid": pid,
            "name": "WizardGraphicalClient.exe",
            "kind": "wizard101",
            "identity": {
                "pid": pid,
                "creation_time_100ns": created,
                "executable_path": "C:/Wizard101/WizardGraphicalClient.exe",
            },
        },
        "is_foreground": True,
        "screen_order": 0,
    }


class RacingManager:
    cleanup_instance_id = "helper-a"

    def __init__(self, snapshots):
        self.snapshots = iter(snapshots)
        self.instance_id = "helper-a"
        self.calls = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.identity_states = {}

    def list_clients(self):
        self.calls.append((self.instance_id, "list"))
        return {"clients": next(self.snapshots)}

    def send_key(self, client_id, key, seconds):
        instance = self.instance_id
        self.calls.append((instance, "key", client_id, key))
        self.entered.set()
        self.release.wait(timeout=2)
        return {"instance": instance}

    def client_window_state(self, client_id):
        instance = self.instance_id
        self.calls.append((instance, "window", client_id))
        self.entered.set()
        self.release.wait(timeout=2)
        return {
            "title": f"Wizard101-{instance}",
            "is_foreground": True,
            "rectangle": {"left": 0, "top": 0, "right": 800, "bottom": 600},
            "client_origin": {"x": 0, "y": 0},
            "client_size": {"width": 800, "height": 600},
        }

    def read_memory(self, session_id, address, size):
        self.calls.append((self.instance_id, "read", session_id))
        self.entered.set()
        self.release.wait(timeout=2)
        return bytes(size)

    def close_process_for_instance(self, session_id, expected_instance_id):
        self.calls.append((self.instance_id, "close", session_id))

    def process_identity_status(self, pid, expected_identity_json):
        self.calls.append((self.instance_id, "identity_status", pid))
        return {"state": self.identity_states.get(pid, "matching")}

    def capabilities(self):
        self.calls.append((self.instance_id, "capabilities"))
        return ["memory.read_only.v1"]


class HelperGenerationRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_conversion_cannot_publish_after_fence_closes(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingClients(list):
            def __iter__(self):
                entered.set()
                release.wait(timeout=2)
                return super().__iter__()

        current = descriptor("old-a", 530)
        manager = RacingManager([[current]])
        manager.snapshots = iter([BlockingClients([current])])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        discovery = asyncio.create_task(asyncio.to_thread(handler.get_new_clients))
        await asyncio.to_thread(entered.wait, 1)

        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0)
        self.assertFalse(draining.done())
        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            await discovery
        await draining
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        self.assertEqual(handler.clients, [])
        self.assertEqual(handler.managed_identities, ())

    async def test_blocked_client_constructor_does_not_block_fence_close(self):
        entered = threading.Event()
        release = threading.Event()
        current = descriptor("old-a", 537)
        manager = RacingManager([[current]])

        class BlockingClient(DiscoveredClient):
            def __init__(self, *args, **kwargs):
                entered.set()
                release.wait(timeout=2)
                super().__init__(*args, **kwargs)

        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-a",
            client_cls=BlockingClient,
        )
        discovery = asyncio.create_task(asyncio.to_thread(handler.get_new_clients))
        await asyncio.to_thread(entered.wait, 1)
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0.01)
        self.assertFalse(draining.done())

        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await discovery
        await draining
        self.assertEqual(handler.clients, [])

    async def test_failed_discovery_batch_terminalizes_prepared_clients(self):
        descriptors = [descriptor("one", 539), descriptor("two", 540)]
        manager = RacingManager([descriptors])
        constructed = []

        class SecondFails(DiscoveredClient):
            def __init__(self, *args, **kwargs):
                if constructed:
                    raise RuntimeError("second constructor failed")
                super().__init__(*args, **kwargs)
                constructed.append(self)

        handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-a",
            client_cls=SecondFails,
        )
        with self.assertRaisesRegex(RuntimeError, "second constructor failed"):
            handler.get_new_clients()
        self.assertEqual(handler.clients, [])
        self.assertEqual(len(constructed), 1)
        self.assertFalse(constructed[0].is_running())

    async def test_concurrent_discovery_and_manage_publish_one_client(self):
        current = descriptor("same", 541)

        async def assert_one_published(operation):
            manager = RacingManager([[current], [current]])
            barrier = threading.Barrier(2)
            constructed = []

            class ConcurrentClient(DiscoveredClient):
                def __init__(self, *args, **kwargs):
                    barrier.wait(timeout=2)
                    super().__init__(*args, **kwargs)
                    constructed.append(self)

            handler = ClientHandler(
                agent_manager=manager,
                agent_instance_id="helper-a",
                client_cls=ConcurrentClient,
            )
            results = await asyncio.gather(
                asyncio.to_thread(operation, handler),
                asyncio.to_thread(operation, handler),
            )
            self.assertEqual(len(handler.clients), 1)
            self.assertEqual(sum(client.is_running() for client in constructed), 1)
            return handler, results

        discovered, discovery_results = await assert_one_published(
            lambda handler: handler.get_new_clients()
        )
        self.assertEqual(sum(len(result) for result in discovery_results), 1)
        self.assertEqual(discovered.managed_identities, ("same",))

        managed, manage_results = await assert_one_published(
            lambda handler: handler.manage_client("same")
        )
        self.assertIs(manage_results[0], manage_results[1])
        self.assertEqual(managed.managed_identities, ("same",))

    async def test_missing_descriptor_status_rpc_does_not_block_fence_close(self):
        entered = threading.Event()
        release = threading.Event()
        current = descriptor("old-a", 531)
        manager = RacingManager([[current], []])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        client = handler.get_new_clients()[0]
        client._session_id = "session-a"
        client._session_instance_id = "helper-a"

        def process_status(_session_id):
            entered.set()
            release.wait(timeout=2)
            return {"state": "open"}

        manager.process_status = process_status
        refresh = asyncio.create_task(asyncio.to_thread(handler.get_new_clients))
        await asyncio.to_thread(entered.wait, 1)
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0.01)
        self.assertFalse(draining.done())
        self.assertFalse(refresh.done())

        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await refresh
        await draining

    async def test_release_terminalizes_clean_client_and_quarantines_hook_owner(self):
        current = descriptor("same", 532)
        manager = RacingManager([[current], [current], [current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        clean = handler.get_new_clients()[0]
        handler.release_client(clean)
        self.assertFalse(clean.is_running())
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await clean.send_key(65)

        fresh = handler.get_new_clients()[0]
        fresh.hook_handler = type(
            "OwnedHooks",
            (),
            {
                "cancel_core_hook_heartbeat": lambda self: None,
                "close": lambda self: asyncio.sleep(0),
            },
        )()
        fresh._hook_session_id = "hook-a"
        fresh._hook_session_instance_id = "helper-a"
        handler.release_client(fresh)

        self.assertEqual(handler.get_new_clients(), [])
        owners = handler._quarantined_hook_clients[
            handler._process_identity(fresh)
        ]
        self.assertIn(fresh, owners)

    async def test_shared_quarantine_keeps_all_owners_until_each_is_released(self):
        current = descriptor("same", 533)
        manager = RacingManager([[current], [current], [current]])
        manager.release.set()
        first_handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-a",
        )
        second_handler = ClientHandler(
            agent_manager=manager,
            agent_instance_id="helper-a",
        )
        first = first_handler.get_new_clients()[0]
        second = second_handler.get_new_clients()[0]
        for client in (first, second):
            client.hook_handler = object()
            client._hook_session_id = f"hook-{id(client)}"
            client.begin_detach()
            client._generation_context.quarantine_cleanup_owner(client)

        identity = first_handler._process_identity(first)
        self.assertEqual(
            first_handler._quarantined_hook_clients[identity],
            {first, second},
        )
        first.hook_handler = None
        first._hook_session_id = None
        first._generation_context.release_cleanup_owner(first)
        self.assertEqual(first_handler._quarantined_hook_clients[identity], {second})
        self.assertEqual(first_handler.get_new_clients(), [])

    async def test_direct_hook_owner_is_reserved_retried_and_reconciled(self):
        current = descriptor("same", 534)
        manager = RacingManager([[current]])
        manager.release.set()
        manager.open_hook_calls = 0

        def open_hook_process(_pid, **_kwargs):
            manager.open_hook_calls += 1
            return {"session_id": "hook-direct"}

        manager.open_hook_process = open_hook_process
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        context = handler.generation_context
        first = DiscoveredClient(manager, current, generation_context=context)
        second = DiscoveredClient(manager, current, generation_context=context)
        await first._ensure_hook_handler()
        with self.assertRaisesRegex(RuntimeError, "already has a native hook owner"):
            await second._ensure_hook_handler()
        self.assertEqual(manager.open_hook_calls, 1)

        await handler.begin_agent_replacement()
        handler.note_agent_instance("helper-a", previous_replaced=False)
        for _ in range(100):
            if first.cleanup_complete:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(first.cleanup_complete)
        self.assertFalse(context.is_process_quarantined(current))

        third = DiscoveredClient(manager, current, generation_context=context)
        third.hook_handler = type(
            "OwnedHooks",
            (),
            {
                "cancel_core_hook_heartbeat": lambda self: None,
                "close": lambda self: asyncio.sleep(0),
            },
        )()
        third._hook_session_id = "hook-old"
        third._hook_session_instance_id = "helper-a"
        context.reserve_hook_owner(third)
        reference = weakref.ref(third)
        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)
        del third
        gc.collect()
        self.assertIsNotNone(reference())
        with self.assertRaisesRegex(RuntimeError, "quarantined hooks"):
            DiscoveredClient(manager, current, generation_context=context)
        manager.identity_states[534] = "exited"
        replacement = DiscoveredClient(manager, current, generation_context=context)
        self.assertTrue(replacement.is_running())

    async def test_memory_executor_discards_result_delivered_after_publish(self):
        current = descriptor("same", 535)
        manager = RacingManager([[current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        old_token = handler.agent_generation_token
        entered = threading.Event()
        release = threading.Event()

        class DelayedDeliveryBackend(DeimosNativeMemoryBackend):
            def read_bytes(self, address, size):
                super().read_bytes(address, size)
                entered.set()
                release.wait(timeout=2)
                return b"OLD-A"

        backend = DelayedDeliveryBackend(
            manager,
            "session-a",
            expected_instance_id="helper-a",
            generation_fence=handler._generation_fence,
            generation_token=old_token,
            generation_context=handler.generation_context,
        )
        read = asyncio.create_task(MemoryReader(backend).read_bytes(0x1000, 5))
        await asyncio.to_thread(entered.wait, 1)
        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)
        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            await read

    async def test_hook_activation_publishes_ownership_before_future_delivery(self):
        current = descriptor("same", 538)
        manager = RacingManager([[]])
        manager.release.set()
        manager.open_hook_process = lambda *_args, **_kwargs: {
            "session_id": "hook-a"
        }
        manager.activate_core_hooks = lambda _session_id: {"hooks": []}
        manager.deactivate_core_hooks_for_instance = (
            lambda *_args: {"hooks": []}
        )
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        client = DiscoveredClient(
            manager,
            current,
            generation_context=handler.generation_context,
        )
        hook_handler, _ = await client._ensure_hook_handler()
        original_activate = hook_handler._backend.activate_core_hooks
        entered = threading.Event()
        release = threading.Event()

        def delayed_delivery(_backend):
            result = original_activate()
            entered.set()
            release.wait(timeout=2)
            return result

        hook_handler._backend.activate_core_hooks = delayed_delivery.__get__(
            hook_handler._backend,
            type(hook_handler._backend),
        )
        activation = asyncio.create_task(
            hook_handler.activate_all_hooks(wait_for_ready=False)
        )
        await asyncio.to_thread(entered.wait, 1)
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0.01)
        self.assertFalse(draining.done())
        self.assertTrue(hook_handler._active_hooks)

        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await activation
        await draining
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        identity = handler._process_identity(client)
        self.assertIn(client, handler._quarantined_hook_clients[identity])
        self.assertTrue(hook_handler._active_hooks)
        self.assertFalse(
            any(call[:2] == ("helper-b", "activate") for call in manager.calls)
        )

    async def test_single_core_activation_prepublishes_before_future_delivery(self):
        current = descriptor("same", 542)
        manager = RacingManager([[]])
        manager.release.set()
        manager.open_hook_process = lambda *_args, **_kwargs: {
            "session_id": "hook-a"
        }
        manager.activate_core_hook = lambda *_args: {"hook": "client"}
        manager.deactivate_core_hook_for_instance = (
            lambda *_args: {"hook": "client"}
        )
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        client = DiscoveredClient(
            manager,
            current,
            generation_context=handler.generation_context,
        )
        hook_handler, _ = await client._ensure_hook_handler()
        original_activate = hook_handler._backend.activate_core_hook
        entered = threading.Event()
        release = threading.Event()

        def delayed_delivery(_backend, hook_name):
            result = original_activate(hook_name)
            entered.set()
            release.wait(timeout=2)
            return result

        hook_handler._backend.activate_core_hook = delayed_delivery.__get__(
            hook_handler._backend,
            type(hook_handler._backend),
        )
        hook_type = type("SingleCoreHook", (), {})
        activation = asyncio.create_task(
            hook_handler._activate_agent_core_hook(
                hook_type,
                "client",
                "current_client",
                wait_for_ready=False,
                timeout=1,
            )
        )
        await asyncio.to_thread(entered.wait, 1)
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0.01)
        self.assertEqual(hook_handler._active_hooks[hook_type], "client")
        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await activation
        await draining
        self.assertEqual(hook_handler._active_hooks[hook_type], "client")

    async def test_canceled_generation_control_dispatch_does_not_kill_consumer(self):
        stale_publication = []
        entered = asyncio.Event()

        async def old_dispatch():
            entered.set()
            await asyncio.Event().wait()
            stale_publication.append("old")

        old = asyncio.create_task(old_dispatch())
        consumer = asyncio.create_task(await_generation_control_dispatch(old))
        await entered.wait()
        old.cancel()
        self.assertFalse(await consumer)

        async def new_dispatch():
            stale_publication.append("new")

        new = asyncio.create_task(new_dispatch())
        self.assertTrue(await await_generation_control_dispatch(new))
        self.assertEqual(stale_publication, ["new"])

    async def test_no_wait_bulk_activation_is_owned_and_drained(self):
        manager = RacingManager([[]])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        entered = asyncio.Event()
        canceled = asyncio.Event()

        class ActivatingClient:
            client_id = "direct"
            process = descriptor("direct", 536)["process"]
            cleanup_complete = True
            has_hook_cleanup_ownership = False

            async def activate_hooks(self, **_kwargs):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    canceled.set()

            def _mark_closed(self):
                pass

        handler.clients.append(ActivatingClient())
        await handler.activate_all_client_hooks(wait_for_ready=False)
        await entered.wait()
        await handler.begin_agent_replacement()
        self.assertTrue(canceled.is_set())
        self.assertEqual(handler.generation_context._generation_tasks, set())

    async def test_same_helper_publish_advances_host_epoch_and_rejects_all_stale_work(self):
        current = descriptor("reused", 516)
        manager = RacingManager([[current], [current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale_client = handler.get_new_clients()[0]
        old_token = handler.agent_generation_token
        stale_runtime = handler.bind_agent_manager(old_token)
        stale_backend = DeimosNativeMemoryBackend(
            manager,
            "session-old",
            expected_instance_id="helper-a",
            generation_fence=handler._generation_fence,
            generation_token=old_token,
            generation_context=handler.generation_context,
        )
        queued = GenerationTaggedQueue(old_token)
        queued.put("KillClient")

        await handler.begin_agent_replacement()
        handler.note_agent_instance("helper-a", previous_replaced=False)
        new_token = handler.agent_generation_token
        queued.set_generation(new_token)

        self.assertIsNot(old_token, new_token)
        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            stale_runtime.list_clients()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await stale_client.send_key(65)
        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            stale_backend.read_bytes(0x1000, 4)
        self.assertFalse(
            generation_command_is_current(
                queued.get_nowait(),
                new_token,
                recovery_ready=True,
            )
        )
        self.assertFalse(any(call[:2] == ("helper-a", "key") for call in manager.calls))
        self.assertFalse(any(call[:2] == ("helper-a", "read") for call in manager.calls))

        fresh = handler.get_new_clients()[0]
        self.assertIsNot(fresh, stale_client)

    async def test_same_helper_retry_admits_exact_cleanup_but_not_normal_work(self):
        current = descriptor("reused", 517)
        manager = RacingManager([[current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]
        stale._session_id = "session-old"
        stale._session_instance_id = "helper-a"

        await handler.begin_agent_replacement()
        handler.note_agent_instance("helper-a", previous_replaced=False)
        await stale.close()

        self.assertIn(("helper-a", "close", "session-old"), manager.calls)
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await stale.send_key(65)

    async def test_window_conversion_is_drained_and_discards_retired_result(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingState(dict):
            def get(self, key, default=None):
                if key == "title":
                    entered.set()
                    release.wait(timeout=2)
                return super().get(key, default)

        current = descriptor("reused", 518)
        manager = RacingManager([[current]])
        manager.release.set()

        def window_state(client_id):
            manager.calls.append((manager.instance_id, "window", client_id))
            return BlockingState(title="OLD-A")

        manager.client_window_state = window_state
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]
        title = asyncio.create_task(asyncio.to_thread(lambda: stale.title))
        await asyncio.to_thread(entered.wait, 1)
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0)
        self.assertFalse(draining.done())

        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await title
        await draining
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

    async def test_memory_conversion_is_drained_and_discards_retired_result(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingBytes:
            def __bytes__(self):
                entered.set()
                release.wait(timeout=2)
                return b"OLD-A"

        current = descriptor("reused", 520)
        manager = RacingManager([[current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        handler.get_new_clients()
        manager.read_memory = lambda *args: BlockingBytes()
        backend = DeimosNativeMemoryBackend(
            manager,
            "session-a",
            expected_instance_id="helper-a",
            generation_fence=handler._generation_fence,
            generation_token=handler.agent_generation_token,
            generation_context=handler.generation_context,
        )

        read = asyncio.create_task(asyncio.to_thread(backend.read_bytes, 0x1000, 5))
        await asyncio.to_thread(entered.wait, 1)
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0)
        self.assertFalse(draining.done())
        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            await read
        await draining

    async def test_memory_scan_parse_cannot_publish_stale_addresses(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingScan(dict):
            def get(self, key, default=None):
                if key == "matches":
                    entered.set()
                    release.wait(timeout=2)
                return super().get(key, default)

        current = descriptor("reused", 521)
        manager = RacingManager([[current]])
        manager.release.set()
        manager.scan_memory = lambda *args, **kwargs: BlockingScan(
            matches=["0x140001000"]
        )
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        handler.get_new_clients()
        backend = DeimosNativeMemoryBackend(
            manager,
            "session-a",
            expected_instance_id="helper-a",
            generation_fence=handler._generation_fence,
            generation_token=handler.agent_generation_token,
            generation_context=handler.generation_context,
        )

        scan = asyncio.create_task(
            asyncio.to_thread(
                backend.scan,
                "90",
                module_name="WizardGraphicalClient.exe",
                return_multiple=False,
            )
        )
        await asyncio.to_thread(entered.wait, 1)
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0)
        self.assertFalse(draining.done())
        release.set()
        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            await scan
        await draining

    async def test_shutdown_drain_detects_native_call_after_failed_recovery_drain(self):
        current = descriptor("client-a", 519)
        manager = RacingManager([[current]])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        client = handler.get_new_clients()[0]
        operation = asyncio.create_task(client.send_key(65))
        await asyncio.to_thread(manager.entered.wait, 1)

        with self.assertRaises(NativeGenerationDrainTimeout):
            await handler.begin_agent_replacement(timeout_seconds=0.01)
        self.assertFalse(
            await asyncio.to_thread(
                handler.generation_context.close_for_shutdown,
                0.01,
            )
        )

        manager.release.set()
        with self.assertRaisesRegex(RuntimeError, "discarded"):
            await operation

    async def test_delayed_feature_capability_gate_cannot_read_replacement(self):
        manager = RacingManager([[]])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        feature_runtime = handler.bind_agent_manager(handler.agent_generation_token)

        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            require_agent_capabilities(
                feature_runtime,
                "Telemetry",
                "memory.read_only.v1",
            )
        self.assertNotIn(("helper-b", "capabilities"), manager.calls)

    async def test_unmanaged_native_objects_fail_closed_without_shared_fence(self):
        current = descriptor("reused", 513)
        manager = RacingManager([[current]])
        manager.release.set()
        direct_client = DiscoveredClient(manager, current)
        direct_backend = DeimosNativeMemoryBackend(manager, "session-a")
        manager.instance_id = "helper-b"

        with self.assertRaisesRegex(RuntimeError, "manager-scoped generation fence"):
            await direct_client.send_key(65)
        with self.assertRaisesRegex(RuntimeError, "explicitly bound"):
            direct_backend.read_bytes(0x1000, 4)

        self.assertFalse(any(call[0] == "helper-b" for call in manager.calls))

    async def test_manual_manage_respects_exact_identity_quarantine(self):
        current = descriptor("reused", 514, "same-process")
        replacement = descriptor("reused", 514, "replacement-process")
        manager = RacingManager([[current], [current], [replacement]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]
        stale.hook_handler = type(
            "OwnedHooks",
            (),
            {"cancel_core_hook_heartbeat": lambda self: None},
        )()
        stale._hook_session_id = "hook-a"

        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)
        replacement_generation = handler.agent_generation_token

        with self.assertRaisesRegex(RuntimeError, "quarantined hooks"):
            handler.manage_client(
                "reused",
                expected_instance_id=replacement_generation,
            )
        self.assertIn(
            stale,
            handler._quarantined_hook_clients[handler._process_identity(stale)],
        )

        manager.identity_states[514] = "replaced"
        fresh = handler.manage_client(
            "reused",
            expected_instance_id=replacement_generation,
        )
        self.assertIsNot(fresh, stale)
        self.assertEqual(
            fresh.process["identity"]["creation_time_100ns"],
            "replacement-process",
        )

    async def test_invalid_identity_is_closed_then_later_recovery_can_publish(self):
        class AgentLifecycleError(RuntimeError):
            code = "agent_exited"

        current = descriptor("reused", 515)

        class RestartingManager(RacingManager):
            def __init__(self):
                super().__init__([[current], [current]])
                self.starts = 0

            def start(self):
                self.starts += 1
                if self.starts == 1:
                    self.instance_id = "helper-b"
                    return {"identity": {}}
                self.instance_id = "helper-c"
                return {"identity": {"instance_id": "helper-c"}}

        manager = RestartingManager()
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        old_generation = handler.agent_generation_token
        handler.get_new_clients()
        runtime = AgentRuntimeRecovery(manager, cooldown_seconds=0)
        runtime.remember({"identity": {"instance_id": "helper-a"}})

        await handler.begin_agent_replacement()
        first = await runtime.recover(AgentLifecycleError("lost"))
        self.assertFalse(first.recovered)
        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            handler.bind_agent_manager(old_generation).list_clients()
        self.assertNotIn(("helper-b", "list"), manager.calls)

        second = await runtime.recover(AgentLifecycleError("retry"))
        self.assertTrue(second.recovered)
        handler.note_agent_instance("helper-c", previous_replaced=True)
        self.assertEqual(
            handler.bind_agent_manager(handler.agent_generation_token).list_clients(),
            {"clients": [current]},
        )
        self.assertIn(("helper-c", "list"), manager.calls)

    async def test_runtime_generation_reset_clears_every_derived_cache(self):
        window_config_applied = {"reused-client"}
        launching_status = {"wizard": "launching"}

        state = reset_generation_runtime_state(
            window_config_applied,
            launching_status,
            7,
        )

        self.assertEqual(window_config_applied, set())
        self.assertEqual(launching_status, {})
        self.assertEqual(state.epoch, 7)
        self.assertIsNone(state.paused_task_names)
        self.assertIsNone(state.previous_client_count)
        self.assertEqual(state.last_known_handle_count, 0)
        self.assertIsNone(state.last_prewarm_zone)
        self.assertIsNone(state.sigil_leader_pid)
        self.assertIsNone(state.questing_leader_pid)
        self.assertFalse(state.freecam_status)

    async def test_shutdown_drains_slow_start_and_prevents_late_publish(self):
        class AgentLifecycleError(RuntimeError):
            code = "agent_exited"

        class SlowStartManager:
            def __init__(self):
                self.started = threading.Event()
                self.release = threading.Event()
                self.start_finished = threading.Event()
                self.stop_before_finish = False

            def start(self):
                self.started.set()
                self.release.wait(timeout=2)
                self.start_finished.set()
                return {"identity": {"instance_id": "helper-b"}}

            def stop(self):
                self.stop_before_finish = not self.start_finished.is_set()

        manager = SlowStartManager()
        runtime = AgentRuntimeRecovery(manager, cooldown_seconds=0)
        coordinator = AgentRecoveryCoordinator()
        published = []

        async def transaction():
            outcome = await runtime.recover(AgentLifecycleError("lost"))
            if outcome.recovered:
                published.append(outcome.response)
            return outcome.recovered

        waiter = asyncio.create_task(coordinator.run(transaction))
        await asyncio.to_thread(manager.started.wait, 1)
        waiter.cancel()
        shutdown = asyncio.create_task(coordinator.shutdown(timeout_seconds=1))
        await asyncio.sleep(0)
        self.assertFalse(waiter.done())
        self.assertFalse(shutdown.done())
        manager.release.set()
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertTrue(await shutdown)
        manager.stop()

        self.assertEqual(published, [])
        self.assertFalse(manager.stop_before_finish)
        self.assertFalse(coordinator.ready)

    async def test_hung_native_call_times_out_without_replacement_then_retries(self):
        current = descriptor("client-a", 512)
        manager = RacingManager([[current]])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        client = handler.get_new_clients()[0]
        operation = asyncio.create_task(client.send_key(65))
        await asyncio.to_thread(manager.entered.wait, 1)
        ticked = asyncio.Event()
        asyncio.get_running_loop().call_soon(ticked.set)

        with self.assertRaises(NativeGenerationDrainTimeout):
            await handler.begin_agent_replacement(timeout_seconds=0.01)
        await asyncio.wait_for(ticked.wait(), timeout=0.1)
        self.assertEqual(manager.instance_id, "helper-a")

        manager.release.set()
        with self.assertRaisesRegex(RuntimeError, "discarded"):
            await operation
        await handler.begin_agent_replacement(timeout_seconds=0.1)

    async def test_cancellation_suppressing_task_has_bounded_retryable_drain(self):
        release = asyncio.Event()
        started = asyncio.Event()

        async def stubborn():
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await release.wait()

        task = asyncio.create_task(stubborn())
        await started.wait()
        with self.assertRaises(GenerationTaskDrainTimeout):
            await cancel_and_drain_tasks([task], timeout_seconds=0.01)
        self.assertFalse(task.done())
        release.set()
        await asyncio.wait_for(task, timeout=0.1)
        await cancel_and_drain_tasks([task], timeout_seconds=0.01)

    async def test_commands_are_stamped_before_queueing_and_rejected_after_publish(self):
        commands = ("HookClient", "KillClient", "RelaunchClient")
        command_queue = GenerationTaggedQueue("helper-a")
        for command in commands:
            command_queue.put(command)
        command_queue.set_generation("helper-b")

        dispatched = []
        for _ in commands:
            envelope = command_queue.get_nowait()
            if generation_command_is_current(
                envelope,
                "helper-b",
                recovery_ready=True,
            ):
                dispatched.append(envelope.command)

        self.assertEqual(dispatched, [])

    async def test_slow_import_cannot_requeue_bot_into_replacement_generation(self):
        command_queue = GenerationTaggedQueue("helper-a")
        release = threading.Event()
        started = threading.Event()

        async def import_and_requeue():
            started.set()
            await asyncio.to_thread(release.wait, 1)
            command_queue.put_for_generation("ExecuteBot", "helper-a")

        task = asyncio.create_task(import_and_requeue())
        await asyncio.to_thread(started.wait, 1)
        await cancel_and_drain_tasks([task], timeout_seconds=0.1)
        command_queue.set_generation("helper-b")
        release.set()
        await asyncio.sleep(0.01)

        self.assertTrue(command_queue.empty())

    async def test_releasing_active_hook_retains_exact_cleanup_owner(self):
        current = descriptor("client-a", 511)
        manager = RacingManager([[current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        client = handler.get_new_clients()[0]
        client.hook_handler = type(
            "OwnedHooks",
            (),
            {"cancel_core_hook_heartbeat": lambda self: None},
        )()
        client._hook_session_id = "hook-a"
        owner_ref = weakref.ref(client)

        handler.release_client(client)
        del client
        gc.collect()

        owner = owner_ref()
        self.assertIsNotNone(owner)
        self.assertIn(owner, handler.cleanup_clients)
        self.assertFalse(owner.is_running())

    async def test_inflight_a_call_drains_before_b_and_cannot_publish(self):
        current = descriptor("reused-client", 500)
        manager = RacingManager([[current], [current]])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]

        operation = asyncio.create_task(stale.send_key(65))
        await asyncio.to_thread(manager.entered.wait, 1)
        handler.retire_native_clients()
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0)
        self.assertFalse(draining.done())

        manager.release.set()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await operation
        await draining

        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await stale.send_key(66)
        self.assertNotIn(("helper-b", "key", "reused-client", 66), manager.calls)

        fresh = handler.get_new_clients()[0]
        self.assertIsNot(fresh, stale)
        await fresh.send_key(67)
        self.assertIn(("helper-b", "key", "reused-client", 67), manager.calls)

    async def test_old_memory_proxy_is_fenced_from_replacement_helper(self):
        current = descriptor("client-a", 501)
        manager = RacingManager([[current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]
        backend = DeimosNativeMemoryBackend(
            manager,
            "reused-session",
            expected_instance_id="helper-a",
            generation_fence=handler._generation_fence,
            generation_token=handler.agent_generation_token,
            generation_context=handler.generation_context,
        )

        handler.retire_native_clients()
        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            backend.read_bytes(0x1000, 4)
        self.assertNotIn(("helper-b", "read", "reused-session"), manager.calls)
        self.assertFalse(stale.is_running())

    async def test_inflight_memory_proxy_result_is_discarded_on_retirement(self):
        current = descriptor("client-a", 507)
        manager = RacingManager([[current]])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        handler.get_new_clients()
        backend = DeimosNativeMemoryBackend(
            manager,
            "session-a",
            expected_instance_id="helper-a",
            generation_fence=handler._generation_fence,
            generation_token=handler.agent_generation_token,
            generation_context=handler.generation_context,
        )

        read = asyncio.create_task(asyncio.to_thread(backend.read_bytes, 0x1000, 4))
        await asyncio.to_thread(manager.entered.wait, 1)
        handler.retire_native_clients()
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0)
        manager.release.set()

        with self.assertRaisesRegex(RuntimeError, "result was discarded"):
            await read
        await draining

    async def test_inflight_window_result_is_not_published_after_retirement(self):
        current = descriptor("reused-client", 506)
        manager = RacingManager([[current]])
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]

        window_read = asyncio.create_task(asyncio.to_thread(lambda: stale.title))
        await asyncio.to_thread(manager.entered.wait, 1)
        handler.retire_native_clients()
        draining = asyncio.create_task(handler.begin_agent_replacement())
        await asyncio.sleep(0)
        manager.release.set()

        with self.assertRaisesRegex(RuntimeError, "retired"):
            await window_read
        await draining
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)
        self.assertNotIn(("helper-b", "window", "reused-client"), manager.calls)

    async def test_active_hook_process_is_quarantined_until_exact_exit(self):
        current = descriptor("client-a", 502, "old-process")
        replacement = descriptor("client-a", 502, "new-process")
        manager = RacingManager([[current], [current], [], [replacement]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]

        class OwnedHooks:
            def cancel_core_hook_heartbeat(self):
                pass

        stale.hook_handler = OwnedHooks()
        stale._hook_session_id = "old-hook-session"
        handler.retire_native_clients()
        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        self.assertEqual(handler.get_new_clients(), [])
        self.assertIsNotNone(stale.hook_handler)
        self.assertEqual(handler.get_new_clients(), [])
        manager.identity_states[502] = "replaced"
        fresh = handler.get_new_clients()[0]
        self.assertIsNot(fresh, stale)
        self.assertEqual(fresh.process["identity"]["creation_time_100ns"], "new-process")

    async def test_window_gap_does_not_release_hook_quarantine(self):
        current = descriptor("client-a", 509, "same-process")
        manager = RacingManager([[current], [], [current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]
        stale.hook_handler = type(
            "OwnedHooks",
            (),
            {"cancel_core_hook_heartbeat": lambda self: None},
        )()
        stale._hook_session_id = "hook-a"

        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        self.assertEqual(handler.get_new_clients(), [])
        self.assertEqual(handler.get_new_clients(), [])
        self.assertIsNotNone(stale.hook_handler)
        self.assertIn(("helper-b", "identity_status", 509), manager.calls)

    async def test_two_handlers_share_fence_and_hook_quarantine(self):
        current = descriptor("reused", 510, "same-process")
        manager = RacingManager([[current], [current], [current]])
        manager.release.set()
        first = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        second = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = second.get_new_clients()[0]
        stale.hook_handler = type(
            "OwnedHooks",
            (),
            {"cancel_core_hook_heartbeat": lambda self: None},
        )()
        stale._hook_session_id = "hook-a"

        self.assertIs(first._generation_fence, second._generation_fence)
        await first.begin_agent_replacement()
        manager.instance_id = "helper-b"
        first.note_agent_instance("helper-b", previous_replaced=True)

        with self.assertRaisesRegex(RuntimeError, "retired"):
            await stale.send_key(65)
        self.assertEqual(first.get_new_clients(), [])
        self.assertFalse(stale.is_running())
        self.assertNotIn(("helper-b", "key", "reused", 65), manager.calls)

    async def test_preexisting_retired_hook_obligation_is_also_quarantined(self):
        current = descriptor("client-a", 504, "same-process")
        manager = RacingManager([[current], [current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]

        class OwnedHooks:
            def cancel_core_hook_heartbeat(self):
                pass

        stale.begin_detach()
        stale.hook_handler = OwnedHooks()
        stale._hook_session_id = "failed-detach-hook"
        handler.release_client(stale)
        self.assertIn(stale, handler._retired_clients)

        self.assertEqual(handler.retire_native_clients(), ())
        await handler.begin_agent_replacement()
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        self.assertEqual(handler.get_new_clients(), [])
        self.assertIn(
            stale,
            handler._quarantined_hook_clients[handler._process_identity(stale)],
        )

    async def test_cancel_and_drain_prevents_late_callback_publish(self):
        entered = asyncio.Event()
        published = []

        async def captured_work():
            entered.set()
            await asyncio.Event().wait()
            published.append("stale")

        task = asyncio.create_task(captured_work())
        await entered.wait()
        await cancel_and_drain_tasks([task])
        self.assertTrue(task.done())
        self.assertEqual(published, [])

    async def test_failed_recovery_identity_leaves_fence_closed(self):
        current = descriptor("client-a", 503)
        manager = RacingManager([[current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]
        handler.retire_native_clients()
        await handler.begin_agent_replacement()

        with self.assertRaisesRegex(RuntimeError, "retired helper generation"):
            handler.get_new_clients()
        with self.assertRaisesRegex(RuntimeError, "retired"):
            await stale.send_key(65)

    async def test_released_client_task_is_drained_with_no_visible_clients(self):
        current = descriptor("reused-client", 505)
        manager = RacingManager([[current]])
        manager.release.set()
        handler = ClientHandler(agent_manager=manager, agent_instance_id="helper-a")
        stale = handler.get_new_clients()[0]
        handler.release_client(stale)
        self.assertEqual(handler.clients, [])

        entered = asyncio.Event()

        async def captured_client_work():
            entered.set()
            await asyncio.Event().wait()
            await stale.send_key(70)

        task = asyncio.create_task(captured_client_work())
        await entered.wait()
        handler.retire_native_clients()
        await handler.begin_agent_replacement()
        await cancel_and_drain_tasks([task])
        manager.instance_id = "helper-b"
        handler.note_agent_instance("helper-b", previous_replaced=True)

        self.assertTrue(task.done())
        self.assertFalse(stale.is_running())
        self.assertFalse(any(call[:2] == ("helper-b", "key") for call in manager.calls))

    async def test_concurrent_recovery_callers_join_one_transaction(self):
        coordinator = AgentRecoveryCoordinator()
        started = asyncio.Event()
        finish = asyncio.Event()
        calls = 0

        async def transaction():
            nonlocal calls
            calls += 1
            started.set()
            await finish.wait()
            return True

        first = asyncio.create_task(coordinator.run(transaction))
        await started.wait()
        second = asyncio.create_task(coordinator.run(transaction))
        await asyncio.sleep(0)
        self.assertEqual(calls, 1)
        finish.set()

        self.assertEqual(await asyncio.gather(first, second), [True, True])
        self.assertEqual(calls, 1)
        self.assertTrue(coordinator.ready)
        self.assertFalse(coordinator.in_progress)

    async def test_concurrent_callers_observe_one_failed_transaction(self):
        coordinator = AgentRecoveryCoordinator()
        started = asyncio.Event()
        finish = asyncio.Event()
        calls = 0

        async def transaction():
            nonlocal calls
            calls += 1
            started.set()
            await finish.wait()
            return False

        first = asyncio.create_task(coordinator.run(transaction))
        await started.wait()
        second = asyncio.create_task(coordinator.run(transaction))
        await asyncio.sleep(0)
        self.assertEqual(calls, 1)
        finish.set()

        self.assertEqual(await asyncio.gather(first, second), [False, False])
        self.assertEqual(calls, 1)
        self.assertFalse(coordinator.ready)
        self.assertFalse(coordinator.in_progress)

    async def test_slow_recovery_owns_resilient_loop_restart(self):
        coordinator = AgentRecoveryCoordinator()
        recovery_started = asyncio.Event()
        recovery_finish = asyncio.Event()
        factory_calls = 0

        async def transaction():
            recovery_started.set()
            await recovery_finish.wait()
            return True

        async def old_loop():
            return None

        async def loop_factory():
            nonlocal factory_calls
            factory_calls += 1

        completed = asyncio.create_task(old_loop())
        await completed
        tasks = {"loop": completed}
        recovery = asyncio.create_task(coordinator.run(transaction))
        await recovery_started.wait()

        # The supervisor observes the failed loop while recovery owns restart.
        self.assertIsNone(
            await restart_resilient_task(
                "loop",
                completed,
                tasks,
                loop_factory,
                coordinator,
                delay_seconds=0,
            )
        )
        recovery_finish.set()
        self.assertTrue(await recovery)

        # Recovery publishes exactly one replacement. A delayed supervisor
        # callback for the old task cannot overwrite it afterward.
        replacement = asyncio.create_task(loop_factory())
        tasks["loop"] = replacement
        await replacement
        self.assertIsNone(
            await restart_resilient_task(
                "loop",
                completed,
                tasks,
                loop_factory,
                coordinator,
                delay_seconds=0,
            )
        )
        self.assertEqual(factory_calls, 1)
        self.assertIs(tasks["loop"], replacement)


if __name__ == "__main__":
    unittest.main()
