import asyncio
import threading
import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
for import_root in (REPOSITORY_ROOT, WIZWALKER_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


sys.modules.setdefault(
    "loguru",
    SimpleNamespace(
        logger=SimpleNamespace(
            debug=lambda *args, **kwargs: None,
            disable=lambda *args, **kwargs: None,
            catch=lambda *args, **kwargs: lambda function: function,
        )
    ),
)

from wizwalker import HookAlreadyActivated, HookNotActive, HookNotReady
from wizwalker.discovered_client import DiscoveredClient
from wizwalker.memory.backends import MemoryBackend
from wizwalker.memory.handler import HookHandler


class AgentCoreHookBackend(MemoryBackend):
    supports_core_hooks = True

    def __init__(self):
        self.process = self
        self.active = set()
        self.bases = {}
        self.calls = []
        self.heartbeat_errors = []

    def is_running(self):
        return True

    def read_bytes(self, address, size):
        raise AssertionError("core hook compatibility must use high-level operations")

    def module_base(self, module_name):
        raise AssertionError("core hook compatibility must not scan in Python")

    def activate_core_hook(self, hook):
        self.calls.append(("activate", hook))
        self.active.add(hook)
        return {"hook": hook, "active": True}

    def activate_core_hooks(self):
        self.calls.append(("activate_all",))
        self.active.update(CORE_HOOKS)
        return {"hooks": sorted(self.active)}

    def deactivate_core_hook(self, hook):
        self.calls.append(("deactivate", hook))
        self.active.discard(hook)
        return {"hook": hook, "deactivated": True}

    def deactivate_core_hooks(self):
        self.calls.append(("deactivate_all",))
        self.active.clear()
        return {"hooks": []}

    def heartbeat_core_hooks(self):
        self.calls.append(("heartbeat_all",))
        if self.heartbeat_errors:
            raise self.heartbeat_errors.pop(0)
        return {"hooks": sorted(self.active)}

    def read_core_hook_base(self, hook):
        self.calls.append(("read_base", hook))
        return self.bases.get(hook, 0)


CORE_HOOKS = {
    "client",
    "player",
    "quest",
    "player_stat",
    "root_window",
    "render_context",
}

HOOK_CASES = (
    (
        "player",
        "activate_player_hook",
        "deactivate_player_hook",
        "read_current_player_base",
    ),
    (
        "quest",
        "activate_quest_hook",
        "deactivate_quest_hook",
        "read_current_quest_base",
    ),
    (
        "player_stat",
        "activate_player_stat_hook",
        "deactivate_player_stat_hook",
        "read_current_player_stat_base",
    ),
    (
        "client",
        "activate_client_hook",
        "deactivate_client_hook",
        "read_current_client_base",
    ),
    (
        "root_window",
        "activate_root_window_hook",
        "deactivate_root_window_hook",
        "read_current_root_window_base",
    ),
    (
        "render_context",
        "activate_render_context_hook",
        "deactivate_render_context_hook",
        "read_current_render_context_base",
    ),
)


class CoreHookCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.backend = AgentCoreHookBackend()
        self.handler = HookHandler(self.backend, client=object())

    async def test_each_legacy_entrypoint_uses_an_isolated_high_level_operation(self):
        for index, (hook, activate, deactivate, read_base) in enumerate(HOOK_CASES, 1):
            self.backend.bases[hook] = 0x1000 + index
            await getattr(self.handler, activate)(wait_for_ready=False)
            self.assertEqual(await getattr(self.handler, read_base)(), 0x1000 + index)
            with self.assertRaises(HookAlreadyActivated):
                await getattr(self.handler, activate)(wait_for_ready=False)
            await getattr(self.handler, deactivate)()
            with self.assertRaises(HookNotActive):
                await getattr(self.handler, read_base)()

        self.assertEqual(self.backend.active, set())
        self.assertFalse(
            any(call[0] in {"write", "allocate", "free"} for call in self.backend.calls)
        )

    async def test_combined_activation_excludes_non_core_hooks_and_close_cleans_up(self):
        self.backend.bases.update(
            {hook: 0x2000 + index for index, hook in enumerate(CORE_HOOKS)}
        )
        await self.handler.activate_all_hooks(wait_for_ready=False)
        self.assertEqual(self.backend.active, CORE_HOOKS)
        self.assertNotIn("movement_teleport", self.backend.active)
        await self.handler.close()
        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.backend.calls[0], ("activate_all",))
        self.assertEqual(self.backend.calls[-1], ("deactivate_all",))

    async def test_zero_export_preserves_hook_not_ready_behavior(self):
        await self.handler.activate_client_hook(wait_for_ready=False)
        with self.assertRaises(HookNotReady):
            await self.handler.read_current_client_base()

    async def test_transient_heartbeat_failure_is_observable_and_retried(self):
        expected = RuntimeError("temporary heartbeat failure")
        self.backend.heartbeat_errors.append(expected)

        await self.handler._heartbeat_core_hooks_once()
        self.assertIs(self.handler._last_core_hook_heartbeat_error, expected)

        await self.handler._heartbeat_core_hooks_once()
        self.assertIsNone(self.handler._last_core_hook_heartbeat_error)
        self.assertEqual(
            self.backend.calls[-2:],
            [("heartbeat_all",), ("heartbeat_all",)],
        )


class LegacyReadError(Exception):
    pass


class LegacyReadBackend(MemoryBackend):
    def __init__(self):
        self.process = self

    def is_running(self):
        return True

    def read_bytes(self, address, size):
        raise LegacyReadError("transient read")

    def module_base(self, module_name):
        return None

    def is_read_error(self, error):
        return isinstance(error, LegacyReadError)


class LegacyWaitCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_transient_legacy_read_error_is_retried_without_pymem_import(self):
        handler = HookHandler(LegacyReadBackend(), client=object())
        with self.assertRaises(TimeoutError):
            await handler._wait_for_value(0x1000, timeout=0.01)


def descriptor(client_id, pid):
    return {
        "client_id": client_id,
        "process": {
            "pid": pid,
            "name": "WizardGraphicalClient.exe",
            "kind": "wizard101",
            "identity": {
                "pid": pid,
                "creation_time_100ns": str(1000 + pid),
                "executable_path": (
                    "C:\\ProgramData\\KingsIsle Entertainment\\Wizard101\\Bin\\"
                    "WizardGraphicalClient.exe"
                ),
            },
        },
        "is_foreground": False,
        "screen_order": 0,
    }


class BlockingHookManager:
    def __init__(self):
        self.activation_started = threading.Event()
        self.release_activation = threading.Event()
        self.closed_sessions = []
        self.core_bases = {
            "client": 0x1000,
            "player_stat": 0x2000,
        }

    def open_hook_process(self, pid, expected_identity_json=None):
        return {"session_id": f"hook-{pid}"}

    def activate_core_hooks(self, session_id):
        self.activation_started.set()
        if not self.release_activation.wait(2):
            raise TimeoutError("test did not release hook activation")
        return {"hooks": sorted(CORE_HOOKS)}

    def heartbeat_core_hooks(self, session_id):
        return {"hooks": sorted(CORE_HOOKS)}

    def deactivate_core_hooks(self, session_id):
        return {"hooks": []}

    def read_core_hook_base(self, session_id, hook):
        return self.core_bases.get(hook, 0)

    def read_memory(self, session_id, address, size):
        values = {
            (0x1000 + 192, 2): (4).to_bytes(2, "little", signed=True),
            (0x2000 + 324, 4): (170).to_bytes(4, "little", signed=True),
        }
        return values[(int(address, 16), size)]

    def close_process(self, session_id):
        self.closed_sessions.append(session_id)
        return {"closed": True}


class DiscoveredClientHookRaceTests(unittest.IsolatedAsyncioTestCase):
    async def _start_blocked_activation(self):
        manager = BlockingHookManager()
        client = DiscoveredClient(manager, descriptor("client-a", 448))
        task = asyncio.create_task(client.activate_hooks(wait_for_ready=False))
        self.assertTrue(
            await asyncio.to_thread(manager.activation_started.wait, 1),
            "hook activation should reach the agent",
        )
        return manager, client, task

    async def test_close_during_activation_rejects_and_closes_late_session(self):
        manager, client, task = await self._start_blocked_activation()
        await client.close()
        manager.release_activation.set()

        with self.assertRaisesRegex(RuntimeError, "changed identity"):
            await task
        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def test_identity_change_during_activation_rejects_stale_session(self):
        manager, client, task = await self._start_blocked_activation()
        client._update(descriptor("client-b", 544))
        manager.release_activation.set()

        with self.assertRaisesRegex(RuntimeError, "changed identity"):
            await task
        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def test_hook_session_binds_and_invalidates_legacy_memory_objects(self):
        manager = BlockingHookManager()
        client = DiscoveredClient(manager, descriptor("client-a", 448))

        handler, created = await client._ensure_hook_handler()

        self.assertTrue(created)
        for attribute in client._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            memory_object = getattr(client, attribute)
            self.assertIs(memory_object.hook_handler, handler)

        changed = descriptor("client-a", 448)
        changed["process"]["identity"]["creation_time_100ns"] = "9999"
        client._update(changed)
        await client.close()

        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        for attribute in client._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            self.assertFalse(hasattr(client, attribute))
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def test_bound_memory_objects_support_deimos_post_hook_initialization(self):
        manager = BlockingHookManager()
        manager.release_activation.set()
        client = DiscoveredClient(manager, descriptor("client-a", 448))

        await client.activate_hooks(wait_for_ready=False)

        async def client_address():
            return 0x1000

        async def stats_address():
            return 0x2000

        client.client_object._base_address_resolver = client_address
        client.stats._base_address_resolver = stats_address

        self.assertEqual(await client.client_object.speed_multiplier(), 4)
        self.assertEqual(await client.stats.reference_level(), 170)
        await client.close()
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def test_hook_memory_resolvers_refresh_dynamic_addresses_and_cache_signatures(self):
        manager = BlockingHookManager()
        client = DiscoveredClient(manager, descriptor("client-a", 448))
        handler = HookHandler(AgentCoreHookBackend(), client=client)
        dynamic = {
            "root_client_object": 0x1000,
            "actor_body": 0x2000,
            "game_stats": 0x3000,
        }
        scans = 0

        class FakeTelemetryContext:
            def __init__(self, memory, signature_addresses):
                self.signature_addresses = signature_addresses

            async def _resolve(self, name):
                nonlocal scans
                if b"stable-signature" not in self.signature_addresses:
                    scans += 1
                    self.signature_addresses[b"stable-signature"] = 0x9000
                return dynamic[name]

            async def root_client_object(self):
                return await self._resolve("root_client_object")

            async def actor_body(self):
                return await self._resolve("actor_body")

            async def game_stats(self):
                return await self._resolve("game_stats")

        with patch(
            "wizwalker.discovered_client._TelemetryReadContext",
            FakeTelemetryContext,
        ):
            objects = client._build_hook_memory_objects(handler)
            self.assertEqual(await objects["client_object"].read_base_address(), 0x1000)
            self.assertEqual(await objects["body"].read_base_address(), 0x2000)
            self.assertEqual(await objects["stats"].read_base_address(), 0x3000)

            dynamic.update(
                root_client_object=0x4000,
                actor_body=0x5000,
                game_stats=0x6000,
            )
            self.assertEqual(await objects["client_object"].read_base_address(), 0x4000)
            self.assertEqual(await objects["body"].read_base_address(), 0x5000)
            self.assertEqual(await objects["stats"].read_base_address(), 0x6000)

        self.assertEqual(scans, 1)

    def test_native_client_exposes_hook_backed_legacy_operations(self):
        client = DiscoveredClient(
            BlockingHookManager(),
            descriptor("client-a", 448),
        )

        for method_name in (
            "zone_name",
            "in_battle",
            "is_loading",
            "get_base_entity_list",
            "teleport",
        ):
            self.assertTrue(callable(getattr(client, method_name)))

        with self.assertRaises(AttributeError):
            getattr(client, "login")
