import asyncio
import threading
import unittest
import sys
from types import SimpleNamespace


sys.modules.setdefault(
    "loguru",
    SimpleNamespace(logger=SimpleNamespace(debug=lambda *args, **kwargs: None)),
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

    def open_hook_process(self, pid, expected_identity_json=None):
        return {"session_id": f"hook-{pid}"}

    def activate_core_hooks(self, session_id):
        self.activation_started.set()
        if not self.release_activation.wait(2):
            raise TimeoutError("test did not release hook activation")
        return {"hooks": sorted(CORE_HOOKS)}

    def heartbeat_core_hooks(self, session_id):
        return {"hooks": sorted(CORE_HOOKS)}

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
