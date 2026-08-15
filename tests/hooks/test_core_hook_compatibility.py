import asyncio
import threading
import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
for import_root in (REPOSITORY_ROOT, WIZWALKER_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


from wizwalker import ClientHandler, HookAlreadyActivated, HookNotActive, HookNotReady
from wizwalker.discovered_client import DiscoveredClient
from wizwalker.generation import manager_generation_context
from wizwalker.client import Client
from wizwalker.memory.backends import MemoryBackend
from wizwalker.memory.handler import HookHandler
from wizwalker.memory.hooks import (
    ClientHook,
    DropsToggleHook,
    MemoryHook,
    MouselessCursorMoveHook,
)


class AgentCoreHookBackend(MemoryBackend):
    supports_core_hooks = True

    def __init__(self):
        self.process = self
        self.session_id = "core-hook-session"
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
        return {
            "session_id": self.session_id,
            "hooks": [
                {
                    "session_id": self.session_id,
                    "hook": hook,
                    "active": True,
                }
                for hook in sorted(self.active)
            ],
        }

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

    async def test_direct_agent_activation_preserves_primary_and_rollback_error(self):
        activation_error = RuntimeError("client hook activation failed")
        cleanup_error = RuntimeError("client hook rollback failed")
        self.backend.activate_core_hook = MagicMock(side_effect=activation_error)
        self.backend.deactivate_core_hook = MagicMock(side_effect=cleanup_error)

        with self.assertRaisesRegex(
            RuntimeError, "client hook activation failed"
        ) as caught:
            await self.handler.activate_client_hook(wait_for_ready=False)

        self.assertIs(caught.exception, activation_error)
        self.assertEqual(caught.exception.cleanup_errors, (cleanup_error,))
        self.assertEqual(self.handler._active_hooks.get(ClientHook), "client")

    async def test_terminal_core_rollback_is_diagnostic_and_releases_owner(self):
        activation_error = TimeoutError("client hook readiness failed")
        cleanup_error = RuntimeError("client process exited during rollback")
        self.handler._wait_for_core_hook = AsyncMock(side_effect=activation_error)
        self.backend.deactivate_core_hook = MagicMock(side_effect=cleanup_error)
        self.backend.is_closed_process_error = MagicMock(return_value=True)

        with self.assertRaisesRegex(
            TimeoutError, "client hook readiness failed"
        ) as caught:
            await self.handler.activate_client_hook(wait_for_ready=True)

        self.assertIs(caught.exception, activation_error)
        self.assertEqual(caught.exception.cleanup_errors, (cleanup_error,))
        self.assertNotIn(ClientHook, self.handler._active_hooks)
        self.assertNotIn("current_client", self.handler._base_addrs)
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

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

    async def test_agent_core_close_also_cleans_legacy_hook_and_cached_allocation(self):
        await self.handler.activate_all_hooks(wait_for_ready=False)
        self.handler._check_for_autobot = AsyncMock()
        self.handler._rewrite_autobot = AsyncMock()
        self.handler.free = AsyncMock()
        drops = SimpleNamespace(
            disable_drops_bool=0x7000,
            hook=AsyncMock(),
            unhook=AsyncMock(),
        )
        with patch(
            "wizwalker.memory.handler.DropsToggleHook", return_value=drops
        ):
            await self.handler.activate_drops_toggle_hook(wait_for_ready=False)

        cache_key = (MouselessCursorMoveHook, "mouse_pos_addr")
        self.handler._hook_cache[MouselessCursorMoveHook] = {
            "mouse_pos_addr": 0x8000
        }
        self.handler._register_cached_hook_allocation(*cache_key, 0x8000)

        await self.handler.close()

        drops.unhook.assert_awaited_once()
        self.handler.free.assert_awaited_once_with(0x8000)
        self.handler._rewrite_autobot.assert_awaited_once()
        self.assertIn(("deactivate_all",), self.backend.calls)
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertEqual(self.handler._cached_hook_allocations, {})

    async def test_hybrid_close_retries_shared_legacy_codecave_restore(self):
        await self.handler.activate_all_hooks(wait_for_ready=False)
        drops = SimpleNamespace(
            disable_drops_bool=0x7000,
            hook=AsyncMock(side_effect=RuntimeError("drops install failed")),
            unhook=AsyncMock(),
        )

        async def prepare_legacy_codecave():
            self.handler._autobot_address = 0x9000
            self.handler._autobot_pos = 128
            self.handler._original_autobot_bytes = b"original-autobot"

        self.handler._check_for_autobot = AsyncMock(
            side_effect=prepare_legacy_codecave
        )
        self.handler.read_bytes = AsyncMock(return_value=b"cleared-autobot")
        self.handler.write_bytes = AsyncMock(
            side_effect=[RuntimeError("codecave restore failed"), None]
        )

        with patch(
            "wizwalker.memory.handler.DropsToggleHook", return_value=drops
        ):
            with self.assertRaisesRegex(RuntimeError, "drops install failed"):
                await self.handler.activate_drops_toggle_hook(wait_for_ready=False)

        drops.unhook.assert_awaited_once()
        self.assertNotIn(DropsToggleHook, self.handler._active_hooks)
        self.assertEqual(self.handler._autobot_address, 0x9000)

        with self.assertRaisesRegex(RuntimeError, "codecave restore failed"):
            await self.handler.close()
        self.assertEqual(self.handler._autobot_address, 0x9000)
        self.assertEqual(self.handler._autobot_pos, 128)
        self.assertEqual(self.handler._active_hooks, {})

        await self.handler.close()
        self.assertIsNone(self.handler._autobot_address)
        self.assertEqual(self.handler._autobot_pos, 0)
        self.assertEqual(self.handler.write_bytes.await_count, 2)

    async def test_hybrid_terminal_process_errors_release_all_local_ownership(self):
        await self.handler.activate_all_hooks(wait_for_ready=False)
        terminal = RuntimeError("native session disappeared")
        terminal.code = "session_not_found"
        self.backend.is_closed_process_error = lambda error: (
            getattr(error, "code", None) == "session_not_found"
        )
        self.backend.deactivate_core_hooks = MagicMock(side_effect=terminal)

        class LocalHook:
            pass

        local = SimpleNamespace(unhook=AsyncMock(side_effect=terminal))
        self.handler._active_hooks[LocalHook] = local
        self.handler._legacy_hook_exports[LocalHook] = {"local_export"}
        self.handler._base_addrs["local_export"] = 0x7000

        cache_key = (MouselessCursorMoveHook, "mouse_pos_addr")
        self.handler._hook_cache[MouselessCursorMoveHook] = {
            "mouse_pos_addr": 0x8000
        }
        self.handler._register_cached_hook_allocation(*cache_key, 0x8000)
        self.handler.free = AsyncMock(side_effect=terminal)
        self.handler._autobot_address = 0x9000
        self.handler._autobot_pos = 128
        self.handler._rewrite_autobot = AsyncMock(side_effect=terminal)

        await self.handler.close()

        local.unhook.assert_awaited_once()
        self.handler.free.assert_awaited_once_with(0x8000)
        self.handler._rewrite_autobot.assert_awaited_once()
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertEqual(self.handler._cached_hook_allocations, {})
        self.assertIsNone(self.handler._autobot_address)
        self.assertEqual(self.handler._autobot_pos, 0)
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_zero_export_preserves_hook_not_ready_behavior(self):
        await self.handler.activate_client_hook(wait_for_ready=False)
        with self.assertRaises(HookNotReady):
            await self.handler.read_current_client_base()

    async def test_direct_agent_core_readiness_failure_rolls_back_hook(self):
        with self.assertRaisesRegex(TimeoutError, "Hook value took too long"):
            await self.handler.activate_client_hook(
                wait_for_ready=True, timeout=0.01
            )

        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_combined_activation_rolls_back_when_core_hooks_never_become_ready(self):
        with self.assertRaisesRegex(TimeoutError, "Hook value took too long"):
            await self.handler.activate_all_hooks(wait_for_ready=True, timeout=0.01)

        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)
        self.assertEqual(self.backend.calls[-1], ("deactivate_all",))

    async def test_heartbeat_failure_latches_for_the_hook_generation(self):
        expected = RuntimeError("temporary heartbeat failure")
        self.backend.heartbeat_errors.append(expected)
        await self.handler.activate_client_hook(wait_for_ready=False)

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        failure = self.handler._last_core_hook_heartbeat_error
        self.assertIs(failure.cause, expected)
        self.assertEqual(failure.scope, "core")

        self.assertFalse(await self.handler._heartbeat_core_hooks_once())
        self.assertIs(self.handler._last_core_hook_heartbeat_error, failure)
        self.assertEqual(
            [call for call in self.backend.calls if call == ("heartbeat_all",)],
            [("heartbeat_all",)],
        )

    def test_legacy_patterns_match_upstream_client_layout(self):
        self.assertEqual(
            HookHandler.AUTOBOT_PATTERN,
            (
                rb"\x48\x89\x5C\x24.\x48\x89\x74\x24.\x48\x89\x7C\x24."
                rb"\x55\x41\x54\x41\x55\x41\x56\x41\x57"
                rb"\x48\x8D\xAC\x24....\x48\x81\xEC...."
                rb"\x48\x8B\x05....\x48\x33\xC4\x48\x89\x85...."
                rb"\x4C\x8B\xF1.......\x80......\x0F\x84...."
            ),
        )
        self.assertEqual(HookHandler.AUTOBOT_SIZE, 4100)
        self.assertIn(rb"\x48\x8B\x7C\x24\x38", ClientHook.pattern)


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
    async def test_public_legacy_activation_rolls_back_each_install_stage(self):
        class StageFailureHook(MemoryHook):
            def __init__(self, handler, stage):
                super().__init__(handler)
                self.stage = stage
                self.player_struct = 0x3000
                self.target_write_failed = False

            async def get_pattern(self):
                return b"pattern", None

            async def get_jump_address(self, pattern, module=None):
                return 0x1000

            async def get_hook_address(self, size):
                self._allocated_addresses.append(0x2000)
                return 0x2000

            async def get_hook_bytecode(self):
                if self.stage == "before_jump":
                    raise RuntimeError("before jump failure")
                return b"hook"

            async def get_jump_bytecode(self):
                return b"jump"

            async def posthook(self):
                if self.stage == "posthook":
                    raise RuntimeError("posthook failure")

        for stage in ("before_jump", "target_write", "posthook"):
            with self.subTest(stage=stage):
                handler = HookHandler(LegacyReadBackend(), client=object())
                handler._check_for_autobot = AsyncMock()
                hook = StageFailureHook(handler, stage)
                hook.read_bytes = AsyncMock(return_value=b"orig")
                hook.free = AsyncMock()

                async def write(address, value, *, current=hook):
                    if (
                        current.stage == "target_write"
                        and address == 0x1000
                        and value == b"jump"
                        and not current.target_write_failed
                    ):
                        current.target_write_failed = True
                        raise RuntimeError("target write failure")

                hook.write_bytes = AsyncMock(side_effect=write)
                with patch(
                    "wizwalker.memory.handler.PlayerHook", return_value=hook
                ):
                    with self.assertRaisesRegex(RuntimeError, "failure"):
                        await handler.activate_player_hook(wait_for_ready=False)

                self.assertEqual(handler._active_hooks, {})
                self.assertEqual(handler._base_addrs, {})
                hook.free.assert_awaited_once_with(0x2000)
                if stage in {"target_write", "posthook"}:
                    hook.write_bytes.assert_any_await(0x1000, b"orig")

    async def test_failed_legacy_rollback_remains_owned_for_close_retry(self):
        handler = HookHandler(LegacyReadBackend(), client=object())
        handler._check_for_autobot = AsyncMock()
        handler._rewrite_autobot = AsyncMock()
        hook = SimpleNamespace(
            player_struct=0x3000,
            hook=AsyncMock(side_effect=RuntimeError("posthook failure")),
            unhook=AsyncMock(
                side_effect=[RuntimeError("jump restore failed"), None]
            ),
        )

        with patch("wizwalker.memory.handler.PlayerHook", return_value=hook):
            with self.assertRaisesRegex(RuntimeError, "posthook failure"):
                await handler.activate_player_hook(wait_for_ready=False)

        self.assertEqual(tuple(handler._active_hooks.values()), (hook,))
        await handler.close()
        self.assertEqual(handler._active_hooks, {})
        self.assertEqual(hook.unhook.await_count, 2)

    async def test_direct_legacy_readiness_failure_rolls_back_registered_hook(self):
        handler = HookHandler(LegacyReadBackend(), client=object())
        handler._check_for_autobot = AsyncMock()
        handler._wait_for_value = AsyncMock(
            side_effect=TimeoutError("hook never became ready")
        )
        hook = SimpleNamespace(
            player_struct=0x3000,
            hook=AsyncMock(),
            unhook=AsyncMock(),
        )

        with patch("wizwalker.memory.handler.PlayerHook", return_value=hook):
            with self.assertRaisesRegex(TimeoutError, "never became ready"):
                await handler.activate_player_hook(wait_for_ready=True)

        self.assertEqual(handler._active_hooks, {})
        self.assertEqual(handler._base_addrs, {})
        hook.unhook.assert_awaited_once()

    def test_legacy_client_opens_process_only_after_object_construction(self):
        pymem_instance = MagicMock()
        fake_pymem = SimpleNamespace(Pymem=MagicMock(return_value=pymem_instance))

        with (
            patch("wizwalker.client.import_module", return_value=fake_pymem),
            patch("wizwalker.client.HookHandler", return_value=object()),
            patch("wizwalker.client.CacheHandler", return_value=object()),
            patch("wizwalker.client.MouseHandler", return_value=object()),
            patch(
                "wizwalker.client.CurrentGameStats",
                side_effect=RuntimeError("memory object construction failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "construction failed"):
                Client(0x1234)

        pymem_instance.open_process_from_id.assert_not_called()

    async def test_transient_legacy_read_error_is_retried_without_pymem_import(self):
        handler = HookHandler(LegacyReadBackend(), client=object())
        with self.assertRaises(TimeoutError):
            await handler._wait_for_value(0x1000, timeout=0.01)

    async def test_combined_activation_rolls_back_completed_legacy_hooks_in_reverse(self):
        handler = HookHandler(LegacyReadBackend(), client=object())
        calls = []
        handler._autobot_address = 0x1000
        handler._autobot_pos = 320
        handler._original_autobot_bytes = b"original-autobot"
        handler.read_bytes = AsyncMock(return_value=b"cleared-autobot!")
        handler.write_bytes = AsyncMock()

        async def activate(name):
            calls.append(("activate", name))
            if name == "player_stat":
                raise RuntimeError("forced player_stat failure")

        async def deactivate(name):
            calls.append(("deactivate", name))

        def activation_for(name):
            async def activation(*args, **kwargs):
                await activate(name)

            return activation

        def deactivation_for(name):
            async def deactivation():
                await deactivate(name)

            return deactivation

        hook_names = (
            "player",
            "quest",
            "player_stat",
            "client",
            "root_window",
            "render_context",
            "movement_teleport",
            "drops_toggle",
        )
        for name in hook_names:
            setattr(
                handler,
                f"activate_{name}_hook",
                AsyncMock(side_effect=activation_for(name)),
            )
            setattr(
                handler,
                f"deactivate_{name}_hook",
                AsyncMock(side_effect=deactivation_for(name)),
            )

        with self.assertRaisesRegex(RuntimeError, "forced player_stat failure"):
            await handler.activate_all_hooks(wait_for_ready=False)

        self.assertEqual(
            calls,
            [
                ("activate", "player"),
                ("activate", "quest"),
                ("activate", "player_stat"),
                ("deactivate", "quest"),
                ("deactivate", "player"),
            ],
        )
        handler.read_bytes.assert_not_awaited()
        handler.write_bytes.assert_not_awaited()
        self.assertEqual(handler._autobot_address, 0x1000)
        self.assertEqual(handler._autobot_pos, 320)

    async def test_combined_legacy_activation_retains_every_rollback_failure(self):
        handler = HookHandler(LegacyReadBackend(), client=object())
        primary_error = RuntimeError("third hook activation failed")
        quest_cleanup_error = RuntimeError("quest rollback failed")
        player_cleanup_error = ValueError("player rollback failed")

        handler.activate_player_hook = AsyncMock()
        handler.activate_quest_hook = AsyncMock()
        handler.activate_player_stat_hook = AsyncMock(side_effect=primary_error)
        handler.deactivate_quest_hook = AsyncMock(side_effect=quest_cleanup_error)
        handler.deactivate_player_hook = AsyncMock(side_effect=player_cleanup_error)

        with self.assertRaisesRegex(
            RuntimeError, "third hook activation failed"
        ) as caught:
            await handler.activate_all_hooks(wait_for_ready=False)

        self.assertIs(caught.exception, primary_error)
        self.assertEqual(
            caught.exception.cleanup_errors,
            (quest_cleanup_error, player_cleanup_error),
        )

    async def test_legacy_close_retains_only_failed_hook_until_retry(self):
        handler = HookHandler(LegacyReadBackend(), client=object())
        first_type = type("FirstHook", (), {})
        second_type = type("SecondHook", (), {})
        first = SimpleNamespace(unhook=AsyncMock())
        second = SimpleNamespace(
            unhook=AsyncMock(side_effect=[RuntimeError("jump restore failed"), None])
        )
        handler._active_hooks = {first_type: first, second_type: second}
        handler._rewrite_autobot = AsyncMock()

        with self.assertRaisesRegex(RuntimeError, "jump restore failed"):
            await handler.close()

        self.assertNotIn(first_type, handler._active_hooks)
        self.assertIs(handler._active_hooks[second_type], second)
        handler._rewrite_autobot.assert_not_awaited()

        await handler.close()
        self.assertEqual(handler._active_hooks, {})
        self.assertEqual(second.unhook.await_count, 2)
        handler._rewrite_autobot.assert_awaited_once()

    async def test_legacy_detach_gates_operations_and_serializes_hook_close(self):
        client = Client.__new__(Client)
        client.window_handle = 0x1234
        client._detach_started = False
        client._hook_lifecycle_lock = asyncio.Lock()
        client._close_lock = asyncio.Lock()
        client._movement_update_patched = False
        cleanup_started = asyncio.Event()
        allow_cleanup = asyncio.Event()

        class Handler:
            async def close(self):
                cleanup_started.set()
                await allow_cleanup.wait()

            async def activate_all_hooks(self, **kwargs):
                raise AssertionError("detaching client must not activate hooks")

        client.hook_handler = Handler()
        client._unpatch_movement_update = AsyncMock()

        with patch.object(client, "_process_is_running", return_value=True):
            closing = asyncio.create_task(client.close())
            await cleanup_started.wait()
            self.assertFalse(client.is_running())
            with self.assertRaisesRegex(RuntimeError, "detaching"):
                await client.activate_hooks(wait_for_ready=False)
            with self.assertRaisesRegex(RuntimeError, "detaching"):
                await client.send_key(0x57)
            with self.assertRaisesRegex(RuntimeError, "detaching"):
                client.login("wizard", "secret")
            with self.assertRaisesRegex(RuntimeError, "detaching"):
                await client.zone_name()
            with self.assertRaisesRegex(RuntimeError, "detaching"):
                await client.get_base_entity_list()
            with self.assertRaisesRegex(RuntimeError, "detaching"):
                await client.get_world_view_window()
            allow_cleanup.set()
            await closing

        client._unpatch_movement_update.assert_awaited_once()
        with patch.object(client, "_process_is_running", return_value=False):
            await client.close()
        client._unpatch_movement_update.assert_awaited_once()


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
    cleanup_instance_id = "test-helper"

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

    def close_process_for_instance(self, session_id, instance_id):
        if instance_id != self.cleanup_instance_id:
            error = RuntimeError("helper changed")
            error.code = "identity_mismatch"
            raise error
        return self.close_process(session_id)

    def deactivate_core_hooks_for_instance(self, session_id, instance_id):
        if instance_id != self.cleanup_instance_id:
            error = RuntimeError("helper changed")
            error.code = "identity_mismatch"
            raise error
        return self.deactivate_core_hooks(session_id)


def bound_client(manager, client_descriptor):
    context = manager_generation_context(manager, manager.cleanup_instance_id)
    return DiscoveredClient(
        manager,
        client_descriptor,
        generation_context=context,
    )


class DiscoveredClientHookRaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_memory_object_construction_failure_closes_unpublished_session(self):
        manager = BlockingHookManager()
        client = bound_client(manager, descriptor("client-a", 448))
        client._build_hook_memory_objects = MagicMock(
            side_effect=RuntimeError("memory object construction failed")
        )

        with self.assertRaisesRegex(RuntimeError, "construction failed"):
            await client._ensure_hook_handler()

        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertEqual(manager.closed_sessions, ["hook-448"])
        self.assertEqual(client._pending_session_cleanup_ids, set())

    async def test_failed_construction_cleanup_retains_session_id_for_retry(self):
        class RetryManager(BlockingHookManager):
            def __init__(self):
                super().__init__()
                self.fail_close = True

            def close_process(self, session_id):
                if self.fail_close:
                    raise RuntimeError("construction cleanup failed")
                return super().close_process(session_id)

        manager = RetryManager()
        client = bound_client(manager, descriptor("client-a", 448))
        client._build_hook_memory_objects = MagicMock(
            side_effect=RuntimeError("memory object construction failed")
        )

        with self.assertRaisesRegex(
            RuntimeError, "memory object construction failed"
        ) as caught:
            await client._ensure_hook_handler()

        self.assertEqual(
            [str(error) for error in caught.exception.cleanup_errors],
            ["construction cleanup failed"],
        )

        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertEqual(client._pending_session_cleanup_ids, {"hook-448"})

        manager.fail_close = False
        await client._await_session_cleanup()
        self.assertEqual(client._pending_session_cleanup_ids, set())
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def _start_blocked_activation(self):
        manager = BlockingHookManager()
        client = bound_client(manager, descriptor("client-a", 448))
        task = asyncio.create_task(client.activate_hooks(wait_for_ready=False))
        self.assertTrue(
            await asyncio.to_thread(manager.activation_started.wait, 1),
            "hook activation should reach the agent",
        )
        return manager, client, task

    async def test_close_during_activation_rejects_and_closes_late_session(self):
        manager, client, task = await self._start_blocked_activation()
        closing = asyncio.create_task(client.close())
        await asyncio.sleep(0)
        self.assertFalse(client.is_running())
        manager.release_activation.set()

        with self.assertRaisesRegex(RuntimeError, "closed while"):
            await task
        await closing
        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def test_identity_change_during_activation_rejects_stale_session(self):
        manager, client, task = await self._start_blocked_activation()
        with self.assertRaisesRegex(RuntimeError, "process identity changed"):
            client._update(descriptor("client-b", 544))
        manager.release_activation.set()

        with self.assertRaisesRegex(RuntimeError, "closed while"):
            await task
        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def test_retirement_race_retains_a_late_hook_session_after_close_failure(self):
        current = descriptor("client-a", 448)

        class LateOpenManager(BlockingHookManager):
            def __init__(self):
                super().__init__()
                self.snapshots = iter(([current], [current], [current]))
                self.open_started = threading.Event()
                self.release_open = threading.Event()
                self.fail_close = True

            def list_clients(self):
                return {"clients": next(self.snapshots)}

            def open_hook_process(self, pid, expected_identity_json=None):
                self.open_started.set()
                if not self.release_open.wait(2):
                    raise TimeoutError("test did not release hook session open")
                return {"session_id": f"hook-{pid}"}

            def close_process(self, session_id):
                if self.fail_close:
                    error = RuntimeError("hook cleanup transport failed")
                    error.code = "transport_error"
                    raise error
                return super().close_process(session_id)

        manager = LateOpenManager()
        handler = ClientHandler(agent_manager=manager)
        previous = handler.get_new_clients()[0]
        opening = asyncio.create_task(previous._ensure_hook_handler())
        self.assertTrue(
            await asyncio.to_thread(manager.open_started.wait, 1),
            "the native open_hook_process call did not start",
        )

        handler.retire_native_clients()
        self.assertEqual(handler.get_new_clients(), [])
        manager.release_open.set()

        with self.assertRaisesRegex(
            RuntimeError, "changed while its hook session was opening"
        ) as caught:
            await opening
        self.assertEqual(
            [str(error) for error in caught.exception.cleanup_errors],
            ["hook cleanup transport failed"],
        )
        self.assertEqual(handler.clients, [])
        self.assertNotIn(previous, handler.clients)
        self.assertIn(previous, handler._retired_clients)
        self.assertEqual(previous._pending_session_cleanup_ids, {"hook-448"})

        manager.fail_close = False
        await previous.close()
        self.assertEqual(previous._pending_session_cleanup_ids, set())
        self.assertEqual(manager.closed_sessions, ["hook-448"])
        replacement = handler.get_new_clients()[0]
        self.assertIsNot(replacement, previous)
        self.assertEqual(handler.clients, [replacement])

    async def test_hook_session_binds_and_invalidates_legacy_memory_objects(self):
        manager = BlockingHookManager()
        client = bound_client(manager, descriptor("client-a", 448))

        handler, created = await client._ensure_hook_handler()

        self.assertTrue(created)
        for attribute in client._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            memory_object = getattr(client, attribute)
            self.assertIs(memory_object.hook_handler, handler)

        client._mark_closed()
        await client.close()

        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        for attribute in client._HOOK_MEMORY_OBJECT_ATTRIBUTES:
            self.assertFalse(hasattr(client, attribute))
        self.assertEqual(manager.closed_sessions, ["hook-448"])

    async def test_failed_native_unhook_keeps_handler_and_sessions_until_retry(self):
        class RetryManager(BlockingHookManager):
            def __init__(self):
                super().__init__()
                self.release_activation.set()
                self.fail_deactivation = True

            def deactivate_core_hooks(self, session_id):
                if self.fail_deactivation:
                    raise RuntimeError("core hook cleanup failed")
                return super().deactivate_core_hooks(session_id)

        manager = RetryManager()
        client = bound_client(manager, descriptor("client-a", 448))
        await client.activate_hooks(wait_for_ready=False)
        original_handler = client.hook_handler
        client._session_id = "telemetry-448"
        client._telemetry_reader = object()

        with self.assertRaisesRegex(RuntimeError, "core hook cleanup failed"):
            await client.close()

        self.assertFalse(client.is_running())
        self.assertIs(client.hook_handler, original_handler)
        self.assertEqual(client._hook_session_id, "hook-448")
        self.assertEqual(client._session_id, "telemetry-448")
        self.assertEqual(manager.closed_sessions, [])
        with self.assertRaisesRegex(RuntimeError, "retired native session"):
            _ = client.title

        manager.fail_deactivation = False
        await client.close()
        self.assertIsNone(client.hook_handler)
        self.assertIsNone(client._hook_session_id)
        self.assertIsNone(client._session_id)
        self.assertEqual(
            manager.closed_sessions,
            ["hook-448", "telemetry-448"],
        )

    async def test_bound_memory_objects_support_deimos_post_hook_initialization(self):
        manager = BlockingHookManager()
        manager.release_activation.set()
        client = bound_client(manager, descriptor("client-a", 448))

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

    async def test_hook_memory_objects_follow_agent_core_hook_exports(self):
        manager = BlockingHookManager()
        client = bound_client(manager, descriptor("client-a", 448))
        backend = AgentCoreHookBackend()
        handler = HookHandler(backend, client=client)
        handler._base_addrs.update(
            current_client="client",
            player_struct="player",
            player_stat_struct="player_stat",
        )
        backend.bases.update(client=0x1000, player=0x2000, player_stat=0x3000)
        objects = client._build_hook_memory_objects(handler)

        self.assertEqual(await objects["client_object"].read_base_address(), 0x1000)
        self.assertEqual(await objects["body"].read_base_address(), 0x2000)
        self.assertEqual(await objects["stats"].read_base_address(), 0x3000)

        backend.bases.update(client=0x4000, player=0x5000, player_stat=0x6000)
        self.assertEqual(await objects["client_object"].read_base_address(), 0x4000)
        self.assertEqual(await objects["body"].read_base_address(), 0x5000)
        self.assertEqual(await objects["stats"].read_base_address(), 0x6000)
        self.assertEqual(
            [call for call in backend.calls if call[0] == "read_base"],
            [
                ("read_base", "client"),
                ("read_base", "player"),
                ("read_base", "player_stat"),
                ("read_base", "client"),
                ("read_base", "player"),
                ("read_base", "player_stat"),
            ],
        )

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
