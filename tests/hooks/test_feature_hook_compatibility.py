import asyncio
import struct
import sys
import threading
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
for import_root in (REPOSITORY_ROOT, WIZWALKER_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


if "pymem" not in sys.modules:
    pymem = ModuleType("pymem")
    pymem_exception = ModuleType("pymem.exception")
    pymem_process = ModuleType("pymem.process")
    pymem_exception.MemoryReadError = RuntimeError
    pymem.Pymem = object
    pymem.exception = pymem_exception
    pymem.process = pymem_process
    sys.modules["pymem"] = pymem
    sys.modules["pymem.exception"] = pymem_exception
    sys.modules["pymem.process"] = pymem_process
sys.modules.setdefault("winreg", ModuleType("winreg"))
sys.modules.setdefault(
    "appdirs", SimpleNamespace(user_data_dir=lambda *args, **kwargs: ".")
)

import wizwalker as wizwalker_package
from wizwalker import HookAlreadyActivated, HookNotActive
from wizwalker.utils import Orient, Rectangle, XYZ

wizwalker_package.CacheHandler = object
wizwalker_package.Orient = Orient
wizwalker_package.Rectangle = Rectangle
wizwalker_package.XYZ = XYZ
import wizwalker.memory as wizwalker_memory
from wizwalker.memory.backends import MemoryBackend
from wizwalker.memory.handler import HookHandler
wizwalker_memory.HookHandler = HookHandler
from wizwalker.memory.hooks import (
    ChatHook,
    ChatSendHook,
    MouselessCursorMoveHook,
    MovementTeleportHook,
    SimpleHook,
)
from wizwalker.memory.memory_objects import (
    CurrentActorBody,
    CurrentChatOwner,
    CurrentClientObject,
    CurrentDuel,
    CurrentGameClient,
    CurrentGameStats,
    CurrentQuestPosition,
    CurrentRenderContext,
    CurrentRootWindow,
    CurrentSocialSystemsManager,
    TeleportHelper,
)
from wizwalker.memory.memory_objects.enums import DuelPhase

for exported_name, exported_value in {
    "CurrentActorBody": CurrentActorBody,
    "CurrentChatOwner": CurrentChatOwner,
    "CurrentClientObject": CurrentClientObject,
    "CurrentDuel": CurrentDuel,
    "CurrentGameClient": CurrentGameClient,
    "CurrentGameStats": CurrentGameStats,
    "CurrentQuestPosition": CurrentQuestPosition,
    "CurrentRenderContext": CurrentRenderContext,
    "CurrentRootWindow": CurrentRootWindow,
    "CurrentSocialSystemsManager": CurrentSocialSystemsManager,
    "DuelPhase": DuelPhase,
    "HookHandler": HookHandler,
    "MovementTeleportHook": MovementTeleportHook,
    "TeleportHelper": TeleportHelper,
}.items():
    setattr(wizwalker_memory, exported_name, exported_value)

from wizwalker.client import Client
wizwalker_package.Client = Client
wizwalker_memory.SimpleHook = SimpleHook
from src import dance_game_hook


async def async_value(value):
    return value


class AgentFeatureHookBackend(MemoryBackend):
    supports_core_hooks = True
    supports_feature_hooks = True

    def __init__(self):
        self.process = self
        self.session_id = "feature-hook-session"
        self.active = set()
        export_names = (
            "teleport_helper",
            "mouse_position",
            "chat_owner",
            "recv_source_gid",
            "recv_message_buf",
            "recv_message_len",
            "recv_counter",
            "send_trigger",
            "send_struct",
            "buddy_trigger",
            "buddy_obj",
            "dance_game_moves",
        )
        self.exports = {
            name: 0x1000 + index * 0x200
            for index, name in enumerate(export_names)
        }
        self.memory = {}
        self.calls = []
        self.core_active = False
        self.fail_feature_activation = None
        self.fail_feature_deactivation = None
        self.fail_feature_export = None

    def is_running(self):
        return True

    def read_bytes(self, address, size):
        for base, value in self.memory.items():
            if base <= address and address + size <= base + len(value):
                offset = address - base
                return value[offset : offset + size]
        return bytes(size)

    def write_bytes(self, address, value, size=None):
        raise AssertionError("feature compatibility must not issue raw writes")

    def allocate(self, size):
        raise AssertionError("feature compatibility must not allocate from Python")

    def free(self, address):
        raise AssertionError("feature compatibility must not free from Python")

    def start_thread(self, address):
        raise AssertionError("feature compatibility must not start remote threads from Python")

    def module_base(self, module_name):
        raise AssertionError("feature compatibility must not scan in Python")

    def activate_feature_hook(self, hook):
        self.calls.append(("activate", hook))
        if self.fail_feature_activation == hook:
            raise RuntimeError(f"forced {hook} activation failure")
        self.active.add(hook)
        return {"hook": hook, "active": True}

    def deactivate_feature_hook(self, hook):
        self.calls.append(("deactivate", hook))
        if self.fail_feature_deactivation == hook:
            raise RuntimeError(f"forced {hook} deactivation failure")
        self.active.discard(hook)
        return {"hook": hook, "deactivated": True}

    def heartbeat_feature_hooks(self):
        self.calls.append(("heartbeat",))
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

    def heartbeat_core_hooks(self):
        return {"session_id": self.session_id, "hooks": []}

    def deactivate_core_hooks(self):
        self.calls.append(("deactivate_core_hooks",))
        self.core_active = False
        return {"hooks": []}

    def activate_core_hooks(self):
        self.calls.append(("activate_core_hooks",))
        self.core_active = True
        return {"hooks": []}

    def read_core_hook_base(self, hook):
        return 0x9000

    def read_feature_hook_export(self, export):
        self.calls.append(("read_export", export))
        if self.fail_feature_export == export:
            raise RuntimeError(f"forced {export} export failure")
        return self.exports[export]

    def set_feature_mouse_position(self, x, y):
        self.calls.append(("mouse", x, y))
        return {"completed": True}

    def feature_teleport(self, object_address, position, **options):
        self.calls.append(("teleport", object_address, position, options))
        return {"completed": True}

    def feature_send_chat(self, message, target_gid):
        self.calls.append(("send_chat", message, target_gid))
        return {"completed": True}

    def feature_add_buddy(self, target_gid):
        self.calls.append(("add_buddy", target_gid))
        return {"completed": True}

    def set_memory(self, export, value):
        self.memory[self.exports[export]] = bytes(value)


class FeatureHookCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.backend = AgentFeatureHookBackend()
        self.handler = HookHandler(self.backend, client=object())

    async def test_feature_lifecycle_uses_semantic_agent_operations(self):
        cases = (
            (
                MovementTeleportHook,
                "movement_teleport",
                self.handler.activate_movement_teleport_hook,
                self.handler.deactivate_movement_teleport_hook,
            ),
            (
                MouselessCursorMoveHook,
                "mouseless_cursor",
                self.handler.activate_mouseless_cursor_hook,
                self.handler.deactivate_mouseless_cursor_hook,
            ),
            (ChatHook, "chat", self.handler.activate_chat_hook, self.handler.deactivate_chat_hook),
            (
                ChatSendHook,
                "chat_send",
                self.handler.activate_chat_send_hook,
                self.handler.deactivate_chat_send_hook,
            ),
        )
        for hook_type, name, activate, deactivate in cases:
            if hook_type is ChatHook:
                await activate(wait_for_ready=False)
            else:
                await activate()
            self.assertIn(name, self.backend.active)
            with self.assertRaises(HookAlreadyActivated):
                if hook_type is ChatHook:
                    await activate(wait_for_ready=False)
                else:
                    await activate()
            await deactivate()
            self.assertNotIn(name, self.backend.active)
            with self.assertRaises(HookNotActive):
                await deactivate()

    async def test_feature_actions_never_fall_back_to_raw_python_mutation(self):
        await self.handler.activate_movement_teleport_hook()
        client = Client.__new__(Client)
        client.hook_handler = self.handler
        client._teleport_helper = SimpleNamespace(
            should_update=lambda: async_value(False)
        )
        await client._teleport_object(
            0x1234,
            SimpleNamespace(x=1.0, y=2.0, z=3.0),
        )

        await self.handler.activate_mouseless_cursor_hook()
        await self.handler.write_mouse_position(40, 80)

        await self.handler.activate_chat_send_hook()
        chat = CurrentChatOwner(self.handler)
        await chat.send_msg("hello from a long semantic message", 55)
        await chat.add_player(77)

        await dance_game_hook.activate_dance_game_moves_hook(self.handler)
        self.backend.set_memory("dance_game_moves", b"abcd\0\0\0\0")
        self.assertEqual(
            await dance_game_hook.read_current_dance_game_moves(self.handler),
            "WDSA",
        )

        self.assertTrue(any(call[0] == "teleport" for call in self.backend.calls))
        self.assertIn(("mouse", 40, 80), self.backend.calls)
        self.assertIn(
            ("send_chat", "hello from a long semantic message", 55),
            self.backend.calls,
        )
        self.assertIn(("add_buddy", 77), self.backend.calls)

    async def test_legacy_dynamic_feature_uses_transactional_hook_ownership(self):
        self.handler._uses_agent_feature_hooks = lambda: False
        self.handler._check_for_autobot = AsyncMock()
        hook = SimpleNamespace(
            dance_game_moves=0x3000,
            hook=AsyncMock(side_effect=RuntimeError("dance posthook failure")),
            unhook=AsyncMock(),
        )

        with patch.object(dance_game_hook, "DanceGameMovesHook", return_value=hook):
            with self.assertRaisesRegex(RuntimeError, "dance posthook failure"):
                await dance_game_hook.activate_dance_game_moves_hook(self.handler)

        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        hook.unhook.assert_awaited_once()

    async def test_legacy_movement_hook_matches_current_client_layout(self):
        movement_jumps = (0x2000, 0x3000)

        async def get_movement_jumps():
            return movement_jumps

        hook = MovementTeleportHook.__new__(MovementTeleportHook)
        hook.hook_handler = SimpleNamespace(
            client=SimpleNamespace(
                _get_je_instruction_forward_backwards=get_movement_jumps
            ),
            read_bytes=AsyncMock(
                side_effect=(b"\x0f\x84\x01\x02\x03\x04\xaa\xbb", b"\x0f\x84\x05\x06\x07\x08\xcc\xdd")
            ),
        )
        hook.pattern_scan = AsyncMock(return_value=0x4000)
        hook.read_bytes = AsyncMock(return_value=b"\x74\x24")
        hook.write_bytes = AsyncMock()
        hook._set_page_protection = lambda address, protection: 0x20

        await hook.prehook()
        self.assertEqual(hook.pattern_scan.await_count, 2)
        hook.pattern_scan.assert_any_await(
            rb"\x74.\xF3\x0F\x10\x55\xA8",
            module="WizardGraphicalClient.exe",
        )
        hook.pattern_scan.assert_any_await(
            rb"\x74.\xF3\x0F\x10\x44\x24\x54\xF3\x0F",
            module="WizardGraphicalClient.exe",
        )
        self.assertEqual(hook.write_bytes.await_count, 2)
        hook.write_bytes.assert_any_await(0x4000, b"\x90\x90")
        self.assertEqual(hook._collision_je_addrs, (0x4000, 0x4000))
        self.assertEqual(
            hook._old_collision_jes_bytes,
            (b"\x74\x24", b"\x74\x24"),
        )

        bytecode = await hook.bytecode_generator((("teleport_helper", struct.pack("<Q", 0x1000)),))
        self.assertTrue(bytecode.endswith(b"\x57\x48\x83\xEC\x20"))
        self.assertTrue(
            MovementTeleportHook.pattern.startswith(
                rb"\x57\x48\x83\xEC"
            )
        )

    async def test_partial_legacy_movement_construction_skips_unpublished_readiness(self):
        backend = AgentFeatureHookBackend()
        backend.supports_core_hooks = False
        backend.supports_feature_hooks = False
        backend.supports_allocation = True
        backend.allocate = MagicMock(return_value=0x5000)
        backend.free = MagicMock(
            side_effect=[RuntimeError("export free failed"), None]
        )
        should_update = AsyncMock(
            side_effect=AssertionError("unpublished helper must not be read")
        )
        handler = HookHandler(
            backend,
            client=SimpleNamespace(
                _teleport_helper=SimpleNamespace(should_update=should_update)
            ),
        )
        handler._rewrite_autobot = AsyncMock()
        hook = MovementTeleportHook(handler)
        hook.get_jump_address = AsyncMock(return_value=0x1000)
        hook.get_hook_address = AsyncMock(return_value=0x2000)
        hook.bytecode_generator = AsyncMock(
            side_effect=RuntimeError("movement bytecode failed")
        )

        with self.assertRaisesRegex(RuntimeError, "movement bytecode failed"):
            await handler._activate_legacy_hook(
                MovementTeleportHook,
                hook,
                {"teleport_helper": "teleport_helper"},
            )

        self.assertIs(handler._active_hooks.get(MovementTeleportHook), hook)
        self.assertEqual(handler._base_addrs, {})
        self.assertEqual(backend.free.call_count, 1)
        should_update.assert_not_awaited()

        await handler.close()
        self.assertEqual(handler._active_hooks, {})
        self.assertEqual(backend.free.call_count, 2)
        should_update.assert_not_awaited()

        await hook.unhook()
        self.assertEqual(backend.free.call_count, 2)

    async def test_movement_auxiliary_restore_failure_keeps_export_for_retry(self):
        backend = AgentFeatureHookBackend()
        backend.supports_core_hooks = False
        backend.supports_feature_hooks = False
        backend.supports_allocation = True
        backend.free = MagicMock()
        should_update = AsyncMock(return_value=False)

        async def movement_jumps():
            return (0x3000, 0x4000)

        handler = HookHandler(
            backend,
            client=SimpleNamespace(
                _teleport_helper=SimpleNamespace(should_update=should_update),
                _get_je_instruction_forward_backwards=movement_jumps,
            ),
        )
        handler._rewrite_autobot = AsyncMock()
        handler.write_bytes = AsyncMock(
            side_effect=[
                RuntimeError("JE restore failed"),
                None,
                None,
                None,
            ]
        )
        hook = MovementTeleportHook(handler)
        hook.teleport_helper = 0x5000
        hook.jump_address = 0x1000
        hook.jump_original_bytecode = b"original-jump"
        hook._jump_write_started = True
        hook._old_jes_bytes = (b"old-je-one", b"old-je-two")
        hook._collision_je_addrs = (0x6000, 0x7000)
        hook._old_collision_jes_bytes = (b"c1", b"c2")
        hook._old_je_page_protection = 0x20
        hook.write_bytes = AsyncMock()
        hook._set_page_protection = MagicMock(return_value=0x40)
        handler._active_hooks[MovementTeleportHook] = hook
        handler._base_addrs["teleport_helper"] = hook.teleport_helper

        with self.assertRaisesRegex(RuntimeError, "JE restore failed"):
            await handler.deactivate_movement_teleport_hook()

        self.assertIs(handler._active_hooks.get(MovementTeleportHook), hook)
        self.assertEqual(handler._base_addrs["teleport_helper"], 0x5000)
        backend.free.assert_not_called()
        should_update.assert_awaited_once()
        self.assertFalse(hook._jump_write_started)

        await handler.close()
        self.assertEqual(handler._active_hooks, {})
        self.assertEqual(handler._base_addrs, {})
        backend.free.assert_called_once_with(0x5000)
        should_update.assert_awaited_once()
        self.assertIsNone(hook._old_jes_bytes)

    async def test_mouseless_cached_allocation_is_owned_until_final_close(self):
        backend = AgentFeatureHookBackend()
        backend.supports_core_hooks = False
        backend.supports_feature_hooks = False
        backend.supports_allocation = True
        backend.allocate = MagicMock(return_value=0x8000)
        backend.free = MagicMock(
            side_effect=[RuntimeError("cached free failed"), None]
        )
        handler = HookHandler(backend, client=object())
        handler._rewrite_autobot = AsyncMock()
        hook = MouselessCursorMoveHook(handler, handler._hook_cache)

        async def allocate_then_fail():
            await hook.set_mouse_pos_addr()
            raise RuntimeError("mouseless construction failed")

        hook.hook = allocate_then_fail
        with self.assertRaisesRegex(RuntimeError, "mouseless construction failed"):
            await handler._activate_legacy_hook(
                MouselessCursorMoveHook,
                hook,
                {"mouse_position": "mouse_pos_addr"},
            )

        self.assertEqual(handler._active_hooks, {})
        cache_key = (MouselessCursorMoveHook, "mouse_pos_addr")
        self.assertEqual(handler._cached_hook_allocations[cache_key], 0x8000)
        replacement = MouselessCursorMoveHook(handler, handler._hook_cache)
        await replacement.set_mouse_pos_addr()
        self.assertEqual(replacement.mouse_pos_addr, 0x8000)
        backend.allocate.assert_called_once_with(8)

        with self.assertRaisesRegex(RuntimeError, "cached free failed"):
            await handler.close()
        self.assertEqual(handler._cached_hook_allocations[cache_key], 0x8000)
        self.assertEqual(
            handler._hook_cache[MouselessCursorMoveHook]["mouse_pos_addr"],
            0x8000,
        )

        await handler.close()
        self.assertEqual(handler._cached_hook_allocations, {})
        self.assertNotIn(
            "mouse_pos_addr", handler._hook_cache[MouselessCursorMoveHook]
        )
        self.assertEqual(backend.free.call_count, 2)

    async def test_chat_exports_are_integer_addresses_for_direct_consumers(self):
        await self.handler.activate_chat_hook(wait_for_ready=False)
        for name in (
            "chat_owner",
            "recv_source_gid",
            "recv_message_buf",
            "recv_message_len",
            "recv_counter",
        ):
            self.assertIsInstance(self.handler._base_addrs[name], int)

        chat = CurrentChatOwner(self.handler)
        self.backend.set_memory("recv_source_gid", struct.pack("<Q", 12345))
        self.backend.set_memory("recv_message_buf", "hello".encode("utf-16-le"))
        self.backend.set_memory("recv_message_len", struct.pack("<Q", 5))
        self.backend.set_memory("recv_counter", struct.pack("<Q", 1))
        self.assertEqual(await chat.recv_message(), (12345, "hello", 1))

        async def publish_message():
            await asyncio.sleep(0.01)
            self.backend.set_memory("recv_message_buf", "world".encode("utf-16-le"))
            self.backend.set_memory("recv_message_len", struct.pack("<Q", 5))
            self.backend.set_memory("recv_counter", struct.pack("<Q", 2))

        publisher = asyncio.create_task(publish_message())
        self.assertEqual(await chat.wait_for_message(timeout=0.2), (12345, "world", 2))
        await publisher

    async def test_combined_activation_rolls_back_core_when_movement_fails(self):
        self.backend.fail_feature_activation = "movement_teleport"
        with self.assertRaisesRegex(RuntimeError, "forced movement_teleport"):
            await self.handler.activate_all_hooks(wait_for_ready=False)
        self.assertFalse(self.backend.core_active)
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertEqual(self.handler._agent_feature_exports, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)
        self.assertIn(("deactivate_core_hooks",), self.backend.calls)

    async def test_close_cleans_mixed_core_and_feature_state(self):
        await self.handler.activate_all_hooks(wait_for_ready=False)
        await self.handler.activate_chat_hook(wait_for_ready=False)
        self.assertTrue(self.backend.core_active)
        self.assertEqual(self.backend.active, {"movement_teleport", "chat"})
        await self.handler.close()
        self.assertFalse(self.backend.core_active)
        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_close_deactivates_feature_hooks_and_cancels_heartbeat(self):
        await self.handler.activate_movement_teleport_hook()
        await self.handler.activate_chat_send_hook()
        await self.handler.close()
        self.assertEqual(self.backend.active, set())
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_failed_close_keeps_retry_ownership_and_heartbeat(self):
        await self.handler.activate_chat_send_hook()
        self.backend.fail_feature_deactivation = "chat_send"
        with self.assertRaisesRegex(RuntimeError, "forced chat_send"):
            await self.handler.close()
        self.assertEqual(self.backend.active, {"chat_send"})
        self.assertTrue(self.handler._active_hooks)
        self.assertIsNotNone(self.handler._core_hook_heartbeat_task)

        self.backend.fail_feature_deactivation = None
        await self.handler.close()
        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.handler._active_hooks, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_export_initialization_failure_rolls_back_remote_feature(self):
        self.backend.fail_feature_export = "send_struct"

        with self.assertRaisesRegex(RuntimeError, "forced send_struct export failure"):
            await self.handler.activate_chat_send_hook()

        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertEqual(self.handler._agent_feature_exports, {})
        self.assertEqual(self.handler._agent_feature_hook_exports, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_failed_export_rollback_retains_remote_feature_for_close_retry(self):
        self.backend.fail_feature_export = "send_struct"
        self.backend.fail_feature_deactivation = "chat_send"

        with self.assertRaisesRegex(
            RuntimeError, "forced send_struct export failure"
        ) as caught:
            await self.handler.activate_chat_send_hook()

        self.assertEqual(
            [str(error) for error in caught.exception.cleanup_errors],
            ["forced chat_send deactivation failure"],
        )
        self.assertTrue(
            any(
                "forced chat_send deactivation failure" in note
                for note in caught.exception.__notes__
            )
        )

        self.assertEqual(self.backend.active, {"chat_send"})
        self.assertEqual(
            self.handler._active_hooks.get(ChatSendHook), "chat_send"
        )
        self.assertEqual(
            self.handler._agent_feature_hook_exports.get("chat_send"),
            {"send_trigger", "send_struct", "buddy_trigger", "buddy_obj"},
        )
        self.assertIsNotNone(self.handler._core_hook_heartbeat_task)

        self.backend.fail_feature_deactivation = None
        await self.handler.close()
        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.handler._active_hooks, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_terminal_feature_rollback_is_diagnostic_and_releases_owner(self):
        self.backend.fail_feature_export = "send_struct"
        cleanup_error = RuntimeError("client process exited during feature rollback")
        self.backend.deactivate_feature_hook = MagicMock(side_effect=cleanup_error)
        self.backend.is_closed_process_error = MagicMock(return_value=True)

        with self.assertRaisesRegex(
            RuntimeError, "forced send_struct export failure"
        ) as caught:
            await self.handler.activate_chat_send_hook()

        self.assertEqual(caught.exception.cleanup_errors, (cleanup_error,))
        self.assertNotIn(ChatSendHook, self.handler._active_hooks)
        self.assertNotIn("chat_send", self.handler._agent_feature_hook_exports)
        self.assertEqual(self.handler._base_addrs, {})
        self.assertEqual(self.handler._agent_feature_exports, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)

    async def test_direct_feature_readiness_failure_is_transactional(self):
        self.handler._wait_for_value = AsyncMock(
            side_effect=TimeoutError("feature never became ready")
        )

        with self.assertRaisesRegex(TimeoutError, "feature never became ready"):
            await self.handler.activate_chat_hook(wait_for_ready=True)

        self.assertEqual(self.backend.active, set())
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})

    async def test_mixed_close_releases_successes_and_retries_only_failure(self):
        await self.handler.activate_all_hooks(wait_for_ready=False)
        await self.handler.activate_chat_hook(wait_for_ready=False)
        self.backend.fail_feature_deactivation = "chat"

        with self.assertRaisesRegex(RuntimeError, "forced chat"):
            await self.handler.close()

        self.assertFalse(self.backend.core_active)
        self.assertEqual(self.backend.active, {"chat"})
        self.assertEqual(set(self.handler._active_hooks.values()), {"chat"})
        self.assertEqual(
            set(self.handler._base_addrs),
            {
                "chat_owner",
                "recv_source_gid",
                "recv_message_buf",
                "recv_message_len",
                "recv_counter",
            },
        )

        calls_before_retry = list(self.backend.calls)
        self.backend.fail_feature_deactivation = None
        await self.handler.close()
        retry_calls = self.backend.calls[len(calls_before_retry):]
        self.assertEqual(retry_calls, [("deactivate", "chat")])
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})

    async def test_direct_feature_activation_after_client_detach_is_rejected(self):
        self.handler.client = SimpleNamespace(_detach_started=True)

        with self.assertRaisesRegex(RuntimeError, "detach has started"):
            await self.handler.activate_chat_send_hook()
        with self.assertRaisesRegex(RuntimeError, "detach has started"):
            await dance_game_hook.serialized_activate_dance_game_moves_hook(
                self.handler
            )

        self.assertEqual(self.backend.active, set())

    async def test_close_wins_race_against_queued_direct_feature_activation(self):
        await self.handler.activate_chat_hook(wait_for_ready=False)
        deactivation_started = threading.Event()
        allow_deactivation = threading.Event()
        original_deactivate = self.backend.deactivate_feature_hook

        def blocking_deactivate(hook):
            deactivation_started.set()
            if not allow_deactivation.wait(2):
                raise TimeoutError("test did not release feature deactivation")
            return original_deactivate(hook)

        self.backend.deactivate_feature_hook = blocking_deactivate
        closing = asyncio.create_task(self.handler.close())
        self.assertTrue(
            await asyncio.to_thread(deactivation_started.wait, 1),
            "close did not reach feature deactivation",
        )
        activating = asyncio.create_task(self.handler.activate_chat_send_hook())
        allow_deactivation.set()
        await closing
        with self.assertRaisesRegex(RuntimeError, "detach has started"):
            await activating
        self.assertEqual(self.backend.active, set())

    async def test_terminal_session_error_completes_hook_cleanup(self):
        await self.handler.activate_chat_send_hook()
        terminal = RuntimeError("session disappeared")
        terminal.code = "session_not_found"

        def terminal_deactivate(hook):
            raise terminal

        self.backend.deactivate_feature_hook = terminal_deactivate
        self.backend.is_closed_process_error = lambda error: (
            getattr(error, "code", None) == "session_not_found"
        )

        await self.handler.close()
        self.assertEqual(self.handler._active_hooks, {})
        self.assertEqual(self.handler._base_addrs, {})
        self.assertIsNone(self.handler._core_hook_heartbeat_task)


if __name__ == "__main__":
    unittest.main()
