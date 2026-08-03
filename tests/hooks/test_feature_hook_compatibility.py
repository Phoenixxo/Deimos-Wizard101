import asyncio
import struct
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock


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
        )
    ),
)
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
sys.modules.setdefault("regex", ModuleType("regex"))
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
        return {"hooks": sorted(self.active)}

    def heartbeat_core_hooks(self):
        return {"hooks": []}

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
        hook.pattern_scan.assert_awaited_once_with(
            rb"\x74\x24\xF3\x0F\x10\x44\x24\x58\xF3\x0F"
            rb"\x11\x44\x24\x78\x48\x8B\x06",
            module="WizardGraphicalClient.exe",
        )
        hook.write_bytes.assert_awaited_once_with(0x4000, b"\x90\x90")
        self.assertEqual(hook._collision_je_addrs, (0x4000,))
        self.assertEqual(hook._old_collision_jes_bytes, (b"\x74\x24",))

        bytecode = await hook.bytecode_generator((("teleport_helper", struct.pack("<Q", 0x1000)),))
        self.assertTrue(bytecode.endswith(b"\x48\x89\x5C\x24\x08\x57"))
        self.assertTrue(
            MovementTeleportHook.pattern.startswith(
                rb"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20"
            )
        )

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


if __name__ == "__main__":
    unittest.main()
