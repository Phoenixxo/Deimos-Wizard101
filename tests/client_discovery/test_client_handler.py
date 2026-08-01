from __future__ import annotations

import asyncio
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"

if str(WIZWALKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WIZWALKER_ROOT))

from wizwalker import ClientHandler, DiscoveredClient  # noqa: E402
from wizwalker.discovered_client import NativeMouseHandler  # noqa: E402


def descriptor(
    client_id: str,
    pid: int,
    *,
    foreground: bool = False,
    screen_order: int = 0,
) -> dict:
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
        "is_foreground": foreground,
        "screen_order": screen_order,
    }


class FakeAgentManager:
    def __init__(self, snapshots: list[list[dict]]):
        self.snapshots = iter(snapshots)
        self.calls = []
        self.foreground_clients = {"client-b"}

    def list_clients(self):
        return {"clients": next(self.snapshots)}

    def client_window_state(self, client_id):
        self.calls.append(("state", client_id))
        return {
            "client_id": client_id,
            "title": "Wizard101",
            "is_foreground": client_id in self.foreground_clients,
            "rectangle": {"left": 10, "top": 20, "right": 810, "bottom": 620},
            "client_origin": {"x": 12, "y": 42},
            "client_size": {"width": 796, "height": 576},
        }

    def focus_client_window(self, client_id):
        self.calls.append(("focus", client_id))
        self.foreground_clients = {client_id}
        return {"client_id": client_id, "is_foreground": True}

    def set_client_window_title(self, client_id, title):
        self.calls.append(("title", client_id, title))
        return {"client_id": client_id, "title": title}

    def send_key(self, client_id, virtual_key, seconds=0):
        self.calls.append(("key", client_id, virtual_key, seconds))
        return {"client_id": client_id, "delivered": True}

    def send_hotkey(self, client_id, modifiers, virtual_key):
        self.calls.append(("hotkey", client_id, modifiers, virtual_key))
        return {"client_id": client_id, "delivered": True}


class FakeLegacyClient:
    def __init__(self, handle):
        self.window_handle = handle
        self.is_foreground = handle == 22
        self.running = True

    def is_running(self):
        return self.running


class ClientHandlerCompatibilityTests(unittest.TestCase):
    def test_legacy_callers_still_construct_clients_from_native_handles(self):
        legacy_utils = SimpleNamespace(
            get_all_wizard_handles=lambda: [11, 22],
            order_clients=lambda clients: list(reversed(clients)),
        )
        handler = ClientHandler(client_cls=FakeLegacyClient)

        with patch.object(ClientHandler, "_legacy_utils", return_value=legacy_utils):
            new_clients = handler.get_new_clients()
            self.assertEqual([client.window_handle for client in new_clients], [11, 22])
            self.assertEqual(handler._managed_handles, [11, 22])
            self.assertEqual(
                [client.window_handle for client in handler.get_ordered_clients()],
                [22, 11],
            )
            self.assertEqual(handler.get_foreground_client().window_handle, 22)
            self.assertEqual(handler.get_new_clients(), [])

    def test_native_discovery_tracks_multiple_clients_and_closure(self):
        both_clients = [
            descriptor("client-a", 448, screen_order=1),
            descriptor("client-b", 544, foreground=True, screen_order=0),
        ]
        manager = FakeAgentManager(
            [
                both_clients,
                both_clients,
                both_clients,
                [descriptor("client-b", 544, foreground=True, screen_order=0)],
                [descriptor("client-c", 448, screen_order=0)],
            ]
        )
        handler = ClientHandler(agent_manager=manager)

        new_clients = handler.get_new_clients()
        self.assertEqual(
            [client.client_id for client in new_clients],
            ["client-a", "client-b"],
        )
        self.assertEqual(
            [client.client_id for client in handler.get_ordered_clients()],
            ["client-b", "client-a"],
        )
        self.assertEqual(handler.get_foreground_client().client_id, "client-b")

        dead_clients = handler.remove_dead_clients()
        self.assertEqual([client.client_id for client in dead_clients], ["client-a"])
        self.assertFalse(dead_clients[0].is_running())

        rediscovered = handler.get_new_clients()
        self.assertEqual([client.client_id for client in rediscovered], ["client-c"])
        self.assertEqual(rediscovered[0].process_id, 448)
        self.assertFalse(hasattr(rediscovered[0], "window_handle"))

    def test_native_discovery_rejects_malformed_agent_responses(self):
        handler = ClientHandler(agent_manager=SimpleNamespace(list_clients=lambda: {}))
        with self.assertRaisesRegex(ValueError, "invalid client discovery response"):
            handler.get_new_clients()

    def test_native_discovery_rejects_malformed_or_duplicate_descriptors(self):
        malformed = ClientHandler(
            agent_manager=SimpleNamespace(list_clients=lambda: {"clients": [{}]})
        )
        with self.assertRaisesRegex(ValueError, "invalid client discovery descriptor"):
            malformed.get_new_clients()

        duplicated = ClientHandler(
            agent_manager=SimpleNamespace(
                list_clients=lambda: {
                    "clients": [descriptor("client-a", 448), descriptor("client-a", 544)]
                }
            )
        )
        with self.assertRaisesRegex(ValueError, "invalid client discovery descriptor"):
            duplicated.get_new_clients()

    def test_native_client_uses_agent_owned_window_and_keyboard_operations(self):
        manager = FakeAgentManager([])
        client = DiscoveredClient(manager, descriptor("client-a", 448))

        self.assertEqual(client.title, "Wizard101")
        self.assertEqual(tuple(client.window_rectangle), (810, 10, 20, 620))
        self.assertEqual(
            client.overlay_geometry,
            {
                "left": 12,
                "top": 42,
                "width": 796,
                "height": 576,
                "is_foreground": False,
            },
        )
        self.assertFalse(client.is_foreground)
        client.title = "Balance"
        client.is_foreground = True
        self.assertTrue(client.is_foreground)
        manager.foreground_clients.clear()
        self.assertFalse(client.is_foreground)
        asyncio.run(client.send_key(SimpleNamespace(value=0x57), 0.1))
        asyncio.run(
            client.send_hotkey(
                [SimpleNamespace(value=0x11)],
                SimpleNamespace(value=0x43),
            )
        )

        self.assertIn(("title", "client-a", "Balance"), manager.calls)
        self.assertIn(("focus", "client-a"), manager.calls)
        self.assertIn(("key", "client-a", 0x57, 0.1), manager.calls)
        self.assertIn(("hotkey", "client-a", [0x11], 0x43), manager.calls)
        self.assertFalse(hasattr(client, "window_handle"))
        self.assertIs(client.mouse_handler, client.mouse_handler)

        # Discovery-only clients own no hooks or process sessions, so cleanup
        # remains compatible with ClientHandler context-manager usage.
        asyncio.run(client.close())

    def test_failed_mouseless_activation_closes_a_new_hook_session(self):
        class FailingHookHandler:
            def __init__(self):
                self._active_hooks = {}

            async def activate_mouseless_cursor_hook(self):
                raise RuntimeError("activation failed")

        class HookClient:
            def __init__(self):
                self.hook_handler = FailingHookHandler()
                self.closed_sessions = []

            async def _ensure_hook_handler(self):
                return self.hook_handler, True

            def _detach_hook_session(self):
                self.hook_handler = None
                return "hook-session"

            async def _close_session(self, session_id):
                self.closed_sessions.append(session_id)

        client = HookClient()
        mouse = NativeMouseHandler(client)
        with self.assertRaisesRegex(RuntimeError, "activation failed"):
            asyncio.run(mouse._activate_mouseless())

        self.assertEqual(client.closed_sessions, ["hook-session"])
        self.assertIsNone(client.hook_handler)


@unittest.skipIf(sys.platform == "win32", "macOS/Linux import isolation only")
class NonWindowsImportTests(unittest.TestCase):
    def test_client_discovery_imports_without_windows_dependencies(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(WIZWALKER_ROOT)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "from wizwalker import ClientHandler, DiscoveredClient; "
                    "assert 'pymem' not in sys.modules; "
                    "assert 'wizwalker.utils' not in sys.modules; "
                    "print(ClientHandler.__name__, DiscoveredClient.__name__)"
                ),
            ],
            env=environment,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "ClientHandler DiscoveredClient")


if __name__ == "__main__":
    unittest.main()
