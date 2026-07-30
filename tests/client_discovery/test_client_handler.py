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
from wizwalker.errors import UnsupportedClientOperation  # noqa: E402


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

    def list_clients(self):
        return {"clients": next(self.snapshots)}


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

    def test_native_client_reports_unsupported_legacy_operations_clearly(self):
        client = DiscoveredClient(
            FakeAgentManager([]),
            descriptor("client-a", 448),
        )
        with self.assertRaisesRegex(
            UnsupportedClientOperation,
            "does not support mouseless input yet",
        ):
            _ = client.mouse_handler

        # Discovery-only clients own no hooks or process sessions, so cleanup
        # remains compatible with ClientHandler context-manager usage.
        asyncio.run(client.close())


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
