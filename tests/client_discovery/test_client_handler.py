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
from wizwalker.generation import manager_generation_context  # noqa: E402


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


def bound_client(manager, client_descriptor):
    instance_id = getattr(manager, "cleanup_instance_id", "test-helper")
    context = manager_generation_context(manager, instance_id)
    return DiscoveredClient(
        manager,
        client_descriptor,
        generation_context=context,
    )


class FakeAgentManager:
    cleanup_instance_id = "test-helper"

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

    def process_status(self, session_id):
        self.calls.append(("process_status", session_id))
        return {"session_id": session_id, "state": "open"}

    def close_process(self, session_id):
        self.calls.append(("close_process", session_id))

    def close_process_for_instance(self, session_id, instance_id):
        if instance_id != self.cleanup_instance_id:
            raise NativeWindowError("identity_mismatch")
        self.close_process(session_id)


class FakeLegacyClient:
    def __init__(self, handle):
        self.window_handle = handle
        self.is_foreground = handle == 22
        self.running = True

    def is_running(self):
        return self.running


class NativeWindowError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


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

    def test_native_discovery_rebinds_replaced_window_without_invalidating_hooks(self):
        manager = FakeAgentManager(
            [
                [descriptor("client-old-window", 448, foreground=True)],
                [descriptor("client-new-window", 448, foreground=True)],
            ]
        )
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        hook_marker = object()
        client._hook_session_id = "hook-448"
        client.body = hook_marker

        self.assertEqual(handler.get_new_clients(), [])
        self.assertIs(handler.clients[0], client)
        self.assertEqual(client.client_id, "client-new-window")
        self.assertEqual(handler.managed_identities, ("client-new-window",))
        self.assertIs(client.body, hook_marker)
        self.assertTrue(client.is_running())

    def test_native_discovery_keeps_live_hook_session_during_window_gap(self):
        manager = FakeAgentManager(
            [
                [descriptor("client-stable", 448, foreground=True)],
                [],
                [descriptor("client-stable", 448, foreground=True)],
            ]
        )
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        hook_marker = object()
        client._hook_session_id = "hook-448"
        client.body = hook_marker

        self.assertEqual(handler.remove_dead_clients(), [])
        self.assertTrue(client.is_running())
        self.assertIs(client.body, hook_marker)
        self.assertEqual(handler.get_new_clients(), [])
        self.assertIs(handler.clients[0], client)

    def test_foreground_state_survives_a_live_window_gap_and_recovers(self):
        manager = FakeAgentManager([])
        client = bound_client(
            manager,
            descriptor("client-stable", 448, foreground=True),
        )
        client._hook_session_id = "hook-448"
        original_window_state = manager.client_window_state
        manager.client_window_state = lambda client_id: (_ for _ in ()).throw(
            NativeWindowError("client_not_found")
        )

        self.assertTrue(client.is_foreground)

        manager.client_window_state = original_window_state
        manager.foreground_clients.clear()
        self.assertFalse(client.is_foreground)

    def test_foreground_window_gap_fails_when_process_has_exited(self):
        manager = FakeAgentManager([])
        client = bound_client(
            manager,
            descriptor("client-stable", 448, foreground=True),
        )
        client._hook_session_id = "hook-448"
        manager.client_window_state = lambda client_id: (_ for _ in ()).throw(
            NativeWindowError("client_not_found")
        )
        manager.process_status = lambda session_id: (_ for _ in ()).throw(
            NativeWindowError("process_exited")
        )

        with self.assertRaisesRegex(NativeWindowError, "client_not_found"):
            _ = client.is_foreground

    def test_native_discovery_rejects_malformed_agent_responses(self):
        handler = ClientHandler(agent_manager=SimpleNamespace(list_clients=lambda: {}))
        with self.assertRaisesRegex(ValueError, "invalid client discovery response"):
            handler.get_new_clients()

    def test_specific_native_client_can_be_managed_by_opaque_identity(self):
        manager = FakeAgentManager(
            [[descriptor("client-a", 448), descriptor("client-b", 544)]]
        )
        handler = ClientHandler(agent_manager=manager)

        client = handler.manage_client("client-b")

        self.assertEqual(client.client_id, "client-b")
        self.assertEqual(handler.client_identity(client), "client-b")
        self.assertEqual(handler.managed_identities, ("client-b",))
        handler.release_client(client)
        self.assertEqual(handler.managed_identities, ())
        self.assertEqual(handler.clients, [])

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

    def test_invalid_reconnect_descriptor_does_not_mutate_the_current_generation(self):
        original = descriptor("client-a", 448)
        malformed = descriptor("client-a", 448)
        malformed["process"]["identity"]["creation_time_100ns"] = ""
        manager = FakeAgentManager([[original], [malformed]])
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        hook_marker = object()
        client.hook_handler = hook_marker
        client.body = hook_marker

        with self.assertRaisesRegex(ValueError, "matching process identity"):
            handler.get_new_clients()

        self.assertEqual(handler.clients, [client])
        self.assertEqual(handler.managed_identities, ("client-a",))
        self.assertTrue(client.is_running())
        self.assertIs(client.hook_handler, hook_marker)
        self.assertIs(client.body, hook_marker)

    def test_native_client_uses_agent_owned_window_and_keyboard_operations(self):
        manager = FakeAgentManager([])
        client = bound_client(manager, descriptor("client-a", 448))

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
                self._hook_lifecycle_lock = asyncio.Lock()

            async def _ensure_hook_handler(self):
                return self.hook_handler, True

            def _detach_hook_session(self):
                self.hook_handler = None
                return "hook-session"

            async def _close_session(self, session_id):
                self.closed_sessions.append(session_id)

            async def _close_hook_session_locked(self):
                session_id = self._detach_hook_session()
                if session_id is not None:
                    await self._close_session(session_id)

        client = HookClient()
        mouse = NativeMouseHandler(client)
        with self.assertRaisesRegex(RuntimeError, "activation failed"):
            asyncio.run(mouse._activate_mouseless())

        self.assertEqual(client.closed_sessions, ["hook-session"])
        self.assertIsNone(client.hook_handler)


class NativeReconnectTransactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_mark_closed_schedules_one_cleanup_transaction(self):
        manager = FakeAgentManager([])
        client = bound_client(manager, descriptor("client-a", 448))
        cleanup_started = asyncio.Event()
        allow_cleanup = asyncio.Event()

        class HookHandler:
            def __init__(self):
                self.close_calls = 0

            async def close(self):
                self.close_calls += 1
                cleanup_started.set()
                await allow_cleanup.wait()

            def cancel_core_hook_heartbeat(self):
                return None

        hook_handler = HookHandler()
        client.hook_handler = hook_handler
        client._hook_session_id = "hooks-old"

        client._mark_closed()
        client._mark_closed()
        await cleanup_started.wait()
        self.assertEqual(len(client._lifecycle_cleanup_tasks), 1)
        self.assertEqual(hook_handler.close_calls, 1)

        allow_cleanup.set()
        await client.close()
        self.assertEqual(hook_handler.close_calls, 1)
        self.assertEqual(manager.calls.count(("close_process", "hooks-old")), 1)

    async def test_in_progress_detach_cannot_be_resurrected_by_discovery(self):
        current = descriptor("client-a", 448)
        manager = FakeAgentManager([[current], [current], [current]])
        handler = ClientHandler(agent_manager=manager)
        detaching = handler.get_new_clients()[0]

        detaching.begin_detach()
        self.assertEqual(handler.get_new_clients(), [])
        self.assertFalse(detaching.is_running())
        self.assertTrue(detaching._detach_started)

        await detaching.close()
        handler.release_client(detaching)
        replacement = handler.get_new_clients()[0]
        self.assertIsNot(replacement, detaching)
        self.assertTrue(replacement.is_running())

    async def test_hidden_failed_detach_remains_in_cleanup_ownership(self):
        current = descriptor("client-a", 448)
        manager = FakeAgentManager([[current], [current]])
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]

        client.begin_detach()
        self.assertEqual(handler.remove_dead_clients(), [client])
        self.assertNotIn(client, handler.clients)
        self.assertIn(client, handler._retired_clients)
        self.assertIn(client, handler.cleanup_clients)

        await client.close()
        handler.release_client(client)
        self.assertNotIn(client, handler.cleanup_clients)

    async def test_retirement_hides_stale_sessions_and_owns_cleanup(self):
        current = descriptor("client-a", 448)
        manager = FakeAgentManager([[current], [current]])
        handler = ClientHandler(agent_manager=manager)
        previous = handler.get_new_clients()[0]

        class HookHandler:
            def __init__(self):
                self.cancelled = False
                self.closed = False

            async def close(self):
                self.closed = True

            def cancel_core_hook_heartbeat(self):
                self.cancelled = True

        hook_handler = HookHandler()
        previous._session_id = "telemetry-old"
        previous._telemetry_reader = object()
        previous._hook_session_id = "hooks-old"
        previous.hook_handler = hook_handler
        previous.body = object()
        previous._world_view_window = object()
        previous._character_registry_addr = 0x1234
        previous._quest_client_manager_addr = 0x5678
        previous._je_instruction_forward_backwards = 0x9ABC

        retired = handler.retire_native_clients()

        self.assertEqual(retired, (previous,))
        self.assertEqual(handler.clients, [])
        self.assertEqual(handler.managed_identities, ())
        self.assertFalse(previous.is_running())
        self.assertIsNone(previous._session_id)
        self.assertIsNone(previous._telemetry_reader)
        # Hook ownership remains attached until the asynchronous unhook is
        # confirmed; the retired object is hidden from discovery immediately.
        self.assertEqual(previous._hook_session_id, "hooks-old")
        self.assertIs(previous.hook_handler, hook_handler)
        self.assertIn(previous, handler._retired_clients)

        # The same live process is quarantined while its prior hooks remain
        # owned; publishing a second object here could activate duplicates.
        self.assertEqual(handler.get_new_clients(), [])
        await previous.close()
        await handler.retry_retired_cleanup(force=True)
        manager.snapshots = iter([[current]])
        replacement = handler.get_new_clients()[0]
        self.assertIsNot(replacement, previous)
        self.assertEqual(replacement.client_id, previous.client_id)
        self.assertIsNone(previous._hook_session_id)
        self.assertIsNone(previous.hook_handler)
        self.assertFalse(hasattr(previous, "body"))
        self.assertIsNone(previous._world_view_window)
        self.assertIsNone(previous._character_registry_addr)
        self.assertIsNone(previous._quest_client_manager_addr)
        self.assertIsNone(previous._je_instruction_forward_backwards)
        self.assertTrue(hook_handler.closed)
        self.assertTrue(hook_handler.cancelled)
        self.assertIn(("close_process", "telemetry-old"), manager.calls)
        self.assertIn(("close_process", "hooks-old"), manager.calls)

    async def test_cleanup_failure_stays_owned_without_exposing_old_client(self):
        current = descriptor("client-a", 448)
        manager = FakeAgentManager([[current], [current]])

        def fail_close(session_id):
            manager.calls.append(("close_process", session_id))
            raise NativeWindowError("transport_error")

        manager.close_process = fail_close
        handler = ClientHandler(agent_manager=manager)
        previous = handler.get_new_clients()[0]
        previous._session_id = "telemetry-old"

        handler.retire_native_clients()
        replacement = handler.get_new_clients()[0]
        await asyncio.gather(
            *tuple(previous._session_cleanup_tasks),
            return_exceptions=True,
        )
        await asyncio.sleep(0)

        self.assertEqual(handler.clients, [replacement])
        self.assertNotIn(previous, handler.clients)
        self.assertIn(previous, handler._retired_clients)
        self.assertIsNotNone(previous._last_session_cleanup_error)
        with self.assertRaisesRegex(NativeWindowError, "transport_error"):
            await handler.close()
        self.assertIn(previous, handler._retired_clients)

    async def test_retired_reference_cannot_target_a_reused_client_id(self):
        current = descriptor("client-a", 448)
        manager = FakeAgentManager([[current], [current]])
        handler = ClientHandler(agent_manager=manager)
        previous = handler.get_new_clients()[0]
        handler.retire_native_clients()
        replacement = handler.get_new_clients()[0]
        self.assertEqual(replacement.client_id, previous.client_id)
        calls_before = list(manager.calls)

        for operation in (
            lambda: previous.title,
            lambda: setattr(previous, "title", "stale"),
            lambda: setattr(previous, "is_foreground", True),
        ):
            with self.assertRaisesRegex(RuntimeError, "retired native session"):
                operation()
        with self.assertRaisesRegex(RuntimeError, "retired native session"):
            await previous.send_key(SimpleNamespace(value=0x57), 0.1)

        self.assertEqual(manager.calls, calls_before)


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
                    "from wizwalker import ClientHandler, DiscoveredClient, utils; "
                    "assert 'pymem' not in sys.modules; "
                    "assert 'winreg' not in sys.modules; "
                    "assert utils.__name__ == 'wizwalker.utils'; "
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
