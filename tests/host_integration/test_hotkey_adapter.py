import asyncio
from collections import deque
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
if str(WIZWALKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WIZWALKER_ROOT))

from wizwalker import (  # noqa: E402
    Hotkey,
    HotkeyAlreadyRegistered,
    HotkeyListener,
    HotkeyRegistrationError,
    Keycode,
    Listener,
    ModifierKeys,
)
from wizwalker import hotkey as hotkey_module  # noqa: E402


class NativeError(Exception):
    def __init__(self, message, *, code, details=None, technical_message=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}
        self.technical_message = technical_message


class FakeNativeHotkeys:
    def __init__(self):
        self.next_id = 1
        self.registrations = {}
        self.events = deque()
        self.register_error = None
        self.poll_error = None
        self.calls = []

    def register(self, keycode, modifiers):
        self.calls.append(("register", keycode, modifiers))
        if self.register_error is not None:
            raise self.register_error
        chord = (keycode, modifiers & ~int(ModifierKeys.NOREPEAT))
        if any(
            (registered_key, registered_modifiers & ~int(ModifierKeys.NOREPEAT))
            == chord
            for registered_key, registered_modifiers in self.registrations.values()
        ):
            raise NativeError(
                "That shortcut is already in use.",
                code="hotkey_conflict",
                details={"virtual_key": keycode, "modifiers": modifiers},
            )
        registration_id = self.next_id
        self.next_id += 1
        self.registrations[registration_id] = (keycode, modifiers)
        return registration_id

    def unregister(self, registration_id):
        self.calls.append(("unregister", registration_id))
        if registration_id not in self.registrations:
            raise NativeError(
                "Registration does not exist.",
                code="hotkey_not_registered",
            )
        del self.registrations[registration_id]

    def poll_events(self):
        if self.poll_error is not None:
            raise self.poll_error
        events = list(self.events)
        self.events.clear()
        return events


class HotkeyAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = FakeNativeHotkeys()
        self.message_loop = hotkey_module._GlobalHotkeyMessageLoop(self.backend)
        self.message_loop.set_message_loop_delay(0.005)
        self.patch = patch.object(
            hotkey_module,
            "_hotkey_message_loop",
            self.message_loop,
        )
        self.patch.start()

    async def asyncTearDown(self):
        self.patch.stop()
        if self.message_loop._message_loop_task is not None:
            self.message_loop._message_loop_task.cancel()
            await asyncio.gather(
                self.message_loop._message_loop_task,
                return_exceptions=True,
            )

    async def test_async_callback_runs_for_a_native_registration_event(self):
        callback_ran = asyncio.Event()

        async def callback():
            callback_ran.set()

        listener = HotkeyListener(sleep_time=0.005)
        listener.start()
        await listener.add_hotkey(
            Keycode.F4,
            callback,
            modifiers=ModifierKeys.SHIFT | ModifierKeys.NOREPEAT,
        )
        registration_id = next(iter(self.backend.registrations))
        self.backend.events.append(registration_id)
        await asyncio.wait_for(callback_ran.wait(), timeout=0.25)

        await listener.stop()
        self.assertFalse(self.backend.registrations)
        self.assertFalse(listener.is_running)

    async def test_conflict_is_structured_and_human_readable(self):
        first = HotkeyListener()
        second = HotkeyListener()
        await first.add_hotkey(Keycode.F5, _noop)

        with self.assertRaises(HotkeyAlreadyRegistered) as raised:
            await second.add_hotkey(
                Keycode.F5,
                _noop,
                modifiers=ModifierKeys.NOREPEAT,
            )

        self.assertEqual(raised.exception.code, "hotkey_conflict")
        self.assertEqual(raised.exception.keycode, Keycode.F5.value)
        self.assertIn("already in use", str(raised.exception))
        await first.clear()

    def test_legacy_conflict_exception_constructor_remains_compatible(self):
        error = HotkeyAlreadyRegistered("Keycode.F5 with modifiers 0")

        self.assertEqual(str(error), "Keycode.F5 with modifiers 0 already registered")
        self.assertIsNone(error.keycode)
        self.assertEqual(error.code, "hotkey_conflict")

    async def test_remove_and_clear_unregister_only_owned_shortcuts(self):
        listener = HotkeyListener()
        await listener.add_hotkey(Keycode.F6, _noop)
        await listener.add_hotkey(Keycode.F7, _noop, modifiers=ModifierKeys.CTRL)

        await listener.remove_hotkey(Keycode.F6)
        self.assertEqual(len(self.backend.registrations), 1)
        await listener.clear()
        self.assertFalse(self.backend.registrations)
        self.assertEqual(
            [call[0] for call in self.backend.calls],
            ["register", "register", "unregister", "unregister"],
        )

    async def test_permission_guidance_is_only_used_for_permission_failure(self):
        self.backend.register_error = NativeError(
            "macOS is blocking global hotkeys. Allow Deimos under System Settings > "
            "Privacy & Security > Input Monitoring, then restart Deimos.",
            code="hotkey_permission_required",
            technical_message="CGEventTapCreate returned null",
        )
        listener = HotkeyListener()
        with self.assertRaises(HotkeyRegistrationError) as raised:
            await listener.add_hotkey(Keycode.F8, _noop)
        self.assertEqual(raised.exception.code, "hotkey_permission_required")
        self.assertIn("Input Monitoring", str(raised.exception))

        self.backend.register_error = NativeError(
            "That key cannot be used on this platform.",
            code="hotkey_unsupported_key",
        )
        with self.assertRaises(HotkeyRegistrationError) as raised:
            await listener.add_hotkey(Keycode.F8, _noop)
        self.assertNotIn("Input Monitoring", str(raised.exception))

    async def test_unregister_failure_preserves_native_operation_context(self):
        listener = HotkeyListener()
        await listener.add_hotkey(Keycode.F9, _noop)
        registration_id = next(iter(self.backend.registrations))

        def fail_unregister(candidate):
            self.assertEqual(candidate, registration_id)
            raise NativeError(
                "The native unregister operation failed.",
                code="hotkey_native_failure",
                technical_message="UnregisterHotKey failed",
            )

        self.backend.unregister = fail_unregister
        with self.assertRaises(HotkeyRegistrationError) as raised:
            await listener.remove_hotkey(Keycode.F9)

        self.assertEqual(raised.exception.operation, "hotkey.unregister")
        self.assertEqual(raised.exception.technical_message, "UnregisterHotKey failed")

    async def test_poll_failure_stops_listener_and_is_reported_on_shutdown(self):
        listener = HotkeyListener(sleep_time=0.005)
        listener.start()
        await listener.add_hotkey(Keycode.F10, _noop)
        self.backend.poll_error = NativeError(
            "The native hotkey event stream failed.",
            code="hotkey_native_failure",
            technical_message="native poll failed",
        )

        for _ in range(20):
            if not listener.is_running:
                break
            await asyncio.sleep(0.005)

        self.assertFalse(listener.is_running)
        with self.assertRaises(HotkeyRegistrationError) as raised:
            await listener.stop()
        self.assertEqual(raised.exception.operation, "hotkey.poll")
        self.assertEqual(raised.exception.technical_message, "native poll failed")

    async def test_legacy_listener_close_unblocks_listen_forever(self):
        listener = Listener(Hotkey(Keycode.F10, _noop))
        task = listener.listen_forever()
        for _ in range(20):
            if listener.ready:
                break
            await asyncio.sleep(0.005)
        self.assertTrue(listener.ready)

        await listener.close()
        await asyncio.wait_for(task, timeout=0.25)

        self.assertFalse(self.backend.registrations)
        self.assertFalse(listener.ready)


async def _noop():
    return None


if __name__ == "__main__":
    unittest.main()
