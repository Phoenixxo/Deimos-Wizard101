from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import ctypes
import ctypes.wintypes
import sys
import unittest
from unittest.mock import AsyncMock, patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
for path in (REPOSITORY_ROOT, WIZWALKER_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.platform_adapter import HostPlatformAdapter  # noqa: E402
from src import world_to_screen  # noqa: E402
from wizwalker import Keycode  # noqa: E402
from wizwalker import platform_adapter as platform_module  # noqa: E402


class FakeLegacyWindows:
    def __init__(self):
        self.calls = []

    def client_size(self, window_handle):
        self.calls.append(("size", window_handle))
        return 800, 600

    def send_window_message(
        self,
        window_handle,
        message,
        wparam,
        lparam,
        *,
        post=False,
    ):
        self.calls.append((window_handle, message, wparam, lparam, post))


class FakeWindowsHost:
    def __init__(self):
        self.calls = []

    def set_app_user_model_id(self, value):
        self.calls.append(("app_id", value))

    def enable_rounded_corners(self, window_id):
        self.calls.append(("corners", window_id))

    def set_topmost(self, window_id, enabled):
        self.calls.append(("topmost", window_id, enabled))

    def read_registry_dword(self, path, name, default):
        self.calls.append(("read", path, name, default))
        return 7

    def write_registry_dword(self, path, name, value):
        self.calls.append(("write", path, name, value))

    def show_error_message(self, message, title):
        self.calls.append(("message", message, title))


class FakeView:
    async def viewport_left(self): return -1.0
    async def viewport_right(self): return 1.0
    async def viewport_top(self): return 1.0
    async def viewport_bottom(self): return -1.0
    async def screenport_left(self): return 0.0
    async def screenport_right(self): return 1.0
    async def screenport_top(self): return 0.0
    async def screenport_bottom(self): return 1.0


class FakeCamera:
    async def position(self): return SimpleNamespace(x=1.0, y=2.0, z=3.0)
    async def gamebryo_camera(self):
        return SimpleNamespace(cam_view=AsyncMock(return_value=FakeView()))
    async def yaw(self): return 0.0
    async def pitch(self): return 0.0


class PlatformAdapterTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(sys.platform == "win32", "native Win32 signature check")
    def test_windows_pointer_sized_signatures_are_declared(self):
        self.assertIs(
            platform_module.kernel32.OpenProcess.restype,
            ctypes.wintypes.HANDLE,
        )
        self.assertIs(
            platform_module.user32.GetForegroundWindow.restype,
            ctypes.wintypes.HWND,
        )
        self.assertEqual(
            platform_module.user32.EnumWindows.argtypes[1],
            ctypes.wintypes.LPARAM,
        )
        self.assertIs(
            platform_module.user32.GetDC.restype,
            ctypes.wintypes.HDC,
        )
        self.assertIs(
            platform_module.gdi32.CreateSolidBrush.restype,
            getattr(ctypes.wintypes, "HBRUSH", ctypes.wintypes.HANDLE),
        )

    def test_native_client_size_uses_agent_geometry(self):
        client = SimpleNamespace(
            overlay_geometry={"left": 4, "top": 8, "width": 966, "height": 603}
        )
        self.assertEqual(platform_module.client_size(client), (966, 603))

    def test_legacy_client_size_uses_windows_adapter(self):
        windows = FakeLegacyWindows()
        with patch.object(platform_module, "legacy_windows", windows):
            self.assertEqual(
                platform_module.client_size(SimpleNamespace(window_handle=1234)),
                (800, 600),
            )
        self.assertEqual(windows.calls, [("size", 1234)])

    def test_invalid_native_client_size_is_rejected(self):
        client = SimpleNamespace(
            overlay_geometry={"width": 0, "height": 600}
        )
        with self.assertRaisesRegex(ValueError, "invalid"):
            platform_module.client_size(client)

    async def test_native_key_message_uses_client_adapter(self):
        client = SimpleNamespace(client_id="client-1", send_key=AsyncMock())
        await platform_module.send_key_message(client, Keycode.W)
        client.send_key.assert_awaited_once_with(Keycode.W)

    async def test_legacy_key_message_preserves_down_up_sequence(self):
        windows = FakeLegacyWindows()
        with patch.object(platform_module, "legacy_windows", windows):
            await platform_module.send_key_message(
                SimpleNamespace(window_handle=1234),
                Keycode.D,
            )
        self.assertEqual(
            windows.calls,
            [
                (1234, 0x100, Keycode.D.value, 0, False),
                (1234, 0x101, Keycode.D.value, 0, False),
            ],
        )

    async def test_legacy_posted_key_message_remains_non_blocking(self):
        windows = FakeLegacyWindows()
        with patch.object(platform_module, "legacy_windows", windows):
            await platform_module.send_key_message(
                SimpleNamespace(window_handle=1234),
                Keycode.D,
                post=True,
            )
        self.assertEqual(
            windows.calls,
            [
                (1234, 0x100, Keycode.D.value, 0, True),
                (1234, 0x101, Keycode.D.value, 0, True),
            ],
        )

    async def test_world_to_screen_uses_platform_client_size(self):
        client = SimpleNamespace(
            game_client=SimpleNamespace(
                selected_camera_controller=AsyncMock(return_value=FakeCamera())
            )
        )
        with patch.object(
            world_to_screen,
            "client_size",
            return_value=(1440, 900),
        ) as size:
            state = await world_to_screen.get_camera_state(client)

        size.assert_called_once_with(client)
        self.assertEqual((state["client_w"], state["client_h"]), (1440, 900))

    def test_windows_host_operations_are_delegated(self):
        windows = FakeWindowsHost()
        adapter = HostPlatformAdapter(platform="win32", windows_api=windows)
        adapter.set_app_user_model_id("deimos.Deimos")
        adapter.enable_rounded_corners(77)
        self.assertTrue(adapter.set_topmost(77, True))
        self.assertEqual(adapter.read_registry_dword("path", "name"), 7)
        adapter.write_registry_dword("path", "name", 1)
        adapter.show_error_message("message", "title")
        self.assertEqual(
            windows.calls,
            [
                ("app_id", "deimos.Deimos"),
                ("corners", 77),
                ("topmost", 77, True),
                ("read", "path", "name", 0),
                ("write", "path", "name", 1),
                ("message", "message", "title"),
            ],
        )

    def test_macos_host_operations_have_safe_fallbacks(self):
        adapter = HostPlatformAdapter(platform="darwin")
        adapter.set_app_user_model_id("deimos.Deimos")
        adapter.enable_rounded_corners(77)
        self.assertFalse(adapter.set_topmost(77, True))
        self.assertEqual(adapter.read_registry_dword("path", "name", 3), 3)
        adapter.write_registry_dword("path", "name", 1)
        adapter.show_error_message("message", "title")


if __name__ == "__main__":
    unittest.main()
