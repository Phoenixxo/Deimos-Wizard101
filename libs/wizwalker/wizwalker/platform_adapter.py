from __future__ import annotations

import ctypes
import ctypes.wintypes
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from typing import Callable

from .constants import WM_KEYDOWN, WM_KEYUP, gdi32, kernel32, user32
from .errors import UnsupportedClientOperation


class _PaintStruct(ctypes.Structure):
    _fields_ = [
        ("hdc", ctypes.wintypes.HDC),
        ("erase", ctypes.wintypes.BOOL),
        ("paint_rectangle", ctypes.wintypes.RECT),
        ("restore", ctypes.wintypes.BOOL),
        ("incremental_update", ctypes.wintypes.BOOL),
        ("reserved", ctypes.c_char * 32),
    ]


class LegacyWindowsPlatformAdapter:
    """Windows APIs used by the legacy in-process WizWalker backend."""

    def __init__(self, *, platform: str = sys.platform):
        self.platform = platform
        self._psapi = None
        self._enum_windows_callback_type = None
        if self.platform == "win32" and user32 is not None and kernel32 is not None:
            self._configure_windows_signatures()

    def _configure_windows_signatures(self) -> None:
        handle = ctypes.wintypes.HANDLE
        hwnd = ctypes.wintypes.HWND
        bool_type = ctypes.wintypes.BOOL
        dword = ctypes.wintypes.DWORD
        lparam = ctypes.wintypes.LPARAM
        wparam = ctypes.wintypes.WPARAM

        kernel32.OpenProcess.argtypes = [dword, bool_type, dword]
        kernel32.OpenProcess.restype = handle
        kernel32.CloseHandle.argtypes = [handle]
        kernel32.CloseHandle.restype = bool_type
        kernel32.GetExitCodeProcess.argtypes = [
            handle,
            ctypes.POINTER(dword),
        ]
        kernel32.GetExitCodeProcess.restype = bool_type

        user32.GetWindowThreadProcessId.argtypes = [
            hwnd,
            ctypes.POINTER(dword),
        ]
        user32.GetWindowThreadProcessId.restype = dword
        user32.GetForegroundWindow.argtypes = []
        user32.GetForegroundWindow.restype = hwnd
        user32.SetForegroundWindow.argtypes = [hwnd]
        user32.SetForegroundWindow.restype = bool_type
        user32.GetClientRect.argtypes = [
            hwnd,
            ctypes.POINTER(ctypes.wintypes.RECT),
        ]
        user32.GetClientRect.restype = bool_type
        user32.GetWindowRect.argtypes = [
            hwnd,
            ctypes.POINTER(ctypes.wintypes.RECT),
        ]
        user32.GetWindowRect.restype = bool_type
        user32.ClientToScreen.argtypes = [
            hwnd,
            ctypes.POINTER(ctypes.wintypes.POINT),
        ]
        user32.ClientToScreen.restype = bool_type
        user32.GetWindowTextW.argtypes = [
            hwnd,
            ctypes.wintypes.LPWSTR,
            ctypes.c_int,
        ]
        user32.GetWindowTextW.restype = ctypes.c_int
        user32.SetWindowTextW.argtypes = [hwnd, ctypes.wintypes.LPCWSTR]
        user32.SetWindowTextW.restype = bool_type
        user32.GetClassNameW.argtypes = [
            hwnd,
            ctypes.wintypes.LPWSTR,
            ctypes.c_int,
        ]
        user32.GetClassNameW.restype = ctypes.c_int
        user32.SendMessageW.argtypes = [
            hwnd,
            ctypes.wintypes.UINT,
            wparam,
            lparam,
        ]
        user32.SendMessageW.restype = ctypes.c_ssize_t
        user32.PostMessageW.argtypes = [
            hwnd,
            ctypes.wintypes.UINT,
            wparam,
            lparam,
        ]
        user32.PostMessageW.restype = bool_type

        self._enum_windows_callback_type = ctypes.WINFUNCTYPE(
            bool_type,
            hwnd,
            lparam,
        )
        user32.EnumWindows.argtypes = [self._enum_windows_callback_type, lparam]
        user32.EnumWindows.restype = bool_type

        self._psapi = ctypes.windll.psapi
        self._psapi.GetModuleFileNameExW.argtypes = [
            handle,
            ctypes.wintypes.HMODULE,
            ctypes.wintypes.LPWSTR,
            dword,
        ]
        self._psapi.GetModuleFileNameExW.restype = dword

        hdc = ctypes.wintypes.HDC
        hbrush = getattr(ctypes.wintypes, "HBRUSH", handle)
        hrgn = getattr(ctypes.wintypes, "HRGN", handle)
        hgdiobj = getattr(ctypes.wintypes, "HGDIOBJ", handle)
        user32.GetDC.argtypes = [hwnd]
        user32.GetDC.restype = hdc
        user32.BeginPaint.argtypes = [hwnd, ctypes.POINTER(_PaintStruct)]
        user32.BeginPaint.restype = hdc
        user32.EndPaint.argtypes = [hwnd, ctypes.POINTER(_PaintStruct)]
        user32.EndPaint.restype = bool_type
        user32.ReleaseDC.argtypes = [hwnd, hdc]
        user32.ReleaseDC.restype = ctypes.c_int

        if gdi32 is not None:
            gdi32.CreateSolidBrush.argtypes = [dword]
            gdi32.CreateSolidBrush.restype = hbrush
            gdi32.CreateRectRgnIndirect.argtypes = [
                ctypes.POINTER(ctypes.wintypes.RECT)
            ]
            gdi32.CreateRectRgnIndirect.restype = hrgn
            gdi32.FillRgn.argtypes = [hdc, hrgn, hbrush]
            gdi32.FillRgn.restype = bool_type
            gdi32.DeleteObject.argtypes = [hgdiobj]
            gdi32.DeleteObject.restype = bool_type

    def _require_windows(self) -> None:
        if self.platform != "win32" or user32 is None or kernel32 is None:
            raise UnsupportedClientOperation("legacy Windows platform APIs")

    def install_location(self) -> Path:
        self._require_windows()
        winreg = import_module("winreg")
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{A9E27FF5-6294-46A8-B8FD-77B1DECA3021}",
            0,
            winreg.KEY_READ,
        ) as key:
            return Path(winreg.QueryValueEx(key, "InstallLocation")[0]).absolute()

    def start_instance(self, install_location: Path) -> None:
        self._require_windows()
        subprocess.Popen(
            rf"{install_location}\Bin\WizardGraphicalClient.exe -L login.us.wizard101.com 12000",
            cwd=rf"{install_location}\Bin",
        )

    def send_login(self, window_handle: int, username: str, password: str) -> None:
        self._require_windows()
        for char in username:
            user32.SendMessageW(window_handle, 0x102, ord(char), 0)
        user32.SendMessageW(window_handle, 0x102, 9, 0)
        for char in password:
            user32.SendMessageW(window_handle, 0x102, ord(char), 0)
        user32.SendMessageW(window_handle, 0x102, 13, 0)

    def set_process_dpi_awareness(self) -> None:
        self._require_windows()
        ctypes.windll.shcore.SetProcessDpiAwareness(2)

    def send_window_message(
        self,
        window_handle: int,
        message: int,
        wparam: int,
        lparam: int,
        *,
        post: bool = False,
    ) -> None:
        self._require_windows()
        method = user32.PostMessageW if post else user32.SendMessageW
        method(window_handle, message, wparam, lparam)

    def client_to_screen(self, window_handle: int, x: int, y: int) -> tuple[int, int]:
        self._require_windows()
        point = ctypes.wintypes.POINT(x, y)
        if user32.ClientToScreen(window_handle, ctypes.byref(point)) == 0:
            raise RuntimeError("Client to screen conversion failed")
        return point.x, point.y

    def client_size(self, window_handle: int) -> tuple[int, int]:
        self._require_windows()
        rectangle = ctypes.wintypes.RECT()
        if user32.GetClientRect(window_handle, ctypes.byref(rectangle)) == 0:
            raise RuntimeError("Could not read the client area")
        return rectangle.right - rectangle.left, rectangle.bottom - rectangle.top

    def system_directory(self, max_size: int) -> Path:
        self._require_windows()
        buffer = ctypes.create_unicode_buffer(max_size)
        kernel32.GetSystemDirectoryW(buffer, max_size)
        return Path(buffer.value)

    def foreground_window(self) -> int | None:
        self._require_windows()
        return user32.GetForegroundWindow()

    def set_foreground_window(self, window_handle: int) -> bool:
        self._require_windows()
        return user32.SetForegroundWindow(window_handle) != 0

    def window_title(self, window_handle: int, max_size: int) -> str:
        self._require_windows()
        title = ctypes.create_unicode_buffer(max_size)
        user32.GetWindowTextW(window_handle, title, max_size)
        return title.value

    def set_window_title(self, window_handle: int, title: str) -> None:
        self._require_windows()
        user32.SetWindowTextW(window_handle, title)

    def window_rectangle(self, window_handle: int) -> tuple[int, int, int, int]:
        self._require_windows()
        rectangle = ctypes.wintypes.RECT()
        user32.GetWindowRect(window_handle, ctypes.byref(rectangle))
        return rectangle.right, rectangle.top, rectangle.left, rectangle.bottom

    def process_running(self, process_handle: int) -> bool:
        self._require_windows()
        exit_code = ctypes.wintypes.DWORD()
        kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code))
        return exit_code.value == 259

    def process_id(self, window_handle: int) -> int:
        self._require_windows()
        process_id = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(window_handle, ctypes.byref(process_id))
        return process_id.value

    def process_path(self, window_handle: int, max_size: int = 32768) -> Path:
        self._require_windows()
        process_id = self.process_id(window_handle)
        process_handle = kernel32.OpenProcess(0x410, 0, process_id)
        if not process_handle:
            raise OSError(f"Could not open process {process_id}")
        try:
            path = ctypes.create_unicode_buffer(max_size)
            if self._psapi.GetModuleFileNameExW(
                process_handle, None, path, max_size
            ) == 0:
                raise OSError(f"Could not read the executable path for process {process_id}")
            return Path(path.value)
        finally:
            kernel32.CloseHandle(process_handle)

    def enumerate_windows(self, predicate: Callable[[int], bool]) -> list[int]:
        self._require_windows()
        handles: list[int] = []

        def callback(window_handle, _):
            if predicate(window_handle):
                handles.append(window_handle)
            return 1

        user32.EnumWindows(self._enum_windows_callback_type(callback), 0)
        return handles

    def window_class(self, window_handle: int, max_size: int) -> str:
        self._require_windows()
        class_name = ctypes.create_unicode_buffer(max_size)
        user32.GetClassNameW(window_handle, class_name, max_size)
        return class_name.value

    def paint_rectangle(
        self,
        window_handle: int,
        rectangle: tuple[int, int, int, int],
        rgb: tuple[int, int, int],
    ) -> None:
        self._require_windows()
        if gdi32 is None:
            raise UnsupportedClientOperation("legacy Windows painting")
        paint = _PaintStruct()
        device_context = user32.GetDC(window_handle)
        brush = gdi32.CreateSolidBrush(ctypes.wintypes.RGB(*rgb))
        user32.BeginPaint(window_handle, ctypes.byref(paint))
        draw_rectangle = ctypes.wintypes.RECT(*rectangle)
        region = gdi32.CreateRectRgnIndirect(ctypes.byref(draw_rectangle))
        try:
            gdi32.FillRgn(device_context, region, brush)
        finally:
            user32.EndPaint(window_handle, ctypes.byref(paint))
            user32.ReleaseDC(window_handle, device_context)
            gdi32.DeleteObject(brush)
            gdi32.DeleteObject(region)


legacy_windows = LegacyWindowsPlatformAdapter()


def client_size(client) -> tuple[int, int]:
    """Resolve client-area sizing from native discovery or legacy HWND APIs."""
    geometry = getattr(client, "overlay_geometry", None)
    if isinstance(geometry, dict):
        width = geometry.get("width")
        height = geometry.get("height")
        if (
            isinstance(width, int)
            and not isinstance(width, bool)
            and width > 0
            and isinstance(height, int)
            and not isinstance(height, bool)
            and height > 0
        ):
            return width, height
        raise ValueError("The native client returned an invalid client-area size")
    return legacy_windows.client_size(client.window_handle)


async def send_key_message(client, key, *, post: bool = False) -> None:
    """Send one legacy key press while retaining native-client routing."""
    if hasattr(client, "client_id"):
        await client.send_key(key)
        return
    value = int(getattr(key, "value", key))
    legacy_windows.send_window_message(
        client.window_handle,
        WM_KEYDOWN,
        value,
        0,
        post=post,
    )
    legacy_windows.send_window_message(
        client.window_handle,
        WM_KEYUP,
        value,
        0,
        post=post,
    )
