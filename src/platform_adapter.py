from __future__ import annotations

import ctypes
import ctypes.wintypes
import sys
from importlib import import_module
from typing import Any


class WindowsHostApi:
    """Host-window and registry calls that only exist on native Windows."""

    def set_app_user_model_id(self, value: str) -> None:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(value)

    def enable_rounded_corners(self, window_id: int) -> None:
        window = ctypes.wintypes.HWND(window_id)
        preference = ctypes.c_int(2)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            window,
            33,
            ctypes.byref(preference),
            ctypes.sizeof(preference),
        )

    def set_topmost(self, window_id: int, enabled: bool) -> None:
        method = ctypes.windll.user32.SetWindowPos
        method.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.HWND,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        method.restype = ctypes.wintypes.BOOL
        insert_after = ctypes.wintypes.HWND(-1 if enabled else -2)
        method(
            ctypes.wintypes.HWND(window_id),
            insert_after,
            0,
            0,
            0,
            0,
            0x0002 | 0x0001 | 0x0010,
        )

    def read_registry_dword(self, path: str, name: str, default: int = 0) -> int:
        winreg = import_module("winreg")
        try:
            with winreg.OpenKeyEx(
                winreg.HKEY_CURRENT_USER, path, access=winreg.KEY_READ
            ) as key:
                return int(winreg.QueryValueEx(key, name)[0])
        except OSError:
            return default

    def write_registry_dword(self, path: str, name: str, value: int) -> None:
        winreg = import_module("winreg")
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, path, access=winreg.KEY_ALL_ACCESS
        ) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)

    def show_error_message(self, message: str, title: str) -> None:
        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10 | 0x1000)


class HostPlatformAdapter:
    def __init__(
        self,
        *,
        platform: str = sys.platform,
        windows_api: Any = None,
    ):
        self.platform = platform
        self.windows_api = windows_api
        if self.platform == "win32" and self.windows_api is None:
            self.windows_api = WindowsHostApi()

    def set_app_user_model_id(self, value: str) -> None:
        if self.windows_api is not None:
            self.windows_api.set_app_user_model_id(value)

    def enable_rounded_corners(self, window_id: int) -> None:
        if self.windows_api is not None:
            self.windows_api.enable_rounded_corners(window_id)

    def set_topmost(self, window_id: int, enabled: bool) -> bool:
        if self.windows_api is None:
            return False
        self.windows_api.set_topmost(window_id, enabled)
        return True

    def read_registry_dword(self, path: str, name: str, default: int = 0) -> int:
        if self.windows_api is None:
            return default
        return self.windows_api.read_registry_dword(path, name, default)

    def write_registry_dword(self, path: str, name: str, value: int) -> None:
        if self.windows_api is not None:
            self.windows_api.write_registry_dword(path, name, value)

    def show_error_message(self, message: str, title: str) -> None:
        if self.windows_api is not None:
            self.windows_api.show_error_message(message, title)


host_platform = HostPlatformAdapter()
