"""Client window resizing — freeform, crisp, undistorted game-window resizing.

Pieces (Deimos runs out-of-process, but uses WizWalker's in-process asm hooks for
the one thing cross-process can't do — forcing the render backbuffer):

1. Window (ctypes): add a sizing border (WS_THICKFRAME) so the game window can be
   drag-resized. (A fat WM_NCHITTEST grab zone would need a WndProc subclass, which
   is process-local; the native border still works — grab right at the edge.)

2. Backbuffer (WizWalker asm hook — wizsprinter ResolutionForcer): on resize, force
   the D3D backbuffer to the new client size so the render is crisp (not stretched)
   AND so mouse/UI hit-testing stays correct (the game maps clicks against the
   backbuffer; a backbuffer != client mismatch offsets every click). We therefore
   keep window-client == backbuffer at all times.

3. Camera aspect (WizWalker memory): the 3D projection aspect comes from the engine
   view frustum, not the backbuffer, so we widen the CamView frustum to match the
   window aspect (keeping vertical FOV) → world fills any aspect undistorted.

On a drag (debounced to the final size): force backbuffer = WxH, re-assert the
window client to WxH (the engine's apply snaps the window to its old size), then
correct the frustum aspect. If the asm hook is unavailable/fails, it degrades to
resize + aspect-correct (render scales) without crashing.
"""
from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes

from loguru import logger

try:
    from wizwalker.extensions.wizsprinter.resolution_hook import ResolutionForcer
except Exception:  # pragma: no cover - keep the feature usable without the hook
    ResolutionForcer = None

try:
    # Needs keystone-engine; makes the window grab-resizable in-process.
    from wizwalker.extensions.wizsprinter.resolution_hook import WindowResizeBorder
except Exception:  # pragma: no cover
    WindowResizeBorder = None

RESIZE_MARGIN = 14  # px grab zone at the window edges

# ---- Win32 (cross-process safe: GWL_STYLE, SetWindowPos, Get*Rect) ----
user32 = ctypes.WinDLL("user32", use_last_error=True)
LONG_PTR = ctypes.c_longlong

user32.GetWindowLongPtrW.restype = LONG_PTR
user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.SetWindowLongPtrW.restype = LONG_PTR
user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, LONG_PTR]
user32.SetWindowPos.restype = wintypes.BOOL
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT]
user32.AdjustWindowRectEx.argtypes = [ctypes.POINTER(wintypes.RECT), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.IsWindow.argtypes = [wintypes.HWND]

GWL_STYLE = -16
GWL_EXSTYLE = -20
WS_THICKFRAME = 0x00040000
WS_MAXIMIZEBOX = 0x00010000
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_FRAMECHANGED = 0x0020

# Stability ticks before acting on a new size (debounce drag -> final size).
_STABLE_TICKS = 2


def _client_size(hwnd: int):
    r = wintypes.RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(r)):
        return None
    return (r.right - r.left, r.bottom - r.top)


def _style(hwnd: int, idx: int) -> int:
    return int(user32.GetWindowLongPtrW(hwnd, idx)) & 0xFFFFFFFF


def set_client_size(hwnd: int, w: int, h: int):
    """Resize so the window's CLIENT area is exactly w x h (keeps position)."""
    style = _style(hwnd, GWL_STYLE)
    ex = _style(hwnd, GWL_EXSTYLE)
    r = wintypes.RECT(0, 0, w, h)
    user32.AdjustWindowRectEx(ctypes.byref(r), style, False, ex)
    user32.SetWindowPos(hwnd, 0, 0, 0, r.right - r.left, r.bottom - r.top,
                        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE)


def set_window_placement(hwnd: int, x: int, y: int, w: int, h: int):
    """Move the window to (x, y) and make its CLIENT area exactly w x h."""
    style = _style(hwnd, GWL_STYLE)
    ex = _style(hwnd, GWL_EXSTYLE)
    r = wintypes.RECT(0, 0, w, h)
    user32.AdjustWindowRectEx(ctypes.byref(r), style, False, ex)
    user32.SetWindowPos(hwnd, 0, int(x), int(y), r.right - r.left, r.bottom - r.top,
                        SWP_NOZORDER | SWP_NOACTIVATE)


# NOTE: applying a per-account window config at launch is a METHOD on
# ClientResizingManager (apply_account_config) rather than a free function, so it
# reuses the manager's single per-client ResolutionForcer. A second, independent
# forcer would pattern-scan setMode *after* the manager already hooked it (its
# entry is now a jump, not the original bytes) and fail with PatternFailed.


class _ArmState:
    __slots__ = ("orig_style", "last_size")

    def __init__(self, orig_style: int):
        self.orig_style = orig_style
        self.last_size = None


_armed: dict[int, _ArmState] = {}


def is_armed(hwnd: int) -> bool:
    return hwnd in _armed


def arm_window(hwnd: int) -> bool:
    """Ensure the game window has a sizing border so it can be drag-resized.

    Self-healing: called every tick, it re-adds WS_THICKFRAME if it has gone missing
    (e.g. the game/another tool reset the style), remembering the original style the
    first time so it can be restored on disarm.
    """
    if not hwnd:
        return False
    try:
        style = _style(hwnd, GWL_STYLE)
        if style & WS_THICKFRAME:
            # Already has a sizing border; record the pre-arm style once.
            if hwnd not in _armed:
                _armed[hwnd] = _ArmState(style & ~WS_THICKFRAME)
            return True
        # Missing the sizing border — add it (and remember the original once).
        if hwnd not in _armed:
            _armed[hwnd] = _ArmState(style)
            logger.debug(f"[client_resizing] armed window {hwnd:#x}")
        user32.SetWindowLongPtrW(hwnd, GWL_STYLE, style | WS_THICKFRAME | WS_MAXIMIZEBOX)
        user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
                            SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED)
        return True
    except Exception as e:
        logger.opt(exception=e).warning(f"[client_resizing] failed to arm {hwnd:#x}")
        return False


def disarm_window(hwnd: int):
    """Restore the original window style (removes the sizing border)."""
    state = _armed.pop(hwnd, None)
    if state is None:
        return
    try:
        if user32.IsWindow(hwnd):
            user32.SetWindowLongPtrW(hwnd, GWL_STYLE, state.orig_style)
            user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
                                SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED)
    except Exception as e:
        logger.opt(exception=e).debug(f"[client_resizing] disarm error {hwnd:#x}")


async def _cam_view(client):
    try:
        cam = await client.game_client.selected_camera_controller()
        if cam is None:
            return None
        gcam = await cam.gamebryo_camera()
        if gcam is None:
            return None
        return await gcam.cam_view()
    except Exception:
        return None


NATIVE_ASPECT = 16.0 / 9.0   # the engine's design aspect (its native frustum is 16:9)
# Per-window native vertical half-extent (the frustum's vertical FOV, which is
# constant — zoom is camera distance, not FOV). Captured once so we can rebuild
# both extents for any window aspect.
_native_vert: dict[int, float] = {}


async def correct_aspect(client, hwnd: int) -> bool:
    """Match the camera frustum to the window aspect, writing BOTH extents.

    The frustum aspect = horizontal_extent / vertical_extent must equal the window
    W/H or the 3D view distorts. Anchored on the native vertical FOV, we expand the
    dimension that exceeds the native 16:9 aspect: wider windows widen the
    horizontal extent (see more horizontally), taller/narrower windows grow the
    vertical extent (see more vertically). Both top/bottom and left/right are set.
    """
    size = _client_size(hwnd)
    if not size or size[1] <= 0:
        return False
    aspect = size[0] / size[1]
    view = await _cam_view(client)
    if view is None:
        return False
    try:
        v_ref = _native_vert.get(hwnd)
        if v_ref is None:
            # First time: capture the native vertical half-extent (FOV is constant).
            top = await view.viewport_top()
            bottom = await view.viewport_bottom()
            v_ref = (top - bottom) / 2.0
            if v_ref <= 0:
                return False
            _native_vert[hwnd] = v_ref

        if aspect >= NATIVE_ASPECT:          # wider than native -> grow horizontal
            v = v_ref
            h = v_ref * aspect
        else:                                # taller/narrower -> grow vertical
            h = v_ref * NATIVE_ASPECT
            v = h / aspect
        await view.write_viewport_top(v)
        await view.write_viewport_bottom(-v)
        await view.write_viewport_left(-h)
        await view.write_viewport_right(h)
        return True
    except Exception:
        return False


class ClientResizingManager:
    """Per-client freeform resizing: a sizing border, crisp backbuffer forcing
    (in-process asm hook) keeping window==backbuffer, and camera-aspect correction.

    Call tick(clients, enabled) periodically.
    """

    def __init__(self):
        self._enabled = False
        self._forcers: dict[int, object] = {}     # hwnd -> ResolutionForcer
        self._borders: dict[int, object] = {}      # hwnd -> WindowResizeBorder
        self._pending: dict[int, tuple] = {}       # hwnd -> (size, stable_count)
        # Serializes forcer installation so the tick loop and a launch-time
        # apply can't both install a forcer for the same client (double setMode
        # hook -> the second one's pattern scan fails).
        self._install_lock = asyncio.Lock()

    async def tick(self, clients, enabled: bool):
        if not enabled:
            if self._enabled:
                self._enabled = False
                await self._teardown_all()
            return
        self._enabled = True

        live = set()
        for client in clients:
            hwnd = getattr(client, "window_handle", 0)
            if not hwnd or not user32.IsWindow(hwnd):
                continue
            live.add(hwnd)
            arm_window(hwnd)
            await self._ensure_forcer(client, hwnd)
            await self._ensure_border(client, hwnd)
            await self._update_border(hwnd)
            await self._handle_resize(client, hwnd)

        for hwnd in set(self._forcers) | set(self._borders) | set(_armed):
            if hwnd not in live:
                await self._teardown(hwnd)

    async def _ensure_forcer(self, client, hwnd: int):
        if ResolutionForcer is None or hwnd in self._forcers:
            return
        async with self._install_lock:
            if hwnd in self._forcers:          # re-check after acquiring the lock
                return
            try:
                forcer = ResolutionForcer(client)
                await forcer.install()
                self._forcers[hwnd] = forcer
                logger.debug(f"[client_resizing] resolution hook installed {hwnd:#x}")
            except Exception as e:
                logger.opt(exception=e).warning(f"[client_resizing] resolution hook unavailable {hwnd:#x}")

    async def apply_account_config(self, client, hwnd: int, x: int, y: int, w: int, h: int,
                                   res_w: int, res_h: int, locked: bool) -> bool:
        """Apply a saved per-account window config to a freshly-launched client:
        force the render resolution, place + size the window, correct the aspect.
        Reuses the manager's single per-client forcer (see note above)."""
        if not hwnd or not user32.IsWindow(hwnd):
            return False
        await self._ensure_forcer(client, hwnd)
        forcer = self._forcers.get(hwnd)
        if forcer is not None:
            try:
                for _ in range(15):            # wait for the video-manager capture
                    if await forcer._manager_address():
                        break
                    await asyncio.sleep(0.2)
                await forcer.force(res_w, res_h)
                await asyncio.sleep(0.4)        # let the engine run its apply
            except Exception as e:
                logger.opt(exception=e).debug(f"[client_resizing] launch force failed {hwnd:#x}")
        try:
            set_window_placement(hwnd, x, y, w, h)
        except Exception:
            pass
        await correct_aspect(client, hwnd)
        return True

    async def _ensure_border(self, client, hwnd: int):
        # The in-process WndProc hit-test hook that makes the window grab-resizable.
        if WindowResizeBorder is None or hwnd in self._borders:
            return
        try:
            border = WindowResizeBorder(client)
            await border.install()
            self._borders[hwnd] = border
            logger.debug(f"[client_resizing] resize-border hook installed {hwnd:#x}")
        except Exception as e:
            logger.opt(exception=e).warning(f"[client_resizing] resize-border hook unavailable {hwnd:#x}")

    async def _update_border(self, hwnd: int):
        # Keep the hit-test hook's window rect current (cursor is hit-tested against it).
        border = self._borders.get(hwnd)
        if border is None:
            return
        r = wintypes.RECT()
        if user32.GetWindowRect(hwnd, ctypes.byref(r)):
            try:
                await border.update_rect(r.left, r.top, r.right, r.bottom, RESIZE_MARGIN)
            except Exception:
                pass

    async def _handle_resize(self, client, hwnd: int):
        state = _armed.get(hwnd)
        if state is None:
            return
        cur = _client_size(hwnd)
        if not cur or cur[1] <= 0:
            return
        if cur == state.last_size:
            self._pending.pop(hwnd, None)
            return

        # Debounce: only act once the size has settled (drag finished).
        psize, count = self._pending.get(hwnd, (None, 0))
        count = count + 1 if cur == psize else 0
        self._pending[hwnd] = (cur, count)
        if count < _STABLE_TICKS:
            return

        w, h = cur
        forcer = self._forcers.get(hwnd)
        forced = False
        if forcer is not None:
            try:
                forced = await forcer.force(w, h)
            except Exception as e:
                logger.opt(exception=e).debug(f"[client_resizing] force failed {hwnd:#x}")
                forced = False

        if forced:
            # The engine's apply snaps the window to its descriptor size — re-assert
            # the dragged size so window-client == backbuffer (crisp + clicks correct).
            await asyncio.sleep(0.25)
            try:
                set_client_size(hwnd, w, h)
            except Exception:
                pass
            await correct_aspect(client, hwnd)
            state.last_size = _client_size(hwnd)
            self._pending.pop(hwnd, None)
        else:
            # No backbuffer force (hook unavailable / not ready): still correct the
            # aspect so the (stretched) render isn't distorted. Retry forcing later.
            await correct_aspect(client, hwnd)
            if forcer is None or ResolutionForcer is None:
                state.last_size = cur
                self._pending.pop(hwnd, None)

    async def _teardown(self, hwnd: int):
        for store in (self._forcers, self._borders):
            hook = store.pop(hwnd, None)
            if hook is not None:
                try:
                    await hook.uninstall()
                except Exception:
                    pass
        disarm_window(hwnd)
        self._pending.pop(hwnd, None)
        _native_vert.pop(hwnd, None)

    async def _teardown_all(self):
        for hwnd in set(self._forcers) | set(self._borders) | set(_armed):
            await self._teardown(hwnd)
