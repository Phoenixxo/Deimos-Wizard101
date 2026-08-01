from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class OverlayGeometry:
    left: int
    top: int
    width: int
    height: int
    stack_reference: int | None = None
    is_foreground: bool | None = None

    @classmethod
    def from_mapping(cls, value, *, stack_reference=None):
        if not isinstance(value, dict):
            raise ValueError("The overlay target did not provide window geometry.")
        fields = (value.get(name) for name in ("left", "top", "width", "height"))
        left, top, width, height = fields
        if not all(isinstance(item, int) and not isinstance(item, bool) for item in (left, top, width, height)):
            raise ValueError("The overlay target returned invalid window geometry.")
        if width <= 0 or height <= 0:
            raise ValueError("The selected Wizard101 client has no visible client area.")
        is_foreground = value.get("is_foreground")
        if is_foreground is not None and not isinstance(is_foreground, bool):
            raise ValueError("The overlay target returned an invalid foreground state.")
        return cls(left, top, width, height, stack_reference, is_foreground)


class OverlayGeometryAdapter:
    """Resolves platform window details before the PyQt overlay is positioned."""

    def __init__(self, *, platform=None, windows_api=None):
        self.platform = platform or sys.platform
        self._windows_api = windows_api

    @property
    def windows_api(self):
        if self._windows_api is None:
            self._windows_api = _WindowsOverlayApi()
        return self._windows_api

    def resolve(self, target) -> OverlayGeometry:
        if isinstance(target, OverlayGeometry):
            return target
        if isinstance(target, dict):
            return OverlayGeometry.from_mapping(target)
        geometry = getattr(target, "overlay_geometry", None)
        if geometry is not None:
            return OverlayGeometry.from_mapping(geometry)
        if self.platform == "win32" and isinstance(target, int):
            return self.windows_api.client_geometry(target)
        raise ValueError(
            "The selected Wizard101 client does not provide overlay geometry on this platform."
        )

    def configure_widget(self, widget, qt):
        widget.setAttribute(qt.WidgetAttribute.WA_TranslucentBackground)
        widget.setAttribute(qt.WidgetAttribute.WA_ShowWithoutActivating)
        widget.setAttribute(qt.WidgetAttribute.WA_TransparentForMouseEvents)
        if hasattr(qt.WindowType, "WindowTransparentForInput"):
            widget.setWindowFlag(qt.WindowType.WindowTransparentForInput, True)
        if self.platform == "darwin":
            widget.setWindowFlag(qt.WindowType.WindowStaysOnTopHint, True)

    def ensure_native_behavior(self, widget):
        if self.platform == "win32":
            self.windows_api.make_click_through(int(widget.winId()))

    def qt_coordinate_scale(self, widget) -> float:
        # Win32 client coordinates are physical pixels. CrossOver reports macOS
        # desktop coordinates, which are already in the point units Qt expects.
        return widget.devicePixelRatioF() if self.platform == "win32" else 1.0

    def maintain_stacking(self, widget, geometry: OverlayGeometry):
        if self.platform == "win32" and geometry.stack_reference is not None:
            self.windows_api.stack_above(int(widget.winId()), geometry.stack_reference)
        elif self.platform == "darwin":
            widget.raise_()

    def should_display(self, geometry: OverlayGeometry) -> bool:
        return self.platform != "darwin" or geometry.is_foreground is not False


class _WindowsOverlayApi:
    def __init__(self):
        try:
            import deimos_native
        except ImportError as error:
            raise RuntimeError(
                "The native Deimos extension is required for Windows overlay support."
            ) from error
        try:
            self.manager = deimos_native.HostWindowManager()
        except AttributeError as error:
            raise RuntimeError(
                "This deimos_native build does not include Windows overlay support."
            ) from error

    def client_geometry(self, game_window: int) -> OverlayGeometry:
        left, top, width, height = self.manager.client_geometry(game_window)
        return OverlayGeometry(
            left,
            top,
            width,
            height,
            game_window,
        )

    def make_click_through(self, overlay_window: int):
        self.manager.make_click_through(overlay_window)

    def stack_above(self, overlay_window: int, game_window: int):
        self.manager.stack_above(overlay_window, game_window)
