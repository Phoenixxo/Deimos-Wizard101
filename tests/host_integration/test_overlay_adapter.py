from pathlib import Path
import importlib.util
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

OVERLAY_MODULE_PATH = REPOSITORY_ROOT / "src" / "gui" / "overlay.py"
spec = importlib.util.spec_from_file_location("deimos_overlay_adapter", OVERLAY_MODULE_PATH)
overlay_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = overlay_module
spec.loader.exec_module(overlay_module)
OverlayGeometry = overlay_module.OverlayGeometry
OverlayGeometryAdapter = overlay_module.OverlayGeometryAdapter


class FakeWindowsApi:
    def __init__(self):
        self.calls = []

    def client_geometry(self, target):
        self.calls.append(("geometry", target))
        return OverlayGeometry(10, 20, 800, 600, target)

    def make_click_through(self, overlay):
        self.calls.append(("click_through", overlay))

    def stack_above(self, overlay, target):
        self.calls.append(("stack", overlay, target))


class FakeNativeWindowManager:
    def __init__(self):
        self.calls = []

    def client_geometry(self, target):
        self.calls.append(("geometry", target))
        return (10, 20, 800, 600)

    def make_click_through(self, overlay):
        self.calls.append(("click_through", overlay))

    def stack_above(self, overlay, target):
        self.calls.append(("stack", overlay, target))


class FakeWidget:
    def __init__(self):
        self.attributes = []
        self.flags = []
        self.raise_count = 0

    def setAttribute(self, attribute):
        self.attributes.append(attribute)

    def setWindowFlag(self, flag, enabled):
        self.flags.append((flag, enabled))

    def winId(self):
        return 77

    def raise_(self):
        self.raise_count += 1

    def devicePixelRatioF(self):
        return 2.0


QT = SimpleNamespace(
    WidgetAttribute=SimpleNamespace(
        WA_TranslucentBackground="translucent",
        WA_ShowWithoutActivating="no_activate",
        WA_TransparentForMouseEvents="transparent_input",
    ),
    WindowType=SimpleNamespace(
        WindowTransparentForInput="window_transparent_input",
        WindowStaysOnTopHint="topmost",
    ),
)


class OverlayAdapterTests(unittest.TestCase):
    def test_windows_native_adapter_delegates_without_python_win32_calls(self):
        manager = FakeNativeWindowManager()
        native_module = SimpleNamespace(HostWindowManager=lambda: manager)
        with patch.dict(sys.modules, {"deimos_native": native_module}):
            windows = overlay_module._WindowsOverlayApi()

        self.assertEqual(
            windows.client_geometry(1234),
            OverlayGeometry(10, 20, 800, 600, 1234),
        )
        windows.make_click_through(77)
        windows.stack_above(77, 1234)
        self.assertEqual(
            manager.calls,
            [
                ("geometry", 1234),
                ("click_through", 77),
                ("stack", 77, 1234),
            ],
        )

    def test_native_geometry_mapping_never_requires_a_window_handle(self):
        adapter = OverlayGeometryAdapter(platform="darwin")
        geometry = adapter.resolve(
            {"left": 30, "top": 65, "width": 966, "height": 603}
        )
        self.assertEqual(geometry, OverlayGeometry(30, 65, 966, 603))
        self.assertIsNone(geometry.stack_reference)

    def test_windows_legacy_target_keeps_relative_stacking(self):
        windows = FakeWindowsApi()
        adapter = OverlayGeometryAdapter(platform="win32", windows_api=windows)
        widget = FakeWidget()

        geometry = adapter.resolve(1234)
        adapter.ensure_native_behavior(widget)
        adapter.maintain_stacking(widget, geometry)

        self.assertEqual(
            windows.calls,
            [
                ("geometry", 1234),
                ("click_through", 77),
                ("stack", 77, 1234),
            ],
        )

    def test_macos_widget_is_click_through_and_raised_without_activation(self):
        adapter = OverlayGeometryAdapter(platform="darwin")
        widget = FakeWidget()
        adapter.configure_widget(widget, QT)
        adapter.maintain_stacking(widget, OverlayGeometry(1, 2, 3, 4))

        self.assertIn("transparent_input", widget.attributes)
        self.assertIn(("window_transparent_input", True), widget.flags)
        self.assertIn(("topmost", True), widget.flags)
        self.assertEqual(widget.raise_count, 1)
        self.assertEqual(adapter.qt_coordinate_scale(widget), 1.0)

    def test_macos_overlay_hides_when_its_game_is_not_foreground(self):
        adapter = OverlayGeometryAdapter(platform="darwin")
        background = adapter.resolve(
            {
                "left": 30,
                "top": 65,
                "width": 966,
                "height": 603,
                "is_foreground": False,
            }
        )
        foreground = adapter.resolve(
            {
                "left": 30,
                "top": 65,
                "width": 966,
                "height": 603,
                "is_foreground": True,
            }
        )

        self.assertFalse(adapter.should_display(background))
        self.assertTrue(adapter.should_display(foreground))

    def test_windows_geometry_is_converted_from_device_pixels_for_qt(self):
        adapter = OverlayGeometryAdapter(
            platform="win32",
            windows_api=FakeWindowsApi(),
        )
        self.assertEqual(adapter.qt_coordinate_scale(FakeWidget()), 2.0)

    def test_invalid_or_empty_geometry_is_rejected(self):
        adapter = OverlayGeometryAdapter(platform="darwin")
        with self.assertRaisesRegex(ValueError, "invalid"):
            adapter.resolve({"left": 0, "top": 0, "width": "800", "height": 600})
        with self.assertRaisesRegex(ValueError, "no visible client area"):
            adapter.resolve({"left": 0, "top": 0, "width": 0, "height": 600})
        with self.assertRaisesRegex(ValueError, "foreground"):
            adapter.resolve(
                {
                    "left": 0,
                    "top": 0,
                    "width": 800,
                    "height": 600,
                    "is_foreground": 1,
                }
            )


if __name__ == "__main__":
    unittest.main()
