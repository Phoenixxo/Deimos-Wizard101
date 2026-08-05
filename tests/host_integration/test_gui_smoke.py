from __future__ import annotations

import os
import queue
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton  # noqa: E402
from src.gui.commands import GUICommand, GUICommandType  # noqa: E402
from src.gui import main as gui_main  # noqa: E402
from src.gui.widgets import ConsoleTextEdit, PyQtSink  # noqa: E402
from src.settings_manager import DEFAULT_THEME  # noqa: E402


class GuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_gui_builds_without_windows_host_apis(self):
        send_queue = queue.Queue()
        receive_queue = queue.Queue()
        receive_queue.put(GUICommand(GUICommandType.Close))

        with patch.object(gui_main, "QApplication", return_value=self.app), patch.object(
            self.app,
            "exec",
            return_value=0,
        ), patch.object(
            gui_main.host_platform,
            "request_input_monitoring_permission",
            return_value=False,
        ) as request_permission:
            gui_main.manage_gui(
                send_queue,
                receive_queue,
                DEFAULT_THEME.copy(),
                "Deimos",
                "test",
                False,
                "en",
            )

        request_permission.assert_called_once_with()

        commands = []
        while not send_queue.empty():
            commands.append(send_queue.get_nowait().com_type)
        self.assertIn(GUICommandType.AttemptedClose, commands)

    def test_close_and_open_logs_use_native_priority_paths(self):
        send_queue = queue.Queue()
        receive_queue = queue.Queue()
        receive_queue.put(GUICommand(GUICommandType.Close))
        control_queue = queue.Queue()
        shutdown_event = threading.Event()

        def exercise_window():
            window = next(
                widget
                for widget in self.app.topLevelWidgets()
                if isinstance(widget, QMainWindow)
            )
            open_logs = next(
                button
                for button in window.findChildren(QPushButton)
                if button.toolTip() == "Open Logs"
            )
            open_logs.click()
            window.close()
            self.app.processEvents()
            return 0

        with tempfile.TemporaryDirectory(prefix="deimos-gui-logs-") as logs, patch.object(
            gui_main,
            "QApplication",
            return_value=self.app,
        ), patch.object(
            self.app,
            "exec",
            side_effect=exercise_window,
        ), patch.object(
            gui_main.QDesktopServices,
            "openUrl",
            return_value=True,
        ) as open_url, patch.object(
            gui_main.host_platform,
            "request_input_monitoring_permission",
            return_value=False,
        ):
            gui_main.manage_gui(
                send_queue,
                receive_queue,
                DEFAULT_THEME.copy(),
                "Deimos",
                "test",
                False,
                "en",
                control_queue=control_queue,
                shutdown_event=shutdown_event,
                log_directory=logs,
            )

        self.assertTrue(shutdown_event.is_set())
        self.assertTrue(open_url.called)
        self.assertEqual(
            control_queue.get_nowait().com_type,
            GUICommandType.AttemptedClose,
        )

    def test_console_defaults_to_full_messages_and_retains_more_history(self):
        console = ConsoleTextEdit()
        sink = PyQtSink(console)

        self.assertTrue(sink.show_expanded_logs)
        self.assertEqual(sink.max_lines, 5000)
        self.assertEqual(console.maximumBlockCount(), 5000)


if __name__ == "__main__":
    unittest.main()
