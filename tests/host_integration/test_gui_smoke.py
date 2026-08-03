from __future__ import annotations

import os
import queue
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from PyQt6.QtWidgets import QApplication  # noqa: E402
from src.gui.commands import GUICommand, GUICommandType  # noqa: E402
from src.gui import main as gui_main  # noqa: E402
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
        ):
            gui_main.manage_gui(
                send_queue,
                receive_queue,
                DEFAULT_THEME.copy(),
                "Deimos",
                "test",
                False,
                "en",
            )

        commands = []
        while not send_queue.empty():
            commands.append(send_queue.get_nowait().com_type)
        self.assertIn(GUICommandType.AttemptedClose, commands)


if __name__ == "__main__":
    unittest.main()
