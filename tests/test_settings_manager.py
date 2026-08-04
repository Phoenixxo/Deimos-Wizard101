import os
import unittest
from pathlib import Path
from unittest.mock import patch

from src import settings_manager


class SettingsDirectoryTests(unittest.TestCase):
    def test_macos_uses_application_support_when_appdata_is_unset(self):
        with (
            patch.object(settings_manager.sys, "platform", "darwin"),
            patch.object(settings_manager.Path, "home", return_value=Path("/Users/tester")),
            patch.dict(os.environ, {}, clear=True),
        ):
            self.assertEqual(
                settings_manager._settings_directory(),
                Path("/Users/tester/Library/Application Support/Deimos"),
            )

    def test_appdata_remains_authoritative_when_available(self):
        with patch.dict(os.environ, {"APPDATA": "/tmp/appdata"}, clear=True):
            self.assertEqual(
                settings_manager._settings_directory(),
                Path("/tmp/appdata/Deimos"),
            )


if __name__ == "__main__":
    unittest.main()
