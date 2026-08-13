import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from src import macos_runtime


class _Settings:
    def __init__(self, values):
        self.values = values

    def get_setting(self, key):
        return self.values.get(key)


class MacOSRuntimeTests(unittest.TestCase):
    def test_unconfigured_runtime_does_not_create_a_manager(self):
        settings = _Settings({"macos_cx_root": "", "macos_bottle": ""})
        with patch.object(macos_runtime.sys, "platform", "darwin"):
            self.assertIsNone(
                macos_runtime.configured_agent_manager(settings, native_module=SimpleNamespace())
            )

    def test_standard_crossover_install_is_used_without_saved_settings(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cx_root = root / "wizard101"
            bottle = root / "bottle"
            (cx_root / "bin").mkdir(parents=True)
            bottle.mkdir()
            (cx_root / "bin" / "wine").touch()
            (cx_root / "bin" / "wineserver").touch()
            agent = root / "deimos-agent.exe"
            agent.touch()
            calls = []

            class Manager:
                def __init__(self, *args, **kwargs):
                    calls.append((args, kwargs))

            settings = _Settings({"macos_cx_root": "", "macos_bottle": ""})
            with (
                patch.object(macos_runtime.sys, "platform", "darwin"),
                patch.object(macos_runtime, "DEFAULT_CX_ROOT", cx_root),
                patch.object(macos_runtime, "DEFAULT_BOTTLE", bottle),
                patch.object(macos_runtime, "bundled_agent_path", return_value=agent),
            ):
                manager = macos_runtime.configured_agent_manager(
                    settings, native_module=SimpleNamespace(AgentManager=Manager)
                )

            self.assertIsInstance(manager, Manager)
            self.assertEqual(calls[0][0][0], str(bottle.resolve()))

    def test_game_path_is_discovered_inside_the_selected_bottle(self):
        with TemporaryDirectory() as directory:
            bottle = Path(directory)
            executable = (
                bottle
                / "drive_c"
                / "Program Files (x86)"
                / "Steam"
                / "steamapps"
                / "common"
                / "Wizard101"
                / "Bin"
                / "WizardGraphicalClient.exe"
            )
            executable.parent.mkdir(parents=True)
            executable.touch()

            settings = _Settings({"macos_bottle": str(bottle), "game_path": ""})
            self.assertEqual(
                macos_runtime.configured_game_path(settings),
                r"C:\Program Files (x86)\Steam\steamapps\common\Wizard101",
            )

    def test_configured_runtime_starts_the_packaged_agent(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cx_root = root / "wizard101"
            bottle = root / "bottle"
            (cx_root / "bin").mkdir(parents=True)
            bottle.mkdir()
            (cx_root / "bin" / "wine").touch()
            (cx_root / "bin" / "wineserver").touch()
            agent = root / "deimos-agent.exe"
            agent.touch()
            calls = []

            class Manager:
                def __init__(self, *args, **kwargs):
                    calls.append((args, kwargs))

                def start(self):
                    calls.append("started")

            settings = _Settings({
                "macos_cx_root": str(cx_root),
                "macos_bottle": str(bottle),
                "macos_bottle_name": "wizard101",
            })
            with (
                patch.object(macos_runtime.sys, "platform", "darwin"),
                patch.object(macos_runtime, "bundled_agent_path", return_value=agent),
            ):
                manager = macos_runtime.start_configured_agent(
                    settings, native_module=SimpleNamespace(AgentManager=Manager)
                )

            self.assertIsInstance(manager, Manager)
            self.assertEqual(calls[-1], "started")
            self.assertEqual(calls[0][1]["wine_arguments"], ["--bottle", "wizard101"])

    def test_non_macos_platform_does_not_enable_wine_runtime(self):
        settings = _Settings({"macos_cx_root": "/runtime", "macos_bottle": "/bottle"})
        with patch.object(macos_runtime.sys, "platform", "win32"):
            self.assertIsNone(
                macos_runtime.configured_agent_manager(settings, native_module=SimpleNamespace())
            )

    def test_frozen_macos_bundle_resolves_agent_from_resources(self):
        executable = Path("/Applications/Deimos.app/Contents/MacOS/Deimos")
        with (
            patch.object(macos_runtime.sys, "platform", "darwin"),
            patch.object(macos_runtime.sys, "frozen", True, create=True),
            patch.object(macos_runtime.sys, "executable", str(executable)),
        ):
            self.assertEqual(
                macos_runtime.bundled_agent_path(),
                Path("/Applications/Deimos.app/Contents/Resources/deimos-agent.exe"),
            )


if __name__ == "__main__":
    unittest.main()
