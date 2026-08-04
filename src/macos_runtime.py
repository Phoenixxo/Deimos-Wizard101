"""macOS CrossOver runtime configuration for the packaged desktop app."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


DEFAULT_CX_ROOT = (
    Path.home()
    / "Applications"
    / "Wizard101.app"
    / "Contents"
    / "SharedSupport"
    / "wizard101"
)
DEFAULT_BOTTLE = (
    Path.home()
    / "Library"
    / "Application Support"
    / "Wizard101"
    / "Bottles"
    / "wizard101"
)


class MacOSRuntimeConfigurationError(RuntimeError):
    """Raised when a saved CrossOver runtime configuration cannot be used."""


def bundled_agent_path() -> Path:
    if sys.platform == "darwin" and getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent.parent / "Resources" / "deimos-agent.exe"
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / "deimos-agent.exe"


def configured_agent_manager(settings: Any, *, native_module: Any) -> Any | None:
    """Create the configured CrossOver manager, or leave macOS discovery disabled."""
    if sys.platform != "darwin":
        return None

    cx_root_value = settings.get_setting("macos_cx_root")
    bottle_value = settings.get_setting("macos_bottle")
    if not cx_root_value or not bottle_value:
        return None

    cx_root = Path(cx_root_value).expanduser()
    bottle = Path(bottle_value).expanduser()
    bottle_name = settings.get_setting("macos_bottle_name") or bottle.name
    wine = cx_root / "bin" / "wine"
    wineserver = cx_root / "bin" / "wineserver"
    agent = bundled_agent_path()

    missing = [
        (bottle, "Wizard101 bottle"),
        (wine, "CrossOver Wine wrapper"),
        (wineserver, "CrossOver wineserver"),
        (agent, "bundled Deimos agent"),
    ]
    for path, label in missing:
        if not path.exists():
            raise MacOSRuntimeConfigurationError(f"{label} was not found at {path}")

    return native_module.AgentManager(
        str(bottle.resolve()),
        str(wine.resolve()),
        str(agent.resolve()),
        wineserver_executable=str(wineserver.resolve()),
        wine_arguments=["--bottle", str(bottle_name)],
        wrapper_manages_wine_loader=True,
        component="deimos-desktop",
    )


def start_configured_agent(settings: Any, *, native_module: Any) -> Any | None:
    """Start the saved macOS runtime before the backend begins client discovery."""
    manager = configured_agent_manager(settings, native_module=native_module)
    if manager is not None:
        manager.start()
    return manager
