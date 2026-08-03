#!/usr/bin/env python3
"""Launch the Deimos desktop UI against a live CrossOver Wizard101 bottle."""

from __future__ import annotations

import argparse
import asyncio
import json
import queue
import threading
import traceback
from pathlib import Path
from typing import Any

import deimos_native


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


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the real Deimos UI against a selected CrossOver bottle."
    )
    parser.add_argument("--agent", required=True, help="Matching deimos-agent.exe")
    parser.add_argument("--cx-root", type=Path, default=DEFAULT_CX_ROOT)
    parser.add_argument("--bottle", type=Path, default=DEFAULT_BOTTLE)
    parser.add_argument(
        "--bottle-name",
        default="wizard101",
        help="Bottle name passed to the CrossOver Wine wrapper",
    )
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed helper agent running after the UI closes",
    )
    return parser.parse_args()


def exception_report(error: BaseException) -> dict[str, Any]:
    return {
        "type": type(error).__name__,
        "message": str(error),
        "technical_message": getattr(error, "technical_message", None),
        "code": getattr(error, "code", None),
        "operation": getattr(error, "operation", None),
        "details": getattr(error, "details", None),
    }


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} was not found at {path}")


def require_directory(path: Path, label: str) -> None:
    if not path.is_dir():
        raise FileNotFoundError(f"{label} was not found at {path}")


def main() -> int:
    options = arguments()
    agent_path = Path(options.agent).expanduser().resolve()
    cx_root = options.cx_root.expanduser().resolve()
    bottle = options.bottle.expanduser().resolve()
    wine = cx_root / "bin" / "wine"
    wineserver = cx_root / "bin" / "wineserver"

    manager: deimos_native.AgentManager | None = None
    deimos = None
    backend_thread: threading.Thread | None = None
    backend_errors: list[BaseException] = []

    try:
        require_file(agent_path, "deimos-agent.exe")
        require_directory(bottle, "CrossOver bottle")
        require_file(wine, "CrossOver Wine wrapper")
        require_file(wineserver, "CrossOver wineserver")

        manager = deimos_native.AgentManager(
            str(bottle),
            str(wine),
            str(agent_path),
            wineserver_executable=str(wineserver),
            wine_arguments=["--bottle", options.bottle_name],
            wrapper_manages_wine_loader=True,
            component="deimos-app-live-uat",
        )
        agent = manager.start()

        import Deimos as deimos_module

        deimos = deimos_module
        deimos.gui_send_queue = queue.Queue()
        deimos.recv_queue = queue.Queue()

        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "agent": agent,
                    "capabilities": sorted(manager.capabilities()),
                    "bottle": str(bottle),
                    "uat": [
                        "Deimos UI opens natively on macOS",
                        "running Wizard101 clients appear",
                        "telemetry and UI-tree actions work",
                        "window, input, hotkey, and overlay actions work",
                        "account launch and login work",
                        "closing Deimos cleans up the helper agent",
                    ],
                },
                indent=2,
            ),
            flush=True,
        )

        def run_backend() -> None:
            try:
                asyncio.run(deimos.main(manager))
            except BaseException as error:
                backend_errors.append(error)
                traceback.print_exc()

        backend_thread = threading.Thread(
            target=run_backend,
            name="deimos-live-uat-backend",
            daemon=True,
        )
        backend_thread.start()

        deimos.deimosgui.manage_gui(
            deimos.recv_queue,
            deimos.gui_send_queue,
            deimos.theme_dict,
            deimos.tool_name,
            deimos.tool_version,
            deimos.gui_on_top,
            deimos.gui_langcode,
            deimos.gui_font,
            deimos.gui_font_size,
            deimos.tool_author,
            settings=deimos.settings,
        )
        backend_thread.join(timeout=35)
        if backend_thread.is_alive():
            raise RuntimeError("the Deimos backend did not stop after the UI closed")
        if backend_errors:
            raise backend_errors[0]
        return 0
    except BaseException as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "success": False,
                    "error": exception_report(error),
                },
                indent=2,
            ),
            flush=True,
        )
        return 1
    finally:
        if deimos is not None:
            try:
                deimos.wizlaunch.clear_runtime()
            except Exception:
                pass
        if manager is not None and not options.keep_agent:
            try:
                manager.stop("Deimos desktop live UAT completed")
            except Exception as error:
                print(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "success": False,
                            "cleanup_error": exception_report(error),
                        },
                        indent=2,
                    ),
                    flush=True,
                )


if __name__ == "__main__":
    raise SystemExit(main())
