#!/usr/bin/env python3
"""Exercise portable wizlaunch routing against a live Wine/CrossOver bottle."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import deimos_native
import wizlaunch
from wizwalker.generation import manager_generation_context


REQUIRED_CAPABILITIES = {
    "client.discovery.v1",
    "game.process.v1",
}
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
DEFAULT_GAME_PATH = r"C:\ProgramData\KingsIsle Entertainment\Wizard101"
INVALID_GAME_PATH = r"C:\Deimos-UAT-Missing-Wizard101"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate single and multiple Wizard101 launches, opaque client IDs, "
            "failure reporting, and selective termination through a selected bottle."
        )
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
        "--game-path",
        default=DEFAULT_GAME_PATH,
        help="Windows path containing the Wizard101 Bin directory",
    )
    parser.add_argument(
        "--login-server",
        default=wizlaunch.DEFAULT_LOGIN_SERVER,
        help="Wizard101 login endpoint in host:port form",
    )
    parser.add_argument(
        "--timeout-secs",
        type=int,
        default=60,
        help="Maximum time to wait for each confirmed game window",
    )
    parser.add_argument(
        "--visual-wait-secs",
        type=float,
        default=2.0,
        help="Pause after each launch so its window can be observed",
    )
    parser.add_argument(
        "--keep-clients",
        action="store_true",
        help="Leave the final multi-launch clients running after validation",
    )
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed helper agent running after validation",
    )
    return parser.parse_args()


def exception_report(error: BaseException) -> dict[str, Any]:
    return {
        "type": type(error).__name__,
        "message": str(error),
        "technical_message": getattr(error, "technical_message", None),
        "code": getattr(error, "code", None),
        "operation": getattr(error, "operation", None),
        "native_context": getattr(error, "native_context", None),
        "details": getattr(error, "details", None),
    }


def client_ids() -> list[str]:
    identities = wizlaunch.get_wizard_handles()
    if not all(isinstance(identity, str) and identity for identity in identities):
        raise RuntimeError(
            "the portable wizlaunch route exposed a non-opaque client identity"
        )
    return identities


def require_present(expected: set[str], actual: set[str], phase: str) -> None:
    missing = expected - actual
    if missing:
        raise RuntimeError(
            f"{phase} could not rediscover launched clients: {sorted(missing)}"
        )


def terminate_and_confirm(client_id: str) -> dict[str, Any]:
    terminated = wizlaunch.kill_instance(client_id)
    remaining = set(client_ids())
    if not terminated or client_id in remaining:
        raise RuntimeError(
            f"client {client_id!r} remained discoverable after termination"
        )
    return {
        "client_id": client_id,
        "terminated": terminated,
        "remaining_client_ids": sorted(remaining),
    }


def main() -> int:
    options = arguments()
    if options.timeout_secs <= 0:
        raise SystemExit("--timeout-secs must be greater than zero")
    if options.visual_wait_secs < 0:
        raise SystemExit("--visual-wait-secs cannot be negative")

    manager: deimos_native.AgentManager | None = None
    launched_ids: set[str] = set()
    exit_code = 0
    report: dict[str, Any] = {
        "schema_version": 1,
        "success": False,
        "bottle": str(options.bottle),
        "game_path": options.game_path,
        "login_expected": False,
    }

    try:
        manager = deimos_native.AgentManager(
            str(options.bottle),
            str(options.cx_root / "bin" / "wine"),
            options.agent,
            wineserver_executable=str(options.cx_root / "bin" / "wineserver"),
            wine_arguments=["--bottle", options.bottle_name],
            wrapper_manages_wine_loader=True,
            component="game-launch-live-uat",
        )
        report["agent"] = manager.start()
        capabilities = set(manager.capabilities())
        report["capabilities"] = sorted(capabilities)
        missing_capabilities = REQUIRED_CAPABILITIES - capabilities
        if missing_capabilities:
            raise RuntimeError(
                "the agent is missing required capabilities: "
                f"{sorted(missing_capabilities)}"
            )

        instance_id = report["agent"]["identity"]["instance_id"]
        wizlaunch.configure_runtime(
            manager,
            generation_context=manager_generation_context(manager, instance_id),
        )
        baseline = set(client_ids())
        report["baseline_client_ids"] = sorted(baseline)

        try:
            wizlaunch.launch_instance(
                "uat-invalid-path",
                INVALID_GAME_PATH,
                options.login_server,
                options.timeout_secs,
            )
        except Exception as error:
            invalid_path = exception_report(error)
            if invalid_path["code"] != "game_launch_failed":
                raise RuntimeError(
                    "the invalid-path launch did not return game_launch_failed"
                ) from error
            report["invalid_path"] = invalid_path
        else:
            raise RuntimeError("the invalid-path launch unexpectedly succeeded")

        single_id = wizlaunch.launch_instance(
            "uat-single",
            options.game_path,
            options.login_server,
            options.timeout_secs,
        )
        if not isinstance(single_id, str) or not single_id:
            raise RuntimeError("single launch did not return an opaque client ID")
        launched_ids.add(single_id)
        time.sleep(options.visual_wait_secs)
        require_present({single_id}, set(client_ids()), "single launch")
        report["single_launch"] = {
            "client_id": single_id,
            "opaque_identity": True,
            "window_confirmed": True,
        }
        report["single_termination"] = terminate_and_confirm(single_id)
        launched_ids.remove(single_id)

        multi = wizlaunch.launch_instances(
            ["uat-multi-1", "uat-multi-2"],
            options.game_path,
            options.login_server,
            options.timeout_secs,
        )
        multi_ids = list(multi.values())
        launched_ids.update(
            client_id
            for client_id in multi_ids
            if isinstance(client_id, str) and client_id
        )
        if set(multi) != {"uat-multi-1", "uat-multi-2"}:
            raise RuntimeError(
                "multi-launch did not return both requested clients; "
                f"received {sorted(multi)}"
            )
        if not all(isinstance(client_id, str) and client_id for client_id in multi_ids):
            raise RuntimeError("multi-launch returned a non-opaque client identity")
        if len(set(multi_ids)) != len(multi_ids):
            raise RuntimeError("multi-launch reused one client identity")
        time.sleep(options.visual_wait_secs)
        require_present(set(multi_ids), set(client_ids()), "multi-launch")
        report["multi_launch"] = {
            "clients": multi,
            "distinct_client_ids": True,
            "windows_confirmed": True,
        }

        selected_id = multi_ids[0]
        survivor_id = multi_ids[1]
        selective = terminate_and_confirm(selected_id)
        launched_ids.remove(selected_id)
        if survivor_id not in selective["remaining_client_ids"]:
            raise RuntimeError(
                "terminating one multi-launch client also removed the other client"
            )
        report["selective_termination"] = {
            **selective,
            "survivor_client_id": survivor_id,
            "survivor_confirmed": True,
        }

        report["success"] = True
    except Exception as error:
        report["error"] = exception_report(error)
        exit_code = 1
    finally:
        cleanup_errors: list[dict[str, Any]] = []
        if manager is not None and not options.keep_clients:
            for client_id in sorted(launched_ids):
                try:
                    if not wizlaunch.kill_instance(client_id):
                        raise RuntimeError("the agent did not confirm termination")
                except Exception as error:
                    cleanup_errors.append(
                        {
                            "operation": "game.terminate",
                            "client_id": client_id,
                            **exception_report(error),
                        }
                    )
        if manager is not None:
            wizlaunch.clear_runtime()
            if not options.keep_agent:
                try:
                    manager.stop("game launch live UAT completed")
                except Exception as error:
                    cleanup_errors.append(
                        {"operation": "agent.stop", **exception_report(error)}
                    )
        if cleanup_errors:
            report["success"] = False
            report["cleanup_errors"] = cleanup_errors
            exit_code = 1
        report["kept_client_ids"] = (
            sorted(launched_ids) if options.keep_clients else []
        )

    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
