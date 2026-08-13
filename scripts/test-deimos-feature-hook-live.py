#!/usr/bin/env python3
"""Exercise one feature-hook lifecycle against a live Wizard101 Wine client."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import deimos_native


TARGET_PROCESS = "WizardGraphicalClient.exe"
FEATURE_HOOK = "chat"
FEATURE_EXPORT = "recv_counter"
REQUIRED_CAPABILITY = "memory.feature_hook.v1"
CHAT_PATTERN = (
    "48 89 5C 24 18 48 89 74 24 20 55 57 41 56 "
    "48 8D AC 24 40 FF FF FF 48 81 EC C0 01 00 00 "
    "48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 B0 00 00 00 "
    "48 8B FA 48 8B F1 45 33 F6"
)
CHAT_MARKER_OFFSET = 0x7E
CHAT_MARKER = bytes.fromhex("C7 45 F0 09 00 00 00")
CHAT_HOOK_OFFSET = 0x379
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
        description=(
            "Activate, inspect, heartbeat, and deactivate the live Wizard101 "
            "chat feature hook through the managed Wine agent."
        )
    )
    parser.add_argument("--agent", required=True, help="Matching deimos-agent.exe")
    parser.add_argument(
        "--cx-root",
        type=Path,
        default=DEFAULT_CX_ROOT,
        help="Wizard101 CrossOver runtime root",
    )
    parser.add_argument(
        "--bottle",
        type=Path,
        default=DEFAULT_BOTTLE,
        help="Wizard101 bottle path",
    )
    parser.add_argument("--target", default=TARGET_PROCESS)
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed agent running after the check",
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


def chat_selector_diagnostics(
    manager: deimos_native.AgentManager,
    session_id: str,
    target: str,
) -> dict[str, Any]:
    modules = manager.list_modules(session_id)["modules"]
    module = next(
        candidate
        for candidate in modules
        if candidate["name"].casefold() == target.casefold()
    )
    module_base = int(module["base_address"], 0)
    matches = manager.scan_memory(
        session_id,
        CHAT_PATTERN,
        module_name=target,
        required=True,
        unique=False,
        max_matches=64,
    )["matches"]
    candidates = []
    for match in matches:
        address = int(match, 0)
        marker = bytes(
            manager.read_memory(
                session_id,
                hex(address + CHAT_MARKER_OFFSET),
                len(CHAT_MARKER),
            )
        )
        hook_window = bytes(
            manager.read_memory(
                session_id,
                hex(address + CHAT_HOOK_OFFSET - 16),
                48,
            )
        )
        candidates.append(
            {
                "address": hex(address),
                "rva": hex(address - module_base),
                "marker_matches": marker == CHAT_MARKER,
                "marker": marker.hex(" "),
                "hook_window_start": hex(address + CHAT_HOOK_OFFSET - 16),
                "hook_window": hook_window.hex(" "),
            }
        )
    return {
        "module_base": hex(module_base),
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def main() -> int:
    options = arguments()
    manager: deimos_native.AgentManager | None = None
    session_id: str | None = None
    hook_cleanup_required = False
    exit_code = 0
    report: dict[str, Any] = {
        "schema_version": 1,
        "target_process": options.target,
        "feature_hook": FEATURE_HOOK,
        "success": False,
    }

    try:
        manager = deimos_native.AgentManager(
            str(options.bottle),
            str(options.cx_root / "bin" / "wine"),
            options.agent,
            wineserver_executable=str(options.cx_root / "bin" / "wineserver"),
            wine_arguments=["--bottle", "wizard101"],
            wrapper_manages_wine_loader=True,
            component="dms-017-live-uat",
        )
        report["agent"] = manager.start()

        capabilities = sorted(manager.capabilities())
        report["capabilities"] = capabilities
        if REQUIRED_CAPABILITY not in capabilities:
            raise RuntimeError(
                f"the agent did not negotiate {REQUIRED_CAPABILITY}"
            )

        processes = manager.list_processes([options.target])["processes"]
        if not processes:
            raise RuntimeError(f"{options.target} was not found in the selected bottle")

        process = processes[0]
        identity = process.get("identity")
        session = manager.open_hook_process(
            process["pid"],
            expected_identity_json=(
                json.dumps(identity) if identity is not None else None
            ),
        )
        session_id = session["session_id"]
        report["process"] = {
            "pid": process["pid"],
            "name": process["name"],
            "executable_path": process.get("executable_path"),
        }

        hook_cleanup_required = True
        activation = manager.activate_feature_hook(session_id, FEATURE_HOOK)
        export_address = manager.read_feature_hook_export(
            session_id, FEATURE_EXPORT
        )
        heartbeat = manager.heartbeat_feature_hooks(session_id)
        deactivation = manager.deactivate_feature_hook(session_id, FEATURE_HOOK)
        hook_cleanup_required = False

        report.update(
            {
                "success": True,
                "activation": activation,
                "export": {
                    "name": FEATURE_EXPORT,
                    "address": hex(export_address),
                },
                "heartbeat": heartbeat,
                "deactivation": deactivation,
            }
        )
    except Exception as error:
        report["error"] = exception_report(error)
        if (
            manager is not None
            and session_id is not None
            and getattr(error, "code", None) == "memory_ambiguous_match"
        ):
            try:
                report["selector_diagnostics"] = chat_selector_diagnostics(
                    manager, session_id, options.target
                )
            except Exception as diagnostic_error:
                report["selector_diagnostic_error"] = exception_report(
                    diagnostic_error
                )
        exit_code = 1
    finally:
        cleanup_errors: list[dict[str, Any]] = []
        if manager is not None and session_id is not None:
            if hook_cleanup_required:
                try:
                    manager.deactivate_feature_hook(session_id, FEATURE_HOOK)
                except Exception as error:
                    cleanup_errors.append(
                        {"operation": "feature_hook.deactivate", **exception_report(error)}
                    )
            try:
                manager.close_process(session_id)
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "process.close", **exception_report(error)}
                )
        if manager is not None and not options.keep_agent:
            try:
                manager.stop("Live feature-hook UAT completed")
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "agent.stop", **exception_report(error)}
                )
        if cleanup_errors:
            report["success"] = False
            report["cleanup_errors"] = cleanup_errors
            exit_code = 1

    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
