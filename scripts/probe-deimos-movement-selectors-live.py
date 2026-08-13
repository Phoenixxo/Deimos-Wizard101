#!/usr/bin/env python3
"""Inspect movement-hook selectors in a live Wizard101 Wine client."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import deimos_native


TARGET_PROCESS = "WizardGraphicalClient.exe"
REQUIRED_CAPABILITIES = {
    "agent.lifecycle.v1",
    "memory.read_only.v1",
    "process.read_only.v1",
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


@dataclass(frozen=True)
class Selector:
    name: str
    signature: str


SELECTORS = (
    Selector(
        "core.client",
        "18 48 ?? ?? ?? ?? ?? ?? 48 8B 7C 24 ?? 48 85 FF 74 29 8B C6 F0 0F C1 47 08 83 F8 01 75 1D 48 8B 07 48 8B CF FF 50 08 F0 0F C1 77 0C",
    ),
    Selector(
        "core.player",
        "F2 0F 10 40 58 F2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    ),
    Selector(
        "core.quest",
        "F3 41 0F 10 ?? FC 0C 00 00 F3 0F 11 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    ),
    Selector(
        "core.player_stat",
        "0F 5B C0 F3 0F 59 81 3C 03 00 00 E8 ?? ?? ?? ?? 2B D8 B8 ?? ?? ?? ?? 0F 49 C3 48 83 C4 20 5B C3",
    ),
    Selector(
        "core.root_window",
        "49 8B 8D D8 00 00 00 48 8B 01 ?? ?? ?? ?? ?? ?? ?? FF 50 70 84 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    ),
    Selector(
        "core.render_context",
        "F3 44 0F 10 8B 98 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? F3 41 0F 10 28 F3 0F 10 56 04 48 63 C1 ??",
    ),
    Selector(
        "movement_entry",
        "48 89 5C 24 08 57 48 83 EC 20 48 8B 99 B8 01 00 00 48 85 DB 74 2F",
    ),
    Selector("movement_state", "8B 5F 70 F3"),
    Selector(
        "collision_dispatch",
        "74 24 F3 0F 10 44 24 58 F3 0F 11 44 24 78 48 8B 06",
    ),
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan the live Wizard101 module for each core and movement-hook "
            "selector and print bounded read-only diagnostics."
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
    parser.add_argument("--bottle-name", default="wizard101")
    parser.add_argument("--target", default=TARGET_PROCESS)
    parser.add_argument(
        "--pid",
        type=int,
        help="Probe a specific matching process when more than one client is open",
    )
    parser.add_argument(
        "--context-before",
        type=int,
        default=16,
        help="Bytes to include before each match",
    )
    parser.add_argument(
        "--context-bytes",
        type=int,
        default=64,
        help="Maximum bytes to include in each context window",
    )
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed agent running after the probe",
    )
    parser.add_argument(
        "--mutation-session",
        action="store_true",
        help=(
            "Open the process with mutation permissions while still performing "
            "only scans and reads"
        ),
    )
    options = parser.parse_args()
    if options.context_before < 0:
        parser.error("--context-before cannot be negative")
    if options.context_bytes < 1:
        parser.error("--context-bytes must be at least 1")
    return options


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


def parse_address(value: str | int) -> int:
    return int(value, 0) if isinstance(value, str) else value


def bounded_window(
    manager: deimos_native.AgentManager,
    session_id: str,
    address: int,
    module_base: int,
    module_size: int,
    context_before: int,
    context_bytes: int,
) -> dict[str, Any]:
    module_end = module_base + module_size
    start = max(module_base, address - context_before)
    size = min(context_bytes, max(0, module_end - start))
    if size == 0:
        return {
            "start": hex(start),
            "size": 0,
            "match_offset": address - start,
            "bytes": "",
        }
    data = bytes(manager.read_memory(session_id, hex(start), size))
    return {
        "start": hex(start),
        "size": len(data),
        "match_offset": address - start,
        "bytes": data.hex(" "),
    }


def movement_action_windows(
    manager: deimos_native.AgentManager,
    session_id: str,
    match_address: int,
    module_base: int,
    module_size: int,
) -> list[dict[str, Any]]:
    actions = []
    module_end = module_base + module_size
    for name, offset in (("first_action", 15), ("second_action", 24)):
        address = match_address + offset
        if address < module_base or address + 8 > module_end:
            actions.append(
                {
                    "name": name,
                    "address": hex(address),
                    "rva": hex(address - module_base),
                    "error": {
                        "type": "ProbeBoundsError",
                        "message": "derived action window is outside the selected module",
                    },
                }
            )
            continue
        try:
            data = bytes(manager.read_memory(session_id, hex(address), 8))
            actions.append(
                {
                    "name": name,
                    "address": hex(address),
                    "rva": hex(address - module_base),
                    "bytes": data.hex(" "),
                }
            )
        except Exception as error:
            actions.append(
                {
                    "name": name,
                    "address": hex(address),
                    "rva": hex(address - module_base),
                    "error": exception_report(error),
                }
            )
    return actions


def probe_selector(
    manager: deimos_native.AgentManager,
    session_id: str,
    target: str,
    selector: Selector,
    module_base: int,
    module_size: int,
    context_before: int,
    context_bytes: int,
) -> dict[str, Any]:
    response = manager.scan_memory(
        session_id,
        selector.signature,
        module_name=target,
        required=False,
        unique=False,
        max_matches=64,
    )
    matches = [parse_address(value) for value in response["matches"]]
    if not matches:
        status = "missing"
    elif len(matches) == 1:
        status = "unique"
    else:
        status = "ambiguous"
    candidates = []
    for address in matches:
        candidate: dict[str, Any] = {
            "address": hex(address),
            "rva": hex(address - module_base),
        }
        try:
            candidate["context"] = bounded_window(
                manager,
                session_id,
                address,
                module_base,
                module_size,
                context_before,
                context_bytes,
            )
        except Exception as error:
            candidate["context_error"] = exception_report(error)
        if selector.name == "movement_state":
            candidate["derived_actions"] = movement_action_windows(
                manager,
                session_id,
                address,
                module_base,
                module_size,
            )
        candidates.append(candidate)
    return {
        "name": selector.name,
        "signature": selector.signature,
        "status": status,
        "match_count": len(matches),
        "scan": {
            "scanned_regions": response["scanned_regions"],
            "skipped_regions": response["skipped_regions"],
            "errors": response["errors"],
        },
        "candidates": candidates,
    }


def select_process(
    processes: list[dict[str, Any]], requested_pid: int | None
) -> dict[str, Any]:
    if requested_pid is not None:
        process = next(
            (candidate for candidate in processes if candidate["pid"] == requested_pid),
            None,
        )
        if process is None:
            raise RuntimeError(
                f"PID {requested_pid} is not a matching Wizard101 process"
            )
        return process
    return min(processes, key=lambda candidate: candidate["pid"])


def main() -> int:
    options = arguments()
    manager: deimos_native.AgentManager | None = None
    session_id: str | None = None
    exit_code = 0
    report: dict[str, Any] = {
        "schema_version": 1,
        "target_process": options.target,
        "capture_completed": False,
        "read_only": True,
        "operations_read_only": True,
        "session_access_mode": (
            "mutation" if options.mutation_session else "read_only"
        ),
    }

    try:
        manager = deimos_native.AgentManager(
            str(options.bottle),
            str(options.cx_root / "bin" / "wine"),
            options.agent,
            wineserver_executable=str(options.cx_root / "bin" / "wineserver"),
            wine_arguments=["--bottle", options.bottle_name],
            wrapper_manages_wine_loader=True,
            component="movement-selector-live-probe",
        )
        report["agent"] = manager.start()
        capabilities = set(manager.capabilities())
        report["capabilities"] = sorted(capabilities)
        missing_capabilities = REQUIRED_CAPABILITIES - capabilities
        if missing_capabilities:
            raise RuntimeError(
                "agent did not negotiate required capabilities: "
                f"{sorted(missing_capabilities)}"
            )

        processes = manager.list_processes([options.target])["processes"]
        if not processes:
            raise RuntimeError(f"{options.target} was not found in the selected bottle")
        process = select_process(processes, options.pid)
        report["process_candidates"] = [
            {
                "pid": candidate["pid"],
                "name": candidate["name"],
                "executable_path": candidate.get("executable_path"),
            }
            for candidate in processes
        ]
        report["selected_process"] = {
            "pid": process["pid"],
            "name": process["name"],
            "executable_path": process.get("executable_path"),
        }

        identity = process.get("identity")
        open_process = (
            manager.open_hook_process
            if options.mutation_session
            else manager.open_process
        )
        session = open_process(
            process["pid"],
            expected_identity_json=(
                json.dumps(identity) if identity is not None else None
            ),
        )
        session_id = session["session_id"]

        modules = manager.list_modules(session_id)["modules"]
        module = next(
            (
                candidate
                for candidate in modules
                if candidate["name"].casefold() == options.target.casefold()
            ),
            None,
        )
        if module is None:
            raise RuntimeError(f"{options.target} main module was not found")
        module_base = parse_address(module["base_address"])
        module_size = int(module["size"])
        report["module"] = module

        selector_results = [
            probe_selector(
                manager,
                session_id,
                options.target,
                selector,
                module_base,
                module_size,
                options.context_before,
                options.context_bytes,
            )
            for selector in SELECTORS
        ]
        report["selectors"] = selector_results
        report["capture_completed"] = True
        report["acceptance"] = {
            "selectors_unique": all(
                selector["status"] == "unique" for selector in selector_results
            )
        }
        if not report["acceptance"]["selectors_unique"]:
            exit_code = 2
    except Exception as error:
        report["error"] = exception_report(error)
        exit_code = 1
    finally:
        cleanup_errors: list[dict[str, Any]] = []
        if manager is not None and session_id is not None:
            try:
                manager.close_process(session_id)
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "process.close", **exception_report(error)}
                )
        if manager is not None and not options.keep_agent:
            try:
                manager.stop("movement selector live probe completed")
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "agent.stop", **exception_report(error)}
                )
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            exit_code = 1

    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
