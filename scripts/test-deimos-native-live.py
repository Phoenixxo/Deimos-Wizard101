#!/usr/bin/env python3
"""Run the DMS-010 read-only Python acceptance check against a Wine bottle."""

from __future__ import annotations

import argparse
import json
import struct
from typing import Any

import deimos_native


TARGET_PROCESS = "WizardGraphicalClient.exe"
REQUIRED_CAPABILITIES = {
    "agent.lifecycle.v1",
    "process.read_only.v1",
    "memory.read_only.v1",
}


def environment_entry(value: str) -> tuple[str, str]:
    name, separator, entry_value = value.partition("=")
    if not separator or not name:
        raise argparse.ArgumentTypeError("environment entries must use NAME=VALUE")
    return name, entry_value


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Start the managed Wine agent through deimos_native and repeat the "
            "live Wizard101 PE-header read from native Python."
        )
    )
    parser.add_argument("--bottle", required=True, help="Canonical Wine bottle path")
    parser.add_argument("--wine", required=True, help="Wine loader or wrapper executable")
    parser.add_argument("--agent", required=True, help="Matching deimos-agent.exe artifact")
    parser.add_argument("--wineserver", help="Optional matching wineserver executable")
    parser.add_argument(
        "--wine-arg",
        action="append",
        default=[],
        help="Ordered argument inserted before deimos-agent.exe; repeat as needed",
    )
    parser.add_argument(
        "--wrapper-manages-wine-loader",
        action="store_true",
        help="Do not override WINELOADER; use when the selected wrapper configures it",
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        type=environment_entry,
        metavar="NAME=VALUE",
        help="Additional runtime environment entry; repeat as needed",
    )
    parser.add_argument("--target", default=TARGET_PROCESS)
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed agent running after the check",
    )
    return parser.parse_args()


def validate_pe_header(data: bytes) -> dict[str, Any]:
    if len(data) < 64 or data[:2] != b"MZ":
        raise RuntimeError("memory read did not begin with an MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 6 > len(data):
        raise RuntimeError(
            f"PE header offset 0x{pe_offset:x} is outside the {len(data)}-byte read"
        )
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise RuntimeError("memory read did not contain a valid PE signature")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    return {
        "dos_signature": "MZ",
        "pe_signature": "PE\\0\\0",
        "pe_offset": f"0x{pe_offset:x}",
        "machine_code": f"0x{machine:04x}",
    }


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


def main() -> int:
    options = arguments()
    manager: deimos_native.AgentManager | None = None
    session_id: str | None = None
    exit_code = 0
    report: dict[str, Any] = {
        "schema_version": 1,
        "target_process": options.target,
        "success": False,
    }
    try:
        manager = deimos_native.AgentManager(
            options.bottle,
            options.wine,
            options.agent,
            wineserver_executable=options.wineserver,
            wine_arguments=options.wine_arg,
            environment=dict(options.env),
            wrapper_manages_wine_loader=options.wrapper_manages_wine_loader,
            component="dms-010-live-acceptance",
        )
        report["agent"] = manager.start()
        capabilities = set(manager.capabilities())
        report["capabilities"] = sorted(capabilities)
        missing = REQUIRED_CAPABILITIES - capabilities
        if missing:
            raise RuntimeError(
                f"agent did not negotiate required capabilities: {sorted(missing)}"
            )

        candidates = manager.list_processes([options.target])["processes"]
        if not candidates:
            raise RuntimeError(f"{options.target} was not found in the selected bottle")
        process = candidates[0]
        identity = process.get("identity")
        session = manager.open_process(
            process["pid"],
            expected_identity_json=json.dumps(identity) if identity is not None else None,
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

        header = manager.read_memory(session_id, module["base_address"], 4096)
        report.update(
            {
                "success": True,
                "process": {
                    "pid": process["pid"],
                    "name": process["name"],
                    "executable_path": process.get("executable_path"),
                },
                "module": module,
                "bytes_read": len(header),
                "pe": validate_pe_header(header),
                "diagnostics": manager.status(),
            }
        )
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
                manager.stop("DMS-010 live Python acceptance completed")
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
