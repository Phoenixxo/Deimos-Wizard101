#!/usr/bin/env python3
"""Capture read-only Wizard101 telemetry through a managed Wine agent."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import deimos_native
from wizwalker import ClientHandler


REQUIRED_CAPABILITIES = {
    "agent.lifecycle.v1",
    "client.discovery.v1",
    "memory.read_only.v1",
    "process.read_only.v1",
}
DEFAULT_REQUIRED_FIELDS = {
    "character_identity",
    "zone",
    "position",
    "orientation",
    "health",
    "mana",
    "energy",
    "combat",
}


def environment_entry(value: str) -> tuple[str, str]:
    name, separator, entry_value = value.partition("=")
    if not separator or not name:
        raise argparse.ArgumentTypeError("environment entries must use NAME=VALUE")
    return name, entry_value


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Start the managed Wine agent, discover Wizard101 clients, and "
            "capture hook-free telemetry with field-level validation."
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
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="Number of snapshots to capture from every discovered client",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between snapshots",
    )
    parser.add_argument(
        "--require-field",
        action="append",
        default=None,
        help=(
            "Field that must be available for acceptance; repeat as needed. "
            "Defaults to the hook-free telemetry fields."
        ),
    )
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed agent running after the capture",
    )
    options = parser.parse_args()
    if options.samples < 1:
        parser.error("--samples must be at least 1")
    if options.interval < 0:
        parser.error("--interval must not be negative")
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


async def capture(options: argparse.Namespace) -> tuple[dict[str, Any], int]:
    manager: deimos_native.AgentManager | None = None
    handler: ClientHandler | None = None
    exit_code = 0
    required_fields = set(options.require_field or DEFAULT_REQUIRED_FIELDS)
    report: dict[str, Any] = {
        "schema_version": 1,
        "capture_completed": False,
        "required_fields": sorted(required_fields),
        "acceptance": {
            "scope": "required_fields",
            "passed": False,
            "full_snapshot_parity": False,
        },
        "samples": [],
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
            component="deimos-telemetry-live-acceptance",
        )
        report["agent"] = manager.start()
        capabilities = set(manager.capabilities())
        report["capabilities"] = sorted(capabilities)
        missing_capabilities = REQUIRED_CAPABILITIES - capabilities
        if missing_capabilities:
            raise RuntimeError(
                "The helper agent is missing required capabilities: "
                f"{sorted(missing_capabilities)}"
            )

        handler = ClientHandler(agent_manager=manager)
        clients = handler.get_new_clients()
        if not clients:
            raise RuntimeError(
                "No Wizard101 clients were discovered in the selected Wine bottle."
            )

        for sample_index in range(options.samples):
            handler.get_new_clients()
            closed = handler.remove_dead_clients()
            active_clients = handler.get_ordered_clients()
            if not active_clients:
                raise RuntimeError(
                    "All discovered Wizard101 clients closed during telemetry capture."
                )

            snapshots = await asyncio.gather(
                *(
                    client.telemetry_snapshot()
                    for client in active_clients
                )
            )
            report["samples"].append(
                {
                    "index": sample_index,
                    "closed_client_ids": [
                        client.client_id for client in closed
                    ],
                    "clients": [
                        snapshot.to_dict() for snapshot in snapshots
                    ],
                }
            )
            if sample_index + 1 < options.samples and options.interval:
                await asyncio.sleep(options.interval)

        unavailable_required_fields: list[dict[str, Any]] = []
        for sample in report["samples"]:
            for client in sample["clients"]:
                for field_name in required_fields:
                    field = client["fields"].get(field_name)
                    if not isinstance(field, dict) or not field.get("available"):
                        unavailable_required_fields.append(
                            {
                                "sample": sample["index"],
                                "client_id": client["client_id"],
                                "field": field_name,
                                "error": (
                                    field.get("error")
                                    if isinstance(field, dict)
                                    else {
                                        "code": "missing_field",
                                        "message": (
                                            "The telemetry snapshot did not include "
                                            f"{field_name}."
                                        ),
                                    }
                                ),
                            }
                        )

        report["capture_completed"] = True
        report["validation"] = {
            "validated_fields": sorted(required_fields),
            "unavailable_required_fields": unavailable_required_fields,
        }
        report["acceptance"]["passed"] = not unavailable_required_fields
        report["acceptance"]["full_snapshot_parity"] = all(
            client["complete"]
            for sample in report["samples"]
            for client in sample["clients"]
        )
        if unavailable_required_fields:
            exit_code = 1
    except Exception as error:
        report["error"] = exception_report(error)
        exit_code = 1
    finally:
        cleanup_errors: list[dict[str, Any]] = []
        if handler is not None:
            try:
                await handler.close()
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "client.sessions.close", **exception_report(error)}
                )
        if manager is not None and not options.keep_agent:
            try:
                manager.stop("Live read-only telemetry capture completed")
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "agent.stop", **exception_report(error)}
                )
        if cleanup_errors:
            report["acceptance"]["passed"] = False
            report["cleanup_errors"] = cleanup_errors
            exit_code = 1

    return report, exit_code


def main() -> int:
    report, exit_code = asyncio.run(capture(arguments()))
    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
