#!/usr/bin/env python3
"""Certify core-hook selectors and exports against a live Wine client."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import re
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import deimos_native

from wizwalker.memory import DeimosNativeMemoryBackend, MemoryReader
from wizwalker.telemetry import _TelemetryReadContext


TARGET_PROCESS = "WizardGraphicalClient.exe"
REQUIRED_CAPABILITIES = {
    "agent.lifecycle.v1",
    "memory.core_hook.v1",
    "memory.hook.v1",
    "memory.mutation.v1",
    "memory.read_only.v1",
    "process.mutation.v1",
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
DEFAULT_OUTPUT_DIRECTORY = Path.home() / "Library" / "Logs" / "Deimos"
CONTEXT_BEFORE = 16
CONTEXT_BYTES = 64
TARGET_COMPARE_BYTES = 32


@dataclass(frozen=True)
class CoreHookSpec:
    name: str
    signature: str
    target_offset: int = 0
    reference_resolver: str | None = None
    required_alignment: int = 8


CORE_HOOKS = (
    CoreHookSpec(
        "client",
        "18 48 ?? ?? ?? ?? ?? ?? 48 8B 7C 24 ?? 48 85 FF 74 29 8B C6 F0 0F C1 47 08 83 F8 01 75 1D 48 8B 07 48 8B CF FF 50 08 F0 0F C1 77 0C",
        target_offset=1,
        reference_resolver="root_client_object",
    ),
    CoreHookSpec(
        "player",
        "F2 0F 10 40 58 F2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
        reference_resolver="actor_body",
    ),
    CoreHookSpec(
        "quest",
        "F3 41 0F 10 ?? FC 0C 00 00 F3 0F 11 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
        required_alignment=4,
    ),
    CoreHookSpec(
        "player_stat",
        "0F 5B C0 F3 0F 59 81 3C 03 00 00 E8 ?? ?? ?? ?? 2B D8 B8 ?? ?? ?? ?? 0F 49 C3 48 83 C4 20 5B C3",
        target_offset=3,
        reference_resolver="game_stats",
    ),
    CoreHookSpec(
        "root_window",
        "49 8B 8D D8 00 00 00 48 8B 01 ?? ?? ?? ?? ?? ?? ?? FF 50 70 84 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    ),
    CoreHookSpec(
        "render_context",
        "F3 44 0F 10 8B 98 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? F3 41 0F 10 28 F3 0F 10 56 04 48 63 C1 ??",
    ),
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Activate each core hook independently, validate its selector and "
            "exported pointer, compare independently resolvable objects, and "
            "verify exact target-byte restoration."
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
        help="Certify a specific matching process when multiple clients are open",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=10,
        help="Samples captured for each independently activated hook",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.25,
        help="Seconds between export samples",
    )
    parser.add_argument(
        "--ready-timeout",
        type=float,
        default=5.0,
        help="Seconds allowed for each hook to publish its first nonzero export",
    )
    parser.add_argument(
        "--cleanup-timeout",
        type=float,
        default=5.0,
        help="Seconds allowed for safe hook cleanup retries",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="JSON report path; defaults to the Deimos log directory",
    )
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed helper agent running after certification",
    )
    options = parser.parse_args()
    if options.samples < 1:
        parser.error("--samples must be at least 1")
    if options.interval < 0:
        parser.error("--interval cannot be negative")
    if options.ready_timeout <= 0:
        parser.error("--ready-timeout must be positive")
    if options.cleanup_timeout <= 0:
        parser.error("--cleanup-timeout must be positive")
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
    return int(value, 0) if isinstance(value, str) else int(value)


def select_process(
    processes: list[dict[str, Any]], requested_pid: int | None
) -> dict[str, Any]:
    if requested_pid is not None:
        selected = next(
            (process for process in processes if process["pid"] == requested_pid),
            None,
        )
        if selected is None:
            raise RuntimeError(
                f"PID {requested_pid} is not a matching Wizard101 process"
            )
        return selected
    if len(processes) != 1:
        raise RuntimeError(
            "Address certification requires exactly one Wizard101 client. "
            "Close the others or select one with --pid."
        )
    return processes[0]


def host_executable_path(bottle: Path, windows_path: str) -> Path | None:
    match = re.fullmatch(r"([A-Za-z]):[\\/](.*)", windows_path)
    if match is None:
        return None
    drive, remainder = match.groups()
    parts = [part for part in re.split(r"[\\/]", remainder) if part]
    if drive.casefold() == "c":
        return bottle / "drive_c" / Path(*parts)
    if drive.casefold() == "z":
        return Path("/") / Path(*parts)
    return bottle / f"dosdevices/{drive.casefold()}:" / Path(*parts)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_output_path() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_OUTPUT_DIRECTORY / f"address-certification-{timestamp}.json"


def module_descriptor(
    manager: deimos_native.AgentManager,
    session_id: str,
    target: str,
) -> dict[str, Any]:
    modules = manager.list_modules(session_id)["modules"]
    module = next(
        (
            candidate
            for candidate in modules
            if candidate["name"].casefold() == target.casefold()
        ),
        None,
    )
    if module is None:
        raise RuntimeError(f"{target} main module was not found")
    return module


def scan_selector(
    manager: deimos_native.AgentManager,
    session_id: str,
    target: str,
    module_base: int,
    module_size: int,
    spec: CoreHookSpec,
) -> dict[str, Any]:
    response = manager.scan_memory(
        session_id,
        spec.signature,
        module_name=target,
        required=False,
        unique=False,
        max_matches=64,
    )
    matches = [parse_address(value) for value in response["matches"]]
    candidates = []
    module_end = module_base + module_size
    for match in matches:
        start = max(module_base, match - CONTEXT_BEFORE)
        size = min(CONTEXT_BYTES, max(0, module_end - start))
        candidate: dict[str, Any] = {
            "address": hex(match),
            "rva": hex(match - module_base),
        }
        try:
            context = bytes(manager.read_memory(session_id, hex(start), size))
            candidate["context"] = {
                "start": hex(start),
                "match_offset": match - start,
                "bytes": context.hex(" "),
            }
        except Exception as error:
            candidate["context_error"] = exception_report(error)
        candidates.append(candidate)
    return {
        "signature": spec.signature,
        "match_count": len(matches),
        "status": "unique" if len(matches) == 1 else "missing" if not matches else "ambiguous",
        "matches": matches,
        "candidates": candidates,
        "scan": {
            "scanned_regions": response["scanned_regions"],
            "skipped_regions": response["skipped_regions"],
            "errors": response["errors"],
        },
    }


def find_region(
    regions: list[dict[str, Any]], address: int, size: int
) -> dict[str, Any] | None:
    end = address + size
    for region in regions:
        base = parse_address(region["base_address"])
        region_end = base + int(region["size"])
        if base <= address and end <= region_end:
            return {
                "base_address": hex(base),
                "size": int(region["size"]),
                "protection": region["protection"],
            }
    return None


def canonical_user_pointer(address: int) -> bool:
    return 0 < address <= 0x0000_7FFF_FFFF_FFFF


def read_value(
    manager: deimos_native.AgentManager,
    session_id: str,
    address: int,
    format_string: str,
) -> Any:
    size = struct.calcsize(format_string)
    data = bytes(manager.read_memory(session_id, hex(address), size))
    values = struct.unpack(format_string, data)
    return values[0] if len(values) == 1 else values


def finite_coordinates(values: tuple[float, ...]) -> bool:
    return all(math.isfinite(value) and abs(value) <= 1_000_000_000 for value in values)


def semantic_probe(
    manager: deimos_native.AgentManager,
    session_id: str,
    hook: str,
    base: int,
) -> dict[str, Any]:
    if hook == "client":
        speed = read_value(manager, session_id, base + 192, "<h")
        scale = read_value(manager, session_id, base + 196, "<f")
        return {
            "speed_multiplier": speed,
            "scale": scale,
            "passed": math.isfinite(scale) and 0 < abs(scale) <= 1_000,
        }
    if hook == "player":
        position = read_value(manager, session_id, base + 88, "<fff")
        orientation = read_value(manager, session_id, base + 100, "<fff")
        return {
            "position": dict(zip(("x", "y", "z"), position)),
            "orientation": dict(zip(("pitch", "roll", "yaw"), orientation)),
            "passed": finite_coordinates(position + orientation),
        }
    if hook == "quest":
        position = read_value(manager, session_id, base, "<fff")
        return {
            "position": dict(zip(("x", "y", "z"), position)),
            "passed": finite_coordinates(position),
        }
    if hook == "player_stat":
        level = read_value(manager, session_id, base + 324, "<i")
        return {"reference_level": level, "passed": 0 <= level <= 1_000}
    if hook == "root_window":
        length = read_value(manager, session_id, base + 96, "<i")
        if not 1 <= length <= 512:
            return {"name_length": length, "passed": False}
        string_base = (
            read_value(manager, session_id, base + 80, "<Q")
            if length >= 16
            else base + 80
        )
        name = bytes(
            manager.read_memory(session_id, hex(string_base), length)
        ).decode("utf-8", errors="replace")
        return {"name": name, "name_length": length, "passed": bool(name)}
    if hook == "render_context":
        ui_scale = read_value(manager, session_id, base + 152, "<f")
        return {
            "ui_scale": ui_scale,
            "passed": math.isfinite(ui_scale) and 0.01 <= abs(ui_scale) <= 100,
        }
    raise ValueError(f"unsupported core hook {hook}")


async def independent_address(
    memory: MemoryReader,
    signature_cache: dict[bytes, int],
    selector_cache: dict[str, tuple[int, int]],
    resolver: str,
) -> int:
    context = _TelemetryReadContext(memory, signature_cache, selector_cache)
    return int(await getattr(context, resolver)())


def wait_for_export(
    manager: deimos_native.AgentManager,
    session_id: str,
    hook: str,
    timeout: float,
) -> int:
    deadline = time.monotonic() + timeout
    while True:
        address = int(manager.read_core_hook_base(session_id, hook))
        if address:
            return address
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"core hook {hook} did not publish a nonzero export within {timeout:g} seconds"
            )
        time.sleep(0.05)


def deactivate_with_retry(
    manager: deimos_native.AgentManager,
    session_id: str,
    hook: str,
    timeout: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    attempts = 0
    failures = []
    while True:
        attempts += 1
        try:
            response = manager.deactivate_core_hook(session_id, hook)
            return {
                "passed": True,
                "attempts": attempts,
                "response": response,
                "retry_failures": failures,
            }
        except Exception as error:
            failures.append(exception_report(error))
            if time.monotonic() >= deadline:
                return {
                    "passed": False,
                    "attempts": attempts,
                    "retry_failures": failures,
                }
            time.sleep(0.05)


def certify_hook(
    manager: deimos_native.AgentManager,
    session_id: str,
    target: str,
    module_base: int,
    module_size: int,
    regions: list[dict[str, Any]],
    memory: MemoryReader,
    signature_cache: dict[bytes, int],
    selector_cache: dict[str, tuple[int, int]],
    spec: CoreHookSpec,
    samples: int,
    interval: float,
    ready_timeout: float,
    cleanup_timeout: float,
) -> tuple[dict[str, Any], bool]:
    result: dict[str, Any] = {"hook": spec.name, "passed": False}
    active = False
    selector = scan_selector(
        manager,
        session_id,
        target,
        module_base,
        module_size,
        spec,
    )
    result["selector"] = {key: value for key, value in selector.items() if key != "matches"}
    if len(selector["matches"]) != 1:
        return result, True

    target_address = selector["matches"][0] + spec.target_offset
    result["target"] = {
        "address": hex(target_address),
        "rva": hex(target_address - module_base),
    }
    try:
        original = bytes(
            manager.read_memory(session_id, hex(target_address), TARGET_COMPARE_BYTES)
        )
        result["target"]["original_bytes"] = original.hex(" ")
        active = True
        activation = manager.activate_core_hook(session_id, spec.name)
        result["activation"] = activation
        patched = bytes(
            manager.read_memory(session_id, hex(target_address), TARGET_COMPARE_BYTES)
        )
        result["target"]["patched_bytes"] = patched.hex(" ")
        result["target"]["bytes_changed"] = patched != original
        if patched == original:
            raise RuntimeError(
                "the agent did not patch the selector target resolved by the certifier"
            )
        wait_for_export(manager, session_id, spec.name, ready_timeout)

        sample_results = []
        for index in range(samples):
            manager.heartbeat_core_hooks(session_id)
            sample: dict[str, Any] = {"index": index, "passed": False}
            try:
                base = int(manager.read_core_hook_base(session_id, spec.name))
                sample["export"] = hex(base)
                if spec.reference_resolver is not None:
                    reference = asyncio.run(
                        independent_address(
                            memory,
                            signature_cache,
                            selector_cache,
                            spec.reference_resolver,
                        )
                    )
                    sample["independent_reference"] = hex(reference)
                    sample["independent_match"] = reference == base
                sample["canonical_user_pointer"] = canonical_user_pointer(base)
                sample["required_alignment"] = spec.required_alignment
                sample["aligned"] = base % spec.required_alignment == 0
                sample["region"] = find_region(regions, base, 8)
                if not sample["canonical_user_pointer"]:
                    raise ValueError(f"export {base:#x} is not a canonical user pointer")
                if not sample["aligned"]:
                    raise ValueError(
                        f"export {base:#x} is not {spec.required_alignment}-byte aligned"
                    )
                if sample["region"] is None:
                    raise ValueError(f"export {base:#x} is outside readable memory")
                sample["prefix"] = bytes(
                    manager.read_memory(session_id, hex(base), 8)
                ).hex(" ")
                if spec.reference_resolver is not None:
                    if reference != base:
                        raise ValueError(
                            f"export {base:#x} does not match independent address {reference:#x}"
                        )
                sample["semantic"] = semantic_probe(
                    manager, session_id, spec.name, base
                )
                if not sample["semantic"]["passed"]:
                    raise ValueError("semantic validation failed")
                sample["passed"] = True
            except Exception as error:
                sample["error"] = exception_report(error)
            sample_results.append(sample)
            if index + 1 < samples and interval:
                time.sleep(interval)
        result["samples"] = sample_results
    except Exception as error:
        result["error"] = exception_report(error)
    finally:
        cleanup_safe = True
        if active:
            cleanup = deactivate_with_retry(
                manager, session_id, spec.name, cleanup_timeout
            )
            result["cleanup"] = cleanup
            cleanup_safe = cleanup["passed"]
            if cleanup_safe:
                try:
                    restored = bytes(
                        manager.read_memory(
                            session_id,
                            hex(target_address),
                            TARGET_COMPARE_BYTES,
                        )
                    )
                    result["cleanup"]["restored_bytes"] = restored.hex(" ")
                    result["cleanup"]["bytes_match"] = restored == original
                    cleanup_safe = restored == original
                except Exception as error:
                    result["cleanup"]["verification_error"] = exception_report(error)
                    cleanup_safe = False

    hook_samples = result.get("samples", [])
    result["passed"] = bool(
        hook_samples
        and all(sample["passed"] for sample in hook_samples)
        and result.get("cleanup", {}).get("passed")
        and result.get("cleanup", {}).get("bytes_match")
    )
    return result, cleanup_safe


def main() -> int:
    options = arguments()
    output_path = options.output or default_output_path()
    manager: deimos_native.AgentManager | None = None
    session_id: str | None = None
    exit_code = 0
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_process": options.target,
        "mutation_scope": "one core hook at a time",
        "capture_completed": False,
        "passed": False,
        "hooks": [],
    }

    try:
        manager = deimos_native.AgentManager(
            str(options.bottle),
            str(options.cx_root / "bin" / "wine"),
            options.agent,
            wineserver_executable=str(options.cx_root / "bin" / "wineserver"),
            wine_arguments=["--bottle", options.bottle_name],
            wrapper_manages_wine_loader=True,
            component="address-certification-live",
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
        identity = process.get("identity") or {}
        expected_identity_json = json.dumps(identity) if identity else None
        session = manager.open_hook_process(
            process["pid"], expected_identity_json=expected_identity_json
        )
        session_id = session["session_id"]

        module = module_descriptor(manager, session_id, options.target)
        module_base = parse_address(module["base_address"])
        module_size = int(module["size"])
        windows_executable = identity.get("executable_path") or process.get(
            "executable_path"
        )
        executable_path = (
            host_executable_path(options.bottle, windows_executable)
            if isinstance(windows_executable, str)
            else None
        )
        if executable_path is None or not executable_path.is_file():
            raise RuntimeError(
                "The selected Wizard101 executable could not be mapped into the bottle. "
                "Certification reports must be bound to an exact executable hash."
            )
        report["process"] = {
            "pid": process["pid"],
            "identity": identity,
            "host_executable_path": str(executable_path),
            "sha256": sha256_file(executable_path),
        }
        report["module"] = module

        regions = manager.memory_regions(session_id)["regions"]
        backend = DeimosNativeMemoryBackend(
            manager, session_id, native_module=deimos_native
        )
        memory = MemoryReader(backend)
        signature_cache: dict[bytes, int] = {}
        selector_cache: dict[str, tuple[int, int]] = {}

        for index, spec in enumerate(CORE_HOOKS, start=1):
            print(
                f"[{index}/{len(CORE_HOOKS)}] Certifying {spec.name} core hook...",
                file=sys.stderr,
                flush=True,
            )
            hook_result, cleanup_safe = certify_hook(
                manager,
                session_id,
                options.target,
                module_base,
                module_size,
                regions,
                memory,
                signature_cache,
                selector_cache,
                spec,
                options.samples,
                options.interval,
                options.ready_timeout,
                options.cleanup_timeout,
            )
            report["hooks"].append(hook_result)
            if not cleanup_safe:
                raise RuntimeError(
                    f"cleanup for {spec.name} could not be verified; remaining hooks were not activated"
                )

        report["capture_completed"] = True
        report["passed"] = all(hook["passed"] for hook in report["hooks"])
        if not report["passed"]:
            exit_code = 2
    except Exception as error:
        report["error"] = exception_report(error)
        exit_code = 1
    finally:
        cleanup_errors = []
        if manager is not None and session_id is not None:
            try:
                manager.deactivate_core_hooks(session_id)
            except Exception as error:
                if getattr(error, "code", None) not in {
                    "invalid_request",
                    "session_not_found",
                }:
                    cleanup_errors.append(
                        {"operation": "core_hooks.deactivate", **exception_report(error)}
                    )
            try:
                manager.close_process(session_id)
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "process.close", **exception_report(error)}
                )
        if manager is not None and not options.keep_agent:
            try:
                manager.stop("Address certification completed")
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "agent.stop", **exception_report(error)}
                )
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            report["passed"] = False
            exit_code = 1

        output_path.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(report, indent=2, sort_keys=True)
        output_path.write_text(f"{rendered}\n", encoding="utf-8")
        print(rendered)
        print(f"Report written to {output_path}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
