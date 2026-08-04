#!/usr/bin/env python3
"""Validate the native host and Windows helper used by packaged builds."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
AGENT_COMPONENT = "deimos-agent"
AGENT_FILENAME = "deimos-agent.exe"
MANIFEST_FILENAME = "deimos-agent.json"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class ArtifactValidationError(RuntimeError):
    pass


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ArtifactValidationError(f"{label} must be a regular file: {path}")
    return path.resolve()


def validate_agent(path: Path) -> Path:
    path = _regular_file(path, "Windows helper artifact")
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ArtifactValidationError(
                f"Windows helper artifact is not a PE executable: {path}"
            )
    return path


def _artifact_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _identity(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ArtifactValidationError(f"{label} identity must be a JSON object")
    version = value.get("version")
    build_id = value.get("build_id")
    if not isinstance(version, str) or not version:
        raise ArtifactValidationError(f"{label} identity has no version")
    if not isinstance(build_id, str) or not build_id:
        raise ArtifactValidationError(f"{label} identity has no build ID")
    return {"version": version, "build_id": build_id}


def read_manifest(path: Path) -> dict[str, Any]:
    path = _regular_file(path, "Windows helper manifest")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArtifactValidationError(
            f"Windows helper manifest is unreadable: {path}: {error}"
        ) from error
    if not isinstance(manifest, dict):
        raise ArtifactValidationError("Windows helper manifest must be a JSON object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ArtifactValidationError("Windows helper manifest schema is unsupported")
    if manifest.get("component") != AGENT_COMPONENT:
        raise ArtifactValidationError("Windows helper manifest component is invalid")
    _identity(manifest, "Windows helper")
    size = manifest.get("size")
    sha256 = manifest.get("sha256")
    if isinstance(size, bool) or not isinstance(size, int) or size < 2:
        raise ArtifactValidationError("Windows helper manifest size is invalid")
    if not isinstance(sha256, str) or SHA256_PATTERN.fullmatch(sha256) is None:
        raise ArtifactValidationError("Windows helper manifest SHA-256 is invalid")
    return manifest


def load_native_identity(path: Path) -> dict[str, str]:
    path = _regular_file(path, "native Python module")
    spec = importlib.util.spec_from_file_location("deimos_native", path)
    if spec is None or spec.loader is None:
        raise ArtifactValidationError(f"Native Python module cannot be loaded: {path}")
    previous = sys.modules.pop("deimos_native", None)
    try:
        module = importlib.util.module_from_spec(spec)
        sys.modules["deimos_native"] = module
        spec.loader.exec_module(module)
        identity_method = getattr(module, "build_identity", None)
        if not callable(identity_method):
            raise ArtifactValidationError(
                "Native Python module does not expose build_identity()"
            )
        return _identity(identity_method(), "native Python module")
    except ArtifactValidationError:
        raise
    except BaseException as error:
        raise ArtifactValidationError(
            f"Native Python module import failed: {path}: {error}"
        ) from error
    finally:
        sys.modules.pop("deimos_native", None)
        if previous is not None:
            sys.modules["deimos_native"] = previous


def create_manifest(agent: Path, output: Path, expected_build_id: str) -> None:
    agent = validate_agent(agent)
    completed = subprocess.run(
        [str(agent), "--artifact-identity"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip()
        raise ArtifactValidationError(
            f"Windows helper did not report its identity: {diagnostic}"
        )
    try:
        reported = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ArtifactValidationError(
            "Windows helper returned an unreadable artifact identity"
        ) from error
    identity = _identity(reported, "Windows helper")
    if reported.get("schema_version") != SCHEMA_VERSION:
        raise ArtifactValidationError("Windows helper identity schema is unsupported")
    if reported.get("component") != AGENT_COMPONENT:
        raise ArtifactValidationError("Windows helper identity component is invalid")
    if identity["build_id"] != expected_build_id:
        raise ArtifactValidationError(
            "Windows helper build ID does not match the requested package build ID: "
            f"expected {expected_build_id!r}, got {identity['build_id']!r}"
        )
    size, sha256 = _artifact_digest(agent)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "component": AGENT_COMPONENT,
        **identity,
        "size": size,
        "sha256": sha256,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def validate_package_inputs(
    agent: Path,
    manifest_path: Path,
    native_module: Path,
    expected_build_id: str,
) -> dict[str, str]:
    agent = validate_agent(agent)
    manifest = read_manifest(manifest_path)
    agent_identity = _identity(manifest, "Windows helper")
    agent_size, agent_sha256 = _artifact_digest(agent)
    if agent_size != manifest["size"] or agent_sha256 != manifest["sha256"]:
        raise ArtifactValidationError(
            "Windows helper artifact does not match its identity manifest"
        )
    native_identity = load_native_identity(native_module)
    if agent_identity != native_identity:
        raise ArtifactValidationError(
            "Native Python module and Windows helper were built from different artifacts: "
            f"native={native_identity!r}, helper={agent_identity!r}"
        )
    if native_identity["build_id"] != expected_build_id:
        raise ArtifactValidationError(
            "Package build ID does not match its native artifacts: "
            f"expected {expected_build_id!r}, got {native_identity['build_id']!r}"
        )
    return native_identity


def _archive_member_basenames(listing: str) -> set[str]:
    members = set()
    for line in listing.splitlines():
        match = re.search(r",\s*(?:'([^']+)'|\"([^\"]+)\"|([^,]+))\s*$", line)
        if match is not None:
            name = next(group for group in match.groups() if group is not None).strip()
            members.add(name.replace("\\", "/").rsplit("/", 1)[-1])
    return members


def validate_archive_listing(listing: str) -> None:
    members = _archive_member_basenames(listing)
    missing = []
    if AGENT_FILENAME not in members:
        missing.append(AGENT_FILENAME)
    if MANIFEST_FILENAME not in members:
        missing.append(MANIFEST_FILENAME)
    if not any(
        name == "deimos_native"
        or (name.startswith("deimos_native.") and name.endswith((".pyd", ".so")))
        for name in members
    ):
        missing.append("deimos_native")
    if missing:
        raise ArtifactValidationError(
            "Packaged application is missing required artifacts: " + ", ".join(missing)
        )


def verify_archive(archive: Path, viewer: str) -> None:
    archive = _regular_file(archive, "packaged application archive")
    completed = subprocess.run(
        [viewer, "-l", str(archive)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip()
        raise ArtifactValidationError(
            f"PyInstaller could not inspect the packaged application: {diagnostic}"
        )
    validate_archive_listing(completed.stdout)


def verify_app_bundle(app: Path) -> None:
    app = app.resolve()
    executable = app / "Contents" / "MacOS" / "Deimos"
    if not executable.is_file() or executable.is_symlink():
        raise ArtifactValidationError(
            f"macOS application bundle has no regular executable: {executable}"
        )
    members = {path.name for path in app.rglob("*") if path.is_file()}
    missing = [
        name
        for name in (AGENT_FILENAME, MANIFEST_FILENAME)
        if name not in members
    ]
    if not any(
        name.startswith("deimos_native.") and name.endswith(".so")
        for name in members
    ):
        missing.append("deimos_native")
    if missing:
        raise ArtifactValidationError(
            "macOS application bundle is missing required artifacts: "
            + ", ".join(missing)
        )


def arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create-manifest")
    create.add_argument("--agent", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--expected-build-id", required=True)

    verify = commands.add_parser("verify-inputs")
    verify.add_argument("--agent", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--native-module", required=True, type=Path)
    verify.add_argument("--expected-build-id", required=True)

    archive = commands.add_parser("verify-archive")
    archive.add_argument("--archive", required=True, type=Path)
    archive.add_argument(
        "--viewer", default=os.environ.get("PYINSTALLER_ARCHIVE_VIEWER", "pyi-archive_viewer")
    )

    bundle = commands.add_parser("verify-app-bundle")
    bundle.add_argument("--app", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    options = arguments(argv)
    try:
        if options.command == "create-manifest":
            create_manifest(options.agent, options.output, options.expected_build_id)
        elif options.command == "verify-inputs":
            identity = validate_package_inputs(
                options.agent,
                options.manifest,
                options.native_module,
                options.expected_build_id,
            )
            print(json.dumps(identity, sort_keys=True))
        elif options.command == "verify-app-bundle":
            verify_app_bundle(options.app)
        else:
            verify_archive(options.archive, options.viewer)
    except ArtifactValidationError as error:
        print(f"Packaging validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
