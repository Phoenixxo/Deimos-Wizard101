from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.package_artifacts import (
    ArtifactValidationError,
    read_manifest,
    validate_archive_listing,
    validate_package_inputs,
)


class PackageArtifactTests(unittest.TestCase):
    @staticmethod
    def write_manifest(path: Path, agent: Path, *, build_id: str = "git-test") -> None:
        contents = agent.read_bytes()
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "component": "deimos-agent",
                    "version": "0.1.0",
                    "build_id": build_id,
                    "size": len(contents),
                    "sha256": hashlib.sha256(contents).hexdigest(),
                }
            ),
            encoding="utf-8",
        )

    def test_missing_agent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "deimos-agent.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "component": "deimos-agent",
                        "version": "0.1.0",
                        "build_id": "git-test",
                        "size": 7,
                        "sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            native = root / "deimos_native.so"
            native.write_bytes(b"native")

            with self.assertRaisesRegex(ArtifactValidationError, "regular file"):
                validate_package_inputs(
                    root / "deimos-agent.exe", manifest, native, "git-test"
                )

    def test_matching_native_and_agent_identities_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / "deimos-agent.exe"
            agent.write_bytes(b"MZagent")
            manifest = root / "deimos-agent.json"
            self.write_manifest(manifest, agent)
            native = root / "deimos_native.so"
            native.write_bytes(b"native")

            with patch(
                "scripts.package_artifacts.load_native_identity",
                return_value={"version": "0.1.0", "build_id": "git-test"},
            ):
                identity = validate_package_inputs(
                    agent, manifest, native, "git-test"
                )

            self.assertEqual(identity["build_id"], "git-test")

    def test_mismatched_artifacts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / "deimos-agent.exe"
            agent.write_bytes(b"MZagent")
            manifest = root / "deimos-agent.json"
            self.write_manifest(manifest, agent, build_id="git-agent")
            native = root / "deimos_native.so"
            native.write_bytes(b"native")

            with patch(
                "scripts.package_artifacts.load_native_identity",
                return_value={"version": "0.1.0", "build_id": "git-native"},
            ):
                with self.assertRaisesRegex(
                    ArtifactValidationError, "different artifacts"
                ):
                    validate_package_inputs(agent, manifest, native, "git-native")

    def test_manifest_requires_the_expected_schema_and_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "deimos-agent.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "component": "unexpected",
                        "version": "0.1.0",
                        "build_id": "git-test",
                        "size": 7,
                        "sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ArtifactValidationError, "schema"):
                read_manifest(manifest)

    def test_archive_must_contain_all_native_artifacts(self) -> None:
        validate_archive_listing(
            "0, 7, 7, 0, 'b', 'deimos-agent.exe'\n"
            "7, 2, 2, 0, 'x', 'deimos-agent.json'\n"
            "9, 4, 4, 0, 'b', 'deimos_native.cpython-313-darwin.so'"
        )
        with self.assertRaisesRegex(ArtifactValidationError, "deimos-agent.json"):
            validate_archive_listing(
                "0, 7, 7, 0, 'b', 'deimos-agent.exe'\n"
                "7, 4, 4, 0, 'b', 'deimos_native.cp313-win_amd64.pyd'"
            )

    def test_helper_must_match_manifest_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / "deimos-agent.exe"
            agent.write_bytes(b"MZfirst")
            manifest = root / "deimos-agent.json"
            self.write_manifest(manifest, agent)
            agent.write_bytes(b"MZother")
            native = root / "deimos_native.so"
            native.write_bytes(b"native")

            with patch(
                "scripts.package_artifacts.load_native_identity",
                return_value={"version": "0.1.0", "build_id": "git-test"},
            ):
                with self.assertRaisesRegex(
                    ArtifactValidationError, "does not match its identity manifest"
                ):
                    validate_package_inputs(agent, manifest, native, "git-test")

    def test_archive_rejects_substring_lookalikes(self) -> None:
        listing = (
            "0, 7, 7, 0, 'b', 'not-deimos-agent.exe.backup'\n"
            "7, 2, 2, 0, 'x', 'not-deimos-agent.json.backup'\n"
            "9, 4, 4, 0, 'b', 'not-deimos_native.txt'"
        )
        with self.assertRaisesRegex(ArtifactValidationError, "required artifacts"):
            validate_archive_listing(listing)


if __name__ == "__main__":
    unittest.main()
