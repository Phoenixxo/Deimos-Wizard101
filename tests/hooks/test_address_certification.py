from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"
for import_root in (REPOSITORY_ROOT, WIZWALKER_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def load_certifier():
    module_path = REPOSITORY_ROOT / "scripts" / "certify-deimos-addresses-live.py"
    spec = importlib.util.spec_from_file_location(
        "deimos_address_certification", module_path
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    native_stub = SimpleNamespace(AgentManager=object)
    with patch.dict(sys.modules, {"deimos_native": native_stub}):
        spec.loader.exec_module(module)
    return module


certifier = load_certifier()


class FakeCertificationManager:
    def __init__(
        self, *, export=0x100000005, patch_target=True, activation_error=None
    ):
        self.target = 0x140001000
        self.original = bytes(range(certifier.TARGET_COMPARE_BYTES))
        self.export = export
        self.patch_target = patch_target
        self.activation_error = activation_error
        self.active = False
        self.deactivate_calls = 0

    def scan_memory(self, *args, **kwargs):
        return {
            "matches": [hex(self.target)],
            "scanned_regions": 1,
            "skipped_regions": 0,
            "errors": [],
        }

    def read_memory(self, session_id, address, size):
        del session_id
        parsed = int(address, 0)
        if parsed == self.target:
            if self.active and self.patch_target:
                return (b"\xe9" + self.original[1:])[:size]
            return self.original[:size]
        if parsed == self.export:
            return (struct.pack("<fff", 1.0, 2.0, 3.0) + bytes(8))[:size]
        raise AssertionError(f"unexpected read at {parsed:#x}")

    def activate_core_hook(self, session_id, hook):
        del session_id
        if self.activation_error is not None:
            raise self.activation_error
        self.active = True
        return {"hook": hook, "active": True}

    def read_core_hook_base(self, session_id, hook):
        del session_id, hook
        return self.export

    def heartbeat_core_hooks(self, session_id):
        del session_id
        return {"active": self.active}

    def deactivate_core_hook(self, session_id, hook):
        del session_id
        self.deactivate_calls += 1
        self.active = False
        return {"hook": hook, "deactivated": True}


class AddressCertificationTests(unittest.TestCase):
    def test_windows_executable_path_maps_into_the_bottle(self):
        bottle = Path("/tmp/wizard101")

        result = certifier.host_executable_path(
            bottle,
            r"C:\Program Files\KingsIsle Entertainment\Wizard101\WizardGraphicalClient.exe",
        )

        self.assertEqual(
            result,
            bottle
            / "drive_c"
            / "Program Files"
            / "KingsIsle Entertainment"
            / "Wizard101"
            / "WizardGraphicalClient.exe",
        )

    def test_region_validation_requires_the_whole_read(self):
        regions = [
            {
                "base_address": "0x1000",
                "size": 16,
                "protection": "read_write",
            }
        ]

        self.assertIsNotNone(certifier.find_region(regions, 0x1008, 8))
        self.assertIsNone(certifier.find_region(regions, 0x1008, 9))

    def test_bad_nonzero_export_fails_before_semantic_reads_and_cleans_up(self):
        manager = FakeCertificationManager()
        spec = certifier.CoreHookSpec(
            "quest",
            "90 90 90 90 90 90 90 90 90 90 90 90 90 90",
            required_alignment=4,
        )

        result, cleanup_safe = certifier.certify_hook(
            manager,
            "session-1",
            certifier.TARGET_PROCESS,
            0x140000000,
            0x200000,
            [],
            SimpleNamespace(),
            {},
            {},
            spec,
            samples=1,
            interval=0,
            ready_timeout=0.1,
            cleanup_timeout=0.1,
        )

        self.assertFalse(result["passed"])
        self.assertFalse(result["samples"][0]["aligned"])
        self.assertIn("not 4-byte aligned", result["samples"][0]["error"]["message"])
        self.assertTrue(result["cleanup"]["passed"])
        self.assertTrue(result["cleanup"]["bytes_match"])
        self.assertTrue(cleanup_safe)
        self.assertEqual(manager.deactivate_calls, 1)

    def test_quest_export_accepts_its_four_byte_alignment(self):
        manager = FakeCertificationManager(export=0x100000004)
        spec = certifier.CoreHookSpec(
            "quest",
            "90 90 90 90 90 90 90 90 90 90 90 90 90 90",
            required_alignment=4,
        )

        result, cleanup_safe = certifier.certify_hook(
            manager,
            "session-1",
            certifier.TARGET_PROCESS,
            0x140000000,
            0x200000,
            [
                {
                    "base_address": "0x100000000",
                    "size": 0x1000,
                    "protection": "read_write",
                }
            ],
            SimpleNamespace(),
            {},
            {},
            spec,
            samples=1,
            interval=0,
            ready_timeout=0.1,
            cleanup_timeout=0.1,
        )

        self.assertTrue(result["passed"])
        self.assertTrue(result["samples"][0]["aligned"])
        self.assertEqual(result["samples"][0]["required_alignment"], 4)
        self.assertTrue(cleanup_safe)

    def test_invalid_export_still_records_independent_reference(self):
        manager = FakeCertificationManager(export=0xFFFFFF81)
        spec = certifier.CoreHookSpec(
            "player_stat",
            "90 90 90 90 90 90 90 90 90 90 90 90 90 90",
            reference_resolver="game_stats",
        )

        async def reference(*args):
            del args
            return 0x100000008

        with patch.object(certifier, "independent_address", reference):
            result, cleanup_safe = certifier.certify_hook(
                manager,
                "session-1",
                certifier.TARGET_PROCESS,
                0x140000000,
                0x200000,
                [],
                SimpleNamespace(),
                {},
                {},
                spec,
                samples=1,
                interval=0,
                ready_timeout=0.1,
                cleanup_timeout=0.1,
            )

        sample = result["samples"][0]
        self.assertFalse(result["passed"])
        self.assertEqual(sample["independent_reference"], "0x100000008")
        self.assertFalse(sample["independent_match"])
        self.assertTrue(cleanup_safe)

    def test_selector_drift_is_rejected_when_agent_patches_another_target(self):
        manager = FakeCertificationManager(patch_target=False)
        spec = certifier.CoreHookSpec(
            "quest",
            "90 90 90 90 90 90 90 90 90 90 90 90 90 90",
            required_alignment=4,
        )

        result, cleanup_safe = certifier.certify_hook(
            manager,
            "session-1",
            certifier.TARGET_PROCESS,
            0x140000000,
            0x200000,
            [],
            SimpleNamespace(),
            {},
            {},
            spec,
            samples=1,
            interval=0,
            ready_timeout=0.1,
            cleanup_timeout=0.1,
        )

        self.assertFalse(result["passed"])
        self.assertFalse(result["target"]["bytes_changed"])
        self.assertIn("did not patch", result["error"]["message"])
        self.assertTrue(cleanup_safe)

    def test_activation_failure_still_attempts_cleanup(self):
        manager = FakeCertificationManager(
            activation_error=RuntimeError("activation failed")
        )
        spec = certifier.CoreHookSpec(
            "quest",
            "90 90 90 90 90 90 90 90 90 90 90 90 90 90",
            required_alignment=4,
        )

        result, cleanup_safe = certifier.certify_hook(
            manager,
            "session-1",
            certifier.TARGET_PROCESS,
            0x140000000,
            0x200000,
            [],
            SimpleNamespace(),
            {},
            {},
            spec,
            samples=1,
            interval=0,
            ready_timeout=0.1,
            cleanup_timeout=0.1,
        )

        self.assertFalse(result["passed"])
        self.assertIn("activation failed", result["error"]["message"])
        self.assertTrue(result["cleanup"]["passed"])
        self.assertTrue(result["cleanup"]["bytes_match"])
        self.assertTrue(cleanup_safe)
        self.assertEqual(manager.deactivate_calls, 1)


if __name__ == "__main__":
    unittest.main()
