from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"

if str(WIZWALKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WIZWALKER_ROOT))

from wizwalker import (  # noqa: E402
    ClientHandler,
    DeimosNativeMemoryBackend,
    DiscoveredClient,
    MemoryReader,
    PatternFailed,
    ReadOnlyTelemetryReader,
)
from wizwalker.telemetry import (  # noqa: E402
    CURRENT_ROOT_CLIENT_OBJECT_OFFSET_PATTERN,
    DUEL_MANAGER_PATTERN,
    GAME_CLIENT_PATTERN,
    ROOT_CLIENT_OBJECT_OFFSET_PATTERN,
)


class SparseMemory:
    def __init__(self):
        self.bytes: dict[int, int] = {}

    def write(self, address: int, value: bytes) -> None:
        for offset, byte in enumerate(value):
            self.bytes[address + offset] = byte

    def read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.bytes[address + offset] for offset in range(size))
        except KeyError as error:
            raise RuntimeError(
                f"unmapped fixture read at 0x{address:x} ({size} bytes)"
            ) from error

    def pack(self, address: int, format_string: str, *values: Any) -> None:
        self.write(address, struct.pack(format_string, *values))

    def string(self, address: int, value: str, storage: int) -> None:
        encoded = value.encode("utf-8")
        self.pack(address + 16, "<i", len(encoded))
        if len(encoded) >= 16:
            self.pack(address, "<Q", storage)
            self.write(storage, encoded)
        else:
            self.write(address, encoded)


class TelemetryFixture:
    GAME_CLIENT_INSTRUCTION = 0x140001000
    ROOT_OFFSET_INSTRUCTION = 0x140002000
    DUEL_MANAGER_INSTRUCTION = 0x140003000
    GAME_CLIENT_POINTER = 0x140004000
    DUEL_MANAGER_POINTER = 0x140005000
    GAME_CLIENT = 0x200000
    TREE_ROOT = 0x2F0000
    ROOT = 0x300000
    ZONE = 0x310000
    STATS = 0x320000
    ANIMATION_BEHAVIOR = 0x330000
    PET_BEHAVIOR = 0x331000
    ANIMATION_TEMPLATE = 0x340000
    PET_TEMPLATE = 0x341000
    ACTOR_BODY = 0x350000
    BEHAVIOR_VECTOR = 0x360000
    CLIENT_OBJECT_VECTOR = 0x361000
    DUEL_MANAGER = 0x400000
    DUEL_SENTINEL = 0x410000
    DUEL_NODE = 0x420000
    DUEL = 0x430000
    PARTICIPANT_VECTOR = 0x440000
    PARTICIPANT = 0x450000
    ROOT_OFFSET = 0x212A0
    CURRENT_ROOT_OFFSET = 0x21378

    def __init__(
        self,
        *,
        character_id: int = 123456,
        current_selector: bool = False,
        player_gid: int = 987654,
        zone_name: str = "WizardCity/WC_Hub",
    ):
        self.memory = SparseMemory()
        self.pattern_scan_calls = 0
        root_pattern = (
            CURRENT_ROOT_CLIENT_OBJECT_OFFSET_PATTERN
            if current_selector
            else ROOT_CLIENT_OBJECT_OFFSET_PATTERN
        )
        root_offset = (
            self.CURRENT_ROOT_OFFSET
            if current_selector
            else self.ROOT_OFFSET
        )
        player_gid_offset = 0x213A8 if current_selector else 0x214C0
        self.scan_addresses = {
            GAME_CLIENT_PATTERN: self.GAME_CLIENT_INSTRUCTION,
            root_pattern: self.ROOT_OFFSET_INSTRUCTION,
            DUEL_MANAGER_PATTERN: self.DUEL_MANAGER_INSTRUCTION,
        }

        game_relative = self.GAME_CLIENT_POINTER - (
            self.GAME_CLIENT_INSTRUCTION + 7
        )
        self.memory.pack(
            self.GAME_CLIENT_INSTRUCTION + 3,
            "<i",
            game_relative,
        )
        self.memory.pack(
            self.GAME_CLIENT_POINTER,
            "<Q",
            self.GAME_CLIENT,
        )
        self.memory.pack(
            self.ROOT_OFFSET_INSTRUCTION + 3,
            "<I",
            root_offset,
        )
        self.memory.pack(
            self.GAME_CLIENT + root_offset,
            "<Q",
            self.TREE_ROOT,
        )
        self.memory.pack(
            self.GAME_CLIENT + player_gid_offset,
            "<Q",
            player_gid,
        )

        self.memory.pack(self.TREE_ROOT + 72, "<Q", 1)
        self.memory.pack(
            self.TREE_ROOT + 392,
            "<Q",
            self.CLIENT_OBJECT_VECTOR,
        )
        self.memory.pack(
            self.TREE_ROOT + 400,
            "<Q",
            self.CLIENT_OBJECT_VECTOR + 16,
        )
        self.memory.write(self.CLIENT_OBJECT_VECTOR, bytes(16))
        self.memory.pack(self.CLIENT_OBJECT_VECTOR, "<Q", self.ROOT)

        self.memory.pack(self.ROOT + 72, "<Q", player_gid)
        self.memory.pack(self.ROOT + 392, "<Q", 0)
        self.memory.pack(self.ROOT + 400, "<Q", 0)
        self.memory.pack(self.ROOT + 224, "<Q", self.BEHAVIOR_VECTOR)
        self.memory.pack(self.ROOT + 232, "<Q", self.BEHAVIOR_VECTOR + 32)
        self.memory.pack(self.ROOT + 304, "<Q", self.ZONE)
        self.memory.pack(self.ROOT + 448, "<Q", character_id)
        self.memory.pack(self.ROOT + 560, "<Q", self.STATS)

        self.memory.write(self.BEHAVIOR_VECTOR, bytes(32))
        self.memory.pack(
            self.BEHAVIOR_VECTOR,
            "<Q",
            self.ANIMATION_BEHAVIOR,
        )
        self.memory.pack(
            self.BEHAVIOR_VECTOR + 16,
            "<Q",
            self.PET_BEHAVIOR,
        )
        self.memory.pack(
            self.ANIMATION_BEHAVIOR + 0x58,
            "<Q",
            self.ANIMATION_TEMPLATE,
        )
        self.memory.pack(
            self.ANIMATION_BEHAVIOR + 0x70,
            "<Q",
            self.ACTOR_BODY,
        )
        self.memory.string(
            self.ANIMATION_TEMPLATE + 72,
            "AnimationBehavior",
            0x500000,
        )
        self.memory.pack(
            self.PET_BEHAVIOR + 0x58,
            "<Q",
            self.PET_TEMPLATE,
        )
        self.memory.pack(self.PET_BEHAVIOR + 132, "<i", 72)
        self.memory.string(
            self.PET_TEMPLATE + 72,
            "PetOwnerBehavior",
            0x500100,
        )

        self.memory.pack(
            self.ACTOR_BODY + 88,
            "<fff",
            10.5,
            -20.25,
            30.75,
        )
        self.memory.pack(
            self.ACTOR_BODY + 100,
            "<fff",
            0.1,
            0.2,
            1.5,
        )

        self.memory.pack(self.ZONE + 72, "<q", 501)
        self.memory.string(self.ZONE + 88, zone_name, 0x500200)

        self.memory.pack(self.STATS + 80, "<i", 4_000)
        self.memory.pack(self.STATS + 84, "<i", 100)
        self.memory.pack(self.STATS + 108, "<i", 100)
        self.memory.pack(self.STATS + 112, "<i", 3_750)
        self.memory.pack(self.STATS + 136, "<i", 85)
        self.memory.pack(self.STATS + 224, "<i", 500)
        self.memory.pack(self.STATS + 228, "<i", 25)
        self.memory.pack(self.STATS + 244, "<i", 30)

        duel_relative = self.DUEL_MANAGER_POINTER - (
            self.DUEL_MANAGER_INSTRUCTION + 7
        )
        self.memory.pack(
            self.DUEL_MANAGER_INSTRUCTION + 3,
            "<i",
            duel_relative,
        )
        self.memory.pack(
            self.DUEL_MANAGER_POINTER,
            "<Q",
            self.DUEL_MANAGER,
        )
        self.memory.pack(
            self.DUEL_MANAGER + 8,
            "<Q",
            self.DUEL_SENTINEL,
        )
        self.memory.pack(
            self.DUEL_SENTINEL + 8,
            "<Q",
            self.DUEL_NODE,
        )
        self.memory.pack(
            self.DUEL_NODE,
            "<Q",
            self.DUEL_SENTINEL,
        )
        self.memory.pack(
            self.DUEL_NODE + 0x10,
            "<Q",
            self.DUEL_SENTINEL,
        )
        self.memory.pack(self.DUEL_NODE + 0x19, "<?", False)
        self.memory.pack(self.DUEL_NODE + 0x28, "<Q", self.DUEL)
        self.memory.pack(
            self.DUEL + 80,
            "<Q",
            self.PARTICIPANT_VECTOR,
        )
        self.memory.pack(
            self.DUEL + 88,
            "<Q",
            self.PARTICIPANT_VECTOR + 16,
        )
        self.memory.write(self.PARTICIPANT_VECTOR, bytes(16))
        self.memory.pack(
            self.PARTICIPANT_VECTOR,
            "<Q",
            self.PARTICIPANT,
        )
        self.memory.pack(self.PARTICIPANT + 112, "<Q", player_gid)
        self.memory.pack(self.DUEL + 196, "<i", 2)

    async def pattern_scan(
        self,
        pattern: bytes,
        *,
        module: str | None = None,
        return_multiple: bool = False,
    ) -> int | list[int]:
        del module
        self.pattern_scan_calls += 1
        address = self.scan_addresses.get(pattern)
        if address is None:
            raise PatternFailed(pattern)
        return [address] if return_multiple else address


class FakePymemProcess:
    process_handle = 77

    def __init__(self, memory: SparseMemory):
        self.memory = memory
        self.write_attempts = 0

    def read_bytes(self, address: int, size: int) -> bytes:
        return self.memory.read(address, size)

    def write_bytes(self, address: int, value: bytes, size: int) -> None:
        del address, value, size
        self.write_attempts += 1
        raise AssertionError("read-only telemetry attempted a write")


class FakeNativeError(Exception):
    pass


class FakeProcessError(FakeNativeError):
    def __init__(self, message: str, *, code: str = "process_exited"):
        super().__init__(message)
        self.code = code
        self.technical_message = message


class FakeNativeMemoryError(FakeNativeError):
    pass


FAKE_NATIVE = SimpleNamespace(
    DeimosNativeError=FakeNativeError,
    ProcessError=FakeProcessError,
    MemoryError=FakeNativeMemoryError,
)


class FakeNativeManager:
    def __init__(self, memory: SparseMemory):
        self.memory = memory
        self.read_error: BaseException | None = None
        self.closed_sessions: list[str] = []
        self.open_calls: list[tuple[int, str | None]] = []

    def read_memory(self, session_id: str, address: str, size: int) -> bytes:
        del session_id
        if self.read_error is not None:
            raise self.read_error
        return self.memory.read(int(address, 0), size)

    def process_status(self, session_id: str) -> dict[str, str]:
        return {"session_id": session_id, "state": "open"}

    def open_process(
        self,
        pid: int,
        expected_identity_json: str | None = None,
    ) -> dict[str, str]:
        self.open_calls.append((pid, expected_identity_json))
        return {"session_id": f"session-{pid}"}

    def close_process(self, session_id: str) -> dict[str, str]:
        self.closed_sessions.append(session_id)
        return {"session_id": session_id, "state": "closed"}


class BlockingOpenNativeManager(FakeNativeManager):
    def __init__(self, memory: SparseMemory):
        super().__init__(memory)
        self.open_started = threading.Event()
        self.allow_open = threading.Event()

    def open_process(
        self,
        pid: int,
        expected_identity_json: str | None = None,
    ) -> dict[str, str]:
        self.open_started.set()
        if not self.allow_open.wait(timeout=1):
            raise TimeoutError("test did not allow the native process session to open")
        return super().open_process(pid, expected_identity_json)


def telemetry_reader(
    fixture: TelemetryFixture,
    backend: str,
) -> tuple[ReadOnlyTelemetryReader, Any]:
    if backend == "pymem":
        process = FakePymemProcess(fixture.memory)
        memory_reader = MemoryReader(process)
        owner = process
    else:
        manager = FakeNativeManager(fixture.memory)
        native_backend = DeimosNativeMemoryBackend(
            manager,
            "session-1",
            native_module=FAKE_NATIVE,
        )
        memory_reader = MemoryReader(native_backend)
        owner = manager
    memory_reader.pattern_scan = fixture.pattern_scan
    return ReadOnlyTelemetryReader(memory_reader), owner


def descriptor(client_id: str, pid: int) -> dict[str, Any]:
    return {
        "client_id": client_id,
        "process": {
            "pid": pid,
            "name": "WizardGraphicalClient.exe",
            "kind": "wizard101",
            "identity": {
                "pid": pid,
                "creation_time_100ns": str(1000 + pid),
                "executable_path": (
                    "C:\\ProgramData\\KingsIsle Entertainment\\Wizard101\\Bin\\"
                    "WizardGraphicalClient.exe"
                ),
            },
        },
        "is_foreground": False,
        "screen_order": 0,
    }


class ReadOnlyTelemetryParityTests(unittest.IsolatedAsyncioTestCase):
    def test_root_client_object_offset_matches_the_encoded_instruction(self):
        self.assertEqual(
            struct.unpack_from(
                "<I",
                bytes.fromhex(
                    ROOT_CLIENT_OBJECT_OFFSET_PATTERN.decode().replace("\\x", "")
                ),
                3,
            )[0],
            TelemetryFixture.ROOT_OFFSET,
        )

    async def test_pymem_and_native_backends_return_the_same_snapshot_contract(self):
        fixture = TelemetryFixture()
        pymem_reader, pymem_process = telemetry_reader(fixture, "pymem")
        native_reader, _ = telemetry_reader(fixture, "native")

        pymem_snapshot = await pymem_reader.snapshot(
            client_id="client-a",
            process_id=448,
        )
        native_snapshot = await native_reader.snapshot(
            client_id="client-a",
            process_id=448,
        )

        self.assertEqual(pymem_snapshot.to_dict(), native_snapshot.to_dict())
        self.assertEqual(pymem_process.write_attempts, 0)
        self.assertEqual(
            pymem_snapshot.available_fields,
            [
                "character_identity",
                "zone",
                "position",
                "orientation",
                "health",
                "mana",
                "energy",
                "combat",
            ],
        )
        self.assertEqual(
            pymem_snapshot.fields["character_identity"].value,
            {"player_gid": 987654, "character_id": 123456},
        )
        self.assertEqual(
            pymem_snapshot.fields["health"].value,
            {"current": 3750, "maximum": 4500},
        )
        self.assertEqual(
            pymem_snapshot.fields["combat"].value,
            {"in_combat": True, "phase": "planning", "phase_code": 2},
        )
        for field_name in ("loading", "dialog", "root_ui"):
            error = pymem_snapshot.fields[field_name].error
            self.assertEqual(error.code, "hook_required")

    async def test_current_client_selector_returns_the_same_snapshot(self):
        fixture = TelemetryFixture(current_selector=True)
        reader, process = telemetry_reader(fixture, "pymem")

        snapshot = await reader.snapshot()

        self.assertEqual(
            snapshot.fields["character_identity"].value,
            {"player_gid": 987654, "character_id": 123456},
        )
        self.assertEqual(
            snapshot.fields["position"].value,
            {"x": 10.5, "y": -20.25, "z": 30.75},
        )
        self.assertEqual(process.write_attempts, 0)

    async def test_signature_addresses_are_reused_across_snapshots(self):
        fixture = TelemetryFixture()
        reader, _ = telemetry_reader(fixture, "native")

        await reader.snapshot()
        await reader.snapshot()

        self.assertEqual(fixture.pattern_scan_calls, 3)

    async def test_current_selector_choice_is_reused_across_snapshots(self):
        fixture = TelemetryFixture(current_selector=True)
        reader, _ = telemetry_reader(fixture, "native")

        await reader.snapshot()
        await reader.snapshot()

        self.assertEqual(fixture.pattern_scan_calls, 4)

    async def test_transient_signature_failure_is_not_cached(self):
        fixture = TelemetryFixture()
        reader, _ = telemetry_reader(fixture, "native")
        original_pattern_scan = reader.memory.pattern_scan
        attempts = 0

        async def fail_once(*args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise PatternFailed(GAME_CLIENT_PATTERN)
            return await original_pattern_scan(*args, **kwargs)

        reader.memory.pattern_scan = fail_once
        first = await reader.snapshot()
        second = await reader.snapshot()

        self.assertFalse(first.fields["character_identity"].available)
        self.assertTrue(second.fields["character_identity"].available)

    async def test_signature_mismatch_is_distinct_from_process_failure(self):
        fixture = TelemetryFixture()
        signature_reader, _ = telemetry_reader(fixture, "native")

        async def missing_signature(*args, **kwargs):
            del args, kwargs
            raise PatternFailed(GAME_CLIENT_PATTERN)

        signature_reader.memory.pattern_scan = missing_signature
        signature_snapshot = await signature_reader.snapshot()
        self.assertEqual(
            signature_snapshot.fields["character_identity"].error.code,
            "signature_mismatch",
        )
        self.assertIn(
            "does not match",
            signature_snapshot.fields["character_identity"].error.message,
        )

        process_reader, manager = telemetry_reader(fixture, "native")
        manager.read_error = FakeProcessError("fixture process closed")
        process_snapshot = await process_reader.snapshot()
        self.assertEqual(
            process_snapshot.fields["character_identity"].error.code,
            "process_unavailable",
        )
        self.assertIn(
            "unavailable",
            process_snapshot.fields["character_identity"].error.message,
        )
        self.assertEqual(
            process_snapshot.fields["character_identity"].error.details["native_code"],
            "process_exited",
        )
        self.assertEqual(
            process_snapshot.fields[
                "character_identity"
            ].error.technical_message,
            "fixture process closed",
        )

        access_reader, access_manager = telemetry_reader(fixture, "native")
        access_manager.read_error = FakeProcessError(
            "fixture process access denied",
            code="process_access_denied",
        )
        access_snapshot = await access_reader.snapshot()
        self.assertEqual(
            access_snapshot.fields["character_identity"].error.code,
            "process_unavailable",
        )

    async def test_multiple_clients_can_be_read_concurrently(self):
        first_fixture = TelemetryFixture(character_id=111, zone_name="Zone/One")
        second_fixture = TelemetryFixture(character_id=222, zone_name="Zone/Two")
        first_reader, _ = telemetry_reader(first_fixture, "native")
        second_reader, _ = telemetry_reader(second_fixture, "native")

        first, second = await asyncio.gather(
            first_reader.snapshot(client_id="client-a", process_id=448),
            second_reader.snapshot(client_id="client-b", process_id=544),
        )

        self.assertEqual(first.client_id, "client-a")
        self.assertEqual(second.client_id, "client-b")
        self.assertEqual(
            first.fields["character_identity"].value["character_id"],
            111,
        )
        self.assertEqual(
            second.fields["character_identity"].value["character_id"],
            222,
        )
        self.assertEqual(first.fields["zone"].value["name"], "Zone/One")
        self.assertEqual(second.fields["zone"].value["name"], "Zone/Two")


class DiscoveredClientTelemetryLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_identity_checked_session_is_reused_and_closed(self):
        manager = FakeNativeManager(SparseMemory())
        client = DiscoveredClient(manager, descriptor("client-a", 448))

        first = await client.attach_telemetry()
        second = await client.attach_telemetry()

        self.assertIs(first, second)
        self.assertEqual(len(manager.open_calls), 1)
        pid, identity_json = manager.open_calls[0]
        self.assertEqual(pid, 448)
        self.assertEqual(json.loads(identity_json)["pid"], 448)

        await client.close()
        self.assertEqual(manager.closed_sessions, ["session-448"])

    async def test_closed_client_rejects_new_session(self):
        manager = FakeNativeManager(SparseMemory())
        client = DiscoveredClient(manager, descriptor("client-a", 448))
        await client.attach_telemetry()
        client._mark_closed()

        await client.close()
        self.assertEqual(manager.closed_sessions, ["session-448"])
        with self.assertRaisesRegex(RuntimeError, "has closed"):
            await client.attach_telemetry()

    async def test_identity_change_discards_the_existing_session(self):
        manager = FakeNativeManager(SparseMemory())
        client = DiscoveredClient(manager, descriptor("client-a", 448))
        await client.attach_telemetry()

        changed = descriptor("client-a", 448)
        changed["process"]["identity"]["creation_time_100ns"] = "9999"
        client._update(changed)
        await asyncio.sleep(0)
        await client.attach_telemetry()

        self.assertEqual(manager.closed_sessions, ["session-448"])
        self.assertEqual(len(manager.open_calls), 2)

    async def test_mismatched_descriptor_identity_is_rejected_before_attach(self):
        manager = FakeNativeManager(SparseMemory())
        invalid = descriptor("client-a", 448)
        invalid["process"]["identity"]["pid"] = 544
        client = DiscoveredClient(manager, invalid)

        with self.assertRaisesRegex(ValueError, "matching process identity"):
            await client.attach_telemetry()
        self.assertEqual(manager.open_calls, [])

    async def test_close_during_attach_closes_the_late_opened_session(self):
        manager = BlockingOpenNativeManager(SparseMemory())
        client = DiscoveredClient(manager, descriptor("client-a", 448))
        attaching = asyncio.create_task(client.attach_telemetry())

        self.assertTrue(
            await asyncio.to_thread(manager.open_started.wait, 1),
            "the native open_process call did not start",
        )
        client._mark_closed()
        manager.allow_open.set()

        with self.assertRaisesRegex(RuntimeError, "closed while"):
            await attaching
        self.assertEqual(manager.closed_sessions, ["session-448"])

    async def test_handler_waits_for_retired_client_session_cleanup(self):
        class DiscoveryManager(FakeNativeManager):
            def __init__(self):
                super().__init__(SparseMemory())
                self.process_open = True
                self.snapshots = iter(
                    (
                        [descriptor("client-a", 448)],
                        [],
                    )
                )

            def list_clients(self):
                return {"clients": next(self.snapshots)}

            def process_status(self, session_id):
                if not self.process_open:
                    raise FakeProcessError("fixture process closed")
                return super().process_status(session_id)

        manager = DiscoveryManager()
        handler = ClientHandler(agent_manager=manager)
        client = handler.get_new_clients()[0]
        await client.attach_telemetry()
        manager.process_open = False

        self.assertEqual(handler.remove_dead_clients(), [client])
        await handler.close()

        self.assertEqual(manager.closed_sessions, ["session-448"])


class LiveAcceptanceReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_unavailable_required_field_cannot_report_acceptance(self):
        native_stub = SimpleNamespace(AgentManager=object)
        script_path = REPOSITORY_ROOT / "scripts" / "test-deimos-telemetry-live.py"
        spec = importlib.util.spec_from_file_location(
            "deimos_telemetry_live_acceptance",
            script_path,
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"deimos_native": native_stub}):
            spec.loader.exec_module(module)

        class Manager:
            stopped = False

            def start(self):
                return {"state": "ready"}

            def capabilities(self):
                return sorted(module.REQUIRED_CAPABILITIES)

            def stop(self, reason):
                del reason
                self.stopped = True

        class Snapshot:
            def to_dict(self):
                return {
                    "client_id": "client-a",
                    "complete": False,
                    "fields": {
                        "zone": {
                            "available": False,
                            "error": {
                                "code": "signature_mismatch",
                                "message": "Signature mismatch",
                            },
                        }
                    },
                }

        class Client:
            client_id = "client-a"

            async def telemetry_snapshot(self):
                return Snapshot()

        class Handler:
            closed = False

            def __init__(self):
                self.client = Client()

            def get_new_clients(self):
                return [self.client]

            def remove_dead_clients(self):
                return []

            def get_ordered_clients(self):
                return [self.client]

            async def close(self):
                self.closed = True

        manager = Manager()
        handler = Handler()
        module.deimos_native = SimpleNamespace(
            AgentManager=lambda *args, **kwargs: manager
        )
        module.ClientHandler = lambda **kwargs: handler
        options = SimpleNamespace(
            bottle="/bottle",
            wine="/wine",
            agent="/agent.exe",
            wineserver=None,
            wine_arg=[],
            env=[],
            wrapper_manages_wine_loader=True,
            samples=1,
            interval=0,
            require_field=["zone"],
            keep_agent=False,
        )

        report, exit_code = await module.capture(options)

        self.assertTrue(report["capture_completed"])
        self.assertFalse(report["acceptance"]["passed"])
        self.assertFalse(report["acceptance"]["full_snapshot_parity"])
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            report["validation"]["unavailable_required_fields"][0]["field"],
            "zone",
        )
        self.assertTrue(handler.closed)
        self.assertTrue(manager.stopped)


@unittest.skipIf(sys.platform == "win32", "macOS/Linux import isolation only")
class NonWindowsTelemetryImportTests(unittest.TestCase):
    def test_telemetry_import_does_not_load_windows_only_modules(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(WIZWALKER_ROOT)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "from wizwalker import ReadOnlyTelemetryReader; "
                    "assert 'pymem' not in sys.modules; "
                    "assert 'winreg' not in sys.modules; "
                    "assert 'wizwalker.utils' not in sys.modules; "
                    "print(ReadOnlyTelemetryReader.__name__)"
                ),
            ],
            env=environment,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "ReadOnlyTelemetryReader")


if __name__ == "__main__":
    unittest.main()
