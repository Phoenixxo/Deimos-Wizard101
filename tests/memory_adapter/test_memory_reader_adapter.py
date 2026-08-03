from __future__ import annotations

import inspect
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WIZWALKER_ROOT = REPOSITORY_ROOT / "libs" / "wizwalker"

if str(WIZWALKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WIZWALKER_ROOT))

from wizwalker import (  # noqa: E402
    AddressOutOfRange,
    ClientClosedError,
    DeimosNativeMemoryBackend,
    MemoryReadError,
    MemoryReader,
    MemoryWriteError,
    PatternFailed,
    PatternMultipleResults,
    Primitive,
    UnsupportedMemoryOperation,
)
from wizwalker.memory.backends import PymemMemoryBackend  # noqa: E402
from wizwalker.memory.memory_reader import _legacy_pattern_to_signature  # noqa: E402


class FakePymemReadError(Exception):
    pass


class FakePymemWriteError(Exception):
    pass


FAKE_PYMEM = SimpleNamespace(
    exception=SimpleNamespace(
        MemoryReadError=FakePymemReadError,
        MemoryWriteError=FakePymemWriteError,
    )
)


class FakeProcess:
    process_handle = 77

    def __init__(self):
        self.memory = {}
        self.writes = []
        self.freed = None
        self.started = None
        self.read_thread = None

    def read_bytes(self, address, size):
        self.read_thread = threading.get_ident()
        value = self.memory[address]
        return value[:size]

    def write_bytes(self, address, value, size):
        self.writes.append((address, value, size))
        self.memory[address] = value

    def allocate(self, size):
        return 0xABC000 + size

    def free(self, address):
        self.freed = address

    def start_thread(self, address):
        self.started = address


class FakeDeimosNativeError(Exception):
    pass


class FakeProcessError(FakeDeimosNativeError):
    def __init__(self, message="process closed", *, code="process_exited"):
        super().__init__(message)
        self.code = code


class FakeNativeMemoryError(FakeDeimosNativeError):
    def __init__(self, message="memory read failed", *, code="memory_read_failed"):
        super().__init__(message)
        self.code = code


class FakeProtocolError(FakeDeimosNativeError):
    def __init__(
        self,
        message="protocol failure",
        *,
        code="invalid_request",
        technical_message=None,
    ):
        super().__init__(message)
        self.code = code
        self.technical_message = technical_message or message


FAKE_NATIVE = SimpleNamespace(
    DeimosNativeError=FakeDeimosNativeError,
    ProcessError=FakeProcessError,
    MemoryError=FakeNativeMemoryError,
)


class FakeAgentManager:
    def __init__(self):
        self.state = "open"
        self.status_error = None
        self.status_thread = None
        self.read_result = b"\x48\x8b\x01\x02"
        self.read_error = None
        self.read_errors = {}
        self.short_reads = set()
        self.read_sizes = []
        self.read_thread = None
        self.write_error = None
        self.writes = []
        self.write_thread = None
        self.memory_segments = [
            (0x140001000, self.read_result),
        ]
        self.regions = [
            {
                "base_address": "0x140001000",
                "size": len(self.read_result),
                "protection": "read_only",
            }
        ]
        self.modules = [
            {
                "name": "WizardGraphicalClient.exe",
                "base_address": "0x140000000",
                "executable_path": (
                    "C:\\ProgramData\\KingsIsle Entertainment\\Wizard101\\Bin\\"
                    "WizardGraphicalClient.exe"
                ),
                "size": 57712640,
            },
            {
                "name": "user32.dll",
                "base_address": "0x7ffb00000000",
                "executable_path": "C:\\windows\\system32\\user32.dll",
                "size": 123456,
            },
        ]

    def process_status(self, session_id):
        self.status_thread = threading.get_ident()
        if self.status_error is not None:
            raise self.status_error
        return {"session_id": session_id, "state": self.state}

    def read_memory(self, session_id, address, size):
        self.read_thread = threading.get_ident()
        self.read_sizes.append(size)
        numeric_address = int(address, 0)
        if self.read_error is not None:
            raise self.read_error
        if numeric_address in self.read_errors:
            raise self.read_errors[numeric_address]

        for base_address, data in self.memory_segments:
            offset = numeric_address - base_address
            if 0 <= offset and offset + size <= len(data):
                result = data[offset : offset + size]
                if numeric_address in self.short_reads:
                    return result[:-1]
                return result

        raise FakeNativeMemoryError(
            f"unmapped fake read at {address}",
            code="memory_read_failed",
        )

    def write_memory(self, session_id, address, value):
        self.write_thread = threading.get_ident()
        if self.write_error is not None:
            raise self.write_error
        self.writes.append((session_id, address, bytes(value)))

    def list_modules(self, session_id):
        return {"session_id": session_id, "modules": self.modules}

    def memory_regions(self, session_id):
        return {"session_id": session_id, "regions": self.regions}

    def map_memory(self, base_address, data, *, protection="read_only"):
        self.memory_segments = [(base_address, data)]
        self.regions = [
            {
                "base_address": hex(base_address),
                "size": len(data),
                "protection": protection,
            }
        ]


class MemoryReaderApiShape(unittest.TestCase):
    def test_public_methods_keep_their_async_contract_and_arguments(self):
        expected = {
            "is_running": (
                (("self", "POSITIONAL_OR_KEYWORD", "<required>"),),
                False,
            ),
            "run_in_executor": (
                (
                    ("func", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("args", "VAR_POSITIONAL", "<required>"),
                    ("kwargs", "VAR_KEYWORD", "<required>"),
                ),
                True,
            ),
            "pattern_scan": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("pattern", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("module", "KEYWORD_ONLY", "None"),
                    ("return_multiple", "KEYWORD_ONLY", "False"),
                ),
                True,
            ),
            "get_address_from_symbol": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("module_name", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("symbol_name", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("module_dir", "KEYWORD_ONLY", "None"),
                    ("force_reload", "KEYWORD_ONLY", "False"),
                ),
                True,
            ),
            "allocate": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("size", "POSITIONAL_OR_KEYWORD", "<required>"),
                ),
                True,
            ),
            "free": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("address", "POSITIONAL_OR_KEYWORD", "<required>"),
                ),
                True,
            ),
            "start_thread": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("address", "POSITIONAL_OR_KEYWORD", "<required>"),
                ),
                True,
            ),
            "read_bytes": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("address", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("size", "POSITIONAL_OR_KEYWORD", "<required>"),
                ),
                True,
            ),
            "write_bytes": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("address", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("value", "POSITIONAL_OR_KEYWORD", "<required>"),
                ),
                True,
            ),
            "read_typed": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("address", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("data_type", "POSITIONAL_OR_KEYWORD", "<required>"),
                ),
                True,
            ),
            "write_typed": (
                (
                    ("self", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("address", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("value", "POSITIONAL_OR_KEYWORD", "<required>"),
                    ("data_type", "POSITIONAL_OR_KEYWORD", "<required>"),
                ),
                True,
            ),
        }

        def shape(method):
            return tuple(
                (
                    parameter.name,
                    parameter.kind.name,
                    (
                        "<required>"
                        if parameter.default is inspect.Parameter.empty
                        else repr(parameter.default)
                    ),
                )
                for parameter in inspect.signature(method).parameters.values()
            )

        for name, (parameters, is_async) in expected.items():
            method = getattr(MemoryReader, name)
            self.assertEqual(shape(method), parameters, name)
            self.assertEqual(inspect.iscoroutinefunction(method), is_async, name)


class PatternConversionTests(unittest.TestCase):
    def test_regex_escape_round_trips_every_literal_byte(self):
        try:
            regex_module = __import__("regex")
        except ImportError:
            import re as regex_module

        literal = bytes(range(256))
        escaped = regex_module.escape(literal)
        signature = _legacy_pattern_to_signature(escaped)
        converted = bytes(int(token, 16) for token in signature.split())

        self.assertEqual(converted, literal)
        self.assertNotIn("??", signature.split())

    def test_semantic_alphanumeric_escapes_are_rejected(self):
        for pattern in (rb"\d", rb"\s", rb"\w", rb"\n", rb"\1"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "semantic regex escape"):
                    _legacy_pattern_to_signature(pattern)


class PymemCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.process = FakeProcess()
        self.reader = MemoryReader(self.process)
        self.pymem_patch = patch.object(
            PymemMemoryBackend,
            "_pymem",
            return_value=FAKE_PYMEM,
        )
        self.pymem_patch.start()
        self.addCleanup(self.pymem_patch.stop)

    async def test_legacy_constructor_and_primitive_encoding_are_preserved(self):
        self.assertIs(self.reader.process, self.process)
        self.process.memory[0x1000] = Primitive.int32.value.pack(42)
        event_loop_thread = threading.get_ident()

        self.assertEqual(await self.reader.read_typed(0x1000, Primitive.int32), 42)
        await self.reader.write_typed(0x2000, 19, Primitive.uint16)

        self.assertEqual(self.process.writes[-1], (0x2000, b"\x13\x00", 2))
        self.assertNotEqual(self.process.read_thread, event_loop_thread)

    async def test_legacy_mutation_calls_remain_available(self):
        self.assertEqual(await self.reader.allocate(16), 0xABC010)
        await self.reader.free(0x1234)
        await self.reader.start_thread(0x5678)

        self.assertEqual(self.process.freed, 0x1234)
        self.assertEqual(self.process.started, 0x5678)

    async def test_address_and_pymem_errors_keep_wizwalker_mappings_and_causes(self):
        with self.assertRaises(AddressOutOfRange):
            await self.reader.read_bytes(0, 1)

        read_error = FakePymemReadError("read failed")
        self.process.read_bytes = MagicMock(side_effect=read_error)
        with patch.object(self.reader, "is_running", return_value=True):
            with self.assertRaises(MemoryReadError) as raised:
                await self.reader.read_bytes(0x1000, 4)
        self.assertIs(raised.exception.__cause__, read_error)

        write_error = FakePymemWriteError("write failed")
        self.process.write_bytes = MagicMock(side_effect=write_error)
        with patch.object(self.reader, "is_running", return_value=False):
            with self.assertRaises(ClientClosedError) as raised:
                await self.reader.write_bytes(0x1000, b"x")
        self.assertIs(raised.exception.__cause__, write_error)

    async def test_failed_status_probe_does_not_mask_original_pymem_error(self):
        read_error = FakePymemReadError("original read failure")
        self.process.read_bytes = MagicMock(side_effect=read_error)

        with patch.object(
            self.reader._backend,
            "is_running",
            side_effect=RuntimeError("status probe failed"),
        ):
            with self.assertRaises(MemoryReadError) as raised:
                await self.reader.read_bytes(0x1000, 4)

        self.assertIs(raised.exception.__cause__, read_error)

        write_error = FakePymemWriteError("original write failure")
        self.process.write_bytes = MagicMock(side_effect=write_error)
        with patch.object(
            self.reader._backend,
            "is_running",
            side_effect=RuntimeError("status probe failed"),
        ):
            with self.assertRaises(MemoryWriteError) as raised:
                await self.reader.write_bytes(0x1000, b"x")

        self.assertIs(raised.exception.__cause__, write_error)

    async def test_legacy_pattern_shapes_and_exceptions_are_preserved(self):
        self.reader._scan_all = MagicMock(return_value=[0x10, 0x20])

        with self.assertRaises(PatternMultipleResults):
            await self.reader.pattern_scan(b"abc")
        self.assertEqual(
            await self.reader.pattern_scan(b"abc", return_multiple=True),
            [0x10, 0x20],
        )

        self.reader._scan_all = MagicMock(return_value=[])
        with self.assertRaises(PatternFailed):
            await self.reader.pattern_scan(b"missing")

        self.reader._backend.module = MagicMock(return_value=None)
        with self.assertRaisesRegex(ValueError, "missing.dll module not found"):
            await self.reader.pattern_scan(b"abc", module="missing.dll")


class DeimosNativeBackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.manager = FakeAgentManager()
        self.backend = DeimosNativeMemoryBackend(
            self.manager,
            "session-1",
            native_module=FAKE_NATIVE,
        )
        self.reader = MemoryReader(self.backend)

    async def test_reads_and_typed_decoding_use_the_agent_session_off_loop(self):
        self.manager.map_memory(
            0x140001000,
            Primitive.uint32.value.pack(0x12345678),
        )
        event_loop_thread = threading.get_ident()

        value = await self.reader.read_typed(0x140001000, Primitive.uint32)

        self.assertEqual(value, 0x12345678)
        self.assertNotEqual(self.manager.read_thread, event_loop_thread)

    async def test_scans_translate_legacy_exact_and_wildcard_patterns(self):
        self.manager.map_memory(
            0x140001000,
            b"\x48\x8B\x01\x02\x90",
        )
        result = await self.reader.pattern_scan(
            rb"\x48\x8B..\x90",
            module="WizardGraphicalClient.exe",
        )

        self.assertEqual(result, 0x140001000)

        self.manager.map_memory(0x140001000, b"\x48\x8B\x01\x90")
        self.assertEqual(
            await self.reader.pattern_scan(b"\x48\x8B.\x90"),
            0x140001000,
        )

    async def test_scan_result_shapes_and_existing_exceptions_are_preserved(self):
        self.manager.map_memory(0x1000, b"\x00")
        with self.assertRaises(PatternFailed):
            await self.reader.pattern_scan(b"\x90")

        self.manager.map_memory(0x1000, b"\x90\x00\x90")
        with self.assertRaises(PatternMultipleResults):
            await self.reader.pattern_scan(b"\x90")

        self.assertEqual(
            await self.reader.pattern_scan(b"\x90", return_multiple=True),
            [0x1000, 0x1002],
        )

    async def test_scans_do_not_match_across_adjacent_memory_regions(self):
        self.manager.memory_segments = [
            (0x1000, b"\x41"),
            (0x1001, b"\x42"),
        ]
        self.manager.regions = [
            {
                "base_address": "0x1000",
                "size": 1,
                "protection": "read_only",
            },
            {
                "base_address": "0x1001",
                "size": 1,
                "protection": "read_only",
            },
        ]

        with self.assertRaises(PatternFailed):
            await self.reader.pattern_scan(b"\x41\x42", return_multiple=True)

    async def test_scans_preserve_non_overlapping_regex_results(self):
        self.manager.map_memory(0x2000, b"\x41\x41\x41")

        self.assertEqual(await self.reader.pattern_scan(b"\x41\x41"), 0x2000)
        self.assertEqual(
            await self.reader.pattern_scan(
                b"\x41\x41",
                return_multiple=True,
            ),
            [0x2000],
        )

    async def test_process_single_scan_stops_after_first_matching_region(self):
        self.manager.memory_segments = [
            (0x3000, b"\x90"),
            (0x4000, b"\x90"),
        ]
        self.manager.regions = [
            {
                "base_address": "0x3000",
                "size": 1,
                "protection": "read_only",
            },
            {
                "base_address": "0x4000",
                "size": 1,
                "protection": "read_only",
            },
        ]

        self.assertEqual(await self.reader.pattern_scan(b"\x90"), 0x3000)
        self.assertEqual(
            await self.reader.pattern_scan(b"\x90", return_multiple=True),
            [0x3000, 0x4000],
        )

        self.manager.modules[0]["base_address"] = "0x3000"
        self.manager.modules[0]["size"] = 0x1001
        with self.assertRaises(PatternMultipleResults):
            await self.reader.pattern_scan(
                b"\x90",
                module="WizardGraphicalClient.exe",
            )

    async def test_scans_exclude_legacy_incompatible_protections(self):
        self.manager.memory_segments = [
            (0x5000, b"\x00"),
            (0x6000, b"\x90"),
            (0x7000, b"\x90"),
        ]
        self.manager.regions = [
            {
                "base_address": "0x5000",
                "size": 1,
                "protection": "read_only",
            },
            {
                "base_address": "0x6000",
                "size": 1,
                "protection": "copy_on_write",
            },
            {
                "base_address": "0x7000",
                "size": 1,
                "protection": "execute_copy_on_write",
            },
        ]

        with self.assertRaises(PatternFailed):
            await self.reader.pattern_scan(b"\x90")
        with self.assertRaises(PatternFailed):
            await self.reader.pattern_scan(b"\x90", return_multiple=True)

    async def test_streaming_scan_returns_more_than_4096_matches(self):
        match_count = 5001
        self.manager.map_memory(0x5000, b"\x90" * match_count)

        matches = await self.reader.pattern_scan(
            b"\x90",
            return_multiple=True,
        )

        self.assertEqual(len(matches), match_count)
        self.assertEqual(matches[0], 0x5000)
        self.assertEqual(matches[-1], 0x5000 + match_count - 1)
        self.assertTrue(all(size <= 64 * 1024 for size in self.manager.read_sizes))

    async def test_streaming_scan_retains_and_deduplicates_cross_chunk_match(self):
        base_address = 0x200000
        boundary = 64 * 1024
        pattern = b"\xDE\xAD\xBE\xEF\x01\x02"
        match_offset = boundary - 3
        data = bytearray(b"\x00" * (boundary + 32))
        data[match_offset : match_offset + len(pattern)] = pattern
        self.manager.map_memory(base_address, bytes(data))

        matches = await self.reader.pattern_scan(
            pattern,
            return_multiple=True,
        )

        self.assertEqual(matches, [base_address + match_offset])
        self.assertGreater(len(self.manager.read_sizes), 1)
        self.assertTrue(all(size <= 64 * 1024 for size in self.manager.read_sizes))

    async def test_streaming_scan_keeps_non_overlap_alignment_across_chunks(self):
        base_address = 0x280000
        data = b"\x41" * ((64 * 1024) + 8)
        self.manager.map_memory(base_address, data)

        matches = await self.reader.pattern_scan(
            b"\x41\x41\x41",
            return_multiple=True,
        )

        self.assertEqual(
            matches,
            [base_address + offset for offset in range(0, len(data) - 2, 3)],
        )

    async def test_streaming_module_scan_is_clipped_to_module_bounds(self):
        base_address = 0x300000
        data = bytearray(b"\x00" * 64)
        data[4] = 0x90
        data[36] = 0x90
        self.manager.map_memory(base_address, bytes(data))
        self.manager.modules[0]["base_address"] = hex(base_address + 32)
        self.manager.modules[0]["size"] = 16

        matches = await self.reader.pattern_scan(
            b"\x90",
            module="WizardGraphicalClient.exe",
            return_multiple=True,
        )

        self.assertEqual(matches, [base_address + 36])

    async def test_variable_length_regex_constructs_fail_before_native_scan(self):
        for pattern in (
            rb"\x48.*\x90",
            rb"\x48.+\x90",
            rb"\x48.{4}\x90",
            rb"(?:\x48)",
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(
                    ValueError,
                    "exact bytes and single-byte",
                ):
                    await self.reader.pattern_scan(pattern)

    async def test_module_symbol_address_uses_native_module_base(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(directory) / "user32.dll"
            module_path.touch()
            self.reader._get_symbols = MagicMock(return_value={"SetCursorPos": 0x1234})

            address = await self.reader.get_address_from_symbol(
                "user32.dll",
                "SetCursorPos",
                module_dir=Path(directory),
            )

        self.assertEqual(address, 0x7FFB00001234)

    async def test_native_process_and_memory_errors_map_with_cause(self):
        process_error = FakeProcessError()
        self.manager.read_error = process_error
        with self.assertRaises(ClientClosedError) as raised:
            await self.reader.read_bytes(0x140001000, 4)
        self.assertIs(raised.exception.__cause__, process_error)

        memory_error = FakeNativeMemoryError()
        self.manager.read_error = memory_error
        with self.assertRaises(MemoryReadError) as raised:
            await self.reader.read_bytes(0x140001000, 4)
        self.assertIs(raised.exception.__cause__, memory_error)

    async def test_streaming_read_failure_never_returns_partial_results(self):
        base_address = 0x400000
        data = b"\x90" * ((64 * 1024) + 8)
        self.manager.map_memory(base_address, data)
        failure = FakeNativeMemoryError("second chunk unreadable")
        self.manager.read_errors[base_address + (64 * 1024)] = failure

        with self.assertRaises(MemoryReadError) as raised:
            await self.reader.pattern_scan(b"\x90", return_multiple=True)

        self.assertIs(raised.exception.__cause__, failure)

    async def test_streaming_short_read_is_an_incomplete_scan(self):
        base_address = 0x410000
        self.manager.map_memory(base_address, b"\x90" * 16)
        self.manager.short_reads.add(base_address)

        with self.assertRaises(MemoryReadError) as raised:
            await self.reader.pattern_scan(b"\x90", return_multiple=True)

        self.assertEqual(raised.exception.code, "memory_incomplete_scan")
        self.assertEqual(raised.exception.details["requested_size"], 16)
        self.assertEqual(raised.exception.details["actual_size"], 15)

    async def test_process_error_codes_map_by_meaning_and_keep_causes(self):
        for code in (
            "process_exited",
            "process_not_found",
            "session_not_found",
        ):
            with self.subTest(code=code):
                error = FakeProcessError(code=code)
                self.manager.read_error = error
                with self.assertRaises(ClientClosedError) as raised:
                    await self.reader.read_bytes(0x140001000, 4)
                self.assertIs(raised.exception.__cause__, error)

        closed = FakeProtocolError(
            technical_message="process session session-1 is closed",
        )
        self.manager.read_error = closed
        with self.assertRaises(ClientClosedError) as raised:
            await self.reader.read_bytes(0x140001000, 4)
        self.assertIs(raised.exception.__cause__, closed)

        for code in ("process_access_denied", "internal"):
            with self.subTest(code=code):
                error = FakeProcessError("operation failed", code=code)
                self.manager.read_error = error
                self.manager.status_error = RuntimeError("status unavailable")
                with self.assertRaises(MemoryReadError) as raised:
                    await self.reader.read_bytes(0x140001000, 4)
                self.assertIs(raised.exception.__cause__, error)

        protocol_error = FakeProtocolError(
            "agent operation failed",
            code="internal",
        )
        self.manager.read_error = protocol_error
        with self.assertRaises(MemoryReadError) as raised:
            await self.reader.read_bytes(0x140001000, 4)
        self.assertIs(raised.exception.__cause__, protocol_error)

    async def test_status_behavior_and_error_probe_are_consistent(self):
        self.manager.status_error = FakeProcessError(code="session_not_found")
        self.assertFalse(self.reader.is_running())

        access_denied = FakeProcessError(code="process_access_denied")
        self.manager.status_error = access_denied
        with self.assertRaises(FakeProcessError) as raised:
            self.reader.is_running()
        self.assertIs(raised.exception, access_denied)

        self.manager.status_error = RuntimeError("status probe failed")
        read_error = FakeNativeMemoryError("original read failure")
        self.manager.read_error = read_error
        event_loop_thread = threading.get_ident()
        with self.assertRaises(MemoryReadError) as raised:
            await self.reader.read_bytes(0x140001000, 4)
        self.assertIs(raised.exception.__cause__, read_error)
        self.assertNotEqual(self.manager.status_thread, event_loop_thread)

    async def test_native_value_writes_use_the_mutation_session_off_loop(self):
        event_loop_thread = threading.get_ident()

        await self.reader.write_bytes(0x140001000, b"\x00\x00\x80\x3f")
        await self.reader.write_typed(0x140001004, 2.5, Primitive.float32)

        self.assertEqual(
            self.manager.writes,
            [
                ("session-1", "0x140001000", b"\x00\x00\x80\x3f"),
                ("session-1", "0x140001004", Primitive.float32.value.pack(2.5)),
            ],
        )
        self.assertNotEqual(self.manager.write_thread, event_loop_thread)

    async def test_native_write_errors_keep_wizwalker_mapping_and_cause(self):
        write_error = FakeNativeMemoryError(
            "write failed",
            code="memory_write_failed",
        )
        self.manager.write_error = write_error

        with self.assertRaises(MemoryWriteError) as raised:
            await self.reader.write_bytes(0x140001000, b"x")

        self.assertIs(raised.exception.__cause__, write_error)

    async def test_native_process_management_mutations_remain_unsupported(self):
        operations = (
            self.reader.allocate(16),
            self.reader.free(0x1000),
            self.reader.start_thread(0x1000),
        )

        for operation in operations:
            with self.assertRaises(UnsupportedMemoryOperation):
                await operation

    async def test_missing_modules_keep_the_legacy_value_error(self):
        with self.assertRaisesRegex(ValueError, "missing.dll module not found"):
            await self.reader.pattern_scan(b"\x90", module="missing.dll")


class ImportIsolationTests(unittest.TestCase):
    def test_backend_selection_is_explicit(self):
        process = FakeProcess()
        legacy = MemoryReader(process)
        native = DeimosNativeMemoryBackend(
            FakeAgentManager(),
            "session-1",
            native_module=FAKE_NATIVE,
        )
        rust = MemoryReader(native)

        self.assertIsInstance(legacy._backend, PymemMemoryBackend)
        self.assertIs(rust._backend, native)

    @unittest.skipIf(sys.platform == "win32", "macOS/Linux import isolation only")
    def test_importing_rust_adapter_does_not_import_pymem(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(WIZWALKER_ROOT)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "from wizwalker import DeimosNativeMemoryBackend, MemoryReader; "
                    "assert 'pymem' not in sys.modules; "
                    "print(DeimosNativeMemoryBackend.__name__, MemoryReader.__name__)"
                ),
            ],
            env=environment,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "DeimosNativeMemoryBackend MemoryReader",
        )

    @unittest.skipUnless(
        os.environ.get("DEIMOS_TEST_REAL_NATIVE") == "1",
        "compiled extension contract is enforced by native CI",
    )
    def test_adapter_contract_matches_the_compiled_native_extension(self):
        native = __import__("deimos_native")

        self.assertTrue(issubclass(native.ProcessError, native.DeimosNativeError))
        self.assertTrue(issubclass(native.MemoryError, native.DeimosNativeError))
        for method_name in (
            "list_clients",
            "list_modules",
            "memory_regions",
            "process_status",
            "read_memory",
            "write_memory",
        ):
            self.assertTrue(
                hasattr(native.AgentManager, method_name),
                method_name,
            )

    @unittest.skipUnless(
        sys.platform == "win32",
        "legacy public exports are Windows-only",
    )
    def test_windows_keeps_representative_legacy_public_exports(self):
        import wizwalker
        from wizwalker import memory

        for export_name in ("Client", "ClientHandler", "XYZ"):
            self.assertTrue(hasattr(wizwalker, export_name), export_name)
        for export_name in ("HookHandler", "InstanceFinder", "MemoryObject"):
            self.assertTrue(hasattr(memory, export_name), export_name)


if __name__ == "__main__":
    unittest.main()
