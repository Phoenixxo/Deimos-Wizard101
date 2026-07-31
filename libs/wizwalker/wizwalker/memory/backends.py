from __future__ import annotations

from importlib import import_module
from typing import Any

from wizwalker.errors import UnsupportedMemoryOperation


_MAX_READ_SIZE = 64 * 1024
_MAX_SIGNATURE_SIZE = 4096
_LEGACY_SCAN_PROTECTIONS = frozenset(
    (
        "execute_read",
        "execute_read_write",
        "read_only",
        "read_write",
    )
)
_CLOSED_PROCESS_CODES = frozenset(
    (
        "process_exited",
        "process_not_found",
        "session_not_found",
    )
)


class IncompleteMemoryScanError(Exception):
    """A scan could not inspect every advertised readable byte."""

    code = "memory_incomplete_scan"

    def __init__(self, message: str, *, details: Any):
        super().__init__(message)
        self.details = details


class MemoryBackend:
    """Synchronous process-memory contract used by :class:`MemoryReader`."""

    supports_mutation = False
    process: Any

    def is_running(self) -> bool:
        raise NotImplementedError

    def read_bytes(self, address: int, size: int) -> bytes:
        raise NotImplementedError

    def module_base(self, module_name: str) -> int | None:
        raise NotImplementedError

    def is_process_error(self, error: BaseException) -> bool:
        return False

    def is_closed_process_error(self, error: BaseException) -> bool:
        return False

    def is_read_error(self, error: BaseException) -> bool:
        return False

    def is_operation_error(self, error: BaseException) -> bool:
        return False

    def is_write_error(self, error: BaseException) -> bool:
        return False


class PymemMemoryBackend(MemoryBackend):
    """Compatibility backend around the legacy ``pymem.Pymem`` object."""

    supports_mutation = True

    def __init__(self, process: Any):
        self.process = process

    @staticmethod
    def _pymem():
        # Pymem is intentionally optional and must never be imported merely by
        # importing WizWalker on a non-Windows host.
        pymem = import_module("pymem")
        import_module("pymem.exception")
        import_module("pymem.process")
        return pymem

    def is_running(self) -> bool:
        from wizwalker import utils

        return utils.check_if_process_running(self.process.process_handle)

    def read_bytes(self, address: int, size: int) -> bytes:
        return self.process.read_bytes(address, size)

    def write_bytes(self, address: int, value: bytes) -> None:
        self.process.write_bytes(address, value, len(value))

    def allocate(self, size: int) -> int:
        return self.process.allocate(size)

    def free(self, address: int) -> None:
        self.process.free(address)

    def start_thread(self, address: int) -> None:
        self.process.start_thread(address)

    def module(self, module_name: str):
        pymem = self._pymem()
        return pymem.process.module_from_name(
            self.process.process_handle,
            module_name,
        )

    def module_base(self, module_name: str) -> int | None:
        module = self.module(module_name)
        if module is None:
            return None
        return module.lpBaseOfDll

    def is_read_error(self, error: BaseException) -> bool:
        return isinstance(error, self._pymem().exception.MemoryReadError)

    def is_write_error(self, error: BaseException) -> bool:
        return isinstance(error, self._pymem().exception.MemoryWriteError)


class DeimosNativeMemoryBackend(MemoryBackend):
    """
    Read-only adapter around a ``deimos_native.AgentManager`` session.

    The caller owns the manager and process-session lifecycle. Constructing this
    backend never starts an agent or opens a process implicitly.
    """

    def __init__(
        self,
        manager: Any,
        session_id: str,
        *,
        native_module: Any = None,
    ):
        if not session_id:
            raise ValueError("session_id must not be empty")

        self.manager = manager
        self.session_id = session_id
        self.process = self
        self._native_module = native_module

    supports_core_hooks = True

    def _native(self):
        if self._native_module is None:
            self._native_module = import_module("deimos_native")
        return self._native_module

    def is_running(self) -> bool:
        try:
            status = self.manager.process_status(self.session_id)
        except Exception as error:
            if self.is_closed_process_error(error):
                return False
            raise

        return status.get("state") == "open"

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes(
            self.manager.read_memory(
                self.session_id,
                hex(address),
                size,
            )
        )

    def write_bytes(self, address: int, value: bytes, size: int | None = None) -> None:
        raise UnsupportedMemoryOperation("write")

    def allocate(self, size: int) -> int:
        raise UnsupportedMemoryOperation("allocate")

    def free(self, address: int) -> None:
        raise UnsupportedMemoryOperation("free")

    def start_thread(self, address: int) -> None:
        raise UnsupportedMemoryOperation("remote thread creation")

    def activate_core_hook(self, hook: str) -> dict[str, Any]:
        return self.manager.activate_core_hook(self.session_id, hook)

    def activate_core_hooks(self) -> dict[str, Any]:
        return self.manager.activate_core_hooks(self.session_id)

    def deactivate_core_hook(self, hook: str) -> dict[str, Any]:
        return self.manager.deactivate_core_hook(self.session_id, hook)

    def deactivate_core_hooks(self) -> dict[str, Any]:
        return self.manager.deactivate_core_hooks(self.session_id)

    def heartbeat_core_hooks(self) -> dict[str, Any]:
        return self.manager.heartbeat_core_hooks(self.session_id)

    def read_core_hook_base(self, hook: str) -> int:
        return int(self.manager.read_core_hook_base(self.session_id, hook))

    def scan(
        self,
        signature: str,
        *,
        module_name: str | None,
        return_multiple: bool,
    ) -> list[int]:
        pattern = self._parse_fixed_signature(signature)
        intervals = self._scan_intervals(module_name)
        matches = []
        for start, end in intervals:
            region_matches = self._scan_interval(start, end, pattern)
            matches.extend(region_matches)

            # Legacy process-wide single scans stopped after the first
            # VirtualQuery region containing a match. Module scans and
            # multi-result scans inspected their complete scope.
            if module_name is None and not return_multiple and region_matches:
                break

        return matches

    def _scan_interval(
        self,
        start: int,
        end: int,
        pattern: tuple[int | None, ...],
    ) -> list[int]:
        matches = []
        overlap = len(pattern) - 1
        tail = b""
        next_address = start
        next_non_overlapping_address = start

        while next_address < end:
            read_size = min(_MAX_READ_SIZE, end - next_address)
            chunk = self.read_bytes(next_address, read_size)
            if len(chunk) != read_size:
                raise IncompleteMemoryScanError(
                    "The native backend returned fewer bytes than the "
                    "advertised readable memory range.",
                    details={
                        "address": hex(next_address),
                        "requested_size": read_size,
                        "actual_size": len(chunk),
                        "region_start": hex(start),
                        "region_end": hex(end),
                    },
                )

            window = tail + chunk
            window_address = next_address - len(tail)
            for offset in self._find_matches(window, pattern):
                match_address = window_address + offset
                if (
                    match_address >= next_non_overlapping_address
                    and start <= match_address
                    and match_address + len(pattern) <= end
                ):
                    matches.append(match_address)
                    next_non_overlapping_address = match_address + len(pattern)

            tail = window[-overlap:] if overlap else b""
            next_address += read_size

        return matches

    def module_base(self, module_name: str) -> int | None:
        module = self._module(module_name)
        if module is not None:
            return self._module_bounds(module)[0]
        return None

    def is_process_error(self, error: BaseException) -> bool:
        return isinstance(error, self._native().ProcessError) or (
            self._is_closed_session_invalid_request(error)
        )

    def is_closed_process_error(self, error: BaseException) -> bool:
        code = getattr(error, "code", None)
        return code in _CLOSED_PROCESS_CODES or self._is_closed_session_invalid_request(
            error
        )

    def is_read_error(self, error: BaseException) -> bool:
        return isinstance(error, (self._native().MemoryError, IncompleteMemoryScanError))

    def is_operation_error(self, error: BaseException) -> bool:
        native_error = getattr(self._native(), "DeimosNativeError", None)
        return native_error is not None and isinstance(error, native_error)

    def _module(self, module_name: str):
        response = self.manager.list_modules(self.session_id)
        modules = response.get("modules")
        if not isinstance(modules, list):
            raise IncompleteMemoryScanError(
                "The native backend returned an invalid module list.",
                details={"response": response},
            )
        for module in modules:
            if not isinstance(module, dict) or not isinstance(module.get("name"), str):
                raise IncompleteMemoryScanError(
                    "The native backend returned an invalid module descriptor.",
                    details={"module": module},
                )
            if module["name"].casefold() == module_name.casefold():
                return module
        return None

    def _scan_intervals(self, module_name: str | None) -> list[tuple[int, int]]:
        module_start = None
        module_end = None
        if module_name is not None:
            module = self._module(module_name)
            if module is None:
                raise ValueError(f"{module_name} module not found.")
            module_start, module_end = self._module_bounds(module)

        response = self.manager.memory_regions(self.session_id)
        regions = response.get("regions")
        if not isinstance(regions, list):
            raise IncompleteMemoryScanError(
                "The native backend returned an invalid readable-region list.",
                details={"response": response},
            )
        intervals = []
        for region in regions:
            try:
                start = int(region["base_address"], 0)
                end = start + int(region["size"])
                protection = region["protection"]
            except (KeyError, TypeError, ValueError) as error:
                raise IncompleteMemoryScanError(
                    "The native backend returned an invalid readable memory region.",
                    details={"region": region},
                ) from error

            if protection not in _LEGACY_SCAN_PROTECTIONS:
                continue
            if end <= start:
                continue
            if module_start is not None:
                start = max(start, module_start)
                end = min(end, module_end)
            if start < end:
                intervals.append((start, end))

        intervals.sort()
        merged = []
        for start, end in intervals:
            if merged and start < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    @staticmethod
    def _module_bounds(module: dict[str, Any]) -> tuple[int, int]:
        try:
            start = int(module["base_address"], 0)
            end = start + int(module["size"])
        except (KeyError, TypeError, ValueError) as error:
            raise IncompleteMemoryScanError(
                "The native backend returned invalid module bounds.",
                details={"module": module},
            ) from error
        if end <= start:
            raise IncompleteMemoryScanError(
                "The native backend returned empty module bounds.",
                details={"module": module},
            )
        return start, end

    @staticmethod
    def _parse_fixed_signature(signature: str) -> tuple[int | None, ...]:
        pattern = []
        for token in signature.split():
            if token == "??":
                pattern.append(None)
            else:
                try:
                    value = int(token, 16)
                except ValueError as error:
                    raise ValueError(
                        f"Invalid fixed memory signature token {token!r}."
                    ) from error
                if len(token) != 2 or not 0 <= value <= 0xFF:
                    raise ValueError(
                        f"Invalid fixed memory signature token {token!r}."
                    )
                pattern.append(value)

        if not pattern:
            raise ValueError("Memory signature must not be empty.")
        if len(pattern) > _MAX_SIGNATURE_SIZE:
            raise ValueError(
                f"Memory signature exceeds the {_MAX_SIGNATURE_SIZE}-byte safety limit."
            )
        return tuple(pattern)

    @staticmethod
    def _find_matches(
        data: bytes,
        pattern: tuple[int | None, ...],
    ):
        width = len(pattern)
        if len(data) < width:
            return

        anchor = next(
            ((index, value) for index, value in enumerate(pattern) if value is not None),
            None,
        )
        if anchor is None:
            yield from range(len(data) - width + 1)
            return

        anchor_index, anchor_value = anchor
        anchor_byte = bytes((anchor_value,))
        search_from = anchor_index
        while True:
            found = data.find(anchor_byte, search_from)
            if found < 0:
                return
            start = found - anchor_index
            if start >= 0 and start + width <= len(data):
                if all(
                    expected is None or data[start + offset] == expected
                    for offset, expected in enumerate(pattern)
                ):
                    yield start
            search_from = found + 1

    @staticmethod
    def _is_closed_session_invalid_request(error: BaseException) -> bool:
        if getattr(error, "code", None) != "invalid_request":
            return False
        technical_message = str(
            getattr(error, "technical_message", str(error))
        ).casefold()
        return "process session" in technical_message and "is closed" in technical_message
