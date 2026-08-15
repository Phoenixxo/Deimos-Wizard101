from __future__ import annotations

from contextlib import contextmanager
from importlib import import_module
from typing import Any

from wizwalker.errors import PatternMultipleResults, UnsupportedMemoryOperation


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
    supports_write = False
    supports_allocation = False
    supports_remote_thread = False
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
    supports_write = True
    supports_allocation = True
    supports_remote_thread = True

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
    Adapter around a mutation-capable ``deimos_native.AgentManager`` session.

    The caller owns the manager and process-session lifecycle. Constructing this
    backend never starts an agent or opens a process implicitly.
    """

    def __init__(
        self,
        manager: Any,
        session_id: str,
        *,
        native_module: Any = None,
        expected_instance_id: str | None = None,
        generation_fence: Any = None,
        generation_token: object = None,
        generation_context: Any = None,
    ):
        if not session_id:
            raise ValueError("session_id must not be empty")

        self.manager = manager
        self.session_id = session_id
        self.process = self
        self._native_module = native_module
        self.expected_instance_id = expected_instance_id
        self.generation_fence = generation_fence
        self.generation_token = generation_token
        self.generation_context = generation_context
        self.supports_write = hasattr(manager, "write_memory")
        self.supports_feature_hooks = all(
            hasattr(manager, name)
            for name in (
                "activate_feature_hook",
                "deactivate_feature_hook",
                "heartbeat_feature_hooks",
                "read_feature_hook_export",
                "set_feature_mouse_position",
                "feature_teleport",
                "feature_send_chat",
                "feature_add_buddy",
            )
        )

    supports_core_hooks = True

    def _native(self):
        if self._native_module is None:
            self._native_module = import_module("deimos_native")
        return self._native_module

    def _call_manager(
        self, call, *args, allow_retired_result: bool = False, **kwargs
    ):
        if self.generation_fence is None:
            raise RuntimeError(
                "Native memory work requires an explicitly bound manager-generation fence."
            )
        if not isinstance(self.expected_instance_id, str):
            raise RuntimeError(
                "Native memory work cannot verify its owning helper generation."
            )
        if self.generation_token is None:
            raise RuntimeError(
                "Native memory work requires an explicit host generation token."
            )
        return self.generation_fence.call(
            self.generation_token,
            call,
            *args,
            allow_retired_result=allow_retired_result,
            **kwargs,
        )

    @contextmanager
    def _result_operation(self):
        if self.generation_fence is None or self.generation_token is None:
            raise RuntimeError(
                "Native memory work requires an explicitly bound host generation."
            )
        with self.generation_fence.operation(self.generation_token):
            yield
            self.generation_fence.call(self.generation_token, lambda: None)

    @contextmanager
    def generation_operation(self):
        """Lease this host epoch across an async caller's full transaction."""
        with self._result_operation():
            yield

    def _call_cleanup_manager(self, call, *args, **kwargs):
        """Use only native RPCs that atomically check expected helper identity."""
        if self.generation_context is None:
            raise RuntimeError(
                "Native hook cleanup requires manager-scoped cleanup admission."
            )
        return self.generation_context.call_cleanup(
            self.expected_instance_id,
            call,
            *args,
            **kwargs,
        )

    def require_current(self) -> None:
        """Reject async delivery of a result from a retired host epoch."""
        if self.generation_fence is None or self.generation_token is None:
            raise RuntimeError(
                "Native memory work requires an explicitly bound host generation."
            )
        self.generation_fence.call(self.generation_token, lambda: None)

    def is_running(self) -> bool:
        with self._result_operation():
            try:
                status = self._call_manager(self.manager.process_status, self.session_id)
            except Exception as error:
                if self.is_closed_process_error(error):
                    return False
                raise

            return status.get("state") == "open"

    def read_bytes(self, address: int, size: int) -> bytes:
        with self._result_operation():
            return bytes(
                self._call_manager(
                    self.manager.read_memory,
                    self.session_id,
                    hex(address),
                    size,
                )
            )

    def write_bytes(self, address: int, value: bytes, size: int | None = None) -> None:
        if size is not None and size != len(value):
            raise ValueError("size must match the number of bytes being written")
        self._call_manager(
            self.manager.write_memory,
            self.session_id,
            hex(address),
            bytes(value),
        )

    def allocate(self, size: int) -> int:
        raise UnsupportedMemoryOperation("allocate")

    def free(self, address: int) -> None:
        raise UnsupportedMemoryOperation("free")

    def start_thread(self, address: int) -> None:
        raise UnsupportedMemoryOperation("remote thread creation")

    def activate_core_hook(self, hook: str) -> dict[str, Any]:
        return self._call_manager(self.manager.activate_core_hook, self.session_id, hook)

    def activate_core_hooks(self) -> dict[str, Any]:
        return self._call_manager(self.manager.activate_core_hooks, self.session_id)

    def deactivate_core_hook(self, hook: str) -> dict[str, Any]:
        cleanup = getattr(
            self.manager,
            "deactivate_core_hook_for_instance",
            None,
        )
        if not isinstance(self.expected_instance_id, str) or not callable(cleanup):
            raise RuntimeError(
                "Native core-hook cleanup cannot verify the owning helper generation."
            )
        return self._call_cleanup_manager(
            cleanup,
            self.session_id,
            hook,
            self.expected_instance_id,
        )

    def deactivate_core_hooks(self) -> dict[str, Any]:
        cleanup = getattr(
            self.manager,
            "deactivate_core_hooks_for_instance",
            None,
        )
        if not isinstance(self.expected_instance_id, str) or not callable(cleanup):
            raise RuntimeError(
                "Native core-hook cleanup cannot verify the owning helper generation."
            )
        return self._call_cleanup_manager(
            cleanup,
            self.session_id,
            self.expected_instance_id,
        )

    def heartbeat_core_hooks(self) -> dict[str, Any]:
        return self._call_manager(self.manager.heartbeat_core_hooks, self.session_id)

    def read_core_hook_base(self, hook: str) -> int:
        with self._result_operation():
            return int(
                self._call_manager(
                    self.manager.read_core_hook_base,
                    self.session_id,
                    hook,
                )
            )

    def activate_feature_hook(self, hook: str) -> dict[str, Any]:
        return self._call_manager(self.manager.activate_feature_hook, self.session_id, hook)

    def deactivate_feature_hook(self, hook: str) -> dict[str, Any]:
        cleanup = getattr(
            self.manager,
            "deactivate_feature_hook_for_instance",
            None,
        )
        if not isinstance(self.expected_instance_id, str) or not callable(cleanup):
            raise RuntimeError(
                "Native feature-hook cleanup cannot verify the owning helper generation."
            )
        return self._call_cleanup_manager(
            cleanup,
            self.session_id,
            hook,
            self.expected_instance_id,
        )

    def heartbeat_feature_hooks(self) -> dict[str, Any]:
        return self._call_manager(self.manager.heartbeat_feature_hooks, self.session_id)

    def read_feature_hook_export(self, export: str) -> int:
        with self._result_operation():
            return int(
                self._call_manager(
                    self.manager.read_feature_hook_export,
                    self.session_id,
                    export,
                )
            )

    def set_feature_mouse_position(self, x: int, y: int) -> dict[str, Any]:
        return self._call_manager(
            self.manager.set_feature_mouse_position, self.session_id, x, y
        )

    def feature_teleport(
        self,
        object_address: int,
        position: tuple[float, float, float],
        *,
        wait_on_inuse: bool,
        wait_timeout_ms: int,
        purge_after_timeout: bool,
        purge_timeout_ms: int,
    ) -> dict[str, Any]:
        return self._call_manager(
            self.manager.feature_teleport,
            self.session_id,
            hex(object_address),
            position,
            wait_on_inuse=wait_on_inuse,
            wait_timeout_ms=wait_timeout_ms,
            purge_after_timeout=purge_after_timeout,
            purge_timeout_ms=purge_timeout_ms,
        )

    def feature_send_chat(self, message: str, target_gid: int) -> dict[str, Any]:
        return self._call_manager(
            self.manager.feature_send_chat, self.session_id, message, target_gid
        )

    def feature_add_buddy(self, target_gid: int) -> dict[str, Any]:
        return self._call_manager(
            self.manager.feature_add_buddy, self.session_id, target_gid
        )

    def scan(
        self,
        signature: str,
        *,
        module_name: str | None,
        return_multiple: bool,
    ) -> list[int]:
        with self._result_operation():
            return self._scan_bound(
                signature,
                module_name=module_name,
                return_multiple=return_multiple,
            )

    def _scan_bound(
        self,
        signature: str,
        *,
        module_name: str | None,
        return_multiple: bool,
    ) -> list[int]:
        # The agent can enforce uniqueness efficiently, but its result count is
        # bounded. Keep legacy streaming for process scans and callers that need
        # every match so their historical result semantics remain unchanged.
        if (
            module_name is not None
            and not return_multiple
            and hasattr(self.manager, "scan_memory")
        ):
            try:
                response = self._call_manager(
                    self.manager.scan_memory,
                    self.session_id,
                    signature,
                    module_name=module_name,
                    required=False,
                    unique=True,
                    max_matches=2,
                )
            except Exception as error:
                if getattr(error, "code", None) == "memory_ambiguous_match":
                    raise PatternMultipleResults(
                        f"Got multiple results for signature {signature}"
                    ) from error
                raise

            matches = response.get("matches") if isinstance(response, dict) else None
            if not isinstance(matches, list):
                raise IncompleteMemoryScanError(
                    "The native backend returned an invalid memory scan response.",
                    details={"response_type": type(response).__name__},
                )
            try:
                return [
                    int(address, 0) if isinstance(address, str) else int(address)
                    for address in matches
                ]
            except (TypeError, ValueError) as error:
                raise IncompleteMemoryScanError(
                    "The native backend returned an invalid memory scan address.",
                    details={"matches": matches},
                ) from error

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
        with self._result_operation():
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

    def is_write_error(self, error: BaseException) -> bool:
        return isinstance(error, self._native().MemoryError)

    def is_operation_error(self, error: BaseException) -> bool:
        native_error = getattr(self._native(), "DeimosNativeError", None)
        return native_error is not None and isinstance(error, native_error)

    def _module(self, module_name: str):
        response = self._call_manager(self.manager.list_modules, self.session_id)
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

        response = self._call_manager(self.manager.memory_regions, self.session_id)
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
