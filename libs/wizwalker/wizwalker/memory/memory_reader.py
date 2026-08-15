import asyncio
import functools
from importlib import import_module
from typing import Any, Union

from wizwalker.constants import Primitive
from wizwalker.errors import (
    await_critical_operation,
    AddressOutOfRange,
    ClientClosedError,
    MemoryReadError,
    MemoryWriteError,
    PatternFailed,
    PatternMultipleResults,
    UnsupportedMemoryOperation,
)
from .backends import MemoryBackend, PymemMemoryBackend


_REGEX_META_BYTES = frozenset(b"*+?{}[]()|^$")
_ASCII_ALPHANUMERIC = frozenset(
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def __getattr__(name: str):
    # Preserve the existing module attribute without importing Pymem eagerly.
    if name == "pymem":
        pymem = import_module("pymem")
        import_module("pymem.exception")
        import_module("pymem.process")
        return pymem
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _legacy_pattern_to_signature(pattern: bytes) -> str:
    """
    Convert WizWalker's fixed-width byte-regex subset into an agent signature.

    Legacy patterns use exact bytes plus ``.`` as a one-byte wildcard. Regex
    constructs that could change the consumed length are deliberately rejected
    instead of being silently interpreted as literal bytes.
    """
    if not isinstance(pattern, bytes):
        raise TypeError("pattern must be bytes")
    if not pattern:
        raise ValueError("pattern must not be empty")

    signature = []
    index = 0
    while index < len(pattern):
        value = pattern[index]

        if value == ord("."):
            signature.append("??")
            index += 1
            continue

        if value in _REGEX_META_BYTES:
            character = chr(value)
            raise ValueError(
                f"Unsupported variable-length regex construct {character!r} in "
                "memory pattern. Rust scans support exact bytes and single-byte "
                "'.' wildcards only."
            )

        if value != ord("\\"):
            signature.append(f"{value:02X}")
            index += 1
            continue

        if index + 1 >= len(pattern):
            raise ValueError("Memory pattern ends with an incomplete escape.")

        escaped = pattern[index + 1]
        if escaped == ord("x"):
            if index + 3 >= len(pattern):
                raise ValueError("Memory pattern contains an incomplete hexadecimal escape.")
            digits = pattern[index + 2 : index + 4]
            try:
                signature.append(f"{int(digits.decode('ascii'), 16):02X}")
            except (UnicodeDecodeError, ValueError) as error:
                raise ValueError(
                    f"Memory pattern contains an invalid hexadecimal escape {digits!r}."
                ) from error
            index += 4
            continue

        if escaped in _ASCII_ALPHANUMERIC:
            raise ValueError(
                f"Unsupported semantic regex escape "
                f"{bytes((value, escaped))!r} in memory pattern. Rust scans "
                "support exact bytes, hexadecimal escapes, and single-byte "
                "'.' wildcards only."
            )

        # regex.escape emits a backslash followed by the literal byte for
        # punctuation and whitespace. Those escapes do not change width or
        # matching semantics and can be represented exactly by the agent.
        signature.append(f"{escaped:02X}")
        index += 2

    return " ".join(signature)


class MemoryReader:
    """
    Represents anything that needs to read/write from/to memory
    """

    def __init__(self, process):
        if isinstance(process, MemoryBackend):
            self._backend = process
            self.process = process.process
        else:
            self._backend = PymemMemoryBackend(process)
            self.process = process

        self._symbol_table = {}

    # TODO: 2.0 make this a property
    def is_running(self) -> bool:
        """
        If the process we're reading/writing to/from is running
        """
        return self._backend.is_running()

    @staticmethod
    async def run_in_executor(func, *args, **kwargs):
        """
        Run a function within an executor

        Args:
            func: The function to run
            args: Args to pass to the function
            kwargs: Kwargs to pass to the function
        """
        loop = asyncio.get_event_loop()
        function = functools.partial(func, *args, **kwargs)

        result = await await_critical_operation(
            loop.run_in_executor(None, function),
            operation=getattr(func, "__name__", "native memory operation"),
        )
        owner = getattr(func, "__self__", None)
        backend = getattr(owner, "_backend", owner)
        require_current = getattr(backend, "require_current", None)
        if callable(require_current):
            require_current()
        return result

    @staticmethod
    async def _run_cleanup_in_executor(func, *args, **kwargs):
        """Deliver exact-helper cleanup without stale normal-result checks."""
        loop = asyncio.get_event_loop()
        function = functools.partial(func, *args, **kwargs)
        return await await_critical_operation(
            loop.run_in_executor(None, function),
            operation=getattr(func, "__name__", "native memory cleanup"),
        )

    def _get_symbols(self, file_path: str, *, force_reload: bool = False):
        if (dll_table := self._symbol_table.get(file_path)) and not force_reload:
            return dll_table

        # exe_path = utils.get_wiz_install() / "Bin" / "WizardGraphicalClient.exe"
        pefile = import_module("pefile")
        pe = pefile.PE(file_path)

        symbols = {}

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                symbols[exp.name.decode()] = exp.address

            else:
                symbols[f"Ordinal {exp.ordinal}"] = exp.address

        self._symbol_table[file_path] = symbols
        return symbols

    @staticmethod
    def _scan_page_return_all(handle, address, pattern):
        pymem_memory = import_module("pymem.memory")
        pymem_structure = import_module("pymem.ressources.structure")
        regex = import_module("regex")
        mbi = pymem_memory.virtual_query(handle, address)
        next_region = mbi.BaseAddress + mbi.RegionSize
        allowed_protections = [
            pymem_structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
            pymem_structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
            pymem_structure.MEMORY_PROTECTION.PAGE_READWRITE,
            pymem_structure.MEMORY_PROTECTION.PAGE_READONLY,
        ]
        if (
            mbi.state != pymem_structure.MEMORY_STATE.MEM_COMMIT
            or mbi.protect not in allowed_protections
        ):
            return next_region, None

        page_bytes = pymem_memory.read_bytes(handle, address, mbi.RegionSize)

        found = []

        for match in regex.finditer(pattern, page_bytes, regex.DOTALL):
            found_address = address + match.span()[0]
            found.append(found_address)

        return next_region, found

    def _scan_all(
        self,
        handle: int,
        pattern: bytes,
        return_multiple: bool = False,
    ):
        next_region = 0

        found = []
        while next_region < 0x7FFFFFFF0000:
            next_region, page_found = self._scan_page_return_all(
                handle, next_region, pattern
            )
            if page_found:
                found += page_found

            if not return_multiple and found:
                break

        return found

    def _scan_entire_module(self, handle, module, pattern):
        base_address = module.lpBaseOfDll
        max_address = module.lpBaseOfDll + module.SizeOfImage
        page_address = base_address

        found = []
        while page_address < max_address:
            page_address, page_found = self._scan_page_return_all(
                handle, page_address, pattern
            )
            if page_found:
                found += page_found

        return found

    async def pattern_scan(
        self, pattern: bytes, *, module: str = None, return_multiple: bool = False
    ) -> Union[list, int]:
        """
        Scan for a pattern

        Args:
            pattern: The byte pattern to search for
            module: What module to search or None to search all
            return_multiple: If multiple results should be returned

        Raises:
            PatternFailed: If the pattern returned no results
            PatternMultipleResults: If the pattern returned multiple results and return_multple is False

        Returns:
            A list of results if return_multple is True otherwise one result
        """
        if isinstance(self._backend, PymemMemoryBackend):
            if module:
                module_object = await self.run_in_executor(
                    self._backend.module,
                    module,
                )

                if module_object is None:
                    raise ValueError(f"{module} module not found.")

                # this can take a long time to run when collecting multiple results
                # so must be run in an executor
                found_addresses = await self.run_in_executor(
                    self._scan_entire_module,
                    self.process.process_handle,
                    module_object,
                    pattern,
                )

            else:
                found_addresses = await self.run_in_executor(
                    self._scan_all,
                    self.process.process_handle,
                    pattern,
                    return_multiple,
                )
        else:
            signature = _legacy_pattern_to_signature(pattern)
            try:
                found_addresses = await self.run_in_executor(
                    self._backend.scan,
                    signature,
                    module_name=module,
                    return_multiple=return_multiple,
                )
            except ValueError:
                raise
            except Exception as error:
                mapped = await self._mapped_read_error(error, str(error))
                if mapped is not None:
                    raise mapped from error
                raise

        if (found_length := len(found_addresses)) == 0:
            raise PatternFailed(pattern)
        elif found_length > 1 and not return_multiple:
            raise PatternMultipleResults(f"Got {found_length} results for {pattern}")
        elif return_multiple:
            return found_addresses
        else:
            return found_addresses[0]

    async def get_address_from_symbol(
        self,
        module_name: str,
        symbol_name: str,
        *,
        module_dir: str = None,
        force_reload: bool = False,
    ) -> int:
        """
        Get an address from a module using its symbol

        Args:
            module_name: Name of the module
            symbol_name: Name of the symbol
            module_dir: Dir the module is within
            force_reload: Force export table reload

        Returns:
            The address of the symbol in memory

        Raises:
            ValueError: No symbol/module with that name
        """
        if not module_dir:
            if isinstance(self._backend, PymemMemoryBackend):
                from wizwalker import utils

                module_dir = utils.get_system_directory()
            else:
                raise ValueError(
                    "module_dir is required when resolving symbols through the "
                    "Rust memory backend."
                )

        file_path = module_dir / module_name

        if not file_path.exists():
            raise ValueError(f"No module named {module_name}")

        symbols = await self.run_in_executor(
            self._get_symbols, file_path, force_reload=force_reload
        )

        if not (symbol := symbols.get(symbol_name)):
            raise ValueError(f"No symbol named {symbol_name} in module {module_name}")

        try:
            module_base = await self.run_in_executor(
                self._backend.module_base,
                module_name,
            )
        except Exception as error:
            mapped = await self._mapped_read_error(error, str(error))
            if mapped is not None:
                raise mapped from error
            raise

        if module_base is None:
            raise ValueError(f"{module_name} module not found.")

        return module_base + symbol

    async def allocate(self, size: int) -> int:
        """
        Allocate some bytes

        Args:
            size: The number of bytes to allocate

        Returns:
            The allocated address
        """
        self._require_mutation("allocate")
        return await self.run_in_executor(self._backend.allocate, size)

    async def free(self, address: int):
        """
        Free some bytes

        Args:
             address: The address to free
        """
        self._require_mutation("free")
        await self.run_in_executor(self._backend.free, address)

    # TODO: figure out how params works
    async def start_thread(self, address: int):
        """
        Start a thread at an address

        Args:
            address: The address to start the thread at
        """
        self._require_mutation("remote thread creation")
        await self.run_in_executor(self._backend.start_thread, address)

    async def read_bytes(self, address: int, size: int) -> bytes:
        """
        Read some bytes from memory

        Args:
            address: The address to read from
            size: The number of bytes to read

        Raises:
            ClientClosedError: If the client is closed
            MemoryReadError: If there was an error reading memory
            AddressOutOfRange: If the addrress is out of bounds
        """
        if not 0 < address <= 0x7FFFFFFFFFFFFFFF:
            raise AddressOutOfRange(address)

        try:
            return await self.run_in_executor(
                self._backend.read_bytes,
                address,
                size,
            )
        except Exception as error:
            if getattr(error, "code", None) == "generation_unavailable":
                raise
            mapped = await self._mapped_read_error(error, address)
            if mapped is not None:
                raise mapped from error
            raise

    async def write_bytes(self, address: int, value: bytes):
        """
        Write bytes to memory

        Args:
            address: The address to write to
            value: The bytes to write
        """
        self._require_mutation("write")

        try:
            await self.run_in_executor(
                self._backend.write_bytes,
                address,
                value,
            )
        except Exception as error:
            if getattr(error, "code", None) == "generation_unavailable":
                raise
            if not self._backend.is_write_error(error):
                raise

            # see read_bytes
            if await self._is_running_after_error() is False:
                raise ClientClosedError() from error
            raise MemoryWriteError(address) from error

    def _require_mutation(self, operation: str):
        capability = {
            "write": "supports_write",
            "allocate": "supports_allocation",
            "free": "supports_allocation",
            "remote thread creation": "supports_remote_thread",
        }.get(operation)
        supported = (
            getattr(self._backend, capability)
            if capability is not None and hasattr(self._backend, capability)
            else self._backend.supports_mutation
        )
        if not supported:
            raise UnsupportedMemoryOperation(operation)

    async def _is_running_after_error(self) -> bool | None:
        """
        Probe process status without blocking the event loop.

        A status failure is inconclusive and must not replace the operation
        error that prompted the probe.
        """
        try:
            return await self.run_in_executor(self.is_running)
        except Exception:
            return None

    async def _mapped_read_error(
        self,
        error: BaseException,
        address_or_message: int | str,
    ) -> Exception | None:
        if self._backend.is_closed_process_error(error):
            return self._copy_native_error_context(ClientClosedError(), error)

        if not (
            self._backend.is_process_error(error)
            or self._backend.is_read_error(error)
            or self._backend.is_operation_error(error)
        ):
            return None

        if await self._is_running_after_error() is False:
            return self._copy_native_error_context(ClientClosedError(), error)

        mapped = MemoryReadError(address_or_message)
        return self._copy_native_error_context(mapped, error)

    @staticmethod
    def _copy_native_error_context(
        mapped: Exception,
        error: BaseException,
    ) -> Exception:
        for attribute in (
            "code",
            "details",
            "native_context",
            "operation",
            "request_id",
            "technical_message",
        ):
            if hasattr(error, attribute):
                setattr(mapped, attribute, getattr(error, attribute))
        return mapped

    async def read_typed(self, address: int, data_type: Primitive) -> Any:
        """
        Read typed bytes from memory

        Args:
            address: The address to read from
            data_type: The type to read (defined in constants)

        Returns:
            The converted data type
        """
        data = await self.read_bytes(address, data_type.value.size)
        return data_type.value.unpack(data)[0]

    async def write_typed(self, address: int, value: Any, data_type: Primitive):
        """
        Write typed bytes to memory

        Args:
            address: The address to write to
            value: The value to convert and then write
            data_type: The data type to convert to
        """
        packed_data = data_type.value.pack(value)
        await self.write_bytes(address, packed_data)
