from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .constants import Primitive
from .errors import (
    AddressOutOfRange,
    ClientClosedError,
    MemoryReadError,
    PatternFailed,
    PatternMultipleResults,
)
from .memory.memory_reader import MemoryReader


GAME_CLIENT_PATTERN = (
    rb"\x48\x8b.....\x48\x8b.\x80\xb8....\x00\x74.\x4c\x8b"
)
ROOT_CLIENT_OBJECT_OFFSET_PATTERN = (
    rb"\x48\x8D\x93\xA0\x12\x02\x00\xFF\x90\xB8\x01"
    rb"\x00\x00\x90\x48\x8B\x7C\x24\x30\x48\x85\xFF\x74\x2E\xBE"
    rb"\xFF\xFF\xFF\xFF\x8B\xC6\xF0\x0F\xC1\x47\x08"
)
DUEL_MANAGER_PATTERN = (
    rb".......\xE8....\x90.......\x48\x85\xC9\x74.\x0F\x28\x45"
)
GAME_MODULE = "WizardGraphicalClient.exe"

_MAX_STRING_LENGTH = 5_000
_MAX_BEHAVIORS = 1_000
_MAX_CHILDREN_PER_OBJECT = 1_000
_MAX_CLIENT_OBJECTS = 4_096
_MAX_DUELS = 64
_MAX_PARTICIPANTS = 64
_PROCESS_SESSION_CODES = frozenset(
    (
        "process_access_denied",
        "process_exited",
        "process_not_found",
        "session_not_found",
    )
)
_DUEL_PHASE_NAMES = {
    0: "starting",
    1: "pre_planning",
    2: "planning",
    3: "pre_execution",
    4: "execution",
    5: "resolution",
    6: "victory",
    7: "ended",
    10: "max",
}


@dataclass(frozen=True)
class TelemetryDiagnostic:
    code: str
    message: str
    technical_message: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "technical_message": self.technical_message,
            "details": self.details,
        }


@dataclass(frozen=True)
class TelemetryField:
    available: bool
    value: Any = None
    error: TelemetryDiagnostic | None = None

    @classmethod
    def available_value(cls, value: Any) -> "TelemetryField":
        return cls(available=True, value=value)

    @classmethod
    def unavailable(
        cls,
        code: str,
        message: str,
        *,
        technical_message: str,
        details: dict[str, Any] | None = None,
    ) -> "TelemetryField":
        return cls(
            available=False,
            error=TelemetryDiagnostic(
                code=code,
                message=message,
                technical_message=technical_message,
                details=details or {},
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        if self.available:
            return {"available": True, "value": self.value}
        return {
            "available": False,
            "error": self.error.to_dict() if self.error is not None else None,
        }


@dataclass(frozen=True)
class ReadOnlyTelemetrySnapshot:
    fields: dict[str, TelemetryField]
    client_id: str | None = None
    process_id: int | None = None

    @property
    def complete(self) -> bool:
        return all(field.available for field in self.fields.values())

    @property
    def available_fields(self) -> list[str]:
        return [name for name, field in self.fields.items() if field.available]

    @property
    def unavailable_fields(self) -> list[str]:
        return [name for name, field in self.fields.items() if not field.available]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "client_id": self.client_id,
            "process_id": self.process_id,
            "complete": self.complete,
            "available_fields": self.available_fields,
            "unavailable_fields": self.unavailable_fields,
            "fields": {
                name: field.to_dict()
                for name, field in self.fields.items()
            },
        }


class _CachedReadFailure:
    def __init__(self, error: BaseException):
        self.error = error


class _TelemetryReadContext:
    def __init__(
        self,
        memory: MemoryReader,
        signature_addresses: dict[bytes, int],
    ):
        self.memory = memory
        self.signature_addresses = signature_addresses
        self._cache: dict[str, Any | _CachedReadFailure] = {}

    async def _cached(
        self,
        name: str,
        read: Callable[[], Awaitable[Any]],
    ) -> Any:
        if name in self._cache:
            value = self._cache[name]
            if isinstance(value, _CachedReadFailure):
                raise value.error
            return value

        try:
            value = await read()
        except Exception as error:
            self._cache[name] = _CachedReadFailure(error)
            raise
        self._cache[name] = value
        return value

    async def _read(self, address: int, primitive: Primitive) -> Any:
        return await self.memory.read_typed(address, primitive)

    async def _pattern(self, pattern: bytes) -> int:
        if pattern not in self.signature_addresses:
            self.signature_addresses[pattern] = await self.memory.pattern_scan(
                pattern,
                module=GAME_MODULE,
            )
        return self.signature_addresses[pattern]

    async def _read_string(self, address: int) -> str:
        length = await self._read(address + 16, Primitive.int32)
        if length == 0:
            return ""
        if not 1 <= length <= _MAX_STRING_LENGTH:
            raise MemoryReadError(
                f"String length {length} at 0x{address:x} is outside the "
                f"supported range of 1 to {_MAX_STRING_LENGTH}."
            )
        string_address = (
            await self._read(address, Primitive.uint64)
            if length >= 16
            else address
        )
        if string_address == 0:
            raise MemoryReadError(
                f"String at 0x{address:x} has a null data pointer."
            )
        try:
            return (await self.memory.read_bytes(string_address, length)).decode("utf-8")
        except UnicodeDecodeError as error:
            raise MemoryReadError(
                f"String at 0x{string_address:x} is not valid UTF-8."
            ) from error

    async def _read_shared_vector(
        self,
        address: int,
        *,
        maximum: int,
    ) -> list[int]:
        start = await self._read(address, Primitive.uint64)
        end = await self._read(address + 8, Primitive.uint64)
        if end < start or (end - start) % 16 != 0:
            raise MemoryReadError(
                f"Shared vector at 0x{address:x} has invalid bounds "
                f"0x{start:x}..0x{end:x}."
            )
        count = (end - start) // 16
        if count and start == 0:
            raise MemoryReadError(
                f"Shared vector at 0x{address:x} has a null data pointer."
            )
        if count > maximum:
            raise MemoryReadError(
                f"Shared vector at 0x{address:x} contains {count} entries; "
                f"the read-only safety limit is {maximum}."
            )
        if count == 0:
            return []
        data = await self.memory.read_bytes(start, count * 16)
        return [
            Primitive.uint64.value.unpack_from(data, index * 16)[0]
            for index in range(count)
        ]

    async def game_client(self) -> int:
        async def locate() -> int:
            instruction = await self._pattern(GAME_CLIENT_PATTERN)
            relative_offset = await self._read(
                instruction + 3,
                Primitive.int32,
            )
            pointer_address = instruction + 7 + relative_offset
            base_address = await self._read(pointer_address, Primitive.uint64)
            if base_address == 0:
                raise MemoryReadError(
                    "The GameClient signature resolved to a null pointer."
                )
            return base_address

        return await self._cached("game_client", locate)

    async def client_tree_root(self) -> int:
        async def locate() -> int:
            game_client = await self.game_client()
            instruction = await self._pattern(
                ROOT_CLIENT_OBJECT_OFFSET_PATTERN
            )
            offset = await self._read(instruction + 3, Primitive.uint32)
            base_address = await self._read(
                game_client + offset,
                Primitive.uint64,
            )
            if base_address == 0:
                raise MemoryReadError(
                    "Wizard101 has not published its client-object tree yet."
                )
            return base_address

        return await self._cached("client_tree_root", locate)

    async def root_client_object(self) -> int:
        async def locate() -> int:
            game_client = await self.game_client()
            player_id = await self._read(
                game_client + 0x214C0,
                Primitive.uint64,
            )
            if player_id == 0:
                raise MemoryReadError(
                    "Wizard101 has not selected a character yet."
                )

            stack = [await self.client_tree_root()]
            visited: set[int] = set()
            while stack:
                client_object = stack.pop()
                if client_object == 0 or client_object in visited:
                    continue
                if len(visited) >= _MAX_CLIENT_OBJECTS:
                    raise MemoryReadError(
                        "The client-object tree exceeds the read-only safety "
                        f"limit of {_MAX_CLIENT_OBJECTS} objects."
                    )
                visited.add(client_object)
                if (
                    await self._read(
                        client_object + 72,
                        Primitive.uint64,
                    )
                    == player_id
                ):
                    return client_object
                stack.extend(
                    await self._read_shared_vector(
                        client_object + 392,
                        maximum=_MAX_CHILDREN_PER_OBJECT,
                    )
                )

            raise MemoryReadError(
                f"The client-object tree does not contain player 0x{player_id:x}."
            )

        return await self._cached("root_client_object", locate)

    async def game_stats(self) -> int:
        async def locate() -> int:
            root = await self.root_client_object()
            base_address = await self._read(root + 560, Primitive.uint64)
            if base_address == 0:
                raise MemoryReadError(
                    "The current player does not have a GameStats object."
                )
            return base_address

        return await self._cached("game_stats", locate)

    async def behaviors(self) -> dict[str, int]:
        async def locate() -> dict[str, int]:
            root = await self.root_client_object()
            behaviors: dict[str, int] = {}
            for behavior in await self._read_shared_vector(
                root + 224,
                maximum=_MAX_BEHAVIORS,
            ):
                if behavior == 0:
                    continue
                template = await self._read(behavior + 0x58, Primitive.uint64)
                if template == 0:
                    continue
                name = await self._read_string(template + 72)
                if name:
                    behaviors.setdefault(name, behavior)
            return behaviors

        return await self._cached("behaviors", locate)

    async def behavior(self, name: str) -> int:
        behavior = (await self.behaviors()).get(name)
        if behavior is None:
            raise MemoryReadError(
                f"The current player does not expose {name}."
            )
        return behavior

    async def actor_body(self) -> int:
        async def locate() -> int:
            behavior = await self.behavior("AnimationBehavior")
            base_address = await self._read(behavior + 0x70, Primitive.uint64)
            if base_address == 0:
                raise MemoryReadError(
                    "AnimationBehavior does not expose an actor body."
                )
            return base_address

        return await self._cached("actor_body", locate)

    async def character_identity(self) -> dict[str, Any]:
        game_client = await self.game_client()
        root = await self.root_client_object()
        return {
            "player_gid": await self._read(
                game_client + 0x214C0,
                Primitive.uint64,
            ),
            "character_id": await self._read(root + 448, Primitive.uint64),
        }

    async def zone(self) -> dict[str, Any]:
        root = await self.root_client_object()
        zone = await self._read(root + 304, Primitive.uint64)
        if zone == 0:
            raise MemoryReadError(
                "The current player does not have a loaded ClientZone."
            )
        return {
            "id": await self._read(zone + 72, Primitive.int64),
            "name": await self._read_string(zone + 88),
        }

    async def position(self) -> dict[str, float]:
        body = await self.actor_body()
        x, y, z = struct.unpack(
            "<fff",
            await self.memory.read_bytes(body + 88, 12),
        )
        return {"x": x, "y": y, "z": z}

    async def orientation(self) -> dict[str, float]:
        body = await self.actor_body()
        pitch, roll, yaw = struct.unpack(
            "<fff",
            await self.memory.read_bytes(body + 100, 12),
        )
        return {"pitch": pitch, "roll": roll, "yaw": yaw}

    async def health(self) -> dict[str, int]:
        stats = await self.game_stats()
        base = await self._read(stats + 80, Primitive.int32)
        bonus = await self._read(stats + 224, Primitive.int32)
        return {
            "current": await self._read(stats + 112, Primitive.int32),
            "maximum": base + bonus,
        }

    async def mana(self) -> dict[str, int]:
        stats = await self.game_stats()
        base = await self._read(stats + 84, Primitive.int32)
        bonus = await self._read(stats + 228, Primitive.int32)
        return {
            "current": await self._read(stats + 136, Primitive.int32),
            "maximum": base + bonus,
        }

    async def energy(self) -> dict[str, int]:
        stats = await self.game_stats()
        behavior = await self.behavior("PetOwnerBehavior")
        base = await self._read(stats + 108, Primitive.int32)
        bonus = await self._read(stats + 244, Primitive.int32)
        return {
            "current": await self._read(behavior + 132, Primitive.int32),
            "maximum": base + bonus,
        }

    async def combat(self) -> dict[str, Any]:
        root = await self.root_client_object()
        player_id = await self._read(root + 72, Primitive.uint64)
        instruction = await self._pattern(DUEL_MANAGER_PATTERN)
        relative_offset = await self._read(instruction + 3, Primitive.int32)
        manager_pointer = instruction + 7 + relative_offset
        manager = await self._read(manager_pointer, Primitive.uint64)
        if manager == 0:
            return {"in_combat": False, "phase": "ended", "phase_code": 7}

        sentinel = await self._read(manager + 8, Primitive.uint64)
        if sentinel == 0:
            return {"in_combat": False, "phase": "ended", "phase_code": 7}
        first = await self._read(sentinel + 8, Primitive.uint64)
        if first == sentinel:
            return {"in_combat": False, "phase": "ended", "phase_code": 7}

        stack = [first]
        visited: set[int] = set()
        while stack:
            node = stack.pop()
            if node == 0 or node == sentinel or node in visited:
                continue
            if len(visited) >= _MAX_DUELS:
                raise MemoryReadError(
                    f"The duel map exceeds the read-only safety limit of "
                    f"{_MAX_DUELS} nodes."
                )
            visited.add(node)
            if await self._read(node + 0x19, Primitive.bool):
                continue

            stack.extend(
                (
                    await self._read(node, Primitive.uint64),
                    await self._read(node + 0x10, Primitive.uint64),
                )
            )
            duel = await self._read(node + 0x28, Primitive.uint64)
            if duel == 0:
                continue
            participants = await self._read_shared_vector(
                duel + 80,
                maximum=_MAX_PARTICIPANTS,
            )
            for participant in participants:
                if participant != 0 and (
                    await self._read(participant + 112, Primitive.uint64)
                ) == player_id:
                    phase = await self._read(duel + 196, Primitive.int32)
                    if phase not in _DUEL_PHASE_NAMES:
                        raise MemoryReadError(
                            f"Wizard101 reported unknown duel phase {phase}."
                        )
                    return {
                        "in_combat": phase != 7,
                        "phase": _DUEL_PHASE_NAMES[phase],
                        "phase_code": phase,
                    }

        return {"in_combat": False, "phase": "ended", "phase_code": 7}


class ReadOnlyTelemetryReader:
    """Capture hook-free Wizard101 telemetry through any MemoryReader backend."""

    def __init__(self, memory: MemoryReader):
        self.memory = memory
        self._signature_addresses: dict[bytes, int] = {}

    @staticmethod
    def _diagnostic(error: BaseException) -> TelemetryDiagnostic:
        details = {
            "exception_type": type(error).__name__,
        }
        native_code = getattr(error, "code", None)
        native_operation = getattr(error, "operation", None)
        if native_code is not None:
            details["native_code"] = native_code
        if native_operation is not None:
            details["native_operation"] = native_operation

        if isinstance(error, (PatternFailed, PatternMultipleResults)):
            return TelemetryDiagnostic(
                code="signature_mismatch",
                message=(
                    "This Wizard101 build does not match the read-only telemetry "
                    "signatures. Update the signatures for this game version."
                ),
                technical_message=str(error),
                details=details,
            )
        if isinstance(error, ClientClosedError) or native_code in _PROCESS_SESSION_CODES:
            return TelemetryDiagnostic(
                code="process_unavailable",
                message=(
                    "The Wizard101 process or its read-only session is unavailable. "
                    "Rediscover the client and try again."
                ),
                technical_message=(
                    getattr(error, "technical_message", None) or str(error)
                ),
                details=details,
            )
        if isinstance(error, (MemoryReadError, AddressOutOfRange)):
            return TelemetryDiagnostic(
                code="memory_read_failed",
                message=(
                    "Wizard101 telemetry changed while it was being read. "
                    "Try another snapshot; if it persists, include the technical "
                    "message in a bug report."
                ),
                technical_message=str(error),
                details=details,
            )
        return TelemetryDiagnostic(
            code="telemetry_read_failed",
            message=(
                "Deimos could not read this telemetry field. Try again and include "
                "the technical message if the problem continues."
            ),
            technical_message=(
                getattr(error, "technical_message", None) or str(error)
            ),
            details=details,
        )

    async def _capture(
        self,
        read: Callable[[], Awaitable[Any]],
    ) -> TelemetryField:
        try:
            return TelemetryField.available_value(await read())
        except Exception as error:
            diagnostic = self._diagnostic(error)
            return TelemetryField(
                available=False,
                error=diagnostic,
            )

    @staticmethod
    def _hook_required(field: str) -> TelemetryField:
        return TelemetryField.unavailable(
            "hook_required",
            (
                f"{field} is not available through the current read-only path "
                "because Wizard101 only exposes its root UI pointer through an "
                "in-process hook."
            ),
            technical_message=(
                "The legacy RootWindowHook captures a transient register value. "
                "The read-only telemetry path does not write code, allocate "
                "memory, or install hooks."
            ),
            details={"required_capability": "root_ui.read_only"},
        )

    async def snapshot(
        self,
        *,
        client_id: str | None = None,
        process_id: int | None = None,
    ) -> ReadOnlyTelemetrySnapshot:
        context = _TelemetryReadContext(
            self.memory,
            self._signature_addresses,
        )
        fields = {
            "character_identity": await self._capture(
                context.character_identity
            ),
            "zone": await self._capture(context.zone),
            "position": await self._capture(context.position),
            "orientation": await self._capture(context.orientation),
            "health": await self._capture(context.health),
            "mana": await self._capture(context.mana),
            "energy": await self._capture(context.energy),
            "loading": self._hook_required("Loading state"),
            "dialog": self._hook_required("Dialog state"),
            "combat": await self._capture(context.combat),
            "root_ui": self._hook_required("Root UI traversal"),
        }
        return ReadOnlyTelemetrySnapshot(
            fields=fields,
            client_id=client_id,
            process_id=process_id,
        )
