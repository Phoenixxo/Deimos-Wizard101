from __future__ import annotations

import json
import os
import socket
import struct
import sys
from enum import IntEnum
from importlib import import_module
from pathlib import Path
from typing import Protocol


app_id = 1000159655357587566
rpc_version = 1


class Opcodes(IntEnum):
    Handshake = 0
    Frame = 1
    Close = 2
    Ping = 3
    Pong = 4


class DiscordIpcConnection(Protocol):
    def write(self, data: bytes) -> None: ...

    def read(self, size: int) -> bytes: ...

    def close(self) -> None: ...


class WindowsNamedPipeConnection:
    def __init__(self, handle, win32file):
        self.handle = handle
        self.win32file = win32file

    def write(self, data: bytes) -> None:
        self.win32file.WriteFile(self.handle, data)

    def read(self, size: int) -> bytes:
        result, data = self.win32file.ReadFile(self.handle, size)
        if result != 0:
            raise OSError(f"Discord named-pipe read failed with code {result}")
        return bytes(data)

    def close(self) -> None:
        self.win32file.CloseHandle(self.handle)


class UnixSocketConnection:
    def __init__(self, connection: socket.socket):
        self.connection = connection

    def write(self, data: bytes) -> None:
        self.connection.sendall(data)

    def read(self, size: int) -> bytes:
        return self.connection.recv(size)

    def close(self) -> None:
        self.connection.close()


class DiscordIpcTransport:
    def __init__(self, *, platform: str = sys.platform, environ=None):
        self.platform = platform
        self.environ = os.environ if environ is None else environ

    def connect(self) -> DiscordIpcConnection | None:
        if self.platform == "win32":
            return self._connect_windows()
        return self._connect_unix()

    def _connect_windows(self) -> DiscordIpcConnection | None:
        win32file = import_module("win32file")
        win32pipe = import_module("win32pipe")
        for index in range(10):
            try:
                handle = win32file.CreateFile(
                    rf"\\?\pipe\discord-ipc-{index}",
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None,
                )
                win32pipe.SetNamedPipeHandleState(
                    handle,
                    win32pipe.PIPE_READMODE_BYTE,
                    None,
                    None,
                )
                return WindowsNamedPipeConnection(handle, win32file)
            except OSError:
                continue
        return None

    def _runtime_directories(self) -> list[Path]:
        values = [
            self.environ.get("XDG_RUNTIME_DIR"),
            self.environ.get("TMPDIR"),
            self.environ.get("TMP"),
            self.environ.get("TEMP"),
            "/tmp",
        ]
        if hasattr(os, "getuid"):
            values.append(f"/run/user/{os.getuid()}")
        directories: list[Path] = []
        for value in values:
            if value:
                directory = Path(value)
                if directory not in directories:
                    directories.append(directory)
        return directories

    def _connect_unix(self) -> DiscordIpcConnection | None:
        for directory in self._runtime_directories():
            for index in range(10):
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    connection.connect(str(directory / f"discord-ipc-{index}"))
                    return UnixSocketConnection(connection)
                except OSError:
                    connection.close()
        return None


def connect(transport: DiscordIpcTransport | None = None) -> DiscordIpcConnection | None:
    return (transport or DiscordIpcTransport()).connect()


def close(connection: DiscordIpcConnection) -> None:
    connection.close()


def serialize_message(opcode, jsondata) -> bytearray:
    data = json.dumps(jsondata).encode()
    return bytearray(struct.pack("<LL", int(opcode), len(data)) + data)


def parse_message(msg: bytes):
    opcode = Opcodes(struct.unpack("<L", msg[0:4])[0])
    data_len = struct.unpack("<L", msg[4:8])[0]
    data = msg[8 : 8 + data_len].decode()
    return json.loads(data)


def send(connection: DiscordIpcConnection, data: bytes) -> None:
    connection.write(data)


def _read_exact(connection: DiscordIpcConnection, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.read(size - len(chunks))
        if not chunk:
            raise EOFError("Discord IPC connection closed while reading a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def recv(connection: DiscordIpcConnection):
    header = _read_exact(connection, 8)
    payload_size = struct.unpack("<L", header[4:8])[0]
    return parse_message(header + _read_exact(connection, payload_size))


shake = serialize_message(
    Opcodes.Handshake,
    {
        "v": rpc_version,
        "client_id": str(app_id),
    },
)


def get_discord_user():
	"""Return the logged-in Discord user dict (id, username, global_name, ...) read
	from the local Discord IPC pipe, or None if Discord isn't running / on any error.

	Blocking named-pipe I/O — call off the main thread (e.g. via asyncio.to_thread).
	"""
	handle = None
	try:
		handle = connect()
		if handle is None:
			return None
		send(handle, shake)
		resp = recv(handle)
		return resp["data"]["user"]
	except Exception:
		return None
	finally:
		if handle is not None:
			try:
				close(handle)
			except Exception:
				pass


_cached_username = None


def get_discord_username():
	"""Best-effort current Discord username (the unique handle, falling back to the
	display name), or None if it can't be determined.

	The first success is cached for the process lifetime: Discord throttles rapid
	back-to-back IPC handshakes, and the username is stable within a session.
	"""
	global _cached_username
	if _cached_username is not None:
		return _cached_username
	user = get_discord_user()
	if not user:
		return None
	_cached_username = user.get("username") or user.get("global_name")
	return _cached_username
