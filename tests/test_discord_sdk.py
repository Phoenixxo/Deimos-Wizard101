from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from src import discsdk  # noqa: E402


class PartialConnection:
    def __init__(self, data: bytes, chunk_size: int = 3):
        self.data = bytearray(data)
        self.chunk_size = chunk_size
        self.writes = []
        self.closed = False

    def write(self, data):
        self.writes.append(bytes(data))

    def read(self, size):
        count = min(size, self.chunk_size, len(self.data))
        result = bytes(self.data[:count])
        del self.data[:count]
        return result

    def close(self):
        self.closed = True


class FakeSocket:
    def __init__(self, successful_path):
        self.successful_path = successful_path
        self.paths = []
        self.closed = False

    def connect(self, path):
        self.paths.append(path)
        if path != self.successful_path:
            raise OSError("not available")

    def close(self):
        self.closed = True


class FakeWin32File:
    GENERIC_READ = 1
    GENERIC_WRITE = 2
    OPEN_EXISTING = 3

    def __init__(self):
        self.paths = []

    def CreateFile(self, path, *args):
        self.paths.append(path)
        if path.endswith("0"):
            raise OSError("not available")
        return "handle-1"

    def WriteFile(self, handle, data):
        self.write = (handle, bytes(data))

    def ReadFile(self, handle, size):
        return 0, b"x" * size

    def CloseHandle(self, handle):
        self.closed = handle


class FakeWin32Pipe:
    PIPE_READMODE_BYTE = 4

    def SetNamedPipeHandleState(self, *args):
        self.state = args


class DiscordSdkTests(unittest.TestCase):
    def test_message_round_trip_and_partial_reads(self):
        message = discsdk.serialize_message(
            discsdk.Opcodes.Frame,
            {"evt": "READY", "data": {"user": {"id": "42"}}},
        )
        connection = PartialConnection(message)
        self.assertEqual(discsdk.recv(connection)["data"]["user"]["id"], "42")
        discsdk.send(connection, b"payload")
        discsdk.close(connection)
        self.assertEqual(connection.writes, [b"payload"])
        self.assertTrue(connection.closed)

    def test_unix_transport_finds_discord_socket_without_pywin32(self):
        sockets = []

        def socket_factory(*args):
            created = FakeSocket("/runtime/discord-ipc-2")
            sockets.append(created)
            return created

        transport = discsdk.DiscordIpcTransport(
            platform="darwin",
            environ={"XDG_RUNTIME_DIR": "/runtime"},
        )
        with patch.object(discsdk.socket, "socket", side_effect=socket_factory), patch.object(
            discsdk,
            "import_module",
            side_effect=AssertionError("Unix transport must not import pywin32"),
        ):
            connection = transport.connect()

        self.assertIsInstance(connection, discsdk.UnixSocketConnection)
        self.assertEqual(sockets[-1].paths, ["/runtime/discord-ipc-2"])
        self.assertTrue(all(sock.closed for sock in sockets[:-1]))

    def test_windows_transport_preserves_named_pipe_behavior(self):
        win32file = FakeWin32File()
        win32pipe = FakeWin32Pipe()

        def load_module(name):
            return {"win32file": win32file, "win32pipe": win32pipe}[name]

        with patch.object(discsdk, "import_module", side_effect=load_module):
            connection = discsdk.DiscordIpcTransport(platform="win32").connect()

        self.assertIsInstance(connection, discsdk.WindowsNamedPipeConnection)
        self.assertEqual(
            win32file.paths,
            [r"\\?\pipe\discord-ipc-0", r"\\?\pipe\discord-ipc-1"],
        )
        self.assertEqual(
            win32pipe.state,
            ("handle-1", win32pipe.PIPE_READMODE_BYTE, None, None),
        )

    def test_closed_connection_during_frame_raises_eof(self):
        with self.assertRaisesRegex(EOFError, "closed"):
            discsdk.recv(PartialConnection(b""))


if __name__ == "__main__":
    unittest.main()
