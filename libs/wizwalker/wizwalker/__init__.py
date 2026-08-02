import sys

from .constants import *
from .errors import *
from .hotkey import *

if sys.platform == "win32":
    import logging

    from loguru import logger

    from .utils import XYZ, Orient, Rectangle
    from . import combat, utils
    from . import memory
    from .memory import DeimosNativeMemoryBackend, MemoryBackend, MemoryReader
    from .file_readers import CacheHandler, NifMap, Wad
    from .mouse_handler import MouseHandler
    from .client import Client
    from .client_handler import ClientHandler

    logger.disable("wizwalker")
    logging.getLogger("pymem").setLevel(logging.FATAL)
else:
    from . import memory
    from .client_handler import ClientHandler
    from .memory import DeimosNativeMemoryBackend, MemoryBackend, MemoryReader

from .discovered_client import DiscoveredClient
from .telemetry import (
    ReadOnlyTelemetryReader,
    ReadOnlyTelemetrySnapshot,
    TelemetryDiagnostic,
    TelemetryField,
)
