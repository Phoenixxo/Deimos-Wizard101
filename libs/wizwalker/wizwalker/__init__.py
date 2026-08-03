import sys
from importlib import import_module

from .constants import *
from .errors import *
from .hotkey import *

if sys.platform == "win32":
    from .utils import Orient, Rectangle, XYZ

from . import memory
from .memory import DeimosNativeMemoryBackend, MemoryBackend, MemoryReader
from .client_handler import Client, ClientHandler
from .discovered_client import DiscoveredClient

WizWalker = ClientHandler

if sys.platform == "win32":
    import logging

    from loguru import logger

    from . import combat, utils
    from .file_readers import CacheHandler, NifMap, Wad
    from .mouse_handler import MouseHandler

    logger.disable("wizwalker")
    logging.getLogger("pymem").setLevel(logging.FATAL)


def __getattr__(name):
    if name in {"XYZ", "Orient", "Rectangle"}:
        return getattr(import_module(".utils", __name__), name)
    if name in {"CacheHandler", "NifMap", "Wad"}:
        return getattr(import_module(".file_readers", __name__), name)
    if name == "MouseHandler":
        return import_module(".mouse_handler", __name__).MouseHandler
    if name in {"combat", "utils"}:
        return import_module(f".{name}", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


from .telemetry import (
    ReadOnlyTelemetryReader,
    ReadOnlyTelemetrySnapshot,
    TelemetryDiagnostic,
    TelemetryField,
)
