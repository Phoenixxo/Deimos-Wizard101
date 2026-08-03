import sys
from importlib import import_module

from .backends import DeimosNativeMemoryBackend, MemoryBackend, PymemMemoryBackend
from .memory_reader import MemoryReader

if sys.platform == "win32":
    from .handler import HookHandler
    from .hooks import *
    from .instance_finder import InstanceFinder
    from .memory_object import MemoryObject
    from .memory_objects import *


def __getattr__(name):
    direct_exports = {
        "HookHandler": (".handler", "HookHandler"),
        "InstanceFinder": (".instance_finder", "InstanceFinder"),
        "MemoryObject": (".memory_object", "MemoryObject"),
    }
    if name in direct_exports:
        module_name, attribute = direct_exports[name]
        return getattr(import_module(module_name, __name__), attribute)

    for module_name in (".hooks", ".memory_objects"):
        module = import_module(module_name, __name__)
        if hasattr(module, name):
            return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
