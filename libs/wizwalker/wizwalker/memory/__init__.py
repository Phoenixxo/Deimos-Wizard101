import sys

from .backends import DeimosNativeMemoryBackend, MemoryBackend, PymemMemoryBackend
from .memory_reader import MemoryReader

if sys.platform == "win32":
    from .handler import HookHandler
    from .hooks import *
    from .memory_object import MemoryObject
    from .memory_objects import *
    from .instance_finder import InstanceFinder
