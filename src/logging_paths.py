from pathlib import Path
import sys


def application_log_directory() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "Deimos"
    return Path.home() / ".deimos" / "logs"
