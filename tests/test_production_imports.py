from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (
    REPOSITORY_ROOT / "src",
    REPOSITORY_ROOT / "libs" / "wizwalker" / "wizwalker",
    REPOSITORY_ROOT / "libs" / "wizsprinter" / "wizwalker",
    REPOSITORY_ROOT / "libs" / "wizlaunch" / "python" / "wizlaunch",
)

PYTHON_PATHS = (
    REPOSITORY_ROOT,
    REPOSITORY_ROOT / "libs" / "wizwalker",
    REPOSITORY_ROOT / "libs" / "wizsprinter",
    REPOSITORY_ROOT / "libs" / "wizlaunch" / "python",
)
WIZSPRINTER_EXTENSIONS = (
    REPOSITORY_ROOT / "libs" / "wizsprinter" / "wizwalker" / "extensions"
)


def production_modules() -> list[str]:
    modules = {"Deimos", "_pyi_rthook_wizsprinter"}
    prefixes = {
        PRODUCTION_ROOTS[0]: "src",
        PRODUCTION_ROOTS[1]: "wizwalker",
        PRODUCTION_ROOTS[2]: "wizwalker",
        PRODUCTION_ROOTS[3]: "wizlaunch",
    }
    for root, prefix in prefixes.items():
        for source in root.rglob("*.py"):
            relative = source.relative_to(root).with_suffix("")
            parts = list(relative.parts)
            if parts[-1] == "__init__":
                parts.pop()
            modules.add(".".join((prefix, *parts)).rstrip("."))
    return sorted(modules)


IMPORT_SCRIPT = r"""
import importlib
import importlib.abc
import os
import sys

class BlockWindowsImports(importlib.abc.MetaPathFinder):
    blocked = frozenset(("pymem", "win32file", "win32pipe", "winreg"))

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in self.blocked:
            raise ModuleNotFoundError(f"blocked platform dependency: {fullname}")
        return None

sys.meta_path.insert(0, BlockWindowsImports())
extensions = importlib.import_module("wizwalker.extensions")
wizsprinter_extensions = os.environ["DEIMOS_WIZSPRINTER_EXTENSIONS"]
if wizsprinter_extensions not in extensions.__path__:
    extensions.__path__.append(wizsprinter_extensions)
importlib.import_module(sys.argv[1])
"""


class ProductionImportTests(unittest.TestCase):
    def test_frozen_entrypoint_bootstraps_multiprocessing_before_queued_logging(self):
        source = (REPOSITORY_ROOT / "Deimos.py").read_text(encoding="utf-8")

        self.assertLess(
            source.index("multiprocessing.freeze_support()"),
            source.index("from loguru import logger"),
        )
        self.assertIn("enqueue=True", source)

    def test_all_production_modules_import_without_windows_dependencies(self):
        failures = []
        with tempfile.TemporaryDirectory(
            prefix="deimos-production-imports-"
        ) as sandbox:
            environment = os.environ.copy()
            environment["APPDATA"] = sandbox
            environment["MPLCONFIGDIR"] = str(Path(sandbox) / "matplotlib")
            environment["XDG_CACHE_HOME"] = str(Path(sandbox) / "cache")
            environment["DEIMOS_WIZSPRINTER_EXTENSIONS"] = str(
                WIZSPRINTER_EXTENSIONS
            )
            environment["PYTHONPATH"] = os.pathsep.join(
                [*(str(path) for path in PYTHON_PATHS), environment.get("PYTHONPATH", "")]
            )
            for module_name in production_modules():
                result = subprocess.run(
                    [sys.executable, "-c", IMPORT_SCRIPT, module_name],
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    failures.append(
                        f"{module_name}: {result.stderr.strip() or result.stdout.strip()}"
                    )

        self.assertFalse(failures, "\n" + "\n".join(failures))

    def test_windows_dependencies_are_isolated_to_platform_adapters(self):
        forbidden_imports = frozenset(("pymem", "win32file", "win32pipe", "winreg"))
        windll_allowed = {
            REPOSITORY_ROOT / "libs" / "wizwalker" / "wizwalker" / "constants.py",
            REPOSITORY_ROOT
            / "libs"
            / "wizwalker"
            / "wizwalker"
            / "platform_adapter.py",
            REPOSITORY_ROOT / "src" / "platform_adapter.py",
        }
        failures = []
        sources = [REPOSITORY_ROOT / "Deimos.py"]
        for root in PRODUCTION_ROOTS:
            sources.extend(root.rglob("*.py"))

        for source in sources:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                imported = []
                if isinstance(node, ast.Import):
                    imported = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported = [node.module]
                for name in imported:
                    if name.split(".", 1)[0] in forbidden_imports:
                        failures.append(f"{source}: direct import of {name}")
                if (
                    isinstance(node, ast.Attribute)
                    and node.attr == "windll"
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "ctypes"
                    and source not in windll_allowed
                ):
                    failures.append(f"{source}: direct ctypes.windll access")

        self.assertFalse(failures, "\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
