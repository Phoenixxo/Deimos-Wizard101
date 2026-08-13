# -*- mode: python ; coding: utf-8 -*-

import os
import shutil
import subprocess
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

repository_root = Path(SPECPATH).resolve()
analysis_source_root = repository_root / 'build' / 'pyinstaller-source'
merged_wizwalker = analysis_source_root / 'wizwalker'
shutil.rmtree(analysis_source_root, ignore_errors=True)
shutil.copytree(
    repository_root / 'libs' / 'wizwalker' / 'wizwalker',
    merged_wizwalker,
    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'),
)
shutil.copytree(
    repository_root / 'libs' / 'wizsprinter' / 'wizwalker' / 'extensions' / 'wizsprinter',
    merged_wizwalker / 'extensions' / 'wizsprinter',
    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'),
)
workspace_package_roots = [analysis_source_root]
for package_root in workspace_package_roots:
    sys.path.insert(0, str(package_root))
sys.path.insert(0, str(repository_root))
from scripts.package_artifacts import validate_package_inputs


def required_artifact(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} must name an artifact produced for this package build')
    return Path(value).resolve()


agent_artifact = required_artifact('DEIMOS_AGENT_ARTIFACT_PATH')
agent_manifest = required_artifact('DEIMOS_AGENT_MANIFEST_PATH')
native_module = required_artifact('DEIMOS_NATIVE_MODULE_PATH')
build_id = os.environ.get('DEIMOS_BUILD_ID')
if not build_id:
    raise RuntimeError('DEIMOS_BUILD_ID must identify this package build')
validate_package_inputs(agent_artifact, agent_manifest, native_module, build_id)

# Always rebuild the native helpers so local builds pick up Rust source changes
# (cargo is incremental, so this is cheap when nothing changed). A missing cargo
# is non-fatal — the os.path.exists guards below then omit the helper from the
# bundle. A cargo *failure* is not silently swallowed: without the warning below
# a stale target/release/*.exe from an earlier build gets bundled instead, which
# is how a moved manifest path went unnoticed until CI caught it.
#
#   libs/updater  -> deimos-updater.exe, the self-update helper
#   libs/wizpatch -> wizpatch.exe, the "verify/patch before launch" patcher
#                    (its default features include the `cli` bin target)
for _crate in ("updater", "wizpatch"):
    _manifest = os.path.join("libs", _crate, "Cargo.toml")
    if not os.path.exists(_manifest):
        print(f"WARNING: {_manifest} not found; skipping {_crate} build.")
        continue
    try:
        _r = subprocess.run(
            ["cargo", "build", "--release", "--manifest-path", _manifest],
            check=False,
        )
        if _r.returncode != 0:
            print(f"WARNING: cargo build failed for {_crate} (exit {_r.returncode}); "
                  "any binary bundled below is stale.")
    except FileNotFoundError:
        print(f"WARNING: cargo not found; skipping {_crate} build.")

# wizsprinter installs into the wizwalker.extensions namespace at runtime via a
# sys.path scan in wizwalker/extensions/__init__.py. PyInstaller's static
# analysis can't see that, so collect submodules and data files explicitly.
hiddenimports = (
    collect_submodules('wizwalker')
    + collect_submodules('wizwalker.extensions.wizsprinter')
    + collect_submodules('wizwalker.extensions.wizsprinter.combat_backends')
    + collect_submodules('lark')
    + ['wizlaunch', 'deimos_native']
)
if sys.platform == 'win32':
    hiddenimports += collect_submodules('pymem')

datas = [
    ('Deimos-logo.ico', '.'),
    ('Deimos-logo.png', '.'),
    ('locale', 'locale'),
    # The katsuba TypeList is no longer shipped: it's generated on demand by wiztype
    # from the running client and cached per-revision under %APPDATA%/Deimos/types/.
    (str(agent_artifact), '.'),
    (str(agent_manifest), '.'),
]
datas += collect_data_files('wizwalker.extensions.wizsprinter')
datas += collect_data_files('wizwalker.extensions.wizsprinter.combat_backends')
# Also collect .py sources as data. The data files above force
# wizwalker/extensions/wizsprinter/ to exist on disk, which would shadow the
# PYZ-archived submodules (Python treats the on-disk dir as a namespace
# package and only searches __path__ for submodules). Putting the .py files
# on disk too keeps imports working.
datas += collect_data_files(
    'wizwalker.extensions.wizsprinter',
    include_py_files=True,
)
datas += collect_data_files(
    'wizwalker.extensions.wizsprinter.combat_backends',
    include_py_files=True,
)

# Embed the native self-update helper (built from libs/updater via `cargo build
# --release`). If it hasn't been built, the bundle still works — Deimos just
# falls back to telling the user to update manually.
_updater_exe = os.path.join('libs', 'updater', 'target', 'release', 'deimos-updater.exe')
if os.path.exists(_updater_exe):
    datas += [(_updater_exe, '.')]
else:
    print(f"WARNING: {_updater_exe} not found; self-updater will be unavailable in this build.")

# Embed the wizpatch game-file patcher (built from libs/wizpatch). If it's
# missing, the bundle still works — the "verify/patch before launch" option
# simply no-ops with a warning.
_wizpatch_exe = os.path.join('libs', 'wizpatch', 'target', 'release', 'wizpatch.exe')
if os.path.exists(_wizpatch_exe):
    datas += [(_wizpatch_exe, '.')]
else:
    print(f"WARNING: {_wizpatch_exe} not found; game-file patching will be unavailable in this build.")


a = Analysis(
    ['Deimos.py'],
    pathex=[str(path) for path in workspace_package_roots],
    binaries=[(str(native_module), '.')],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

if sys.platform == 'darwin':
    exe = EXE(
        pyz,
        a.scripts,
        [],
        name='Deimos',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        icon='Deimos-logo.ico',
        exclude_binaries=True,
    )
    app = BUNDLE(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        name='Deimos.app',
        icon='Deimos-logo.ico',
        bundle_identifier='io.github.deimos-wizard101',
        info_plist={
            'LSMultipleInstancesProhibited': True,
        },
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name='Deimos',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        icon='Deimos-logo.ico',
        version='version_info.txt' if sys.platform == 'win32' else None,
        manifest='app.manifest' if sys.platform == 'win32' else None,
    )
