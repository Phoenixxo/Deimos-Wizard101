# -*- mode: python ; coding: utf-8 -*-

import os
import subprocess
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

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
    + collect_submodules('wizsprinter')
    + collect_submodules('lark')
    + ['wizlaunch']
)

datas = [
    ('Deimos-logo.ico', '.'),
    ('Deimos-logo.png', '.'),
    ('locale', 'locale'),
    # The katsuba TypeList is no longer shipped: it's generated on demand by wiztype
    # from the running client and cached per-revision under %APPDATA%/Deimos/types/.
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
    pathex=[],
    binaries=[],
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
    version='version_info.txt',
    manifest='app.manifest',
)
