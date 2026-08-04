# -*- mode: python ; coding: utf-8 -*-

import os
import shutil
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

datas = [
    ('Deimos-logo.ico', '.'),
    ('Deimos-logo.png', '.'),
    ('locale', 'locale'),
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
