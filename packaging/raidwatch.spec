# PyInstaller spec for the raidwatch single-file binary.
# Build (run on the TARGET platform — no cross-compile):
#   pyinstaller packaging/raidwatch.spec --clean --noconfirm
# Output: dist/raidwatch(.exe)

import os

_HERE = os.path.dirname(os.path.abspath(SPEC))
_ROOT = os.path.dirname(_HERE)

a = Analysis(
    [os.path.join(_HERE, "raidwatch-entry.py")],
    pathex=[_ROOT],
    binaries=[],
    # Ship the package SOURCE too — `raidwatch bundle` run inside the
    # frozen exe re-stages it into the kit's .pyz fallback; in onefile
    # mode the importable package lives in the PYZ, not as files.
    datas=[(os.path.join(_ROOT, "raidwatch"), "raidwatch_src")],
    # gui.py imports tkinter lazily inside a try — force the bundling
    # hook so the office-side GUI works inside the exe.
    hiddenimports=["tkinter"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="raidwatch",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX raises AV false positives on forensic tools
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
