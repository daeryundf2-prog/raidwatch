#!/bin/sh
# Build the raidwatch single-file binary with PyInstaller.
# MUST be run on the target platform — PyInstaller does not cross-compile.
#   Windows (PowerShell/CMD): py -m pip install pyinstaller && pyinstaller packaging\raidwatch.spec --clean --noconfirm
#   This script:              sh tools/build-exe.sh
# Output: dist/raidwatch(.exe)
set -e
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
if ! "$PY" -c "import PyInstaller" 2>/dev/null; then
    echo "PyInstaller not found for $PY — install first:" >&2
    echo "  $PY -m pip install 'pyinstaller>=6'" >&2
    exit 1
fi
"$PY" -m PyInstaller packaging/raidwatch.spec --clean --noconfirm
ls -lh dist/
