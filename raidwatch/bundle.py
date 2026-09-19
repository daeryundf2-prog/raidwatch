"""Deployable kit builder — send raidwatch to the client's machine.

Produces a self-contained directory ("the kit") that can be zipped,
e-mailed, or put on a USB stick:

    raidwatch-kit/
    ├── raidwatch.exe     — preferred: single-file binary (if provided)
    ├── raidwatch.pyz     — fallback: zipapp (needs Python 3.11+)
    ├── inputs/           — optional: profile.json, seized.*, baseline.db
    ├── RUN.bat / RUN.sh  — double-clickable field pipeline
    └── README.txt        — instructions for the client

Most seized PCs have no Python — build the exe once (packaging/
raidwatch.spec via PyInstaller on the target OS) and pass --exe so
RUN.bat never needs an interpreter. The .pyz stays as POSIX/dev
fallback.
"""

from __future__ import annotations

import shutil
import zipapp
from pathlib import Path

from .common import sha256_file, utc_now_iso, write_manifest

PYZ_NAME = "raidwatch.pyz"
EXE_NAME = "raidwatch.exe"

_RUN_BAT = r"""@echo off
rem raidwatch field runner — defense-side analysis kit
rem Prefers the bundled raidwatch.exe; falls back to Python + .pyz.
rem Asks for seizure date/list first (all optional — Enter skips).
setlocal
cd /d "%~dp0"
set ROOT=%~1
if "%ROOT%"=="" set ROOT=C:\

echo ============================================
echo  raidwatch - seizure response field kit
echo  Answers below are saved with the results.
echo  Press Enter to skip any question.
echo ============================================
echo.
set /p RAIDTIME="Seizure date/time (e.g. 2026-09-19 14:30): "
set /p SEIZED="Seized-list file (drag it here, or Enter): "
set /p NOTES="Case no. / notes (or Enter): "
if not exist inputs mkdir inputs
set "SEIZED=%SEIZED:"=%"
if not "%SEIZED%"=="" (
    if exist "%SEIZED%" (
        for %%f in ("%SEIZED%") do copy /y "%%~f" "inputs\seized%%~xf" >nul
        echo Seized list copied into inputs.
    ) else (
        echo WARNING: file not found - "%SEIZED%"
    )
)
if not "%RAIDTIME%%NOTES%"=="" (
    > inputs\info.txt echo datetime: %RAIDTIME%
    >> inputs\info.txt echo notes: %NOTES%
    echo Saved to inputs\info.txt
)
echo.
echo Starting analysis. This may take a while...

if exist raidwatch.exe (
    raidwatch.exe field --root "%ROOT%" --inputs inputs --out raidwatch-out
    goto :done
)
where py >nul 2>&1 && (set PY=py -3& goto :havepy)
where python >nul 2>&1 && (set PY=python& goto :havepy)
where python3 >nul 2>&1 && (set PY=python3& goto :havepy)
echo No raidwatch.exe and no Python 3.11+ found on PATH.
echo Ask the sender for a kit built with --exe.
pause
exit /b 1
:havepy
%PY% raidwatch.pyz field --root "%ROOT%" --inputs inputs --out raidwatch-out
:done
echo.
echo Done. Send the raidwatch-out folder back: it contains
echo raidwatch-results.zip and SHA256SUMS.txt for verification.
pause
endlocal
"""

_RUN_SH = """#!/bin/sh
# raidwatch field runner — defense-side analysis kit
# Asks for seizure date/list first (all optional — Enter skips).
set -e
cd "$(dirname "$0")"
ROOT="${1:-/}"

echo "============================================"
echo " raidwatch - seizure response field kit"
echo " Answers are saved with the results."
echo " Press Enter to skip any question."
echo "============================================"
printf "Seizure date/time (e.g. 2026-09-19 14:30): "
read -r RAIDTIME
printf "Seized-list file path (or Enter): "
read -r SEIZED
printf "Case no. / notes (or Enter): "
read -r NOTES
mkdir -p inputs
if [ -n "$SEIZED" ]; then
    SEIZED="${SEIZED%\\"}"; SEIZED="${SEIZED#\\"}"
    if [ -f "$SEIZED" ]; then
        ext="${SEIZED##*.}"
        cp "$SEIZED" "inputs/seized.$ext"
        echo "Seized list copied into inputs."
    else
        echo "WARNING: file not found - $SEIZED"
    fi
fi
if [ -n "$RAIDTIME$NOTES" ]; then
    printf 'datetime: %s\\nnotes: %s\\n' "$RAIDTIME" "$NOTES" > inputs/info.txt
    echo "Saved to inputs/info.txt"
fi
echo "Starting analysis. This may take a while..."

if [ -x ./raidwatch ]; then
    ./raidwatch field --root "$ROOT" --inputs inputs --out raidwatch-out
elif [ -x ./raidwatch.exe ]; then
    ./raidwatch.exe field --root "$ROOT" --inputs inputs --out raidwatch-out
else
    PY="$(command -v python3 || command -v python || true)"
    if [ -z "$PY" ]; then
        echo "no bundled binary and no python3 on PATH" >&2
        exit 1
    fi
    "$PY" raidwatch.pyz field --root "$ROOT" --inputs inputs --out raidwatch-out
fi
echo "Done. Return the raidwatch-out directory (raidwatch-results.zip + SHA256SUMS.txt)."
"""

_README = """raidwatch field kit — 압수수색 대응 분석 키트
=============================================

이 폴더를 압수 대상 PC로 옮긴 뒤 RUN.bat(윈도우) 또는 RUN.sh를 실행하면
됩니다.

- raidwatch.exe 가 포함된 키트: 설치 없이 바로 실행됩니다.
- raidwatch.pyz 만 있는 키트: Python 3.11+가 필요합니다
  (없으면 발송자에게 exe 포함 키트를 요청하세요).

실행하면 먼저 세 가지를 물어봅니다 (전부 선택사항 — Enter로 건너뛰기):
  1. 압수수색 집행 일시  — 예: 2026-09-19 14:30, 2026년 9월 19일 오후 2시
     입력하면 그 시각 이후 만들어진 파일만 골라내는 데 씁니다.
  2. 압수 목록 파일     — 사진/스캔 말고 텍스트(txt/csv)로 된 파일이 있으면
     이 창에 끌어다 놓으세요. 입력한 내용과 대조 검증이 자동 실행됩니다.
  3. 사건번호/메모     — 결과물에 함께 기록됩니다.

답변은 inputs/info.txt 에 저장되어 결과 zip 안의 field-report.json 에
기록됩니다. 압수 목록을 나중에 받았으면 inputs/ 폴더에
seized-목록.txt 같은 이름으로 넣고 RUN.bat 을 다시 실행하면 됩니다.

실행 내용 (raidwatch field):
  - sources    압수 목록 디지털 원본 회수 (프린터 스풀/Temp/휴지통)
  - artifacts  수사 도구 실행 흔적 수집 (prefetch/evtx/hive/VSS)
  - scan       inputs/profile.json 이 있으면 영장 조건 독립 재스캔
  - diff       inputs/baseline*.db 가 있으면 기준선 대비 변경 비교
  - verify     inputs/seized.* 가 있으면 압수 목록 검증

결과물은 raidwatch-out/ 에만 생깁니다:
  - raidwatch-results.zip — 분석 산출물 전부 (보존된 증거 사본 포함)
  - SHA256SUMS.txt        — 각 산출물의 해시 (전송 무결성 검증용)

주의: 이 키트는 분석 결과만 만들며, 디스크 전체를 수집·반출하지 않습니다.
분석 대상 루트를 바꾸려면 `RUN.bat D:\\` 처럼 인자를 주세요.
"""


def _stage_pyz_source(stage: Path, package_src: Path) -> None:
    """Stage 'raidwatch/' package + a top-level __main__ for zipapp."""
    shutil.copytree(package_src, stage / "raidwatch")
    (stage / "__main__.py").write_text(
        "from raidwatch.cli import main\n\nraise SystemExit(main())\n",
        encoding="utf-8",
    )


def build_bundle(
    out_dir: Path,
    *,
    profile: Path | None = None,
    seized: Path | None = None,
    baseline: Path | None = None,
    exe: Path | None = None,
) -> dict:
    """Assemble the deployable kit under out_dir. Returns a summary.

    `exe` should point at a PyInstaller-built raidwatch binary for the
    TARGET platform (Windows targets need raidwatch.exe built on
    Windows — PyInstaller does not cross-compile). Without it the kit
    falls back to the .pyz + a Python interpreter on the target.
    """
    out_dir = Path(out_dir).resolve()
    package_src = Path(__file__).resolve().parent
    inputs_dir = out_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    stage = out_dir / "_stage_pyz"
    try:
        _stage_pyz_source(stage, package_src)
        zipapp.create_archive(
            stage, out_dir / PYZ_NAME, interpreter="/usr/bin/env python3"
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    exe_name = None
    if exe is not None:
        exe = Path(exe)
        exe_name = EXE_NAME if exe.name.lower().endswith(".exe") else exe.name
        shutil.copy2(exe, out_dir / exe_name)
        (out_dir / exe_name).chmod(0o755)

    placed = []
    for src, dest_name in (
        (profile, "profile.json"),
        (seized, None),
        (baseline, "baseline.db"),
    ):
        if src is None:
            continue
        src = Path(src)
        name = dest_name or ("seized" + src.suffix.lower())
        shutil.copy2(src, inputs_dir / name)
        placed.append(f"inputs/{name}")

    (out_dir / "RUN.bat").write_text(_RUN_BAT, encoding="utf-8", newline="\r\n")
    run_sh = out_dir / "RUN.sh"
    run_sh.write_text(_RUN_SH, encoding="utf-8")
    run_sh.chmod(0o755)
    (out_dir / "README.txt").write_text(_README, encoding="utf-8")

    manifest = write_manifest(
        out_dir,
        "bundle",
        {
            "pyz": PYZ_NAME,
            "pyz_sha256": sha256_file(out_dir / PYZ_NAME),
            "exe": exe_name,
            "exe_sha256": (
                sha256_file(out_dir / exe_name) if exe_name else None
            ),
            "inputs": placed,
            "requires": (
                "nothing — self-contained exe"
                if exe_name
                else "python >= 3.11 on target PATH"
            ),
        },
    )
    return {
        "kit_dir": str(out_dir),
        "pyz": str(out_dir / PYZ_NAME),
        "exe": str(out_dir / exe_name) if exe_name else None,
        "inputs": placed,
        "manifest": str(manifest),
    }
