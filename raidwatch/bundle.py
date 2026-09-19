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
rem Optional return path: RUN.bat D:\ \\server\share — or set RW_DEST.
set "DEST=%~2"
if "%DEST%"=="" set "DEST=%RW_DEST%"

rem Auto-elevate via UAC: BitLocker keys, USN journal and VSS snapshots
rem need Administrator. If the prompt is declined we continue with
rem reduced coverage rather than dying.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights - click Yes on the UAC prompt.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%~1','%~2' -Verb RunAs" >nul 2>&1 && exit /b
    echo UAC declined/unavailable - continuing WITHOUT admin coverage.
)
set "VSSFLAG="
net session >nul 2>&1
if not errorlevel 1 (
    set "VSSFLAG=--vss"
    echo Running as Administrator - VSS snapshot enabled for locked files.
) else (
    echo Not Administrator - existing shadow copies still used if present.
)

echo ============================================
echo  raidwatch - seizure response field kit
echo  Answers below are saved with the results.
echo  Press Enter to skip any question.
echo ============================================
echo.
rem Counsel can pre-fill answers in CONFIG.txt so the client only has
rem to press Enter — any value left blank is asked here instead.
if exist CONFIG.txt (
    for /f "usebackq tokens=1,* delims== eol=#" %%a in ("CONFIG.txt") do set "CFG_%%a=%%b"
)
if "%DEST%"=="" if defined CFG_dest set "DEST=%CFG_dest%"

set "SEIZED="
set "SEXT="
set "SEIZEDBAKED="
rem A list baked into inputs\ by counsel needs no asking at all.
if exist inputs\seized.* (
    for %%f in (inputs\seized.*) do (
        set "SEIZED=%%f"
        set "SEXT=%%~xf"
    )
    set "SEIZEDBAKED=1"
    echo Seized list already provided: %SEIZED%
)

rem Anything not preset → clickable dialog (native WinForms calendar
rem picker + file browser; writes inputs\answers.txt). If the dialog
rem is unavailable we fall through to plain console questions.
set "NEEDGUI="
if not defined CFG_raid_datetime set "NEEDGUI=1"
if not defined SEIZEDBAKED set "NEEDGUI=1"
if not defined CFG_stamp set "NEEDGUI=1"
if not defined CFG_notes set "NEEDGUI=1"
if defined NEEDGUI if exist KIT-INPUT.ps1 (
    powershell -NoProfile -ExecutionPolicy Bypass -File KIT-INPUT.ps1 -KitDir "%~dp0" >nul 2>&1
    if exist inputs\answers.txt (
        for /f "usebackq tokens=1,* delims== eol=#" %%a in ("inputs\answers.txt") do set "ANS_%%a=%%b"
    )
    if not defined SEIZEDBAKED if exist inputs\seized.* (
        for %%f in (inputs\seized.*) do (
            set "SEIZED=%%f"
            set "SEXT=%%~xf"
        )
        set "SEIZEDBAKED=1"
        echo Seized list picked in dialog: %SEIZED%
    )
)

set "RAIDTIME=%CFG_raid_datetime%"
if not defined RAIDTIME set "RAIDTIME=%ANS_raid_datetime%"
if not defined RAIDTIME if not defined ANS_skip set /p RAIDTIME="Seizure date/time (e.g. 2026-09-19 14:30): "
if defined RAIDTIME echo Seizure date/time: %RAIDTIME%

if not defined SEIZEDBAKED if not defined ANS_skip set /p SEIZED="Seized-list file (drag it here, or Enter): "

set "STAMP=%CFG_stamp%"
if not defined STAMP set "STAMP=%ANS_stamp%"
if /i "%STAMP%"=="ask" set "STAMP="
if not defined STAMP if not defined ANS_skip set /p STAMP="Red stamps covering list text? (y/N): "

set "NOTES=%CFG_notes%"
if not defined NOTES set "NOTES=%ANS_notes%"
if not defined NOTES if not defined ANS_skip set /p NOTES="Case no. / notes (or Enter): "

if not exist inputs mkdir inputs
set "SEIZED=%SEIZED:"=%"
if not "%SEIZED%"=="" if not defined SEIZEDBAKED (
    if exist "%SEIZED%" (
        for %%f in ("%SEIZED%") do (
            copy /y "%%~f" "inputs\seized%%~xf" >nul
            set "SEXT=%%~xf"
        )
        echo Seized list copied into inputs.
    ) else (
        echo WARNING: file not found - "%SEIZED%"
    )
)
rem Scanned PDFs / photos need real OCR — use Windows built-in WinRT OCR.
set "OCRFLAG="
if /i "%STAMP%"=="y" set "OCRFLAG=-RemoveRedStamps"
if exist OCR-LIST.ps1 (
    echo "%SEXT%" | findstr /i "pdf jpg jpeg png bmp tif" >nul && (
        echo Running built-in Windows OCR on the seized list...
        powershell -NoProfile -ExecutionPolicy Bypass -File OCR-LIST.ps1 -In "%SEIZED%" -Out "inputs\seized-ocr.txt" %OCRFLAG% || echo OCR failed - continuing without it.
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
    raidwatch.exe field --root "%ROOT%" --inputs inputs --out raidwatch-out %VSSFLAG%
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
%PY% raidwatch.pyz field --root "%ROOT%" --inputs inputs --out raidwatch-out %VSSFLAG%
:done
if not "%DEST%"=="" (
    echo.
    echo Copying results to %DEST% ...
    mkdir "%DEST%" 2>nul
    copy /y "raidwatch-out\raidwatch-results.zip" "%DEST%\" >nul && echo  - raidwatch-results.zip uploaded
    copy /y "raidwatch-out\SHA256SUMS.txt" "%DEST%\" >nul
    copy /y "raidwatch-out\custody.txt" "%DEST%\" >nul
)
echo.
echo Done. Send the raidwatch-out folder back: it contains
echo raidwatch-results.zip and SHA256SUMS.txt for verification.
echo TIP: email custody.txt to counsel now — its hash timestamps the evidence set.
pause
endlocal
"""

_KIT_INPUT_PS1 = r"""param(
    [string]$Out = "inputs\answers.txt",
    [string]$KitDir = "."
)
# KIT-INPUT.ps1 — clickable input dialog for the field kit.
# Native WinForms (DateTimePicker calendar + OpenFileDialog) — zero
# installs on any Windows 10+. Writes inputs\answers.txt in the same
# key=value format as CONFIG.txt; copies a chosen seized list into
# inputs\. "모두 건너뛰기" (or closing the window) writes skip=1 so
# RUN.bat proceeds without asking anything on the console.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = "raidwatch - 압수수색 대응 분석"
$form.ClientSize = New-Object System.Drawing.Size(440, 300)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

function Add-Label($text, $y) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.AutoSize = $true
    $l.Location = New-Object System.Drawing.Point(16, $y)
    $form.Controls.Add($l)
}

Add-Label "집행(압수수색) 일시 — 달력에서 클릭 선택. 모르면 체크 해제" 12
$dtp = New-Object System.Windows.Forms.DateTimePicker
$dtp.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
$dtp.CustomFormat = "yyyy-MM-dd HH:mm"
$dtp.ShowCheckBox = $true          # unchecked = unknown / skip
$dtp.Checked = $true
$dtp.Width = 200
$dtp.Location = New-Object System.Drawing.Point(16, 36)
$form.Controls.Add($dtp)

Add-Label "압수 목록 파일 (선택사항 — txt/csv/json/pdf/사진)" 74
$txtFile = New-Object System.Windows.Forms.TextBox
$txtFile.ReadOnly = $true
$txtFile.Width = 300
$txtFile.Location = New-Object System.Drawing.Point(16, 98)
$form.Controls.Add($txtFile)
$btnFile = New-Object System.Windows.Forms.Button
$btnFile.Text = "파일 선택..."
$btnFile.Width = 100
$btnFile.Location = New-Object System.Drawing.Point(324, 96)
$ofd = New-Object System.Windows.Forms.OpenFileDialog
$ofd.Title = "압수 목록 파일 선택"
$ofd.Filter = "압수 목록|*.txt;*.csv;*.json;*.pdf;*.jpg;*.jpeg;*.png;*.bmp;*.tif;*.tiff|모든 파일|*.*"
$btnFile.Add_Click({
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtFile.Text = $ofd.FileName
    }
})
$form.Controls.Add($btnFile)

$chkStamp = New-Object System.Windows.Forms.CheckBox
$chkStamp.Text = "목록에 빨간 인주 도장이 글자를 가림"
$chkStamp.AutoSize = $true
$chkStamp.Location = New-Object System.Drawing.Point(16, 134)
$form.Controls.Add($chkStamp)

Add-Label "사건번호 / 메모 (선택사항)" 166
$txtNotes = New-Object System.Windows.Forms.TextBox
$txtNotes.Width = 408
$txtNotes.Location = New-Object System.Drawing.Point(16, 190)
$form.Controls.Add($txtNotes)

$answers = Join-Path $KitDir $Out
$seizedDest = $null

$btnOK = New-Object System.Windows.Forms.Button
$btnOK.Text = "분석 시작"
$btnOK.Width = 200
$btnOK.Location = New-Object System.Drawing.Point(16, 240)
$btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($btnOK)
$form.AcceptButton = $btnOK

$btnSkip = New-Object System.Windows.Forms.Button
$btnSkip.Text = "모두 건너뛰기"
$btnSkip.Width = 200
$btnSkip.Location = New-Object System.Drawing.Point(224, 240)
$btnSkip.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnSkip)

$result = $form.ShowDialog()
New-Item -ItemType Directory -Force -Path (Split-Path $answers) | Out-Null
$lines = @()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    if ($dtp.Checked) {
        $lines += "raid_datetime=" + $dtp.Value.ToString("yyyy-MM-dd HH:mm")
    }
    $lines += "stamp=" + $(if ($chkStamp.Checked) { "y" } else { "n" })
    if ($txtNotes.Text.Trim()) {
        $lines += "notes=" + ($txtNotes.Text.Trim() -replace "[\r\n=]", " ")
    }
    if ($txtFile.Text -and (Test-Path -LiteralPath $txtFile.Text)) {
        $ext = [IO.Path]::GetExtension($txtFile.Text)
        Copy-Item -LiteralPath $txtFile.Text `
            -Destination (Join-Path $KitDir "inputs\seized$ext") -Force
    }
} else {
    $lines += "skip=1"
}
[IO.File]::WriteAllLines($answers, $lines)
"""

_CONFIG_TXT = """\
# raidwatch kit preset answers — counsel fills what they know BEFORE
# sending; the client just double-clicks RUN.bat and answers nothing.
# 한 줄에 key=value 하나. # 으로 시작하는 줄과 빈 값은 무시됩니다.
# 비워둔 항목은 RUN.bat이 현장에서 물어봅니다.

# 집행(압수수색) 일시 — 변호인이 보통 아는 정보. 예: 2026-09-19 14:30
raid_datetime=

# 결과 자동 반송 경로 — 사무실 NAS/공유폴더 UNC. 예: \\\\서버\\raidwatch\\사건001
dest=

# 압수 목록에 빨간 인주 도장이 텍스트를 가리는지 — y / n / ask(현장에서 질문)
stamp=ask

# 사건번호·메모 — 모르면 비워두면 됨 (현장에서 입력하거나 건너뜀)
notes=
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
# Counsel presets from CONFIG.txt (same keys as RUN.bat).
_cfg() { sed -n "s/^$1=//p" CONFIG.txt 2>/dev/null | head -n 1; }
RAIDTIME="$(_cfg raid_datetime)"
if [ -z "$RAIDTIME" ]; then
    printf "Seizure date/time (e.g. 2026-09-19 14:30): "
    read -r RAIDTIME
else
    echo "Seizure date/time: $RAIDTIME (preset)"
fi
SEIZED=""
if ls inputs/seized.* >/dev/null 2>&1; then
    SEIZED="$(ls inputs/seized.* | head -n 1)"
    echo "Seized list already provided: $SEIZED"
else
    printf "Seized-list file path (or Enter): "
    read -r SEIZED
fi
NOTES="$(_cfg notes)"
if [ -z "$NOTES" ]; then
    printf "Case no. / notes (or Enter): "
    read -r NOTES
fi
mkdir -p inputs
if [ -n "$SEIZED" ]; then
    SEIZED="${SEIZED%\\"}"; SEIZED="${SEIZED#\\"}"
    case "$SEIZED" in
        inputs/*) : ;;  # baked by counsel — already in place
        *)
            if [ -f "$SEIZED" ]; then
                ext="${SEIZED##*.}"
                cp "$SEIZED" "inputs/seized.$ext"
                echo "Seized list copied into inputs."
            else
                echo "WARNING: file not found - $SEIZED"
            fi
            ;;
    esac
fi
if [ -n "$RAIDTIME$NOTES" ]; then
    printf 'datetime: %s\\nnotes: %s\\n' "$RAIDTIME" "$NOTES" > inputs/info.txt
    echo "Saved to inputs/info.txt"
fi
# Optional: OCR scanned lists/images if tesseract is installed.
if [ -n "$SEIZED" ] && command -v tesseract >/dev/null 2>&1; then
    case "$SEIZED" in
        *.pdf|*.jpg|*.jpeg|*.png|*.bmp|*.tif|*.tiff)
            echo "Running tesseract OCR on the seized list..."
            tesseract "$SEIZED" "inputs/seized-ocr" -l kor+eng 2>/dev/null || true
            ;;
    esac
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

_OCR_PS1 = r"""param(
    [Parameter(Mandatory=$true)][string]$In,
    [Parameter(Mandatory=$true)][string]$Out,
    [switch]$RemoveRedStamps
)
# OCR-LIST.ps1 — OCR a seized-list PDF or image using Windows built-in
# WinRT APIs (Windows.Data.Pdf renderer + Windows.Media.Ocr). No installs
# needed on Windows 10+. Korean OCR requires the Korean language pack;
# falls back to profile languages, then English.
# -RemoveRedStamps: erase red stamp ink (사법경찰관 인주) before OCR —
# stamps placed over text otherwise destroy recognition.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Runtime.WindowsRuntime

$asTaskOp = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]
$asTaskAct = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
})[0]

function Await-Op($Op, $Type) {
    $t = $asTaskOp.MakeGenericMethod($Type).Invoke($null, @($Op))
    $t.Wait()
    $t.Result
}
function Await-Act($Act) {
    $asTaskAct.Invoke($null, @($Act)).Wait()
}

[void][Windows.Storage.StorageFile, Windows.Storage, ContentType=WindowsRuntime]
[void][Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Storage.Streams, ContentType=WindowsRuntime]
[void][Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType=WindowsRuntime]
[void][Windows.Media.Ocr.OcrEngine, Windows.Media.Ocr, ContentType=WindowsRuntime]
[void][Windows.Data.Pdf.PdfDocument, Windows.Data.Pdf, ContentType=WindowsRuntime]
[void][Windows.Data.Pdf.PdfPageRenderOptions, Windows.Data.Pdf, ContentType=WindowsRuntime]
[void][Windows.Globalization.Language, Windows.Globalization, ContentType=WindowsRuntime]

$engine = $null
foreach ($lang in @('ko', 'en')) {
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage(
        (New-Object Windows.Globalization.Language $lang))
    if ($engine) { break }
}
if (-not $engine) {
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
}
if (-not $engine) { throw "no OCR engine (install a language pack with OCR)" }

if ($RemoveRedStamps) {
    Add-Type -TypeDefinition @'
public static class RwStampMask {
    // BGRA buffer → white-out pixels where red channel dominates
    public static void RemoveRed(byte[] px) {
        for (int i = 0; i + 3 < px.Length; i += 4) {
            int b = px[i], g = px[i + 1], r = px[i + 2];
            if (r > 110 && r - g > 55 && r - b > 55) {
                px[i] = 255; px[i + 1] = 255; px[i + 2] = 255;
            }
        }
    }
}
'@ -ReferencedAssemblies @([byte[]].Assembly.Location)
}

function Ocr-Bmp($bmp) {
    if ($RemoveRedStamps) {
        $bgra = [Windows.Graphics.Imaging.SoftwareBitmap]::Convert(
            $bmp,
            [Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
            [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied)
        $buf = [Windows.Storage.Streams.Buffer]::Create(
            $bgra.PixelWidth * $bgra.PixelHeight * 4)
        $bgra.CopyToBuffer($buf)
        $px = [byte[]]::new($buf.Length)
        [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::CopyTo(
            $buf, $px)
        [RwStampMask]::RemoveRed($px)
        $buf2 = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer(
            $px, 0, $px.Length)
        $bmp = [Windows.Graphics.Imaging.SoftwareBitmap]::CreateCopyFromBuffer(
            $buf2, [Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
            $bgra.PixelWidth, $bgra.PixelHeight)
    }
    $r = Await-Op ($engine.RecognizeAsync($bmp)) ([Windows.Media.Ocr.OcrResult])
    ($r.Lines | ForEach-Object { $_.Text }) -join "`n"
}

$resolved = (Resolve-Path $In).Path
$ext = [IO.Path]::GetExtension($resolved).ToLowerInvariant()
$out = @()

if ($ext -eq '.pdf') {
    $file = Await-Op ([Windows.Storage.StorageFile]::GetFileFromPathAsync($resolved)) ([Windows.Storage.StorageFile])
    $pdf = Await-Op ([Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($file)) ([Windows.Data.Pdf.PdfDocument])
    for ($i = 0; $i -lt $pdf.PageCount; $i++) {
        $page = $pdf.GetPage($i)
        $opts = New-Object Windows.Data.Pdf.PdfPageRenderOptions
        $opts.DestinationWidth = [uint32]($page.Size.Width * 2)
        $opts.DestinationHeight = [uint32]($page.Size.Height * 2)
        $stream = New-Object Windows.Storage.Streams.InMemoryRandomAccessStream
        Await-Act ($page.RenderToStreamAsync($stream, $opts))
        $stream.Seek(0)
        $dec = Await-Op ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
        $bmp = Await-Op ($dec.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        $out += Ocr-Bmp $bmp
        $stream.Dispose(); $page.Dispose()
    }
} else {
    $file = Await-Op ([Windows.Storage.StorageFile]::GetFileFromPathAsync($resolved)) ([Windows.Storage.StorageFile])
    $fs = Await-Op ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    $dec = Await-Op ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($fs)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bmp = Await-Op ($dec.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
    $out += Ocr-Bmp $bmp
    $fs.Dispose()
}

($out -join "`n") | Out-File -Encoding utf8 $Out
Write-Host "OCR complete -> $Out"
"""

_README = """raidwatch field kit — 압수수색 대응 분석 키트
=============================================

이 폴더를 압수 대상 PC로 옮긴 뒤 RUN.bat(윈도우) 또는 RUN.sh를 실행하면
됩니다.

- raidwatch.exe 가 포함된 키트: 설치 없이 바로 실행됩니다.
- raidwatch.pyz 만 있는 키트: Python 3.11+가 필요합니다
  (없으면 발송자에게 exe 포함 키트를 요청하세요).

실행하면 입력 창이 뜹니다 (클릭으로 선택 — 타이핑 거의 불필요):
  1. 압수수색 집행 일시  — 달력에서 날짜를 클릭해서 고릅니다.
     모르면 체크를 해제하면 됩니다.
  2. 압수 목록 파일     — "파일 선택..." 버튼으로 고릅니다.
     txt/csv/json은 바로 검증되고, PDF는 텍스트가 살아있으면 자동
     처리, 스캔/사진은 Windows 내장 OCR로 자동 읽기를 시도합니다.
  3. 인주 도장 체크    — 빨간 도장이 글자를 가리면 체크합니다.
  4. 사건번호/메모     — 모르면 비워둡니다.
  ※ 대화상자가 안 뜨는 환경에서는 검은 창에 직접 입력하게 됩니다
    (전부 Enter로 건너뛸 수 있습니다).

답변은 inputs/info.txt 에 저장되어 결과 zip 안의 field-report.json 에
기록됩니다. 압수 목록을 나중에 받았으면 inputs/ 폴더에
seized-목록.txt 같은 이름으로 넣고 RUN.bat 을 다시 실행하면 됩니다.

[발송하는 변호인용] CONFIG.txt 를 미리 채워 보내면 의뢰인은 질문에
답할 필요 없이 RUN.bat 더블클릭 + UAC "예" 만 누르면 됩니다:
  raid_datetime= 집행 일시   (미리 채우면 질문 생략)
  dest=          결과 반송 공유폴더 경로 (예: \\서버\공유\사건001)
  stamp=         인주 도장 여부 y/n/ask
  notes=         사건번호·메모
비워둔 항목은 현장에서 평소처럼 물어봅니다.

실행 내용 (raidwatch field):
  - sources    압수 목록 디지털 원본 회수 (프린터 스풀/Temp/휴지통)
  - artifacts  수사 도구 실행 흔적 수집 (prefetch/evtx/hive/VSS)
  - scan       inputs/profile.json 이 있으면 영장 조건 독립 재스캔
  - diff       inputs/baseline*.db 가 있으면 기준선 대비 변경 비교
  - verify     inputs/seized.* 가 있으면 압수 목록 검증

결과물은 raidwatch-out/ 에만 생깁니다:
  - raidwatch-results.zip — 분석 산출물 전부 (보존된 증거 사본 포함)
  - SHA256SUMS.txt        — 각 산출물의 해시 (전송 무결성 검증용)
  - custody.txt           — 증거 세트 봉인 해시. 실행 직후 이 파일을
                            변호인/본인 이메일로 보내두면 발송 시각이
                            "이 결과가 그 시점에 존재했다"는 독립 증거가
                            됩니다.

관리자 권한으로 실행하면 잠긴 파일(레지스트리 하이브, 사용 중 로그)을
읽기 위해 VSS 스냅샷이 자동 사용됩니다(읽기 전용·자동 해제).
관리자가 아니어도 기존 섀도 카피가 있으면 거기서 읽습니다.

결과를 바로 공유폴더로 반송하려면:
  RUN.bat D:\\ \\\\서버\\공유\\폴더      (두번째 인자 = 반송 위치)
  또는  set RW_DEST=\\서버\공유\폴더  후 RUN.bat 실행

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
    raid_date: str | None = None,
    dest: str | None = None,
    stamp: str | None = None,
    notes: str | None = None,
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
    (out_dir / "OCR-LIST.ps1").write_text(
        _OCR_PS1, encoding="utf-8", newline="\r\n"
    )
    (out_dir / "KIT-INPUT.ps1").write_text(
        _KIT_INPUT_PS1, encoding="utf-8", newline="\r\n"
    )
    (out_dir / "README.txt").write_text(_README, encoding="utf-8")

    # Counsel preset answers — anything left blank gets asked on-site.
    config = _CONFIG_TXT
    for key, value in (
        ("raid_datetime", raid_date),
        ("dest", dest),
        ("stamp", stamp),
        ("notes", notes),
    ):
        if value:
            value = str(value).splitlines()[0].strip()
            config = config.replace(f"{key}=\n", f"{key}={value}\n", 1)
            config = config.replace(f"{key}=ask\n", f"{key}={value}\n", 1)
    (out_dir / "CONFIG.txt").write_text(
        config, encoding="utf-8", newline="\r\n"
    )

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
            "ocr_helper": "OCR-LIST.ps1",
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
