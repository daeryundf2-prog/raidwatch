"""Pre-raid hardening kit generator.

`raidwatch harden --out dir` writes a ready-to-run bundle that turns ON
the operating system's own recording before a seizure ever happens.
The idea: investigators' tools leave traces, but only if the OS was
asked to remember. Everything here is standard Windows audit policy —
nothing hides, blocks, or interferes; it just *records*.

HARDEN.bat (run as Administrator) enables:
- USN journal on C: — per-file create/delete/rename history
- Process creation auditing + command-line capture (4688 events)
- PowerShell script-block + module logging
- PrintService Operational log (what got printed — seized lists)
- Bitsadmin/Kernel-PnP operational logs (device connect history)
sysmon-raidwatch.xml is included for users who install Sysmon
(microsoft.com/sysinternals): it adds file-create time tampering
detection (Event 2 — catches timestomping) and file creation events
in evidence-relevant locations.
REVERT.bat turns the audit settings back off.
"""

from __future__ import annotations

from pathlib import Path

from .common import sha256_file, utc_now_iso, write_json, write_manifest

_HARDEN_BAT = r"""@echo off
rem raidwatch HARDEN — pre-raid audit hardening. Run as Administrator.
rem Everything below only turns on recording; nothing is hidden or blocked.
setlocal
net session >nul 2>&1 || (echo Need Administrator. & pause & exit /b 1)

echo [1/6] USN journal on C: — per-file create/delete/rename history
fsutil usn createjournal m=2147483648 a=33554432 C:

echo [2/6] Process creation auditing incl. command line (Event 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

echo [3/6] PowerShell script-block + module logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

echo [4/6] PrintService Operational log (prints = seized-list originals)
wevtutil sl Microsoft-Windows-PrintService/Operational /e:true

echo [5/6] Device / storage operational logs
wevtutil sl Microsoft-Windows-Kernel-Pnp/Configuration /e:true 2>nul
wevtutil sl Microsoft-Windows-Storage-Storport/Operational /e:true 2>nul

echo [6/6] Optional: Sysmon — install for file-level detail
echo If sysmon-raidwatch.xml sits next to this script and Sysmon64.exe is
echo on PATH:  Sysmon64.exe -i sysmon-raidwatch.xml

echo Done. Reboot or logoff not required; auditing is live now.
pause
endlocal
"""

_REVERT_BAT = r"""@echo off
rem Revert raidwatch hardening — run as Administrator.
setlocal
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f
wevtutil sl Microsoft-Windows-PrintService/Operational /e:false
echo Reverted. (USN journal left enabled — fsutil usn deletejournal /d C: removes it.)
pause
endlocal
"""

_SYSMON_XML = """<Sysmon schemaversion="4.90">
  <!-- raidwatch sysmon profile — record, don't interfere -->
  <HashAlgorithms>sha256</HashAlgorithms>
  <EventFiltering>
    <!-- Event 1: every process creation with cmdline + hashes -->
    <ProcessCreate onmatch="exclude"/>
    <!-- Event 2: file-create-time CHANGED — classic timestomp tell -->
    <FileCreateTime onmatch="exclude"/>
    <!-- Event 11: file creation in evidence-relevant locations -->
    <FileCreate onmatch="include">
      <TargetFilename condition="begin with">C:\\Windows\\Prefetch</TargetFilename>
      <TargetFilename condition="begin with">C:\\Windows\\System32\\spool</TargetFilename>
      <TargetFilename condition="contains">\\AppData\\Local\\Temp</TargetFilename>
      <TargetFilename condition="contains">\\Recent</TargetFilename>
      <TargetFilename condition="end with">.evtx</TargetFilename>
    </FileCreate>
    <!-- Event 13: registry set — device/USB hive writes -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">Enum\\USBSTOR</TargetObject>
    </RegistryEvent>
    <!-- Event 26: file deletion logged (keeps name+hash) -->
    <FileDelete onmatch="include">
      <TargetFilename condition="contains">\\AppData\\Local\\Temp</TargetFilename>
      <TargetFilename condition="begin with">C:\\Windows\\System32\\spool</TargetFilename>
    </FileDelete>
  </EventFiltering>
</Sysmon>
"""

_README = """raidwatch harden — 사전 감사 하드닝
=====================================

압수수색 "이전"에 대상 PC에서 HARDEN.bat을 관리자 권한으로 실행하세요.
운영체제 자체의 기록 기능을 켜는 것뿐이며, 어떤 것도 숨기거나 차단하지
않습니다 — 집행 중 수사관의 행위가 Windows 로그에 남도록 만듭니다.

켜지는 것:
- USN 저널: 파일 생성/삭제/이름변경 이력 (raidwatch journal로 재생)
- 프로세스 생성 감사 + 명령행 캡처 (어떤 도구가 어떤 인자로 실행됐는지)
- PowerShell 스크립트 블록 로깅 (수사 스크립트 본문까지 기록)
- 인쇄 로그 (압수 목록 인쇄 이벤트 — sources의 스풀 회수와 연계)
- 장치 연결 로그 (수사관 수집 USB의 연결 기록)

선택: Sysmon64.exe를 sysinternals에서 받아 sysmon-raidwatch.xml로
설치하면 파일 시각 조작 탐지(Event 2 = timestomp 방지)와 파일 생성/
삭제 기록이 추가됩니다.

되돌리기: REVERT.bat (관리자). USN 저널은 별도 명령이 주석에 있습니다.
"""


def build_harden(out_dir: Path) -> dict:
    """Write the hardening bundle; returns summary with file hashes."""
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, content in (
        ("HARDEN.bat", _HARDEN_BAT),
        ("REVERT.bat", _REVERT_BAT),
        ("sysmon-raidwatch.xml", _SYSMON_XML),
        ("README.txt", _README),
    ):
        p = out_dir / name
        newline = "\r\n" if name.endswith(".bat") else "\n"
        p.write_text(content, encoding="utf-8", newline=newline)
        files[name] = sha256_file(p)
    write_json(
        out_dir / "harden.json",
        {
            "generated_utc": utc_now_iso(),
            "files": files,
            "note": (
                "Enables OS-native recording only (audit policy, event "
                "logs, USN journal, optional Sysmon). Nothing hides, "
                "blocks, or interferes — it records."
            ),
        },
    )
    write_manifest(out_dir, "harden", {"files": sorted(files)})
    return {"out_dir": str(out_dir), "files": files}
