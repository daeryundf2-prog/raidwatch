r"""BitLocker lockbox (`raidwatch lockbox`) — rescue keys before power-off.

If investigators pull the plug or reboot, a BitLocker-encrypted volume
locks permanently: no post-raid baseline, no diff, no verify — total
evidence loss for BOTH sides. While the machine is still on, this
extracts and preserves:

- Recovery passwords / key protectors per fixed volume
  (``manage-bde -protectors -get <vol>`` — needs Administrator)
- Encryption status per volume (``manage-bde -status``)
- Volume GUID map (``mountvol``)

Windows-only; every failure is recorded per volume. Output is
**sensitive** — whoever holds lockbox-recovery-keys.txt holds the
drive. Route it to counsel, not to the seized machine's disks.
"""

from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path

from .common import sha256_file, utc_now_iso, write_json, write_manifest


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return out.returncode, (out.stdout or "") + (out.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)


def _fixed_volumes() -> list[str]:
    """Drive letters of fixed (DriveType=3) volumes."""
    if platform.system() != "Windows":
        return []
    code, out = _run(
        [
            "powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' "
            "| ForEach-Object { $_.DeviceID }",
        ]
    )
    vols = re.findall(r"[A-Z]:", out) if code == 0 else []
    if vols:
        return sorted(set(vols))
    code, out = _run(["fsutil", "fsinfo", "drives"])
    return sorted(set(re.findall(r"[A-Z]:\\", out))) if code == 0 else []


def _parse_protectors(text: str) -> dict:
    """manage-bde -protectors -get output → structured protectors."""
    passwords = re.findall(
        r"(?:Numerical Password|Recovery Password)[:\s]+([0-9]{6}-[0-9-]+)",
        text, re.I,
    )
    key_ids = re.findall(r"ID:\s*(\{[0-9A-Fa-f-]+\})", text)
    ext_keys = re.findall(r"External Key[^\n]*", text)
    return {
        "recovery_passwords": passwords,
        "key_protector_ids": key_ids,
        "external_key_lines": [k.strip() for k in ext_keys],
    }


def run_lockbox(root: Path | None, out_dir: Path) -> dict:
    """Collect BitLocker state + recovery keys for all fixed volumes."""
    out_dir = Path(out_dir).resolve()
    report = {
        "generated_utc": utc_now_iso(),
        "platform": platform.system(),
        "volumes": {},
        "mountvol": None,
    }
    if platform.system() != "Windows":
        report["status"] = "skipped"
        report["reason"] = "windows_only"
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json(out_dir / "lockbox.json", report)
        write_manifest(out_dir, "lockbox", {"status": "skipped"})
        return report

    code, mvol = _run(["mountvol"])
    report["mountvol"] = mvol if code == 0 else None

    key_lines = []
    for vol in _fixed_volumes():
        pcode, ptext = _run(["manage-bde", "-protectors", "-get", vol])
        scode, stext = _run(["manage-bde", "-status", vol])
        prot = _parse_protectors(ptext) if pcode == 0 else None
        report["volumes"][vol] = {
            "protectors": prot,
            "protectors_raw": ptext,
            "protectors_error": None if pcode == 0 else "needs_admin_or_failed",
            "status_raw": stext if scode == 0 else None,
            "status_error": None if scode == 0 else "needs_admin_or_failed",
        }
        if prot and prot["recovery_passwords"]:
            for pw in prot["recovery_passwords"]:
                key_lines.append(f"{vol}  {pw}")

    sensitive = bool(key_lines)
    keys_path = None
    if key_lines:
        keys_path = out_dir / "lockbox-recovery-keys.txt"
        keys_path.parent.mkdir(parents=True, exist_ok=True)
        keys_path.write_text(
            "raidwatch BitLocker recovery keys — SENSITIVE\n"
            "=============================================\n"
            "Route to counsel. Do NOT leave on the seized machine.\n\n"
            + "\n".join(key_lines)
            + "\n",
            encoding="utf-8",
        )
        report["recovery_keys_file"] = str(keys_path)
        report["recovery_keys_sha256"] = sha256_file(keys_path)

    report["status"] = "ok"
    report["note"] = (
        "Recovery keys let a locked volume be opened after power loss. "
        "Without them a reboot on a BitLocker drive ends all post-raid "
        "verification — for both sides."
    )
    report["sensitive"] = sensitive
    write_json(out_dir / "lockbox.json", report)
    write_manifest(
        out_dir, "lockbox",
        {"volumes": sorted(report["volumes"]), "sensitive": sensitive},
    )
    return report
