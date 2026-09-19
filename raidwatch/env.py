"""Environment probe (`raidwatch env`) — machine spec/capability check.

Runs FIRST in every field run: the machine decides what we can do, so
we ask it before doing anything. Probes OS version, elevation,
filesystems, available system tools, and derives a capability map the
rest of the pipeline consults — e.g. no fsutil → no USN journal; FAT
volume → no ADS/journal; no PowerShell → console prompts only;
pre-Win10 → legacy $I recycle-bin format.

Everything degrades gracefully: a failed probe records
"unknown"/False and never aborts the run.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from .common import TOOL_VERSION, utc_now_iso, write_json

# Windows major.minor → friendly name for report readability.
_WIN_NAMES = {
    (6, 1): "Windows 7 / Server 2008R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 3): "Windows 8.1 / Server 2012R2",
    (10, 0): "Windows 10/11 / Server 2016+",
}

_TOOLS = (
    "fsutil", "certutil", "manage-bde", "vssadmin", "powershell",
    "pwsh", "wevtutil", "reg", "chkdsk", "wbadmin", "diskpart",
    "robocopy", "tar", "cipher",
)

_CLOUD_HINTS = (
    "OneDrive", "Google Drive", "GoogleDrive", "Dropbox", "iCloudDrive",
    "iCloud Drive", "네이버 MYBOX", "Naver MYBOX", "Box", "MEGA",
)


def _is_elevated() -> bool:
    if platform.system() == "Windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _run_text(cmd: list[str], timeout: int = 15) -> str | None:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True,
            errors="replace", timeout=timeout,
        )
        return (out.stdout or out.stderr or "").strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _windows_version() -> dict:
    v = sys.getwindowsversion()  # type: ignore[attr-defined]
    return {
        "major": v.major,
        "minor": v.minor,
        "build": v.build,
        "name": _WIN_NAMES.get(
            (v.major, v.minor), f"Windows {v.major}.{v.minor}"
        ),
    }


def _win_volumes() -> list[dict]:
    import ctypes

    vols = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    _DRIVE_TYPES = {
        0: "unknown", 1: "invalid", 2: "removable", 3: "fixed",
        4: "remote", 5: "cdrom", 6: "ramdisk",
    }
    for i in range(26):
        if not (bitmask >> i) & 1:
            continue
        letter = chr(ord("A") + i)
        root = f"{letter}:\\"
        dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
        fs = "unknown"
        try:
            buf = ctypes.create_unicode_buffer(64)
            if ctypes.windll.kernel32.GetVolumeInformationW(
                root, None, 0, None, None, None, buf, 64
            ):
                fs = buf.value or "unknown"
        except Exception:
            pass
        try:
            usage = shutil.disk_usage(root)
            free_gb, total_gb = (
                round(usage.free / 1e9, 1), round(usage.total / 1e9, 1))
        except OSError:
            free_gb = total_gb = None
        vols.append({
            "mount": root,
            "drive_type": _DRIVE_TYPES.get(dtype, str(dtype)),
            "filesystem": fs,
            "free_gb": free_gb,
            "total_gb": total_gb,
        })
    return vols


def _posix_volumes() -> list[dict]:
    vols = []
    mounts: list[tuple[str, str]] = []
    try:
        with open("/proc/mounts", encoding="utf-8",
                  errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1].startswith("/"):
                    mounts.append((parts[1], parts[2]))
    except OSError:
        text = _run_text(["mount"]) or ""
        for line in text.splitlines():
            # macOS: "/dev/disk3s1 on / (apfs, ...)"
            if " on " in line:
                mnt = line.split(" on ", 1)[1].split(" (")[0]
                fs = line.split("(", 1)[1].split(",")[0] if "(" in line else "unknown"
                mounts.append((mnt.strip(), fs.strip()))
    seen = set()
    for mnt, fs in mounts:
        if mnt in seen:
            continue
        seen.add(mnt)
        if mnt != "/" and not (
            mnt.startswith("/Volumes") or mnt.startswith("/media")
            or mnt.startswith("/mnt") or mnt.startswith("/home")
            or mnt == "/System/Volumes/Data"
        ):
            continue
        try:
            usage = shutil.disk_usage(mnt)
            free_gb, total_gb = (
                round(usage.free / 1e9, 1), round(usage.total / 1e9, 1))
        except OSError:
            free_gb = total_gb = None
        vols.append({
            "mount": mnt, "drive_type": "unknown", "filesystem": fs,
            "free_gb": free_gb, "total_gb": total_gb,
        })
    return vols


def _ram_gb() -> float | None:
    if platform.system() == "Windows":
        try:
            import ctypes

            class _M(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            m = _M()
            m.dwLength = ctypes.sizeof(_M)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(
                ctypes.byref(m))
            return round(m.ullTotalPhys / 1e9, 1)
        except Exception:
            return None
    try:
        return round(
            os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 1e9,
            1,
        )
    except (ValueError, OSError, AttributeError):
        return None


def _reg_atime_disabled() -> int | None:
    """NtfsDisableLastAccessUpdate: None=not windows/unknown."""
    if platform.system() != "Windows":
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
        ) as k:
            return int(
                winreg.QueryValueEx(k, "NtfsDisableLastAccessUpdate")[0]
            )
    except OSError:
        return None


def _ps_version() -> str | None:
    for exe in ("powershell", "pwsh"):
        if shutil.which(exe):
            out = _run_text(
                [exe, "-NoProfile", "-Command",
                 "$PSVersionTable.PSVersion.ToString()"], 20)
            if out:
                return out.splitlines()[0].strip()
    return None


def _cloud_dirs() -> list[str]:
    found = []
    homes = []
    if platform.system() == "Windows":
        for base in (Path(os.environ.get("USERPROFILE", "C:/")),
                     Path("C:/Users")):
            if base.is_dir():
                if base.name != "Users":
                    homes.append(base)
                else:
                    homes.extend(
                        p for p in base.iterdir() if p.is_dir())
    else:
        homes.append(Path.home())
    for home in homes:
        for hint in _CLOUD_HINTS:
            if (home / hint).exists():
                found.append(str(home / hint))
    return sorted(set(found))


def probe_environment(out_dir: Path | None = None) -> dict:
    """Probe the machine; optionally write env.json under out_dir."""
    system = platform.system()
    is_win = system == "Windows"
    win_ver = _windows_version() if is_win else {}
    elevated = _is_elevated()
    tools = {t: bool(shutil.which(t)) for t in _TOOLS}
    volumes = _win_volumes() if is_win else _posix_volumes()
    ps_ver = _ps_version() if (tools["powershell"] or tools["pwsh"]) else None
    ntfs_vols = [
        v for v in volumes if v["filesystem"].upper() == "NTFS"]
    remote_vols = [v for v in volumes if v["drive_type"] == "remote"]
    removable_vols = [
        v for v in volumes if v["drive_type"] == "removable"]
    build = win_ver.get("build", 0)
    win_major = win_ver.get("major", 0)
    atime_reg = _reg_atime_disabled()

    caps = {
        # USN journal needs fsutil + admin + an NTFS volume
        "usn_journal": bool(
            is_win and tools["fsutil"] and elevated and ntfs_vols),
        # VSS snapshot work needs vssadmin + admin
        "vss": bool(is_win and tools["vssadmin"] and elevated),
        # BitLocker key export needs manage-bde + admin
        "bitlocker": bool(is_win and tools["manage-bde"] and elevated),
        # Native GUI input dialog: powershell + client windows
        "gui_dialog": bool(
            is_win and (tools["powershell"] or tools["pwsh"])),
        # WinRT OCR needs Win10 build 10240+
        "winrt_ocr": bool(is_win and build >= 10240),
        # NTFS ADS / $I v2 bin format / certutil hashing
        "ads": bool(ntfs_vols),
        "recycle_bin_v2": bool(win_major >= 10),
        "recycle_bin_legacy": bool(is_win and win_major < 10),
        "certutil_hash": bool(is_win and tools["certutil"]),
        "evtx": bool(is_win and tools["wevtutil"]),
        # Always-on channels
        "window_scan": True,
        "leftovers": True,
        "containers": True,
    }

    env = {
        "generated_utc": utc_now_iso(),
        "tool_version": TOOL_VERSION,
        "os": {
            "system": system,
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            **({"windows": win_ver} if is_win else {}),
        },
        "python": platform.python_version(),
        "elevated": elevated,
        "hardware": {
            "cpu_cores": os.cpu_count(),
            "ram_gb": _ram_gb(),
        },
        "locale": {
            "preferred_encoding": locale_getpreferred(),
            "stdout_encoding": getattr(
                sys.stdout, "encoding", None),
        },
        "tools": tools,
        "powershell_version": ps_ver,
        "volumes": volumes,
        "ntfs_volumes": [v["mount"] for v in ntfs_vols],
        "remote_volumes": [v["mount"] for v in remote_vols],
        "removable_volumes": [v["mount"] for v in removable_vols],
        "cloud_sync_dirs": _cloud_dirs(),
        "ntfs_atime": (
            "disabled_or_system_default" if atime_reg in (1, 2, 3)
            else "enabled" if atime_reg == 0
            else "unknown" if atime_reg is None
            else f"registry_value_{atime_reg}"
        ),
        "capabilities": caps,
        "summary": _summarize(caps, is_win, elevated, ps_ver),
        "note": (
            "capabilities=False means that channel was skipped or "
            "degraded on this machine — see tools/volumes for why. "
            "Degraded ≠ impossible: e.g. journal can still run from "
            "an exported CSV without fsutil."
        ),
    }
    if out_dir is not None:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        write_json(Path(out_dir) / "env.json", env)
    return env


def locale_getpreferred() -> str | None:
    try:
        import locale

        return locale.getpreferredencoding(False)
    except Exception:
        return None


def _summarize(
    caps: dict, is_win: bool, elevated: bool, ps_ver: str | None
) -> list[str]:
    lines = []
    if not is_win:
        lines.append(
            "non-Windows host — NTFS-only channels "
            "(journal/ADS/VSS/BitLocker/evtx) unavailable; "
            "metadata channels still run")
    if is_win and not elevated:
        lines.append(
            "not elevated — BitLocker/USN/VSS/locked-file reads "
            "will fail; rerun via RUN.bat for UAC elevation")
    if is_win and elevated:
        lines.append("elevated — privileged channels enabled")
    if ps_ver:
        lines.append(f"PowerShell {ps_ver} — GUI input dialog OK")
    off = [k for k, v in caps.items() if v is False]
    if off:
        lines.append("capabilities off: " + ", ".join(sorted(off)))
    return lines
