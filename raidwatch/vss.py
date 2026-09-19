r"""Volume Shadow Copy helpers — reach files Windows has locked open.

Two modes, both read-only with respect to evidence:

1. Existing shadows (no admin needed to *read*): files under
   \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\ mirror the volume
   at snapshot time — locked hives, in-use .evtx, and even the $MFT
   become readable. Bonus: the snapshot predates the raid, so its
   contents are pre-seizure state.
2. --vss opt-in (admin): create a fresh shadow, copy through it, then
   delete the shadow we created. Standard forensic practice; the shadow
   is ours, so deleting it destroys nothing pre-existing.

Non-Windows platforms report unsupported and everything falls back to
direct copies.
"""

from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path

GLOBALROOT = "\\\\?\\GLOBALROOT\\Device\\"


def list_shadows() -> list[str]:
    """Existing shadow device paths, e.g.
    \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3"""
    if platform.system() != "Windows":
        return []
    try:
        out = subprocess.run(
            ["vssadmin", "list", "shadows"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return re.findall(
        r"Shadow Copy Volume:\s*(\\\\\?\\GLOBALROOT\\[^\s]+)", out.stdout
    )


def is_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def create_shadow(drive: str = "C:") -> str | None:
    """vssadmin create shadow → device path, or None."""
    try:
        out = subprocess.run(
            ["vssadmin", "create", "shadow", f"/for={drive}"],
            capture_output=True, text=True, timeout=300,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(
        r"Shadow Copy Volume:\s*(\\\\\?\\GLOBALROOT\\[^\s]+)", out.stdout
    )
    return m.group(1) if m else None


def delete_shadow(device_path: str) -> bool:
    m = re.search(r"HarddiskVolumeShadowCopy(\d+)", device_path)
    if not m:
        return False
    try:
        out = subprocess.run(
            ["vssadmin", "delete", "shadows",
             f"/shadow=HarddiskVolumeShadowCopy{m.group(1)}", "/quiet"],
            capture_output=True, text=True, timeout=60,
        )
        return out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def shadow_path_for(abs_path: Path, shadow_device: str) -> Path:
    """Map C:\\Windows\\x → <shadow>\\Windows\\x."""
    p = str(abs_path)
    if len(p) >= 2 and p[1] == ":":
        p = p[2:]
    return Path(shadow_device + p.replace("/", "\\"))


class ShadowSource:
    """Try copying through shadow copies when the direct file is locked.

    `created` holds the device path of a shadow WE made so callers can
    delete it afterwards; existing shadows are never touched.
    """

    def __init__(self, drive: str = "C:", *, allow_create: bool = False):
        self.existing = list_shadows()
        self.created: str | None = None
        if allow_create and not self.existing and is_admin():
            self.created = create_shadow(drive)
        self.devices = self.existing + ([self.created] if self.created else [])

    def fallback_paths(self, abs_path: Path):
        for dev in self.devices:
            yield shadow_path_for(abs_path, dev)

    def cleanup(self) -> None:
        if self.created:
            delete_shadow(self.created)
            self.created = None
