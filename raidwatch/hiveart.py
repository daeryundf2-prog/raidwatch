"""Structured artifact extraction from parsed registry hives.

Built on hive.py: turns raw nk/vk cells into forensic answers —
which tools executed (ShimCache/AmCache/UserAssist), which USB devices
an operator plugged in (USBSTOR), what persists (Run keys), and what
documents a user touched (RecentDocs).

Honesty notes:
- ShimCache entry timestamps are the *file's* mtime at scan time, not
  the execution time — the cache key's LastWrite approximates when the
  cache was last updated. Both are reported, labelled.
- Win10 shimcache entries are parsed via the documented "00ts" record
  layout; other versions fall back to a UTF-16 path scan marked
  "scan_fallback".
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from .common import filetime_to_iso, ns_to_iso
from .hive import Hive, HiveError, NkKey

ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def _control_sets(hive: Hive) -> list[NkKey]:
    root = hive.root()
    return [k for k in hive.subkeys(root) if k.name.lower().startswith("controlset")]


def _find_any(hive: Hive, root: NkKey, *suffix: str) -> NkKey | None:
    key = root
    for part in suffix:
        nxt = next((k for k in hive.subkeys(key) if k.name.lower() == part.lower()), None)
        if nxt is None:
            return None
        key = nxt
    return key


def _value_named(hive: Hive, key: NkKey, *names: str):
    vals = hive.values(key)
    for n in names:
        for v in vals:
            if v.name.lower() == n.lower():
                return v
    return None


# ---------------------------------------------------------------------------
# ShimCache (AppCompatCache) — programs Windows recorded as executed

_WIN10_SIG = b"00ts"


def _shimcache_win10(blob: bytes) -> list[dict]:
    """Parse the Win10 '00ts' entry layout; [] if none found."""
    out = []
    pos = 0
    while True:
        i = blob.find(_WIN10_SIG, pos)
        if i < 0 or i + 48 > len(blob):
            break
        entry_size = struct.unpack_from("<I", blob, i + 8)[0]
        path_size = struct.unpack_from("<I", blob, i + 12)[0]
        ft = struct.unpack_from("<Q", blob, i + 16)[0]
        path_off = i + 32  # signature(4)+unk(4)+size(4)+psz(4)+ft(8)+unk(8)
        if not (0 < path_size <= 2048 and path_off + path_size <= len(blob)):
            pos = i + 4
            continue
        path = blob[path_off:path_off + path_size].decode(
            "utf-16-le", errors="replace"
        ).rstrip("\x00")
        if path:
            out.append({
                "path": path,
                "entry_file_mtime_utc": filetime_to_iso(ft),
                "parse": "win10_00ts",
            })
        pos = i + (entry_size if entry_size > 4 else 4)
    return out


def _shimcache_scan(blob: bytes) -> list[dict]:
    """Fallback: UTF-16 path strings inside the cache blob."""
    out = []
    i = 0
    while i + 4 < len(blob):
        # plausible UTF-16 path start: "X:\" or "\\" or "%windir%" style
        if blob[i + 1] == 0 and 32 <= blob[i] < 127:
            j = i
            while j + 1 < len(blob) and blob[j + 1] == 0 and 32 <= blob[j] < 127:
                j += 2
            n = j - i + 2
            if n >= 8:
                s = blob[i:i + n].decode("utf-16-le", errors="replace")
                if "\\" in s and (".exe" in s.lower() or s[1:3] == ":\\"):
                    out.append({"path": s, "parse": "scan_fallback"})
            i = j + 2
        else:
            i += 1
    return out


def shimcache(hive: Hive) -> list[dict]:
    """Executed-program evidence from SYSTEM ControlSet*\\...AppCompatCache."""
    out: list[dict] = []
    for cs in _control_sets(hive):
        key = _find_any(
            hive, cs, "Control", "Session Manager", "AppCompatCache"
        ) or _find_any(hive, cs, "Control", "Session Manager", "AppCompatCache", "AppCompatibility")
        if key is None:
            continue
        val = _value_named(hive, key, "AppCompatCache", "Main")
        if val is None or not val.data:
            continue
        cache_lw = ns_to_iso(key.last_write_ns) if key.last_write_ns else None
        entries = _shimcache_win10(val.data) or _shimcache_scan(val.data)
        for e in entries:
            e["cache_key"] = cs.name
            e["cache_last_write_utc"] = cache_lw
            out.append(e)
    return out


# ---------------------------------------------------------------------------
# USBSTOR — devices that were plugged in (evidence-collection drives)

def usbstor(hive: Hive) -> list[dict]:
    out: list[dict] = []
    for cs in _control_sets(hive):
        base = _find_any(hive, cs, "Enum", "USBSTOR")
        if base is None:
            continue
        for dev in hive.subkeys(base):
            for serial in hive.subkeys(dev):
                fv = _value_named(hive, serial, "FriendlyName")
                out.append({
                    "device": dev.name,
                    "serial": serial.name,
                    "friendly_name": fv.text() if fv else None,
                    "first_seen_utc": (
                        ns_to_iso(serial.last_write_ns)
                        if serial.last_write_ns else None
                    ),
                    "control_set": cs.name,
                })
    return out


# ---------------------------------------------------------------------------
# UserAssist — GUI program launches (NTUSER.DAT)

def userassist(hive: Hive) -> list[dict]:
    base = hive.find(
        "Software", "Microsoft", "Windows", "CurrentVersion",
        "Explorer", "UserAssist",
    )
    if base is None:
        return []
    out: list[dict] = []
    for guid in hive.subkeys(base):
        count = next(
            (k for k in hive.subkeys(guid) if k.name.lower() == "count"), None
        )
        if count is None:
            continue
        for v in hive.values(count):
            name = v.name.translate(ROT13)
            run_count = last_run = None
            d = v.data
            if len(d) >= 68:
                run_count = struct.unpack_from("<I", d, 4)[0]
                last_run = filetime_to_iso(struct.unpack_from("<Q", d, 60)[0])
            elif len(d) >= 16:
                run_count = struct.unpack_from("<I", d, 4)[0]
                last_run = filetime_to_iso(struct.unpack_from("<Q", d, 8)[0])
            out.append({
                "name_rot13_decoded": name,
                "run_count": run_count,
                "last_run_utc": last_run,
            })
    return out


# ---------------------------------------------------------------------------
# Run keys — autostart entries (HKLM/HKCU hives)

def run_keys(hive: Hive) -> list[dict]:
    out: list[dict] = []
    for path in (
        ("Microsoft", "Windows", "CurrentVersion", "Run"),
        ("Microsoft", "Windows", "CurrentVersion", "RunOnce"),
    ):
        key = hive.find(*path) or hive.find("Software", *path)
        if key is None:
            continue
        for v in hive.values(key):
            out.append({
                "key": "\\".join(path),
                "value_name": v.name,
                "command": v.text(),
                "key_last_write_utc": (
                    ns_to_iso(key.last_write_ns) if key.last_write_ns else None
                ),
            })
    return out


# ---------------------------------------------------------------------------
# RecentDocs — documents a user opened (NTUSER.DAT)

def recentdocs(hive: Hive) -> list[dict]:
    base = hive.find(
        "Software", "Microsoft", "Windows", "CurrentVersion",
        "Explorer", "RecentDocs",
    )
    if base is None:
        return []
    out: list[dict] = []

    def _entries(key: NkKey, sub: str | None) -> None:
        for v in hive.values(key):
            try:
                name = v.data.split(b"\x00\x00")[0].decode(
                    "utf-16-le", errors="replace"
                )
            except (UnicodeDecodeError, ValueError):
                name = ""
            if name.strip():
                out.append({"name": name.strip(), "folder": sub})

    _entries(base, None)
    for sub in hive.subkeys(base):
        _entries(sub, sub.name)
    return out


# ---------------------------------------------------------------------------
# Amcache.hve — program inventory with SHA-1 (InventoryApplicationFile)

def amcache(hive: Hive) -> list[dict]:
    root = hive.root()
    out: list[dict] = []
    for top_name in ("File", "InventoryApplicationFile"):
        top = next(
            (k for k in hive.subkeys(root) if k.name.lower() == top_name.lower()),
            None,
        )
        if top is None:
            continue
        for mid in hive.subkeys(top):
            for leaf in hive.subkeys(mid) or [mid]:
                vals = {v.name.lower(): v for v in hive.values(leaf)}
                path_v = next(
                    (vals[k] for k in (
                        "lowercaselongpath", "longpath", "fullpath", "101"
                    ) if k in vals),
                    None,
                )
                sha1_v = next(
                    (vals[k] for k in ("sha1", "fileid", "17") if k in vals),
                    None,
                )
                if path_v is None:
                    continue
                path_text = path_v.text() or ""
                if not path_text.strip():
                    continue
                sha1 = None
                if sha1_v is not None:
                    raw = sha1_v.data
                    sha1 = raw.hex() if raw and len(raw) == 20 else (
                        raw[:20].hex() if len(raw) >= 20 else sha1_v.text()
                    )
                out.append({
                    "path": path_text.strip(),
                    "sha1": sha1,
                    "key_last_write_utc": (
                        ns_to_iso(leaf.last_write_ns)
                        if leaf.last_write_ns else None
                    ),
                })
    return out


# ---------------------------------------------------------------------------

def extract_hive_artifacts(path: Path) -> dict:
    """Run every applicable extractor over one hive file."""
    try:
        hive = Hive.from_path(path)
    except (HiveError, OSError, struct.error, zlib.error) as exc:
        return {"hive": str(path), "parsed": False, "error": str(exc)}
    name = path.name.lower()
    result: dict = {"hive": str(path), "parsed": True}
    try:
        if name in ("system",) or "system" in name:
            result["shimcache"] = shimcache(hive)
            result["usbstor"] = usbstor(hive)
        if name in ("ntuser.dat",) or "ntuser" in name:
            result["userassist"] = userassist(hive)
            result["recentdocs"] = recentdocs(hive)
        if "amcache" in name:
            result["amcache"] = amcache(hive)
        if name in ("software", "ntuser.dat") or "software" in name:
            result["run_keys"] = run_keys(hive)
    except (HiveError, struct.error) as exc:
        result["partial_error"] = str(exc)
    return result
