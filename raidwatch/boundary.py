"""Scope boundary (`raidwatch boundary`) — territory violations.

The warrant says "the suspect's PC (local media)". Investigators then
wander into whatever is *connected*: the company NAS mapped as Z:\\,
the OneDrive/Google Drive sync folder, the boss's external USB, a UNC
share. Under 형사소송법 §215③ remote-media seizure needs its own
warrant basis — files taken from outside the warrant's territory are
a distinct, strong suppression ground.

Classifies every claimed path:
- remote UNC (\\\\server\\share)
- mapped network drive (GetDriveType == DRIVE_REMOTE on Windows)
- removable media (DRIVE_REMOVABLE — the investigator's own USB
  shouldn't be a source of seized items at all)
- cloud sync mounts (OneDrive, Google Drive, Dropbox, iCloud,
  Naver MYBOX etc.)
- local fixed media (in territory)

Input: a seized list or verify.json. Output: boundary.json + flag list
for petition.
"""

from __future__ import annotations

import json
import platform
import re
from pathlib import Path

from .common import utc_now_iso, write_json, write_manifest

_CLOUD_MARKERS = (
    "onedrive", "google drive", "내 드라이브", "googledrivefs",
    "dropbox", "icloud", "iclouddrive", "box",
    "mybox", "네이버", "naverworks", "nextcloud", "mega",
)


def _cloud_hit(low: str) -> str | None:
    """Marker must own a whole path segment (or a segment prefix with a
    space/hyphen boundary, e.g. 'OneDrive - 회사') — a bare substring
    match fires on 'XboxGamingOverlay' via 'box', which is noise."""
    for seg in re.split(r"[\\/]+", low):
        for marker in _CLOUD_MARKERS:
            if (
                seg == marker
                or seg.startswith(marker + " ")
                or seg.startswith(marker + "-")
                or seg.startswith(marker + "_")
            ):
                return marker
    return None

_DRIVE_TYPES = {2: "removable", 3: "fixed", 4: "remote"}


def _drive_type(drive: str) -> str | None:
    """GetDriveTypeW for 'Z:' → 'removable'/'fixed'/'remote' (Windows)."""
    if platform.system() != "Windows":
        return None
    try:
        import ctypes

        code = ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\")
        return _DRIVE_TYPES.get(code)
    except (AttributeError, OSError):
        return None


def classify_path(path: str) -> dict:
    """One claimed path → territory classification."""
    p = (path or "").strip().strip('"')
    low = p.lower().replace("/", "\\")
    if not p:
        return {"territory": "unknown", "violation": False,
                "reason": "empty path"}
    if p.startswith("\\\\") or p.startswith("//"):
        return {"territory": "remote_unc", "violation": True,
                "reason": "UNC network share — outside local media"}
    marker = _cloud_hit(low)
    if marker:
        return {"territory": "cloud_sync", "violation": True,
                "reason": f"cloud-sync location ({marker})"}
    m = re.match(r"([A-Za-z]):", p)
    if m:
        dtype = _drive_type(m.group(1) + ":")
        if dtype == "remote":
            return {"territory": "remote_mapped", "violation": True,
                    "reason": f"mapped network drive {m.group(1)}:"}
        if dtype == "removable":
            return {"territory": "removable", "violation": True,
                    "reason": f"removable media {m.group(1)}:"}
        if dtype == "fixed":
            return {"territory": "local_fixed", "violation": False,
                    "reason": "local fixed volume — in territory"}
        return {"territory": "local_unverified", "violation": False,
                "reason": f"drive {m.group(1)}: type unknown (non-Windows "
                          "or offline); treated as local, verify manually"}
    return {"territory": "unknown", "violation": False,
            "reason": "no drive/UNC prefix"}


def run_boundary(
    seized_path: Path | None,
    verify_path: Path | None,
    out_dir: Path,
) -> dict:
    """Classify every claimed path by territory; flag violations."""
    from .verify import parse_seized_list

    out_dir = Path(out_dir).resolve()
    if verify_path is not None:
        data = json.loads(Path(verify_path).read_text(encoding="utf-8"))
        paths = [
            it.get("claimed_path") for it in data.get("items", [])
        ]
        source = f"verify:{Path(verify_path).resolve()}"
    elif seized_path is not None:
        paths = [
            it.get("claimed_path") for it in parse_seized_list(seized_path)
        ]
        source = f"seized:{Path(seized_path).resolve()}"
    else:
        raise ValueError("seized_path or verify_path required")

    entries = []
    counts: dict[str, int] = {}
    for p in paths:
        c = classify_path(p or "")
        if c["violation"]:
            c["flag"] = "warrant_territory_violation"
        entries.append({"claimed_path": p, **c})
        counts[c["territory"]] = counts.get(c["territory"], 0) + 1
    violations = [e for e in entries if e["violation"]]
    summary = {
        "total_paths": len(entries),
        "territory_counts": counts,
        "violations": len(violations),
    }
    report = {
        "source": source,
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "violating_paths": violations,
        "entries": entries,
        "note": (
            "Items flagged warrant_territory_violation were taken from "
            "outside the warrant's local-media scope (network shares, "
            "removable drives, cloud-sync folders). 형사소송법 제215조 "
            "제3항 — remote-media seizure needs its own basis; these are "
            "independent suppression grounds. Drive types marked "
            "'unverified' need manual confirmation on the actual machine."
        ),
    }
    write_json(out_dir / "boundary.json", report)
    write_manifest(out_dir, "boundary", {"summary": summary})
    return report
