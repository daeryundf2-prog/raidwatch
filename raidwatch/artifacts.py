"""Post-raid investigator-activity reconstruction.

Harvests the traces investigators' own tools leave on the seized PC:
prefetch entries and drivers (which tools ran), Recent/jump-list links
(what they browsed), event logs (prints, log-clears, device connects),
registry hives and setupapi (which collection media they plugged in),
and VSS shadow copies (a free pre-raid baseline, if present).

All operations are read-only observation on the owner's own machine.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from pathlib import Path

from .common import ns_to_iso, sha256_file, utc_now_iso, write_json, write_manifest
from .inventory import iter_fs
from .sources import extract_strings

# Known investigator-tool executable markers (lowercase substring → label)
KNOWN_TOOL_MARKERS = {
    "ftkimager": "FTK Imager",
    "imager_lite": "FTK Imager Lite",
    "encase": "EnCase",
    "enstart": "EnCase Portable",
    "axiom": "Magnet AXIOM",
    "outrider": "Magnet OUTRIDER",
    "kape": "KAPE",
    "mdlive": "MD-LIVE",
    "md-live": "MD-LIVE",
    "mdnext": "MD-NEXT",
    "md-next": "MD-NEXT",
    "dfas": "DFAS Pro",
    "crane": "Forensic Crane (포크레인)",
    "xways": "X-Ways",
    "xwforens": "X-Ways Forensics",
    "dumpit": "DumpIt",
    "winpmem": "WinPmem",
    "ramcapt": "Belkasoft RAM Capturer",
    "cellebrite": "Cellebrite",
    "ufed": "Cellebrite UFED",
    "graykey": "GrayKey",
    "tableau": "Tableau",
    "guymager": "Guymager",
    "dc3dd": "dc3dd",
    "dcfldd": "dcfldd",
    "osforensics": "OSForensics",
    "belkasoft": "Belkasoft",
    "passware": "Passware",
    "nuix": "Nuix",
}

PF_NAME_RE = re.compile(r"^(?P<exe>.+)-[0-9A-Fa-f]{8,16}\.pf$", re.IGNORECASE)

ARTIFACT_DIRS = {
    "prefetch": ("windows", "prefetch"),
    "evtx": ("windows", "system32", "winevt", "logs"),
    "drivers": ("windows", "system32", "drivers"),
}
RECENT_PATH = "microsoft/windows/recent"
JUMPLIST_HINT = ("automaticdestinations", "customdestinations")
HIVE_NAMES = {"system", "software", "sam", "security", "ntuser.dat", "usrclass.dat"}
DEVICE_LOG = "setupapi.dev.log"
EVT_LOG_HINTS = (
    "system.evtx",
    "security.evtx",
    "printservice",
    "operational.evtx",
    "kernel-pnp",
    "partition",
)


def _tool_label(name: str) -> str | None:
    low = name.lower()
    for marker, label in KNOWN_TOOL_MARKERS.items():
        if marker in low:
            return label
    return None


def _classify_artifact(rel: str) -> str | None:
    parts = rel.lower().split("/")
    if len(parts) >= 3 and tuple(parts[:3]) == ARTIFACT_DIRS["prefetch"]:
        return "prefetch"
    if "prefetch" in parts:
        return "prefetch"
    if len(parts) >= 5 and tuple(parts[:5]) == ARTIFACT_DIRS["evtx"]:
        return "evtx"
    if "winevt" in parts:
        return "evtx"
    joined = "/".join(parts)
    if RECENT_PATH in joined or any(h in parts for h in JUMPLIST_HINT):
        return "recent_items"
    if parts[-1] in HIVE_NAMES or parts[-1] == DEVICE_LOG:
        return "registry_or_device_log"
    if len(parts) >= 4 and tuple(parts[:4]) == ARTIFACT_DIRS["drivers"]:
        return "drivers"
    return None


def detect_shadow_copies() -> dict:
    """Best-effort VSS detection — a pre-existing baseline we did not create."""
    if platform.system() != "Windows":
        return {
            "platform": platform.system(),
            "available": False,
            "note": "VSS detection requires Windows (vssadmin); skipped.",
        }
    try:
        out = subprocess.run(
            ["vssadmin", "list", "shadows"],
            capture_output=True, text=True, timeout=30,
        )
        text = out.stdout + out.stderr
        count = text.count("Shadow Copy Volume")
        return {"platform": "Windows", "available": True,
                "shadow_count": count, "raw": text[:4000]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"platform": "Windows", "available": False,
                "note": f"vssadmin failed: {exc}"}


def _copy_and_hash(src: Path, dest_dir: Path, tag: str, max_bytes: int) -> dict:
    try:
        size = src.stat().st_size
    except OSError:
        return {"copied_to": None, "sha256": None, "skipped": "stat_failed"}
    if size > max_bytes:
        return {"copied_to": None, "sha256": None, "skipped": "too_large"}
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{tag}__{src.name}"
    try:
        shutil.copy2(src, dest)
        return {"copied_to": str(dest), "sha256": sha256_file(src)}
    except OSError:
        return {"copied_to": None, "sha256": None, "skipped": "copy_failed"}


def collect_artifacts(
    root: Path,
    out_dir: Path,
    *,
    since_ns: int | None = None,
    max_file_bytes: int = 200 * 1024 * 1024,
) -> dict:
    root = root.resolve()
    copies_dir = out_dir / "copies"
    strings_dir = out_dir / "strings"

    artifacts: dict[str, list] = {}
    observed: dict[str, list] = {}
    summary = {"scanned": 0, "matched": 0, "copied": 0, "tools_found": 0}

    for rel, abs_path, st, kind in iter_fs(root):
        if kind != "file" or st is None:
            continue
        category = _classify_artifact(rel)
        if category is None:
            continue
        if since_ns is not None and category in ("prefetch", "recent_items", "drivers"):
            if st.st_mtime_ns < since_ns:
                continue
        summary["matched"] += 1
        entry = {
            "path": rel,
            "category": category,
            "size": st.st_size,
            "mtime_utc": ns_to_iso(st.st_mtime_ns),
            **_copy_and_hash(abs_path, copies_dir, category, max_file_bytes),
        }
        if entry["copied_to"]:
            summary["copied"] += 1

        if category == "prefetch":
            m = PF_NAME_RE.match(abs_path.name)
            exe_guess = m.group("exe") if m else abs_path.stem
            entry["exe_guess"] = exe_guess
            label = _tool_label(exe_guess) or _tool_label(abs_path.name)
            if label:
                observed.setdefault(label, []).append(
                    {"evidence": "prefetch", "path": rel, "mtime_utc": entry["mtime_utc"]}
                )
        elif category == "recent_items" and abs_path.suffix.lower() == ".lnk":
            strings = extract_strings(abs_path)
            targets = [s for s in strings if re.search(r"[A-Za-z]:[\\/]|^/|\.(lnk|exe|txt|pdf|docx?|hwp)\b", s, re.IGNORECASE)]
            entry["link_targets_guess"] = targets[:20]
            if strings:
                dest = strings_dir / (rel.replace("/", "__") + ".strings.txt")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text("\n".join(strings) + "\n", encoding="utf-8")
        elif category in ("registry_or_device_log", "drivers"):
            label = _tool_label(abs_path.name)
            if label:
                observed.setdefault(label, []).append(
                    {"evidence": category, "path": rel, "mtime_utc": entry["mtime_utc"]}
                )

        artifacts.setdefault(category, []).append(entry)
        summary["scanned"] += 1

    # Drivers are also evidence of tool execution (e.g. winpmem kernel driver)
    for drv in artifacts.get("drivers", []):
        label = _tool_label(drv["path"])
        if label:
            observed.setdefault(label, []).append(
                {"evidence": "driver_file", "path": drv["path"], "mtime_utc": drv["mtime_utc"]}
            )

    summary["tools_found"] = len(observed)
    vss = detect_shadow_copies()
    report = {
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "observed_investigator_tools": observed,
        "shadow_copies": vss,
        "artifacts": artifacts,
        "note": (
            "Prefetch/Recent/driver evidence shows which tools ran and when; "
            "evtx copies (System/Security/PrintService/Kernel-PnP) support "
            "print-event, log-clear (1102), and device-connect reconstruction. "
            "VSS shadow copies, if present, may serve as a pre-raid baseline."
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "artifacts.json", report)
    write_manifest(out_dir, "artifacts",
                   {"root": str(root), "summary": summary})
    return report
