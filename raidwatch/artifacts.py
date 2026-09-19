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
from .evtx import decompress_evtx_file, event_timeline, evtx_strings
from .hiveart import extract_hive_artifacts
from .inventory import iter_fs
from .lnk import parse_lnk_file
from .pfparse import parse_prefetch
from .sources import extract_strings
from .vss import ShadowSource

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
HIVE_NAMES = {
    "system", "software", "sam", "security", "ntuser.dat", "usrclass.dat",
    "amcache.hve",
}
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
    """Substring-match markers against the filename stem. Broad by design:
    prefetch names embed hashes (FTKIMAGER.EXE-1A2B3C.pf) and tool exes
    vary — a false label only marks a file for review, never excludes it."""
    low = Path(name).stem.lower()
    for marker, label in KNOWN_TOOL_MARKERS.items():
        if marker in low:
            return label
    return None


def _classify_artifact(rel: str) -> str | None:
    parts = rel.lower().split("/")

    def _starts(prefix: tuple) -> bool:
        return tuple(parts[: len(prefix)]) == prefix

    if _starts(ARTIFACT_DIRS["prefetch"]) or "prefetch" in parts:
        return "prefetch"
    if (_starts(ARTIFACT_DIRS["evtx"]) or "winevt" in parts) and any(
        h in parts[-1] for h in EVT_LOG_HINTS
    ):
        return "evtx"
    joined = "/".join(parts)
    if RECENT_PATH in joined or any(h in parts for h in JUMPLIST_HINT):
        return "recent_items"
    if parts[-1] in HIVE_NAMES or parts[-1] == DEVICE_LOG:
        return "registry_or_device_log"
    if _starts(ARTIFACT_DIRS["drivers"]):
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


def _copy_and_hash(
    src: Path, dest_dir: Path, tag: str, max_bytes: int, rel: str,
    shadow: ShadowSource | None = None,
) -> dict:
    try:
        size = src.stat().st_size
    except OSError:
        return {"copied_to": None, "sha256": None, "skipped": "stat_failed"}
    if size > max_bytes:
        return {"copied_to": None, "sha256": None, "skipped": "too_large"}
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Same-named artifacts exist per-user (NTUSER.DAT, *.evtx) — encode the
    # full relative path so copies never overwrite each other.
    dest = dest_dir / f"{tag}__{rel.replace('/', '__')}"
    try:
        shutil.copy2(src, dest)
        return {"copied_to": str(dest), "sha256": sha256_file(src)}
    except OSError:
        pass
    # Locked by the OS (live hives, in-use .evtx): existing VSS snapshots
    # expose the same bytes read-only — and predate the raid.
    if shadow is not None:
        for alt in shadow.fallback_paths(src):
            try:
                shutil.copy2(alt, dest)
                return {
                    "copied_to": str(dest),
                    "sha256": sha256_file(alt),
                    "via_shadow": str(alt),
                }
            except OSError:
                continue
    return {"copied_to": None, "sha256": None, "skipped": "copy_failed_or_locked"}


def _scan_ads(root: Path, out_dir: Path, *, timeout: int = 180) -> dict:
    """Alternate Data Streams — the classic NTFS hiding spot. PowerShell
    enumeration, capped by timeout; partial results are still evidence."""
    if platform.system() != "Windows":
        return {"status": "skipped", "reason": "windows_only"}
    safe_root = str(root).replace("'", "''")
    ps = (
        f"Get-ChildItem -Path '{safe_root}' -Recurse -File "
        "-ErrorAction SilentlyContinue | Get-Item -Stream * "
        "-ErrorAction SilentlyContinue | Where-Object "
        "{$_.Stream -ne ':$DATA'} | ForEach-Object "
        "{\"$($_.FileName)|$($_.Stream)|$($_.Length)\"}"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=timeout,
        )
        lines = [ln for ln in out.stdout.splitlines() if "|" in ln]
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        lines = [
            ln for ln in (exc.stdout or "").splitlines() if "|" in ln
        ] if isinstance(exc.stdout, str) else []
        timed_out = True
    except OSError:
        return {"status": "skipped", "reason": "powershell_unavailable"}
    dest = out_dir / "alternate-data-streams.txt"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "status": "partial" if timed_out else "ok",
        "streams_found": len(lines),
        "truncated": timed_out,
        "list_to": str(dest),
    }


def collect_artifacts(
    root: Path,
    out_dir: Path,
    *,
    since_ns: int | None = None,
    max_file_bytes: int = 200 * 1024 * 1024,
    use_vss: bool = False,
    ads_timeout: int = 180,
) -> dict:
    root = root.resolve()
    copies_dir = out_dir / "copies"
    strings_dir = out_dir / "strings"

    # Existing shadows are read-only evidence we did not create; --vss
    # opts into making a fresh one (admin only) for locked files.
    drive = str(root)[:2] if len(str(root)) >= 2 and str(root)[1] == ":" else "C:"
    shadow = ShadowSource(drive, allow_create=use_vss)

    artifacts: dict[str, list] = {}
    observed: dict[str, list] = {}
    summary = {"scanned": 0, "matched": 0, "copied": 0,
               "via_shadow": 0, "tools_found": 0}

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
            **_copy_and_hash(
                abs_path, copies_dir, category, max_file_bytes, rel,
                shadow=shadow,
            ),
        }
        if entry.get("via_shadow"):
            summary["via_shadow"] += 1
        if entry["copied_to"]:
            summary["copied"] += 1

        if category == "prefetch":
            m = PF_NAME_RE.match(abs_path.name)
            exe_guess = m.group("exe") if m else abs_path.stem
            entry["exe_guess"] = exe_guess
            try:
                pf = parse_prefetch(abs_path.read_bytes())
            except OSError:
                pf = {"status": "read_error"}
            entry["prefetch"] = {
                "exe_name": pf.get("exe_name"),
                "version_label": pf.get("version_label"),
                "run_count": pf.get("run_count"),
                "last_runs_utc": pf.get("last_runs_utc"),
                "parse_status": pf.get("status"),
            }
            label = (
                _tool_label(exe_guess)
                or _tool_label(pf.get("exe_name") or "")
                or _tool_label(abs_path.name)
            )
            if label:
                observed.setdefault(label, []).append(
                    {
                        "evidence": "prefetch",
                        "path": rel,
                        "run_count": pf.get("run_count"),
                        "last_runs_utc": pf.get("last_runs_utc"),
                    }
                )
        elif category == "evtx":
            binxml_dir = out_dir / "binxml"
            dec = decompress_evtx_file(
                abs_path, binxml_dir / (rel.replace("/", "__") + ".binxml")
            )
            entry["binxml"] = dec
            timeline = event_timeline(abs_path)
            entry["event_timeline"] = {
                k: v for k, v in timeline.items() if k != "events"
            }
            if timeline["events"]:
                dest = out_dir / "timelines" / (
                    rel.replace("/", "__") + ".timeline.json"
                )
                dest.parent.mkdir(parents=True, exist_ok=True)
                write_json(dest, timeline)
                entry["timeline_to"] = str(dest)
            strings = evtx_strings(abs_path)
            if strings:
                dest = strings_dir / (rel.replace("/", "__") + ".strings.txt")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text("\n".join(strings) + "\n", encoding="utf-8")
                entry["strings_to"] = str(dest)
        elif category == "recent_items" and abs_path.suffix.lower() == ".lnk":
            lnk = parse_lnk_file(abs_path)
            entry["lnk"] = lnk
            if lnk.get("target_path"):
                label = _tool_label(Path(lnk["target_path"]).name)
                if label:
                    observed.setdefault(label, []).append(
                        {
                            "evidence": "recent_link",
                            "path": rel,
                            "target": lnk["target_path"],
                            "accessed_utc": lnk.get("accessed_utc"),
                        }
                    )
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
            if category == "registry_or_device_log" and entry["copied_to"]:
                # Structured hive parse first — ShimCache executions,
                # USBSTOR devices, UserAssist launches, Run keys.
                if abs_path.name.lower() in HIVE_NAMES:
                    hive_art = extract_hive_artifacts(abs_path)
                    entry["hive_artifacts"] = hive_art
                    if hive_art.get("parsed"):
                        for section in ("shimcache", "userassist", "amcache"):
                            for item in hive_art.get(section, []):
                                p = item.get("path") or item.get("name_rot13_decoded") or ""
                                label = _tool_label(Path(p).name)
                                if label:
                                    observed.setdefault(label, []).append(
                                        {
                                            "evidence": f"hive_{section}",
                                            "path": rel,
                                            "observed": p,
                                            "detail": {
                                                k: v for k, v in item.items()
                                                if k not in ("path", "name_rot13_decoded")
                                            },
                                        }
                                    )
                        for dev in hive_art.get("usbstor", []):
                            observed.setdefault("USB device (collection media?)", []).append(
                                {"evidence": "usbstor", "path": rel, "detail": dev}
                            )
                strings = extract_strings(abs_path)
                # USB device serials and service names left by collection media
                hits = [
                    s for s in strings
                    if re.search(
                        r"USBSTOR|VID_[0-9A-Fa-f]{4}|Disk&Ven_|serial|"
                        r"FTK|EnCase|AXIOM|OUTRIDER|KAPE|MD-LIVE",
                        s,
                    )
                ]
                if hits:
                    entry["notable_strings"] = hits[:50]
                    dest = strings_dir / (rel.replace("/", "__") + ".strings.txt")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(
                        "\n".join(strings) + "\n", encoding="utf-8"
                    )
                    entry["strings_to"] = str(dest)

        artifacts.setdefault(category, []).append(entry)
        summary["scanned"] += 1

    # Drivers are also evidence of tool execution (e.g. winpmem kernel driver)
    for drv in artifacts.get("drivers", []):
        label = _tool_label(drv["path"].rsplit("/", 1)[-1])
        if label:
            observed.setdefault(label, []).append(
                {"evidence": "driver_file", "path": drv["path"], "mtime_utc": drv["mtime_utc"]}
            )

    summary["tools_found"] = len(observed)
    vss = detect_shadow_copies()
    vss["shadow_devices_used"] = shadow.devices
    vss["shadow_created_by_us"] = shadow.created is not None
    ads = _scan_ads(root, out_dir, timeout=ads_timeout)
    shadow.cleanup()
    report = {
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "observed_investigator_tools": observed,
        "alternate_data_streams": ads,
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
