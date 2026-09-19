"""Raid-window scan (`raidwatch window`) — what was touched that day.

Sometimes there IS no seized list to verify: investigators finish,
hand over nothing, and leave. The one fact counsel usually knows is
the date/time. Given just that timestamp, this walks the filesystem
metadata-only (no hashing — fast even on multi-TB drives) and lists
every file created, modified, or merely accessed since then:

- created:  ctime/btime inside the window → files investigators made
            (their exports, notes, temp copies) or planted
- modified: mtime inside the window → files written during the raid
- accessed: atime moved but content untouched → "read but not taken"
            — the exact category that later becomes "봤지만 안 가져간"
            evidence when a file mysteriously matters at trial

It is deliberately observational: it cannot prove WHO touched a file
(the journal/artifacts steps attribute actor context), only THAT the
filesystem changed after the stated time.

Honest limits baked into the report:
- NTFS last-access updates are often disabled (NtfsDisableLastAccess
  Update=1 default on modern Windows) → 'accessed' may be empty on
  real systems; absence is not proof nobody looked.
- ctime on POSIX is inode-change-time, not creation; on Windows it is
  creation time. btime is used where the OS exposes it.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .common import ns_to_iso, utc_now_iso, write_json, write_manifest

_MAX_SCANNED = 500_000  # dir entries walked — bounded runtime
_MAX_HITS = 100_000     # recorded window hits


def _btime_ns(st: os.stat_result) -> int | None:
    """True creation time where the OS exposes it (Windows/macOS)."""
    bt = getattr(st, "st_birthtime", None)
    if bt is not None:
        return int(bt * 1_000_000_000)
    # Windows: st_ctime IS creation time
    if os.name == "nt":
        return st.st_ctime_ns
    return None


def scan_window(
    root: Path,
    out_dir: Path,
    *,
    since_ns: int,
    until_ns: int | None = None,
    max_scanned: int = _MAX_SCANNED,
    max_hits: int = _MAX_HITS,
    progress=None,
) -> dict:
    """List files touched inside [since_ns, until_ns] — metadata only."""
    root = Path(root).resolve()
    out_dir = Path(out_dir).resolve()
    if until_ns is None:
        until_ns = time.time_ns()

    hits: list[dict] = []
    scanned = 0
    errors = 0
    truncated = False
    t0 = time.monotonic()

    for dirpath, _dirs, files in os.walk(root, onerror=lambda e: None):
        for name in files:
            scanned += 1
            if scanned > max_scanned or len(hits) >= max_hits:
                truncated = True
                break
            p = Path(dirpath) / name
            try:
                st = p.lstat()
            except OSError:
                errors += 1
                continue
            if p.is_symlink():
                continue
            btime = _btime_ns(st)
            created = (
                btime is not None and since_ns <= btime <= until_ns
            )
            # POSIX ctime ≈ metadata/creation change — treat as created
            # signal only when no real btime exists.
            if not created and btime is None:
                created = since_ns <= st.st_ctime_ns <= until_ns
            modified = since_ns <= st.st_mtime_ns <= until_ns
            accessed = (
                not modified
                and since_ns <= st.st_atime_ns <= until_ns
            )
            if not (created or modified or accessed):
                continue
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                rel = str(p)
            hits.append({
                "path": rel,
                "size": st.st_size,
                "created_in_window": created,
                "modified_in_window": modified,
                "accessed_in_window": accessed,
                "btime_utc": ns_to_iso(btime) if btime else None,
                "mtime_utc": ns_to_iso(st.st_mtime_ns),
                "atime_utc": ns_to_iso(st.st_atime_ns),
            })
        if truncated:
            break
        if progress and scanned and scanned % 20_000 == 0:
            progress(scanned, len(hits))

    hits.sort(key=lambda h: (
        h["btime_utc"] or h["mtime_utc"], h["path"]))
    summary = {
        "since_utc": ns_to_iso(since_ns),
        "until_utc": ns_to_iso(until_ns),
        "entries_scanned": scanned,
        "files_in_window": len(hits),
        "created": sum(1 for h in hits if h["created_in_window"]),
        "modified": sum(1 for h in hits if h["modified_in_window"]),
        "accessed_only": sum(1 for h in hits if h["accessed_in_window"]),
        "read_errors": errors,
        "truncated": truncated,
        "elapsed_s": round(time.monotonic() - t0, 1),
    }
    report = {
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "files": hits,
        "note": (
            "Files whose filesystem timestamps fall inside the raid "
            "window — metadata-only scan, no hashing. 'created' = file "
            "appeared after the raid time (investigator exports, temp "
            "copies — or planted material). 'accessed_only' = read but "
            "not modified: the '열람만 하고 안 가져간' category. Caveats: "
            "NTFS atime updates are commonly disabled so accessed_only "
            "may undercount; timestamps prove the filesystem changed, "
            "not who changed it — pair with journal/artifacts for actor "
            "context."
        ),
    }
    write_json(out_dir / "window.json", report)
    write_manifest(out_dir, "window", {"summary": summary})
    return report
