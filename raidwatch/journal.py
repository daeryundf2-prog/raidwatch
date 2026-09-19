"""USN Journal replay — what investigators touched, with timestamps.

The NTFS USN (Update Sequence Number) journal records every metadata
mutation on a volume: creates, deletes, renames, data writes, security
changes. During a seizure it captures the investigators' own footprint —
files their tools created, report exports they deleted, volumes of
interest they browsed — even when every other artifact was cleaned.

Acquisition paths supported here (this module stays portable):

- ``--volume C:`` on Windows: invokes ``fsutil usn readjournal <vol> csv``
  (needs elevation) and parses the CSV stream.
- ``--csv dump.csv``: parses a previously exported CSV with the same
  columns (any tool's export works — headers are matched loosely).
"""

from __future__ import annotations

import csv
import io
import platform
import subprocess
from pathlib import Path

from .common import (
    filetime_to_iso,
    iso_to_ns,
    ns_to_iso,
    utc_now_iso,
    write_json,
    write_manifest,
)

USN_REASONS = {
    0x00000001: "data_overwrite",
    0x00000002: "data_extend",
    0x00000004: "data_truncation",
    0x00000010: "named_data_overwrite",
    0x00000020: "named_data_extend",
    0x00000040: "named_data_truncation",
    0x00000100: "file_create",
    0x00000200: "file_delete",
    0x00000400: "ea_change",
    0x00000800: "security_change",
    0x00001000: "rename_old",
    0x00002000: "rename_new",
    0x00004000: "indexable_change",
    0x00008000: "basic_info_change",
    0x00010000: "hard_link_change",
    0x00020000: "compression_change",
    0x00040000: "encryption_change",
    0x00080000: "object_id_change",
    0x00100000: "reparse_point_change",
    0x00200000: "stream_change",
    0x80000000: "close",
}

_HEADER_ALIASES = {
    "file_name": ("file name", "filename", "name"),
    "reason": ("reason", "usn reason"),
    "timestamp": ("time stamp", "timestamp", "time"),
    "usn": ("usn",),
    "file_id": ("file id", "fileid"),
    "parent_id": ("parent file id", "parent id"),
}


def _decode_reasons(mask: int) -> list[str]:
    return [name for bit, name in USN_REASONS.items() if mask & bit]


def _parse_hex(value: str) -> int | None:
    try:
        return int(value.strip(), 0)
    except (ValueError, TypeError):
        return None


def parse_usn_csv(text: str) -> list[dict]:
    """Parse fsutil-style USN CSV output into event dicts (lenient headers)."""
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return []
    header = [c.strip().lower() for c in rows[0]]
    col = {}
    for key, aliases in _HEADER_ALIASES.items():
        for i, h in enumerate(header):
            if h in aliases:
                col[key] = i
                break
    if "file_name" not in col or "reason" not in col:
        return []

    events = []
    for row in rows[1:]:
        if len(row) <= max(col.values()):
            continue
        name = row[col["file_name"]].strip().strip('"')
        if not name:
            continue
        reason_mask = _parse_hex(row[col["reason"]])
        ts_raw = row[col["timestamp"]] if "timestamp" in col else ""
        ts = _parse_hex(ts_raw)
        events.append(
            {
                "file_name": name,
                "reasons": _decode_reasons(reason_mask or 0),
                "reason_mask": reason_mask,
                "timestamp_utc": filetime_to_iso(ts) if ts else None,
                "usn": _parse_hex(row[col["usn"]]) if "usn" in col else None,
            }
        )
    return events


def read_journal_fsutil(volume: str) -> str:
    """Invoke fsutil on Windows; raises on any platform/privilege failure."""
    if platform.system() != "Windows":
        raise OSError("fsutil requires Windows; export the journal to CSV instead")
    out = subprocess.run(
        ["fsutil", "usn", "readjournal", volume, "csv"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if out.returncode != 0:
        raise OSError(f"fsutil failed (needs elevation?): {out.stderr.strip()}")
    return out.stdout


def replay_journal(
    out_dir: Path,
    *,
    volume: str | None = None,
    csv_path: Path | None = None,
    since_ns: int | None = None,
    name_filter: str | None = None,
) -> dict:
    """Parse a USN journal export into a filtered event report."""
    if csv_path is not None:
        text = Path(csv_path).read_text(encoding="utf-8", errors="replace")
        source = str(Path(csv_path).resolve())
    elif volume is not None:
        text = read_journal_fsutil(volume)
        source = f"fsutil:{volume}"
    else:
        raise ValueError("either csv_path or volume is required")

    events = parse_usn_csv(text)
    since_iso = ns_to_iso(since_ns) if since_ns else None
    filtered = [
        e for e in events
        if (since_iso is None or (e["timestamp_utc"] or "") >= since_iso)
        and (
            name_filter is None
            or name_filter.lower() in e["file_name"].lower()
        )
    ]
    reason_counts: dict[str, int] = {}
    for e in filtered:
        for r in e["reasons"]:
            reason_counts[r] = reason_counts.get(r, 0) + 1
    interesting = [
        e for e in filtered
        if {"file_delete", "rename_old", "security_change"} & set(e["reasons"])
    ]
    summary = {
        "events_parsed": len(events),
        "events_in_window": len(filtered),
        "deletes_renames_security_changes": len(interesting),
        "reason_counts": reason_counts,
    }
    report = {
        "source": source,
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "notable_events": interesting,
        "events": filtered,
        "note": (
            "USN records show which files changed and when — including "
            "files investigators' tools created and later deleted. A gap "
            "in USN coverage (journal wrap or disabled journal) is itself "
            "worth noting; absence of an event does not prove it never "
            "happened."
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "journal.json", report)
    write_manifest(out_dir, "journal", {"source": source, "summary": summary})
    return report
