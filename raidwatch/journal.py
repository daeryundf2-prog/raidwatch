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
import re
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
    "reason": ("reason", "usn reason", "updatereasons", "update reasons"),
    "timestamp": (
        "time stamp", "timestamp", "time",
        "updatetimestamp", "update timestamp",
    ),
    "usn": ("usn",),
    "file_id": ("file id", "fileid"),
    "parent_id": ("parent file id", "parent id"),
}

# fsutil emits reason *text* (e.g. "File delete | Close") as well as masks
_REASON_TEXT = {
    "data overwrite": 0x1,
    "data extend": 0x2,
    "data truncation": 0x4,
    "named data overwrite": 0x10,
    "named data extend": 0x20,
    "named data truncation": 0x40,
    "file create": 0x100,
    "file delete": 0x200,
    "ea change": 0x400,
    "security change": 0x800,
    "rename old": 0x1000,
    "rename new": 0x2000,
    "indexable change": 0x4000,
    "basic info change": 0x8000,
    "hard link change": 0x10000,
    "compression change": 0x20000,
    "encryption change": 0x40000,
    "object id change": 0x80000,
    "reparse point change": 0x100000,
    "stream change": 0x200000,
    "close": 0x80000000,
}

_DATE_RE = re.compile(r"(\d{1,4})[/-](\d{1,2})[/-](\d{1,4})\s+(\d{1,2}):(\d{2}):(\d{2})")


def _decode_reasons(mask: int) -> list[str]:
    return [name for bit, name in USN_REASONS.items() if mask & bit]


def _parse_reason(value: str) -> tuple[int, list[str]]:
    """Reason cell → (mask, names). Accepts hex masks and 'a | b' text."""
    value = value.strip().strip('"')
    mask = _parse_hex(value)
    if mask is not None:
        return mask, _decode_reasons(mask)
    mask = 0
    for part in value.split("|"):
        mask |= _REASON_TEXT.get(part.strip().lower(), 0)
    return mask, _decode_reasons(mask)


def _parse_hex(value: str) -> int | None:
    try:
        return int(value.strip(), 0)
    except (ValueError, TypeError):
        return None


def _parse_timestamp(value: str) -> str | None:
    """FILETIME hex/int, or fsutil's local 'M/D/YYYY H:MM:SS' → ISO."""
    value = value.strip().strip('"')
    ft = _parse_hex(value)
    if ft is not None and ft > 10**15:  # FILETIME-scale integer
        return filetime_to_iso(ft)
    m = _DATE_RE.search(value)
    if m:
        a, b, c, hh, mm, ss = (int(x) for x in m.groups())
        year = a if a > 31 else c
        month, day = (b, a) if a > 31 else (a, b)
        if month > 12:
            month, day = day, month
        try:
            return f"{year:04d}-{month:02d}-{day:02d}T{hh:02d}:{mm:02d}:{ss:02d}+00:00"
        except ValueError:
            return None
    return None


def _guess_columns(row: list[str]) -> dict:
    """Headerless fsutil rows: identify cells by content shape.

    fsutil csv emits a fixed order — file name, file ID, parent ID, USN,
    time stamp, reason — but without a header we can only trust shapes:
    the name is the first non-numeric cell, the timestamp is date-like or
    FILETIME-scale, and the reason is textual ("a | b") or a trailing
    mask. Bare numeric cells before the timestamp are IDs/USN, where the
    last one before the timestamp is the USN.
    """
    col: dict[str, int] = {}
    n = len(row)
    for i, cell in enumerate(row):
        v = cell.strip().strip('"')
        if not v:
            continue
        is_hex = _parse_hex(v) is not None
        is_date = bool(_DATE_RE.search(v))
        if "file_name" not in col and not is_hex and not is_date:
            col["file_name"] = i
        elif is_date or (is_hex and (_parse_hex(v) or 0) > 10**15):
            col.setdefault("timestamp", i)
        elif "|" in v or any(w in v.lower() for w in _REASON_TEXT):
            col.setdefault("reason", i)
    if "reason" not in col and n > 0:
        last = row[n - 1].strip().strip('"')
        if _parse_hex(last) is not None and n - 1 != col.get("file_name"):
            col["reason"] = n - 1
    first = (col.get("file_name") or -1) + 1
    stop = col.get("timestamp", n)
    numeric = [
        i for i in range(first, stop)
        if i != col.get("reason", -1)
        and _parse_hex(row[i].strip().strip('"')) is not None
    ]
    if numeric:
        col["usn"] = numeric[-1]
    return col


def parse_usn_csv(text: str) -> list[dict]:
    """Parse USN CSV exports into event dicts.

    Handles headered CSVs (loose header matching incl. MFTECmd's
    Name/UpdateTimestamp/UpdateReasons) and fsutil's *headerless* csv
    output, where cells are identified by content shape.
    """
    reader = csv.reader(io.StringIO(text))
    rows = [r for r in reader if any(c.strip() for c in r)]
    if not rows:
        return []
    header = [c.strip().lower() for c in rows[0]]
    col = {}
    for key, aliases in _HEADER_ALIASES.items():
        for i, h in enumerate(header):
            if h in aliases:
                col[key] = i
                break
    start = 1 if ("file_name" in col and ("reason" in col or "timestamp" in col)) else 0
    if start == 0:
        col = {}  # first row is data, not a header

    events = []
    for row in rows[start:]:
        if start == 0:
            col = _guess_columns(row)
        if "file_name" not in col or len(row) <= col["file_name"]:
            continue
        name = row[col["file_name"]].strip().strip('"')
        if not name:
            continue
        mask, names = _parse_reason(row[col["reason"]]) if "reason" in col and len(row) > col["reason"] else (0, [])
        events.append(
            {
                "file_name": name,
                "reasons": names,
                "reason_mask": mask,
                "timestamp_utc": (
                    _parse_timestamp(row[col["timestamp"]])
                    if "timestamp" in col and len(row) > col["timestamp"]
                    else None
                ),
                "usn": (
                    _parse_hex(row[col["usn"]])
                    if "usn" in col and len(row) > col["usn"]
                    else None
                ),
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
