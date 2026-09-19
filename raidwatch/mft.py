"""$MFT dump parsing — deleted-entry listing and resident-data carving.

This is the "carve the temp file" capability the reverse-thinking plan
called for: forensic tools' report artifacts are small files, and small
files store their entire content *inside* their MFT record (resident
$DATA). A deleted record's resident payload is therefore recoverable
in full from an $MFT dump alone — no unallocated-space imaging needed.

Input is an $MFT byte dump acquired by other means (live capture by an
imaging tool, or a copy extracted from a shadow copy). This module does
not open raw devices itself.

Anti-timestomp signal: timestomping tools rewrite $STANDARD_INFORMATION
timestamps but usually leave $FILE_NAME timestamps untouched. We report
both and flag records where the two disagree.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .common import (
    filetime_to_iso,
    sha256_bytes,
    utc_now_iso,
    write_json,
    write_manifest,
)

RECORD_SIZE = 1024
ATTR_END = 0xFFFFFFFF
ATTR_SI = 0x10
ATTR_FILENAME = 0x30
ATTR_DATA = 0x80

_SAFE_NAME_CHARS = set("._-")


class MftError(ValueError):
    pass


def _apply_fixup(record: bytearray, record_size: int) -> bool:
    """Apply the update-sequence fixup; False when the signature mismatches.

    The sector stride is derived from record_size // (usa_count - 1) so
    4KB-native volumes (usa_count=2, tail at record_size-2) parse too.
    """
    if len(record) < 8:
        return False
    usa_off, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < 2 or usa_off + usa_count * 2 > len(record):
        return False
    stride = record_size // (usa_count - 1)
    if stride <= 0 or stride > record_size:
        return False
    signature = bytes(record[usa_off : usa_off + 2])
    for i in range(1, usa_count):
        tail = i * stride - 2
        if tail + 2 > len(record):
            break
        if bytes(record[tail : tail + 2]) != signature:
            return False
        record[tail : tail + 2] = record[usa_off + i * 2 : usa_off + i * 2 + 2]
    return True


def _iter_attrs(record: bytes, first_off: int, limit: int):
    """Yield (attr_type, off, attr_len), bounded by the record's used size."""
    off = first_off
    end = min(limit, len(record))
    while off + 16 <= end:
        attr_type, attr_len = struct.unpack_from("<II", record, off)
        if attr_type == ATTR_END or attr_len < 16:
            return
        if off + attr_len > end:
            return  # truncated attribute — stop, don't parse garbage
        yield attr_type, off, attr_len
        off += attr_len


def _attr_content(record: bytes, off: int, attr_len: int) -> bytes | None:
    """Resident-attribute payload, bounded strictly to the attribute."""
    if record[off + 8] != 0:
        return None  # non-resident
    if attr_len < 24 or off + 22 > len(record):
        return None
    content_len, content_off = struct.unpack_from("<IH", record, off + 16)
    if content_off < 24 or content_off + content_len > attr_len:
        return None  # content region escapes its own attribute
    start = off + content_off
    return record[start : start + content_len]


def parse_mft(data: bytes, record_size: int = RECORD_SIZE) -> list[dict]:
    """Parse an $MFT dump into per-record summaries.

    Each entry: {index, in_use, deleted, is_dir, name, parent_ref,
    size, si_*_utc, fn_*_utc, si_fn_mismatch, resident_data_len}.
    """
    entries: list[dict] = []
    for index in range(len(data) // record_size):
        raw = bytearray(
            data[index * record_size : (index + 1) * record_size]
        )
        if bytes(raw[:4]) != b"FILE":
            continue
        if not _apply_fixup(raw, record_size):
            entries.append({"index": index, "parse_error": "fixup_mismatch"})
            continue
        flags = struct.unpack_from("<H", raw, 0x16)[0]
        first_off = struct.unpack_from("<H", raw, 0x14)[0]
        used_size = struct.unpack_from("<I", raw, 0x18)[0]

        entry: dict = {
            "index": index,
            "in_use": bool(flags & 0x01),
            "is_dir": bool(flags & 0x02),
            "name": None,
            "parent_ref": None,
            "size": None,
            "resident_data_len": 0,
            "_resident_data": None,
        }
        si_times = fn_times = None
        limit = used_size if first_off < used_size <= record_size else record_size
        for attr_type, off, attr_len in _iter_attrs(raw, first_off, limit):
            content = _attr_content(raw, off, attr_len)
            if content is None:
                continue
            if attr_type == ATTR_SI and len(content) >= 48:
                si_times = struct.unpack_from("<4Q", content, 0)
            elif attr_type == ATTR_FILENAME and len(content) >= 66:
                parent, = struct.unpack_from("<Q", content, 0)
                fn_times = struct.unpack_from("<4Q", content, 8)
                real_size, = struct.unpack_from("<Q", content, 48)
                name_len = content[64]
                name = content[66 : 66 + name_len * 2].decode(
                    "utf-16-le", errors="replace"
                )
                # Prefer the Win32/Win32+DOS name over a DOS 8.3 alias.
                if entry["name"] is None or content[65] in (1, 3):
                    entry["name"] = name
                    entry["parent_ref"] = parent & 0x0000FFFFFFFFFFFF
                    entry["size"] = real_size
            elif attr_type == ATTR_DATA and not entry["_resident_data"]:
                entry["resident_data_len"] = len(content)
                entry["_resident_data"] = bytes(content)

        if si_times:
            entry["si_created_utc"] = filetime_to_iso(si_times[0])
            entry["si_modified_utc"] = filetime_to_iso(si_times[1])
            entry["si_mft_changed_utc"] = filetime_to_iso(si_times[2])
            entry["si_accessed_utc"] = filetime_to_iso(si_times[3])
        if fn_times:
            entry["fn_created_utc"] = filetime_to_iso(fn_times[0])
            entry["fn_modified_utc"] = filetime_to_iso(fn_times[1])
            entry["fn_accessed_utc"] = filetime_to_iso(fn_times[3])
        entry["deleted"] = not entry["in_use"]
        # Timestomp indicator: $SI rewritten but $FN kept the real times.
        entry["si_fn_mismatch"] = bool(
            si_times
            and fn_times
            and abs(si_times[1] - fn_times[1]) > 10_000_000  # >1s
        )
        entries.append(entry)
    return entries


def carve_mft(
    mft_path: Path,
    out_dir: Path,
    *,
    record_size: int = RECORD_SIZE,
    recover_resident: bool = True,
    max_recover_bytes: int = 4096,
) -> dict:
    """Parse an $MFT dump; recover resident payloads of deleted files."""
    data = Path(mft_path).read_bytes()
    entries = parse_mft(data, record_size=record_size)

    recovered_dir = out_dir / "recovered"
    recovered = []
    deleted = []
    for entry in entries:
        if entry.get("parse_error"):
            continue
        if entry["deleted"]:
            deleted.append(
                {k: v for k, v in entry.items() if not k.startswith("_")}
            )
        payload = entry.pop("_resident_data", None)
        if (
            recover_resident
            and entry["deleted"]
            and payload
            and 0 < len(payload) <= max_recover_bytes
        ):
            safe = "".join(
                c if c.isalnum() or c in _SAFE_NAME_CHARS else "_"
                for c in (entry["name"] or f"mft_{entry['index']}")
            )
            dest = recovered_dir / f"{entry['index']:06d}_{safe}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload)
            recovered.append(
                {
                    "mft_index": entry["index"],
                    "name": entry["name"],
                    "size": len(payload),
                    "recovered_to": str(dest),
                    "sha256": sha256_bytes(payload),
                }
            )
        else:
            entry.pop("_resident_data", None)

    timestomp_flags = [
        {k: v for k, v in e.items() if not k.startswith("_")}
        for e in entries
        if e.get("si_fn_mismatch")
    ]
    summary = {
        "records_parsed": len(entries),
        "deleted_entries": len(deleted),
        "resident_recovered": len(recovered),
        "si_fn_mismatch_flags": len(timestomp_flags),
    }
    report = {
        "mft_source": str(Path(mft_path).resolve()),
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "deleted_entries": deleted,
        "resident_recovered": recovered,
        "timestomp_flags": timestomp_flags,
        "note": (
            "Resident recovery covers small files only (payload stored "
            "inside the MFT record). Non-resident data lives in "
            "unallocated clusters and is not carved by this module. "
            "si_fn_mismatch flags indicate $SI/$FN timestamp disagreement "
            "— a classic timestomp signature, not proof by itself."
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "carve.json", report)
    write_manifest(out_dir, "carve", {"summary": summary})
    return report
