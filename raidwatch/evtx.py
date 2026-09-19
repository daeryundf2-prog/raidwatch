"""EVTX chunk decompression — recover the binxml stream for scanning.

.evtx files store event records in 64KB chunks ("ElfChnk") whose payloads
are deflate-compressed. Decompressed chunks contain the binary-XML
records in which event *data strings* (file paths, usernames, command
lines, print-job names) remain plain UTF-16LE — so plain string
extraction over the decompressed stream recovers investigator-visible
details without a full binxml parser.

This is evidence locating, not full event reconstruction: event IDs and
template structure stay binary. Pair with a real binxml tool (evtx_dump,
chainsaw) for event-ID-level analysis.
"""

from __future__ import annotations

import zlib
from pathlib import Path

CHUNK_SIG = b"ElfChnk\x00"
FILE_SIG = b"ElfFile\x00"
CHUNK_SIZE = 0x10000
CHUNK_HEADER = 0x200


def decompress_chunks(data: bytes) -> bytes:
    """Decompress all EVTX chunks into a concatenated binxml stream.

    Chunk payloads are *raw* DEFLATE (RFC 1951) — no zlib wrapper —
    so wbits must be -15. The compressed region inside a chunk ends at
    the chunk's next_record_offset field (chunk+48).
    """
    if not data.startswith(FILE_SIG):
        return b""
    out = bytearray()
    for off in range(0x1000, len(data) - CHUNK_HEADER, CHUNK_SIZE):
        if data[off : off + 8] != CHUNK_SIG:
            continue
        end = min(off + CHUNK_SIZE, len(data))
        # next_record_offset (absolute file offset) bounds the deflate area
        next_rec = int.from_bytes(data[off + 48 : off + 52], "little")
        if off + CHUNK_HEADER < next_rec <= end:
            payload = data[off + CHUNK_HEADER : next_rec]
        else:
            payload = data[off + CHUNK_HEADER : end]
        try:
            out += zlib.decompress(payload, -15)
        except zlib.error:
            # Partially-filled last chunk: keep the raw-deflate attempt but
            # trim trailing padding progressively.
            for trim in (0x8000, 0x4000, 0x1000, 0x400, 0x100):
                try:
                    out += zlib.decompress(payload[: len(payload) - trim], -15)
                    break
                except zlib.error:
                    continue
    return bytes(out)


def iter_records(blob: bytes):
    """Yield (record_id, timestamp_ns, payload) for each ELF record in a
    decompressed binxml stream. Record header: u32 sig 0x00002a2a,
    u32 size, u64 record_id, u64 FILETIME — enough for a real event
    timeline without parsing the binary XML body."""
    pos = 0
    sig = b"**\x00\x00"
    while True:
        i = blob.find(sig, pos)
        if i < 0 or i + 24 > len(blob):
            return
        size = int.from_bytes(blob[i + 4: i + 8], "little")
        if size < 24 or i + size > len(blob):
            pos = i + 4
            continue
        # tail signature must repeat the size for a valid record
        if blob[i + size - 4: i + size] != blob[i + 4: i + 8]:
            pos = i + 4
            continue
        rec_id = int.from_bytes(blob[i + 8: i + 16], "little")
        ft = int.from_bytes(blob[i + 16: i + 24], "little")
        ts_ns = (ft - 116444736000000000) * 100 if ft else None
        yield rec_id, ts_ns, blob[i + 24: i + size - 4]
        pos = i + size


def event_timeline(path: Path, *, per_record_strings: int = 6) -> dict:
    """Parse an .evtx into a real event timeline: record id + UTC time
    per event, plus a few UTF-16 strings per record for context."""
    from .common import ns_to_iso
    from .sources import extract_strings_bytes

    try:
        data = Path(path).read_bytes()
    except OSError:
        return {"status": "read_error", "events": []}
    blob = decompress_chunks(data) or data
    events = []
    for rec_id, ts_ns, payload in iter_records(blob):
        ev = {"record_id": rec_id, "timestamp_utc": ns_to_iso(ts_ns) if ts_ns else None}
        if per_record_strings:
            ev["strings"] = extract_strings_bytes(payload, limit=per_record_strings)
        events.append(ev)
    return {
        "status": "ok" if events else "no_records",
        "event_count": len(events),
        "first_event_utc": events[0]["timestamp_utc"] if events else None,
        "last_event_utc": events[-1]["timestamp_utc"] if events else None,
        "events": events,
    }


def evtx_strings(path: Path, limit: int = 4000) -> list[str]:
    """Decompress an .evtx file and pull ASCII + UTF-16LE strings."""
    from .sources import extract_strings_bytes

    try:
        data = Path(path).read_bytes()
    except OSError:
        return []
    blob = decompress_chunks(data)
    return extract_strings_bytes(blob or data, limit=limit)


def decompress_evtx_file(path: Path, dest: Path) -> dict:
    """Decompress an .evtx to a .binxml stream file; returns a summary."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return {"status": "read_error", "decompressed_bytes": 0}
    blob = decompress_chunks(data)
    if not blob:
        return {"status": "no_chunks", "decompressed_bytes": 0}
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(blob)
    return {"status": "ok", "decompressed_bytes": len(blob),
            "binxml_to": str(dest)}
