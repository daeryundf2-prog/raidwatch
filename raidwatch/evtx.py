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
