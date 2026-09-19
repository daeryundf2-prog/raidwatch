"""Prefetch (.pf) parsing — execution counts and last-run times.

Turns a copied .pf file into evidence: which investigator tool ran, how
many times, and when it last ran. Handles uncompressed v23/v26/v30
records directly; Windows 10+ prefetch files are usually XPRESS-Huffman
compressed ("MAM\x04") — we attempt RtlDecompressBufferEx via ntdll on
Windows and report ``compressed_unparsed`` elsewhere.

Offsets follow the documented libscca layout; all reads are bounds-
checked and failures degrade to partial results rather than exceptions.
"""

from __future__ import annotations

import ctypes
import platform
import struct
from pathlib import Path

from .common import filetime_to_iso

_VERSIONS = {17: "xp", 23: "vista_win7", 26: "win8x", 30: "win10_plus"}
# (last_runs_offset, run_count_offset) per version — libscca layout:
# v17/v23 carry a single last-run FILETIME; v26/v30 carry 8 slots and
# move the run count to 0xD0 (0x98 sits inside the timestamp array).
_OFFSETS = {
    17: (0x78, 0x90),
    23: (0x80, 0x98),
    26: (0x80, 0xD0),
    30: (0x80, 0xD0),
}
_MAM_SIG = b"MAM\x04"
_MAX_MAM_EXPECTED = 64 * 1024 * 1024


def _decompress_mam(data: bytes) -> bytes | None:
    """Windows-only XPRESS-Huffman decompression via ntdll; None elsewhere."""
    if platform.system() != "Windows" or len(data) < 8:
        return None
    try:
        ntdll = ctypes.windll.ntdll
        expected = struct.unpack_from("<I", data, 4)[0]
        if not 0 < expected <= _MAX_MAM_EXPECTED:
            return None
        workspace_size = ctypes.c_ulong(0)
        ntdll.RtlGetCompressionWorkSpaceSize(
            ctypes.c_ushort(0x104),  # XPRESS_HUFF | ENGINE_MAXIMUM
            ctypes.byref(workspace_size),
            ctypes.byref(ctypes.c_ulong(0)),
        )
        workspace = ctypes.create_string_buffer(workspace_size.value)
        out = ctypes.create_string_buffer(expected)
        final = ctypes.c_ulong(0)
        status = ntdll.RtlDecompressBufferEx(
            ctypes.c_ushort(0x104),
            out,
            ctypes.c_ulong(expected),
            data[8:],
            ctypes.c_ulong(len(data) - 8),
            ctypes.byref(final),
            workspace,
        )
        if status != 0:
            return None
        return out.raw[: final.value]
    except (OSError, AttributeError, ctypes.ArgumentError):
        return None


def parse_prefetch(data: bytes) -> dict:
    """Parse .pf bytes → {exe_name, version, run_count, last_runs_utc}."""
    result: dict = {
        "exe_name": None,
        "version": None,
        "version_label": None,
        "run_count": None,
        "last_runs_utc": [],
        "status": "ok",
    }
    if data.startswith(_MAM_SIG):
        decompressed = _decompress_mam(data)
        if decompressed is None:
            result["status"] = "compressed_unparsed"
            return result
        data = decompressed
    # Real .pf layout: format version @0x00, "SCCA" signature @0x04.
    if len(data) < 0x60 or data[4:8] != b"SCCA":
        result["status"] = "not_prefetch"
        return result

    version = struct.unpack_from("<I", data, 0)[0]
    result["version"] = version
    result["version_label"] = _VERSIONS.get(version, f"unknown_{version}")
    result["exe_name"] = (
        data[0x10:0x4C].decode("utf-16-le", errors="replace").rstrip("\x00")
    )

    offsets = _OFFSETS.get(version)
    slots = 8 if version >= 26 else 1
    if (
        offsets is None
        or len(data) < max(offsets[1] + 4, offsets[0] + slots * 8)
    ):
        result["status"] = "partial"
        return result
    runs_off, count_off = offsets
    result["run_count"] = struct.unpack_from("<I", data, count_off)[0]
    for i in range(slots):
        raw, = struct.unpack_from("<Q", data, runs_off + i * 8)
        iso = filetime_to_iso(raw)
        if iso:
            result["last_runs_utc"].append(iso)
    return result


def parse_prefetch_file(path: Path) -> dict:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return {"exe_name": None, "status": "read_error", "last_runs_utc": []}
    return parse_prefetch(data)
