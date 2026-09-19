"""Windows .lnk (Shell Link) parser — stdlib only.

Extracts what Recent Items / Jump Lists actually pointed at: the
target path (LinkInfo local base path + common path suffix), working
dir, arguments, and the link's own create/access/write FILETIMEs —
which approximate when the item was opened.

Layout: 0x4C header ("L" + CLSID 00021401-0000-0000-C000-000000000046),
LinkFlags, FileAttributes, 3x FILETIME, size, icon, show, hotkey,
then optional IDList / LinkInfo / StringData blocks per LinkFlags.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .common import filetime_to_iso

_LNK_SIZE = 0x4C
_LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

F_IDLIST = 0x01
F_LINKINFO = 0x02
F_NAME = 0x04
F_RELPATH = 0x08
F_WORKDIR = 0x10
F_ARGS = 0x20
F_ICONLOC = 0x40
F_UNICODE = 0x80


class LnkError(Exception):
    pass


def _ansi(raw: bytes) -> str:
    """ANSI string: mbcs on Windows targets, Korean/1252 fallbacks elsewhere."""
    for enc in ("mbcs", "cp949", "cp1252", "latin-1"):
        try:
            return raw.decode(enc, errors="replace")
        except LookupError:
            continue
    return raw.decode("utf-8", errors="replace")


def _read_counted(data: bytes, pos: int, unicode_: bool) -> tuple[str, int]:
    if pos + 2 > len(data):
        return "", pos
    n = struct.unpack_from("<H", data, pos)[0]
    pos += 2
    if unicode_:
        raw = data[pos: pos + n * 2]
        s = raw.decode("utf-16-le", errors="replace")
        return s, pos + n * 2
    raw = data[pos: pos + n]
    return _ansi(raw), pos + n


def parse_lnk(data: bytes) -> dict:
    if len(data) < _LNK_SIZE or data[:4] != b"L\x00\x00\x00" or data[4:20] != _LNK_CLSID:
        raise LnkError("not a shell link")
    flags = struct.unpack_from("<I", data, 0x14)[0]
    out: dict = {
        "created_utc": filetime_to_iso(struct.unpack_from("<Q", data, 0x1C)[0]),
        "accessed_utc": filetime_to_iso(struct.unpack_from("<Q", data, 0x24)[0]),
        "modified_utc": filetime_to_iso(struct.unpack_from("<Q", data, 0x2C)[0]),
        "target_size": struct.unpack_from("<I", data, 0x34)[0],
        "target_path": None,
        "relative_path": None,
        "working_dir": None,
        "arguments": None,
        "description": None,
    }
    pos = _LNK_SIZE

    if flags & F_IDLIST:
        if pos + 2 > len(data):
            return out
        n = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + n

    if flags & F_LINKINFO and pos + 4 <= len(data):
        li_size = struct.unpack_from("<I", data, pos)[0]
        li_end = min(pos + li_size, len(data))
        if li_size >= 0x1C and pos + 0x1C <= len(data):
            hdr_size = struct.unpack_from("<I", data, pos + 4)[0]
            li_flags = struct.unpack_from("<I", data, pos + 8)[0]
            # offsets are relative to LinkInfo start
            def _cstr(o: int, uni: bool) -> str | None:
                p = pos + o
                if p >= li_end or p >= len(data):
                    return None
                if uni:
                    end = p
                    while end + 1 < li_end and data[end:end + 2] != b"\x00\x00":
                        end += 2
                    return data[p:end].decode("utf-16-le", errors="replace") or None
                end = data.find(b"\x00", p)
                if end < 0 or end > li_end:
                    end = li_end
                return _ansi(data[p:end]) or None

            base = None
            if li_flags & 0x01:  # VolumeIDAndLocalBasePath
                base = _cstr(struct.unpack_from("<I", data, pos + 0x10)[0], False)
            suffix_off = struct.unpack_from("<I", data, pos + 0x18)[0]
            suffix = _cstr(suffix_off, False)
            if hdr_size >= 0x24:  # unicode variants (Win7+)
                ubase_off = struct.unpack_from("<I", data, pos + 0x1C)[0]
                usuffix_off = struct.unpack_from("<I", data, pos + 0x20)[0]
                if li_flags & 0x01 and ubase_off:
                    base = _cstr(ubase_off, True) or base
                if usuffix_off:
                    suffix = _cstr(usuffix_off, True) or suffix
            if base and suffix:
                out["target_path"] = base.rstrip("\\") + "\\" + suffix.lstrip("\\")
            else:
                out["target_path"] = base or suffix
        pos += li_size

    uni = bool(flags & F_UNICODE)
    for flag, key in (
        (F_NAME, "description"),
        (F_RELPATH, "relative_path"),
        (F_WORKDIR, "working_dir"),
        (F_ARGS, "arguments"),
        (F_ICONLOC, None),
    ):
        if flags & flag:
            s, pos = _read_counted(data, pos, uni)
            if key and s:
                out[key] = s
    if out["target_path"] is None and out["relative_path"]:
        out["target_path"] = out["relative_path"]
    return out


def parse_lnk_file(path: Path | str) -> dict:
    try:
        return parse_lnk(Path(path).read_bytes())
    except (LnkError, OSError, struct.error) as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "target_path": None}
