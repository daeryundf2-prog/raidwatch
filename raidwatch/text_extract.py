"""Best-effort text extraction for content-keyword matching (M5).

Supports the document formats that dominate Korean case files:

- plain text (UTF-8, EUC-KR/CP949, UTF-16 fallbacks) — txt/csv/log/eml/…
- OOXML (docx/xlsx/pptx) — zip members' XML text nodes
- HWPX — zip members' XML text nodes
- legacy HWP — OLE compound file: PrvText (UTF-16LE preview) plus
  zlib-deflated BodyText sections scanned for printable UTF-16LE runs
- PDF — deflated stream objects scanned for Tj/TJ literal strings
- zip — one level of member recursion

Extraction is positional, best-effort text only: layout, fonts, and
encrypted/DRM-protected content are not handled. ``extract_text`` returns
``None`` when nothing usable was recovered; callers must record that as
``extract_failed`` rather than silently matching.
"""

from __future__ import annotations

import io
import re
import struct
import zlib
import zipfile
from pathlib import Path

MAX_EXTRACT_BYTES = 64 * 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_XML_TAG_RE = re.compile(r"<[^>]+>")
_UTF16_RUN = re.compile(r"[ -~\uac00-\ud7a3\u3130-\u318f]{4,}")

TEXT_EXTS = {
    ".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".htm", ".html",
    ".md", ".eml", ".ini", ".cfg", ".rtf",
}
OOXML_EXTS = {".docx", ".xlsx", ".pptx", ".hwpx"}
SUPPORTED_EXTS = TEXT_EXTS | OOXML_EXTS | {".hwp", ".pdf", ".zip"}

_ENCODINGS = ("utf-8", "cp949", "utf-16")


def _decode_text(data: bytes) -> str | None:
    for enc in _ENCODINGS:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _strip_xml(text: str) -> str:
    return _XML_TAG_RE.sub(" ", text)


def _extract_zip_xml_text(zf: zipfile.ZipFile) -> str:
    """Concatenate text from all XML-ish members of an open zip."""
    parts: list[str] = []
    for name in zf.namelist():
        if not name.lower().endswith((".xml", ".txt")):
            continue
        try:
            data = zf.read(name)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError):
            continue
        if len(data) > _MAX_MEMBER_BYTES:
            continue
        decoded = _decode_text(data)
        if decoded:
            parts.append(_strip_xml(decoded))
    return "\n".join(parts)


def _extract_zip_container(zf: zipfile.ZipFile, depth: int) -> str:
    """Recurse one level into a generic .zip of mixed members."""
    parts: list[str] = []
    for info in zf.infolist():
        if info.file_size > _MAX_MEMBER_BYTES:
            continue
        suffix = Path(info.filename).suffix.lower()
        if suffix not in SUPPORTED_EXTS:
            continue
        try:
            data = zf.read(info)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError):
            continue
        text = _extract_bytes(data, suffix, depth=depth + 1)
        if text:
            parts.append(text)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# OLE Compound File (CFB) — needed for legacy .hwp

_CFB_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF


class CfbError(ValueError):
    pass


class CfbFile:
    """Minimal read-only CFB parser sufficient for HWP stream extraction."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or data[:8] != _CFB_SIG:
            raise CfbError("not a CFB file")
        self._data = data
        self._sector_size = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self._mini_sector_size = 1 << struct.unpack_from("<H", data, 0x20)[0]
        num_fat = struct.unpack_from("<I", data, 0x2C)[0]
        self._first_dir = struct.unpack_from("<I", data, 0x30)[0]
        self._mini_cutoff = struct.unpack_from("<I", data, 0x38)[0]
        first_minifat = struct.unpack_from("<I", data, 0x3C)[0]
        num_minifat = struct.unpack_from("<I", data, 0x40)[0]
        first_difat = struct.unpack_from("<I", data, 0x44)[0]
        num_difat = struct.unpack_from("<I", data, 0x48)[0]

        difat = list(struct.unpack_from("<109I", data, 0x4C))
        sid = first_difat
        for _ in range(num_difat):
            if sid >= _FREESECT:
                break
            entries = struct.unpack_from(
                f"<{self._sector_size // 4}I", self._sector(sid), 0
            )
            difat.extend(entries[:-1])
            sid = entries[-1]

        self._fat: list[int] = []
        for fat_sid in difat[:num_fat]:
            if fat_sid >= _FREESECT:
                continue
            self._fat.extend(
                struct.unpack(f"<{self._sector_size // 4}I",
                              self._sector(fat_sid))
            )

        self._minifat: list[int] = []
        sid = first_minifat
        for _ in range(num_minifat):
            if sid >= _FREESECT:
                break
            self._minifat.extend(
                struct.unpack(f"<{self._sector_size // 4}I", self._sector(sid))
            )
            sid = self._fat[sid] if sid < len(self._fat) else _ENDOFCHAIN

        self._dir_entries = self._read_dir()
        root = next((e for e in self._dir_entries if e["type"] == 5), None)
        self._mini_stream = b""
        if root and root["start"] < _FREESECT:
            self._mini_stream = self._read_chain(root["start"])[: root["size"]]

    def _sector(self, sid: int) -> bytes:
        start = 512 + sid * self._sector_size
        sector = self._data[start : start + self._sector_size]
        if len(sector) != self._sector_size:
            raise CfbError(f"truncated sector {sid}")
        return sector

    def _read_chain(self, start_sid: int) -> bytes:
        out = bytearray()
        sid = start_sid
        seen = set()
        while sid < _FREESECT and sid not in seen:
            seen.add(sid)
            out += self._sector(sid)
            sid = self._fat[sid] if sid < len(self._fat) else _ENDOFCHAIN
        return bytes(out)

    def _read_mini_chain(self, start_sid: int) -> bytes:
        out = bytearray()
        sid = start_sid
        seen = set()
        while sid < _FREESECT and sid not in seen:
            seen.add(sid)
            start = sid * self._mini_sector_size
            out += self._mini_stream[start : start + self._mini_sector_size]
            sid = (
                self._minifat[sid] if sid < len(self._minifat) else _ENDOFCHAIN
            )
        return bytes(out)

    def _read_dir(self) -> list[dict]:
        raw = self._read_chain(self._first_dir)
        entries = []
        for off in range(0, len(raw) - 127, 128):
            name_len = struct.unpack_from("<H", raw, off + 64)[0]
            if name_len < 2 or name_len > 64:
                continue
            name = raw[off : off + name_len - 2].decode(
                "utf-16-le", errors="replace"
            )
            entries.append(
                {
                    "name": name,
                    "type": raw[off + 66],
                    "start": struct.unpack_from("<I", raw, off + 116)[0],
                    "size": struct.unpack_from("<Q", raw, off + 120)[0],
                }
            )
        return entries

    def stream_names(self) -> list[str]:
        return [e["name"] for e in self._dir_entries if e["type"] == 2]

    def open_stream(self, name: str) -> bytes | None:
        entry = next(
            (e for e in self._dir_entries
             if e["type"] == 2 and e["name"].lower() == name.lower()),
            None,
        )
        if entry is None:
            return None
        if entry["size"] < self._mini_cutoff:
            # Small streams live in the mini stream — never reinterpret
            # a mini-sector id as a regular sector id.
            if not self._mini_stream:
                return None
            return self._read_mini_chain(entry["start"])[: entry["size"]]
        return self._read_chain(entry["start"])[: entry["size"]]


def _hwp_text(cfb: CfbFile) -> str | None:
    parts: list[str] = []
    prv = cfb.open_stream("PrvText")
    if prv:
        parts.append(prv.decode("utf-16-le", errors="ignore"))
    for name in cfb.stream_names():
        if not name.lower().startswith("section"):
            continue
        # CFB entry names are flat; BodyText/SectionN resolves as "SectionN"
        stream = cfb.open_stream(name)
        if not stream:
            continue
        try:
            stream = zlib.decompress(stream)
        except zlib.error:
            pass  # uncompressed section — still scannable
        parts.extend(
            _UTF16_RUN.findall(stream.decode("utf-16-le", errors="ignore"))
        )
    text = "\n".join(p for p in parts if p.strip())
    return text or None


# ---------------------------------------------------------------------------
# PDF — deflated streams, Tj/TJ literal strings only (best effort)

_PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_PDF_LIT_RE = re.compile(rb"\((?:\\.|[^\\()])*\)\s*(?:Tj|')")
_PDF_TJ_RE = re.compile(rb"\[(.*?)\]\s*TJ", re.DOTALL)
_PDF_STR_RE = re.compile(rb"\((?:\\.|[^\\()])*\)")


def _pdf_unescape(raw: bytes) -> str:
    text = raw.decode("latin-1", errors="replace")
    for esc, rep in (
        (r"\(", "("), (r"\)", ")"), (r"\\", "\\"),
        (r"\n", "\n"), (r"\r", ""), (r"\t", "\t"),
    ):
        text = text.replace(esc, rep)
    return text


def _pdf_text(data: bytes) -> str | None:
    parts: list[str] = []
    for match in _PDF_STREAM_RE.finditer(data):
        payload = match.group(1)
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            continue
        for lit in _PDF_LIT_RE.findall(payload):
            parts.append(_pdf_unescape(lit[1 : lit.rfind(b")")]))
        for arr in _PDF_TJ_RE.findall(payload):
            for s in _PDF_STR_RE.findall(arr):
                parts.append(_pdf_unescape(s[1:-1]))
    text = "\n".join(parts)
    return text if text.strip() else None


# ---------------------------------------------------------------------------

def _extract_bytes(data: bytes, suffix: str, *, depth: int) -> str | None:
    """Dispatch on already-read bytes (zip member recursion, depth-capped)."""
    suffix = suffix.lower()
    if len(data) > MAX_EXTRACT_BYTES or suffix not in SUPPORTED_EXTS:
        return None
    if suffix in TEXT_EXTS:
        return _decode_text(data)
    if suffix == ".pdf":
        return _pdf_text(data)
    if suffix == ".hwp":
        try:
            return _hwp_text(CfbFile(data))
        except (CfbError, struct.error, IndexError, zlib.error):
            return None
    if suffix in OOXML_EXTS or (suffix == ".zip" and depth < 2):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if suffix == ".zip":
                    return _extract_zip_container(zf, depth) or None
                return _extract_zip_xml_text(zf) or None
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
            return None
    return None


def extract_text(
    path: Path, *, max_bytes: int = MAX_EXTRACT_BYTES
) -> str | None:
    """Extract positional text from a supported file; None on failure."""
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_EXTS:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > max_bytes:
        return None
    return _extract_bytes(data, suffix, depth=0)
