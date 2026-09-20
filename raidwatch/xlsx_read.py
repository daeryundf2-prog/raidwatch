"""Minimal XLSX reader (stdlib-only) for seized-evidence detail lists.

The 전자정보확인서 detail list arrives as .xlsx — multi-sheet workbooks
(sheets named 파일1…파일N, ≤1000 rows each) with Korean or English
headers such as 연번/파일명/확장자명/파일 크기(바이트)/경로/SHA1/생성일시/
수정일시/접근일시. openpyxl is not available in the field kit, so this
reads the OOXML structure directly: sharedStrings + sheet XML.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_NS_REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_PKG_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"

_COL_RE = re.compile(r"^([A-Z]+)(\d+)$")

# header (normalized: lowercase, whitespace/punct stripped) → field
_HEADER_FIELDS = {
    "seq": ("연번", "순번", "번호", "no", "index", "#"),
    "name": ("파일명", "파일이름", "filename", "name"),
    "ext": ("확장자명", "확장자", "extension", "ext"),
    "size": (
        "파일크기바이트", "파일크기", "크기바이트", "크기",
        "filesizebytes", "filesize", "sizebytes", "size",
    ),
    "path": (
        "전체파일경로", "파일경로", "경로", "filepath",
        "fullpath", "path", "location",
    ),
    "sha256": ("sha256",),
    "sha1": ("sha1",),
    "md5": ("md5",),
    "created": ("생성일시", "작성일시", "created", "creationdate", "ctime"),
    "modified": (
        "최종수정일시", "수정일시", "modified", "modifieddate", "mtime",
    ),
    "accessed": (
        "접근일시", "열람일시", "accessed", "accesseddate", "atime",
    ),
    "note": ("비고", "note", "notes", "remark"),
}


def _norm_header(text: str) -> str:
    return re.sub(r"[\s\-_.()\[\]/]", "", str(text).lower())


def _match_header(text: str) -> str | None:
    norm = _norm_header(text)
    if not norm:
        return None
    # hash headers first — "SHA-256 해시" must win over generic keys
    for field in ("sha256", "sha1", "md5"):
        if any(k in norm for k in _HEADER_FIELDS[field]):
            return field
    for field, keys in _HEADER_FIELDS.items():
        if field in ("sha256", "sha1", "md5"):
            continue
        for k in keys:
            if norm == k or norm.startswith(k):
                return field
    return None


def _col_index(ref: str) -> int:
    m = _COL_RE.match(ref or "")
    if not m:
        return -1
    idx = 0
    for ch in m.group(1):
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def _load_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    try:
        data = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    return [
        "".join(t.text or "" for t in si.iter(f"{_NS}t"))
        for si in ET.fromstring(data).iter(f"{_NS}si")
    ]


def _sheet_files(zf: zipfile.ZipFile) -> list[tuple[str, str]]:
    """[(sheet_name, member_path)] in workbook order."""
    try:
        wb = ET.fromstring(zf.read("xl/workbook.xml"))
        rels = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    except (KeyError, ET.ParseError):
        return [
            (Path(n).stem, n)
            for n in sorted(zf.namelist())
            if re.match(r"xl/worksheets/sheet\d+\.xml$", n)
        ]
    relmap = {
        r.get("Id"): r.get("Target", "")
        for r in rels.iter(f"{_PKG_REL}Relationship")
    }
    out = []
    for sh in wb.iter(f"{_NS}sheet"):
        target = relmap.get(sh.get(f"{_NS_REL}id"), "")
        if target and not target.startswith("xl/"):
            target = "xl/" + target.lstrip("/")
        if target:
            out.append((sh.get("name", ""), target))
    return out


def _cell_text(cell: ET.Element, shared: list[str]) -> str:
    ctype = cell.get("t", "n")
    if ctype == "s":
        v = cell.find(f"{_NS}v")
        if v is None or v.text is None:
            return ""
        try:
            return shared[int(v.text)]
        except (IndexError, ValueError):
            return ""
    if ctype == "inlineStr":
        is_el = cell.find(f"{_NS}is")
        if is_el is None:
            return ""
        return "".join(t.text or "" for t in is_el.iter(f"{_NS}t"))
    v = cell.find(f"{_NS}v")
    if v is None or v.text is None:
        return ""
    text = v.text
    if ctype == "n" and re.fullmatch(r"-?\d+\.0", text):
        return text[:-2]  # integer-valued float → clean string
    return text


def read_xlsx(path) -> list[tuple[str, list[list[str]]]]:
    """Return [(sheet_name, rows)]; each row is a list of cell strings."""
    with zipfile.ZipFile(path) as zf:
        shared = _load_shared_strings(zf)
        sheets: list[tuple[str, list[list[str]]]] = []
        for name, member in _sheet_files(zf):
            try:
                root = ET.fromstring(zf.read(member))
            except (KeyError, ET.ParseError):
                continue
            rows: list[list[str]] = []
            for row in root.iter(f"{_NS}row"):
                cells: dict[int, str] = {}
                max_col = -1
                for c in row.iter(f"{_NS}c"):
                    ci = _col_index(c.get("r", ""))
                    if ci < 0:
                        ci = max_col + 1
                    cells[ci] = _cell_text(c, shared)
                    max_col = max(max_col, ci)
                rows.append([cells.get(i, "") for i in range(max_col + 1)])
            sheets.append((name, rows))
        return sheets


def iter_seized_rows(path) -> list[dict]:
    """Normalize an .xlsx seized list into row dicts.

    Returns [{seq, name, ext, size_bytes, path, hashes{md5,sha1,sha256},
              created, modified, accessed, note, sheet, row}].
    Sheets whose first non-empty row has no recognizable headers are
    treated as headerless data (path in col with a drive pattern).
    """
    out: list[dict] = []
    for sheet_name, rows in read_xlsx(path):
        header_map: dict[int, str] = {}
        header_seen = False
        for ridx, row in enumerate(rows):
            if not any(str(c).strip() for c in row):
                continue
            if not header_seen:
                mapped = {
                    i: _match_header(c) for i, c in enumerate(row)
                }
                known = {f for f in mapped.values() if f}
                if "path" in known or "name" in known or len(known) >= 2:
                    header_map = {
                        i: f for i, f in mapped.items() if f
                    }
                    header_seen = True
                    continue
                header_seen = True  # headerless sheet — data starts here
            rec: dict = {
                "seq": "", "name": "", "ext": "", "size": "",
                "path": "", "md5": "", "sha1": "", "sha256": "",
                "created": "", "modified": "", "accessed": "",
                "note": "", "sheet": sheet_name, "row": ridx + 1,
            }
            for i, cell in enumerate(row):
                field = header_map.get(i)
                if field:
                    rec[field] = str(cell).strip()
            if not header_map:
                # headerless: guess drive-path-looking cell
                for cell in row:
                    text = str(cell).strip()
                    if re.match(r"^[A-Za-z]:[\\/]", text) or "/" in text:
                        rec["path"] = text
                        break
            if not any(rec[k] for k in ("path", "name", "sha1", "md5")):
                continue
            out.append(rec)
    return out
