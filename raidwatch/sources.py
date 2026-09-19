"""Recovery of the original digital seized-list from the seized PC.

The stamped paper list handed over on scene was printed from a tool that
left digital originals behind: printer spool files, temp report artifacts,
and the recycle bin. This module locates and preserves those sources so
the paper copy does not need to be OCR-read at all.

Deleted-file carving (raw MFT/unallocated) is out of scope for this
portable version; existing-but-overlooked files are covered.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from .common import ns_to_iso, sha256_file, utc_now_iso, write_json, write_manifest
from .inventory import iter_fs

TEXT_EXTS = {
    ".txt", ".csv", ".tsv", ".json", ".xml", ".htm", ".html",
    ".log", ".ini", ".eml", ".rtf",
}
REPORT_EXTS = TEXT_EXTS | {".xlsx", ".xls", ".pdf", ".spl", ".shd", ".emf"}
NAME_HINTS = (
    "evidence", "manifest", "list", "report", "seiz", "export",
    "print", "scan", "목록", "압수", "조서", "증거",
)
SPOOL_SUFFIXES = {".spl", ".shd", ".emf"}

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RUN = re.compile(r"[ -\u007e가-힯ㄱ-ㅣ]{6,}")


def extract_strings(path: Path, limit: int = 2000) -> list[str]:
    """Pull printable ASCII and UTF-16LE runs (incl. Hangul) from a file."""
    try:
        data = path.read_bytes()
    except OSError:
        return []
    out: list[str] = []
    seen = set()
    for raw in _ASCII_RUN.findall(data):
        text = raw.decode("ascii", errors="replace")
        if text not in seen:
            seen.add(text)
            out.append(text)
    decoded = data.decode("utf-16-le", errors="ignore")
    for text in _UTF16_RUN.findall(decoded):
        text = text.strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
        if len(out) >= limit:
            break
    return out[:limit]


def _reason_for(rel: str, mtime_ns: int, since_ns: int | None) -> str | None:
    parts = rel.lower().split("/")
    if "spool" in parts and "printers" in parts:
        return "spool"
    if any(p.startswith("$recycle.bin") or p == "recycler" for p in parts):
        return "recycle_bin"
    if "temp" in parts:
        if since_ns is None or mtime_ns >= since_ns:
            return "temp"
    return None


def collect_sources(
    root: Path,
    out_dir: Path,
    *,
    since_ns: int | None = None,
    max_file_bytes: int = 50 * 1024 * 1024,
) -> dict:
    """Find and preserve candidate seized-list sources under root."""
    root = root.resolve()
    collected_dir = out_dir / "collected"
    extracted_dir = out_dir / "extracted"
    items = []
    summary = {"candidates": 0, "copied": 0, "too_large": 0, "extracted": 0,
               "by_reason": {}}

    for rel, abs_path, st, kind in iter_fs(root):
        if kind != "file" or st is None:
            continue
        reason = _reason_for(rel, st.st_mtime_ns, since_ns)
        if reason is None:
            continue
        suffix = abs_path.suffix.lower()
        name_l = abs_path.name.lower()
        if reason == "temp" and not (
            suffix in REPORT_EXTS or any(h in name_l for h in NAME_HINTS)
        ):
            continue
        summary["candidates"] += 1
        summary["by_reason"][reason] = summary["by_reason"].get(reason, 0) + 1

        entry = {
            "path": rel,
            "reason": reason,
            "size": st.st_size,
            "mtime_utc": ns_to_iso(st.st_mtime_ns),
            "sha256": None,
            "copied_to": None,
            "extracted_to": None,
        }
        safe_rel = rel.replace("/", "__")
        if st.st_size <= max_file_bytes:
            dest = collected_dir / reason / safe_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(abs_path, dest)
                entry["sha256"] = sha256_file(abs_path)
                entry["copied_to"] = str(dest)
                summary["copied"] += 1
            except OSError:
                entry["copied_to"] = None
            if suffix in SPOOL_SUFFIXES or suffix in TEXT_EXTS:
                strings = extract_strings(abs_path)
                if strings:
                    ext_dest = extracted_dir / f"{safe_rel}.strings.txt"
                    ext_dest.parent.mkdir(parents=True, exist_ok=True)
                    ext_dest.write_text(
                        "\n".join(strings) + "\n", encoding="utf-8"
                    )
                    entry["extracted_to"] = str(ext_dest)
                    summary["extracted"] += 1
        else:
            summary["too_large"] += 1
        items.append(entry)

    report = {
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "items": items,
        "note": (
            "Deleted-file carving (MFT unallocated) is not performed by "
            "this portable build; run against unallocated space separately."
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "sources.json", report)
    write_manifest(
        out_dir,
        "sources",
        {"root": str(root), "summary": summary},
    )
    return report
