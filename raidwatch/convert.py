"""Normalize collector outputs / seized lists into one canonical CSV.

`raidwatch convert` turns whatever the evidence source actually is —
a ForensicArtifactCollector scan dir, a ForensicOutput zip, a
report.json, an 엑셀 detail list, or a plain text list — into a single
UTF-8-BOM CSV that:

- opens cleanly in Excel for counsel review (Korean headers intact),
- feeds straight back into `verify`/`boundary`/`keyword-audit` as
  `seized.csv`,
- keeps every row, including unparsed ones, with its source recorded.

Nothing is dropped silently: rows that could not be parsed are written
with unparsed=1 and their raw content in the note column.
"""

from __future__ import annotations

import csv
import json
import tempfile
import zipfile
from pathlib import Path

from .common import utc_now_iso, write_json, write_manifest
from .verify import parse_seized_list

# Collector scan dirs carry several overlapping lists with DIFFERENT
# meanings — do not pick by row count. report.json's
# likely_seized_files is the actual seizure estimate; file_paths.txt is
# a dump of EVERY discovered path (incl. the collector's own output
# mirror) and stays last-resort only.
_SOURCE_PRIORITY = (
    "report.json",
    "selected_files_ranked.txt",
    "likely_seized_files.txt",
    "selected_files.txt",
    "file_paths.txt",
    "copy_candidates.txt",
    "user_files.txt",
)

_FIELDS = (
    "seq", "claimed_path", "rel_path", "hash", "hash_algo",
    "name", "ext", "size", "created", "modified", "accessed",
    "sheet", "row", "unparsed", "note",
)


def _candidates(root: Path) -> list[Path]:
    """Parseable sources, semantic-priority first; within one name the
    latest scan_* dir wins (sorted-desc — timestamps sort lexically)."""
    found: list[Path] = []
    for name in _SOURCE_PRIORITY:
        found.extend(
            sorted(
                (p for p in root.rglob(name) if p.is_file()),
                reverse=True,
            )
        )
    if not found:
        found.extend(
            p for p in sorted(root.rglob("*"))
            if p.suffix.lower() in (".xlsx", ".csv", ".json", ".txt")
        )
    return found


def _pick_best(root: Path) -> tuple[list[dict], str | None, list[str]]:
    """First source in priority order that yields any real row wins —
    a ForensicOutput zip may hold several scan_*/dirs, but merging them
    would be wrong (each is a separate reconstruction hypothesis)."""
    cands = _candidates(root)
    found_names = [
        str(p.relative_to(root)).replace("\\", "/") for p in cands
    ]
    first_items: list[dict] = []
    first_used: str | None = None
    for p in cands:
        try:
            parsed = parse_seized_list(p)
        except Exception:
            continue  # unreadable member — try the next source
        if not first_items:
            first_items, first_used = parsed, str(
                p.relative_to(root)).replace("\\", "/")
        if any(not it.get("unparsed") for it in parsed):
            return parsed, str(p.relative_to(root)).replace("\\", "/"), found_names
    return first_items, first_used, found_names


def _extract_zip(path: Path, dest: Path) -> Path:
    """Extract a ForensicOutput zip → dir of candidates."""
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)
    return dest


def _rows(items: list[dict]) -> list[dict]:
    out: list[dict] = []
    for i, it in enumerate(items, 1):
        meta = it.get("claimed_meta") or {}
        raw = it.get("raw")
        note = ""
        if it.get("unparsed"):
            note = "unparsed"
            if raw:
                note += ": " + json.dumps(raw, ensure_ascii=False)[:400]
        out.append({
            "seq": meta.get("seq") or i,
            "claimed_path": it.get("claimed_path") or "",
            "rel_path": it.get("rel") or "",
            "hash": it.get("sha256") or "",
            "hash_algo": it.get("hash_algo") or "",
            "name": meta.get("name", ""),
            "ext": meta.get("ext", ""),
            "size": meta.get("size", ""),
            "created": meta.get("created", ""),
            "modified": meta.get("modified", ""),
            "accessed": meta.get("accessed", ""),
            "sheet": meta.get("sheet", ""),
            "row": meta.get("row", ""),
            "unparsed": 1 if it.get("unparsed") else 0,
            "note": note,
        })
    return out


def run_convert(source: Path, out_dir: Path) -> dict:
    """Normalize `source` (file/dir/zip) → out_dir/seized.csv (+report)."""
    source = Path(source)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sources_found: list[str] = []
    items: list[dict] = []
    used: str | None = None

    with tempfile.TemporaryDirectory(prefix="raidwatch-conv-") as td:
        root = source
        if source.is_file() and source.suffix.lower() == ".zip":
            root = _extract_zip(source, Path(td) / "pkg")
        if root.is_dir():
            items, used, sources_found = _pick_best(root)
        else:
            items = parse_seized_list(root)
            used = source.name
            sources_found = [source.name]

    rows = _rows(items)
    csv_path = out_dir / "seized.csv"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=_FIELDS)
        w.writeheader()
        w.writerows(rows)

    report = {
        "generated_at": utc_now_iso(),
        "input": str(source),
        "source_used": used,
        "sources_found": sources_found,
        "rows": len(rows),
        "unparsed": sum(1 for r in rows if r["unparsed"]),
        "output": str(csv_path),
        "note": (
            "seized.csv is UTF-8-BOM for Excel and is itself a valid "
            "seized list — `raidwatch verify seized.csv ...` works "
            "directly on it."
        ),
    }
    write_json(out_dir / "convert-report.json", report)
    write_manifest(out_dir, "convert", {"input": str(source), "rows": len(rows)})
    return report
