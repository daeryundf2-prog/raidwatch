"""Mirror — copy the exact file set investigators seized.

The highest-value artifact counsel can walk away with: a byte-identical
copy of everything on the seized list, preserving directory structure,
with SHA-256 computed on OUR copy — so later "their file vs ours"
comparisons are possible without trusting their hash work.

Sources of truth (either works):

- ``--verify verify.json``: reuse the resolved matches from a verify
  run (preferred — matches are already adjudicated).
- ``--seized list.*``: resolve on the fly — builds a temp inventory of
  --root, parses the list (txt/csv/json/pdf/OCR text), fuzzy-matches,
  then copies whatever resolved.

Every item with a resolved path is copied regardless of scope verdict —
scope is a legal question; mirroring is evidence preservation.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from .common import sha256_file, utc_now_iso, write_json, write_manifest
from .db import Inventory
from .inventory import build_inventory

SUMS_NAME = "MIRROR-SHA256SUMS.txt"


def _items_from_verify(verify_path: Path) -> list[dict]:
    data = json.loads(Path(verify_path).read_text(encoding="utf-8"))
    return [
        it for it in data.get("items", [])
        if it.get("matched_path")
    ]


def _items_from_list(seized_path: Path, root: Path) -> list[dict]:
    """Resolve a raw seized list against a fresh inventory of root."""
    from .verify import parse_seized_list, verify_items

    with tempfile.TemporaryDirectory(prefix="raidwatch-mirror-") as td:
        inv = Inventory(Path(td) / "inv.db", create=True)
        try:
            build_inventory(root, inv, hash_files=False)
            seized = parse_seized_list(seized_path)
            report = verify_items(
                seized, inv, current_root=root
            )
            return [
                it for it in report.get("items", [])
                if it.get("matched_path")
            ]
        finally:
            inv.close()


def run_mirror(
    root: Path,
    out_dir: Path,
    *,
    verify_path: Path | None = None,
    seized_path: Path | None = None,
    max_file_mb: int = 0,  # 0 = unlimited — mirror wants completeness
) -> dict:
    """Copy every resolved seized file from root into out_dir/files/."""
    root = Path(root).resolve()
    out_dir = Path(out_dir).resolve()
    files_dir = out_dir / "files"
    if verify_path is not None:
        items = _items_from_verify(Path(verify_path))
        source = f"verify:{Path(verify_path).resolve()}"
    elif seized_path is not None:
        items = _items_from_list(Path(seized_path), root)
        source = f"seized:{Path(seized_path).resolve()}"
    else:
        raise ValueError("either verify_path or seized_path is required")

    max_bytes = max_file_mb * 1024 * 1024 if max_file_mb else None
    copied, sums, seen = [], [], set()
    results = []
    for it in items:
        rel = it["matched_path"]
        if rel in seen:
            continue
        seen.add(rel)
        src = root / rel  # Path handles '/' separators on Windows too
        entry = {
            "rel": rel,
            "claimed_path": it.get("claimed_path"),
            "claimed_sha256": it.get("claimed_sha256"),
            "verify_status": it.get("status"),
        }
        try:
            size = src.stat().st_size
        except OSError:
            entry["status"] = "missing_now"
            entry["notes"] = "resolved at verify time but absent on disk now"
            results.append(entry)
            continue
        entry["size"] = size
        if max_bytes is not None and size > max_bytes:
            entry["status"] = "skipped_too_large"
            results.append(entry)
            continue
        dest = files_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dest)
        except OSError as exc:
            entry["status"] = "copy_failed"
            entry["error"] = str(exc)
            results.append(entry)
            continue
        digest = sha256_file(src)
        entry["dest"] = str(dest)
        entry["sha256"] = digest
        claimed = (it.get("claimed_sha256") or "").lower()
        entry["hash_vs_claimed"] = (
            "match" if claimed and claimed == digest
            else "mismatch" if claimed and len(claimed) == 64
            else "incomparable" if claimed
            else "no_claimed_hash"
        )
        entry["status"] = "copied"
        sums.append((digest, f"files/{rel}"))
        results.append(entry)
        copied.append(rel)

    sums_path = out_dir / SUMS_NAME
    sums_path.parent.mkdir(parents=True, exist_ok=True)
    sums_path.write_text(
        "".join(f"{d}  {r}\n" for d, r in sums), encoding="utf-8"
    )
    summary = {
        "items_resolved": len(items),
        "copied": len(copied),
        "missing_now": sum(1 for r in results if r["status"] == "missing_now"),
        "copy_failed": sum(1 for r in results if r["status"] == "copy_failed"),
        "skipped_too_large": sum(
            1 for r in results if r["status"] == "skipped_too_large"
        ),
        "hash_match": sum(1 for r in results if r.get("hash_vs_claimed") == "match"),
        "hash_mismatch": sum(1 for r in results if r.get("hash_vs_claimed") == "mismatch"),
    }
    report = {
        "source": source,
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "items": results,
        "note": (
            "Mirror preserves directory structure and hashes OUR copy — "
            "hash_mismatch against a printed claimed hash means the file "
            "changed since the list was made or their hash is wrong; "
            "either way the mirrored bytes + MIRROR-SHA256SUMS.txt are "
            "the defense's independent record."
        ),
    }
    write_json(out_dir / "mirror.json", report)
    write_manifest(out_dir, "mirror", {"source": source, "summary": summary})
    return report
