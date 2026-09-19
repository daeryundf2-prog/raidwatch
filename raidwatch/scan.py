"""Independent warrant-criteria rescan producing a hit list."""

from __future__ import annotations

from pathlib import Path

from .common import ns_to_iso, write_json, write_manifest
from .inventory import iter_fs, record_for
from .profile import evaluate
from .text_extract import SUPPORTED_EXTS, extract_text

DEFAULT_MAX_CONTENT_BYTES = 32 * 1024 * 1024


def scan_target(
    root: Path,
    profile: dict,
    *,
    hash_files: bool = True,
    max_hash_bytes: int | None = None,
    follow_symlinks: bool = False,
    max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES,
) -> dict:
    """Evaluate every filesystem entry against the profile.

    Returns {"hits": [...], "summary": {...}}. Hits are broad matches;
    each carries a scope verdict (in_scope = narrow AND, borderline =
    broad OR only).
    """
    root = root.resolve()
    content_kws = [
        k for k in profile["criteria"]["keywords"] if k["in"] == "content"
    ]
    hits = []
    summary = {
        "evaluated": 0,
        "excluded": 0,
        "hits": 0,
        "in_scope": 0,
        "borderline": 0,
        "errors": 0,
        "skipped_status": {},
        "content_extracted": 0,
        "content_extract_failed": 0,
        "content_keyword_terms": len(content_kws),
    }
    for rel, abs_path, st, kind in iter_fs(root, follow_symlinks=follow_symlinks):
        if kind == "dir":
            continue
        summary["evaluated"] += 1
        rec = record_for(
            rel, abs_path, st, kind,
            hash_files=hash_files, max_hash_bytes=max_hash_bytes,
        )
        summary["skipped_status"][rec.status] = (
            summary["skipped_status"].get(rec.status, 0) + 1
        )
        if rec.status in ("stat_error", "read_error"):
            summary["errors"] += 1
        item = rec.as_dict()
        item["content"] = None
        extract_failed = False
        if (
            content_kws
            and st is not None
            and st.st_size <= max_content_bytes
            and abs_path.suffix.lower() in SUPPORTED_EXTS
        ):
            text = extract_text(abs_path, max_bytes=max_content_bytes)
            if text is not None:
                item["content"] = text
                summary["content_extracted"] += 1
            else:
                extract_failed = True
                summary["content_extract_failed"] += 1
        result = evaluate(item, profile)
        if result["excluded"]:
            summary["excluded"] += 1
            continue
        if not result["broad"]:
            continue
        summary["hits"] += 1
        summary["in_scope" if result["narrow"] else "borderline"] += 1
        hits.append(
            {
                "seq": summary["hits"],
                "path": rel,
                "name": abs_path.name,
                "size": rec.size,
                "mtime_utc": ns_to_iso(rec.mtime_ns),
                "sha256": rec.sha256,
                "matched": result["matched"],
                "verdict": result["verdict"],
                "status": (
                    "extract_failed" if extract_failed else rec.status
                ),
            }
        )
    return {"hits": hits, "summary": summary}


def run_scan(
    root: Path,
    profile: dict,
    out_dir: Path,
    **kwargs,
) -> dict:
    result = scan_target(root, profile, **kwargs)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "hits.json", result)
    write_manifest(
        out_dir,
        "scan",
        {
            "root": str(root.resolve()),
            "profile_sha256": profile["profile_sha256"],
            "summary": result["summary"],
        },
    )
    return result
