"""Filesystem enumeration shared by baseline, scan, diff, and watcher."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterator

from .common import TOOL_NAME, TOOL_VERSION, sha256_file, utc_now_iso
from .db import FileRecord, Inventory

ProgressFn = Callable[[int, str], None]


def iter_fs(root: Path, *, follow_symlinks: bool = False) -> Iterator[tuple[str, Path, os.stat_result, str]]:
    """Yield (rel_posix, abs_path, stat_result, kind) in deterministic order."""
    stack = [Path(root)]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError:
            continue
        dirs = []
        for entry in entries:
            abs_path = Path(entry.path)
            rel = abs_path.relative_to(root).as_posix()
            try:
                st = entry.stat(follow_symlinks=follow_symlinks)
            except OSError:
                yield rel, abs_path, None, "error"
                continue
            if entry.is_symlink():
                yield rel, abs_path, st, "symlink"
            elif entry.is_dir(follow_symlinks=follow_symlinks):
                yield rel, abs_path, st, "dir"
                dirs.append(abs_path)
            elif entry.is_file(follow_symlinks=follow_symlinks):
                yield rel, abs_path, st, "file"
            else:
                yield rel, abs_path, st, "other"
        stack.extend(reversed(dirs))


def record_for(
    rel: str,
    abs_path: Path,
    st: os.stat_result | None,
    kind: str,
    *,
    hash_files: bool,
    max_hash_bytes: int | None,
) -> FileRecord:
    if st is None:
        return FileRecord(rel, 0, 0, 0, 0, None, "error", "stat_error")
    if kind != "file" or not hash_files:
        return FileRecord(
            rel, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_atime_ns,
            None, kind, "ok",
        )
    try:
        digest = sha256_file(abs_path, max_bytes=max_hash_bytes)
    except OSError:
        return FileRecord(
            rel, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_atime_ns,
            None, kind, "read_error",
        )
    status = "ok" if digest is not None else "hash_skipped_oversize"
    return FileRecord(
        rel, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_atime_ns,
        digest, kind, status,
    )


def build_inventory(
    root: Path,
    inv: Inventory,
    *,
    hash_files: bool = True,
    max_hash_bytes: int | None = None,
    follow_symlinks: bool = False,
    progress: ProgressFn | None = None,
) -> dict:
    """Enumerate root into the inventory DB. Returns summary counts."""
    root = root.resolve()
    counts = {"file": 0, "dir": 0, "symlink": 0, "other": 0, "error": 0}
    status_counts: dict[str, int] = {}
    seen = 0
    for rel, abs_path, st, kind in iter_fs(root, follow_symlinks=follow_symlinks):
        rec = record_for(
            rel, abs_path, st, kind,
            hash_files=hash_files, max_hash_bytes=max_hash_bytes,
        )
        inv.upsert(rec)
        counts[kind] = counts.get(kind, 0) + 1
        status_counts[rec.status] = status_counts.get(rec.status, 0) + 1
        seen += 1
        if progress and seen % 2000 == 0:
            progress(seen, rel)
    inv.set_meta("tool", TOOL_NAME)
    inv.set_meta("tool_version", TOOL_VERSION)
    inv.set_meta("root", str(root))
    inv.set_meta("created_utc", utc_now_iso())
    inv.set_meta("hash_files", hash_files)
    inv.set_meta("counts", counts)
    inv.set_meta("status_counts", status_counts)
    inv.commit()
    return {"entries": seen, "counts": counts, "status_counts": status_counts}
