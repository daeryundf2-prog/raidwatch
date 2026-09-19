"""Filesystem enumeration shared by baseline, scan, diff, and watcher."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterator

from .common import TOOL_NAME, TOOL_VERSION, sha256_file_preserve, utc_now_iso
from .db import FileRecord, Inventory

ProgressFn = Callable[[int, str], None]


def iter_fs(root: Path, *, follow_symlinks: bool = False) -> Iterator[tuple[str, Path, os.stat_result, str]]:
    """Yield (rel_posix, abs_path, stat_result, kind) in deterministic order."""
    stack = [Path(root)]
    seen_inodes: set[int] = set()
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
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
            is_link = entry.is_symlink()
            is_dir = entry.is_dir(follow_symlinks=follow_symlinks)
            if is_link and not (follow_symlinks and is_dir):
                yield rel, abs_path, st, "symlink"
            elif is_dir:
                # Cycle guard for symlinked dirs (junction loops, etc.)
                if is_link and st.st_ino in seen_inodes:
                    yield rel, abs_path, st, "symlink"
                    continue
                if is_link:
                    seen_inodes.add(st.st_ino)
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
) -> tuple[FileRecord, str | None]:
    """(record, atime_mode) — "o_noatime"/"restored" mean the recorded
    atime still reflects real access history; "none" means our own read
    may have advanced it, so later atime diffs are unreliable."""
    if st is None:
        return (
            FileRecord(rel, 0, 0, 0, 0, None, "error", "stat_error"),
            None,
        )
    if kind != "file" or not hash_files:
        return (
            FileRecord(
                rel, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                st.st_atime_ns, None, kind, "ok",
            ),
            None,
        )
    try:
        digest, atime_mode = sha256_file_preserve(
            abs_path,
            max_bytes=max_hash_bytes,
            restore_ns=(st.st_atime_ns, st.st_mtime_ns),
        )
    except OSError:
        return (
            FileRecord(
                rel, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                st.st_atime_ns, None, kind, "read_error",
            ),
            "none",
        )
    # Re-stat AFTER hash+restore: on Windows the restore is lossless
    # (ctime = creation time, untouched by utime); on POSIX without
    # O_NOATIME the restore bumps ctime — recording the post-hash stat
    # keeps the record self-consistent with what's on disk.
    try:
        st = os.stat(abs_path, follow_symlinks=False)
    except OSError:
        pass
    status = "ok" if digest is not None else "hash_skipped_oversize"
    return (
        FileRecord(
            rel, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_atime_ns, digest, kind, status,
        ),
        atime_mode,
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
    inv.clear_files()  # reused db must not keep stale paths
    counts = {"file": 0, "dir": 0, "symlink": 0, "other": 0, "error": 0}
    status_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    seen = 0
    for rel, abs_path, st, kind in iter_fs(root, follow_symlinks=follow_symlinks):
        rec, atime_mode = record_for(
            rel, abs_path, st, kind,
            hash_files=hash_files, max_hash_bytes=max_hash_bytes,
        )
        if atime_mode is not None:
            mode_counts[atime_mode] = mode_counts.get(atime_mode, 0) + 1
        inv.upsert(rec)
        counts[kind] = counts.get(kind, 0) + 1
        status_counts[rec.status] = status_counts.get(rec.status, 0) + 1
        seen += 1
        if progress and seen % 2000 == 0:
            progress(seen, rel)
    if not hash_files or not mode_counts:
        atime_mode = "n/a"
    elif set(mode_counts) == {"o_noatime"}:
        atime_mode = "o_noatime"
    elif set(mode_counts) == {"restored"}:
        atime_mode = "restored"
    elif "o_noatime" not in mode_counts and "restored" not in mode_counts:
        atime_mode = "none"
    else:
        atime_mode = "mixed"
    inv.set_meta("tool", TOOL_NAME)
    inv.set_meta("tool_version", TOOL_VERSION)
    inv.set_meta("root", str(root))
    inv.set_meta("created_utc", utc_now_iso())
    inv.set_meta("hash_files", hash_files)
    inv.set_meta("atime_preservation", atime_mode)
    inv.set_meta("counts", counts)
    inv.set_meta("status_counts", status_counts)
    inv.commit()
    return {"entries": seen, "counts": counts, "status_counts": status_counts,
            "atime_preservation": atime_mode}
