"""Snapshot-polling watcher for pre-installed raid monitoring.

Records filesystem change events (created/modified/removed) to an
append-only JSONL log. Portable fallback for the USN/Sysmon-based
monitor planned for Windows; its own termination is also logged.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .common import (
    TOOL_NAME,
    TOOL_VERSION,
    append_jsonl,
    sha256_file,
    utc_now_iso,
    write_json,
    write_manifest,
)
from .inventory import iter_fs

STATE_NAME = "watch-state.json"
EVENTS_NAME = "events.jsonl"


def snapshot_fs(root: Path, *, hash_changes: bool = False) -> dict:
    """Lightweight stat-only snapshot: {rel: {size, mtime_ns, kind}}."""
    snap = {}
    for rel, _abs, st, kind in iter_fs(root):
        if st is None:
            continue
        snap[rel] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "kind": kind}
    return snap


def _diff_snap(prev: dict, cur: dict) -> list[dict]:
    events = []
    for path in sorted(set(prev) | set(cur)):
        before, after = prev.get(path), cur.get(path)
        if before is None:
            events.append({"event": "created", "path": path, "detail": after})
        elif after is None:
            events.append({"event": "removed", "path": path, "detail": before})
        elif before["size"] != after["size"] or before["mtime_ns"] != after["mtime_ns"]:
            events.append(
                {"event": "modified", "path": path, "detail": {"before": before, "after": after}}
            )
    return events


def _load_state(path: Path) -> dict | None:
    import json

    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def run_watch(
    root: Path,
    out_dir: Path,
    *,
    interval: float = 5.0,
    once: bool = False,
    max_passes: int | None = None,
) -> dict:
    """Poll root and append change events to events.jsonl.

    `once` runs a single pass (useful for scheduled/diff use); otherwise
    loops until interrupted, logging `watcher_stopped` on termination.
    """
    root = root.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    events_path = out_dir / EVENTS_NAME
    state_path = out_dir / STATE_NAME
    started = utc_now_iso()

    append_jsonl(
        events_path,
        {
            "ts": started,
            "event": "session_start",
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "pid": os.getpid(),
            "root": str(root),
            "interval_s": interval,
        },
    )

    passes = 0
    try:
        while True:
            prev_state = _load_state(state_path)
            prev = (prev_state or {}).get("files") or {}
            cur = snapshot_fs(root)
            ts = utc_now_iso()
            if prev_state is None:
                append_jsonl(
                    events_path,
                    {"ts": ts, "event": "snapshot_init", "entries": len(cur)},
                )
            else:
                for ev in _diff_snap(prev, cur):
                    ev["ts"] = ts
                    append_jsonl(events_path, ev)
            write_json(state_path, {"ts": ts, "root": str(root), "files": cur})
            passes += 1
            if once or (max_passes is not None and passes >= max_passes):
                append_jsonl(events_path, {"ts": utc_now_iso(), "event": "pass_complete", "pass": passes})
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        append_jsonl(
            events_path,
            {"ts": utc_now_iso(), "event": "watcher_stopped", "reason": "interrupted"},
        )

    write_manifest(
        out_dir,
        "watch",
        {"root": str(root), "started_utc": started, "passes": passes},
    )
    return {"passes": passes, "events_log": str(events_path)}
