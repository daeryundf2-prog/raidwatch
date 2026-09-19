"""Shared helpers: hashing, timestamps, deterministic output writers."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "raidwatch"
TOOL_VERSION = "0.8.6"
_CHUNK = 1024 * 1024
_FILETIME_EPOCH_NS = 116444736000000000  # 1601-01-01 in 100ns units *100


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ns_to_iso(ns: int) -> str:
    try:
        return datetime.fromtimestamp(
            ns / 1_000_000_000, tz=timezone.utc
        ).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return f"invalid_ns:{ns}"  # never crash a scan on a bogus timestamp


def filetime_to_iso(value: int) -> str | None:
    """Windows FILETIME (100ns since 1601) → ISO; None for zero/invalid."""
    if value <= 0:
        return None
    try:
        ns = (value - _FILETIME_EPOCH_NS) * 100
        return ns_to_iso(ns)
    except (OverflowError, OSError, ValueError):
        return None


def iso_to_ns(value: str) -> int:
    text = value.strip()
    if len(text) == 10:
        text += "T00:00:00+00:00"
    elif text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path, max_bytes: int | None = None) -> str | None:
    """Stream-hash a file; returns None when it exceeds max_bytes."""
    digest, _ = sha256_file_preserve(path, max_bytes)
    return digest


def sha256_file_preserve(
    path: Path,
    max_bytes: int | None = None,
    *,
    restore_ns: tuple[int, int] | None = None,
) -> tuple[str | None, str]:
    """Hash a file without permanently advancing atime.

    Returns (digest, mode) where mode is:
    - "o_noatime": read with O_NOATIME — atime untouched (Linux)
    - "restored": read bumped atime; caller's (atime_ns, mtime_ns) pair
      was written back via utime afterwards — lossless on Windows where
      ctime is creation-time, but bumps ctime on POSIX
    - "none": read happened, atime may have advanced (no permission to
      restore) — atime diffs are unreliable
    - "skipped": file exceeded max_bytes before any meaningful read

    Callers diffing atime MUST gate on the mode or every hashed file
    looks "accessed".
    """
    import os

    digest = hashlib.sha256()
    total = 0
    noatime = getattr(os, "O_NOATIME", 0)
    mode = "none"
    try:
        fd = os.open(path, os.O_RDONLY | noatime)
        mode = "o_noatime" if noatime else "none"
    except OSError:
        fd = os.open(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                return None, "skipped"
    if mode == "none" and restore_ns is not None:
        try:
            os.utime(path, ns=restore_ns)
            mode = "restored"
        except OSError:
            pass
    return digest.hexdigest(), mode


def write_json(path: Path, payload) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)  # atomic — no torn manifest/state on crash
    return path


def append_jsonl(path: Path, record: dict) -> None:
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())  # evidence log survives power loss


def write_manifest(out_dir: Path, command: str, extra: dict) -> Path:
    payload = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "command": command,
        "finished_utc": utc_now_iso(),
        **extra,
    }
    return write_json(out_dir / "manifest.json", payload)
