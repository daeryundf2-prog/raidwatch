"""Shared helpers: hashing, timestamps, deterministic output writers."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "raidwatch"
TOOL_VERSION = "0.3.0"
_CHUNK = 1024 * 1024


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ns_to_iso(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat(
        timespec="seconds"
    )


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
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if max_bytes is not None and total >= max_bytes:
                return None
    return digest.hexdigest()


def write_json(path: Path, payload) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def write_manifest(out_dir: Path, command: str, extra: dict) -> Path:
    payload = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "command": command,
        "finished_utc": utc_now_iso(),
        **extra,
    }
    return write_json(out_dir / "manifest.json", payload)
