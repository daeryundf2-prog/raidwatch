"""Container sniff (`raidwatch containers`) — hash THEIR evidence file.

Investigators export their seized set into a forensic container on
their own external drive: FTK's .ad1, EnCase .e01/.ex01/.l01, Guymager
.aff/.m01, plain .zip/.7z. The defense usually gets a printed list and
never sees that file's hash — which means a swapped or rebuilt
container is undetectable.

While the machine (or their drive) is reachable, this scans removable
media and recently-created container files anywhere, and records
name + size + mtime + SHA-256. If the hash logged during the raid
differs from what later appears in court, the evidence is impeached.

Runs one-shot (repeatable) and inside the field pipeline. Non-Windows
looks under /Volumes, /media, /mnt.
"""

from __future__ import annotations

import platform
import re
import string
from datetime import datetime, timezone
from pathlib import Path

from .common import ns_to_iso, sha256_file, utc_now_iso, write_json, write_manifest

CONTAINER_EXTS = {
    ".ad1", ".e01", ".ex01", ".l01", ".lx01", ".s01",
    ".aff", ".afd", ".afm", ".m01",
    ".zip", ".7z", ".rar", ".tar", ".gz",
    ".dd", ".img", ".raw", ".001",
    ".vhd", ".vhdx", ".ufd",
}

# Hashing a 2TB .e01 takes hours — beyond this cap we record
# name/size/mtime without the digest and mark it hash_skipped, which
# is still impeachment evidence (and the operator can rerun with a
# higher cap).
DEFAULT_MAX_HASH_GB = 128


def _removable_roots() -> list[Path]:
    """Mounted removable/external volumes."""
    roots: list[Path] = []
    if platform.system() == "Windows":
        try:
            import ctypes

            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(drive) == 2:
                    roots.append(Path(drive))
        except (AttributeError, OSError):
            pass
    else:
        for base in ("/Volumes", "/media", "/mnt"):
            b = Path(base)
            if not b.is_dir():
                continue
            for p in b.iterdir():
                if not p.is_dir():
                    continue
                try:
                    if p.resolve() == Path("/"):
                        continue  # macOS /Volumes lists the boot volume
                except OSError:
                    continue
                roots.append(p)
    return roots


_MAX_ENTRIES = 200_000  # per-volume dir-entry cap — bounded runtime


def _scan_root(root: Path, out: list, seen: set, since_ns: int | None,
               errors: list, depth_cap: int = 12) -> None:
    """Walk a volume for container files (bounded depth + entry cap,
    quiet on permission errors — investigators' drives are often
    locked down)."""
    stack = [(root, 0)]
    visited = 0
    # Junction/mount-point loops: is_symlink() misses junctions and
    # they report st_ino=0 — dedup by resolved path instead.
    seen_dirs: set[Path] = {root.resolve()}
    while stack and visited < _MAX_ENTRIES:
        d, depth = stack.pop()
        if depth > depth_cap:
            continue
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        visited += len(entries)
        for p in entries:
            try:
                if p.is_dir() and not p.is_symlink():
                    rp = p.resolve()
                    if rp in seen_dirs:
                        continue
                    seen_dirs.add(rp)
                    stack.append((p, depth + 1))
                elif p.suffix.lower() in CONTAINER_EXTS:
                    key = str(p)
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        st = p.stat()
                    except OSError:
                        continue
                    if since_ns is not None and st.st_mtime_ns < since_ns:
                        continue
                    out.append((p, st))
            except OSError as exc:
                errors.append(f"{p}: {exc}")


def sniff_containers(
    out_dir: Path,
    *,
    since_ns: int | None = None,
    extra_roots: list[Path] | None = None,
    hash_files: bool = True,
    max_hash_gb: float = DEFAULT_MAX_HASH_GB,
) -> dict:
    """Scan external media for investigator evidence containers."""
    out_dir = Path(out_dir).resolve()
    roots = _removable_roots()
    if extra_roots:
        roots.extend(Path(r) for r in extra_roots)
    found, errors = [], []
    seen: set = set()
    for r in roots:
        _scan_root(r, found, seen, since_ns, errors)

    cap = int(max_hash_gb * 1024**3) if max_hash_gb else None
    items = []
    for p, st in sorted(found, key=lambda t: str(t[0])):
        entry = {
            "path": str(p),
            "volume_root": str(p.anchor),
            "size": st.st_size,
            "mtime_utc": ns_to_iso(st.st_mtime_ns),
        }
        if hash_files and cap is not None and st.st_size > cap:
            entry["sha256"] = None
            entry["hash_skipped"] = (
                f"exceeds {max_hash_gb:g}GiB cap — name/size/mtime "
                "recorded; rerun with --max-hash-gb 0 to hash anyway"
            )
        elif hash_files:
            try:
                entry["sha256"] = sha256_file(p)
            except OSError as exc:
                entry["sha256"] = None
                entry["hash_error"] = str(exc)
        items.append(entry)

    summary = {
        "volumes_scanned": len(roots),
        "containers_found": len(items),
        "hashed": sum(1 for i in items if i.get("sha256")),
        "hash_skipped_large": sum(
            1 for i in items if i.get("hash_skipped")),
        "errors": len(errors),
    }
    report = {
        "generated_utc": utc_now_iso(),
        "volumes": [str(r) for r in roots],
        "summary": summary,
        "containers": items,
        "errors": errors[:200],
        "note": (
            "These are evidence containers created during the raid "
            "window — probably on the investigators' own media. Keep "
            "this list: if a container presented later has a different "
            "SHA-256 than logged here, it is not the same file."
        ),
    }
    write_json(out_dir / "containers.json", report)
    write_manifest(out_dir, "containers", {"summary": summary})
    return report
