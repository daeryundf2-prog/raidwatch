"""Join (`raidwatch join`) — receiver-side reassembly of split results.

The client emails the raidwatch-results-parts/ pieces back (Gmail
sized, one or two per mail). Counsel drops them all into one folder
and runs:

    raidwatch join <folder>

This concatenates the .001 .002 … parts in order into
raidwatch-results.zip, then verifies:

- every part's sha256 against SHA256SUMS-parts.txt when present
- the joined zip's sha256 against the whole-zip hash — the value
  custody.txt sealed at the scene (found via the parts manifest
  header or a custody.txt in the same folder)

A mismatch means a part is missing, duplicated, truncated in transit,
or tampered with — resend that part rather than trusting the zip.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .common import sha256_file, utc_now_iso, write_json

_PART_RE = re.compile(r"^(?P<base>.+\.zip)\.(?P<idx>\d{3,})$")
_HEADER_RE = re.compile(r"whole-zip sha256:\s*([0-9a-fA-F]{64})")


def _find_parts(parts_dir: Path) -> list[Path]:
    parts = []
    for p in parts_dir.iterdir():
        m = _PART_RE.match(p.name)
        if m and p.is_file():
            parts.append((int(m.group("idx")), p))
    return [p for _, p in sorted(parts)]


def _read_sums(path: Path) -> tuple[str | None, dict[str, str]]:
    """(whole_zip_sha256, {part_name: sha256}) from SHA256SUMS-parts.txt."""
    if not path.is_file():
        return None, {}
    whole, per_part = None, {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _HEADER_RE.search(line)
        if m:
            whole = m.group(1).lower()
            continue
        mm = re.match(r"([0-9a-fA-F]{64})\s+(\S+)", line.strip())
        if mm:
            per_part[mm.group(2)] = mm.group(1).lower()
    return whole, per_part


def _custody_hash(parts_dir: Path) -> str | None:
    for cand in (parts_dir / "custody.txt", parts_dir.parent / "custody.txt"):
        if cand.is_file():
            for line in cand.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if line.startswith("zip_sha256:"):
                    return line.split(":", 1)[1].strip().lower()
    return None


def run_join(
    parts_dir: Path,
    out_path: Path | None = None,
) -> dict:
    """Reassemble parts in parts_dir → raidwatch-results.zip."""
    parts_dir = Path(parts_dir).resolve()
    parts = _find_parts(parts_dir)
    if not parts:
        raise ValueError(
            f"no split parts (* .zip.NNN) found in {parts_dir}"
        )
    if out_path is None:
        out_path = parts_dir / parts[0].name.rsplit(".", 1)[0]
    out_path = Path(out_path)

    whole_expected, per_part = _read_sums(
        parts_dir / "SHA256SUMS-parts.txt"
    )
    if whole_expected is None:
        whole_expected = _custody_hash(parts_dir)

    part_reports = []
    h = hashlib.sha256()
    with out_path.open("wb") as dst:
        for p in parts:
            data = p.read_bytes()
            dst.write(data)
            h.update(data)
            digest = hashlib.sha256(data).hexdigest()
            expect = per_part.get(p.name)
            part_reports.append({
                "name": p.name,
                "size": len(data),
                "sha256": digest,
                "hash_match": (
                    True if expect == digest
                    else False if expect is not None
                    else None  # no record to compare against
                ),
            })
    joined_sha = h.hexdigest()
    part_fail = [r["name"] for r in part_reports if r["hash_match"] is False]

    verdict = (
        "ok"
        if whole_expected and joined_sha == whole_expected
        else "mismatch" if whole_expected
        else "unverifiable"
    )
    report = {
        "generated_utc": utc_now_iso(),
        "parts_dir": str(parts_dir),
        "output": str(out_path),
        "summary": {
            "parts": len(parts),
            "bytes": out_path.stat().st_size,
            "joined_sha256": joined_sha,
            "expected_sha256": whole_expected,
            "verdict": verdict,
            "bad_parts": part_fail,
        },
        "parts": part_reports,
        "note": (
            "ok = the reassembled zip matches the hash sealed at the "
            "scene — usable as the evidence archive. mismatch = a part "
            "is missing/corrupt/changed: check bad_parts and resend. "
            "unverifiable = no whole-zip hash was found to compare "
            "against (ask for custody.txt or SHA256SUMS-parts.txt)."
        ),
    }
    write_json(out_path.parent / "join-report.json", report)
    return report
