"""Field run — the pipeline that executes inside a deployed kit.

A bundle dropped on the client's machine carries whatever inputs the
case has (warrant profile, seized list, baseline db). This module
detects which inputs are present, runs every applicable raidwatch step
against the local disk, and packs *only the analysis outputs* into a
results archive with a SHA-256 manifest for transport integrity.

Design contract:
- outputs go under out_dir only — nothing is written elsewhere
- the archive contains raidwatch reports and deliberately-preserved
  evidence copies, never a bulk dump of the disk
- every step failure is recorded, not fatal — a field run must return
  partial results rather than die on one bad input
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .artifacts import collect_artifacts
from .audit import run_keyword_audit
from .boundary import run_boundary
from .common import sha256_file, utc_now_iso, write_json, write_manifest
from .containers import sniff_containers
from .window import scan_window
from .db import Inventory
from .diff import run_diff
from .inventory import build_inventory
from .journal import replay_journal
from .lockbox import run_lockbox
from .mobile import collect_mobile
from .profile import ProfileError, load_profile
from .scan import run_scan
from .sources import collect_sources
from .verify import run_verify
from .vss import is_admin

RESULTS_ZIP = "raidwatch-results.zip"
SUMS_NAME = "SHA256SUMS.txt"

_DT_RE = re.compile(
    r"(\d{4})\D{0,3}(\d{1,2})\D{0,3}(\d{1,2})"
    r"(?:\D{0,5}(\d{1,2})\D{0,3}(\d{1,2}))?"
)


def _parse_dt_lenient(text: str) -> int | None:
    """Parse a user-typed raid datetime → epoch ns (LOCAL time of the
    machine the kit runs on). Accepts ISO-ish, 2026.9.19, 2026/9/19,
    and Korean-style '2026년 9월 19일 오후 2시 30분'. None if unclear."""
    t = text.strip()
    if not t:
        return None
    pm = bool(re.search(r"오후|pm|PM", t))
    m = _DT_RE.search(t)
    if m is None:
        return None
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hour = int(m.group(4)) if m.group(4) else 0
    minute = int(m.group(5)) if m.group(5) else 0
    if pm and hour < 12:
        hour += 12
    try:
        dt = datetime(year, month, day, hour, minute).astimezone()
    except ValueError:
        return None
    return int(dt.timestamp() * 1_000_000_000)


def _read_seizure_info(path: Path | None) -> dict:
    """Read the kit's seizure-info file (info.json preferred, info.txt
    written by RUN.bat/RUN.sh prompts). Tolerant of anything the user
    typed — raw text is always preserved."""
    info: dict = {
        "raid_datetime": None, "raid_dt_ns": None, "notes": None,
        "raw": None, "source": None,
    }
    if path is None:
        return info
    info["source"] = str(path)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return info
    info["raw"] = raw.strip()
    dt_text = notes = None
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                dt_text = str(data.get("raid_datetime") or "")
                notes = data.get("notes") or data.get("memo")
        except (ValueError, TypeError):
            dt_text = raw  # not real JSON — treat whole text as input
    else:
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        labeled = {}
        for ln in lines:
            m = re.match(r"(datetime|notes|memo|case)\s*:\s*(.*)", ln, re.I)
            if m:
                labeled[m.group(1).lower()] = m.group(2).strip()
        if labeled:
            dt_text = labeled.get("datetime")
            notes = labeled.get("notes") or labeled.get("memo") or labeled.get("case")
        elif lines:
            dt_text, notes = lines[0], "\n".join(lines[1:]) or None
        dt_text = dt_text or None
    info["raid_datetime"] = dt_text
    info["raid_dt_ns"] = _parse_dt_lenient(dt_text) if dt_text else None
    info["notes"] = notes
    return info


def _find_inputs(inputs_dir: Path) -> dict:
    """Locate optional inputs carried by the kit."""
    found: dict[str, Path | None] = {
        "profile": None, "seized": None, "baseline": None, "info": None,
    }
    if not inputs_dir.is_dir():
        return found
    for p in sorted(inputs_dir.iterdir()):
        low = p.name.lower()
        if found["profile"] is None and low.startswith("profile") and p.suffix == ".json":
            found["profile"] = p
        elif low.startswith("seized"):
            # Prefer text/OCR'd formats over the raw PDF source — a
            # seized.pdf kept beside a seized-ocr.txt stays as the
            # preserved original while the text drives verification.
            cur = found["seized"]
            if cur is None or (cur.suffix.lower() == ".pdf" and p.suffix.lower() != ".pdf"):
                found["seized"] = p
        elif found["baseline"] is None and low.startswith("baseline") and p.suffix == ".db":
            found["baseline"] = p
        elif low.startswith("info") and p.suffix in (".json", ".txt"):
            if found["info"] is None or p.suffix == ".json":
                found["info"] = p
    return found


def run_field(
    root: Path,
    inputs_dir: Path,
    out_dir: Path,
    *,
    hash_files: bool = True,
    since_ns: int | None = None,
    use_vss: bool = False,
) -> dict:
    """Run every applicable raidwatch step against root.

    Returns the step report; side effects are confined to out_dir, which
    afterwards contains per-step outputs plus raidwatch-results.zip and
    SHA256SUMS.txt. An explicit `since_ns` overrides any raid datetime
    the user typed into inputs/info.*.
    """
    root = root.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    steps_dir = out_dir / "steps"
    inputs = _find_inputs(inputs_dir)
    steps: list[dict] = []

    info = _read_seizure_info(inputs["info"])
    if since_ns is None:
        since_ns = info["raid_dt_ns"]

    def _run(name: str, fn) -> dict:
        try:
            fn()
            steps.append({"step": name, "status": "ok"})
            return {"status": "ok"}
        except Exception as exc:  # field runs must not die mid-pipeline
            steps.append(
                {"step": name, "status": "error", "error": f"{type(exc).__name__}: {exc}"}
            )
            return {"status": "error"}

    # Always-on reconstruction: no inputs required. The raid datetime
    # narrows temp-dir candidates to files touched after the seizure.
    _run(
        "sources",
        lambda: collect_sources(root, steps_dir / "sources", since_ns=since_ns),
    )
    _run(
        "artifacts",
        lambda: collect_artifacts(
            root, steps_dir / "artifacts", since_ns=since_ns,
            use_vss=use_vss,
        ),
    )

    # USN journal replay: Windows only, fsutil needs elevation. Locked
    # hives/EVTX are already covered by the artifacts shadow fallback;
    # the journal adds per-file create/delete/rename history.
    if platform.system() == "Windows":
        drive = str(root)[:2] if len(str(root)) >= 2 and str(root)[1] == ":" else "C:"
        if is_admin():
            _run(
                "journal",
                lambda: replay_journal(
                    steps_dir / "journal", volume=drive, since_ns=since_ns
                ),
            )
        else:
            steps.append(
                {"step": "journal", "status": "skipped",
                 "reason": "fsutil requires Administrator"}
            )

    # PC-resident mobile data (KakaoTalk DB, iTunes/SmartSwitch backups)
    # — preserved before investigators touch the machine.
    _run(
        "mobile",
        lambda: collect_mobile(root, steps_dir / "mobile"),
    )

    # BitLocker recovery keys while the machine is still on — Windows
    # only; per-volume failures (needs admin) are recorded, not fatal.
    if platform.system() == "Windows":
        _run(
            "lockbox",
            lambda: run_lockbox(root, steps_dir / "lockbox"),
        )

    # Investigators' evidence containers (.ad1/.e01/.zip…) on attached
    # external media — hash them while their drive is still plugged in.
    _run(
        "containers",
        lambda: sniff_containers(
            steps_dir / "containers", since_ns=since_ns
        ),
    )

    # Raid-window file activity: with only a date and no baseline this
    # is THE deliverable — every file created/modified/accessed since
    # the seizure time (metadata-only walk). A baseline+diff subsumes
    # it, so it is skipped when one is present.
    if since_ns is not None and not inputs["baseline"]:
        _run(
            "window",
            lambda: scan_window(
                root, steps_dir / "window", since_ns=since_ns,
                progress=lambda n, h: print(
                    f"  window: {n} scanned, {h} hits", flush=True),
            ),
        )

    profile = None
    if inputs["profile"]:
        try:
            profile = load_profile(inputs["profile"])
        except ProfileError as exc:
            steps.append({"step": "profile_load", "status": "error", "error": str(exc)})
    if profile is not None:
        _run("scan", lambda: run_scan(root, profile, steps_dir / "scan"))

    # Baseline-dependent steps reuse one inventory build.
    inv = None
    inv_tmp = steps_dir / "_field_inventory.db"
    if inputs["seized"] or inputs["baseline"]:
        def _build() -> None:
            nonlocal inv
            inv = Inventory(inv_tmp, create=True)
            build_inventory(
                root, inv, hash_files=hash_files,
                progress=lambda n, p: print(
                    f"  inventory: {n} entries ({p})", flush=True),
            )
        _run("inventory", _build)

    if inputs["baseline"] and inv is not None:
        _run(
            "diff",
            lambda: run_diff(
                Path(inputs["baseline"]), inv_tmp, steps_dir / "diff"
            ),
        )
    if inputs["seized"] and inv is not None:
        _run(
            "verify",
            lambda: run_verify(
                Path(inputs["seized"]),
                inv,
                steps_dir / "verify",
                profile=profile,
                current_root=root,
            ),
        )
    if inv is not None:
        inv.close()

    # Territory check needs only the list; keyword audit needs list +
    # profile. Both feed petition evidence automatically.
    if inputs["seized"]:
        _run(
            "boundary",
            lambda: run_boundary(
                Path(inputs["seized"]), None, steps_dir / "boundary"
            ),
        )
        if profile is not None:
            _run(
                "keyword-audit",
                lambda: run_keyword_audit(
                    Path(inputs["seized"]), profile, root,
                    steps_dir / "keyword-audit",
                ),
            )

    # Write the run report inside steps/ so the archive itself carries
    # the seizure info and step outcomes (not just files beside it).
    report = {
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "inputs_found": {k: str(v) if v else None for k, v in inputs.items()},
        "seizure_info": {
            "raid_datetime": info["raid_datetime"],
            "raid_datetime_utc": (
                datetime.fromtimestamp(
                    info["raid_dt_ns"] / 1_000_000_000, tz=timezone.utc
                ).isoformat(timespec="seconds")
                if info["raid_dt_ns"] is not None
                else None
            ),
            "notes": info["notes"],
            "raw": info["raw"],
        },
        "sources_since_utc": (
            datetime.fromtimestamp(
                since_ns / 1_000_000_000, tz=timezone.utc
            ).isoformat(timespec="seconds")
            if since_ns is not None
            else None
        ),
        "steps": steps,
    }
    write_json(steps_dir / "field-report.json", report)

    # Results archive: every file the run produced, hashed.
    archive_path = out_dir / RESULTS_ZIP
    sums = []
    produced = sorted(
        p for p in steps_dir.rglob("*")
        if p.is_file() and p.name != "_field_inventory.db"
    )
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in produced:
            rel = p.relative_to(out_dir).as_posix()
            zf.write(p, rel)
            sums.append((sha256_file(p), rel))
    sums_path = out_dir / SUMS_NAME
    sums_path.write_text(
        "".join(f"{digest}  {rel}\n" for digest, rel in sums),
        encoding="utf-8",
    )

    # Custody seal: one hash covering the whole evidence set. Sending
    # this hash to counsel/notary *right now* anchors "these outputs
    # existed at this time" without any trusted infrastructure.
    root_hash = hashlib.sha256(
        "".join(digest for digest, _ in sums).encode("ascii")
    ).hexdigest()
    custody_path = out_dir / "custody.txt"
    custody_path.write_text(
        "raidwatch custody seal\n"
        "=====================\n"
        f"sealed_utc:  {utc_now_iso()}\n"
        f"zip_sha256:  {sha256_file(archive_path)}\n"
        f"root_hash:   {root_hash}\n"
        f"file_count:  {len(sums)}\n"
        "\n"
        "root_hash = sha256 of every per-file sha256 in SHA256SUMS.txt,\n"
        "concatenated in archive order. One hash seals the whole set.\n"
        "\n"
        "TO ANCHOR THIS EVIDENCE SET IN TIME:\n"
        "  - email THIS FILE (or just root_hash) to counsel / yourself now\n"
        "  - the sent timestamp becomes independent proof these outputs\n"
        "    existed at that moment; any later change breaks the hash\n"
        "  - stronger: paste root_hash into a public timestamp service\n"
        "    (e.g. an RFC3161 TSA or opentimestamps) for legal-grade proof\n",
        encoding="utf-8",
    )

    report.update(
        {
            "results_zip": str(archive_path),
            "results_zip_sha256": sha256_file(archive_path),
            "sums_file": str(sums_path),
            "custody_file": str(custody_path),
            "custody_root_hash": root_hash,
            "note": (
                "Archive contains raidwatch analysis outputs and preserved "
                "evidence copies only — never a bulk dump of the disk. Verify "
                "integrity with SHA256SUMS.txt after transport."
            ),
        }
    )
    write_json(out_dir / "field.json", report)
    write_manifest(out_dir, "field", {"steps": steps})
    return report
