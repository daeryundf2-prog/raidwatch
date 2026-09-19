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

import json
import shutil
import zipfile
from pathlib import Path

from .artifacts import collect_artifacts
from .common import sha256_file, utc_now_iso, write_json, write_manifest
from .db import Inventory
from .diff import run_diff
from .inventory import build_inventory
from .profile import ProfileError, load_profile
from .scan import run_scan
from .sources import collect_sources
from .verify import run_verify

RESULTS_ZIP = "raidwatch-results.zip"
SUMS_NAME = "SHA256SUMS.txt"


def _find_inputs(inputs_dir: Path) -> dict:
    """Locate optional inputs carried by the kit."""
    found: dict[str, Path | None] = {
        "profile": None, "seized": None, "baseline": None,
    }
    if not inputs_dir.is_dir():
        return found
    for p in sorted(inputs_dir.iterdir()):
        low = p.name.lower()
        if found["profile"] is None and low.startswith("profile") and p.suffix == ".json":
            found["profile"] = p
        elif found["seized"] is None and low.startswith("seized"):
            found["seized"] = p
        elif found["baseline"] is None and low.startswith("baseline") and p.suffix == ".db":
            found["baseline"] = p
    return found


def run_field(
    root: Path,
    inputs_dir: Path,
    out_dir: Path,
    *,
    hash_files: bool = True,
) -> dict:
    """Run every applicable raidwatch step against root.

    Returns the step report; side effects are confined to out_dir, which
    afterwards contains per-step outputs plus raidwatch-results.zip and
    SHA256SUMS.txt.
    """
    root = root.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    steps_dir = out_dir / "steps"
    inputs = _find_inputs(inputs_dir)
    steps: list[dict] = []

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

    # Always-on reconstruction: no inputs required.
    _run("sources", lambda: collect_sources(root, steps_dir / "sources"))
    _run("artifacts", lambda: collect_artifacts(root, steps_dir / "artifacts"))

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
            build_inventory(root, inv, hash_files=hash_files)
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

    report = {
        "root": str(root),
        "generated_utc": utc_now_iso(),
        "inputs_found": {k: str(v) if v else None for k, v in inputs.items()},
        "steps": steps,
        "results_zip": str(archive_path),
        "results_zip_sha256": sha256_file(archive_path),
        "sums_file": str(sums_path),
        "note": (
            "Archive contains raidwatch analysis outputs and preserved "
            "evidence copies only — never a bulk dump of the disk. Verify "
            "integrity with SHA256SUMS.txt after transport."
        ),
    }
    write_json(out_dir / "field.json", report)
    write_manifest(out_dir, "field", {"steps": steps})
    return report
