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
from .leftover import run_leftovers
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

# Output transport: Gmail's attachment limit is ~25 MB — a monolithic
# results zip over _SPLIT_THRESHOLD is split into _PART_SIZE chunks so
# each part fits one email attachment (20 MiB leaves headroom for
# base64 inflation).
_SPLIT_THRESHOLD = 2 * 1024**3   # 2 GiB
_PART_SIZE = 20 * 1024**2        # 20 MiB — under Gmail's 25MB
PARTS_DIR = "raidwatch-results-parts"

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


def _maybe_split_archive(
    archive_path: Path, out_dir: Path, zip_sha256: str
) -> dict | None:
    """Split an oversized results zip into email-sized parts.

    Returns a parts info dict, or None when the zip is small enough to
    send as one file. Parts land in out_dir/raidwatch-results-parts/
    with a one-click JOIN.bat, a join.sh, per-part SHA256SUMS and a
    README; the monolithic zip is deleted afterwards — the parts ARE
    the zip bytes, and custody.txt already sealed the whole-zip hash.
    """
    try:
        size = archive_path.stat().st_size
    except OSError:
        return None
    if size <= _SPLIT_THRESHOLD:
        return None

    parts_dir = out_dir / PARTS_DIR
    parts_dir.mkdir(parents=True, exist_ok=True)
    parts: list[dict] = []
    idx = 0
    with archive_path.open("rb") as src:
        while True:
            chunk = src.read(_PART_SIZE)
            if not chunk:
                break
            idx += 1
            name = f"{RESULTS_ZIP}.{idx:03d}"
            (parts_dir / name).write_bytes(chunk)
            parts.append(
                {"name": name, "size": len(chunk),
                 "sha256": hashlib.sha256(chunk).hexdigest()}
            )
    # One stream, one read — per-part hashes plus the whole-zip hash
    # already computed by the caller.
    sums = "".join(f"{p['sha256']}  {p['name']}\n" for p in parts)
    (parts_dir / "SHA256SUMS-parts.txt").write_text(
        f"# per-part sha256 — whole-zip sha256: {zip_sha256}\n" + sums,
        encoding="utf-8",
    )
    # One-click receiver tool: no install needed — only Windows
    # built-ins (copy, certutil, findstr, powershell for the popup).
    # Double-click → reassemble → per-part verify → seal-hash compare
    # → OK/FAIL message box.
    (parts_dir / "JOIN.bat").write_text(
        "@echo off\r\n"
        "chcp 65001 >nul 2>&1\r\n"
        "cd /d \"%~dp0\"\r\n"
        "setlocal enabledelayedexpansion\r\n"
        f"set \"OUT={RESULTS_ZIP}\"\r\n"
        f"set \"WANT={zip_sha256}\"\r\n"
        "echo ==========================================================\r\n"
        "echo   raidwatch 결과 복원 + 검증  (설치 불필요)\r\n"
        "echo   이 폴더에 조각 파일(.001 .002 ...)이 모두 있어야 합니다\r\n"
        "echo ==========================================================\r\n"
        "echo.\r\n"
        "set \"LIST=\"\r\n"
        "for /f \"delims=\" %%f in ('dir /b /on \"%OUT%.???\" 2^>nul') do "
        "set \"LIST=!LIST!+\"%%f\"\"\r\n"
        "if not defined LIST (\r\n"
        "  echo [오류] %OUT%.001 형식의 조각 파일이 없습니다.\r\n"
        "  echo        조각 파일들을 이 폴더에 모두 넣고 다시 실행하세요.\r\n"
        "  goto :end\r\n"
        ")\r\n"
        "set \"LIST=!LIST:~1!\"\r\n"
        "if exist \"%OUT%\" del /f /q \"%OUT%\"\r\n"
        "copy /b %LIST% \"%OUT%\" >nul\r\n"
        "echo [1/3] 조각 복원 완료 -^> %OUT%\r\n"
        "set \"BAD=\"\r\n"
        "if exist SHA256SUMS-parts.txt (\r\n"
        "  for /f \"tokens=1,2\" %%a in (SHA256SUMS-parts.txt) do (\r\n"
        "    echo(%%a | findstr /r \"^[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]\" >nul\r\n"
        "    if not errorlevel 1 (\r\n"
        "      if exist \"%%b\" (\r\n"
        "        set \"PH=\"\r\n"
        "        for /f \"delims=\" %%h in ('certutil -hashfile \"%%b\" SHA256 ^| findstr /v /c:\":\"') do set \"PH=%%h\"\r\n"
        "        set \"PH=!PH: =!\"\r\n"
        "        if /i not \"!PH!\"==\"%%a\" set \"BAD=!BAD! %%b\"\r\n"
        "      ) else set \"BAD=!BAD! %%b(없음)\"\r\n"
        "    )\r\n"
        "  )\r\n"
        "  echo [2/3] 조각별 해시 검증 완료\r\n"
        ") else echo [2/3] SHA256SUMS-parts.txt 없음 - 조각별 검증 생략\r\n"
        "set \"GOT=\"\r\n"
        "for /f \"delims=\" %%h in ('certutil -hashfile \"%OUT%\" SHA256 ^| findstr /v /c:\":\"') do set \"GOT=%%h\"\r\n"
        "set \"GOT=!GOT: =!\"\r\n"
        "echo [3/3] 복원 해시: %GOT%\r\n"
        "echo        봉인 해시: %WANT%\r\n"
        "echo.\r\n"
        "if /i \"%GOT%\"==\"%WANT%\" (\r\n"
        "  echo [성공] 해시 일치 — 현장에서 봉인된 결과물과 동일합니다.\r\n"
        "  powershell -NoProfile -Command \"Add-Type -AssemblyName System.Windows.Forms;[void][System.Windows.Forms.MessageBox]::Show('복원 완료 — 해시가 현장 봉인값과 일치합니다.','raidwatch',0,64)\" >nul 2>&1\r\n"
        ") else (\r\n"
        "  echo [실패] 해시 불일치 — 조각이 빠졌거나 손상/변조됐습니다.\r\n"
        "  if defined BAD (\r\n"
        "    echo       다시 받아야 할 조각:%BAD%\r\n"
        "  ) else (\r\n"
        "    echo       SHA256SUMS-parts.txt가 없어 어느 조각인지 알 수 없습니다.\r\n"
        "    echo       보낸 사람에게 전체 재전송을 요청하세요.\r\n"
        "  )\r\n"
        "  powershell -NoProfile -Command \"Add-Type -AssemblyName System.Windows.Forms;[void][System.Windows.Forms.MessageBox]::Show('해시 불일치 — 검은 창의 안내를 확인하세요.','raidwatch',0,16)\" >nul 2>&1\r\n"
        ")\r\n"
        ":end\r\n"
        "echo.\r\n"
        "pause\r\n",
        encoding="utf-8",
    )
    (parts_dir / "join.sh").write_text(
        "#!/bin/sh\n"
        "cd \"$(dirname \"$0\")\"\n"
        f"OUT={RESULTS_ZIP}\n"
        f"WANT={zip_sha256}\n"
        "ls \"$OUT\".??? >/dev/null 2>&1 || "
        "{ echo \"[오류] $OUT.001 형식의 조각이 없습니다.\"; exit 1; }\n"
        "cat \"$OUT\".??? > \"$OUT\"\n"
        "echo \"[1/2] 복원 완료 -> $OUT\"\n"
        "GOT=$(sha256sum \"$OUT\" 2>/dev/null | awk '{print $1}')\n"
        "[ -z \"$GOT\" ] && GOT=$(shasum -a 256 \"$OUT\" | awk '{print $1}')\n"
        "echo \"복원 해시: $GOT\"\n"
        "echo \"봉인 해시: $WANT\"\n"
        "if [ \"$GOT\" = \"$WANT\" ]; then\n"
        "  echo \"[성공] 해시 일치 — 현장 봉인 결과물과 동일합니다.\"\n"
        "else\n"
        "  echo \"[실패] 해시 불일치 — 조각 누락/손상/변조. 다시 받으세요.\"\n"
        "  exit 1\n"
        "fi\n",
        encoding="utf-8",
    )
    (parts_dir / "README-parts.txt").write_text(
        "분할 압축 안내 / split archive\n"
        "=============================\n"
        f"결과물이 2GB를 넘어 이메일 첨부 단위(20MB)로 분할했습니다.\n"
        f"총 {len(parts)}개 조각입니다.\n\n"
        "보내는 쪽: 이 폴더의 .001 .002 ... 파일들을 이메일에 나눠 첨부\n"
        "           (한 통에 1~2개씩). SHA256SUMS-parts.txt 와 JOIN.bat\n"
        "           도 같이 보내 주세요 (작은 파일이라 한 통에 들어감).\n"
        "받는 쪽:   아무것도 설치할 필요 없습니다. 조각 파일 + JOIN.bat\n"
        "           + SHA256SUMS-parts.txt 를 전부 한 폴더에 모으고\n"
        "           JOIN.bat 을 더블클릭하면 복원→조각별 검증→봉인 해시\n"
        "           대조→성공/실패 팝업까지 자동으로 진행됩니다.\n"
        "           (mac/linux 은 join.sh 실행)\n\n"
        f"whole-zip sha256: {zip_sha256}\n",
        encoding="utf-8",
    )
    archive_path.unlink()  # parts carry the same bytes — save disk
    return {
        "parts_dir": str(parts_dir),
        "count": len(parts),
        "part_bytes": _PART_SIZE,
        "total_bytes": size,
        "whole_zip_sha256": zip_sha256,
        "parts": parts,
        "join": ["JOIN.bat", "join.sh"],
        "note": (
            "zip exceeded 2GiB → split into Gmail-attachment-sized "
            "parts; reassemble with JOIN.bat/join.sh then verify "
            "against whole_zip_sha256. custody.txt already sealed this "
            "hash before splitting."
        ),
    }


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

    # Investigators' own work product left behind: their itemized
    # list PDF / export archive created in the raid window, recycle
    # bin entries, and signature files the journal saw being deleted.
    # Finding these beats OCR — it IS their authoritative output.
    if since_ns is not None:
        _run(
            "leftovers",
            lambda: run_leftovers(
                [root], steps_dir / "leftovers",
                since_ns=since_ns,
                journal=steps_dir / "journal" / "journal.json",
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
    zip_sha256 = sha256_file(archive_path)
    parts_info = _maybe_split_archive(archive_path, out_dir, zip_sha256)

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
        f"zip_sha256:  {zip_sha256}\n"
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
            "results_zip": (
                str(archive_path)
                if archive_path.exists()
                else f"{archive_path} (split into parts)"
            ),
            "results_zip_sha256": zip_sha256,
            "results_zip_parts": parts_info,
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
