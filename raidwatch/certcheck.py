"""Certificate audit (`raidwatch certcheck`) — check the 확인서 itself.

The 전자정보확인서 package an investigator hands over is itself evidence
of diligence: 서식1 certificate form + 상세목록 detail list (often a
scanned PDF) + a machine-readable .xlsx row list claiming 연번/파일명/
크기/경로/SHA1/생성·수정·접근일시 per seized file.

Before arguing scope, check the paper trail for internal defects:

- 연번 sequence — gaps/dups/restarts across the paged sheets mean rows
  were dropped, reordered, or merged after issuance
- hash sanity — a "SHA1" cell that isn't 40 hex can't be verified by
  anyone; that row's integrity claim is void
- name↔path consistency — basename(경로) ≠ 파일명 flags transcription
  or re-pathing errors in the list itself
- duplicate rows — same SHA1 or same path listed twice = padded or
  double-counted seizure (과잉 기재)
- timestamp sanity — 수정일시 AFTER the certificate timestamp means the
  list claims a file state that postdates its own issuance
- PDF↔xlsx cross-check — the printed 상세목록 should contain as many
  hash strings as the xlsx has rows; a shortfall means the printed and
  delivered lists diverge
- optional --root live re-verification — resolve each claimed path on a
  mirror/returned PC and compare size + claimed-algorithm hash

Everything is recorded as findings with counts — the tool never edits
the package it audits.
"""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path, PurePosixPath

from .common import (
    hash_file, iter_tree, sha256_file, utc_now_iso, write_json,
    write_manifest,
)
from .xlsx_read import iter_seized_rows

_HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_CERT_TS_RE = re.compile(r"(\d{14})")
_KO_DATE_RE = re.compile(
    r"(\d{4})[-./년]\s*(\d{1,2})[-./월]\s*(\d{1,2})[일]?\s+"
    r"(\d{1,2}):(\d{2})(?::(\d{2}))?"
)
_MAX_SAMPLE = 10  # rows sampled into each finding


def _members(package: Path) -> list[tuple[str, "bytes | Path"]]:
    """[(name, bytes|Path)] — zip members read lazily as bytes."""
    package = Path(package)
    if package.is_dir():
        return sorted(
            (str(p.relative_to(package)).replace("\\", "/"), p)
            for p in iter_tree(package)
        )
    if package.suffix.lower() in (".xlsx", ".pdf", ".csv", ".txt"):
        # a bare detail list / certificate — itself a member, not a
        # package container (xlsx is a zip internally!)
        return [(package.name, package)]
    if zipfile.is_zipfile(package):
        out = []
        with zipfile.ZipFile(package) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                data = zf.read(info.filename)
                out.append((info.filename, data))
                # nested archives (시스템정보.zip etc.) may hold the
                # detail list — peek one level for xlsx/pdf members
                if info.filename.lower().endswith(".zip"):
                    try:
                        inner = zipfile.ZipFile(io.BytesIO(data))
                    except zipfile.BadZipFile:
                        continue
                    for ii in inner.infolist():
                        ilow = ii.filename.lower()
                        if ii.is_dir() or not ilow.endswith(
                            (".xlsx", ".pdf")
                        ):
                            continue
                        out.append((
                            f"{info.filename}!{ii.filename}",
                            inner.read(ii.filename),
                        ))
        return sorted(out, key=lambda kv: kv[0])
    return [(package.name, package)]


def _open_bytes(payload):
    """xlsx source for iter_seized_rows — BytesIO for zip members,
    Path for loose files (zipfile accepts either)."""
    return io.BytesIO(payload) if isinstance(payload, bytes) else payload


def _parse_ko_date(text: str) -> str | None:
    """'2025-01-11 13:28:02' / '2025. 1. 11. 오후 1:28' → sortable iso-ish."""
    m = _KO_DATE_RE.search(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) if g else 0 for g in m.groups())
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}"


def _basename(path: str) -> str:
    return PurePosixPath(path.replace("\\", "/")).name


def _resolve(root: Path, claimed: str) -> Path:
    rel = claimed.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", rel):
        rel = rel[2:]
    return root / rel.lstrip("/")


def audit_rows(
    rows: list[dict],
    *,
    cert_ts: str | None = None,
) -> tuple[list[dict], dict]:
    """Consistency checks over normalized seized rows."""
    findings: list[dict] = []

    def flag(check: str, severity: str, detail: str, samples: list) -> None:
        findings.append({
            "check": check,
            "severity": severity,
            "count": len(samples),
            "detail": detail,
            "samples": samples[:_MAX_SAMPLE],
        })

    # 연번 sequence — expect a single continuous sequence across sheets
    seqs = [r["seq"] for r in rows if r.get("seq")]
    nums = [int(s) for s in seqs if s.isdigit()]
    non_numeric = [
        f'{r["sheet"]}!{r["row"]}: {r["seq"]}' for r in rows
        if r.get("seq") and not r["seq"].isdigit()
    ]
    issues = []
    if len(nums) != len(set(nums)):
        issues.append("duplicate 연번 values present")
    if nums and sorted(set(nums)) != list(range(min(nums), max(nums) + 1)):
        missing = sorted(set(range(min(nums), max(nums) + 1)) - set(nums))
        issues.append(f"gaps in sequence: missing {missing[:10]}"
                      + (" …" if len(missing) > 10 else ""))
    if nums != sorted(nums):
        issues.append("연번 order is not monotonic across sheets")
    if non_numeric:
        issues.append(f"{len(non_numeric)} non-numeric 연번 cells")
    if issues:
        flag("seq_integrity", "warn",
             "연번 must run 1..N continuously across paged sheets; "
             "gaps/dups suggest post-issuance editing",
             non_numeric + issues or issues)

    # hash sanity
    bad_hash = []
    for r in rows:
        for algo in ("sha256", "sha1", "md5"):
            val = r.get(algo, "")
            if val and (
                len(val) != _HASH_LEN[algo] or not _HEX_RE.match(val)
            ):
                bad_hash.append(
                    f'{r["sheet"]}!{r["row"]} seq={r.get("seq")}: '
                    f'{algo}="{val[:24]}"'
                )
    if bad_hash:
        flag("hash_format", "fail",
             "claimed digest is not valid hex of the expected length — "
             "that row's integrity claim cannot be verified",
             bad_hash)

    # name ↔ path basename
    name_mismatch = [
        f'{r["sheet"]}!{r["row"]} seq={r.get("seq")}: '
        f'파일명="{r["name"]}" vs basename(경로)="{_basename(r["path"])}"'
        for r in rows
        if r.get("name") and r.get("path")
        and _basename(r["path"]) != r["name"]
    ]
    if name_mismatch:
        flag("name_path_mismatch", "warn",
             "파일명 column disagrees with the 경로 basename — "
             "transcription or re-pathing error in the delivered list",
             name_mismatch)

    # duplicates — same content or same path listed more than once
    for field, label in (("sha1", "sha1"), ("md5", "md5"),
                         ("sha256", "sha256"), ("path", "path")):
        seen: dict[str, list[str]] = {}
        for r in rows:
            val = r.get(field, "").lower()
            if val:
                seen.setdefault(val, []).append(
                    f'{r["sheet"]}!{r["row"]}(seq {r.get("seq")})'
                )
        dups = [
            f"{label} {v[:16]}… ×{len(locs)}: {', '.join(locs[:4])}"
            if field != "path" else
            f"path {v[:60]} ×{len(locs)}: {', '.join(locs[:4])}"
            for v, locs in seen.items() if len(locs) > 1
        ]
        if dups:
            flag(f"duplicate_{field}", "warn",
                 f"same {label} appears on multiple rows — duplicated "
                 "seizure entries inflate the list",
                 dups)

    # timestamp sanity — 수정일시 must not postdate the certificate itself
    if cert_ts:
        late = []
        for r in rows:
            mod = _parse_ko_date(r.get("modified", "") or "")
            if mod and mod > cert_ts:
                late.append(
                    f'{r["sheet"]}!{r["row"]} seq={r.get("seq")}: '
                    f'modified {mod} > cert {cert_ts}'
                )
        if late:
            flag("post_cert_mtime", "fail",
                 "row claims an mtime AFTER the certificate's own "
                 "timestamp — impossible state for evidence sealed at "
                 "collection time",
                 late)

    bad_dates = [
        f'{r["sheet"]}!{r["row"]} seq={r.get("seq")}: {f}="{r[f]}"'
        for r in rows for f in ("created", "modified", "accessed")
        if r.get(f) and _parse_ko_date(r[f]) is None
    ]
    if bad_dates:
        flag("unparseable_date", "info",
             "timestamp cell is not in a recognizable format — "
             "cannot sanity-check it",
             bad_dates)

    summary = {
        "rows": len(rows),
        "seq_first": min(nums) if nums else None,
        "seq_last": max(nums) if nums else None,
        "findings": len(findings),
        "fail": sum(1 for f in findings if f["severity"] == "fail"),
        "warn": sum(1 for f in findings if f["severity"] == "warn"),
    }
    return findings, summary


def run_certcheck(
    package: Path,
    out_dir: Path,
    *,
    root: Path | None = None,
) -> dict:
    package = Path(package)
    members = _members(package)

    inventory = {
        "form_pdf": [], "detail_pdf": [], "xlsx": [],
        "sysinfo": [], "other": [],
    }
    rows: list[dict] = []
    cert_ts = None
    detail_hash_hits = 0
    detail_text = None

    for name, payload in members:
        low = name.lower()
        base = PurePosixPath(name).name
        if low.endswith(".xlsx"):
            inventory["xlsx"].append(name)
            try:
                rows.extend(iter_seized_rows(_open_bytes(payload)))
            except Exception as exc:
                inventory.setdefault("unreadable", []).append(
                    f"{name}: {exc}"
                )
        elif low.endswith(".pdf"):
            if "상세목록" in base or "detail" in low:
                inventory["detail_pdf"].append(name)
                from .text_extract import _pdf_text
                data = (
                    payload if isinstance(payload, bytes)
                    else Path(payload).read_bytes()
                )
                detail_text = _pdf_text(data) or ""
                detail_hash_hits += len(re.findall(
                    r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])",
                    detail_text,
                ))
            elif "서식" in base or "확인서" in base:
                inventory["form_pdf"].append(name)
                m = _CERT_TS_RE.search(base)
                if m:
                    ts = m.group(1)
                    cert_ts = (
                        f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T"
                        f"{ts[8:10]}:{ts[10:12]}:{ts[12:14]}"
                    )
            else:
                inventory["other"].append(name)
        elif "시스템정보" in name or low.endswith(".zip"):
            inventory["sysinfo"].append(name)
        else:
            inventory["other"].append(name)

    findings, summary = audit_rows(rows, cert_ts=cert_ts)
    if not inventory["xlsx"]:
        findings.append({
            "check": "no_detail_xlsx",
            "severity": "info",
            "count": 1,
            "detail": "package contains no .xlsx detail list — only "
                      "the printed/scanned PDFs; the row-level checks "
                      "below need the machine-readable list (or OCR)",
            "samples": [],
        })

    # printed detail list ↔ xlsx row cross-check
    if inventory["detail_pdf"]:
        if not detail_text or not detail_text.strip():
            findings.append({
                "check": "detail_pdf_text",
                "severity": "info",
                "count": 1,
                "detail": "상세목록 PDF has no text layer — scanned; "
                          "OCR (kit OCR-LIST.ps1) needed to cross-check "
                          "it against the xlsx",
                "samples": inventory["detail_pdf"][:_MAX_SAMPLE],
            })
        else:
            xlsx_hashes = sum(
                1 for r in rows if r.get("sha1") or r.get("sha256")
                or r.get("md5")
            )
            diverge = detail_hash_hits != xlsx_hashes
            findings.append({
                "check": "detail_pdf_crosscheck",
                "severity": "warn" if diverge else "ok",
                "count": abs(detail_hash_hits - xlsx_hashes),
                "detail": (
                    f"printed 상세목록 contains {detail_hash_hits} "
                    f"hash strings vs {xlsx_hashes} hashed xlsx rows"
                    + (" — printed and delivered lists diverge"
                       if diverge else " — consistent")
                ),
                "samples": [],
            })
            summary["detail_pdf_hashes"] = detail_hash_hits

    # optional live re-verification on a mirror / returned PC
    live_stats = None
    if root is not None:
        root = Path(root)
        stats = {
            "resolved": 0, "missing": 0,
            "size_match": 0, "size_mismatch": 0,
            "hash_verified": 0, "hash_mismatch": 0,
            "hash_skipped": 0,
        }
        mismatches = []
        for r in rows:
            claimed = r.get("path")
            if not claimed:
                continue
            p = _resolve(root, claimed)
            if not p.is_file():
                stats["missing"] += 1
                continue
            stats["resolved"] += 1
            size_txt = re.sub(r"[^\d]", "", r.get("size", ""))
            if size_txt and int(size_txt) != p.stat().st_size:
                stats["size_mismatch"] += 1
                mismatches.append(
                    f'{r.get("seq")}: {claimed} size claimed '
                    f'{size_txt} != actual {p.stat().st_size}'
                )
            elif size_txt:
                stats["size_match"] += 1
            algo = next(
                (a for a in ("sha256", "sha1", "md5") if r.get(a)), None
            )
            if algo:
                actual = hash_file(p, algo)
                if actual is None:
                    stats["hash_skipped"] += 1
                elif actual.lower() == r[algo].lower():
                    stats["hash_verified"] += 1
                else:
                    stats["hash_mismatch"] += 1
                    mismatches.append(
                        f'{r.get("seq")}: {claimed} {algo} claimed '
                        f'{r[algo][:16]}… != actual {actual[:16]}…'
                    )
        if stats["size_mismatch"] or stats["hash_mismatch"]:
            findings.append({
                "check": "live_reverify",
                "severity": "fail",
                "count": stats["size_mismatch"] + stats["hash_mismatch"],
                "detail": "files on the mirror/returned PC disagree with "
                          "the certificate's claimed size/hash",
                "samples": mismatches[:_MAX_SAMPLE],
            })
        live_stats = stats

    summary["findings"] = len(findings)
    summary["fail"] = sum(1 for f in findings if f["severity"] == "fail")
    summary["warn"] = sum(1 for f in findings if f["severity"] == "warn")

    report = {
        "package": str(package),
        "generated_utc": utc_now_iso(),
        "certificate_ts": cert_ts,
        "members": inventory,
        "row_summary": summary,
        "live_reverify": live_stats,
        "findings": findings,
        "note": (
            "Internal-consistency audit of the delivered 전자정보확인서 "
            "package. 'fail' findings are claims that cannot be true "
            "(bad hash format, mtime after issuance); 'warn' findings "
            "are defects that weaken the list's evidentiary weight "
            "(seq gaps, duplicates, name/path mismatches)."
        ),
    }
    write_json(out_dir / "certcheck.json", report)
    (out_dir / "report.md").write_text(
        _render_markdown(report), encoding="utf-8"
    )
    write_manifest(out_dir, "certcheck", {
        "package": str(package),
        "package_sha256": (
            sha256_file(package) if package.is_file() else None
        ),
        "summary": summary,
    })
    return report


def _render_markdown(report: dict) -> str:
    s = report["row_summary"]
    lines = [
        "# raidwatch 전자정보확인서 감사 리포트",
        "",
        f"- 패키지: `{report['package']}`",
        f"- 확인서 시각: {report.get('certificate_ts') or 'unknown'}",
        f"- 상세목록 행 수: {s['rows']} (연번 {s['seq_first']}–{s['seq_last']})",
        "",
        "## 구성물",
        "",
        "| 종류 | 파일 |",
        "|---|---|",
    ]
    for kind, files in report["members"].items():
        for f in files:
            lines.append(f"| {kind} | `{f}` |")
    lines += ["", "## 발견 사항", "",
              "| 심각도 | 검사 | 건수 | 내용 |", "|---|---|---|---|"]
    for f in report["findings"]:
        lines.append(
            f"| {f['severity']} | {f['check']} | {f['count']} | "
            f"{f['detail']} |"
        )
    if report.get("live_reverify"):
        ls = report["live_reverify"]
        lines += ["", "## 실물 대조 (--root)", "",
                  "| 구분 | 건수 |", "|---|---|"]
        for k, v in ls.items():
            lines.append(f"| {k} | {v} |")
    return "\n".join(lines) + "\n"
