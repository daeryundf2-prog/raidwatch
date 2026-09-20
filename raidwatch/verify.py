"""Seized-list parsing and verification.

Parses the evidence list delivered by investigators (JSON/CSV/plain text/
PDF text layer/.xlsx detail lists incl. the 경찰 전자정보확인서 상세목록
format), cross-checks each item against a baseline or live re-inventory,
verifies claimed hashes, and classifies warrant scope under narrow/broad
readings.
"""

from __future__ import annotations

import csv
import difflib
import json
import re
from pathlib import Path

from .common import hash_file, sha256_file, write_json, write_manifest
from .db import Inventory
from .profile import evaluate

_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
_PATH_KEYS = (
    "path", "file", "filepath", "file_path", "filename", "name",
    "경로", "파일경로", "파일 경로", "전체 파일 경로", "파일명",
)
# algo-specific keys first; bare "hash" algorithm is inferred from length
_HASH_KEYS = (
    "sha256", "sha-256", "sha-256 해시", "sha256 해시",
    "sha1", "sha-1", "sha-1 해시", "sha1 해시",
    "md5", "md5 해시", "hash", "해시",
)
# JSON keys (beyond "items") that hold the claimed file list — covers
# ForensicArtifactCollector report.json and similar tool exports
_JSON_LIST_KEYS = (
    "items", "likely_seized_files", "selected_files", "seized",
    "seized_files", "files", "file_paths",
)
_ALGO_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def _claim_algo(key: str, digest: str) -> str:
    k = key.lower().replace("-", "")
    if k in ("sha256", "sha1", "md5", "sha512"):
        return k
    return _ALGO_BY_LEN.get(len(digest), "unknown")


def _norm_rel(path: str) -> str:
    text = path.strip().replace("\\", "/")
    text = re.sub(r"/{2,}", "/", text)  # 'C:\\a\\b' exports → 'a/b'
    if re.match(r"^[A-Za-z]:/", text):
        text = text[2:]
    return text.lstrip("/")


def _mk_item(claimed: str, digest: str | None, algo: str = "sha256") -> dict:
    return {
        "claimed_path": claimed,
        "rel": _norm_rel(claimed),
        "sha256": digest,
        "hash_algo": algo,
    }


def parse_seized_list(path: Path | str) -> list[dict]:
    """Return [{claimed_path, rel, sha256, hash_algo}] from JSON/CSV/TXT
    evidence lists. Rows without a usable path are kept as
    {"claimed_path": None, "unparsed": True} so they are counted, not
    silently dropped. PDFs are handled via their embedded text layer —
    a scanned PDF with no text yields a single unparsed item telling the
    operator OCR is needed (the kit ships OCR-LIST.ps1 for Windows)."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        from .text_extract import extract_text

        text = extract_text(path) or ""
        if not text.strip():
            return [{
                "claimed_path": None, "rel": None, "sha256": None,
                "hash_algo": None, "unparsed": True,
                "raw": {
                    "pdf": "no usable text layer — likely a scan/photo; "
                           "run OCR-LIST.ps1 (kit) or supply OCR'd text",
                },
            }]
        return _parse_text_lines(text)

    if suffix == ".xlsx":
        return _parse_xlsx_list(path)
    if suffix == ".xls":
        return [{
            "claimed_path": None, "rel": None, "sha256": None,
            "hash_algo": None, "unparsed": True,
            "raw": {
                "xls": "legacy binary .xls — re-save as .xlsx or export "
                       "to CSV and retry",
            },
        }]

    text = path.read_text(encoding="utf-8", errors="replace")

    items: list[dict] = []
    if suffix == ".json" or text.lstrip().startswith(("[", "{")):
        data = json.loads(text)
        rows: object = data
        if isinstance(data, dict):
            rows = None
            for key in _JSON_LIST_KEYS:
                if isinstance(data.get(key), list):
                    rows = data[key]
                    break
            if rows is None:
                return [{
                    "claimed_path": None, "rel": None, "sha256": None,
                    "hash_algo": None, "unparsed": True,
                    "raw": {
                        "json": "object has no file-list key "
                                f"(looked for {', '.join(_JSON_LIST_KEYS)})",
                    },
                }]
        for entry in rows:
            if isinstance(entry, str):
                items.append(_mk_item(entry, None))
                continue
            claimed = next((str(entry[k]) for k in _PATH_KEYS if entry.get(k)), None)
            if not claimed:
                items.append({"claimed_path": None, "rel": None,
                              "sha256": None, "hash_algo": None,
                              "unparsed": True, "raw": entry})
                continue
            digest = algo = None
            for k in _HASH_KEYS:
                if entry.get(k):
                    digest = str(entry[k]).lower()
                    algo = _claim_algo(k, digest)
                    break
            items.append(_mk_item(claimed, digest, algo or "sha256"))
        return items

    if suffix == ".csv" or "," in text.splitlines()[0]:
        reader = csv.DictReader(text.splitlines())
        fieldmap = {f.lower().strip(): f for f in (reader.fieldnames or [])}
        path_key = next((fieldmap[k] for k in _PATH_KEYS if k in fieldmap), None)
        hash_key = next((fieldmap[k] for k in _HASH_KEYS if k in fieldmap), None)
        for row in reader:
            claimed = (row.get(path_key) or "").strip() if path_key else ""
            if not claimed:
                items.append({"claimed_path": None, "rel": None,
                              "sha256": None, "hash_algo": None,
                              "unparsed": True, "raw": dict(row)})
                continue
            digest = (row.get(hash_key) or "").strip().lower() if hash_key else None
            algo = _claim_algo(hash_key or "", digest) if digest else "sha256"
            items.append(_mk_item(claimed, digest or None, algo))
        return items

    return _parse_text_lines(text)


def _parse_text_lines(text: str) -> list[dict]:
    items: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest = None
        algo = "sha256"
        parts = line.split(None, 1)
        if len(parts) == 2 and _HEX_RE.match(parts[0]):
            digest, line = parts[0].lower(), parts[1].strip()
            algo = _ALGO_BY_LEN.get(len(digest), "sha256")
        items.append(_mk_item(line, digest, algo))
    return items


def _parse_xlsx_list(path: Path) -> list[dict]:
    """Parse the 전자정보확인서-style .xlsx detail list.

    Rows carry the claimed SHA1/MD5/SHA256 plus size and timestamps —
    extras are preserved under "claimed_meta" for downstream audit
    (certcheck) while verify uses path+hash as usual.
    """
    from .xlsx_read import iter_seized_rows

    try:
        rows = iter_seized_rows(path)
    except Exception as exc:
        return [{
            "claimed_path": None, "rel": None, "sha256": None,
            "hash_algo": None, "unparsed": True,
            "raw": {"xlsx": f"unreadable workbook: {exc}"},
        }]

    items: list[dict] = []
    for row in rows:
        claimed = row["path"] or row["name"]
        if not claimed:
            items.append({
                "claimed_path": None, "rel": None, "sha256": None,
                "hash_algo": None, "unparsed": True, "raw": row,
            })
            continue
        digest = algo = None
        for cand in ("sha256", "sha1", "md5"):
            if row.get(cand):
                digest, algo = row[cand].lower(), cand
                break
        item = _mk_item(claimed, digest, algo or "sha256")
        item["claimed_meta"] = {
            k: row[k] for k in
            ("seq", "name", "ext", "size", "created", "modified",
             "accessed", "sheet", "row")
            if row.get(k)
        }
        items.append(item)
    if not items:
        return [{
            "claimed_path": None, "rel": None, "sha256": None,
            "hash_algo": None, "unparsed": True,
            "raw": {"xlsx": "no recognizable seized-list rows found"},
        }]
    return items


def _match_path(rel: str, known: set[str]) -> str | None:
    if rel in known:
        return rel
    candidates = [p for p in known if p.endswith("/" + rel)]
    return candidates[0] if len(candidates) == 1 else None


# Visually confusable characters collapsed for OCR-noise-tolerant matching:
# a seized list read by OCR may contain "U5ers", "0" for "O", "1" for "l", etc.
_CONFUSABLES = str.maketrans(
    {
        "O": "0", "o": "0", "Q": "0",
        "I": "1", "l": "1", "i": "1", "|": "1",
        "S": "5", "s": "5",
        "B": "8",
        "Z": "2", "z": "2",
        "G": "6",
        "g": "9", "q": "9",
    }
)


def _fuzzy_key(text: str) -> str:
    return text.lower().replace("\\", "/").translate(_CONFUSABLES)


def _fuzzy_match(
    rel: str, known: set[str], threshold: float = 0.82, margin: float = 0.05
) -> tuple[str | None, float, bool]:
    """Best fuzzy path match for an OCR-damaged claimed path.

    Returns (path|None, best_score, ambiguous). A match requires the best
    candidate to beat the second best by `margin` so near-ties are not
    silently resolved.
    """
    target = _fuzzy_key(rel)
    best = None
    best_score = 0.0
    second_score = 0.0
    for p in known:
        score = difflib.SequenceMatcher(None, target, _fuzzy_key(p)).ratio()
        if score > best_score:
            second_score, best_score, best = best_score, score, p
        elif score > second_score:
            second_score = score
    if best is None or best_score < threshold:
        return None, best_score, False
    if best_score - second_score < margin:
        return None, best_score, True
    return best, best_score, False


def verify_items(
    seized: list[dict],
    inv: Inventory,
    *,
    profile: dict | None = None,
    current_root: Path | None = None,
) -> dict:
    known = inv.paths()
    results = []
    summary = {
        "total": 0,
        "verified": 0,
        "hash_mismatch": 0,
        "hash_incomparable": 0,
        "unverifiable": 0,
        "unparsed_item": 0,
        "no_claimed_hash": 0,
        "not_in_inventory": 0,
        "ambiguous_path": 0,
        "missing_now": 0,
        "in_scope": 0,
        "in_scope_partial": 0,
        "borderline": 0,
        "out_of_scope": 0,
        "scope_unknown": 0,
        "scope_unverifiable": 0,
        "fuzzy_matched": 0,
    }
    for item in seized:
        summary["total"] += 1
        if item.get("unparsed") or not item.get("rel"):
            results.append({
                "claimed_path": item.get("claimed_path"),
                "claimed_sha256": None,
                "matched_path": None,
                "status": "unparsed_item",
                "scope_verdict": "unknown",
                "notes": ["seized-list row had no usable path field"],
            })
            summary["unparsed_item"] += 1
            continue
        rel = item["rel"]
        match = _match_path(rel, known)
        match_method = "exact" if match else None
        entry = {
            "claimed_path": item["claimed_path"],
            "claimed_sha256": item["sha256"],
            "matched_path": match,
            "status": None,
            "scope_verdict": "unknown",
            "notes": [],
        }
        if match is None:
            fuzzy_path, score, ambiguous = _fuzzy_match(rel, known)
            if fuzzy_path is not None:
                match = fuzzy_path
                match_method = "fuzzy"
                entry["matched_path"] = match
                summary["fuzzy_matched"] += 1
                entry["notes"].append(
                    f"fuzzy path match score={score:.3f}; "
                    "hash verified from inventory, not from the printed list"
                )
            else:
                suffix_hits = [p for p in known if p.endswith("/" + rel)]
                entry["status"] = (
                    "ambiguous_path"
                    if (ambiguous or len(suffix_hits) > 1)
                    else "not_in_inventory"
                )
                if ambiguous:
                    entry["notes"].append(
                        f"fuzzy candidates too close (score={score:.3f})"
                    )
                summary[entry["status"]] += 1
                results.append(entry)
                continue
        if match_method:
            entry["notes"].append(f"matched via {match_method}")

        rec = inv.get(match)
        if profile is not None:
            verdict = evaluate(rec.as_dict(), profile)["verdict"]
            entry["scope_verdict"] = verdict
            # scope verdicts and statuses share names ("unverifiable") —
            # keep them in separate counters so they never collide.
            key = {
                "excluded": "scope_unknown",
                "unverifiable": "scope_unverifiable",
            }.get(verdict, verdict)
            summary[key] = summary.get(key, 0) + 1

        claimed = (item["sha256"] or "").lower() or None
        algo = item.get("hash_algo") or "sha256"
        if claimed and algo != "sha256":
            # Printed list hash is md5/sha1/etc — not comparable to our
            # sha256 baseline. But if the returned PC is at hand we can
            # recompute the *claimed* algorithm on the live file.
            live_path = (
                Path(current_root) / match if current_root is not None
                else None
            )
            actual = None
            if live_path is not None and live_path.is_file():
                actual = hash_file(live_path, algo)
            if actual is not None:
                if actual == claimed:
                    entry["status"] = "verified"
                    entry["notes"].append(
                        f"claimed {algo} verified against live file"
                    )
                else:
                    entry["status"] = "hash_mismatch"
                    entry["notes"].append(
                        f"claimed {algo} {claimed} != live {actual}"
                    )
            else:
                entry["status"] = "verified"
                summary["hash_incomparable"] += 1
                entry["notes"].append(
                    f"claimed {algo} hash not comparable to baseline "
                    "sha256"
                )
        elif claimed and not rec.sha256:
            entry["status"] = "unverifiable"
            entry["notes"].append(
                "baseline has no digest for this path; claim unverifiable"
            )
        elif claimed and claimed != rec.sha256:
            entry["status"] = "hash_mismatch"
            entry["notes"].append(f"claimed {claimed} != baseline {rec.sha256}")
        elif not claimed:
            entry["status"] = "verified"
            summary["no_claimed_hash"] += 1
            entry["notes"].append("no claimed hash; path matched only")
        else:
            entry["status"] = "verified"

        if current_root is not None and entry["status"] == "verified":
            cur_path = Path(current_root) / match
            if not cur_path.exists():
                entry["notes"].append("file absent on current disk")
                summary["missing_now"] += 1
            else:
                try:
                    cur_hash = sha256_file(cur_path)
                except OSError:
                    cur_hash = None
                if cur_hash and rec.sha256 and cur_hash != rec.sha256:
                    entry["status"] = "hash_mismatch"
                    entry["notes"].append(
                        f"current {cur_hash} != baseline {rec.sha256}"
                    )
        summary[entry["status"]] += 1
        results.append(entry)
    return {"items": results, "summary": summary}


def render_verify_markdown(report: dict, seized_source: str) -> str:
    s = report["summary"]
    lines = [
        "# raidwatch 압수 목록 검증 리포트",
        "",
        f"- 입력 목록: `{seized_source}`",
        "",
        "## 요약",
        "",
        "| 구분 | 건수 |",
        "|---|---|",
        f"| 전체 항목 | {s['total']} |",
        f"| 검증 일치 | {s['verified']} |",
        f"| 해시 불일치 | {s['hash_mismatch']} |",
        f"| 해시 알고리즘 상이(md5/sha1 — 비교 불가) | {s['hash_incomparable']} |",
        f"| 검증 불가(기준선 해시 없음) | {s['unverifiable']} |",
        f"| 해시 미기재(경로만 일치) | {s['no_claimed_hash']} |",
        f"| 파싱 불가 행 | {s['unparsed_item']} |",
        f"| 인벤토리에 없음 | {s['not_in_inventory']} |",
        f"| 퍼지 매칭(OCR 손상 경로 복원) | {s['fuzzy_matched']} |",
        f"| 경로 모호 | {s['ambiguous_path']} |",
        f"| 현재 디스크에 없음 | {s['missing_now']} |",
        "",
        "## 영장 범위 판정",
        "",
        "| 구분 | 건수 |",
        "|---|---|",
        f"| 범위 내(좁은 해석 AND) | {s['in_scope']} |",
        f"| 범위 내 후보(일부 조건 미평가) | {s['in_scope_partial']} |",
        f"| 경계(넓은 해석에서만 해당) | {s['borderline']} |",
        f"| **범위 밖(어느 해석에도 불해당)** | {s['out_of_scope']} |",
        f"| 판정 불가(조건 평가 불가) | {s['scope_unverifiable']} |",
        f"| 제외 대상 | {s['scope_unknown']} |",
        "",
    ]
    flagged = [
        it for it in report["items"]
        if it["status"] != "verified"
        or it["scope_verdict"] in ("out_of_scope", "unverifiable")
    ]
    if flagged:
        lines += [
            "## 주의 항목",
            "",
            "| 경로 | 상태 | 범위 판정 | 비고 |",
            "|---|---|---|---|",
        ]
        for it in flagged:
            lines.append(
                f"| `{it['claimed_path']}` | {it['status']} | "
                f"{it['scope_verdict']} | {'; '.join(it['notes'])} |"
            )
        lines.append("")
    return "\n".join(lines)


def run_verify(
    seized_path: Path,
    inv: Inventory,
    out_dir: Path,
    *,
    profile: dict | None = None,
    current_root: Path | None = None,
) -> dict:
    seized = parse_seized_list(seized_path)
    report = verify_items(seized, inv, profile=profile, current_root=current_root)
    out_dir.mkdir(parents=True, exist_ok=True)
    is_pdf = Path(seized_path).suffix.lower() == ".pdf"
    if is_pdf:
        from .text_extract import extract_text

        extracted = extract_text(Path(seized_path))
        if extracted:
            (out_dir / "seized-extracted-text.txt").write_text(
                extracted, encoding="utf-8"
            )
    write_json(out_dir / "verify.json", report)
    (out_dir / "report.md").write_text(
        render_verify_markdown(report, str(seized_path)), encoding="utf-8"
    )
    write_manifest(
        out_dir,
        "verify",
        {
            "seized_list": str(seized_path),
            "seized_list_sha256": sha256_file(Path(seized_path)),
            "seized_list_format": Path(seized_path).suffix.lower(),
            "pdf_text_layer": (
                "extracted" if is_pdf and (out_dir / "seized-extracted-text.txt").exists()
                else None
            ),
            "profile_sha256": profile["profile_sha256"] if profile else None,
            "summary": report["summary"],
        },
    )
    return report
