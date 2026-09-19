"""Seized-list parsing and verification.

Parses the evidence list delivered by investigators (JSON/CSV/plain text),
cross-checks each item against a baseline or live re-inventory, verifies
claimed hashes, and classifies warrant scope under narrow/broad readings.
"""

from __future__ import annotations

import csv
import difflib
import json
import re
from pathlib import Path

from .common import sha256_file, write_json, write_manifest
from .db import Inventory
from .profile import evaluate

_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
_PATH_KEYS = ("path", "file", "filepath", "file_path", "filename", "name")
_HASH_KEYS = ("sha256", "sha-256", "hash", "sha1", "md5")


def _norm_rel(path: str) -> str:
    text = path.strip().replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", text):
        text = text[2:]
    return text.lstrip("/")


def parse_seized_list(path: Path | str) -> list[dict]:
    """Return [{claimed_path, rel, sha256}] from JSON/CSV/TXT evidence lists."""
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()

    items: list[dict] = []
    if suffix == ".json" or text.lstrip().startswith(("[", "{")):
        data = json.loads(text)
        rows = data.get("items", data) if isinstance(data, dict) else data
        for entry in rows:
            if isinstance(entry, str):
                items.append({"claimed_path": entry, "rel": _norm_rel(entry), "sha256": None})
                continue
            claimed = next((str(entry[k]) for k in _PATH_KEYS if entry.get(k)), None)
            if not claimed:
                continue
            digest = next((str(entry[k]).lower() for k in _HASH_KEYS if entry.get(k)), None)
            items.append({"claimed_path": claimed, "rel": _norm_rel(claimed), "sha256": digest})
        return items

    if suffix == ".csv" or "," in text.splitlines()[0]:
        reader = csv.DictReader(text.splitlines())
        fieldmap = {f.lower().strip(): f for f in (reader.fieldnames or [])}
        path_key = next((fieldmap[k] for k in _PATH_KEYS if k in fieldmap), None)
        hash_key = next((fieldmap[k] for k in _HASH_KEYS if k in fieldmap), None)
        for row in reader:
            claimed = (row.get(path_key) or "").strip() if path_key else ""
            if not claimed:
                continue
            digest = (row.get(hash_key) or "").strip().lower() if hash_key else None
            items.append({"claimed_path": claimed, "rel": _norm_rel(claimed), "sha256": digest or None})
        return items

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest = None
        parts = line.split(None, 1)
        if len(parts) == 2 and _HEX_RE.match(parts[0]):
            digest, line = parts[0].lower(), parts[1].strip()
        items.append({"claimed_path": line, "rel": _norm_rel(line), "sha256": digest})
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
        "no_claimed_hash": 0,
        "not_in_inventory": 0,
        "ambiguous_path": 0,
        "missing_now": 0,
        "in_scope": 0,
        "borderline": 0,
        "out_of_scope": 0,
        "scope_unknown": 0,
        "fuzzy_matched": 0,
    }
    for item in seized:
        summary["total"] += 1
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
            key = "scope_unknown" if verdict == "excluded" else verdict
            summary[key] = summary.get(key, 0) + 1

        claimed = (item["sha256"] or "").lower() or None
        if claimed and rec.sha256 and claimed != rec.sha256:
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
        f"| 해시 미기재(경로만 일치) | {s['no_claimed_hash']} |",
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
        f"| 경계(넓은 해석에서만 해당) | {s['borderline']} |",
        f"| **범위 밖(어느 해석에도 불해당)** | {s['out_of_scope']} |",
        f"| 판정 불가 | {s['scope_unknown']} |",
        "",
    ]
    flagged = [
        it for it in report["items"]
        if it["status"] != "verified" or it["scope_verdict"] == "out_of_scope"
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
            "profile_sha256": profile["profile_sha256"] if profile else None,
            "summary": report["summary"],
        },
    )
    return report
