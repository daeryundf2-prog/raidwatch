"""Keyword audit (`raidwatch keyword-audit`) — noise-rate metrology.

"돈", "계약", "대표", "보고" — scattershot keywords let investigators
sweep tens of thousands of files and call it selection. Judges trust
numbers over adjectives: this measures, per warrant keyword, how much
of what was actually taken fails the warrant's own criteria.

For each seized item resolved to a real file:
- attribute it to every warrant keyword whose term appears in the
  file name (attribution is documented, not guessed silently)
- evaluate the item against the full warrant profile (date ranges,
  path include/exclude, extensions) via the same engine as verify
- noise = seized but out_of_scope / outside date range / excluded path

Also reports items matching NO keyword at all — seized with no stated
basis, the sharpest violation of the two.
"""

from __future__ import annotations

import json
from pathlib import Path

from .common import utc_now_iso, write_json, write_manifest
from .profile import evaluate


def _keyword_terms(profile: dict) -> list[str]:
    return [
        str(k.get("term", "")).strip()
        for k in (profile.get("criteria", {}).get("keywords") or [])
        if k.get("term")
    ]


def _attributes(path: str, terms: list[str]) -> list[str]:
    low = Path(path).name.lower() if path else ""
    return [t for t in terms if t.lower() in low]


def run_keyword_audit(
    seized_path: Path,
    profile: dict,
    root: Path,
    out_dir: Path,
) -> dict:
    """Per-keyword seizure noise measurement."""
    from .verify import parse_seized_list

    root = Path(root).resolve()
    out_dir = Path(out_dir).resolve()
    terms = _keyword_terms(profile)
    items = parse_seized_list(seized_path)

    per_kw = {
        t: {"seized": 0, "in_scope": 0, "out_of_scope": 0,
            "unverifiable": 0, "missing": 0}
        for t in terms
    }
    unattributed = {"seized": 0, "out_of_scope": 0}
    detail = []
    # Direct probe — no full-disk inventory. Unresolved paths get the
    # same scoped-subtree fuzzy fallback as mirror.
    from .mirror import _scoped_candidates
    from .verify import _fuzzy_match

    for it in items:
        rel = it.get("rel")
        claimed = it.get("claimed_path") or rel or "?"
        resolved = None
        if rel and not it.get("unparsed"):
            if (root / rel).is_file():
                resolved = rel
            else:
                scoped = _scoped_candidates(root, rel)
                if scoped:
                    match, _score, _amb = _fuzzy_match(rel, set(scoped))
                    if match is not None:
                        resolved = match
        verdict = None
        if resolved is not None:
            try:
                st = (root / resolved).stat()
            except OSError:
                resolved = None
            else:
                verdict = evaluate(
                    {
                        "path": resolved,
                        "name": Path(resolved).name,
                        "size": st.st_size,
                        "mtime_ns": st.st_mtime_ns,
                        "ctime_ns": st.st_ctime_ns,
                        "atime_ns": st.st_atime_ns,
                    },
                    profile,
                )["verdict"]
        attrs = _attributes(claimed, terms)
        # noise = attributed to a keyword but fails the warrant's own
        # full criteria — out_of_scope, excluded, or "borderline" (the
        # keyword matched but e.g. the date range did not: taken under
        # the keyword, outside the warrant's own limits). "unverifiable"
        # is NOT noise — we cannot assert it fails.
        noise = verdict in ("out_of_scope", "excluded", "borderline")
        if not attrs:
            unattributed["seized"] += 1
            if noise:
                unattributed["out_of_scope"] += 1
        for t in attrs:
            bucket = per_kw[t]
            bucket["seized"] += 1
            if resolved is None:
                bucket["missing"] += 1
            elif noise:
                bucket["out_of_scope"] += 1
            elif verdict in ("in_scope", "in_scope_partial", "borderline"):
                bucket["in_scope"] += 1
            else:
                bucket["unverifiable"] += 1
        detail.append({
            "claimed_path": claimed,
            "resolved": resolved,
            "keywords": attrs,
            "verdict": verdict,
        })

    keywords = []
    total_seized = total_noise = 0
    for t, b in sorted(per_kw.items(), key=lambda kv: -kv[1]["seized"]):
        ratio = (b["out_of_scope"] / b["seized"]) if b["seized"] else 0.0
        keywords.append({
            "term": t,
            **b,
            "noise_ratio": round(ratio, 4),
        })
        total_seized += b["seized"]
        total_noise += b["out_of_scope"]
    overall_ratio = (total_noise / total_seized) if total_seized else 0.0
    summary = {
        "seized_items": len(items),
        "keyword_attributed": total_seized,
        "unattributed_items": unattributed["seized"],
        "unattributed_out_of_scope": unattributed["out_of_scope"],
        "overall_noise_ratio": round(overall_ratio, 4),
    }
    report = {
        "generated_utc": utc_now_iso(),
        "summary": summary,
        "keywords": keywords,
        "items": detail,
        "note": (
            "noise_ratio = seized items attributed to a keyword that "
            "fail the warrant's own full criteria (out_of_scope, "
            "excluded, or borderline — keyword matched but another "
            "criterion such as the date range did not). 'unverifiable' "
            "items are excluded from the noise count — we do not assert "
            "what we cannot evaluate. A 95% noise ratio on a keyword is "
            "a proportionality/specificity indicator for counsel review "
            "— 영장의 구체성·비례 원칙 검토 근거. 'unattributed' items "
            "matched no warrant keyword at all: seized without any "
            "stated basis."
        ),
    }
    write_json(out_dir / "keyword-audit.json", report)
    write_manifest(out_dir, "keyword-audit", {"summary": summary})
    return report
