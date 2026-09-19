"""Inquiry (`raidwatch inquiry`) — the interrogation-room checker.

Two weeks after the raid, in the police interview room, the
investigator slides a printout across the table: "이 문서 피의자
컴퓨터에서 나온 거 맞죠?" Counsel types the file name and gets the
verdict in one second:

    [OUT_OF_SCOPE — 폐기청구 대상 / 위법수집증거 → 진술거부 근거]

Sources: the case dir's verify.json (item statuses + scope verdicts),
diff.json (added/removed/modified), optionally keyword-audit.json and
boundary.json for richer context. Interactive REPL when no --query.
"""

from __future__ import annotations

import json
from pathlib import Path

from .common import utc_now_iso


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _case_file(case_dir: Path, name: str) -> dict | None:
    """Look in case_dir/name, case_dir/<stem>/name (per-step layout),
    and field-layout case_dir/steps/*/name."""
    for cand in (
        case_dir / name,
        case_dir / Path(name).stem / name,
        *sorted(case_dir.glob("steps/*/" + name)),
    ):
        d = _load(cand)
        if d:
            return d
    return None


def load_case_index(case_dir: Path) -> dict:
    """Pre-index all lookup sources once (REPL speed)."""
    case_dir = Path(case_dir).resolve()
    index: dict[str, list] = {"items": [], "diff": [], "extras": []}
    verify = _case_file(case_dir, "verify.json")
    if verify:
        index["items"] = verify.get("items", [])
    diff = _case_file(case_dir, "diff.json")
    if diff:
        for key in ("added", "removed", "modified", "accessed"):
            for e in diff.get(key, []):
                index["diff"].append({"change": key, **e})
    for name in ("boundary.json", "keyword-audit.json"):
        d = _case_file(case_dir, name)
        if d:
            index["extras"].append(d)
    return index


def _verdict(item: dict) -> str:
    scope = item.get("scope_verdict")
    status = item.get("status") or "?"
    if scope == "out_of_scope":
        return "[OUT_OF_SCOPE — 폐기·환부 청구 대상 / 위법수집증거 → 진술거부 근거]"
    if scope in ("in_scope", "in_scope_partial"):
        return "[IN_SCOPE — 영장 범위 내 (단, 절차 적법성은 별도 검토)]"
    if status == "not_in_inventory":
        return "[미발견 — 압수 목록에만 있고 디스크에 없음 → 반출 추정]"
    if status == "ambiguous_path":
        return "[특정 불가 — 경로 모호 → 수사기관에 확인 요청 대상]"
    if status == "unverifiable":
        return "[검증 불가 — 평가 불가 항목 → 범위 판정 보류]"
    return f"[{status}]"


def query(index: dict, text: str) -> str:
    """Answer one interrogation-room lookup."""
    needle = text.strip().lower()
    if not needle:
        return "?"
    hits = []
    for it in index["items"]:
        hay = " ".join(
            str(x or "") for x in
            (it.get("claimed_path"), it.get("matched_path"))
        ).lower()
        if needle in hay or needle in Path(it.get("claimed_path") or "").name.lower():
            hits.append(it)
    lines = []
    for it in hits[:8]:
        lines.append(
            f"  {_verdict(it)}\n"
            f"    목록 경로: {it.get('claimed_path')}\n"
            f"    실제 경로: {it.get('matched_path') or '—'}\n"
            f"    상태: {it.get('status')} / 범위: {it.get('scope_verdict')}"
        )
    if len(hits) > 8:
        lines.append(f"  … 외 {len(hits) - 8}건")
    if not hits:
        for e in index["diff"]:
            if needle in str(e.get("path", "")).lower():
                lines.append(
                    f"  [압수 목록 외 — diff 발견: {e['change']}]\n"
                    f"    경로: {e.get('path')}"
                )
        if not lines:
            lines.append(
                "  [기록 없음 — 압수 목록에도 diff에도 없는 파일\n"
                "   → 수사기관에 출처 확인 요청]"
            )
    return "\n".join(lines)


def run_inquiry(case_dir: Path, out_dir: Path | None = None,
                query_text: str | None = None) -> int:
    index = load_case_index(case_dir)
    print(f"raidwatch inquiry — {len(index['items'])} seized items, "
          f"{len(index['diff'])} diff entries loaded")
    print("파일명이나 경로 일부를 입력하면 판정 결과가 나옵니다 "
          "(빈 줄 = 종료)\n")
    log = None
    if out_dir is not None:
        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        log = out_dir / "inquiry-log.txt"

    def _ask(text: str) -> None:
        answer = query(index, text)
        print(answer)
        if log is not None:
            with log.open("a", encoding="utf-8") as fh:
                fh.write(
                    f"[{utc_now_iso()}] Q: {text}\n{answer}\n\n"
                )

    if query_text:
        _ask(query_text)
        return 0
    try:
        while True:
            text = input("inquiry> ").strip()
            if not text:
                break
            _ask(text)
    except (EOFError, KeyboardInterrupt):
        pass
    return 0
