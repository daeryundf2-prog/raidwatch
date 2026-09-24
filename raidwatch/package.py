"""Case-package assembly (M7) — legal-review bundle generator.

Pulls every raidwatch output in a case directory into one hashed,
indexed bundle plus two stakeholder-facing documents:

- ``폐기청구목록.md`` — items the verification classified as outside the
  warrant scope or missing now, formatted as an attachment-ready list
  for a suppression/return-motion (폐기·환부 청구) filing.
- ``절차기록.md`` — a chronological reconstruction of the response:
  baseline creation, watcher events, raid-window changes, investigator
  tool observations, and each analysis step with its manifest hash.

Documents carry observation language only; they are drafting aids for
counsel, not legal conclusions.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .common import (
    iter_tree, sha256_file, utc_now_iso, write_json, write_manifest,
)

KNOWN_OUTPUTS = (
    "verify.json", "diff.json", "hits.json", "artifacts.json",
    "sources.json", "carve.json", "journal.json", "manifest.json",
    "report.md", "events.jsonl",
)


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_disposal_list(verify: dict | None, diff: dict | None, dest: Path) -> int:
    """Render the out-of-scope attachment list; returns the item count."""
    lines = [
        "# 압수물 범위 초과·환부 대상 목록 (부속 문서)",
        "",
        f"생성: {utc_now_iso()} — raidwatch 자동 생성, 변호인 검토용 초안",
        "",
    ]
    count = 0
    entries = (verify or {}).get("items", [])
    out_scope = [e for e in entries if e.get("scope_verdict") == "out_of_scope"]
    missing = [
        e for e in entries
        if any("absent on current disk" in n for n in e.get("notes", []))
    ]
    ambiguous = [
        e for e in entries
        if e.get("status")
        in ("ambiguous_path", "not_in_inventory", "unverifiable",
            "unparsed_item")
    ]
    if out_scope:
        lines += [
            "## 1. 영장 범위 밖으로 판정된 압수 항목",
            "",
            "| # | 경로 | SHA-256 | 검증 상태 |",
            "|---|---|---|---|",
        ]
        for e in out_scope:
            count += 1
            lines.append(
                f"| {count} | `{e.get('claimed_path')}` | "
                f"`{(e.get('claimed_sha256') or '—')[:16]}…` | "
                f"{e.get('status')} |"
            )
        lines.append("")
    if missing:
        lines += [
            "## 2. 목록에는 있으나 현재 디스크에 없는 항목 (반출 추정)",
            "",
            "| # | 경로 | 비고 |",
            "|---|---|---|",
        ]
        for e in missing:
            count += 1
            lines.append(
                f"| {count} | `{e.get('claimed_path')}` | 현재 PC에 부재 |"
            )
        lines.append("")
    if ambiguous:
        lines += [
            "## 3. 특정 불가 항목 (인벤토리 부재/모호 — 확인 요청 필요)",
            "",
            "| # | 경로 | 상태 |",
            "|---|---|---|",
        ]
        for e in ambiguous:
            count += 1
            lines.append(
                f"| {count} | `{e.get('claimed_path')}` | {e.get('status')} |"
            )
        lines.append("")
    backdated = [
        c for c in (diff or {}).get("added", []) if c.get("backdated")
    ]
    if backdated:
        lines += [
            "## 4. 타임스탬프 의심 신규 파일 (식재 가능성 — 전문가 감정 요)",
            "",
            "| # | 경로 | mtime | 비고 |",
            "|---|---|---|---|",
        ]
        for c in backdated:
            count += 1
            lines.append(
                f"| {count} | `{c.get('path')}` | {c.get('mtime_utc')} | "
                "mtime이 기준선보다 과거 |"
            )
        lines.append("")
    if count == 0:
        lines.append("_범위 초과·부재·의심 항목이 없습니다._")
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return count


def _write_procedure_log(case_dir: Path, dest: Path) -> int:
    """Chronological response log from manifests + watcher events."""
    events: list[tuple[str, str]] = []
    manifests = sorted(
        p for p in iter_tree(case_dir) if p.name == "manifest.json"
    )
    for manifest in manifests:
        data = _load_json(manifest) or {}
        events.append(
            (
                data.get("finished_utc", "?"),
                f"`{data.get('command', '?')}` 실행 완료 "
                f"({manifest.parent.name}/ — manifest sha256 "
                f"`{sha256_file(manifest)[:16]}…`)",
            )
        )
    events_log = case_dir / "watch" / "events.jsonl"
    if events_log.is_file():
        counts: dict[str, int] = {}
        first = last = None
        for line in events_log.read_text(encoding="utf-8").splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            counts[e.get("event", "?")] = counts.get(e.get("event", "?"), 0) + 1
            ts = e.get("ts") or e.get("ts_utc")
            if ts:
                first = first or ts
                last = ts
        events.append(
            (
                first or "?",
                f"watcher 감시 기간 {first}~{last}, 이벤트: "
                + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
            )
        )
    events.sort()
    lines = [
        "# 절차 기록 (대응 타임라인)",
        "",
        f"생성: {utc_now_iso()} — raidwatch 자동 생성, 변호인 검토용 초안",
        "",
        "| 시각(UTC) | 내용 |",
        "|---|---|",
        *[f"| {ts} | {desc} |" for ts, desc in events],
        "",
        "> 각 산출물의 무결성은 `index.json`의 SHA-256으로 독립 검증 가능.",
    ]
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(events)


def _write_checklist(
    case_dir: Path,
    dest: Path,
    verify: dict | None,
    diff: dict | None,
    artifacts: dict | None,
) -> None:
    """Data-driven counsel checklist — items the bundle itself flags."""
    vsum = (verify or {}).get("summary", {})
    dsum = (diff or {}).get("summary", {})
    tools = sorted(
        (artifacts or {}).get("observed_investigator_tools", {}).keys()
    )
    ads = (artifacts or {}).get("alternate_data_streams", {})
    via_shadow = (artifacts or {}).get("summary", {}).get("via_shadow", 0)
    seized_manifest = None
    for m in sorted(
        p for p in iter_tree(case_dir) if p.name == "manifest.json"
    ):
        data = _load_json(m) or {}
        if data.get("command") == "verify":
            seized_manifest = data
            break
    pdf_note = (
        "압수 목록이 PDF였으며 텍스트 레이어가 추출됨 — "
        "스캔본이었다면 OCR 결과와 원본을 대조할 것"
        if seized_manifest and seized_manifest.get("pdf_text_layer")
        else "압수 목록이 스캔본이었다면 OCR 텍스트와 원본 대조 필수"
    )
    lines = [
        "# 압수수색 대응 검토 체크리스트 (자동 생성 초안)",
        "",
        f"생성: {utc_now_iso()} — raidwatch, 변호인 검토용",
        "",
        "## A. 압수조서 문서 자체",
        "- [ ] 영장 범위(대상 파일·기간·키워드)가 조서에 명시되어 있는가 → profile.json과 대조",
        "- [ ] 집행 일시·장소·집행자·참여인 기재 및 서명·날인 유무",
        f"- [ ] {pdf_note}",
        "- [ ] 인쇄된 목록의 디지털 원본(스풀/Temp 잔재)을 확보했는가 → sources.json",
        "",
        "## B. 압수물 검증 (verify.json)",
        f"- 목록 항목: {vsum or 'verify 결과 없음'}",
        "- [ ] hash_mismatch: 수사기관 해시와 알고리즘이 다른지(md5/sha1이면 비교 불가) 확인",
        "- [ ] not_in_inventory / ambiguous_path: 수사기관에 구체 경로 확인 요청",
        "- [ ] out_of_scope / in_scope_partial: 폐기청구목록.md와 대조",
        "- [ ] unverifiable: 평가 불가 항목이 범위 밖으로 오인되지 않았는지",
        "",
        "## C. 변경 이력 (diff.json)",
        f"- 요약: {dsum or '기준선 비교 결과 없음'}",
        "- [ ] 삭제된 파일이 압수 목록에 있는가 → 반출(가져감)의 독립 증거",
        "- [ ] backdated(과거 mtime 식재 의심) 항목 → 전문가 감정 의뢰",
        "- [ ] atime 열람 신호는 OS 기록 시에만 의미 — 음수 결과는 무증거",
        "",
        "## D. 수사 행위 재구성 (artifacts / journal)",
        f"- 관찰된 수사 도구: {', '.join(tools) if tools else '없음'}",
        "- [ ] ShimCache 타임스탬프는 실행 시각이 아니라 파일 mtime — 해석 주의",
        f"- [ ] ADS(대체 데이터 스트림) {ads.get('streams_found', 0)}건"
        + (" (부분 스캔 — 시간 초과)" if ads.get("truncated") else ""),
        f"- [ ] VSS 섀도 경유 복사 {via_shadow}건 — 집행 '이전' 상태 스냅샷임",
        "- [ ] USN 저널의 공백(래핑/비활성)은 부재 증거가 아님",
        "",
        "## E. 증거 보전",
        "- [ ] custody.txt의 root_hash를 실행 직후 이메일/공증으로 시점 고정했는가",
        "- [ ] 전달받은 zip을 SHA256SUMS.txt로 검증했는가",
        "- [ ] raidwatch-out 원본을 변경 없이 보존 중인가",
        "- [ ] exe 미서명 경고(SmartScreen)는 악성코드 의미가 아님 — 해시 대조로 확인",
        "",
    ]
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_package(case_dir: Path, out_dir: Path) -> dict:
    """Assemble all raidwatch outputs under case_dir into a legal bundle."""
    case_dir = Path(case_dir).resolve()
    files_dir = out_dir / "files"
    index = []
    for name in KNOWN_OUTPUTS:
        for src in sorted(p for p in iter_tree(case_dir)
                          if p.name == name):
            rel = src.relative_to(case_dir).as_posix()
            dest = files_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            index.append(
                {
                    "path": rel,
                    "sha256": sha256_file(src),
                    "size": src.stat().st_size,
                }
            )

    verify = _load_json(case_dir / "verify" / "verify.json")
    diff = _load_json(case_dir / "diff" / "diff.json")
    artifacts = _load_json(case_dir / "artifacts" / "artifacts.json")
    disposal_count = _write_disposal_list(
        verify, diff, out_dir / "폐기청구목록.md"
    )
    event_count = _write_procedure_log(case_dir, out_dir / "절차기록.md")
    _write_checklist(
        case_dir, out_dir / "검토체크리스트.md", verify, diff, artifacts
    )

    write_json(out_dir / "index.json", {"files": index})
    summary = {
        "files_bundled": len(index),
        "disposal_items": disposal_count,
        "timeline_entries": event_count,
    }
    write_manifest(out_dir, "package", {"case_dir": str(case_dir),
                                        "summary": summary})
    return {
        "summary": summary,
        "disposal_list": str(out_dir / "폐기청구목록.md"),
        "procedure_log": str(out_dir / "절차기록.md"),
        "checklist": str(out_dir / "검토체크리스트.md"),
        "index": str(out_dir / "index.json"),
    }
