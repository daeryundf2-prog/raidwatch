"""Petition — print-ready legal filing from raidwatch outputs.

`package` produces markdown for engineers; counsel needs a formatted
서면 they can print on-site and hand to the lead investigator or file
with the court. This renders a formal 환부·폐기 청구서 as
print-optimized HTML (A4, serif, signature block) built from the same
verify/diff/artifacts data — observation language only, blanks for
the fields only a human can fill (names, signatures).

Output: 청구서.html — double-click → print → sign.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .common import sha256_file, utc_now_iso, write_json, write_manifest


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


_CSS = """
@page { size: A4; margin: 25mm 20mm; }
body { font-family: 'Batang','바탕','Times New Roman',serif;
       font-size: 11pt; line-height: 1.9; color: #111;
       max-width: 170mm; margin: 0 auto; padding: 20mm 0; }
h1 { text-align: center; font-size: 16pt; letter-spacing: .3em;
     border-bottom: 2px solid #000; padding-bottom: 8px; }
h2 { font-size: 12pt; margin-top: 2em; border-left: 4px solid #333;
     padding-left: 8px; }
table { border-collapse: collapse; width: 100%; font-size: 10pt; }
th, td { border: 1px solid #555; padding: 4px 6px; text-align: left;
         word-break: break-all; }
th { background: #eee; }
.parties td { border: none; padding: 2px 4px; }
.sig { margin-top: 4em; text-align: center; }
.sig .line { display: inline-block; border-bottom: 1px solid #000;
             min-width: 30mm; }
.meta { color: #555; font-size: 9pt; margin-top: 3em;
        border-top: 1px solid #999; padding-top: 6px; }
@media screen { body { background: #f4f4f4; }
  body > * { background: #fff; padding: 0 4mm; } }
"""


def _fmt(v, default="〔     〕") -> str:
    return _esc(v) if v else default


def run_petition(
    case_dir: Path,
    out_dir: Path,
    *,
    case_no: str | None = None,
    suspect: str | None = None,
    counsel: str | None = None,
    agency: str | None = None,
) -> dict:
    """Render 청구서.html from the case dir's verify/diff/artifacts."""
    case_dir = Path(case_dir).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    verify = _load_json(case_dir / "verify" / "verify.json")
    if verify is None:  # field runs nest outputs under steps/
        verify = _load_json(case_dir / "steps" / "verify" / "verify.json")
    diff = _load_json(case_dir / "diff" / "diff.json") or _load_json(
        case_dir / "steps" / "diff" / "diff.json")
    boundary = _load_json(case_dir / "boundary" / "boundary.json") or _load_json(
        case_dir / "steps" / "boundary" / "boundary.json")
    kw_audit = _load_json(
        case_dir / "keyword-audit" / "keyword-audit.json") or _load_json(
        case_dir / "steps" / "keyword-audit" / "keyword-audit.json")
    field = _load_json(case_dir / "field.json")
    seizure = (field or {}).get("seizure_info", {})

    items = (verify or {}).get("items", [])
    out_scope = [i for i in items if i.get("scope_verdict") == "out_of_scope"]
    missing = [
        i for i in items
        if any("absent on current disk" in n for n in i.get("notes", []))
    ]
    vsum = (verify or {}).get("summary", {})
    dsum = (diff or {}).get("summary", {})
    raid_dt = seizure.get("raid_datetime") or seizure.get("raid_datetime_utc")

    rows = []
    for n, it in enumerate(out_scope + missing, 1):
        rows.append(
            f"<tr><td>{n}</td><td><code>{_esc(it.get('claimed_path'))}</code></td>"
            f"<td>{_esc((it.get('claimed_sha256') or '—')[:20])}…</td>"
            f"<td>{_esc(it.get('status'))}</td>"
            f"<td>{_esc(it.get('scope_verdict'))}</td></tr>"
        )
    items_table = (
        "<table><tr><th>#</th><th>압수 목록상 경로</th><th>기재 해시(앞부분)</th>"
        f"<th>독립 검증 상태</th><th>범위 판정</th></tr>{''.join(rows)}</table>"
        if rows else "<p>대상 항목 없음.</p>"
    )

    # Grounds 5/6 — only appear when the data supports them.
    special = ""
    n_para = 5
    viol = (boundary or {}).get("summary", {}).get("violations", 0)
    if viol:
        special += (
            f"<p>{n_para}. 압수 목록 중 {viol}건은 본 건 영장 대상인 로컬 "
            "저장매체가 아니라 네트워크 공유·외장 드라이브·클라우드 동기화 "
            "영역의 전자정보로서, 형사소송법 제215조 제3항의 원격지 압수수색 "
            "요건을 갖추지 못한 중대한 위법 압수물입니다.</p>"
        )
        n_para += 1
    asum = (kw_audit or {}).get("summary", {})
    kws = (kw_audit or {}).get("keywords", [])
    if kws and asum.get("overall_noise_ratio") is not None:
        pct = round(asum["overall_noise_ratio"] * 100, 1)
        worst = max(kws, key=lambda k: k.get("noise_ratio", 0))
        special += (
            f"<p>{n_para}. 압수 항목을 영장 키워드별로 역분석한 결과 전체 "
            f"노이즈율(영장 자체 조건 불부합 비율)이 {pct}%에 이르고, 키워드 "
            f"‘{_esc(worst['term'])}’ 단독으로는 "
            f"{round(worst['noise_ratio'] * 100, 1)}%에 이르러 영장의 "
            "구체성 및 비례의 원칙을 위배하였습니다.</p>"
        )
        n_para += 1

    today = datetime.now(timezone.utc).strftime("%Y. %m. %d.")
    doc = f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<title>압수물 환부·폐기 청구서</title><style>{_CSS}</style></head><body>
<h1>압수물 환부·폐기 청구서</h1>

<table class="parties">
<tr><td>사건:</td><td>{_fmt(case_no)}</td></tr>
<tr><td>피압수자:</td><td>{_fmt(suspect)}</td></tr>
<tr><td>청구인:</td><td>{_fmt(counsel)} 위 피압수자의 변호인</td></tr>
<tr><td>피청구인(집행기관):</td><td>{_fmt(agency)}</td></tr>
</table>

<h2>청 구 취 지</h2>
<p>피청구인이 위 사건 압수수색영장 집행 과정에서 영장에 기재된 선별 대상
범위를 벗어나 압수한 전자정보 별지 목록 기재 각 항목에 대하여,
형사소송법 제106조, 제215조 및 제308조의2에 따라 그 폐기 및 원본의
환부를 구합니다.</p>

<h2>청 구 원 인</h2>
<p>1. 청구인 측은 피압수자 소유 전자기기에 대하여 독립 검증 도구
(raidwatch)로 파일시스템 인벤토리, SHA-256 해시 및 압수 목록 대조
검증을 실시하였습니다.</p>
<p>2. 검증 결과, 수사기관이 교부한 압수 목록 {vsum.get('total', '—')}개
항목 중 영장 범위 밖으로 판정된 항목 {vsum.get('out_of_scope', '—')}건,
현재 디스크에 존재하지 않는 항목(반출 추정) {len(missing)}건,
기준선 대비 변경 {dsum.get('modified_unverifiable', 0) + dsum.get('content_changed', 0) if dsum else '—'}건,
삭제 {dsum.get('removed', '—') if dsum else '—'}건이 확인되었습니다.</p>
<p>3. 형사소송법 제106조는 영장에 기재된 것만 압수할 수 있다고 규정하고
있고, 제308조의2는 적법한 절차 없이 수집된 증거의 증거능력을 배제하도록
규정하고 있으며, 제417조는 압수물 환부 등 처분에 대한 준항고를
허용하고 있습니다.</p>
<p>4. 따라서 별지 목록의 범위 외 압수물은 즉시 폐기하고, 이미 반출된
원본은 환부하여야 합니다.</p>
{special}

<h2>별 지: 독립 검증 결과 범위 외·부재 압수물 목록</h2>
{items_table}

<h2>첨 부</h2>
<p>1. raidwatch 검증 리포트(verify.json, diff.json) 및 SHA256SUMS.txt
2. 절차 기록(각 산출물의 생성 시각 및 해시 매니페스트)
3. 증거 봉인 해시(custody.txt — root_hash로 산출물 전체의 시점 고정)</p>

<p class="sig">{_esc(today)}<br><br>
위 청구인 변호사 <span class="line">&nbsp;</span> (인)<br><br>
{_fmt(agency)} 귀중</p>

<p class="meta">본 문서는 raidwatch가 검증 데이터를 바탕으로 자동 생성한
초안입니다. 각 항목의 상태는 관찰 결과이며 법적 판단은 변호인 검토 후
확정하십시오. 생성 시각(UTC): {_esc(utc_now_iso())}
{('· 집행 일시 기록: ' + _esc(raid_dt)) if raid_dt else ''}</p>
</body></html>
"""
    dest = out_dir / "청구서.html"
    dest.write_text(doc, encoding="utf-8")
    report = {
        "generated_utc": utc_now_iso(),
        "petition": str(dest),
        "petition_sha256": sha256_file(dest),
        "items_listed": len(rows),
        "fields": {
            "case_no": case_no, "suspect": suspect,
            "counsel": counsel, "agency": agency,
        },
        "note": (
            "Print-optimized HTML (A4). Open in any browser → print → "
            "sign. Blanks 〔 〕 are for fields only counsel can fill."
        ),
    }
    write_json(out_dir / "petition.json", report)
    write_manifest(out_dir, "petition", {"petition": str(dest)})
    return report
