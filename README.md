# raidwatch

압수수색 **대응 측**(피압수자·변호인·기업 법무팀)을 위한 독립 검증 도구.
수사기관의 선별 과정을 재현·검증·기록하여 범위 초과 압수와 증거 오염에
대한 이의제기·배제 주장(형사소송법 §308-2)·환부 청구의 객관적 근거를 만든다.

표준 라이브러리만 사용. 네트워크 통신 없음.

## 세 가지 사용 시점

| 시점 | 명령 | 역할 |
|---|---|---|
| 사전 (raid 이전) | `baseline`, `watch` | 내 PC 기준선 인벤토리+해시, 변경 감시 |
| 집행 중 | `watch` (사전 설치 시) | 수사 도구 행위의 수동적 관찰 기록 |
| 사후 | `scan`, `diff`, `verify` | 독립 재현 스캔, 전후 변경점 비교, 압수 목록 검증 |

## 사용법

```bash
# 1. 사전: 기준선 생성 (평시에 실행)
python -m raidwatch baseline /path/to/pc --out case/<case_id>/baseline

# 2. 사후: 돌려받은 PC와 기준선 비교
python -m raidwatch diff \
  --baseline case/<case_id>/baseline/inventory.db \
  --rescan /path/to/returned-pc \
  --out case/<case_id>/diff

# 3. 영장 조건으로 독립 재현 스캔
python -m raidwatch scan /path --profile warrant-profile.json --out case/<case_id>/scan

# 4. 수사기관이 교부한 선별 목록 검증 (json/csv/txt)
python -m raidwatch verify \
  --seized seized-list.txt \
  --baseline case/<case_id>/baseline/inventory.db \
  --profile warrant-profile.json \
  --current-root /path/to/returned-pc \
  --out case/<case_id>/verify

# 4a. 종이 목록의 디지털 원본 회수 — 스풀/Temp/휴지통
#     인쇄물을 OCR하기 전에 원본 파일을 먼저 찾는다
python -m raidwatch sources /path/to/seized-pc \
  --out case/<case_id>/sources --since 2026-09-19

# 5. 수사관 행위 재구성 — 어떤 도구로 뭘 했는지
python -m raidwatch artifacts /path/to/seized-pc \
  --out case/<case_id>/artifacts --since 2026-09-19

# 6. 삭제 파일 카빙 — $MFT 덤프에서 삭제 항목 + resident 본문 복구
python -m raidwatch carve --mft mft-dump.bin --out case/<case_id>/carve

# 7. USN 저널 리플레이 — 수사관이 만들고 지운 파일 이력
python -m raidwatch journal --csv usn-export.csv \
  --out case/<case_id>/journal --since 2026-09-19

# 8. 법적 검토 패키지 — 폐기청구 목록 + 절차 기록 묶음
python -m raidwatch package --case case/<case_id> \
  --out case/<case_id>/package

# 감시 모드 (폴링 스냅샷 + 프로세스 모니터링,
#   Ctrl+C 종료 시 watcher_stopped 기록)
python -m raidwatch watch /path --out case/<case_id>/watch --interval 5
```

## 역발상 레퍼토리

| 트릭 | 커맨드 | 원리 |
|---|---|---|
| 종이 말고 원본을 턴다 | `sources` | 인쇄물의 디지털 원본이 스풀/Temp/휴지통에 남는다 |
| 해시 말고 경로만 읽는다 | `verify` | 깨진 경로도 인벤토리와 퍼지 매칭 → 해시는 직접 계산 |
| 수사관 도구의 흔적을 수거한다 | `artifacts` | prefetch/recent/evtx/hive에 어떤 툴로 뭘 했는지 남는다 |
| 열람 흔적을 분류한다 | `diff` | atime만 이동 = 읽기만 함 → "봤지만 안 가져간" 증거 |
| 백데이팅을 잡는다 | `diff` | 집행 중 새 파일인데 mtime이 과거 = timestomp 식재 의심 |
| VSS를 기준선으로 쓴다 | `artifacts` | 윈도우 섀도 카피가 이미 집행 전 상태를 찍어뒀을 수 있다 |
| 수사 프로세스를 본다 | `watch` | 패스마다 프로세스 스냅샷 → 수사 도구 등장/종료 기록 |
| 삭제 파일을 되살린다 | `carve` | $MFT 레코드 안 resident 본문 + $SI/$FN 불일치로 timestomp 탐지 |
| 저널이 전부 기억한다 | `journal` | USN 저널이 수사관의 파일 생성·삭제·이름변경을 다 기록한다 |
| 파일 안을 들여다본다 | `scan` | `in: content` 키워드 → txt/Office/PDF/HWP까지 내용 선별 재현 |
| 판사에게 줄 묶음을 만든다 | `package` | 범위 초과 목록+타임라인+해시 인덱스 → 폐기청구 부속 문서 |

## 검증 시 두 가지 역발상

1. **종이를 읽지 말고 원본 파일을 턴다** (`sources`): 수사관이 준
   인쇄물은 도구의 출력물이고, 스풀 파일·Temp 임시 산출물·휴지통에
   원본이 남는 경우가 많다. 먼저 회수해서 문자열 추출로 복원한다.
   (미할당 영역 카빙은 별도 과제)
2. **해시를 읽지 말고 경로만 매핑한다** (`verify` 퍼지 매칭): 도장에
   가린 해시는 OCR이 불가능하지만, 경로는 깨져도(`U5ers`→`Users`)
   혼동문자 정규화+유사도 매칭으로 인벤토리의 진짜 경로를 찾는다.
   해시는 찾은 파일에서 직접 계산하면 된다.

## 영장 프로필 (warrant-profile.json)

```json
{
  "profile_version": "1.0",
  "case_id": "2026-xx-xxxx",
  "warrant": { "issued": "2026-09-15", "scope_note": "영장 별지 조건" },
  "criteria": {
    "keywords": [
      { "term": "계약서" },
      { "term": "비밀회계", "in": "content" }
    ],
    "extensions": [".hwp", ".docx", ".pdf"],
    "filename_patterns": ["*회계*"],
    "date_ranges": [{ "field": "mtime", "from": "2025-01-01", "to": "2026-09-19" }],
    "path_include": ["Users/*/Documents/*"],
    "path_exclude": ["Windows/*"]
  }
}
```

범위 판정은 이중으로 한다: `in_scope`(지정된 모든 조건 AND = 좁은 해석),
`borderline`(일부 조건만 OR = 넓은 해석), `out_of_scope`(어느 해석에도
불해당 → 폐기 청구 근거).

`"in": "content"` 키워드는 파일 본문에서 검색한다 — 지원 형식은
txt/csv/log/eml 등 텍스트(UTF-8·CP949·UTF-16 폴백), docx/xlsx/pptx,
HWPX, legacy HWP(내장 CFB 파서), PDF 텍스트 스트림, zip 멤버 재귀.
추출 실패 파일은 `extract_failed`로 표시되며 조용히 매칭하지 않는다.

## 설계 원칙

- **관찰만 한다**: 수사 도구 차단·파일 은닉·자동 삭제 같은 능동 방해
  기능은 없다 (증거인멸/공무집행방해 논점 방지).
- **조용한 실패 금지**: 읽기 실패·추출 실패·스킵은 전부 목록에 기록.
- **재현성**: 동일 입력 + 동일 프로필 → 동일 결과 (결정적 정렬).
- **자기 검증 가능**: 모든 출력에 도구 버전·입력 해시·프로필 해시 표기.

자세한 스펙: `docs/raidwatch-spec.md`

## 테스트

```bash
python -m unittest discover -s tests
```
