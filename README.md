# raidwatch

압수수색 **대응 측**(피압수자·변호인·기업 법무팀)을 위한 독립 검증 도구.
수사기관의 선별 과정을 재현·검증·기록하여 범위 초과 압수와 증거 오염에
대한 이의제기·배제 주장(형사소송법 §308-2)·환부 청구의 객관적 근거를 만든다.

표준 라이브러리만 사용. 네트워크 통신 없음.

## 세 가지 사용 시점

| 시점 | 명령 | 역할 |
|---|---|---|
| 사전 (raid 이전) | `baseline`, `watch`, `harden` | 기준선 인벤토리+해시, 변경 감시, OS 감사 기록 활성화 |
| 집행 중 | `watch` (사전 설치 시) | 수사 도구 행위의 수동적 관찰 기록 |
| 사후 | `scan`, `diff`, `verify`, `sources`, `artifacts`, `carve`, `journal` | 독립 재현, 전후 비교, 목록 검증, 원본 회수, 행위 재구성 |
| 사후 (분석) | `boundary`, `keyword-audit`, `containers`, `mirror` | 관할 위반·노이즈율·컨테이너 해시·맞복사 |
| 배포/수거 | `bundle`, `field`, `collect` | 키트 생성 → 의뢰인 PC 실행 → 산출물만 회수 |
| 사무실 | `gui`, `package`, `petition`, `inquiry` | Tkinter 프런트엔드, 검토 패키지, 인쇄 서면, 조사실 확인기 |

## 사용법

```bash
# 1. 사전: 기준선 생성 (평시에 실행)
python -m raidwatch baseline /path/to/pc --out case/<case_id>/baseline
#    대용량 디스크는 --incremental로 재스캔 가속 (size+mtime 불변 시 해시 재사용)

# 2. 사후: 돌려받은 PC와 기준선 비교
python -m raidwatch diff \
  --baseline case/<case_id>/baseline/inventory.db \
  --rescan /path/to/returned-pc \
  --out case/<case_id>/diff

# 3. 영장 조건으로 독립 재현 스캔
python -m raidwatch scan /path --profile warrant-profile.json --out case/<case_id>/scan

# 4. 수사기관이 교부한 선별 목록 검증 (json/csv/txt/pdf)
#    pdf는 텍스트 레이어 자동 추출 — 스캔 PDF는 키트의 OCR-LIST.ps1로 텍스트화
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
#    Windows + 관리자면 --volume C: 로 fsutil 직접 호출도 가능

# 8. 법적 검토 패키지 — 폐기청구 목록 + 절차 기록 + 검토 체크리스트
python -m raidwatch package --case case/<case_id> \
  --out case/<case_id>/package

# 8a. 사전 하드닝 — OS 자체 기록을 켜두는 키트 생성
#     HARDEN.bat(관리자): USN 저널 + 프로세스 감사+명령행 +
#     PS 로깅 + 인쇄/장치 로그. sysmon-raidwatch.xml 동봉.
python -m raidwatch harden --out harden-kit

# 8b. 사무실용 GUI — Tkinter (exe 안에 포함됨)
raidwatch gui

# 9. 현장 배포 키트 — 의뢰인 PC로 보내서 분석 산출물만 회수
#    (단일 exe: 대상 PC에 Python 없어도 됨 — PyInstaller로 1회 빌드)
pyinstaller packaging/raidwatch.spec --clean --noconfirm   # Windows에서 실행
python -m raidwatch bundle --out raidwatch-kit \
  --exe dist/raidwatch.exe \
  --profile profile.json --seized seized-list.txt --baseline inv.db
#   → raidwatch-kit/ (raidwatch.exe + raidwatch.pyz 폴백 + inputs/
#     + RUN.bat/RUN.sh + README + CONFIG.txt)
#   USB·메일로 전달 → 의뢰인이 RUN 실행 → raidwatch-out/ 반환
#   (관리자로 실행하면 --vss 자동: 잠긴 hive/evtx를 스냅샷 경유로 읽음.
#    RUN.bat D:\ \\서버\공유 → 결과 zip을 공유폴더로 바로 반송)
#
#   변호인 프리필 — 아는 답을 미리 채워 보내면 의뢰인은 더블클릭+UAC 예뿐:
python -m raidwatch bundle --out raidwatch-kit \
  --exe dist/raidwatch.exe \
  --raid-date "2026-09-19 14:30" \
  --dest "\\\사무실NAS\raidwatch\사건001" --stamp ask
#   또는 키트 안의 CONFIG.txt를 직접 편집해도 됨 (모르는 항목은
#   비워두면 현장에서 물어봄 — 사건번호 등)

# 10. 원격 수거 — SSH로 키트 전송·실행·결과 회수 + 해시 검증
python -m raidwatch collect --host user@client-pc \
  --kit raidwatch-kit --out case/<case_id>/collected \
  --remote-root 'C:\'

# 11. 맞복사 — 수사관이 가져간 파일 세트를 우리도 똑같이
#     verify 결과 또는 원본 목록에서 경로 해석 → 외장 SSD로 구조 보존 복사
python -m raidwatch mirror --root C:\ \
  --verify case/<case_id>/verify/verify.json --out E:\Seized_Mirror
python -m raidwatch mirror --root C:\ \
  --seized seized-list.pdf --out E:\Seized_Mirror   # 목록 → 즉시 해석·복사

# 12. 인쇄 서면 — 검증 데이터 → A4 환부·폐기 청구서 HTML
python -m raidwatch petition --case case/<case_id> \
  --case-no 2026고단1234 --suspect 홍길동 --counsel 김변호 \
  --agency 서울중앙지방검찰청 --out case/<case_id>/petition

# 13. BitLocker 긴급 보존 — 전원 차단/재부팅 전에 복구키 확보 (관리자)
python -m raidwatch lockbox --out case/<case_id>/lockbox

# 14. PC 잔존 모바일 데이터 — 카톡 PC DB·iTunes/SmartSwitch 백업 보존
python -m raidwatch mobile C:\ --out case/<case_id>/mobile

# 15. 관할 경계 — NAS/외장/클라우드 영역에서 가져간 항목 자동 플래그
python -m raidwatch boundary --seized seized-list.txt --out case/<case_id>/boundary
python -m raidwatch boundary --verify case/<case_id>/verify/verify.json \
  --out case/<case_id>/boundary

# 16. 증거 컨테이너 탐지 — 수사관 외장매체의 .ad1/.e01/.zip 해시 기록
python -m raidwatch containers --out case/<case_id>/containers \
  --since 2026-09-19 --scan E:\ --max-hash-gb 128

# 17. 키워드 노이즈율 — '계약' 키워드로 가져간 3,000건 중 범위 외 비율
python -m raidwatch keyword-audit --seized seized-list.txt \
  --profile warrant.json --root C:\ --out case/<case_id>/keyword-audit

# 18. 조사실 1초 확인 — 수사관이 들이민 파일명 → 범위 판정 즉시 출력
python -m raidwatch inquiry --case case/<case_id>          # 대화형
python -m raidwatch inquiry --case case/<case_id> -q '보고서.hwp'

# 19. 날짜만으로 — 압수 목록이 없어도 "그날 손댄 파일" 전부 수집
#     생성/수정/열람 타임스탬프가 창 안에 있는 파일만 (메타데이터만, 해시 없이 빠름)
python -m raidwatch window --root C:\ --since "2026-09-19 14:30" \
  --out case/<case_id>/window

# 20. 수신측 — 의뢰인이 메일로 보낸 분할 조각을 한 폴더에 모은 뒤
#     복원 + 현장 봉인 해시와 자동 대조 (join-report.json 기록)
python -m raidwatch join raidwatch-results-parts/

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
| 프로그램을 보내서 결과만 받는다 | `bundle`/`field`/`collect` | zipapp 단일 파일 키트 → 의뢰인 PC에서 분석 → 산출물 zip+해시만 회수 |
| 잠긴 파일을 섀도에서 읽는다 | `artifacts --vss` | 기존 VSS(집행 전 상태!) 또는 새 스냅샷으로 잠긴 hive/evtx 복사 |
| 은닉 스트림을 드러낸다 | `artifacts` | NTFS ADS 열거 — `file.txt:숨김:$DATA` 같은 고전적 수법 |
| OS가 미리 다 기록하게 한다 | `harden` | 집행 전 USN/감사정책/PS로깅 활성화 → 수사관 행위가 로그로 남음 |
| 해시 하나로 전체를 봉인한다 | `field` → custody.txt | 산출물 해시의 해시 → 즉시 이메일 발송 = 시점 고정 증거 |
| 수사관이 가져간 걸 똑같이 가져온다 | `mirror` | verify/목록 기준 맞복사 — Direct Probe로 2TB도 즉시 시작 |
| 도장 밑 글자를 읽는다 | OCR `-RemoveRedStamps` | 인주(빨간 도장) 잉크를 지우고 OCR → 인식률 회복 |
| 서면을 바로 뽑는다 | `petition` | 검증 데이터 → A4 인쇄 최적화 환부·폐기 청구서 HTML |
| 전원이 꺼지기 전에 키를 뺀다 | `lockbox` | BitLocker 복구키+볼륨맵 긴급 보존 — 재부팅=영구 잠금 방지 |
| 폰은 가져가도 DB는 남는다 | `mobile` | 카톡 PC DB·iTunes/SmartSwitch 백업·데스크톱 메신저 보존 |
| 영장 없는 NAS를 건드리면 잡힌다 | `boundary` | UNC·매핑드라이브·클라우드 경로 → warrant_territory_violation |
| 수사관의 증거 파일을 먼저 해시한다 | `containers` | 외장매체의 신규 .ad1/.e01/.zip 해시 → 나중에 바꿔치기하면 탄핵 |
| 키워드 폭탄을 숫자로 바꾼다 | `keyword-audit` | 키워드별 노이즈율 95% → 구체성·비례 원칙 위배 수치화 |
| 조사실에서 1초 만에 답한다 | `inquiry` | 파일명 입력 → 범위 판정·diff 상태 즉시 출력 → 진술거부 판단 근거 |
| 목록을 안 줘도 날짜로 잡는다 | `window` | 집행일 이후 생성·수정·열람 파일 전수 — 목록 없이도 "그날 뭘 했는지" |
| 변호인이 답을 대신 쓴다 | `CONFIG.txt` | 키트에 프리필 → 의뢰인은 더블클릭+UAC 예뿐, 결과는 자동 반송 |
| 결과가 커도 메일로 간다 | `field` 자동 | 결과 zip이 2GB 초과 → 지메일 첨부 단위(20MB)로 자동 분할 + JOIN.bat 복원 |
| 받는 쪽도 설치가 필요 없다 | `JOIN.bat` | 조각+SUMS+JOIN.bat를 한 폴더에 → 더블클릭 하나로 복원·조각별 검증·봉인 해시 대조·성공/실패 팝업 (Windows 기본 기능만 사용) |
| 받은 조각을 봉인 해시로 검증한다 | `join` | 분할 파츠 재결합 → custody.txt의 현장 해시와 대조 → 손상 파츠 지목 |

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
`in_scope_partial`(평가된 조건은 전부 일치하지만 일부 조건이 미평가),
`borderline`(일부 조건만 OR = 넓은 해석), `out_of_scope`(어느 해석에도
불해당 → 폐기 청구 근거), `unverifiable`(조건이 있으나 전부 평가 불가 —
예: content 키워드인데 텍스트 추출 불가). 미평가 조건을 `out_of_scope`로
돌리지 않는다 — 방어용 도구가 범위 판정을 날조하면 안 된다.

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
