# 압수수색 대응용 독립 검증 도구 (Defense-Side Verification) 스펙

> 상태: 초안 v2 — 목적 재정의 (수사기관용 선별 도구 → 피압수자/대응 측 검증 도구)
> 범위: PC 전용. 모바일/클라우드 제외.
> 목적: 압수수색 집행 시 수사기관의 선별 과정을 피압수자·변호인 측이
> 독립적으로 재현·검증·기록하고, 범위 초과 압수와 증거 오염에 대한
> 이의제기·배제 주장(§308-2)·환부 청구의 객관적 근거를 만든다.

## 1. 배경: 왜 대응 도구가 필요한가

### 1.1 법적 구도

- 형사소송법 제106조 제3항: 사건 관련 전자정보만 선별 압수해야 하고,
  피압수자 측은 탐색·선별 과정에 **참여권(참관)**을 가진다.
- 수사기관이 현장 선별 없이 매체를 통째로 반출하거나 영장 범위를 넘는
  정보를 압수하면, 제308조의2(위법수집증거 배제법칙)의 문제가 된다.
- 그런데 이를 다투려면 피압수자 측이 **"무엇이 있었고, 무엇을 가져갔고,
  그 과정에서 무엇이 바뀌었는가"**를 자기 증거로 입증해야 한다.
  수사기관의 목록을 그대로 믿고 이의제기를 하는 것은 근거가 없는
  진술에 불과하다.

### 1.2 검증 대상이 되는 수사기관 측 도구

현장에서 우리가 검증해야 할 상대방 도구 (스펙 v1의 "경쟁자"가 아니라
**감시 대상**):

- 선별/수집: 포크레인(인섹시큐리티), DFAS Pro(유락/에이블시큐),
  FTK Imager AD1, Magnet OUTRIDER, KAPE, EnCase Portable, 국가용 DFT
- 이미징: Tableau TX1, Logicube Falcon/Talon, FTK Imager, X-Ways
- 모바일: MD-LIVE/NEXT, Cellebrite (범위 밖이지만 현장 목록에는 등장)
- 정부 시스템: 대검 D-NET/e-DIS, 경찰 디지털증거 통합관리시스템

이들의 공통 취약점(대응 논점):

- **블랙박스**: 검색 조건·제외 항목·스킵 이유를 피압수자 측이 재현할 수 없다
- **결과 중심 산출물**: "가져간 목록"은 주지만 "보고 안 가져간 것",
  "스킵한 것", "조건 해석"은 남기지 않는다
- **프로세스 기록 부재**: 수사기관 도구가 대상 PC에서 무엇을 실행하고
  무엇을 썼는지(메타데이터 변경, 파일 생성) 독립 기록이 없다

### 1.3 대응 도구의 세 가지 사용 시점

| 시점 | 상황 | 도구 역할 |
|---|---|---|
| 사전 (raid 이전) | 압수수색 가능성을 예상하는 기업/개인 | 기준선(baseline) 인벤토리+해시 생성, 감시 에이전트(선택) 상주 |
| 집행 중 | 수사관이 현장에서 선별·복제·반출 | 감시(watcher): 수사 도구의 프로세스/파일 접근/쓰기 기록, 독립 스캔으로 동일 조건 hit 목록 생성 |
| 사후 | 선별 목록·복제본 교부, 참관 선별, 공판 준비 | 목록 검증, 범위 초과 분류, 무관 정보 폐기 요청 목록, 변경점 비교 리포트 |

사후 모드가 가장 현실적이고, 사전 기준선이 있으면 사후 검증이 배로 강해진다.
집행 중 watcher는 대상 PC를 수사기관이 통제하므로 **사전 설치가 전제**다.

## 2. 코어 엔진 (수사기관 측 스펙과 공유)

아래는 수사 측 선별 도구와 같은 기술 기반이지만 용도가 검증이다.

### 2.1 파일 열거 + 기준선(baseline)

- 대상 볼륨의 전체 파일 인벤토리: 경로, 파일명, 크기, MAC시각, 속성,
  ADS, SHA-256. 결정적 정렬로 저장.
- 삭제 파일/미할당 영역 스캔 옵션 (수사기관이 "복원"했다고 주장하는
  파일이 실제 존재했는지 대조하는 근거)
- 출력: `baseline/<timestamp>/inventory.db` (SQLite) + 매니페스트 해시.
  소유자가 평시에 돌려두는 자기 PC의 감사 스냅샷이다.
- 주기적 재실행 시 diff 리포트(증감 파일 목록) — 정상 사용 이력 기록이
  그 자체로 "수사기관이 파일을 심었다/바꿨다" 주장에 대한 대응 자료.

### 2.2 선별 조건 (Search Profile)

영장 별지의 압수 조건을 그대로 JSON으로 옮겨 **독립 재현 스캔**에 쓴다.

```jsonc
{
  "profile_version": "1.0",
  "case_id": "2026-xx-xxxx",
  "warrant": { "issued": "2026-09-15", "scope_note": "영장 별지 조건 원문" },
  "criteria": {
    "keywords": [ { "term": "...", "regex": false } ],
    "extensions": [".hwp", ".hwpx", ".docx", ".pdf"],
    "filename_patterns": ["*회계*"],
    "date_ranges": [ { "field": "mtime", "from": "...", "to": "..." } ],
    "path_include": ["C:\\Users\\*\\Documents\\*"],
    "path_exclude": ["C:\\Windows\\*"]
  }
}
```

핵심: 수사기관이 조건을 어떻게 해석했는지 모르기 때문에 **해석 범위를
넓게/좁게 양쪽으로 스캔**한다. 영장 문언상 넓은 해석으로도 매칭되지
않는 파일이 압수 목록에 있으면 범위 초과의 직접 근거가 된다.

### 2.3 내용 검색 ✅ 구현됨 (`scan` + `in: content` 키워드)

- 텍스트 추출 구현: plain text(UTF-8/CP949/UTF-16 폴백), docx/xlsx/pptx,
  HWPX(zip+XML), **legacy HWP**(내장 CFB 파서 → PrvText + zlib 압축
  BodyText의 UTF-16 런), PDF(deflate 스트림의 Tj/TJ 문자열),
  zip 멤버 재귀(깊이 1)
- 추출 실패/용량 초과/권한 거부는 전부 상태로 기록(`extract_failed`,
  `content_extract_failed` 카운트) — 수사기관이 "검색했다"고 주장한
  범위가 실제로 검색 가능했는지 교차 확인
- 한계 명시: 추출은 위치정보 없는 best-effort 텍스트다. 암호화/DRM
  문서, PDF 폰트 매핑(ToUnicode 미포함), 스풀 RAW 모드는 미지원 — 매칭
  실패를 "내용 부재"의 증거로 쓰지 않는다.

### 2.4 Hit 목록

기존 스키마 유지: seq, path, filename, size, MAC시각, sha256,
matched 조건, status, deleted. 여기에 대응용 필드 추가:

| 추가 필드 | 설명 |
|---|---|
| in_seized_list | 수사기관이 교부한 선별 목록에 등장하는가 |
| scope_verdict | `in_scope` / `in_scope_partial` / `borderline` / `out_of_scope` / `unverifiable` — 미평가 조건은 out_of_scope가 아니라 unverifiable/partial로 정직하게 표시 |
| modified_during_raid | baseline 대비 변경 여부 (mtime/hash/size) |

## 3. 집행 중 감시 (Watcher) — 사전 설치 전제

피압수자 PC에 미리 상주하거나, 집행 시작 시점에 실행되어 수사기관의
행위를 **수동적으로 관찰**한다. 수사기관 도구의 동작을 방해하지 않는다
(간섭하면 증거인멸/공무집행방해 논점이 되므로 읽기 전용 관찰만).

- 프로세스/서비스 실행 이력 (새 프로세스, 외장 매체 실행 파일)
- 파일 생성·수정·삭제·이름변경 이벤트 (USN 저널, Sysmon, ETW)
- 수사기관 도구가 읽은 파일 범위 vs 실제 복제 목록 비교 단서
- 볼륨 마운트/언마운트, 외장 매체 연결 이력
- 화면 잠금/절전 우회 시도, 시스템 시각 변경 이벤트
- 감시 로그는 수집 매체가 아니라 **피압수자 측 별도 위치**에 실시간
  기록(로컬 로그 + 가능하면 오프사이트 미러 — 단, 외부 전송은 해당
  기기 소유자의 합법적 권한 범위 내에서만)
- 수사기관이 watcher를 종료/제거하면 그 사실 자체를 기록

현실적 제약을 명시: 수사기관이 PC 통제권을 가지므로 watcher 생존은
보장되지 않는다. 죽더라도 종료 시점까지의 로그와 "종료된 사실"이
남는 것으로 설계한다.

## 4. 사후 검증 (가장 강한 모드)

### 4.1 선별 목록 검증

- 수사기관이 교부한 목록(종이/PDF/파일)을 입력으로 파싱
- 목록의 각 항목과 기준선/잔여 원본을 대조:
  - 목록의 해시가 실제 파일 해시와 일치하는가
  - 목록에 없는데 가져간 파일이 있는가 (복제 대상 스토리지 열람 가능 시)
  - 영장 조건으로 매칭되지 않는 항목이 목록에 있는가 → `out_of_scope`
- 영장 해석표: 문언 해석별(좁게/넓게)로 항목을 분류해 "어느 해석에서도
  관련성이 없는 항목"을 자동 추출
- **퍼지 경로 매칭** (OCR 손상 대응): 종이 목록을 OCR로 읽으면 경로가
  깨진다(`U5ers`→`Users`, `0`↔`O`, `1`↔`l`). 도장에 가린 해시는 사실상
  판독 불가. 따라서 경로는 혼동문자 정규화 + 유사도(SequenceMatcher)
  매칭으로 인벤토리의 진짜 경로에 매핑하고, 해시는 인쇄물에서 읽지 않고
  **우리 인벤토리에서 직접 계산**한다. 1순위·2순위 후보 점수차가
  일정 이하이면 모호(`ambiguous`)로 표시해 잘못 매핑하지 않는다.

### 4.1a 원본 목록 회수 (`raidwatch sources`)

수사기관이 교부한 종이는 인쇄물일 뿐이고, 그 원본 디지털 파일이 피압수
PC에 남아 있을 가능성이 높다. 종이를 OCR하기 전에 원본을 먼저 찾는다:

- **프린터 스풀**: `Windows/System32/spool/PRINTERS/*.SPL/.SHD` — 인쇄
  명령 직전의 출력 데이터 원본. 문자열 추출(ASCII/UTF-16LE, 한글 포함)로
  목록 텍스트 복원 시도.
- **Temp 산출물**: `Users/*/AppData/Local/Temp/` 아래 리포트성 파일
  (csv/xlsx/html/xml/pdf 또는 목록성 파일명) — 포렌식 도구들이 인쇄용
  산출물을 만들 때 거치는 위치. `--since`로 집행 시각 이후 파일만 수집.
- **휴지통**: `$Recycle.Bin/**` — 삭제됐지만 복구 가능한 목록 파일.
- 수집물은 사본+해시+출처 이유(spool/temp/recycle_bin)로 보존하고,
  텍스트 계열은 `.strings.txt`로 추출본을 둔다.
- 삭제된 목록 파일의 추가 회수 경로는 `raidwatch carve`(§4.3b)로
  커버한다 — $MFT 덤프의 resident 데이터는 레코드 안에 온전히 남는다.
  비-resident 데이터(미할당 클러스터)는 raw 디스크 이미지가 필요해
  여전히 범위 밖이다.

### 4.2 변경점 비교 (기준선 vs 사후 상태)

- 압수 후 돌려받은 PC/매체를 다시 인벤토리 → baseline과 diff
- 수사 과정에서 변경된 파일 목록: 메타데이터만 바뀐 것(열람), 내용이
  바뀐 것(수정 의심), 새로 생긴 것(도구 생성물 vs 식재 의심 구분 단서),
  사라진 것
- **열람 분류**: 해시 동일 + mtime 동일 + atime만 이동 → `accessed`
  (수정이 아니라 읽기만 한 흔적 — "봤지만 안 가져간" 증거와 연계).
  단 Windows 기본 설정은 atime 기록이 꺼져 있을 수 있어 빈 결과일 수
  있음을 리포트에 명시한다.
- **자기 오염 방지**: 인벤토리 해싱 자체가 atime을 전진시키면 모든
  파일이 `accessed`로 오탐된다. 이를 막기 위해 O_NOATIME(Linux)을
  시도하고, 불가하면 해싱 직후 atime/mtime을 utime으로 복원한다
  (Windows는 ctime이 생성시각이라 무손실; POSIX는 ctime이 bump되어
  ctime 단독 변경은 스캔 아티팩트일 수 있음을 리포트에 명시).
  인벤토리 meta의 `atime_preservation`(o_noatime/restored/mixed/none)
  로 신뢰도를 노출한다.
- **백데이팅 탐지**: 집행 창에 새로 나타난 파일인데 mtime이 기준선
  생성 시각보다 과거 → `backdated` 플래그 (timestomp로 위장된 식재
  의심). 생성 시각(birth time)과 mtime의 모순은 위조의 고전적 단서다.
- 수사기관 도구의 정상 산출물 패턴과 대조해 "도구 생성물"을 먼저
  분류하고 나머지를 미지 변경으로 표시

### 4.3 무관 정보 폐기·환부 청구 근거

- `out_of_scope` 항목 목록 → 삭제·폐기 요청서의 부속 목록으로 출력
- 가선별로 반출된 복제본(참관 시 열람 가능)에서 무관 정보 분류 지원
- 이의제기 타임라인: 언제 어떤 항목에 이의를 제기했는지 기록 관리

### 4.3a 수사관 행위 재구성 (`raidwatch artifacts`)

수사관의 도구는 대상 PC에 자기 흔적을 남긴다 — 그걸 수거해 "누가 무엇을
언제 실행하고 무엇을 봤는지"를 재구성한다. 전부 읽기 전용 관찰이다.

- **Prefetch + 드라이버**: `Windows/Prefetch/*.pf`, `System32/drivers` —
  알려진 수사 도구 실행 파일(FTK Imager, EnCase, AXIOM, OUTRIDER,
  포크레인, KAPE, MD-LIVE, DumpIt, WinPmem 등)의 실행 흔적을 식별해
  `observed_investigator_tools`로 출력. "어떤 도구로 선별했는가"는
  재현성 질의의 첫 질문이다.
- **Recent items / 점프리스트 .lnk**: `.lnk` 구조 파서로 링크 타깃의
  정확한 경로(LinkInfo+접미사 유니코드 포함)·작업 디렉터리·인자·
  생성/접근/수정 시각을 복원 — "봤지만 압수하지 않은" 파일 목록의
  단서 (참관 없이도 열람 행위 재구성).
- **이벤트 로그 사본 + 레코드 타임라인**: System/Security/PrintService/
  Kernel-PnP `.evtx` 수집 + deflate 청크 해제 + ELF 레코드 파싱으로
  레코드ID·UTC 시각의 이벤트 타임라인 생성 — 인쇄·로그 삭제·장치 연결의
  시간축. 이벤트ID/필드 수준 파싱은 chainsaw 등 별도 도구 영역.
- **레지스트리 하이브 구조 파싱**: regf 셀 파서로 SYSTEM/SOFTWARE/
  NTUSER.DAT/Amcache.hve에서 구조화 추출 — ShimCache(실행된 도구 경로,
  Win10 `00ts` 레코드 + 스캔 폴백), USBSTOR(꽂힌 장치 시리얼·Friendly
  Name), UserAssist(GUI 실행+횟수+최종 실행), AmCache(경로+SHA1),
  Run 키, RecentDocs. 발견된 경로는 수사 도구 마커와 대조해
  `observed_investigator_tools`에 피드. 주의: ShimCache 타임스탬프는
  실행 시각이 아니라 파일 mtime임을 명시. setupapi.dev.log는 문자열 추출.
- **VSS 스냅샷 감지**: 기준선을 미리 못 찍었어도 Windows 볼륨 섀도
  카피에 집행 이전 상태가 남아 있을 수 있다 — 존재하면 "공짜 기준선".
  감지만 수행하고 존재 여부를 리포트.
- **Prefetch 정밀 파싱**: `.pf` 본체를 파싱해 실행 파일명·실행 횟수·
  마지막 실행 시각까지 복원 (v23/26/30; Win10+ MAM 압축은 Windows에서
  ntdll로 해제 시도, 실패 시 `compressed_unparsed`로 명시).
- **EVTX 청크 해제 + 타임라인**: `.evtx`의 deflate 압축 청크를 풀어
  binxml 스트림을 복원하고 ELF 레코드 헤더(시그니처·크기·레코드ID·
  FILETIME)를 파싱해 실제 이벤트 타임라인을 만든다. 이벤트 데이터
  문자열도 UTF-16LE로 추출. 이벤트 ID 수준의 완전 binxml 파싱은 별도
  도구(chainsaw 등) 영역임을 명시.

### 4.3b 삭제 파일 카빙 + USN 저널 (`raidwatch carve`, `raidwatch journal`)

- **`carve`**: $MFT 덤프(이미징 도구/섀도 카피로 확보)를 파싱해 삭제
  레코드를 나열하고, resident `$DATA` 페이로드(소형 파일은 레코드 안에
  본문 전체)를 복구한다 — Temp 임시 목록 파일 카빙의 실체. 추가로
  `$STANDARD_INFORMATION`과 `$FILE_NAME` 시각 불일치(`si_fn_mismatch`)를
  플래그 — 타임스톰프 도구가 $SI만 고치고 $FN을 놓치는 고전적 패턴.
- **`journal`**: NTFS USN 저널(fsutil 또는 CSV export)을 파싱해 집행
  창의 file_create/file_delete/rename/security_change 이벤트를
  재구성 — 수사관 도구가 만들고 지운 산출물, 로그 청소 흔적의
  고해상도 기록. 저널 wrap/비활성화로 생긴 공백 자체도 기록한다.

### 4.4 리포트

1. **검증 리포트** — 수사기관 목록 vs 독립 스캔 대조표, 해시 불일치,
   범위 초과 항목, 해석별 scope verdict 요약
2. **변경점 리포트** — 집행 전후 파일시스템 diff, 분류(도구 생성물/
   열람 흔적/미지 변경), 관측 근거(경로·오프셋·이벤트ID)
3. **절차 기록 패키지** — watcher 로그, 참관 타임라인, 이의제기 기록,
   수사기관이 제공한 문서 목록 — §308-2 주장 또는 항고/준항고 근거로
   변호인이 쓸 수 있는 묶음

### 4.5 현장 배포·원격 수거 (`raidwatch bundle` / `field` / `collect`)

의뢰인 PC에 직접 앉을 수 없는 경우, 분석 도구 자체를 보내서 **분석
산출물만** 회수한다:

- **`bundle`**: 자체 완결 키트 디렉터리 생성 — `raidwatch.exe`
  (PyInstaller 단일 바이너리, 대상 PC에 Python 불필요 — 대부분의
  피압수자 PC는 Python이 없으므로 사실상 필수) + `raidwatch.pyz`
  폴백 + `inputs/`(프로필·압수 목록·기준선 DB 선택적 임베드) +
  `RUN.bat`/`RUN.sh` + README. USB·메일로 전달해 의뢰인이 더블클릭으로
  실행. PyInstaller는 크로스컴파일 불가 → Windows exe는 Windows에서
  빌드(`packaging/raidwatch.spec`, CI 워크플로우 제공).
- **`field`**: 키트 내부에서 도는 파이프라인 — inputs에 존재하는
  입력물만 감지해 sources/artifacts는 항상, scan/verify/diff는 조건
  충족 시 실행. 한 단계가 실패해도 나머지는 계속(부분 결과 보장).
  출력은 `raidwatch-out/`에만 생기며 `raidwatch-results.zip` +
  `SHA256SUMS.txt`로 묶인다 — 디스크 대량 수집이 아니라 분석
  산출물+의도적 증거 사본만 반출.
- **`collect`**: SSH(scp/ssh subprocess, 외부 의존 없음)로 키트 전송
  → 원격 실행 → 결과 아카이브 다운로드 → SHA256SUMS 대조로 전송
  무결성 검증. 키 인증 전용(BatchMode) — 비밀번호 프롬프트에 멈추지
  않음. Windows OpenSSH·POSIX 호스트 모두 대상.
- 한계: Windows exe는 Windows 머신/CI에서 1회 빌드 필요(PyInstaller
  크로스컴파일 불가 — `.github/workflows/build-exe.yml`로 windows-
  latest 빌드 지원); exe 미포함 키트는 Python 폴백으로 동작하나 실전
  대상 PC엔 exe 경로가 사실상 필수. SSH 서버 미설치 시 수동 키트
  경로만 가능. PyInstaller onefile은 일부 AV에서 오탐 가능 —
  코드서명 인증서 확보 시 권장.

## 5. 안전 및 설계 원칙

- **수사 방해 금지**: watcher는 관찰만. 수사 도구 프로세스 차단,
  파일 은닉, 자동 삭제 같은 능동 방해 기능은 만들지 않는다 — 법적으로
  위험하고 도구 존재 이유를 스스로 무너뜨림.
- **자기 무결성**: 도구 바이너리/설정/기준선 데이터의 해시를 기록하고,
  생성하는 모든 리포트에 도구 버전과 입력 해시를 표기 — "대응 측
  도구도 검증 가능해야" 진정성립 대응이 성립.
- **재현성**: 동일 입력 + 동일 프로필 → 동일 결과. 결정적 정렬.
- **조용한 실패 금지**: 접근 불가·파싱 실패는 전부 기록. 수사기관 목록의
  불일치를 과장하지 않기 위해 "확인 불가" 카테고리를 명시적으로 둔다.
- **프라이버시**: 이 도구는 피압수자 자기 기기/자기 데이터에 대한
  감사이므로 대상은 본인(또는 위임받은 조직) 소유 매체로 한정.
- **오프라인 동작**: 수사 현장에서 네트워크 의존 금지(오프사이트 미러는
  사전 합법 설정 시에만 선택).

## 6. 기술 방향 (후보)

- 언어: Python + PyInstaller 단일 exe (기존 `rapidtriage`의 해시/케이스DB/
  리포트 자산 재사용). watcher의 저수준 이벤트 캡처만 네이티브
  (ETW/USN reader) 검토.
- 기준선 DB: SQLite (`case_db` 패턴 재사용).
- watcher: Sysmon 로그 소비 + USN 저널 리더 + 주기적 프로세스/볼륨
  스냅샷. Sysmon 사전 설치가 가능하면 가장 싼 경로.
- 목록 파싱: 수사기관 교부 목록은 종이/PDF/XLSX가 섞이므로
  OCR+표 파싱 + 수동 입력 UI 병행.
- `rapidtriage` 연동: 검증 결과를 case로 관리, 타임라인/보고서 재사용.

## 7. 범위 밖 (명시적 제외)

- 모바일 기기 (MD 계열 상대 검증은 별개 프로젝트)
- 수사기관 도구의 역공학/크랙 — 목록·산출물 수준의 검증만
- 클라우드/원격지 데이터
- 능동적 수사 방해·증거 은닉·데이터 삭제 기능 (설계상 금지)
- 법률 자문 — 리포트는 변호인 검토용 자료이며 법적 판단을 대신하지 않음

## 8. 마일스톤 (제안)

| 단계 | 내용 | 상태 |
|---|---|---|
| M1 | 기준선: 파일 열거 + 해시 + SQLite 인벤토리 + 매니페스트 | ✅ `raidwatch baseline` |
| M2 | 프로필 기반 독립 스캔(속성 선별) + hit 목록 + 영장 해석별 분류 | ✅ `raidwatch scan` |
| M3 | 사후 diff: 기준선 vs 재인벤토리 비교 + 변경점 분류 리포트 | ✅ `raidwatch diff` (열람 `accessed` 분류 + 백데이팅 식재 탐지) |
| M4 | 수사기관 목록 파싱 + 해시 대조 + out_of_scope 추출 + 검증 리포트 | ✅ `raidwatch verify` — json/csv/txt/pdf + **전자정보확인서 상세목록 .xlsx**(연번/파일명/경로/SHA1 다중시트, stdlib 파서) + 수집기 report.json(`likely_seized_files`); 주장 sha1/md5는 `--current-root`에서 실물 재계산 검증 (OCR 손상 경로 퍼지 매칭 포함) |
| M4a | 원본 목록 회수: 스풀/Temp/휴지통 수집 + 문자열 추출 | ✅ `raidwatch sources` |
| M4b | 수사관 행위 재구성: prefetch 정밀 파싱/evtx 청크 해제+레코드 타임라인/regf 하이브 구조 파싱(ShimCache·USBSTOR·UserAssist·AmCache)/lnk 파서/VSS 감지 | ✅ `raidwatch artifacts` |
| M4c | 삭제 파일 카빙: $MFT 덤프 파싱 + resident 데이터 복구 + $SI/$FN 타임스톰프 불일치 탐지 | ✅ `raidwatch carve` (비-resident/미할당 클러스터는 미구현) |
| M4d | USN 저널 리플레이: 집행 중 파일 생성·삭제·이름변경 이력 | ✅ `raidwatch journal` (fsutil 또는 CSV export 입력) |
| M5 | 내용 검색(텍스트 추출/키워드)으로 선별 조건 재현 강화 | ✅ `scan`에 `in: content` — txt/Office/PDF/HWP·HWPX/zip 재귀 (best-effort 추출, `extract_failed` 명시) |
| M6 | watcher: USN/Sysmon 기반 집행 중 감시 + 종료 기록 | 🔶 `raidwatch watch` — 폴링 스냅샷 + 프로세스 등장/종료 이벤트(포터블); USN은 `journal`으로 사후 커버, Sysmon/ETW 네이티브는 미구현 |
| M7 | 폐기·환부 청구용 무관 정보 목록 + 절차 기록 패키지 | ✅ `raidwatch package` — 범위 초과/부재/백데이팅 목록 + 타임라인 + 해시 인덱스 |
| M8 | 현장 배포·원격 수거: 키트 빌드 + 현장 파이프라인 + SSH 회수 | ✅ `raidwatch bundle`/`field`/`collect` — PyInstaller 단일 exe(대상에 Python 불필요) + pyz 폴백 + 산출물 zip + SHA256SUMS 검증 |
| M9 | 잠금 파일 도달: 기존 VSS 섀도 경유 읽기(읽기전용) + `--vss` 신규 스냅샷(관리자, 자동 해제) | ✅ `artifacts`/`field --vss` — 라이브 hive·evtx를 GLOBALROOT 섀도 경로로 복사, `via_shadow` 기록 |
| M10 | NTFS ADS 열거(은닉 스트림 탐지, PS, 타임아웃 캡) | ✅ `artifacts` → `alternate_data_streams` (Windows only, 부분 결과도 보존) |
| M11 | 사전 하드닝 키트: USN 저널+프로세스 감사+명령행+PS 로깅+인쇄/장치 로그 + Sysmon 설정 + REVERT | ✅ `raidwatch harden` — HARDEN.bat/REVERT.bat/sysmon-raidwatch.xml/README 생성 |
| M12 | 증거 봉인: 산출물 해시의 해시(root_hash) + 시점 고정 안내 | ✅ field 산출 `custody.txt` — 즉시 이메일 발송/RFC3161 안내 |
| M13 | 사무실 GUI | ✅ `raidwatch gui` — Tkinter(exe 내장), baseline/field/bundle 버튼 |
| M14 | 변호인 검토 체크리스트 자동 생성 | ✅ `package` → `검토체크리스트.md` (데이터 기반 항목) |
| M15 | 맞복사 수집: 수사관이 가져간 파일 세트를 구조 보존+우리 해시로 복제 | ✅ `raidwatch mirror` — verify.json 또는 원본 목록에서 해석, `MIRROR-SHA256SUMS.txt` |
| M16 | 인주 마스킹 OCR 전처리 | ✅ `OCR-LIST.ps1 -RemoveRedStamps` — 빨간 도장 잉크를 지우고 OCR (RUN.bat이 질문함) |
| M17 | 법원 제출 서면: 인쇄 최적화 환부·폐기 청구서 | ✅ `raidwatch petition` → `청구서.html` (A4, 당사자/서명란, 별지 목록 자동 삽입) |
| M18 | BitLocker 긴급 보존 | ✅ `raidwatch lockbox` — 복구키·프로텍터·볼륨맵 (Windows, 관리자 권한 필요 부분은 항목별 기록) |
| M19 | PC 잔존 모바일 데이터 보존 | ✅ `raidwatch mobile`/`pc-mobile` — 카톡 PC·iTunes·SmartSwitch·WhatsApp/Telegram Desktop |
| M20 | mirror 속도: Direct Probe — 목록 경로를 `is_file`로 직접 확인, 깨진 경로만 부모 서브트리로 좁혀 퍼지매칭 | ✅ `mirror --seized` — 전체 디스크 인벤토리 제거, 2TB도 즉시 복사 시작 |
| M21 | RUN.bat UAC 자동 승격 | ✅ `net session` 체크 → 미승격 시 `Start-Process -Verb RunAs` 재기동, 거절 시 제한 커버리지로 계속, 승격 성공 시 `--vss` 자동 |
| M22 | 관할 경계 적발: UNC·매핑 네트워크 드라이브·리무버블·클라우드 동기화 경로 플래그 | ✅ `raidwatch boundary` — `warrant_territory_violation` 플래그, GetDriveTypeW 기반(비Windows/오프라인은 `local_unverified`로 과장 금지), petition 자동 반영 |
| M23 | 수사관 증거 컨테이너 해시 | ✅ `raidwatch containers` — 부착 외장매체의 .ad1/.e01/.ex01/.l01/.aff/.zip 등 탐지·해시 기록(부트 볼륨 제외, 깊이·엔트리 상한, `--max-hash-gb` 초과 시 이름/크기/mtime만 기록) — 이후 제시 해시와 다르면 증거 탄핵 |
| M24 | 키워드 노이즈율 계측 | ✅ `raidwatch keyword-audit` — 키워드 귀속 항목 중 영장 자체 조건 불부합 비율(out_of_scope·excluded·borderline; unverifiable은 노이즈에서 제외), 무귀속 항목 별도 집계, petition 자동 반영 |
| M25 | 조사실 1초 확인기 | ✅ `raidwatch inquiry` — case 디렉터리의 verify/diff 인덱스에서 파일명·경로 조각으로 즉시 판정 출력, 대화형 또는 `-q` 단발, `--out` 시 조회 로그 보존 |
| M26 | 변호인 프리필 키트 | ✅ 키트 내 `CONFIG.txt`(raid_datetime/dest/stamp/notes) + `bundle --raid-date/--dest/--stamp/--notes` — 프리필된 질문은 RUN.bat/RUN.sh가 건너뜀, 구워 넣은 `inputs\seized.*`도 질문 생략 |
| M27 | 날짜만으로 집행일 행위 수집 | ✅ `raidwatch window --root --since` — 창 안 생성(btime/ctime)·수정(mtime)·열람(atime, accessed_only) 파일 전수, 메타데이터만(해시 없음), 스캔·히트 상한+truncated 기록. field는 since 있고 baseline 없을 때 자동 실행. NTFS atime 비활성 한계 명시 |
| M28 | 클릭 입력 대화상자 | ✅ 키트 내장 `KIT-INPUT.ps1` — WinForms DateTimePicker 달력+OpenFileDialog+인주 체크박스+"모두 건너뛰기" → `inputs\answers.txt`; 프리필 부족분만 표시, WinForms 불가 시 콘솔 폴백 |
| M29 | 결과물 분할 전송 | ✅ field: 결과 zip 2GiB 초과 시 20MiB(지메일 첨부 단위) 분할 → `raidwatch-results-parts/`(.001…+파트별 해시+`JOIN.bat`/`join.sh` 원클릭 복원+안내서), 원본 zip은 분할 후 삭제(whole-zip 해시는 custody에 보존), RUN.bat DEST 반송 시 파츠 폴더도 업로드 |
| M30 | 확인서 자체 감사 | ✅ `raidwatch certcheck` — 확인서 패키지(dir/zip/xlsx) 내부 모순 탐지: 연번 누락·중복·비단조, 무효 해시(hex/길이), 파일명↔경로 basename 불일치, 동일 해시·경로 중복 기재, 확인서 발급시각 이후 mtime(불가능 상태), 인쇄 상세목록 PDF 해시 개수↔xlsx 행 대조, 중첩 zip 1단계 재귀, `--root`로 실물 크기·주장알고리즘 해시 재검증 |
| M31 | 산출물 포맷 통일 변환기 | ✅ `raidwatch convert` — collector 산출물(scan_*/ForensicOutput zip/report.json/likely_seized_files/selected_files/ranked/file_paths/엑셀) → 정규화 `seized.csv`(UTF-8 BOM, Excel 바로 열림, verify/boundary/mirror 입력 재사용). 의미 우선순위(likely_seized > selected > report.json > 전체덤프 file_paths) + 동명 소스는 최신 scan 우선. `claimed_path` 우선 매핑으로 CSV 왕복 재파싱 unparsed 0 보장, 변환 매니페스트(명령·소스·행수) 기록 |

구현: `raidwatch/` 패키지 (Python, `python -m raidwatch`), 테스트
`tests/test_raidwatch.py`. 기존 `rapidtriage` 코어와 분리된 독립 모듈.

## 9. 미결 사항

- 사용 주체 확정: 피압수자 본인 / 기업 법무팀 / 변호인측 디지털포렌식
  전문가 — UI 수준과 리포트 어조가 달라짐
- 사전 설치(기준선+watcher) 시나리오를 1차로 할지, 사후 검증만으로
  시작할지 — M3/M4가 사후만으로도 동작하므로 순서 조정 가능
- watcher의 오프사이트 로그 미러: 합법성(본인 기기/동의)과 현장
  네트워크 가용성 의존 — 옵션으로 둘지 제외할지
- 수사기관 목록 입력 형식: txt/csv/json + 전자정보확인서 상세목록
  xlsx(한글 헤더·다중시트) 직접 파싱, 수집기 report.json의
  `likely_seized_files`도 인식. 텍스트 레이어 있는 PDF는 내장 추출기로
  처리, 스캔 PDF/이미지는 키트 내장 `OCR-LIST.ps1`(Windows WinRT OCR,
  설치 불필요 — 한글 언어팩 필요)로 텍스트화 후 검증. OCR 결과물의
  경로 손상은 퍼지 매칭이 흡수.
- 도구 이름 (작업명 후보: `rapidwatch`, `raid-response`, `verify-seizure`)
- 영장 해석 엔진을 어느 수준까지 자동화할지(키워드 포함관계 추론은
  법률 판단과 인접 — 보조 표시 수준으로 제한할지)
