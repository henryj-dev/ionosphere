# 공유 메일함·권한·디렉터리·캐시 — 게이트 실행판

계획은 [SHARED-MAILBOX-ACL-DIRECTORY-CACHE.md](SHARED-MAILBOX-ACL-DIRECTORY-CACHE.md)다. 이 문서는 순서·통과 조건·잠금만 적는다.

## 0. 체계

### 작업 ID

작업 ID는 `<단계>.T<번호>`다. 한 작업은 한 커밋 크기이며, 삭제된 작업 ID는 재사용하지 않고
`(폐기)`로 남긴다.

### 상태

작업 상태는 `미착수 · 진행 · 완료`, 단계 상태는 `잠김 · 열림 · 봉인 · 무효`만 사용한다.
잠긴 단계의 작업은 시작하지 않는다. `열림`은 모든 선행 단계가 봉인됐다는 뜻이고, `봉인`은
게이트의 모든 검사가 통과되어 커밋 SHA가 저장됐다는 뜻이다.

### 작업 형식

각 작업은 `선행 · 산출 · 되돌리기 · 장치 요구`를 먼저 적고, 이어서 `작업 · 테스트 · 통과`를
적는다. 통과 조건은 명령의 종료 코드, 수치, 파일 내용처럼 기계가 판정할 수 있는 것만 둔다.

### 테스트케이스

각 TC는 `이름 · 단언 · 검출`을 가진다. 검출은 그 테스트가 없을 때 놓치는 구체적인 회귀를
적는다. 사람의 코드 검토나 “깔끔함”은 통과 조건으로 사용하지 않는다.

### GATE와 봉인

게이트 장치는 `scripts/gates/shared-mailbox.ts`다. 첫 단계가 장치를 구현한다.

```text
node scripts/gates/shared-mailbox.ts <단계>
node scripts/gates/shared-mailbox.ts <단계> --seal
node scripts/gates/shared-mailbox.ts <단계> --explain
node scripts/gates/shared-mailbox.ts <단계> --seal --waived "사유"
node scripts/gates/shared-mailbox.ts --status
node scripts/gates/shared-mailbox.ts --assert-order
```

봉인은 `docs/plan/.gates/shared-mailbox/<단계>.json`에 기록한다. 봉인 JSON에는 `phase`,
`sealed`, `head`, `at`, `waived`, `reason`, `checks[{id,ok,measured,limit}]`를 반드시 둔다.
운영 디렉터리나 `.gitignore` 대상에는 봉인을 쓰지 않는다.

장치는 다음을 기계적으로 강제한다.

- R1 순서: 선행 단계 봉인이 없으면 검사 자체를 실행하지 않고 종료 코드 1 이상
- R2 최신성: 봉인의 `head`가 현재 기본 브랜치의 조상이 아니면 `무효`
- R3 재검: `--seal`은 이전 결과를 사용하지 않고 모든 검사를 다시 실행
- `--waived`는 선택 단계에만 허용하며 빈 사유는 거부
- `--assert-order`는 선행 봉인 이후 산출 경로가 변경됐는데 재봉인하지 않았으면 실패

### 수치 원장

계획서의 수치는 아래 GATE에 빠짐없이 연결한다.

| 수치·정책 | 판정 GATE |
|---|---|
| principal 4종, `negative=0` 1차 | G-P0, G-P1 |
| IMAP standard right 11개와 virtual `c/d` | G-P0, G-P4 |
| migration 020~023 | G-P1, G-P10 |
| header name 190 bytes, display 16 KiB, sort 4 KiB, occurrence 32 | G-P7 |
| listing 결과 2,000개, TTL 5~30초, bounded LRU | G-P8 |
| LDAP 1차 3 transport 동작과 4 후순위 항목 | G-P6 |
| 전체 검증 2,383개 테스트·3 skip·smoke | G-P10 |

## 진행 현황

| 단계 | 상태 | 선행 | 게이트 | 봉인 |
|---|---|---|---|---|
| P0 계약·게이트 장치 | 봉인 | 없음 | `node scripts/gates/shared-mailbox.ts P0 --seal` | `docs/plan/.gates/shared-mailbox/P0.json` |
| P1 principal·ACL 스키마 | 봉인 | P0 | `node scripts/gates/shared-mailbox.ts P1 --seal` | `docs/plan/.gates/shared-mailbox/P1.json` |
| P2 Store authorization | 봉인 | P1 | `node scripts/gates/shared-mailbox.ts P2 --seal` | `docs/plan/.gates/shared-mailbox/P2.json` |
| P3 shared account·IMAP namespace | 봉인 | P2 | `node scripts/gates/shared-mailbox.ts P3 --seal` | `docs/plan/.gates/shared-mailbox/P3.json` |
| P4 IMAP ACL 명령 | 열림 | P3 | `node scripts/gates/shared-mailbox.ts P4 --seal` | P4 게이트 통과 후 생성 |
| P5 JMAP shared account | 잠김 | P4 | `node scripts/gates/shared-mailbox.ts P5 --seal` | 없음 |
| P6 LDAP/AD mapping | 잠김 | P5 | `node scripts/gates/shared-mailbox.ts P6 --seal` | 없음 |
| P7 header projection·backfill | 잠김 | P6 | `node scripts/gates/shared-mailbox.ts P7 --seal` | 없음 |
| P8 listing query·LRU | 잠김 | P7 | `node scripts/gates/shared-mailbox.ts P8 --seal` | 없음 |
| P9 admin·관측성 | 잠김 | P8 | `node scripts/gates/shared-mailbox.ts P9 --seal` | 없음 |
| P10 통합·성능·복구 | 잠김 | P9 | `node scripts/gates/shared-mailbox.ts P10 --seal` | 없음 |

## 선행 관계

```text
P0 → P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8 → P9 → P10
```

동시에 진행하는 단계는 0개로 제한한다. 권한·스키마·캐시가 서로의 계약을 바꾸므로 이 실행판은
직렬 순서를 사용한다. 한 단계 안의 작업도 listed 순서대로 수행한다.

## P0 — 계약·게이트 장치 (열림, 선행 없음)

### 완료 P0.T1 — 게이트 장치 구현

선행: 없음 · 산출: `scripts/gates/shared-mailbox.ts`, 봉인 디렉터리, gate 단위 테스트 ·
되돌리기: 해당 파일과 봉인 파일만 revert · 장치 요구: 이 작업의 완료 전에는 P1을 열지 않음

【작업】 GATE 계약의 명령, JSON 봉인, R1~R3, 단계별 check data를 구현한다. 검사 정의는
코드 분기가 아니라 선언 데이터로 둔다.

【테스트】

- TC-P0.T1.a 선행 봉인 없는 P1 실행 거부
  - 단언: P1 seal 파일이 없을 때 `P1` 실행 종료 코드가 0이 아니고 검사 명령을 실행하지 않는다.
  - 검출: 순서 잠금이 빠져 P1이 부분 구현 상태로 시작되는 회귀.
- TC-P0.T1.b 봉인 head 최신성
  - 단언: 조상이 아닌 `head` 봉인에 `--status`가 `무효`를 출력한다.
  - 검출: 이전 브랜치의 초록 결과를 현재 코드에 재사용하는 회귀.
- TC-P0.T1.c `--seal` 재검
  - 단언: 검사 대상 파일을 깨뜨린 뒤 `--seal`이 봉인 파일을 쓰지 않는다.
  - 검출: 옛 결과를 복사해 실패 상태를 초록으로 봉인하는 회귀.
- TC-P0.T1.d 검사 이빨
  - 단언: 각 check의 위반 fixture에서 그 check가 실패하고 종료 코드가 0이 아니다.
  - 검출: 실행은 되지만 아무것도 검출하지 않는 장식용 GATE.

【통과】 `--status`, R1~R3, waived, assert-order의 양·음성 fixture가 모두 0/비0을 정확히 반환한다.

### 완료 P0.T2 — ADR·공통 권한 계약 봉인

선행: P0.T1 · 산출: `principal.ts`, `rights.ts` 계약과 ADR · 되돌리기: 추가 파일 revert ·
장치 요구: G-P0 봉인 없이는 P1 시작 금지

【작업】 principal 4종(account/group/anyone/authenticated), operation과 rights의 매핑,
shared account owner 정책, positive right 1차 범위, `c/d` 확장·반환 규칙, JMAP permission
version state 및 credential precedence를 고정한다.

【테스트】

- TC-P0.T2.a rights 목록
  - 단언: `lrswipkxta e`의 11개 standard right과 `c/d` compatibility가 계약 데이터에 존재한다.
  - 검출: IMAP/JMAP 변환기가 서로 다른 권한 집합을 사용하는 회귀.
- TC-P0.T2.b owner·subscription 기본값
  - 단언: shared account에 암묵 owner를 만들지 않고 subscription 기본값이 false다.
  - 검출: shared mailbox가 개인 계정 전권으로 열리는 회귀.

【통과】 계약 fixture가 pass하고 계획서의 4 principal, `negative=0`, 11 rights가 G-P0 결과에 기록된다.

## 🚪 GATE P0

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P0.1 | 장치 음성 대조 TC-P0.T1.a~d | `node --test packages/core/test/gated-todo-gate.test.ts` | 4개 pass |
| G-P0.2 | 계약 수치·rights | `node scripts/gates/shared-mailbox.ts P0` | principal 4종, standard 11개, negative 1차만 확인 |
| G-P0.3 | lint/typecheck | `npm run lint && npm run typecheck` | 종료 코드 0 |

가장 중요한 검사는 G-P0.1이다. 장치가 스스로 순서를 막지 못하면 이후의 모든 녹색 결과는
선행 계약 없이 실행된 것이므로 증거가 아니다.

## P1 — principal·ACL 스키마 (봉인 완료)

### 완료 P1.T1 — migration 020 schema

선행: P0 · 산출: migration 020, `docs/SCHEMA.md` 표 갱신 · 되돌리기: forward-fix migration;
기존 테이블 DROP 금지 · 장치 요구: G-P0 봉인

【작업】 principals에 tenant/provider 범위, mailbox_acl, account_memberships,
`accounts.permissions_version`, `mailboxes.acl_version`을 추가한다. FK 없음 정책을 유지하되
같은 batch의 레시피로 참조 무결성을 보장한다. 기존 account principal backfill은 idempotent하게 한다.

【테스트】

- TC-P1.T1.a migration 재실행
  - 단언: SQLite/PG/MySQL에서 020을 두 번 적용해도 오류·중복이 없고 기존 행이 보존된다.
  - 검출: 운영 재기동 때 DDL이 실패하거나 principal이 중복 생성되는 회귀.
- TC-P1.T1.b tenant/provider 격리
  - 단언: 동일 external key가 tenant/provider별로 별도 principal이고 다른 tenant mailbox ACL 조회가 0행이다.
  - 검출: 다른 조직의 group 권한이 shared mailbox에 붙는 회귀.

【통과】 schema introspection에 새 테이블·컬럼·index가 존재하고 migration 수가 20이 된다.

### 완료 P1.T2 — rights parser·ACL 계산 계약

선행: P1.T1 · 산출: parser와 pure authorization fixture · 되돌리기: parser/fixture revert ·
장치 요구: P1 내부 순서 준수

【작업】 중복·대문자·unknown right을 처리하고, 1차 positive union과 owner/admin 정책을 구현한다.
negative 행은 저장하지 않고(`negative=0`) 후속 범위로 명시한다.

【테스트】

- TC-P1.T2.a parser 거부
  - 단언: 대문자·unknown right은 오류이며 silent ignore가 아니다.
  - 검출: 오타가 권한 상승으로 바뀌는 회귀.
- TC-P1.T2.b principal union
  - 단언: account와 group의 rights union은 허용하고, 다른 tenant group은 제외한다.
  - 검출: group 권한이 누락되거나 cross-tenant로 합쳐지는 회귀.

【통과】 P1 fixture와 migration 전수 테스트가 pass하고 unknown/uppercase 0건이 수용된다.

## 🚪 GATE P1

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P1.1 | schema 020 | `node --test packages/db/test/migrate.test.ts` | 새 테이블·컬럼 존재, 재실행 pass |
| G-P1.2 | ACL parser | `node --test packages/core/test/rights.test.ts` | TC-P1.T2 전체 pass |
| G-P1.3 | migration 수 | gate 내부 allMigrations 검사 | `migrations=20`, duplicate=0 |
| G-P1.4 | schema 문서 | gate 내부 `mailbox_acl` 검사 | 020 DDL과 문서 표가 함께 존재 |

## P2 — Store authorization (진행 중, P1 봉인 완료)

### 미착수 P2.T1 — PrincipalContext Store 경계

선행: P1 · 산출: authorization/acl-store와 기존 Store API 변경 · 되돌리기: API 변경을 한 커밋 단위로 revert · 장치 요구: raw mailboxId 경계 내부화

【작업】 모든 read/write 경로가 PrincipalContext와 operation을 통해 검사하도록 바꾼다.
계정 scope, mailbox 존재 은닉, writer queue와 단일 batch를 유지한다.

【테스트】

- TC-P2.T1.a ID 직접 접근
  - 단언: 권한 없는 mailboxId를 직접 전달해도 notFound/denied이고 메시지 행·blob을 반환하지 않는다.
  - 검출: protocol 우회로 private/shared 데이터가 노출되는 회귀.
- TC-P2.T1.b atomic ACL version
  - 단언: ACL 변경 batch 실패 시 ACL·permissions_version·acl_version 모두 이전 값이다.
  - 검출: 권한은 바뀌었지만 cache version은 남아 stale 결과를 내는 회귀.

【통과】 기존 개인 계정 회귀와 authorization matrix가 pass한다.

## 🚪 GATE P2

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P2.1 | Store 경계 검색 | `node scripts/gates/shared-mailbox.ts P2` | accountId-only 외부 mailbox 경로 0건 |
| G-P2.2 | authorization tests | `npm test -- packages/store/test/authorization.test.ts` | TC-P2.T1 전체 pass |
| G-P2.3 | 회귀 | `npm run verify` | 종료 코드 0 |

## P3 — shared account·IMAP namespace (진행 중, P2 봉인 완료)

### 미착수 P3.T1 — provisioning·namespace

선행: P2 · 산출: shared account 명령, IMAP Shared namespace · 되돌리기: feature flag off 후 forward-fix · 장치 요구: 수신 fanout 중복 금지

【작업】 account kind shared, 기본 mailbox, address_targets, explicit ACL과 namespace 충돌 검사를 추가한다.

【테스트】

- TC-P3.T1.a 팬아웃
  - 단언: shared 주소 1통이 shared account INBOX에 정확히 한 membership으로 배달된다.
  - 검출: 기존 alias fanout과 shared 분기가 중복되어 메일이 두 번 저장되는 회귀.
- TC-P3.T1.b namespace 은닉
  - 단언: l 없는 shared mailbox는 LIST·SELECT 모두 존재하지 않는 것처럼 거부된다.
  - 검출: LIST에서 숨겼지만 SELECT로 mailbox 존재가 드러나는 회귀.

【통과】 shared 생성·삭제와 namespace collision fixture가 pass한다.

## 🚪 GATE P3

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P3.1 | provisioning | `node --test apps/server/test/imap-shared-namespace.test.ts` | TC-P3.T1.a 전체 pass |
| G-P3.2 | namespace | `node --test apps/server/test/imap-shared-namespace.test.ts` | TC-P3.T1.b, hidden mailbox 누출 0건 |
| G-P3.3 | lint/typecheck | gate 내부 명령 | 종료 코드 0 |

## P4 — IMAP ACL 명령 (진행 완료, P3 봉인 완료)

### 미착수 P4.T1 — ACL protocol engine·backend

선행: P3 · 산출: GETACL/SETACL/DELETEACL/LISTRIGHTS/MYRIGHTS · 되돌리기: protocol commit revert · 장치 요구: `a`와 mailbox visibility 동시 검사

【작업】 engine은 action만 emit하고 backend가 Store authorization을 호출한다. CREATE/DELETE/RENAME,
APPEND/COPY flag별 권한, virtual `c/d`, READ-ONLY 교집합을 구현한다.

【테스트】

- TC-P4.T1.a command rights
  - 단언: a 없는 ACL 명령, k 없는 CREATE, x 없는 DELETE, e 없는 EXPUNGE가 각각 거부된다.
  - 검출: 한 protocol command만 raw Store를 우회하는 회귀.
- TC-P4.T1.b RENAME/COPY 세부 규칙
  - 단언: RENAME은 원본 x+새 parent k, COPY는 대상 i와 flag별 s/w/t를 적용한다.
  - 검출: mailbox 이동·flag 복사에서 권한보다 넓게 허용하는 회귀.

【통과】 Store authorization, IMAP ACL engine, IMAP backend namespace/mutation fixture가 모두 pass하고
`hasMailboxRight` 호출이 backend 산출물에 존재한다. shared account의 메시지 기록은 mailbox 소유
계정으로, 권한 판정은 요청 주체로 분리한다.

## 🚪 GATE P4

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P4.1 | Store authorization | `node --test packages/store/test/authorization.test.ts` | 5개 TC pass |
| G-P4.2 | ACL protocol engine | `node --test packages/proto-imap/test/acl-commands.test.ts` | 3개 TC pass |
| G-P4.3 | backend namespace·mutation | `node --test apps/server/test/imap-shared-namespace.test.ts` | 4개 TC pass |
| G-P4.4 | 권한 관문 존재 | gate 내부 grep | backend `hasMailboxRight` 검출 1건 이상 |
| G-P4.5 | RFC mapping·품질 | `node scripts/gates/shared-mailbox.ts P4` | standard 11, virtual 2, lint/typecheck 0 |

## P5 — JMAP shared account (잠김, P4 봉인 필요)

### 미착수 P5.T1 — Session·partial access·myRights

선행: P4 · 산출: accessible accounts, JMAP rights, visibility filter · 되돌리기: JMAP feature flag off · 장치 요구: primary account regression

【작업】 Session에 shared account를 노출하고, 모든 Mailbox/Email/Thread/blob 경로를 accessible
mailbox 집합으로 제한한다. From Identity와 maySubmit을 별도 검사한다. permission version이
다르면 changes는 cannotCalculateChanges를 반환한다.

【테스트】

- TC-P5.T1.a partial account
  - 단언: 일부 mailbox만 접근 가능한 계정에서 Email/Thread/blob이 접근 가능한 ID만 반환된다.
  - 검출: Thread·blob direct ID 또는 mixed mailboxIds로 private 데이터가 노출되는 회귀.
- TC-P5.T1.b permission state
  - 단언: ACL/group 변경 전 state로 changes를 요청하면 cannotCalculateChanges이고 현재 get/query 재동기화가 가능하다.
  - 검출: 권한 회수 객체를 잘못 destroyed/누락 처리하는 회귀.
- TC-P5.T1.c send identity
  - 단언: maySubmit과 From Identity 중 하나라도 없으면 EmailSubmission/set이 거부된다.
  - 검출: shared mailbox 읽기 권한이 발신 권한으로 상승하는 회귀.

【통과】 8개 TC-JMAP-SHARED와 primary account 회귀가 pass한다.

## 🚪 GATE P5

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P5.1 | JMAP shared | `npm test -- apps/server/test/jmap-shared-account.test.ts` | 8개 TC pass |
| G-P5.2 | state transition | `node scripts/gates/shared-mailbox.ts P5` | permission mismatch는 cannotCalculateChanges만 허용 |

## P6 — LDAP/AD mapping (잠김, P5 봉인 필요)

### 미착수 P6.T1 — DirectoryProvider·external mapping

선행: P5 · 산출: DirectoryProvider, migration 021, group sync · 되돌리기: directory login flag off; mapping forward-fix · 장치 요구: fail closed

【작업】 LDAPS/StartTLS/simple bind, timeout/TLS 검증, AD UPN/sAMAccountName alias와 immutable
objectGUID/objectSid를 지원한다. nested group은 cycle·최대 깊이를 검사한다. Kerberos/GSSAPI,
password modify, referral 자동 추적은 1차에서 제외한다. provisioning 기본값은 off다.

【테스트】

- TC-P6.T1.a transport fail closed
  - 단언: bind timeout/TLS 검증 실패/ directory 장애는 password login과 sensitive write를 거부한다.
  - 검출: 외부 directory 장애 때 stale 권한으로 쓰기를 허용하는 회귀.
- TC-P6.T1.b immutable mapping
  - 단언: loginName/email 변경은 같은 external identity를 유지하고 동일 email만으로 local account와 병합하지 않는다.
  - 검출: 주소 변경이나 collision으로 다른 계정 권한을 획득하는 회귀.
- TC-P6.T1.c group propagation
  - 단언: group 추가·제거가 모든 참조 shared account의 permissions_version을 증가시킨 뒤에만 권한을 반영한다.
  - 검출: 여러 shared account 중 일부만 무효화되어 stale ACL이 남는 회귀.

【통과】 8개 TC-DIR와 migration 021 재실행 fixture가 pass한다.

## 🚪 GATE P6

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P6.1 | directory tests | `npm test -- packages/store/test/directory.test.ts` | 8개 TC pass |
| G-P6.2 | mapping | `node scripts/gates/shared-mailbox.ts P6` | transport 3개, 후순위 4개, provision=off |

## P7 — header projection·backfill (잠김, P6 봉인 필요)

### 미착수 P7.T1 — typed projection

선행: P6 · 산출: migration 022, typed projection, ingest parser · 되돌리기: projection table forward-fix; BlobStore 원본 삭제 금지 · 장치 요구: 원본 불변

【작업】 allowlist 11개 header를 저장한다. Date/text/ref/address projection을 분리하고
display string을 정렬 기준으로 사용하지 않는다. header name 190 bytes, display 16 KiB,
sort 4 KiB, header별 occurrence 32개로 제한한다.

【테스트】

- TC-P7.T1.a typed codec
  - 단언: encoded-word Subject, Date, address, Message-ID/References가 typed projection에 기대한 값으로 저장된다.
  - 검출: display string 정렬로 locale·timezone·인코딩 순서가 틀리는 회귀.
- TC-P7.T1.b bounds/original
  - 단언: 각 상한 초과는 projection만 제한하고 원본 MIME blob은 byte-identical이다.
  - 검출: 악성 header가 DB·메모리를 폭주시켜 원본까지 잘리는 회귀.
- TC-P7.T1.c backfill checkpoint
  - 단언: BlobStore read 실패 후 checkpoint가 전진하지 않고 재시작 시 중복·누락이 없다.
  - 검출: 대량 backfill 중단 후 메시지를 영구 누락하는 회귀.

【통과】 migration 022와 7개 TC-HEADER가 pass하고 수치 원장의 190/16 KiB/4 KiB/32가 기록된다.

## 🚪 GATE P7

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P7.1 | header tests | `npm test -- packages/store/test/header-projection.test.ts` | 7개 TC pass |
| G-P7.2 | bounds | `node scripts/gates/shared-mailbox.ts P7` | name≤190, display≤16KiB, sort≤4KiB, occurrence≤32 |

## P8 — listing query·bounded LRU (잠김, P7 봉인 필요)

### 미착수 P8.T1 — query split·indexes

선행: P7 · 산출: migration 023, query functions와 indexes · 되돌리기: index forward-fix; cache flag off · 장치 요구: existing query 결과 보존

【작업】 UID, summary, SORT/THREAD/JMAP query를 분리한다. cache key에는 principalId,
mailboxId, mailbox modseq, ACL/permissions version, 전체 query fingerprint를 포함한다.
memory cap, mailbox 결과 2,000개, TTL 5~30초를 설정하고 process 종료 유실을 허용한다.

【테스트】

- TC-P8.T1.a isolation
  - 단언: 사용자 A의 hit가 B에게 반환되지 않고 ACL/permission version 변화는 miss를 만든다.
  - 검출: shared mailbox 결과가 principal 간 섞이는 회귀.
- TC-P8.T1.b fingerprint
  - 단언: collapseThreads/anchor/offset/calculateTotal/SORT/THREAD/projection field 변화가 서로 다른 key다.
  - 검출: 같은 filter처럼 보여 잘못된 페이지나 total을 반환하는 회귀.
- TC-P8.T1.c bound
  - 단언: 결과 2,001개와 TTL 4초/31초 경계가 설정한 eviction/TTL 정책을 준수한다.
  - 검출: cache가 무한히 커지거나 stale 결과가 무기한 살아남는 회귀.

【통과】 migration 023, 8개 TC-LIST, EXPLAIN 결과가 pass한다.

## 🚪 GATE P8

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P8.1 | listing tests | `npm test -- packages/store/test/listing-cache.test.ts` | 8개 TC pass |
| G-P8.2 | limits | `node scripts/gates/shared-mailbox.ts P8` | result≤2,000, TTL 5~30초, bounded=true |

## P9 — admin·관측성 (잠김, P8 봉인 필요)

### 미착수 P9.T1 — registry·metrics·audit

선행: P8 · 산출: admin-cmd registry 명령, REST/CLI/GUI 파생, metrics · 되돌리기: 명령 feature flag off · 장치 요구: 민감정보 로그 금지

【작업】 shared account/ACL/directory sync/header rebuild/cache flush 명령을 registry에 등록한다.
audit와 metrics에 operation/outcome/reason을 기록하되 password, bind credential, 전체 header,
directory filter를 기록하지 않는다.

【테스트】

- TC-P9.T1.a surface parity
  - 단언: registry 명령 하나가 REST·CLI·GUI descriptor에 동일한 destructive/scope/columns로 나타난다.
  - 검출: 한 표면에만 관리 기능이 붙는 회귀.
- TC-P9.T1.b sensitive audit
  - 단언: 테스트 secret/header/filter가 audit/log output에 0회 나타난다.
  - 검출: directory credential이나 MIME 본문이 운영 로그로 유출되는 회귀.

【통과】 registry parity와 metric label contract가 pass한다.

## 🚪 GATE P9

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P9.1 | admin surfaces | `npm test -- packages/admin-cmd/test/shared-mailbox.test.ts` | 모든 surface parity pass |
| G-P9.2 | audit | `node scripts/gates/shared-mailbox.ts P9` | forbidden secret/body/filter matches=0 |

## P10 — 통합·성능·복구 (잠김, P9 봉인 필요)

### 미착수 P10.T1 — interoperability·load·restore

선행: P9 · 산출: integration report와 최종 봉인 · 되돌리기: feature flag off; schema는 forward-fix · 장치 요구: backup/restore rehearsal

【작업】 IMAP ACL interoperability, JMAP shared account e2e, LDAP/AD fixture, 대형 mailbox
EXPLAIN/latency, cache isolation, migration restore rehearsal을 수행한다. SQLite/PG/MySQL을
확인하고 D1 공통 SQL 제한을 위반하지 않는다.

【테스트】

- TC-P10.T1.a cross-surface consistency
  - 단언: 같은 principal·mailbox에 대한 IMAP/JMAP/admin 판정이 동일하다.
  - 검출: protocol별 rights 계산 차이로 한 표면만 권한 상승하는 회귀.
- TC-P10.T1.b restore
  - 단언: 020~023 적용 전 backup을 복구하고 migration을 재개해 데이터·version·ACL이 보존된다.
  - 검출: migration 실패 시 복구 불능 또는 부분 ACL로 기동하는 회귀.
- TC-P10.T1.c full verification
  - 단언: `npm run verify`가 테스트 2,383개 중 2,380 pass·3 skip, smoke 성공을 기록한다.
  - 검출: 기존 프로토콜 회귀가 새 기능의 녹색 결과에 가려지는 회귀.

【통과】 모든 필수 integration/load/restore 명령 종료 코드 0, 3 skip 외 실패 0이다.

## 🚪 GATE P10

| id | 검사 | 명령 | 통과 기준 |
|---|---|---|---|
| G-P10.1 | 전체 verify | `npm run verify` | 2,380 pass, 3 skip, fail=0, todo=0 |
| G-P10.2 | migration 수·복구 | `node scripts/gates/shared-mailbox.ts P10` | migrations=23, restore=pass |
| G-P10.3 | 잔재·순서 | `node scripts/gates/shared-mailbox.ts --assert-order` | unsealed changed outputs=0 |

최종 판정 지표는 **권한 경계의 교차 표면 일관성**이다. 같은 principal이 같은 mailbox에 대해
IMAP·JMAP·관리 명령에서 서로 다른 결론을 얻지 않아야 하며, 이것이 맞지 않으면 성능이나
기능 수가 모두 성공해도 최종 GATE는 실패한다.

## 막혔을 때

- GATE가 빨간데 원인을 모르면 `--explain`을 먼저 실행하고 측정값·상한을 보존한다.
- 봉인 후 회귀하면 해당 단계 봉인을 무효화하고 원인 커밋을 수정한 뒤 다시 `--seal`한다.
- 이동인지 행동 변경인지 모르면 parent branch의 테스트 결과와 현재 branch의 결과를 분리한다.
- 권한·migration 단계 중간 이탈은 feature flag를 끄고 봉인하지 않는다.
- 일정 부족은 필수 단계를 waive하지 않는다. 선택 단계만 사유를 적어 `--waived`로 봉인한다.

## 코드 미확인 TC

없음. P0~P10의 산출 경로는 기존 코드와 계획서의 실제 함수·migration·테스트 경로를 대조해
기록했다. 구현 중 경로가 바뀌면 해당 TC의 검출줄과 GATE 명령을 같은 커밋에서 갱신한다.
