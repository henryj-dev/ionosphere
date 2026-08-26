# 2026-08-26 구조 개선 — 실행 목록

계획은 [`REFACTOR-2026-08-26.md`](./REFACTOR-2026-08-26.md) 다. 이 문서는 **순서 · 통과 조건 · 잠금**만
적는다. 논거·위치·문제 서술은 계획서의 절 번호(§)로 가리키고 되풀이하지 않는다.

---

## 0. 체계

이 문서는 자기 체계를 쓴다. 아래에 정의하지 않은 표기는 본문에 없다.

**단계(Phase)** — `P0` ~ `P8`, 그리고 선택 단계 `P2x`. 계획서의 "단계"와 번호가 같다(계획서 §1).
단계는 잠금의 단위다. 단계 상태는 넷 중 하나이며 장치(`scripts/gate.ts --status`)가 판정한다:

| 표기 | 뜻 |
|:--|:--|
| 🔒 잠김 | 선행 단계의 봉인이 없다. **이 단계의 작업은 시작하지 않는다.** 장치가 이 단계의 검사 실행 자체를 거부한다 |
| 🔓 열림 | 선행 봉인이 전부 있고 이 단계는 아직 봉인되지 않았다 |
| 🔏 봉인 | `gate <단계> --seal`이 검사 전부 초록을 확인하고 `docs/plan/seals/<단계>.json`을 썼다 |
| ⚠ 무효 | 봉인은 있으나 그 `head`가 현재 `origin/main`의 조상이 아니다(되돌려졌다). 잠김과 같이 취급 |

**작업(Task)** — `P<n>.T<k>`. 커밋 하나 크기. 번호는 재사용하지 않는다(지운 작업은 `(폐기)`로
남긴다). 작업 상태는 `▢ 미착수` · `▶ 진행` · `■ 완료`. 성격 표기 넷 중 하나를 제목에 단다:

| 성격 | 뜻 | 「통과」에 반드시 들어가는 것 |
|:--|:--|:--|
| `[이동]` | 코드를 다른 파일로 옮긴다. 내용 무변경 | 패키지 export 표면 스냅샷이 선행 봉인 시점과 **동일**(`surface`) · 그 패키지 테스트 초록 |
| `[삭제]` | 코드를 지운다 | 표면 스냅샷이 **허용 목록만큼만** 줄었다 · 테스트 비악화 |
| `[변경]` | 행동 또는 내부 구조를 바꾼다 | 행동 변경이면 재현 테스트가 **부모 커밋에서 빨강, HEAD에서 초록**(`red-green`); 구조 변경이면 테스트 초록 + 표면 검사 |
| `[신설]` | 새 모듈·장치를 만든다 | 그 모듈의 테스트 초록 · 음성 대조 TC |

**작업 하나의 모양**

```
### ▢ P<n>.T<k> — 제목 [성격]
선행: … · 산출: 파일 목록 · 되돌리기: revert 단위 · 트리: 워크트리 이름
【작업】 번호 = 커밋 하나
【테스트】 TC 목록
【통과】 체크박스. 전부 기계 판정. 사람 판단이 필요한 것은 【작업】에 있다
```

`트리` 칸이 있는 이유 — 이 저장소의 `scripts/git-hooks/pre-commit`은 에이전트 하네스 환경변수가
있을 때 메인 작업 트리 커밋을 **거부**한다(관례가 아니라 제약). 모든 작업은
`python3 scripts/claude-hooks/enter-worktree.py <이름>`으로 만든 워크트리에서 한다.

**테스트케이스(TC)** — `TC-P<n>.T<k>.<a|b|c…>`. 세 줄: **이름 · 단언 · 검출**.
검출 줄은 "이 테스트가 없으면 놓치는 구체적 고장"이다. 못 쓰면 그 TC는 없다.
코드를 열지 않고 쓴 TC는 `(코드 미확인)`을 달고 문서 끝 목록에 있다.

**GATE** — 단계마다 하나. 검사 `G-P<n>.<m>`의 표(검사 · 명령 · 통과 기준). 계획서의 모든 숫자
(줄 수·개수·델타)는 어느 GATE의 「통과 기준」열에 있다.

**장치** — `scripts/gate.ts`(P0.T1이 만든다). 검사 정의는 코드가 아니라 데이터
(`scripts/gate-checks.ts`의 `GATES` 객체). 계약:

```
node scripts/gate.ts <단계>                 검사 전부 실행, 결과 표. 실패 시 종료코드 ≠ 0
node scripts/gate.ts <단계> --seal          검사를 다시 돌려 전부 초록이면 docs/plan/seals/<단계>.json
node scripts/gate.ts <단계> --explain       실패 검사의 측정값과 상한
node scripts/gate.ts <단계> --seal --waived "<사유>"   선택 단계(P2x)만. 사유 없으면 거부
node scripts/gate.ts --status               단계별 잠김/열림/봉인/무효 표 (진행 현황 표와 같은 열)
node scripts/gate.ts --assert-order         CI용. 봉인 안 된 단계의 산출 경로에 변경이 있으면 실패
```

`how`의 집합 여덟: `lines`(파일 줄 수 ≤ limit) · `grep`(고정 문자열 또는 정규식과 일치하는 줄 수가
`=`/`≤` limit; `in`은 경로 글롭, `exclude` 가능) · `test`(`node --test <파일…>` 종료코드 0) ·
`cmd`(임의 명령 종료코드 0) · `diff-empty`(`since: seal:<단계>` 이후 경로에 변경 없음) · `json`(파일의
경로 값을 비교; `absent`는 키 없음) · `surface`(패키지 `src/**`의 `export` 이름 정렬 목록을
`seal:<단계>` 스냅샷과 비교; `allowRemoved`·`allowAdded` 목록) · `red-green`(`git archive <fixCommit>^`로
부모 트리를 임시 디렉터리에 풀어 `test`가 **실패**, HEAD에서 **성공**임을 확인. `git worktree add`는
가드가 거부하므로 archive를 쓴다. `fixCommit`은 검사 정의에 커밋 제목 접두 `[R-01]`처럼 적고 장치가
`git log --grep`으로 푼다).

봉인 파일 — `docs/plan/seals/<단계>.json`(커밋되는 경로. `.omc/`·`.claude/` 같은 무시 디렉터리
금지):

```json
{ "phase": "P1", "sealed": true, "head": "<SHA>", "at": "<ISO>", "waived": false, "reason": null,
  "checks": [ { "id": "G-P1.1", "ok": true, "measured": 998, "limit": 1000 } ],
  "surface": { "packages/store": ["Store", "StoreError", "..."] } }
```

규칙 셋(장치가 스스로 지킨다): **R1 순서** — `needs`의 봉인이 없으면 검사 실행 거부.
**R2 최신성** — 봉인 `head`가 `origin/main`의 조상이 아니면 ⚠ 무효. **R3 재검** — `--seal`은
이전 결과를 읽지 않고 검사를 다시 돌린다.

**결정 파일** — `docs/plan/REFACTOR-2026-08-26-decisions.json`. 계획서 §11의 D-01~D-07을
`{ "D-01": { "choice": "1"|"2", "by": "...", "at": "ISO", "note": "..." }, … }`로 적는다. 결정이
전제인 단계의 GATE가 `json` 검사로 값을 요구한다 — **결정을 안 하면 그 단계가 열리지 않는다.**

**릴리즈 파일** — `docs/plan/REFACTOR-2026-08-26-releases.json`. `{ "P0": "v2026.MM.DD", … }`.
계획서 §12의 "단계마다 릴리즈 1회 · 9회"가 P8 GATE의 검사가 된다(태그 형식은 기존 `v2026.08.23`).

---

## 진행 현황

`node scripts/gate.ts --status`의 출력과 같은 열. 봉인 열은 봉인 파일의 `head` 앞 7자.

| 단계 | 제목 | 상태 | 선행 | 게이트 명령 | 봉인 |
|:--|:--|:--|:--|:--|:--|
| P0 | 기준선 · 장치 · 결함 봉합 · 래칫 | 🔓 열림 | — | `node scripts/gate.ts P0 --seal` | — |
| P1 | store 재편 | 🔒 잠김 | P0 | `node scripts/gate.ts P1 --seal` | — |
| P3 | SMTP 엔진 + MTA | 🔒 잠김 | P0 | `node scripts/gate.ts P3 --seal` | — |
| P6 | Sieve · core · mime | 🔒 잠김 | P0 | `node scripts/gate.ts P6 --seal` | — |
| P7 | 훅 · CI · testkit | 🔒 잠김 | P0 | `node scripts/gate.ts P7 --seal` | — |
| P2 | IMAP | 🔒 잠김 | P1 | `node scripts/gate.ts P2 --seal` | — |
| P2x | IMAP COMPRESS 전송층 (선택) | 🔒 잠김 | P2 | `node scripts/gate.ts P2x --seal [--waived "…"]` | — |
| P5 | JMAP · push · 리포트 | 🔒 잠김 | P1 | `node scripts/gate.ts P5 --seal` | — |
| P4 | apps/server 조립층 · backend 분리 | 🔒 잠김 | P1, P3 | `node scripts/gate.ts P4 --seal` | — |
| P8 | 문서 · 재발 방지 (최종) | 🔒 잠김 | P1~P7 (P2x는 봉인 또는 면제) | `node scripts/gate.ts P8 --seal` | — |

## 선행 관계

```
P0 ─┬─ P1 ─┬─ P2 ─── P2x(선택)
    │      ├─ P5
    │      └─────┐
    ├─ P3 ───────┴─ P4 ─┐
    ├─ P6 ──────────────┼─ P8
    └─ P7 ──────────────┘
```

직렬: `P0 → P1 → P2`, `P1 → P5`, `{P1, P3} → P4`, 전부 → `P8`.
병렬 가능: P0 봉인 뒤 **P1 · P3 · P6 · P7 넷 동시**. P1 봉인 뒤 P2 · P5 동시.
동시 진행 상한 **4**(겹치는 파일이 `core/limits.ts`(P1.T10 · P6.T6)와 `scripts/lint.ts`(P0.T9 ·
P1.T8 · P3.T5)뿐이라 넷까지는 rebase 충돌이 자명하다 — 계획서 §13). P1.T10과 P6.T6은 순차.

---

# P0 — 기준선 · 장치 · 결함 봉합 · 래칫 🔓 열림 (선행 없음)

**브랜치** 워크트리 `p0-gate`(T1, T9, T10) · `p0-fixes`(T2~T8). 두 워크트리는 파일이 겹치지 않는다.

### ▢ P0.T1 — 게이트 장치 `scripts/gate.ts` [신설]
선행: 없음 · 산출: `scripts/gate.ts`, `scripts/gate-checks.ts`, `scripts/test-gate.ts`,
`docs/plan/seals/.gitkeep`, `docs/plan/REFACTOR-2026-08-26-decisions.json`(D-01~D-07 전부
`null`), `docs/plan/REFACTOR-2026-08-26-releases.json`(`{}`), `package.json`에 `"gate": "node scripts/gate.ts"` ·
되돌리기: 커밋 1개 revert · 트리: `p0-gate`

【작업】
1. `scripts/gate.ts` — §0의 계약 여섯 명령. 의존성 0(`node:` 빌트인만 — 린터 규약). `how` 8종
   구현. R1·R2·R3. `--status`는 `origin/main`을 `git merge-base --is-ancestor`로 판정.
2. `scripts/gate-checks.ts` — `export const GATES = { P0: { needs: [], checks: [...] }, … }`.
   이 문서의 모든 GATE 표를 그대로 옮긴다(표가 정본, 코드는 사본 — `G-P8.9`가 둘의 일치를 검사).
3. `scripts/test-gate.ts` — 아래 TC a~f. 임시 저장소를 `git init`해서 돈다(라이브 `.git` 무접촉).

【테스트】
- `TC-P0.T1.a` 선행이 봉인되지 않으면 실행을 거부한다
  단언: 봉인 디렉터리가 빈 임시 저장소에서 `gate P1` → 종료코드 ≠ 0, stderr에 `P0` 언급
  검출: 순서 강제가 실제로는 안 걸리는 것 — 이 문서 전체의 전제가 무너진다
- `TC-P0.T1.b` 봉인 후 그 단계를 되돌리면 봉인이 무효가 된다
  단언: `head`가 현재 HEAD의 조상이 아닌 봉인 파일을 심고 `--status` → 그 단계가 `⚠ 무효`, 다음 단계는 `🔒`
  검출: R2 미구현 — revert 뒤에도 다음 단계가 열려 있어 되돌린 코드 위에 다음 단계가 쌓인다
- `TC-P0.T1.c` `--seal`은 검사를 다시 돌린다
  단언: `lines` 검사 대상 파일을 한도 초과로 늘린 뒤 `--seal` → 봉인 파일이 **안** 쓰이고 종료코드 ≠ 0
  검출: R3 미구현 — 옛 초록 결과로 봉인
- `TC-P0.T1.d` 검사마다 이빨이 있다
  단언: `how` 8종 각각에 대해 위반 상태를 인위로 만든 픽스처(줄 수 초과·패턴 1건·실패하는 테스트·
  종료코드 1·변경된 파일·값 불일치·export 하나 삭제·부모에서도 초록인 테스트) → 그 검사가 실패
  검출: 검출력 0인 `how` — 특히 `red-green`이 부모 트리를 안 풀고 HEAD만 두 번 돌리는 것
- `TC-P0.T1.e` `--waived`는 사유 없이는 거부되고 선택 단계에만 허용된다
  단언: `gate P1 --seal --waived ""` → 거부; `gate P1 --seal --waived "x"` → 거부(P1은 필수);
  `gate P2x --seal --waived "x"` → `waived: true` 봉인
  검출: 필수 단계를 면제로 건너뛰는 것 — 계획서 §1의 "필수/선택"이 문서에만 남는다
- `TC-P0.T1.f` `--assert-order`는 봉인 안 된 단계의 산출 경로 변경을 잡는다
  단언: P1 미봉인 상태에서 `packages/store/src/message-destroy.ts`를 만들고 `--assert-order` → 실패
  검출: CI가 순서를 안 보는 것 — 잠긴 단계의 파일이 먼저 main에 들어간다

【통과】
- [ ] `G-P0.1` ~ `G-P0.6`(TC a~f) 초록
- [ ] `npm run lint`가 `scripts/gate.ts`·`gate-checks.ts`를 통과(의존성 0, `.ts` 확장자, 제어문자 없음)

### ▢ P0.T2 — R-01 EXPUNGE Thread change_log [변경]
선행: 없음 · 산출: `packages/store/test/jmap-changes.test.ts`(TC 4개 추가), `packages/store/src/store.ts:1256-1262` ·
되돌리기: 테스트 커밋 + 수정 커밋(제목 접두 `[R-01]`), 수정 커밋만 revert 가능 · 트리: `p0-fixes`

【작업】
1. 테스트 커밋 — TC a~d 추가. 이 커밋에서 a와 b는 **빨강**(a: `targets` 매핑 결함, b:
   `removeMembershipAttempt`의 `isLast` 가지에 Thread 로그 없음 — 계획서 §3 1-A). c·d는 현재 통과할
   수 있다 — 통과하는 것은 그대로 둔다(P1.T2의 안전망).
2. 수정 커밋 `[R-01]` — `targets`에 `threadId: String(r.thread_id)`, `threadIds`를 거기서 파생, 캐스트
   삭제. b는 `:1397-1411` 가지에 `ENTITY.Thread` 로그 한 줄.

【테스트】
- `TC-P0.T2.a` expunge 뒤 Thread/changes에 그 스레드가 있다
  단언: append(1) → setDeleted(uid 1) → expunge → `jmapChanges(acc, "thread", before)`의
  `updated ∪ destroyed`에 그 메시지의 thread_id가 있다. 현재 실측: `state 1→3`, 둘 다 `[]`
  검출: `targets` 매핑이 `thread_id`를 떨어뜨리고 캐스트가 `undefined`를 읽는 것 — `state_thread`만
  오르고 로그가 비어 클라이언트 스레드 캐시가 영영 낡는다
- `TC-P0.T2.b` 마지막 멤버십 제거(`removeMessageFromMailbox`, isLast)도 Thread 로그를 남긴다
  단언: 메일함 하나에만 있는 메시지를 제거 → Thread/changes에 항목
  검출: `store.ts:1397-1411` 가지가 `ENTITY.Thread`를 안 쓰는 것(형제 가지 `:1416`은 쓴다)
- `TC-P0.T2.c` `destroyMessage`가 Thread 로그를 남긴다
  단언: destroy → Thread/changes에 항목
  검출: 1-A 빌더 전환 중 이 경로가 빠지는 것
- `TC-P0.T2.d` COPY로 새 messages 행이 생기면 그 thread가 `updated`
  단언: copy → Thread/changes에 항목
  검출: `copyOrMoveBatchAttempt`의 `copiedIds.length > 0 ? … : …` 삼항이 `state_thread`를 빠뜨리는 것

【통과】
- [ ] `G-P0.7` `red-green`: `jmap-changes.test.ts`가 `[R-01]` 부모에서 빨강, HEAD에서 초록
- [ ] `G-P0.8` `grep "as typeof t &" packages/store/src/store.ts` = 0

### ▢ P0.T3 — R-02 `deferAll`이 NOTIFY=NEVER를 무시 [변경]
선행: 없음 · 산출: `packages/mta/test/dsn-worker.test.ts`, `packages/mta/src/worker.ts:1237-1250` ·
되돌리기: 수정 커밋 `[R-02]` revert · 트리: `p0-fixes`

【작업】
1. 테스트 커밋(TC a, b). 2. 수정 커밋 — `if (dsnWanted(row.dsnNotify, "failure"))` 가드,
`...(row.dsnOrcpt ? { originalRecipient: row.dsnOrcpt } : {})`.

【테스트】
- `TC-P0.T3.a` MX 소진 bounce는 NOTIFY=NEVER를 존중한다
  단언: `dsn_notify = "NEVER"` 큐 행 + MX 조회가 항상 실패 → `attempts ≥ maxAttempts` 도달 시
  `status = bounced`이고 DSN 발송 훅 호출 0회
  검출: `deferAll`(`:1243`)이 `dsnRows.push`를 무조건 하는 것 — 발신자가 명시적으로 끈 바운스가
  연결 실패 경로에서만 나가 바운스 폭풍(RFC 3461 §4.1 NEVER의 존재 이유)
- `TC-P0.T3.b` 같은 경로에서 NOTIFY=FAILURE면 DSN 1건에 Original-Recipient가 있다
  단언: `dsn_notify = "FAILURE"`, `dsn_orcpt = "rfc822;a@example.com"` → DSN 본문에 `Original-Recipient: rfc822;a@example.com`
  검출: 세 번째 사본이 `originalRecipient`를 빠뜨린 것 — 다른 두 경로(`:1056`, `:1094`)와 갈라짐

【통과】
- [ ] `G-P0.9` `red-green`: `dsn-worker.test.ts`
- [ ] `G-P0.10` `grep -c 'dsnWanted(row.dsnNotify, "failure")' packages/mta/src/worker.ts` = 3

### ▢ P0.T4 — R-03 `Identity/changes` 와이어 계약 [변경]
선행: 없음 · 산출: `apps/server/test/jmap-e2e.test.ts`, `apps/server/src/jmap-backend.ts:487-491` ·
되돌리기: 수정 커밋 `[R-03]` revert · 트리: `p0-fixes`

【작업】 1. 테스트 커밋. 2. `identityChangesSource` + `standardChanges` 한 줄. 인라인 핸들러 삭제.

【테스트】
- `TC-P0.T4.a` 계산 불가 상태는 메서드 오류다
  단언: `Identity/changes { sinceState: "0" }`(보존창 밖) → `error` 응답, `type: "cannotCalculateChanges"`
  검출: `store.jmapChanges`의 `{ cannotCalculate: true }` 객체가 그대로 응답에 실리는 것 — RFC 8620 §5.2
  를 따르는 클라이언트는 이 응답을 "변경 없음"으로 읽고 identity를 영영 재동기화하지 않는다
- `TC-P0.T4.b` 정상 응답에 `accountId`가 있고 `cannotCalculate` 필드가 없다
  단언: 응답 키 집합 = `{accountId, oldState, newState, hasMoreChanges, created, updated, destroyed}`
  검출: 내부 유니온의 판별 필드가 와이어에 새는 것
- `TC-P0.T4.c` `maxChanges`가 문자열이면 `invalidArguments`
  단언: `maxChanges: "abc"` → `invalidArguments`; 생략 시 `DEFAULT_MAX_CHANGES`(500) 적용
  검출: `Number(args.maxChanges ?? 0) || 256` — 검증 없음, 기본값이 다른 `/changes`(500)와 다름

【통과】
- [ ] `G-P0.11` `red-green`: `jmap-e2e.test.ts`
- [ ] `G-P0.12` `grep -c "standardChanges(" apps/server/src/jmap-backend.ts` = 6 (기존 5 + Identity)

### ▢ P0.T5 — R-04 리포트 메일 Content-Type [변경]
선행: 없음 · 산출: `apps/server/test/reports.test.ts`, `apps/server/src/app.ts:1402` ·
되돌리기: 수정 커밋 `[R-04]` revert · 트리: `p0-fixes`

【작업】 1. 테스트 커밋. 2. `multipart/mixed`로 수정.

【테스트】
- `TC-P0.T5.a` DMARC 집계 메일은 DSN이 아니다
  단언: 발송된 바이트의 최상위 `Content-Type`이 `multipart/mixed; boundary=…`이고 `report-type`이 없다
  검출: `dsn.ts:184`에서 복사한 `multipart/report; report-type=delivery-status` — 수신 측 DSN 파서가
  집계 리포트를 바운스로 분류해 발신 억제 목록에 넣는다

【통과】
- [ ] `G-P0.13` `red-green`: `reports.test.ts`
- [ ] `G-P0.14` `grep "report-type=delivery-status" in {apps,packages}/**/*.ts` = 1 (`packages/mta/src/dsn.ts`만)

### ▢ P0.T6 — R-05 데드라인 계층 역전 [변경]
선행: 없음 · 산출: `packages/testkit/test/deadline.test.ts`(신설), `packages/testkit/src/deadline.ts:43` ·
되돌리기: 수정 커밋 `[R-05]` revert · 트리: `p0-fixes`

【작업】 1. 테스트 커밋. 2. `PROBE_DEADLINE_MS = SOCKET_DEADLINE_MS * 3`. 두 번째 `fromEnv()` 삭제.

【테스트】
- `TC-P0.T6.a` env를 올리면 프로브 계층도 같이 오른다
  단언: `IONOSPHERE_TEST_DEADLINE_MS=30000`으로 자식 프로세스에서 모듈 로드 → `PROBE_DEADLINE_MS === 90000`
  검출: 두 상수가 같은 env를 읽어 30000 설정 시 PROBE가 45000→30000으로 **내려가는** 것 —
  느린 CI에서 쓰라고 만든 손잡이가 프로브 플레이크를 되살린다

【통과】
- [ ] `G-P0.15` `red-green`: `packages/testkit/test/deadline.test.ts`
- [ ] `G-P0.16` `grep -c "fromEnv()" packages/testkit/src/deadline.ts` = 1

### ▢ P0.T7 — R-06 종료 훅의 보호 대상 해석 [변경]
선행: 없음 · 산출: `scripts/claude-hooks/test-session-end-cleanup.py`, `session-end-cleanup.py:163` ·
되돌리기: 수정 커밋 `[R-06]` revert · 트리: `p0-fixes`

【작업】 1. 테스트 추가. 2. `__file__` 기준으로 `--git-common-dir`; `cwd`/`CLAUDE_PROJECT_DIR`
폴백 체인 삭제.

【테스트】
- `TC-P0.T7.a` 중첩 체크아웃에서 종료해도 남의 저장소를 건드리지 않는다
  단언: 격리 저장소 안 `target/other/`에 별도 `git init` + 워크트리 하나 → 그 cwd로 훅 호출 →
  `other`의 워크트리는 그대로, 우리 워크트리는 회수
  검출: `data.get("cwd")`로 대상을 정해 `worktree remove`·`branch -d`·`merge --ff-only`가 세션이
  앉아 있던 저장소에 실행되는 것(가드 `:209-214`가 버그라고 적은 규칙)

【통과】
- [ ] `G-P0.17` `cmd`: `python3 scripts/claude-hooks/test-session-end-cleanup.py` 종료코드 0
- [ ] `G-P0.18` `grep -c 'data.get("cwd")' scripts/claude-hooks/session-end-cleanup.py` = 0

### ▢ P0.T8 — R-07 JMAP 제출 옵션 누락 — 실증 후 조건부 수정 [변경]
선행: 없음 · 산출: `apps/server/test/jmap-e2e.test.ts`, 실증 시 `apps/server/src/jmap-backend.ts:595`,
`backend.ts:1774-1777` · 되돌리기: 수정 커밋 `[R-07]` revert · 트리: `p0-fixes`

【작업】
1. 테스트 커밋(TC a, b). 두 TC가 **초록이면** R-07은 오보 — 결정 파일 `D-06`에
   `{ "choice": "closed", "note": "실증 실패: …" }`를 적고 테스트는 남긴다(재발 방지).
2. 빨강이면 SMTP 제출과 같은 옵션 객체를 만드는 함수 하나(`outboundPolicyOf(ctx)`)를 두고
   두 진입점이 호출. `submitOutbound`의 `DEFAULT_RATE_LIMIT` 이중 병합 제거.

【테스트】
- `TC-P0.T8.a` JMAP 제출도 릴레이 상한을 탄다
  단언: `relayPerHour = 1` → JMAP `EmailSubmission/set` 2회 → 두 번째 `notCreated`(이 저장소의 상한 오류 타입)
  검출: `jmap-backend.ts:595`가 `{ rateLimit, localOnly }`만 만들어 `relayPerHour`가 안 실리는 것 —
  과거 "JMAP만 레이트리밋 우회" 사고의 재현
- `TC-P0.T8.b` `requireSenderOwnership`이 JMAP 제출에도 적용된다
  단언: 켠 상태에서 남의 주소 `From` → 거절
  검출: 같은 옵션 누락의 다른 필드

【통과】
- [ ] `G-P0.19` `test`: `jmap-e2e.test.ts` 초록 (빨강→수정이면 `red-green`으로 대체)
- [ ] `G-P0.20` `json`: decisions `D-06.choice` ∈ {`"0-A"`, `"4-B"`, `"closed"`}

### ▢ P0.T9 — 파일 크기 래칫 · `lintAllowed` [신설]
선행: 없음 · 산출: `scripts/lint.ts`(`checkFileSizeRatchet`, `lintAllowed`, `RATCHET` 표),
`scripts/test-lint.ts`(있으면 확장, 없으면 신설) · 되돌리기: 커밋 1개 revert · 트리: `p0-gate`

【작업】
1. `RATCHET = { "packages/proto-imap/src/engine.ts": 2322, "packages/store/src/store.ts": 2203,
   "apps/server/src/backend.ts": 2126, "apps/server/src/app.ts": 2072,
   "apps/server/src/jmap-backend.ts": 1283, "packages/mta/src/worker.ts": 1273,
   "packages/proto-smtp/src/engine.ts": 1238 }`. 규칙: `src/**/*.ts`가 1,000줄 초과이고 표에 없으면
   위반; 표에 있으면 표 값 초과 시 위반. 표는 **줄이는 방향만** — 값을 올리는 커밋은 `G-P8.5`가 잡는다.
2. `lintAllowed(lines, i, rule)` — `checkChunkedInQuery`의 인라인 주석 걷기를 이 함수로.
3. (선택) `check()`의 호출 목록을 `RULES` 배열로.

【테스트】
- `TC-P0.T9.a` 표 값 +1줄이면 위반
  단언: 임시 파일을 `RATCHET`에 1200으로 넣고 1201줄 → `file-size-ratchet` 위반 1건
  검출: 래칫이 "1,000 초과"만 보고 표 값을 안 보는 것 — 2,322줄 파일이 3,000줄이 돼도 통과
- `TC-P0.T9.b` 표에 없는 1,001줄 파일은 위반
  단언: 1,001줄 임시 src 파일 → 위반
  검출: 새 파일이 조용히 1k를 넘는 것
- `TC-P0.T9.c` `lint-allow file-size-ratchet: <사유>`는 **허용되지 않는다**
  단언: 주석을 달아도 위반
  검출: 탈출구가 규칙을 무력화하는 것 — 이 규칙의 유일한 탈출구는 표다
- `TC-P0.T9.d` `lintAllowed`가 기존 `chunked-in-query` 예외 3곳을 그대로 인식한다
  단언: `npm run lint` 위반 0
  검출: 공용화하면서 주석 블록 걷기의 경계(`//`와 `*` 줄)가 달라져 기존 예외가 깨지는 것

【통과】
- [ ] `G-P0.21` `cmd`: `node scripts/test-lint.ts` 종료코드 0
- [ ] `G-P0.22` `cmd`: `npm run lint` 종료코드 0
- [ ] `G-P0.23` `grep -c '"packages/proto-imap/src/engine.ts": 2322' scripts/lint.ts` = 1 (표 초기값 7개 중 대표)

### ▢ P0.T10 — 결정 파일 채우기 [변경]
선행: T1 · 산출: `docs/plan/REFACTOR-2026-08-26-decisions.json` · 되돌리기: 커밋 revert · 트리: `p0-gate`

【작업】 계획서 §11의 D-01~D-07을 사람이 정해 적는다. **D-05는 P0 봉인의 전제**(main push가 배포인지에
따라 P1 이후 push 빈도가 달라진다). 나머지는 각 단계 GATE가 요구한다.
【테스트】
- `TC-P0.T10.a` 결정 파일의 값은 허용 집합 밖이면 거부된다
  단언: `D-05.choice = "deploy "`(뒤 공백)·`"Deploy"`·`"yes"` → `gate P0`의 `json` 검사 실패; `"deploy"` → 통과
  검출: 오타 난 결정값을 `json` 검사가 통과시켜 결정 없이 단계가 열리는 것 — 결정 파일이 잠금 장치인 이유가 사라진다

【통과】
- [ ] `G-P0.24` `json`: `D-05.choice` ∈ {`"deploy"`, `"no-deploy"`} (정확 일치, trim 없음 — TC-P0.T10.a)

## 🚪 GATE P0

| id | 검사 | 명령 (`how`) | 통과 기준 |
|:--|:--|:--|:--|
| G-P0.1~6 | 장치 음성 대조 a~f | `test scripts/test-gate.ts` | 종료코드 0 |
| G-P0.7 | R-01 재현 | `red-green packages/store/test/jmap-changes.test.ts fix:[R-01]` | 부모 빨강 · HEAD 초록 |
| G-P0.8 | 캐스트 잔재 | `grep "as typeof t &" in packages/store/src/store.ts` | = 0 |
| G-P0.9 | R-02 재현 | `red-green packages/mta/test/dsn-worker.test.ts fix:[R-02]` | 부모 빨강 · HEAD 초록 |
| G-P0.10 | 가드 3곳 | `grep 'dsnWanted(row.dsnNotify, "failure")' in packages/mta/src/worker.ts` | = 3 |
| G-P0.11 | R-03 재현 | `red-green apps/server/test/jmap-e2e.test.ts fix:[R-03]` | 부모 빨강 · HEAD 초록 |
| G-P0.12 | changes 표준화 | `grep "standardChanges(" in apps/server/src/jmap-backend.ts` | = 6 |
| G-P0.13 | R-04 재현 | `red-green apps/server/test/reports.test.ts fix:[R-04]` | 부모 빨강 · HEAD 초록 |
| G-P0.14 | report-type 유일 | `grep "report-type=delivery-status" in {apps,packages}/**/*.ts` | = 1 |
| G-P0.15 | R-05 재현 | `red-green packages/testkit/test/deadline.test.ts fix:[R-05]` | 부모 빨강 · HEAD 초록 |
| G-P0.16 | env 단일 읽기 | `grep "fromEnv()" in packages/testkit/src/deadline.ts` | = 1 |
| G-P0.17 | R-06 | `cmd python3 scripts/claude-hooks/test-session-end-cleanup.py` | 0 |
| G-P0.18 | cwd 해석 잔재 | `grep 'data.get("cwd")' in scripts/claude-hooks/session-end-cleanup.py` | = 0 |
| G-P0.19 | R-07 | `test apps/server/test/jmap-e2e.test.ts` | 0 |
| G-P0.20 | R-07 결정 | `json decisions D-06.choice` | ∈ {0-A, 4-B, closed} |
| G-P0.21 | 래칫 음성 대조 | `cmd node scripts/test-lint.ts` | 0 |
| G-P0.22 | 린트 | `cmd npm run lint` | 0 |
| G-P0.23 | 래칫 초기값 | `grep '"packages/proto-imap/src/engine.ts": 2322' in scripts/lint.ts` | = 1 |
| G-P0.24 | D-05 | `json decisions D-05.choice` | ∈ {deploy, no-deploy} |
| G-P0.25 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P0.26 | 표면 기준선 | `surface packages/{store,mta,proto-imap,proto-smtp,proto-jmap,core,sieve,mime,db,webhook,mta-sts,mail-auth}` | 스냅샷 **기록**(비교 대상 없음) |

`node scripts/gate.ts P0 --seal`

가장 중요한 검사는 **G-P0.1~6**이다. 장치가 순서를 안 걸면(a), 되돌림을 못 보면(b), 옛 결과로
봉인하면(c), 검출력이 없으면(d) 이 문서의 나머지 전부가 산문이 된다. 결함 7건의 `red-green`은
그 다음이다 — 이 일곱은 뒤 단계의 추출이 행동을 보존했음을 증명하는 유일한 기계적 근거다.

---

# P1 — store 재편 🔒 잠김 (P0 필요)

**브랜치** 워크트리 `p1-store`. 계획서 §3. T1→T2→T3→T4→T5 순차(같은 함수), T6·T7·T8 병렬 가능,
T9·T10은 T1~T8 뒤.

### ▢ P1.T1 — `message-destroy.ts` 빌더 [신설]
선행: P0 봉인 · 산출: `packages/store/src/message-destroy.ts`, `packages/store/test/message-destroy.test.ts`,
`scripts/lint.ts`(`checkAccountBumpOwner`) · 되돌리기: 커밋 revert(호출자 없음) · 트리: `p1-store`

【작업】
1. `destroyMessageStatements(ctx, dying)` · `detachMessageStatements(ctx, surviving)` ·
   `accountBumpStatement(accountId, nextModseq, touched, delta?)` — 계획서 §3 1-A의 시그니처.
   내부 `chunk()`(P1.T8 전까지는 `store/chunk.ts`).
2. 린트 규칙 `checkAccountBumpOwner`: `UPDATE accounts SET modseq`가 `message-destroy.ts` 밖에서 나오면 위반.
   이 커밋에서는 **기존 12곳이 위반**이므로 규칙은 추가하되 `RATCHET`처럼 예외 수 12를 적고
   T2에서 0으로.

【테스트】
- `TC-P1.T1.a` 빌더가 내는 문장 순서는 툼스톤 → 멤버십 삭제 → 메시지 삭제다
  단언: `destroyMessageStatements`의 결과 배열에서 `INSERT INTO expunged`의 인덱스 < `DELETE FROM message_mailbox`
  < `DELETE FROM messages`
  검출: 순서가 바뀌어 QRESYNC `VANISHED`가 툼스톤 없이 답하는 것(계획서 §13 첫 위험)
- `TC-P1.T1.b` `touched`가 `{email}`이면 `state_thread`를 안 올린다; `{email, thread}`면 올린다
  단언: 생성된 SQL의 SET 절 컬럼 집합이 `touched`에서만 파생된다
  검출: 삼항 12벌이 하던 "어느 state_*를 올리나"가 빌더에서도 손으로 되는 것
- `TC-P1.T1.c` 파괴 문장은 `message_text`·`search_index`·`message_addresses`·`thread_refs`를 전부 지운다
  단언: 테이블 이름 집합 단언
  검출: 검색 부산물 누락(`c57b541`이 고친 결함의 재발)
- `TC-P1.T1.d` 파괴 대상 101개면 문장이 파라미터 한도 안에서 나뉜다
  단언: 어떤 문장도 `params.length > MAX_PARAMS_PER_STATEMENT`가 아니다
  검출: 빌더가 `chunk()`를 안 타는 것 — `UID EXPUNGE 1:*`가 D1에서 깨진다

【통과】
- [ ] `G-P1.1` `test packages/store/test/message-destroy.test.ts`
- [ ] `surface packages/store` — `allowAdded: [destroyMessageStatements, detachMessageStatements, accountBumpStatement]`

### ▢ P1.T2 — 파괴 경로 4곳 · 계정 UPDATE 12곳을 빌더로 [변경]
선행: T1 · 산출: `store.ts`(`reapMailboxAttempt`, `expungeAttempt`, `removeMembershipAttempt`,
`destroyMessageAttempt`, `setKeywords*`, `copyOrMoveBatchAttempt`, `moveMessageAttempt`, `copyMessageAttempt`) ·
되돌리기: 커밋 revert · 트리: `p1-store`

【작업】 1. 네 파괴 경로: 행 수집 → 빌더 → batch. 2. 나머지 계정 UPDATE 8곳 → `accountBumpStatement`.
3. R-01의 임시 수정이 자연히 사라진다(`threadId`가 빌더 입력).

【테스트】
- `TC-P1.T2.a` 네 경로 모두 Thread 로그(= P0.T2 a~d)가 계속 초록
  단언: `jmap-changes.test.ts` 초록
  검출: 전환 중 한 경로가 `touched`에 `thread`를 안 넣는 것
- `TC-P1.T2.b` expunge 뒤 `accounts.used_bytes`·`message_count`·`mailboxes.total_*`가 정확
  단언: `expunge.test.ts`의 기존 카운터 단언 + `used_bytes`가 마지막 멤버십 메시지 크기만큼만 준다
  검출: `delta`가 "죽는 메시지"가 아니라 "제거된 멤버십" 기준으로 잘못 계산되는 것
  (`dyingBytes` vs `mailboxBytes` 구분, `store.ts:1340-1341`)

【통과】
- [ ] `G-P1.2` `grep "UPDATE accounts SET modseq" in packages/store/src/store.ts` = 0
- [ ] `G-P1.3` `test packages/store/test/{jmap-changes,expunge,reap-mailbox,move,threading,search-artifact-cleanup,batch-flags-copy}.test.ts`
- [ ] `G-P1.4` `cmd npm run lint` (checkAccountBumpOwner 예외 수 0)

### ▢ P1.T3 — `copy-move-store.ts`로 이동 [이동]
선행: T2 · 산출: `packages/store/src/copy-move-store.ts`, `store.ts`(위임 3줄) · 되돌리기: 커밋 revert · 트리: `p1-store`

【작업】 `copyOrMoveMessages`·`copySearchArtifacts`·`copyMessage`·`moveMessage`를 내용 무변경으로 이동.
`StoreInternals` 사용(`jmap-store.ts` 형식).

【테스트】
- `TC-P1.T3.a` 표면 동일
  단언: `surface packages/store` 변화 0
  검출: 이동하면서 export가 새거나 빠지는 것
- `TC-P1.T3.b` 이동 커밋의 numstat 대칭
  단언: `git show --numstat HEAD`에서 `store.ts` 삭제 줄 수 − `copy-move-store.ts` 추가 줄 수의 절댓값 ≤ 15(import·위임)
  검출: "이동"이라며 내용을 고치는 것

【통과】
- [ ] `G-P1.5` `surface packages/store` 동일
- [ ] `G-P1.6` `test packages/store/test/{batch-flags-copy,move}.test.ts`

### ▢ P1.T4 — copy/move 갈래 분리 · dead branch · 부산물 한 배치 [변경]
선행: T3 · 산출: `copy-move-store.ts` · 되돌리기: 커밋 revert · 트리: `p1-store`

【작업】 `loadCopyMoveSources → planMove | planCopy → 조립`. `op` 플래그 5곳 제거. `:1607-1625` 삭제.
`groupBy` 사용. `copySearchArtifacts` → `multiRowInsertStatements` 한 배치, `COPY_ARTIFACT_STATEMENTS_PER_BATCH` 삭제.

【테스트】
- `TC-P1.T4.a` COPY는 대상에 이미 있어도 새 메시지 행을 만든다(G2 의미)
  단언: 같은 메일함으로 copy 2회 → messages 행 2개, uid 2개
  검출: dead branch를 살려 "이미 있으면 no-op"으로 되돌리는 것 — `imap-copy-semantics.test.ts`
- `TC-P1.T4.b` 같은 메일함으로 MOVE는 no-op이고 메일을 지우지 않는다(T-01)
  단언: `move.test.ts`의 T-01 케이스
  검출: `planMove`가 `srcUid !== existing` 검사를 잃는 것 — 2026-08-25 검수의 "메일 소실" 재발
- `TC-P1.T4.c` COPY 부산물 복제가 한 `db.batch`다
  단언: `db.batch` 호출 횟수를 세는 래퍼 DbDriver로 copy 1회 → batch 2회 이하(본체 + 부산물)
  검출: 분할 루프가 남아 부산물이 여러 배치로 나가 중간 실패 시 반쪽 인덱스(T-04)
- `TC-P1.T4.d` 쿼터 초과 COPY는 거절된다(T-03)
  단언: 기존 케이스
  검출: `planCopy`가 `assertQuota`를 빠뜨리는 것

【통과】
- [ ] `G-P1.7` `test packages/store/test/{batch-flags-copy,move,search-artifact-cleanup}.test.ts` + `apps/server/test/imap-copy-semantics.test.ts`
- [ ] `G-P1.8` `grep "COPY_ARTIFACT_STATEMENTS_PER_BATCH" in packages/store/src/**` = 0
- [ ] `G-P1.9` `grep 'input.op === "copy"' in packages/store/src/copy-move-store.ts` = 0 (갈래는 함수로 나뉘었다)

### ▢ P1.T5 — `setMailboxMembership` · `moveMessage` 삭제 [변경]+[삭제]
선행: T4 · 산출: `copy-move-store.ts`(신규 API), `types.ts`, `apps/server/src/jmap-backend.ts:394-399` ·
되돌리기: 커밋 `[T-07]` revert(JMAP 호출부 포함) · 트리: `p1-store`

【작업】 1. `setMailboxMembership({ accountId, messageId, desired })` 한 배치 — 대상 메일함 소유 검증을
배치 안 SELECT로. 2. JMAP 호출부 한 줄. 3. `moveMessage`·`moveMessageAttempt`·`MoveMessageInput` 삭제.

【테스트】
- `TC-P1.T5.a` 혼합 패치(유효 + 없는 메일함)는 아무것도 남기지 않는다(T-07 ②)
  단언: `Email/set update { mailboxIds: { valid: true, missing: true } }` → `notUpdated`, `Email/get`의
  `mailboxIds` 불변, `accounts.modseq` 불변
  검출: 순차 루프가 첫 `copyMessage`를 커밋한 뒤 두 번째에서 실패하는 것 — RFC 8620 §5.3 위반
- `TC-P1.T5.b` 단일 이동(제거 1 + 추가 1)의 결과가 예전 `moveMessage`와 같다
  단언: 원본 메일함에 툼스톤, 대상에 새 uid, `used_bytes` 불변, Email·Mailbox·Thread 로그
  검출: 삭제한 `moveMessageAttempt`가 하던 카운터 산술이 새 경로에서 빠지는 것
- `TC-P1.T5.c` `desired`가 현재와 같으면 배치 0회
  단언: batch 카운트 0, modseq 불변
  검출: 빈 변경에 modseq를 소비해 `Email/changes`가 헛 항목을 내는 것

【통과】
- [ ] `G-P1.10` `red-green apps/server/test/jmap-e2e.test.ts fix:[T-07]`(TC a)
- [ ] `G-P1.11` `grep "moveMessage(" in {packages,apps}/**/*.ts` = 0
- [ ] `G-P1.12` `surface packages/store` — `allowRemoved: [MoveMessageInput]`, `allowAdded: [setMailboxMembership, SetMailboxMembershipInput]`

### ▢ P1.T6 — `KeywordChange` · `keyword-store.ts` [변경]
선행: T2 · 산출: `packages/store/src/keyword-store.ts`, `types.ts`, `store.ts`, 호출자 3곳 · 되돌리기: 커밋 revert · 트리: `p1-store`

【작업】 1. 이동 커밋(`setKeywords`·`setKeywordsBatch` → `keyword-store.ts`). 2. 수정 커밋:
`KeywordChange` 유니온, `setKeywordsAttempt` 하나, 단일 버전 삭제, `replace?: boolean` 삭제, 호출자 갱신.

【테스트】
- `TC-P1.T6.a` `replace`는 현재 키워드에 없는 것만 추가하고 없어진 것만 제거한다
  단언: 현재 `{a,b}` → replace `{b,c}` → change_log에 `updated` 1건, `unread_count` 델타는 `\Seen` 유무로만
  검출: `toAdd = addAll.filter(k => !current.has(k) && !(input.replace ? false : removeSet.has(k)))`
  같은 플래그 꿰기가 유니온으로 옮겨지며 seen 토글이 두 번 세지는 것
- `TC-P1.T6.b` 단일 메시지 호출(IMAP STORE 1건)과 배치 호출의 결과가 같다
  단언: `keywords.test.ts`의 기존 단일 케이스가 배치 경로로 통과
  검출: 단일 경로 삭제로 IMAP `STORE` 한 건의 `MODSEQ` 응답이 달라지는 것(`condstore.test.ts`)

【통과】
- [ ] `G-P1.13` `test packages/store/test/keywords.test.ts` + `packages/proto-imap/test/condstore.test.ts`
- [ ] `G-P1.14` `grep "replace?: boolean" in packages/store/src/**` = 0
- [ ] `G-P1.15` `surface packages/store` — `allowAdded: [KeywordChange]`

### ▢ P1.T7 — 실패 표현 통일 · `parseAuthSurfaces` [변경]
선행: 없음(T6과 병렬) · 산출: `store.ts`(`getQuota`), `jmap-store.ts`, `auth.ts`, `admin-cmd/accounts.ts`,
`apps/server/src/jmap-backend.ts`(`wrapStore` 경로) · 되돌리기: 커밋 revert · 트리: `p1-store`

【테스트】
- `TC-P1.T7.a` 없는 계정의 `getQuota`는 `null`
  단언: 반환 `null`, throw 없음
  검출: 읽기 함수가 throw해 IMAP `GETQUOTA`가 `NO`가 아니라 연결 오류로 떨어지는 것
- `TC-P1.T7.b` 없는 identity `updateIdentity`는 `StoreError`
  단언: throw, `jmap-backend`가 `notFound`로 옮김(`jmap-quota-vacation.test.ts`)
  검출: boolean `false`를 호출자가 무시해 `updated`로 응답하는 것
- `TC-P1.T7.c` CLI가 받아들인 scope를 관문이 거절하지 않는다
  단언: `admin-cmd`로 `"imap, smtp"` 저장 → `authenticate(surface: "imap")` 허용, `" IMAP,,smtp "` 정규화 동일
  검출: 두 파서의 구분자·정규화가 갈라져 CLI는 저장하고 관문은 막는 것

【통과】
- [ ] `G-P1.16` `test packages/store/test/{credential-scopes,tenant-usage}.test.ts` + `apps/server/test/{imap-quota,jmap-quota-vacation}.test.ts`
- [ ] `G-P1.17` `grep "split(/[,\\s]+/)" in packages/admin-cmd/src/accounts.ts` = 0

### ▢ P1.T8 — 청크 소유자 → `@ionosphere/db` · `inListStatements` [이동]+[변경]
선행: 없음 · 산출: `packages/db/src/chunk.ts`, `packages/db/test/batch.test.ts`, `store/chunk.ts`(re-export 한 줄 — **P8.T2가 회수**),
`mta/chunk.ts`(삭제), `store.ts` 11곳, `scripts/lint.ts` · 되돌리기: 이동 커밋 + 수정 커밋 · 트리: `p1-store`

【작업】 1. 이동 커밋: `chunk`·`rowsPerStatement`·`multiRowInsertStatements`·`queryInChunks`·상수 → db.
`mta/chunk.ts` 삭제, mta 호출자 갱신. 2. 수정 커밋: `inListStatements(items, sql, fixed)`; 쓰기 11곳 교체;
`DELETED_FIXED_PARAMS` 삭제; 린트 확장 + `MAX_PARAMS_PER_STATEMENT` 재선언 금지.

【테스트】
- `TC-P1.T8.a` `inListStatements`는 고정 파라미터를 세고 100을 넘기지 않는다
  단언: `fixed` 2개 + 항목 99개 → 문장 2개(98+1), 모든 `params.length ≤ 100`
  검출: `rowsPerStatement(1) - 1` 손 계산이 고정 파라미터 수를 틀리는 것 — 101-파라미터 버그의 원형
- `TC-P1.T8.b` 린트가 `db.batch` 근처 `map(() => "?")`를 잡는다
  단언: 픽스처 위반 1건
  검출: 쓰기 경로 탈출구
- `TC-P1.T8.c` 상수가 두 곳이면 린트 위반
  단언: 픽스처에 `MAX_PARAMS_PER_STATEMENT = 100` 재선언 → 위반
  검출: D1 한도가 다시 갈라지는 것

【통과】
- [ ] `G-P1.18` `grep "MAX_PARAMS_PER_STATEMENT = " in packages/**/src/**` = 1
- [ ] `G-P1.19` `grep "DELETED_FIXED_PARAMS" in packages/store/src/**` = 0
- [ ] `G-P1.20` `test packages/db/test/batch.test.ts` + `apps/server/test/dialect-contract.test.ts`
- [ ] `G-P1.21` `cmd test ! -e packages/mta/src/chunk.ts` 종료코드 0 (파일 없음)

### ▢ P1.T9 — `store.ts` 분리 · 어댑터 진입점 [이동]+[신설]
선행: T2~T8 · 산출: `usage-store.ts`(quota), `store.ts`, `mailbox-sync.ts`(`vanishedSince`, `listMessageSortKeys`),
`types.ts`(`AppendMessageInput.deleted?`), `MAILBOX_COLUMNS` · 되돌리기: 이동 커밋 / 신설 커밋 분리 · 트리: `p1-store`

【테스트】
- `TC-P1.T9.a` `vanishedSince`는 floor 이상이면 툼스톤, 미만이면 차집합
  단언: `expunged_floor = 50`; `since = 60` → 툼스톤 질의 결과; `since = 40` → `knownRanges`와 현재 uid의 차집합;
  `since = 50` → 툼스톤
  검출: 어댑터에 있던 분기가 store로 오며 `>=`가 `>`로 바뀌는 것 — 경계 modseq에서 VANISHED 누락
- `TC-P1.T9.b` `knownRanges`의 `*`와 역순 범위가 `normalizeRanges`로 정규화된다
  단언: `[[5, "*"], [3, 1]]` → `[1..3, 5..uidnext-1]`
  검출: `vanishedByDifference`가 손으로 하던 `max(1, …)`·swap이 사라지며 역순 범위가 빈 집합이 되는 것
- `TC-P1.T9.c` `getMailboxByName` 행에도 `expungedFloor`가 실린다
  단언: floor 50인 메일함을 이름으로 조회 → `expungedFloor === 50`
  검출: 세 SELECT 중 둘이 컬럼을 안 실어 `?? 0`이 되는 것 — 그 행으로 QRESYNC에 답하면 삭제된 툼스톤을 믿는다
- `TC-P1.T9.d` `deleted: true`로 append하면 같은 배치에서 `message_mailbox.deleted = 1`
  단언: batch 1회, 조회 시 `\Deleted`
  검출: 멤버십 INSERT와 별개 배치가 남는 것(P2.T6이 이 필드에 의존)

【통과】
- [ ] `G-P1.22` `lines packages/store/src/store.ts` ≤ 1000
- [ ] `G-P1.23` `grep "expunged_floor ?? 0" in packages/store/src/**` = 0
- [ ] `G-P1.24` `test packages/store/test/**` 전체
- [ ] `G-P1.25` `surface packages/store` — `allowAdded: [vanishedSince, listMessageSortKeys]`

### ▢ P1.T10 — 보존·리포트 상수의 소유 [변경]
선행: 없음(P6.T6과 **순차** — 같은 `core/limits.ts`) · 산출: `packages/core/src/limits.ts`, `store/retention.ts`,
`mta/enqueue.ts`, `store/report-store.ts`, `apps/server/src/reports.ts` · 되돌리기: 커밋 revert · 트리: `p1-store`

【테스트】
- `TC-P1.T10.a` 큐 보존 기본값은 가장 긴 레이트리밋 윈도우보다 길다
  단언: `QUEUE_RETENTION_MS >= RATE_LIMIT_MAX_WINDOW_MS`
  검출: `perWeek` 윈도우가 추가돼 스윕이 카운트 행을 먼저 지우는 것 — 계획서 §3 1-E
- `TC-P1.T10.b` 리포트 보존 일수가 한 곳 (기계 판정은 `G-P1.27`)
  단언: `reports.ts`와 `purgeReportRows`가 같은 상수를 참조
  검출: 한쪽 7을 14로 올려 `report_sends`가 먼저 지워지고 재발송되는 것

【통과】
- [ ] `G-P1.26` `test packages/store/test/retention.test.ts`
- [ ] `G-P1.27` `grep "7 \* 86_400_000|retentionDays ?? 7" in {packages,apps}/**/src/**` = 0

## 🚪 GATE P1

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P1.1 | 빌더 | `test packages/store/test/message-destroy.test.ts` | 0 |
| G-P1.2 | 계정 UPDATE 소유 | `grep "UPDATE accounts SET modseq" in packages/store/src/store.ts` | = 0 |
| G-P1.3 | 파괴 경로 회귀 | `test` 7개 파일(P1.T2) | 0 |
| G-P1.4 | 린트(소유 규칙) | `cmd npm run lint` | 0 |
| G-P1.5 | 이동 표면 | `surface packages/store since seal:P0` | 허용 목록 외 변화 0 |
| G-P1.6~7 | copy/move | `test` (P1.T3, T4) | 0 |
| G-P1.8 | 부산물 분할 잔재 | `grep "COPY_ARTIFACT_STATEMENTS_PER_BATCH"` | = 0 |
| G-P1.9 | op 플래그 잔재 | `grep 'input.op === "copy"' in copy-move-store.ts` | = 0 |
| G-P1.10 | T-07 ② | `red-green apps/server/test/jmap-e2e.test.ts fix:[T-07]` | 부모 빨강 · HEAD 초록 |
| G-P1.11 | moveMessage 삭제 | `grep "moveMessage(" in {packages,apps}/**/*.ts` | = 0 |
| G-P1.12~15 | 키워드 | `test` + `grep "replace?: boolean"` | 0 / = 0 |
| G-P1.16~17 | 실패 표현·scope | `test` + `grep` | 0 / = 0 |
| G-P1.18 | 청크 상수 유일 | `grep "MAX_PARAMS_PER_STATEMENT = " in packages/**/src/**` | = 1 |
| G-P1.19~21 | 청크 | `grep` · `test` · `cmd` | = 0 / 0 / 0 |
| G-P1.22 | **store.ts 크기** | `lines packages/store/src/store.ts` | ≤ 1000 |
| G-P1.23 | floor 폴백 잔재 | `grep "expunged_floor ?? 0"` | = 0 |
| G-P1.24 | store 전체 | `test packages/store/test/**` | 0 |
| G-P1.25 | 표면 | `surface packages/store` | 허용 목록 |
| G-P1.26~27 | 상수 | `test` · `grep` | 0 / = 0 |
| G-P1.28 | 래칫 갱신 | `json scripts/lint.ts RATCHET["packages/store/src/store.ts"]` | absent |
| G-P1.29 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P1.30 | 릴리즈 기록 | `json releases P1` + `cmd git tag -l <값>` | 문자열 · 태그 존재 |

`node scripts/gate.ts P1 --seal`

가장 중요한 검사는 **G-P1.2**다. `UPDATE accounts SET modseq`가 `store.ts`에 0건이라는 것은 "어느
state_*를 올리나"를 결정하는 코드가 한 곳(`accountBumpStatement`)뿐이라는 뜻이고, 그것이 T-09가
요구했던 바로 그 헬퍼다. 이 검사가 초록이면 EXPUNGE 결함의 재발 경로가 구조적으로 없다.

---

# P3 — SMTP 엔진 + MTA 🔒 잠김 (P0 필요)

**브랜치** 워크트리 `p3-smtp-mta`. 계획서 §4. T1 → {T2, T3→T4, T5, T6} → T7 → T8. T5·T6·T7은
서로 다른 파일이라 병렬 가능하나 T5·T6은 같은 `engine.ts`이므로 순차.

### ▢ P3.T1 — `core/dsn-params.ts` [신설]
선행: P0 봉인 · 산출: `packages/core/src/dsn-params.ts`, `packages/core/test/dsn-params.test.ts`(`mta/test/dsn-params.test.ts`
이동+확장), `proto-smtp/src/engine.ts`, `mta/src/enqueue.ts`, `mta/src/worker.ts` · 되돌리기: 신설 커밋 / 호출자 커밋 · 트리: `p3-smtp-mta`

【작업】 1. 신설 커밋: `DsnNotify`·`DsnRet`·`DsnParams`·`parseNotify`/`serializeNotify`·`decodeXtext`/`encodeXtext`·
`dsnWanted`. 2. 호출자 커밋: 엔진은 파서만, `enqueue.ts`의 인라인 타입 삭제, 워커는
`dsnWanted(parseNotify(row.dsn_notify), kind)`. DB 컬럼은 문자열 유지(스키마 무변경).

【테스트】
- `TC-P3.T1.a` `parseNotify ∘ serializeNotify`가 항등이다
  단언: `{never:true}`, `{success,failure,delay}` 8조합 전부 왕복 동일; `"NEVER,SUCCESS"`는 파스 오류
  검출: 엔진이 `[...new Set(parts)].join(",")`로 인코드하고 워커가 `split(",")`로 디코드하며 한쪽만
  대소문자·중복 규칙을 바꾸는 것
- `TC-P3.T1.b` `dsnWanted`의 기본값(NOTIFY 없음)은 failure·delay true, success false
  단언: `parseNotify(null)` → `{never:false, success:false, failure:true, delay:true}` (RFC 3461 §4.1)
  검출: 기본값이 워커의 문자열 비교에 묻혀 있던 것 — 이동하면서 `null`을 NEVER로 읽는 실수
- `TC-P3.T1.c` xtext는 `+`·`=`·제어문자를 정확히 escape/unescape한다
  단언: `"a=b+c"` → `"a+3Db+2Bc"` → 원복
  검출: 엔진의 `decodeXtext`와 `smtp-client`의 인코더가 갈라지는 것(현재 인코더는 없다 — 3-A ①에서 필요)

【통과】
- [ ] `G-P3.1` `test packages/core/test/dsn-params.test.ts`
- [ ] `G-P3.2` `grep 'split(",")' in packages/mta/src/**` = 0
- [ ] `G-P3.3` `grep "notify?: string" in packages/mta/src/enqueue.ts` = 0 (구조적 재선언 삭제)
- [ ] `G-P3.4` `surface packages/core` — `allowAdded: [DsnNotify, DsnRet, DsnParams, parseNotify, serializeNotify, decodeXtext, encodeXtext, dsnWanted]`

### ▢ P3.T2 — D-01: ENVID/RET/SMTPUTF8 끝까지 잇기 또는 삭제 [변경]
선행: T1, decisions `D-01` · 산출(①): `mta/src/dsn.ts`(`DsnInput.originalEnvelopeId`, `returnFull`), `worker.ts`(`sendDsn`),
`db/src/migrations/020_smtputf8.ts`, `proto-smtp` `deliver` 액션, `enqueue.ts`, `smtp-client.ts`(`isAscii` 재유도 삭제) ·
산출(②): 컬럼·필드·SELECT 삭제 · 되돌리기: ①은 마이그레이션 포함 — **되돌리기 불가**, 롤포워드만 · 트리: `p3-smtp-mta`

【작업】 ①: 계획서 §4 3-A 3항. 마이그레이션은 이 계획의 **유일한 스키마 변경** — 3단계 릴리즈 전
운영 저장소 백업 절차. ②: 삭제.

【테스트】
- `TC-P3.T2.a` (①) ENVID가 있으면 DSN에 `Original-Envelope-Id`가 있다
  단언: `MAIL FROM:<a@example.com> ENVID=abc` → 바운스 DSN `message/delivery-status` 파트에 `Original-Envelope-Id: abc`
  검출: `dsn_envid`가 저장·로드되고 아무도 안 읽는 것 — RFC 3464 §2.2.1 MUST 위반이 조용히 지속
- `TC-P3.T2.b` (①) `RET=FULL`이면 원본 전체, `RET=HDRS`·생략이면 헤더만
  단언: 세 번째 파트가 `message/rfc822` vs `message/rfc822-headers`
  검출: `RET=FULL`이 HDRS로 취급되는 것
- `TC-P3.T2.c` (①) 엔진이 파싱한 SMTPUTF8이 발송 클라이언트까지 온다
  단언: `MAIL FROM … SMTPUTF8` → 큐 행 `smtputf8 = 1` → `sendSmtp` 호출 인자 `smtputf8: true`
  검출: `smtp-client.ts:641`의 주소 바이트 재유도 — 헤더만 UTF-8인 메시지에서 플래그가 빠지는 것
- `TC-P3.T2.d` (②) 컬럼이 없어도 마이그레이션이 통과하고 `QueueRow`에 필드가 없다
  단언: `tsc` 통과 + `grep dsnEnvid` = 0
  검출: 죽은 데이터 경로가 "나중에 누군가 다시 읽는" 것

【통과】
- [ ] `G-P3.5` `json decisions D-01.choice` ∈ {1, 2}
- [ ] `G-P3.6` (①) `test packages/mta/test/{dsn,dsn-worker,smtputf8-cleartext-auth}.test.ts`; (②) `grep "dsnEnvid|dsnRet\b" in packages/mta/src/**` = 0
- [ ] `G-P3.7` (①) `grep "isAscii(" in packages/mta/src/smtp-client.ts` = 0

### ▢ P3.T3 — `esmtp-params.ts`로 이동 [이동]
선행: T1 · 산출: `packages/proto-smtp/src/esmtp-params.ts`, `engine.ts`, `index.ts` · 되돌리기: 커밋 revert · 트리: `p3-smtp-mta`

【테스트】
- `TC-P3.T3.a` 표면 동일 + numstat 대칭(≤ 15)
  단언: `surface packages/proto-smtp` 변화 0(내부 함수는 export가 아니었다 → `index.ts` re-export만 추가:
  `allowAdded: [parseMailFromArgs, parseRcptToArgs, SmtpDsnParams]`)
  검출: 이동 중 파서 오류 문구·코드를 고치는 것

【통과】
- [ ] `G-P3.8` `surface packages/proto-smtp` 허용 목록
- [ ] `G-P3.9` `lines packages/proto-smtp/src/engine.ts` ≤ 1078 (1238 − 160)

### ▢ P3.T4 — 표 기반 파라미터 파서 · `action` 객체 전달 [변경]
선행: T3 · 산출: `esmtp-params.ts`, `server.ts:299` · 되돌리기: 커밋 revert · 트리: `p3-smtp-mta`

【테스트】
- `TC-P3.T4.a` 미지 파라미터는 504, 값 오류는 501 5.5.4
  단언: `MAIL FROM:<a@example.com> FOO=1` → `504`; `SIZE=abc` → `501 5.5.4`; `NOTIFY=NEVER,SUCCESS` → `501 5.5.4`
  검출: if/else 11벌 → 표 전환 중 한 키워드의 코드가 바뀌는 것(`engine.test.ts` 기존 케이스 + 추가)
- `TC-P3.T4.b` `runDeliver`가 `action` 객체를 받아도 감사 로그 필드가 같다
  단언: `server.test.ts`의 audit 단언 유지
  검출: 6개 위치 인자 → 객체 전환 중 순서가 섞이는 것(`from`/`rcpts` 자리 바뀜)

【통과】
- [ ] `G-P3.10` `test packages/proto-smtp/test/{engine,server,scram-pipeline}.test.ts`
- [ ] `G-P3.11` `grep 'message: "Invalid' in packages/proto-smtp/src/esmtp-params.ts` ≤ 1 (생성자 하나)

### ▢ P3.T5 — `BodySink` · 프레이머 [변경]
선행: T4 · 산출: `packages/proto-smtp/src/body-sink.ts`, `engine.ts`, `scripts/lint.ts`(`checkEngineBufferLimit` 갱신) ·
되돌리기: 커밋 revert · 트리: `p3-smtp-mta`

【작업】 (커밋 전에) `engine.test.ts`에 "CRLF가 청크 경계에 걸친 DATA"·"BDAT 청크가 한도 경계에 정확히 닿는" 케이스를
먼저 추가한다 — 계획서 §13.

【테스트】
- `TC-P3.T5.a` DATA와 BDAT 한도 초과의 552 응답 문구가 같다
  단언: 두 경로 모두 `552 5.3.4 Message size exceeds fixed maximum message size`
  검출: `pumpBdat`의 `Message size exceeds limit`(`:1035`)가 살아남는 것
- `TC-P3.T5.b` 한도 초과 뒤 `dataChunks`가 비어 있고 상태가 `greeted`다
  단언: 552 뒤 `RSET` 없이 `MAIL FROM` 성공, 메모리 상 누적 0
  검출: 세 곳 한도 검사 중 하나가 빠져 한도를 넘긴 바이트를 쌓는 것 — 엔진의 가장 보안 민감한 불변식
- `TC-P3.T5.c` `CRLF.CRLF`가 두 청크에 걸쳐 와도 종료를 인식한다
  단언: `"…\r\n."`, `"\r\n"` 두 write → 250
  검출: 프레이머로 옮기며 dot-unstuff 경계 처리가 오프바이원
- `TC-P3.T5.d` `BDAT n LAST`의 n이 한도 경계와 같으면 통과, +1이면 552
  단언: `maxSizeBytes` 정확히 채우기 → 250; +1 → 552
  검출: `>`와 `>=` 혼동
- `TC-P3.T5.e` `ConnState`에 `"bdat"`가 없다
  단언: 타입 수준 — `grep`(G-P3.13)
  검출: 프레이머 선택이 다시 연결 상태로 되돌아가는 것

【통과】
- [ ] `G-P3.12` `test packages/proto-smtp/test/{bdat,engine}.test.ts`
- [ ] `G-P3.13` `grep '"bdat"' in packages/proto-smtp/src/engine.ts` = 0
- [ ] `G-P3.14` `grep "552 5.3.4" in packages/proto-smtp/src/**` = 1
- [ ] `G-P3.15` `grep "dataChunks.push" in packages/proto-smtp/src/engine.ts` = 0 (sink만 쌓는다)

### ▢ P3.T6 — `auth-machine.ts` [이동]+[변경]
선행: T5 · 산출: `packages/proto-smtp/src/auth-machine.ts`, `test/auth-machine.test.ts`, `engine.ts` · 되돌리기: 커밋 revert · 트리: `p3-smtp-mta`

【테스트】
- `TC-P3.T6.a` 6상태 전이가 엔진 없이 검증된다
  단언: `start("PLAIN", initial)`→`continueLine`→결과; `start("SCRAM-SHA-256")`→`keysResult`→`continueLine` 두 번→성공;
  중간 `*` → 501 취소
  검출: 서브머신이 엔진의 `awaiting`·`pendingAuthUser`에 몰래 의존해 단독 테스트가 불가능한 것
- `TC-P3.T6.b` SCRAM 키 조회 실패도 버퍼를 비우고 실패를 센다(`023f784` 회귀)
  단언: `scram-pipeline.test.ts` 기존 케이스
  검출: 이동 중 `scramFailedAction`의 버퍼 비우기가 빠지는 것

【통과】
- [ ] `G-P3.16` `test packages/proto-smtp/test/{auth-machine,scram-pipeline,engine}.test.ts` + `apps/server/test/scram-e2e.test.ts`
- [ ] `G-P3.17` `lines packages/proto-smtp/src/engine.ts` ≤ 1000
- [ ] `G-P3.18` `grep "authContinuation" in packages/proto-smtp/src/engine.ts` = 0

### ▢ P3.T7 — `outcome.ts` · `bounceRecipient` [신설]+[변경]
선행: T1 · 산출: `packages/mta/src/outcome.ts`, `test/outcome.test.ts`, `worker.ts`, `dsn.ts`(`originalMessage: Uint8Array | null`) ·
되돌리기: 신설 커밋 / 전환 커밋 · 트리: `p3-smtp-mta`

【테스트】
- `TC-P3.T7.a` 세 reason × NOTIFY 4종 = 12조합의 `dsn` 유무가 표와 같다
  단언: `bounceRecipient(row, {reason})`에 대해 `{permanent, exhausted, unreachable}` × `{null, NEVER, FAILURE, SUCCESS}` →
  `dsn !== null` ⇔ `dsnWanted(notify, "failure")`
  검출: R-02의 재발 — 세 사본 중 하나가 가드를 잃는 것. DB 없이 순수 함수로 검증
- `TC-P3.T7.b` `remoteMta`는 대화가 있었던 실패(permanent)에만 있다
  단언: `exhausted`·`unreachable` → `remoteMta` 없음
  검출: MX 소진 DSN에 없는 원격 MTA 이름이 들어가는 것
- `TC-P3.T7.c` null-sender 행은 `sendDsn`에서만 걸러진다
  단언: `noteDelayIfDue`가 null-sender 행에 `DsnRecipient`를 반환하고 `sendDsn`이 발송 0회
  검출: 가드 2벌(`:1145`, `:1176`) 중 하나가 남아 delay DSN만 다르게 동작하는 것
- `TC-P3.T7.d` `deferAll(rows, failure, null)`이 원본 없는 DSN을 낸다
  단언: DSN에 `message/rfc822*` 파트 없음, 다른 파트 정상
  검출: `raw ?? new Uint8Array(0)`가 빈 원본을 붙이던 것

【통과】
- [ ] `G-P3.19` `test packages/mta/test/{outcome,dsn-worker,dsn}.test.ts`
- [ ] `G-P3.20` `grep "DSN_ACTION.failed" in packages/mta/src/worker.ts` = 0
- [ ] `G-P3.21` `grep "raw?: Uint8Array" in packages/mta/src/worker.ts` = 0

### ▢ P3.T8 — `tick-plan.ts` · `core/lanes.ts` · `errMsg` 통합 [신설]+[변경]
선행: T7 · 산출: `packages/mta/src/tick-plan.ts`, `packages/core/src/lanes.ts`, `test/tick-plan.test.ts`, `core/test/lanes.test.ts`,
`worker.ts`, `smtp-client.ts` · 되돌리기: 커밋 revert · 트리: `p3-smtp-mta`

【테스트】
- `TC-P3.T8.a` 같은 도메인의 그룹은 같은 레인에 있다
  단언: 무작위 큐 행 200개 → `planTick` 결과에서 도메인별 레인이 정확히 1개
  검출: 두 패스 그룹핑을 한 패스로 바꾸며 도메인 키 정규화(대소문자·IDN)가 빠져 한 도메인이 두 레인으로 병렬 가는 것 — 원격 MTA에 무례
- `TC-P3.T8.b` `runLanes`는 레인 안에서는 순차, 레인 간에는 `concurrency`까지 병렬이다
  단언: 지연 주입으로 최대 동시 실행 수 = `min(concurrency, lanes)`, 레인 안 순서 보존
  검출: `cursor` 공유 클로저가 하던 보장이 일반화되며 깨지는 것
- `TC-P3.T8.c` 한 레인의 예외가 다른 레인을 멈추지 않는다
  단언: 항목 하나 throw → 나머지 전부 실행
  검출: per-item try/catch 누락

【통과】
- [ ] `G-P3.22` `test packages/mta/test/{tick-plan,worker-concurrency}.test.ts` + `packages/core/test/lanes.test.ts`
- [ ] `G-P3.23` `lines packages/mta/src/worker.ts` ≤ 1000
- [ ] `G-P3.24` `grep "function errMsg" in packages/mta/src/**` = 0

## 🚪 GATE P3

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P3.1~4 | DSN 코덱 | `test` · `grep` × 2 · `surface` | 0 / = 0 / = 0 / 허용 목록 |
| G-P3.5 | D-01 | `json decisions D-01.choice` | ∈ {1, 2} |
| G-P3.6~7 | ENVID/RET/SMTPUTF8 | ①`test` ②`grep` · `grep "isAscii("` | 0 / = 0 |
| G-P3.8 | 이동 표면 | `surface packages/proto-smtp` | 허용 목록 |
| G-P3.9 | **엔진 −160** | `lines packages/proto-smtp/src/engine.ts` | ≤ 1078 (T3 시점) |
| G-P3.10~11 | 파라미터 표 | `test` · `grep` | 0 / ≤ 1 |
| G-P3.12~15 | BodySink | `test` · `grep` × 3 | 0 / = 0 / = 1 / = 0 |
| G-P3.16 | auth-machine | `test` 4파일 | 0 |
| G-P3.17 | **엔진 크기** | `lines packages/proto-smtp/src/engine.ts` | ≤ 1000 |
| G-P3.18 | 서브머신 분리 | `grep "authContinuation" in engine.ts` | = 0 |
| G-P3.19~21 | outcome | `test` · `grep` × 2 | 0 / = 0 / = 0 |
| G-P3.22 | tick-plan·lanes | `test` | 0 |
| G-P3.23 | **워커 크기** | `lines packages/mta/src/worker.ts` | ≤ 1000 |
| G-P3.24 | errMsg 통합 | `grep` | = 0 |
| G-P3.25 | 래칫 갱신 | `json RATCHET["packages/proto-smtp/src/engine.ts"]`, `["packages/mta/src/worker.ts"]` | absent × 2 |
| G-P3.26 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P3.27 | 릴리즈 기록 | `json releases P3` + 태그 존재 | 문자열 |
| G-P3.28 | (D-01 ①) 마이그레이션 020 등록 | `grep "m020" in packages/db/src/index.ts` | = 1 |

`node scripts/gate.ts P3 --seal`

가장 중요한 검사는 **G-P3.14**(`552 5.3.4`가 소스에 정확히 한 번)다. "한도를 넘겨 쌓지 않는다"는
불변식의 판정 코드가 한 곳이라는 뜻이고, DATA·BDAT·다음 프레이밍(BINARYMIME)이 전부 그 한 곳을
지난다는 구조적 보장이다. `G-P3.20`(`DSN_ACTION.failed`가 워커에 0건)은 같은 논리로 R-02의 재발을 막는다.

---

# P2 — IMAP 🔒 잠김 (P1 필요)

**브랜치** 워크트리 `p2-imap`. 계획서 §5. T1→T2→T3→T4→T5 순차(전부 `engine.ts`), T6·T7은 T2 뒤 병렬.

### ▢ P2.T1 — 계약 타입 → `types.ts` [이동]
선행: P1 봉인 · 산출: `packages/proto-imap/src/types.ts`, `engine.ts`, `index.ts` · 되돌리기: 커밋 revert · 트리: `p2-imap`

【테스트】
- `TC-P2.T1.a` 표면 동일
  단언: `surface packages/proto-imap` 변화 0
  검출: 이동하면서 `ImapBackendRequest` 멤버가 빠지거나 `index.ts` re-export가 누락되는 것(apps/server 컴파일 실패로도 드러나지만 표면 검사가 먼저 잡는다)

【통과】
- [ ] `G-P2.1` `surface packages/proto-imap` 동일
- [ ] `G-P2.2` `cmd npm run typecheck`

### ▢ P2.T2 — `items`/`uids` 단일 표현 · 필수 필드 [변경]
선행: T1 · 산출: `types.ts`, `engine.ts:1270-1282, :1956-1961`, `search-criteria.ts:63, :300-301`,
`apps/server/src/imap-backend.ts:609, :652, :674-680`, `server.ts:137` · 되돌리기: 커밋 revert · 트리: `p2-imap`

【테스트】
- `TC-P2.T2.a` APPEND 1건과 MULTIAPPEND 3건이 같은 요청 형태(`items`)로 백엔드에 간다
  단언: 가짜 백엔드가 받은 요청에 `raw`·`flags`·`internalDateMs` 최상위 키 없음, `items.length` 1/3
  검출: 레거시 슬롯이 남아 REPLACE만 옛 형태를 쓰는 것(`imap-backend.ts:674-680`)
- `TC-P2.T2.b` APPENDUID 응답이 `uids`에서만 나온다
  단언: 단일 APPEND `APPENDUID <v> <uid>`, MULTIAPPEND `APPENDUID <v> a:b`; 백엔드 응답에 `uid` 키 없음
  검출: `res.uids ?? [res.uid]` 폴백 삭제 후 단일 경로가 빈 배열을 받는 것
- `TC-P2.T2.c` FETCH `EMAILID`·`THREADID`·`SAVEDATE`에 NIL 분기가 없다
  단언: `rev2.test.ts`의 OBJECTID·SAVEDATE 케이스 + `grep`(G-P2.4)
  검출: 필수화 뒤에도 `?? "NIL"` 잔재

【통과】
- [ ] `G-P2.3` `test packages/proto-imap/test/{rev2,append-copy-move}.test.ts` + `apps/server/test/imap-objectid-multiappend.test.ts`
- [ ] `G-P2.4` `grep "우리는 항상 아는데" in packages/proto-imap/src/**` = 0
- [ ] `G-P2.5` `grep "res.uids ?? \[|req.items ?? \[" in {packages/proto-imap,apps/server}/src/**` = 0
- [ ] `G-P2.6` `grep "emailId?: string" in packages/proto-imap/src/types.ts` = 0

### ▢ P2.T3 — 명령 테이블 [변경]
선행: T2 · 산출: `engine.ts`(`COMMANDS`, `cmdCompress`), `test/command-table.test.ts` · 되돌리기: 커밋 revert · 트리: `p2-imap`

【테스트】
- `TC-P2.T3.a` 표의 모든 `state: "selected"` 명령은 미선택 상태에서 BAD다 (표 순회 자동 생성)
  단언: `for (const [name, e] of Object.entries(COMMANDS))` — `authed` 상태 세션에 `A1 <name> …` → `BAD`
  검출: 게이트 누락 — 옛 스위치에서 `requireSelected`를 빠뜨리면 미선택 FETCH가 `this.selected!`에서 터지거나 통과하던 것
- `TC-P2.T3.b` 표의 모든 `uid: true` 명령은 `UID <name>`으로 통하고, 없는 것은 `BAD unknown UID command`
  단언: 표 순회
  검출: 두 스위치가 갈라져 SORT는 UID 되고 THREAD는 안 되는 것
- `TC-P2.T3.c` `CAPABILITY`가 표에서 파생한 항목을 광고한다
  단언: `SORT`·`THREAD=REFERENCES`·`QUOTA`·`REPLACE`·`MOVE` 광고 ⇔ 표에 존재
  검출: "광고는 약속"(`5f08491`) — 표에 없는 명령을 광고하거나 있는 명령을 빠뜨리는 것

【통과】
- [ ] `G-P2.7` `test packages/proto-imap/test/**` 전체
- [ ] `G-P2.8` `grep "requireAuth(|requireSelected(" in packages/proto-imap/src/engine.ts` = 0
- [ ] `G-P2.9` `grep 'case "' in packages/proto-imap/src/engine.ts` ≤ 10 (`Pending`·SASL 스위치만 남는다)

### ▢ P2.T4 — `commands/*.ts`로 이동 [이동]
선행: T3 · 산출: `packages/proto-imap/src/commands/{auth,mailbox,fetch,search,append,store}.ts`, `engine.ts`(`SessionCtx`) ·
되돌리기: 커밋 revert · 트리: `p2-imap`

【테스트】
- `TC-P2.T4.a` 표면 동일 · 엔진 순수성 유지
  단언: `surface` 변화 0; `npm run lint`의 `checkEnginePurity`가 `commands/*.ts`도 검사(규칙 글롭 확장)
  검출: 핸들러가 별 파일로 가며 `node:fs` 같은 import가 끼어들어도 린터가 `engine.ts`만 보는 것
- `TC-P2.T4.b` `SessionCtx`가 인터페이스뿐이다
  단언: `commands/*.ts`에 `ImapEngine` import 없음(G-P2.12)
  검출: 핸들러가 엔진 클래스를 통째로 받아 분리가 이름뿐인 것

【통과】
- [ ] `G-P2.10` `surface packages/proto-imap` 동일
- [ ] `G-P2.11` `cmd npm run lint` (`checkEnginePurity` 글롭에 `commands/` 포함 — P2.T4 작업)
- [ ] `G-P2.12` `grep "ImapEngine" in packages/proto-imap/src/commands/**` = 0

### ▢ P2.T5 — `scanSelected` · `parseAppendItem` · 술어 이동 [변경]
선행: T4 · 산출: `commands/search.ts`, `commands/append.ts`, `commands/fetch.ts`, `fetch-items.ts`, `sort-thread.ts` ·
되돌리기: 커밋 revert · 트리: `p2-imap`

【작업】 (커밋 전에) `fetch-batching.test.ts`에 메일함 크기 = 배치×n−1, ×n, ×n+1 케이스를 FETCH·SEARCH·SORT 셋 다 추가.

【테스트】
- `TC-P2.T5.a` FETCH·SEARCH·SORT가 배치 경계에서 마지막 메시지를 빠뜨리지 않는다
  단언: 위 9케이스
  검출: 세 벌의 `offset + k` 산술 중 하나가 통합 중 틀리는 것 — 2026-08-23 배칭 수정의 회귀
- `TC-P2.T5.b` REPLACE가 APPEND와 같은 인자 오류를 낸다
  단언: `REPLACE 1 INBOX (\Foo) {5}` → APPEND와 같은 `BAD` 문구; `REPLACE 1 INBOX {0}` → 같은 empty 오류
  검출: 두 파서가 갈라져 있던 `idx !== cmd.args.length - 1` 검사 차이
- `TC-P2.T5.c` BINARY.SIZE는 raw가 필요하고 BODY.PEEK는 `\Seen`을 안 건드린다
  단언: `fetchNeedsRaw([binarySize]) === true`, `fetchMarksSeen([peek]) === false`
  검출: 술어를 `fetch-items.ts`로 옮기며 `some()` 열거에서 한 종류가 빠지는 것

【통과】
- [ ] `G-P2.13` `test packages/proto-imap/test/{fetch-batching,sort-thread,search-substring,rev2}.test.ts`
- [ ] `G-P2.14` `grep "FETCH_BATCH_RAW : FETCH_BATCH_META" in packages/proto-imap/src/**` = 1
- [ ] `G-P2.15` `grep "parseImapDateTime(" in packages/proto-imap/src/commands/append.ts` = 1
- [ ] `G-P2.16` `lines packages/proto-imap/src/engine.ts` ≤ 1000

### ▢ P2.T6 — 어댑터: store API 사용 · 한 배치 [변경]
선행: T2 · 산출: `apps/server/src/imap-backend.ts` · 되돌리기: 커밋 revert · 트리: `p2-imap`

【테스트】
- `TC-P2.T6.a` QRESYNC VANISHED가 store 경로로 같은 답을 낸다
  단언: `qresync-floor.test.ts` 기존 케이스(floor 위/아래) 초록
  검출: `vanishedSince` 호출 인자(`uidnext - 1`)를 틀리는 것
- `TC-P2.T6.b` MULTIAPPEND `\Deleted` 항목이 한 배치다
  단언: batch 카운트 래퍼로 3건 append(1건 `\Deleted`) → batch 1회
  검출: `setDeleted` 루프 잔재
- `TC-P2.T6.c` REPLACE가 두 배치(append + remove)이고 툼스톤을 남긴다
  단언: batch 2회, 구 uid가 `expunged`에 있음, `VANISHED`로 보고
  검출: `setDeleted`+`expunge` 잔재(3배치) 또는 툼스톤 없이 지워 QRESYNC가 놓치는 것

【통과】
- [ ] `G-P2.17` `test apps/server/test/{qresync-floor,imap-objectid-multiappend,imap-copy-semantics,imap-large-mailbox}.test.ts`
- [ ] `G-P2.18` `grep "expunged_floor|message_addresses|ADDRESS_KIND" in apps/server/src/imap-backend.ts` = 0
- [ ] `G-P2.19` `grep "store.setDeleted(" in apps/server/src/imap-backend.ts` ≤ 1 (STORE \Deleted 경로만)

### ▢ P2.T7 — `append-input.ts` · `list-match` 정리 [이동]+[삭제]
선행: T2 · 산출: `apps/server/src/append-input.ts`(← `addresses.ts`), `jmap-backend.ts`, `backend.ts`, `imap-backend.ts`,
`packages/proto-imap/src/list-match.ts`, `index.ts` · 되돌리기: 커밋 revert · 트리: `p2-imap`

【테스트】
- `TC-P2.T7.a` 세 백엔드의 envelope가 같은 함수에서 나온다
  단언: SMTP 배달·IMAP APPEND·JMAP import로 같은 raw → `messages.subject_base`·`sent_at`·`has_attachment` 동일
  검출: 세 벌 중 하나가 `hasAttachment` 계산을 다르게 하던 것
- `TC-P2.T7.b` `compileListPattern`이 export되고 테스트가 그것만 쓴다
  단언: `mailbox-commands.test.ts` 6개 단언이 `compileListPattern(p)(n)`
  검출: 테스트 전용 export가 API 약속으로 남는 것

【통과】
- [ ] `G-P2.20` `grep "hasAttachment:" in apps/server/src/**` = 1
- [ ] `G-P2.21` `grep "matchesListPattern" in packages/proto-imap/**` = 0
- [ ] `G-P2.22` `surface packages/proto-imap` — `allowRemoved: [matchesListPattern]`, `allowAdded: [compileListPattern]`

## 🚪 GATE P2

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P2.1~2 | 계약 이동 | `surface` · `cmd typecheck` | 동일 / 0 |
| G-P2.3~6 | items/uids·필수 필드 | `test` · `grep` × 3 | 0 / = 0 × 3 |
| G-P2.7~9 | 명령 표 | `test` · `grep` × 2 | 0 / = 0 / ≤ 10 |
| G-P2.10~12 | commands 이동 | `surface` · `cmd lint` · `grep` | 동일 / 0 / = 0 |
| G-P2.13~15 | 통합 | `test` · `grep` × 2 | 0 / = 1 / = 1 |
| G-P2.16 | **엔진 크기** | `lines packages/proto-imap/src/engine.ts` | ≤ 1000 |
| G-P2.17~19 | 어댑터 | `test` · `grep` × 2 | 0 / = 0 / ≤ 1 |
| G-P2.20~22 | append-input·list-match | `grep` × 2 · `surface` | = 1 / = 0 / 허용 목록 |
| G-P2.23 | 래칫 갱신 | `json RATCHET["packages/proto-imap/src/engine.ts"]` | absent |
| G-P2.24 | IMAP 전체 | `test packages/proto-imap/test/** apps/server/test/imap-*.test.ts` | 0 |
| G-P2.25 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P2.26 | 릴리즈 기록 | `json releases P2` + 태그 | 문자열 |

`node scripts/gate.ts P2 --seal`

가장 중요한 검사는 **G-P2.8**(`requireAuth(`/`requireSelected(` 0건)과 그 짝 **TC-P2.T3.a**다. 게이트가
표의 데이터가 되면 "빠뜨린다"는 사건이 불가능해지고, 표 순회 테스트가 그것을 매 실행마다 증명한다.

---

# P2x — IMAP COMPRESS 전송층 🔒 잠김 (P2 필요 · **선택** · 면제 가능)

**브랜치** 워크트리 `p2x-compress`. 계획서 §5 말미, §11 D-02.

### ▢ P2x.T1 — `Transport` 객체 · 인플레이션 비율 가드 [변경] (코드 미확인)
선행: P2 봉인, decisions `D-02` · 산출: `packages/proto-imap/src/server.ts`, `transport.ts` · 되돌리기: 커밋 revert · 트리: `p2x-compress`

【테스트】
- `TC-P2x.T1.a` COMPRESS 뒤 512 MiB 넘게 전송해도 세션이 끊기지 않는다 (코드 미확인)
  단언: 인플레이션 비율 정상인 600 MiB 스트림 → 연결 유지
  검출: `MAX_INFLATED_BYTES` 누적 상한(`server.ts:97, :525-531`)이 긴 정상 세션을 destroy하는 것
- `TC-P2x.T1.b` 비율 폭탄(1 KiB → 100 MiB)은 첫 청크에서 끊긴다 (코드 미확인)
  단언: `inflated / consumed > N` → destroy
  검출: 누적 상한만 있어 512 MiB까지는 폭탄을 받아 주는 것
- `TC-P2x.T1.c` STARTTLS 뒤 COMPRESS, COMPRESS 뒤 STARTTLS 거부(RFC 4978 §3)
  단언: `imap-compress.test.ts` 기존 케이스
  검출: 스트림 교체 순서가 바뀌며 TLS 위에 deflate가 아니라 deflate 위에 TLS가 되는 것

【통과】
- [ ] `G-P2x.1` `json decisions D-02.choice` ∈ {1, 2} (2면 `--waived "D-02: 2"`)
- [ ] `G-P2x.2` `test apps/server/test/imap-compress.test.ts`
- [ ] `G-P2x.3` `grep "MAX_INFLATED_BYTES" in packages/proto-imap/src/**` = 0
- [ ] `G-P2x.4` `grep "let deflate|let inflate" in packages/proto-imap/src/server.ts` = 0

## 🚪 GATE P2x

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P2x.1 | D-02 | `json` | ∈ {1, 2} |
| G-P2x.2~4 | 전송층 | `test` · `grep` × 2 | 0 / = 0 / = 0 |

`node scripts/gate.ts P2x --seal` 또는 D-02 = 2이면 `node scripts/gate.ts P2x --seal --waived "D-02: 현행 유지"`

가장 중요한 검사는 **G-P2x.3**이다 — 누적 상한이 사라졌다는 것이 곧 "긴 세션을 끊는" 결함이 사라졌다는 뜻이다.

---

# P5 — JMAP · push · 리포트 🔒 잠김 (P1 필요)

**브랜치** 워크트리 `p5-jmap`. 계획서 §6. T1→T2, T3, T4→T5, T6. T3·T4·T6은 병렬 가능.

### ▢ P5.T1 — `jmap/` 디렉터리로 이동 [이동]
선행: P1 봉인 · 산출: `apps/server/src/jmap/{mail,email,submission,quota,vacation-response,shared}.ts`, `jmap-server.ts`,
`jmap-backend.ts`(삭제 또는 배럴) · 되돌리기: 커밋 revert · 트리: `p5-jmap`

【테스트】
- `TC-P5.T1.a` 메서드 표의 키 집합이 이동 전후 동일
  단언: `engine.ts:46-47`이 만드는 `methodMap`의 키를 정렬해 스냅샷 파일과 비교(`apps/server/test/jmap-methods.snapshot.json` — 이동 커밋 **전**에 기록)
  검출: capability 모듈을 나누며 메서드 하나가 등록에서 빠져 `unknownMethod`가 되는 것(`182ad2d`이 고친 부류)

【통과】
- [ ] `G-P5.1` `test apps/server/test/jmap-e2e.test.ts` (스냅샷 비교 포함)
- [ ] `G-P5.2` `lines apps/server/src/jmap-backend.ts` ≤ 50 또는 파일 없음
- [ ] `G-P5.3` `cmd npm run typecheck`

### ▢ P5.T2 — `identityGet → standardGet` · 헬퍼 export · `toJmapDate` [변경]
선행: T1 · 산출: `jmap/submission.ts`, `packages/proto-jmap/src/standard.ts`, `set.ts`, `index.ts`, `jmap/*.ts`, `push.ts` ·
되돌리기: 커밋 revert · 트리: `p5-jmap`

【테스트】
- `TC-P5.T2.a` 모든 JMAP 날짜가 밀리초 없는 UTCDate다
  단언: `Email.receivedAt`·`VacationResponse.fromDate`·`PushSubscription.expires`·`EmailSubmission.sendAt` 전부 `/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/`
  검출: 아홉 곳 중 다섯이 `toISOString()` 그대로라 타입마다 형식이 다른 것
- `TC-P5.T2.b` `Identity/get`이 `ids: ["nope"]`에 `notFound`를 낸다
  단언: 응답 `notFound: ["nope"]`, `list: []`
  검출: 수제 `identityGet`이 하던 notFound 계산이 `standardGet` 전환에서 빠지는 것

【통과】
- [ ] `G-P5.4` `test apps/server/test/{jmap-e2e,jmap-quota-vacation,push-subscription}.test.ts`
- [ ] `G-P5.5` `grep "toISOString()" in apps/server/src/jmap/** apps/server/src/push*/**` = 0
- [ ] `G-P5.6` `grep "function asObjectLocal|function strArrayOrNull|function project\b" in apps/server/src/**` = 0

### ▢ P5.T3 — `state-change.ts` [신설]+[변경]
선행: T1, decisions `D-07` · 산출: `packages/proto-jmap/src/state-change.ts`, `test/state-change.test.ts`, `jmap-server.ts`, `push.ts` ·
되돌리기: 신설 커밋 / 전환 커밋 · 트리: `p5-jmap`

【테스트】
- `TC-P5.T3.a` `diffStates`는 `wanted`에 없는 타입 변화를 무시하고, 변화 없으면 `null`
  단언: `{email:"1"}→{email:"2"}` with `wanted={Mailbox}` → `null`; with `{Email}` → `{Email:"2"}`
  검출: SSE의 `activeTypes` 필터와 push의 `types` 필터가 두 구현으로 갈라지는 것
- `TC-P5.T3.b` SSE와 push가 같은 변경에 같은 `changed` 객체를 낸다
  단언: 메일 하나 append → SSE 이벤트 `changed[acc]`와 push 페이로드 `changed[acc]` 깊은 동일
  검출: 두 tick의 diff가 갈라져 한 채널만 Thread 변화를 보내는 것
- `TC-P5.T3.c` (D-07) Identity 변경이 두 채널에 간다
  단언: `Identity/set` → SSE·push 모두 `changed[acc].Identity`
  검출: `STATE_TYPES`에 Identity가 없어 `state_identity`(`jmap-store.ts:54`)를 아무도 알리지 않던 것

【통과】
- [ ] `G-P5.7` `json decisions D-07.choice` = "add"
- [ ] `G-P5.8` `test packages/proto-jmap/test/state-change.test.ts` + `apps/server/test/push-subscription.test.ts`
- [ ] `G-P5.9` `grep "PUSH_STATE_TYPES" in apps/server/src/**` = 0
- [ ] `G-P5.10` `grep '"StateChange"' in apps/server/src/**` = 0 (payload 생성은 proto-jmap에서만)

### ▢ P5.T4 — `standardSet/standardGet`에 `scope` [변경]
선행: decisions `D-03` = 1 · 산출: `packages/proto-jmap/src/set.ts`, `standard.ts`, `test/set-scope-bytes.test.ts`(**전환 커밋보다 먼저**) ·
되돌리기: 커밋 revert · 트리: `p5-jmap`

【작업】 1. 테스트 커밋: 기존 6개 타입의 `set`/`get` 응답을 고정 입력으로 JSON 직렬화해 스냅샷 파일에 기록.
2. 전환 커밋: `scope: { accountId } | { user: true }`.

【테스트】
- `TC-P5.T4.a` `{accountId}` scope의 출력 바이트가 전환 전과 동일
  단언: 스냅샷 파일과 `JSON.stringify` 동일(Mailbox·Email·Identity·EmailSubmission·VacationResponse·Quota)
  검출: 매개변수 추가가 응답 키 순서·`accountId` 유무를 바꾸는 것 — 계획서 §13
- `TC-P5.T4.b` `{user:true}` scope는 `accountId` 인자를 요구하지 않고 응답에도 넣지 않는다
  단언: `args`에 `accountId` 없이 호출 → 정상, 응답 키에 `accountId` 없음
  검출: push가 다시 수제 set을 쓰게 되는 이유가 남는 것

【통과】
- [ ] `G-P5.11` `json decisions D-03.choice` = "1"
- [ ] `G-P5.12` `test packages/proto-jmap/test/**`

### ▢ P5.T5 — PushSubscription을 표준 소스로 · `push/` 분리 [삭제]+[이동]
선행: T4 · 산출: `apps/server/src/push/{methods,deliver,watcher}.ts`, `push.ts`(삭제) · 되돌리기: 커밋 revert · 트리: `p5-jmap`

【테스트】
- `TC-P5.T5.a` `PushSubscription/set create { "__proto__": {...} }`가 거부된다
  단언: `notCreated`에 `invalidArguments` 또는 무시, 프로토타입 오염 없음
  검출: 수제 set(`push.ts:221`)이 `isUnsafeKey` 없이 `created[cid]`에 쓰던 것 — `set.ts:70-74`가 막는 부류
- `TC-P5.T5.b` 검증 POST가 `{url, keys}`만으로 나간다
  단언: `postToSubscription({url, keys}, payload)` 시그니처(타입) + 가짜 row 생성 코드 0(G-P5.15)
  검출: `deviceClientId: ""` 가짜 row 잔재
- `TC-P5.T5.c` `ifInState` 불일치는 `stateMismatch`
  단언: 낡은 `ifInState`로 set → `stateMismatch` 오류
  검출: 수제 구현에 없던 표준 검사가 이제 적용되는지(행동 추가 — 테스트가 부모에서 빨강)

【통과】
- [ ] `G-P5.13` `red-green apps/server/test/push-subscription.test.ts fix:[P5.T5]`
- [ ] `G-P5.14` `grep "newVerificationCode" in apps/server/**` = 0
- [ ] `G-P5.15` `grep 'deviceClientId: ""' in apps/server/src/**` = 0
- [ ] `G-P5.16` `cmd test ! -e apps/server/src/push.ts`

### ▢ P5.T6 — `ReportKind` · TXT 파서 단일화 [변경]+[삭제]
선행: decisions `D-04` · 산출: `apps/server/src/reports.ts`, `packages/mta-sts/src/tlsrpt-report.ts`, `index.ts`,
`packages/mail-auth/src/dmarc.ts`, `dmarc-report.ts` · 되돌리기: 커밋 revert · 트리: `p5-jmap`

【테스트】
- `TC-P5.T6.a` DMARC 레코드가 둘인 도메인에는 리포트를 보내지 않는다
  단언: TXT 두 개 → 발송 0, skipped 카운트 1
  검출: `dmarcTags`가 `parseDmarcTagMap`보다 약해(중복 태그 덮어쓰기, "정확히 하나" 없음) 평가 경로가 거절하는 도메인에 리포팅이 보내던 것
- `TC-P5.T6.b` TLS-RPT rua 파싱이 `parseTlsRptTxt`와 같은 결과
  단언: `v=TLSRPTv1; rua=mailto:a@example.com,https://x` → 두 파서 동일(삭제 전 마지막 커밋에서 대조, 삭제 후 `parseTlsRptTxt`만)
  검출: `parseTlsRptRua`가 `https:` 대상을 다르게 다루던 것
- `TC-P5.T6.c` (D-04 배선) 외부 도메인 rua는 승인 레코드가 없으면 건너뛴다(RFC 7489 §7.1)
  단언: `rua=mailto:x@other.example` + `other.example._report._dmarc.<domain>` 없음 → skipped
  검출: `isRuaAuthorized(orgDomain)`을 아무도 안 넘겨 서브도메인 규칙이 죽어 있던 것
- `TC-P5.T6.d` 두 리포트 종류가 같은 `sendDay` 골격을 탄다
  단언: `claimReportSend` 호출 횟수·gzip·필드가 종류별 서술자 외에는 동일(호출 기록 단언)
  검출: 골격 둘이 다시 갈라지는 것

【통과】
- [ ] `G-P5.17` `json decisions D-04.choice` ∈ {wire, delete}
- [ ] `G-P5.18` `test apps/server/test/reports.test.ts` + `packages/mta-sts/test/tlsrpt-report.test.ts` + `packages/mail-auth/test/dmarc-report.test.ts`
- [ ] `G-P5.19` `grep "parseTlsRptRua|function dmarcTags" in {packages,apps}/**/src/**` = 0
- [ ] `G-P5.20` `grep "gzipSync(" in apps/server/src/reports.ts` = 1

## 🚪 GATE P5

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P5.1~3 | jmap/ 이동 | `test` · `lines`/부재 · `cmd typecheck` | 0 / ≤ 50 / 0 |
| G-P5.4~6 | 헬퍼·날짜 | `test` · `grep` × 2 | 0 / = 0 / = 0 |
| G-P5.7~10 | StateChange | `json D-07` · `test` · `grep` × 2 | add / 0 / = 0 / = 0 |
| G-P5.11~12 | scope | `json D-03` · `test` | 1 / 0 |
| G-P5.13~16 | push | `red-green` · `grep` × 2 · `cmd` | 부모 빨강 / = 0 / = 0 / 0 |
| G-P5.17~20 | 리포트 | `json D-04` · `test` · `grep` × 2 | ∈ / 0 / = 0 / = 1 |
| G-P5.21 | 래칫 갱신 | `json RATCHET["apps/server/src/jmap-backend.ts"]` | absent |
| G-P5.22 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P5.23 | 릴리즈 기록 | `json releases P5` + 태그 | 문자열 |

`node scripts/gate.ts P5 --seal`

가장 중요한 검사는 **TC-P5.T4.a**(scope 전환 전후 출력 바이트 동일)다. 이 계획에서 가장 넓은 표면
(6개 JMAP 타입의 set/get)을 건드리는 변경이고, 스냅샷이 전환 커밋보다 먼저 있어야 "동일"이 증명이 된다.

---

# P4 — apps/server 조립층 · backend 분리 🔒 잠김 (P1, P3 필요)

**브랜치** 워크트리 `p4-server`. 계획서 §7. T1→T2, T3→T4, T5→T6, T7. 세 줄기는 병렬 가능하나
`app.ts`를 T2·T3·T7이 건드리므로 rebase 순서는 T2 → T3 → T7.

### ▢ P4.T1 — core 헤더 위생 · mta 첨부 빌더 [신설]+[삭제]
선행: P1·P3 봉인 · 산출: `packages/core/src/header-line.ts`, `packages/mta/src/message-builder.ts`, `test/message-builder.test.ts`,
`vacation.ts`·`dsn.ts`·`backend.ts`·`worker.ts`·`inbound-auth.ts`(사본 삭제) · 되돌리기: 신설 커밋 / 사본 삭제 커밋 · 트리: `p4-server`

【테스트】
- `TC-P4.T1.a` `headerSafe`는 CR·LF·NUL을 제거하고 `max`에서 자른다
  단언: `"a\r\nb\0c"` → `"abc"`; 321자 → 320자
  검출: 세 사본 중 하나만 `\0`을 다루던 차이(계획서 §7 4-A) — 헤더 주입
- `TC-P4.T1.b` `buildAttachmentMessage`가 낸 메시지를 `@ionosphere/mime`가 다시 파싱하면 첨부가 1개다
  단언: `parseMessage(bytes).attachments.length === 1`, `Content-Type: multipart/mixed`, 본문 base64 76자 접기
  검출: 수제 MIME 세 벌 중 하나가 경계 문자열을 헤더에도 쓰던 것; R-04의 재발
- `TC-P4.T1.c` `prependHeaderLine`은 CRLF를 정확히 한 번 붙이고 기존 바이트를 안 건드린다
  단언: 결과 = `line + "\r\n" + raw` 바이트 동일
  검출: 사본 하나가 `\n`만 붙이던 것

【통과】
- [ ] `G-P4.1` `test packages/mta/test/message-builder.test.ts` + `packages/core/test/header-line.test.ts`
- [ ] `G-P4.2` `grep "function headerSafe" in {packages,apps}/**/src/**` = 1
- [ ] `G-P4.3` `grep "function prependHeader" in {packages,apps}/**/src/**` = 1
- [ ] `G-P4.4` `grep "320|400" in apps/server/src/vacation.ts packages/mta/src/dsn.ts` = 0 (이름 붙인 상수만)

### ▢ P4.T2 — `system-send.ts` [신설]+[변경]
선행: T1 · 산출: `apps/server/src/system-send.ts`, `backend.ts:1368-1377, :1693-1704`, `app.ts:1284-1293, :1388-1432`, `reports.ts` ·
되돌리기: 커밋 revert · 트리: `p4-server`

【테스트】
- `TC-P4.T2.a` 네 시스템 발송 전부 null-sender · `relayPerHour` 상한 · 같은 `tenantId`
  단언: vacation·SRS 바운스·DSN·리포트 각각 한 번씩 → `mta_queue` 4행 모두 `env_from = ""`, `system_relay_per_hour = <상한>`
  검출: 한 호출부가 `system` 옵션을 빠뜨려 시스템 메시지가 일반 레이트리밋을 타거나 바운스를 되받는 것
- `TC-P4.T2.b` `relayPerHour` 기본값이 한 곳
  단언: `DEFAULT_RELAY_PER_HOUR` 참조가 `app.ts` 1곳(G-P4.6)
  검출: 세 곳 재유도 잔재

【통과】
- [ ] `G-P4.5` `grep 'envFrom: "null-sender"' in apps/server/src/**` = 1
- [ ] `G-P4.6` `grep "DEFAULT_RELAY_PER_HOUR" in apps/server/src/**` ≤ 2 (import + 1 사용)
- [ ] `G-P4.7` `test apps/server/test/{vacation,reports,sieve-reject-e2e}.test.ts` + `packages/mta/test/dsn-worker.test.ts`
- [ ] `G-P4.8` `grep "boundary" in apps/server/src/app.ts` = 0

### ▢ P4.T3 — `StartContext` 단일 조립 · 리포팅/제출 옵션 타입 [변경]
선행: T2 · 산출: `app.ts`, `backend.ts`(`dmarcReport` 콜백), `inbound-auth.ts`(`Omit<DmarcRowKey,"sourceIp">`),
`worker.ts`(`tlsReport(row)`), `packages/mta-sts/src/tlsrpt-report.ts`(`TLSRPT_RESULT`), R-07 결과에 따라 `outboundPolicy` ·
되돌리기: 커밋 revert · 트리: `p4-server`

【테스트】
- `TC-P4.T3.a` `reports` 옵션 하나로 DMARC 행·TLS-RPT 행·러너가 모두 켜지고, 없으면 셋 다 꺼진다
  단언: `opts.reports` 있음 → 수신 1건 후 `dmarc_rows` 1행, 발송 1건 후 `tlsrpt_rows` 1행, reaper에 러너 등록; 없음 → 셋 다 0
  검출: 세 모양(boolean·콜백·객체) 중 하나가 켜지지 않는 것 — `if (this.opts.reports)` 세 갈래
- `TC-P4.T3.b` `InboundAuthResult.dmarcReport`가 `DmarcRowKey`와 필드 이름이 같다 (타입)
  단언: `tsc` — `{ ...auth.dmarcReport, sourceIp }`가 `DmarcRowKey`에 할당 가능
  검출: 9필드 손 복사에서 이름이 하나 어긋나는 것
- `TC-P4.T3.c` TLS-RPT 결과 문자열이 상수 집합 밖으로 못 나간다 (타입)
  단언: `recordTls(…, "sts-policy-invalidd")` 컴파일 실패(테스트는 `@ts-expect-error`)
  검출: 오타 리터럴이 RFC 8460 소비자가 무시하는 행을 만드는 것
- `TC-P4.T3.d` `createGuardedFetch()` 인스턴스가 하나
  단언: 생성자 호출 카운트 1(모듈 스파이) 또는 `grep`(G-P4.11)
  검출: push 옵션 2회 조립 잔재

【통과】
- [ ] `G-P4.9` `test apps/server/test/{reports,push-subscription,jmap-e2e}.test.ts`
- [ ] `G-P4.10` `grep "reportDmarc" in apps/server/src/**` = 0
- [ ] `G-P4.11` `grep "createGuardedFetch()" in apps/server/src/app.ts` = 1
- [ ] `G-P4.12` `grep '"sts-policy-invalid"|"dane-required"|"starttls-not-supported"|"validation-failure"|"sts-policy-fetch-error"' in packages/mta/src/**` = 0

### ▢ P4.T4 — `guardConnections` · `peerLimit`/`scramDecoySecret` 필수 [신설]+[변경]
선행: T3 · 산출: `packages/core/src/listener-guard.ts`, `test/listener-guard.test.ts`, `proto-{imap,pop3,smtp,managesieve,lmtp}/src/server.ts`,
`proto-*/src/engine.ts`(`PROCESS_SCRAM_DECOY` 삭제), `app.ts` · 되돌리기: 신설 커밋 / 전환 커밋 · 트리: `p4-server`

【테스트】
- `TC-P4.T4.a` 같은 피어가 IMAP 상한을 채운 뒤 ManageSieve로 오면 거절된다
  단언: 한 `PeerConnectionLimiter`를 다섯 서버에 주입 → 상한 N을 IMAP으로 채움 → ManageSieve 4190 연결 즉시 close
  검출: ManageSieve에 피어 제한이 없던 것 + 서버마다 자체 인스턴스를 만들어 "5×N"이 되던 것
- `TC-P4.T4.b` `peerLimit` 없이 서버를 만들면 컴파일 실패
  단언: `@ts-expect-error` 테스트
  검출: optional+폴백 잔재
- `TC-P4.T4.c` SCRAM 디코이가 프로토콜 넷에서 같은 값
  단언: 존재하지 않는 사용자에 대한 SCRAM 첫 응답의 salt가 IMAP·SMTP·POP3·ManageSieve에서 동일
  검출: 엔진마다 `randomBytes(32)`라 "서버 전체 같은 값" 불변식(`engine.ts:314-316`)이 안 지켜지던 것 — 사용자 존재 여부 유출

【통과】
- [ ] `G-P4.13` `test packages/core/test/listener-guard.test.ts` + `apps/server/test/listener-hardening.test.ts`
- [ ] `G-P4.14` `grep "peerLimit ??" in packages/proto-*/src/**` = 0
- [ ] `G-P4.15` `grep "PROCESS_SCRAM_DECOY" in packages/proto-*/src/**` = 0
- [ ] `G-P4.16` `grep "tryAcquire(" in packages/proto-*/src/server.ts` = 0 (core 게이트만 호출)

### ▢ P4.T5 — `backend.ts` 분리 [이동]
선행: T2 · 산출: `apps/server/src/{smtp-backend,sieve-route,pop3-backend,lmtp-backend,dkim-hook}.ts`, `backend.ts`(삭제), `app.ts` import ·
되돌리기: 커밋 revert · 트리: `p4-server`

【테스트】
- `TC-P4.T5.a` numstat 대칭 · 테스트 무변경 초록
  단언: 이동 커밋의 삭제 줄 수 − 추가 줄 수 절댓값 ≤ 30(import·export 5파일); `apps/server/test/**` 초록
  검출: 이동 중 `deliverToAccount`의 순서를 "정리"하는 것

【통과】
- [ ] `G-P4.17` `cmd test ! -e apps/server/src/backend.ts`
- [ ] `G-P4.18` `lines apps/server/src/smtp-backend.ts` ≤ 1000
- [ ] `G-P4.19` `test apps/server/test/**`

### ▢ P4.T6 — `SieveDisposition` · `requiredExtensions` · `EmailBodyPart` [변경]
선행: T5 · 산출: `sieve-route.ts`, `smtp-backend.ts`, `packages/sieve/src/index.ts`(`requiredExtensions`) · 되돌리기: 커밋 revert · 트리: `p4-server`

【테스트】
- `TC-P4.T6.a` `reject`는 vacation·redirect·fileinto를 전부 무시한다
  단언: 스크립트 `reject "no"; redirect "x@example.com"; vacation "y";` → 550 거절, 큐 0행, vacation 0
  검출: 7필드 객체 시절 `reject !== null` 검사가 if 체인 첫 자리에 있어야만 지켜지던 우선순위가 유니온 `switch`로 옮겨지며 뒤바뀌는 것
- `TC-P4.T6.b` `discard`도 vacation을 보낸다(RFC 5230 §4.7 — vacation은 discard와 무관)
  단언: `vacation "y"; discard;` → 배달 0, vacation 1
  검출: `{kind:"discard"; vacation}`에 vacation을 안 실은 것 — 옛 `:712` 리터럴은 실었다
- `TC-P4.T6.c` `require ["include"]` 없는 스크립트에 문자열 `"include"`가 있어도 하위 스크립트를 로드하지 않는다
  단언: `if header :contains "subject" "include" { keep; }` → `getSieveScriptSources` 호출 0
  검출: `script.includes("include")` 스니핑 잔재
- `TC-P4.T6.d` `require ["body"]`가 있어야 `:content` 파트를 만든다
  단언: 호출 기록
  검출: `includes(":content")` 스니핑 잔재 — 확장 선언이 아니라 문자열로 판정

【통과】
- [ ] `G-P4.20` `test apps/server/test/{sieve-reject-e2e,sieve-mailbox-create,vacation}.test.ts`
- [ ] `G-P4.21` `grep "script.includes(" in apps/server/src/**` = 0
- [ ] `G-P4.22` `grep "as never" in apps/server/src/**` = 0
- [ ] `G-P4.23` `grep "fileintoUsed: false" in apps/server/src/**` ≤ 1 (수동 조립 4곳 → 생성자 1곳)

### ▢ P4.T7 — `fetchTextCapped` [변경]+[삭제]
선행: T3 · 산출: `packages/webhook/src/http-client.ts`, `app.ts:1994-2013` · 되돌리기: 커밋 revert · 트리: `p4-server`

【테스트】
- `TC-P4.T7.a` 3xx는 따라가지 않고 오류, 본문은 `maxBytes`에서 끊고 오류
  단언: 302 → reject; 본문 `maxBytes+1` → reject
  검출: `app.ts`의 수제 클라이언트가 하던 두 방어가 공용 함수로 옮겨지며 빠지는 것 — MTA-STS 정책 페치 SSRF/폭탄
- `TC-P4.T7.b` `lookup` 훅이 사설 대역을 거부한다
  단언: `10.0.0.1`로 해석되는 호스트 → reject(`createGuardedLookup`)
  검출: 새 GET 경로가 guarded lookup을 안 쓰는 것

【통과】
- [ ] `G-P4.24` `test packages/webhook/test/**` + `apps/server/test/**mta-sts**`
- [ ] `G-P4.25` `grep "httpsRequest" in apps/server/src/app.ts` = 0
- [ ] `G-P4.26` `lines apps/server/src/app.ts` ≤ 1922 (2072 − 150)

## 🚪 GATE P4

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P4.1~4 | 헤더 위생·빌더 | `test` · `grep` × 3 | 0 / = 1 / = 1 / = 0 |
| G-P4.5~8 | 시스템 발송 | `grep` · `grep` · `test` · `grep` | = 1 / ≤ 2 / 0 / = 0 |
| G-P4.9~12 | StartContext | `test` · `grep` × 3 | 0 / = 0 / = 1 / = 0 |
| G-P4.13~16 | 리스너 게이트 | `test` · `grep` × 3 | 0 / = 0 / = 0 / = 0 |
| G-P4.17~19 | backend 분리 | `cmd` · `lines` · `test` | 0 / ≤ 1000 / 0 |
| G-P4.20~23 | Disposition | `test` · `grep` × 3 | 0 / = 0 / = 0 / ≤ 1 |
| G-P4.24~25 | HTTP | `test` · `grep` | 0 / = 0 |
| G-P4.26 | **app.ts −150** | `lines apps/server/src/app.ts` | ≤ 1922 |
| G-P4.27 | 래칫 갱신 | `json RATCHET["apps/server/src/backend.ts"]` absent · `RATCHET["apps/server/src/app.ts"]` | absent / ≤ 1922 |
| G-P4.28 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P4.29 | 릴리즈 기록 | `json releases P4` + 태그 | 문자열 |

`node scripts/gate.ts P4 --seal`

가장 중요한 검사는 **TC-P4.T4.a**(피어 상한이 다섯 리스너에 걸쳐 하나)다. 이 단계의 주제가
"옵션을 갈래마다 다시 만들지 않는다"이고, 그 규칙을 가장 직접 위반하던 것이 리스너마다 자체
`PeerConnectionLimiter`를 만들던 것이다 — 이 테스트는 그 정책이 서버 전체에서 하나임을 실제 소켓으로 증명한다.

---

# P6 — Sieve · core · mime 🔒 잠김 (P0 필요)

**브랜치** 워크트리 `p6-sieve-core`. 계획서 §8. T1→T2→T3 순차, T4→T5 순차, T6·T7 독립. T6은 P1.T10과 순차.

### ▢ P6.T1 — 파서가 태그에 값을 묶는다 [변경]
선행: P0 봉인 · 산출: `packages/sieve/src/ast.ts`, `parser.ts`(`TAG_ARITY`), `interpret.ts`(리더 교체), `test/parser.test.ts` ·
되돌리기: 커밋 revert · 트리: `p6-sieve-core`

【테스트】
- `TC-P6.T1.a` 값이 필요한 태그가 값 없이 오면 파스 오류다
  단언: `vacation :days;` → `SieveParseError`(현재는 런타임까지 간다)
  검출: 태그 arity를 파서가 모르는 것 — `vacation :mime "body"`가 `:mime`을 값 태그로 오해하던 부류(계획서 §8 6-A)
- `TC-P6.T1.b` `:comparator "i;ascii-numeric" :value "gt"`처럼 값 태그가 연속해도 positional이 정확하다
  단언: `header :comparator "i;ascii-numeric" :value "gt" "x-score" "5"` → positional `["x-score"], ["5"]`
  검출: `positionalStringGroups`의 skip 로직이 하던 일을 파서가 하며 두 번째 값 태그를 positional로 세는 것
- `TC-P6.T1.c` `setflag "var" "\\Seen"`(variables 활성)은 변수 `var`에 넣는다(RFC 5232 §3)
  단언: 변수 값 `\Seen`, 메시지 플래그 무변경
  검출: `flagArgs`의 "변수 미지원(v1)" 잔재

【통과】
- [ ] `G-P6.1` `test packages/sieve/test/**`
- [ ] `G-P6.2` `grep "_VALUE_TAGS" in packages/sieve/src/**` = 0
- [ ] `G-P6.3` `grep "function stringArgs|function firstStrings|function positionalStringGroups" in packages/sieve/src/**` = 0
- [ ] `G-P6.4` `grep "as Relation" in packages/sieve/src/**` = 0

### ▢ P6.T2 — `match.ts` · `tests/` · `actions.ts` · `address.ts`로 이동 [이동]
선행: T1 · 산출: `packages/sieve/src/{match,actions,address}.ts`, `tests/{structural,values}.ts`, `interpret.ts` · 되돌리기: 커밋 revert · 트리: `p6-sieve-core`

【테스트】
- `TC-P6.T2.a` 표면 동일 · 테스트 무변경 초록
  단언: `surface packages/sieve` 변화 0(테스트 전용 re-export는 T6에서 삭제)
  검출: 이동 중 `SieveEnv` 필드를 고치는 것

【통과】
- [ ] `G-P6.5` `surface packages/sieve` 동일
- [ ] `G-P6.6` `test packages/sieve/test/**`

### ▢ P6.T3 — `ValueTest` 모델 · `parseAddressList` [변경]
선행: T2 · 산출: `tests/values.ts`, `match.ts`(`evalMatchTest`), `packages/sieve/package.json`(`@ionosphere/mime`), `address.ts` ·
되돌리기: 커밋 revert · 트리: `p6-sieve-core`

【테스트】
- `TC-P6.T3.a` 8개 매치 테스트가 하나의 `evalMatchTest`를 지난다
  단언: `evalMatchTest` 스파이 호출 8회(각 테스트 종류 1회)
  검출: 프롤로그 7벌 중 하나가 살아남아 `:regex`나 `:count`가 그 테스트에서만 다르게 동작하는 것
- `TC-P6.T3.b` `address :is "to" "a@ionosphere.test"`가 `"x, y" <a@ionosphere.test>`에 매치한다
  단언: 따옴표 안 쉼표·그룹 문법(`g: a@ionosphere.test;`)·주석 `(c)` 세 형태
  검출: `header.split(",")` + `/<([^>]*)>/` 수제 파서가 vacation의 mime 파서와 다른 답을 내던 것 — 사용자 규칙과 자동응답 게이트가 "누구에게 온 메일인가"에서 갈라진다
- `TC-P6.T3.c` 순환 의존 없음
  단언: `npm run lint`(`checkCycles`)
  검출: sieve → mime → (미래에) sieve

【통과】
- [ ] `G-P6.7` `test packages/sieve/test/**` + `apps/server/test/sieve-*.test.ts`
- [ ] `G-P6.8` `grep "function extractAddresses" in packages/sieve/src/**` = 0
- [ ] `G-P6.9` `lines packages/sieve/src/interpret.ts` ≤ 300
- [ ] `G-P6.10` `cmd npm run lint`

### ▢ P6.T4 — glob 동치 속성 테스트 [신설] (**T5보다 먼저 초록**)
선행: 없음 · 산출: `packages/core/test/glob-equivalence.test.ts`, `packages/core/test/fixtures/glob-golden.json` ·
되돌리기: 커밋 revert · 트리: `p6-sieve-core`

【작업】 1. 무작위 패턴(길이 ≤ 12, 알파벳 `a b / . * ? %`) × 입력 **10,000쌍**을 고정 시드로 생성.
2. 구 `compileGlob`/`globCaptures`의 (매치, 캡처) 결과를 **골든 파일**에 기록(`glob-golden.json`).
3. 테스트는 골든과 현재 구현을 비교. 강등 모드(`captures: []`)였던 쌍은 골든에 `degraded: true`로 표시.

【테스트】
- `TC-P6.T4.a` 현재 구현이 골든 10,000쌍과 일치한다
  단언: 매치 여부 100% 동일; 캡처는 `degraded` 아닌 쌍에서 100% 동일
  검출: T5의 재구현이 `%`(계층 구분자 제외)나 leftmost-greedy 캡처 의미를 바꾸는 것 — 계획서 §13 최상위 위험
- `TC-P6.T4.b` 골든 파일에 강등 쌍이 1개 이상 있다
  단언: `degraded === true` 카운트 ≥ 1
  검출: 생성기가 강등 모드를 한 번도 안 건드려 T5가 그 경로 삭제를 검증 없이 하는 것

【통과】
- [ ] `G-P6.11` `test packages/core/test/glob-equivalence.test.ts`
- [ ] `G-P6.12` `json packages/core/test/fixtures/glob-golden.json .length` = 10000

### ▢ P6.T5 — glob→regex 컴파일 · regex 정리 [변경]+[삭제]
선행: T4 · 산출: `packages/core/src/glob.ts`, `regex.ts`, `index.ts`, `packages/sieve/src/match.ts`(`:matches` 한 경로), `list-match.ts` ·
되돌리기: 커밋 revert · 트리: `p6-sieve-core`

【테스트】
- `TC-P6.T5.a` 골든 10,000쌍 일치, 강등 쌍은 이제 캡처가 있다
  단언: `degraded` 쌍에서 캡처 길이 > 0(신 구현은 강등 모드가 없다)
  검출: 재구현이 큰 입력에서 예외를 던지거나 캡처를 비우는 것
- `TC-P6.T5.b` `x{2,}`와 `x*`의 컴파일 결과가 같은 프로그램 모양이다
  단언: `compileRegex("a{2,}").prog`가 `aa` + `a*` 프로그램과 동일
  검출: 동일 분기 삭제 중 `min > 0` 경로가 사라져 `{n,}`이 깨지는 것
- `TC-P6.T5.c` Sieve `:matches`가 `vars` 유무와 무관하게 같은 엔진을 탄다
  단언: `header :matches "subject" "*x*"`의 결과와 `${1}` 캡처가 variables on/off에서 동일(off면 캡처만 무시)
  검출: `interpret.ts:728-738` vs `:764-768` 두 경로 잔재
- `TC-P6.T5.d` IMAP LIST `%`가 계층 구분자를 넘지 않는다
  단언: `mailbox-commands.test.ts` 기존 케이스
  검출: `%` → `repeat(class negate [구분자])` 변환 오류

【통과】
- [ ] `G-P6.13` `test packages/core/test/{glob,glob-captures,glob-equivalence,regex}.test.ts` + `packages/proto-imap/test/mailbox-commands.test.ts`
- [ ] `G-P6.14` `lines packages/core/src/glob.ts` ≤ 150
- [ ] `G-P6.15` `grep "MAX_CAPTURE_CELLS|function matchTokens|globMatch\b|regexMatch\b" in packages/core/src/**` = 0
- [ ] `G-P6.16` `grep "as { a: number }|as { b: number }|as { to: number }" in packages/core/src/regex.ts` = 0
- [ ] `G-P6.17` `surface packages/core` — `allowRemoved: [globMatch, regexMatch, GlobCaptureResult]`, `allowAdded: [compileAst, Node]`

### ▢ P6.T6 — 잔여 정리 [이동]+[삭제]
선행: P1.T10 봉인 또는 순차 합의(같은 `limits.ts`) · 산출: `packages/sieve/src/vacation.ts`(← `apps/server/src/vacation.ts` 술어),
`core/webpush.ts`, `proto-smtp/src/engine.ts:46`, `core/limits.ts`, `mime/src/*`(헤더 한도 이동), `sieve/src/index.ts` ·
되돌리기: 커밋 revert · 트리: `p6-sieve-core`

【테스트】
- `TC-P6.T6.a` `hkdfSync` 기반 키가 이전 수제 HKDF와 같은 바이트다
  단언: 고정 ikm·salt·info·length 32 → 이전 구현의 골든 32바이트와 동일
  검출: T(1)만 계산하던 수제 구현과 표준 HKDF가 `length ≤ 32`에서 같다는 가정이 틀리는 것 — Web Push 복호 실패
- `TC-P6.T6.b` `decideVacation`이 sieve 패키지에서 같은 결정을 낸다
  단언: `vacation.test.ts`의 스킵 사유 8종(List-*, Auto-Submitted, Precedence, null-sender, 자기 자신, 수신자 아님, 기간 내 재발송, 발신 도메인)
  검출: 이동 중 헤더 이름 대소문자 정규화가 빠지는 것

【통과】
- [ ] `G-P6.18` `test packages/core/test/webpush.test.ts` + `apps/server/test/vacation.test.ts`
- [ ] `G-P6.19` `grep "MAX_DATA_LINE" in packages/proto-smtp/src/**` = 0
- [ ] `G-P6.20` `grep "function hkdf\b" in packages/core/src/webpush.ts` = 0
- [ ] `G-P6.21` `grep "MAX_HEADER_SECTION_BYTES|MAX_HEADER_LINE_BYTES|MAX_ADDRESSES_PER_HEADER" in packages/core/src/limits.ts` = 0

### ▢ P6.T7 — mime RFC 2231 · 헤더 상한 공용 · bailiwick [변경] (코드 미확인)
선행: 없음 · 산출: `packages/mime/src/encoding.ts`(`decodeRfc2231`), `headers.ts`, `parse.ts`(상한을 `splitHeaderBody`로),
`packages/dns/src/resolver.ts`(`isInBailiwick`) · 되돌리기: 커밋 revert · 트리: `p6-sieve-core`

【테스트】
- `TC-P6.T7.a` IMAP `parseStructure` 경로도 헤더 섹션 상한을 지킨다 (코드 미확인)
  단언: 상한 초과 헤더 메시지 → `parseMessage`는 `emptyParsedMessage()`, `parseStructure`도 같은 바이트에서 빈 구조
  검출: `mime/index.ts:3`의 "두 파서가 같은 바이트를 다르게 읽지 않는다" 불변식이 초과 헤더에서 깨지는 것
- `TC-P6.T7.b` `filename*0*=UTF-8''%E1%84%80; filename*1*=%E1%85%A1` 연속 조각이 하나로 디코드된다 (코드 미확인)
  단언: 한글 파일명 복원
  검출: `decodeRfc2231` 추출 중 조각 순서·charset 상속이 깨지는 것
- `TC-P6.T7.c` `isInBailiwick`: 루트 소유자 통과 · 정확 일치 · 조상 통과 · 형제 존 거부
  단언: `("a.b.example", "")`=true, `("a.b.example","b.example")`=true, `("a.b.example","c.example")`=false, `("b.example","a.b.example")`=false
  검출: 루프 안 클로저를 함수로 빼며 `endsWith(".${o}")`의 점 경계를 놓쳐 `xb.example`이 `b.example` 안으로 들어오는 것 — 위임 오염

【통과】
- [ ] `G-P6.22` `test packages/mime/test/**` + `packages/dns/test/bailiwick.test.ts`
- [ ] `G-P6.23` `grep "export function isInBailiwick" in packages/dns/src/resolver.ts` = 1
- [ ] `G-P6.24` `grep "split(\"\").map((c) => c.charCodeAt(0))" in packages/mime/src/**` = 0

## 🚪 GATE P6

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P6.1~4 | 파서 arity | `test` · `grep` × 3 | 0 / = 0 × 3 |
| G-P6.5~6 | 이동 | `surface` · `test` | 동일 / 0 |
| G-P6.7~10 | ValueTest·주소 | `test` · `grep` · `lines` · `cmd lint` | 0 / = 0 / **≤ 300** / 0 |
| G-P6.11~12 | 동치 골든 | `test` · `json .length` | 0 / **= 10000** |
| G-P6.13~17 | glob→regex | `test` · `lines` · `grep` × 2 · `surface` | 0 / **≤ 150** / = 0 / = 0 / 허용 목록 |
| G-P6.18~21 | 잔여 | `test` · `grep` × 3 | 0 / = 0 × 3 |
| G-P6.22~24 | mime·dns | `test` · `grep` × 2 | 0 / = 1 / = 0 |
| G-P6.25 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P6.26 | 릴리즈 기록 | `json releases P6` + 태그 | 문자열 |

`node scripts/gate.ts P6 --seal`

가장 중요한 검사는 **G-P6.11~13**(골든 10,000쌍)이다. glob→regex는 이 계획에서 유일하게 "삭제하는
코드의 의미를 새 코드가 완전히 재현한다"는 주장을 하는 작업이고, 골든이 삭제 **전**에 기록돼
있어야 그 주장이 검증이 된다.

---

# P7 — 훅 · CI · testkit 🔒 잠김 (P0 필요)

**브랜치** 워크트리 `p7-tooling`. 계획서 §9. T1→T2→T3→T4 순차, T5·T6 독립.

### ▢ P7.T1 — `_common.py` · 다섯 훅을 정책만 남기기 [신설]+[변경]
선행: P0 봉인 · 산출: `scripts/claude-hooks/_common.py`, `{enter-worktree,main-tree-guard,session-end-cleanup,session-start-pull}.py`,
`scripts/git-hooks/pre-commit` · 되돌리기: 커밋 revert · 트리: `p7-tooling`

【테스트】
- `TC-P7.T1.a` `git()`이 한 형태이고 타임아웃이 있다
  단언: `_common.git(cwd, "rev-parse", "HEAD")` → `GitResult(rc, out, err)`; `index.lock`을 잠근 저장소에서 `git(..., "commit", ...)` → 15초 안에 `rc ≠ 0`
  검출: `pre-commit:83-85`의 타임아웃 없는 래퍼 — 락 대기가 모든 커밋을 매다는 것
- `TC-P7.T1.b` `enter-worktree`가 `CLAUDE_CODE_SESSION_ID`를 owner 기록에 쓴다
  단언: env `CLAUDE_CODE_SESSION_ID=abc` → owners JSON의 `session_id === "abc"`(현재: `agent-process-<pid>`)
  검출: `AGENT_ENV` 두 벌이 갈라져 생성기 기록과 종료 훅 필터(`session-end-cleanup.py:214`)가 영영 안 맞는 것
- `TC-P7.T1.c` `fast_forward_main`이 한 곳이고 FETCH_HEAD 경합 없이 ff한다
  단언: 두 프로세스 동시 호출 → 둘 다 성공 또는 "경합에서 짐"(실패 아님), 최종 HEAD 일치
  검출: 통합 중 `merge --ff-only origin/main`(원격 추적 ref)이 `pull`로 되돌아가는 것 — 2026-08-15 6세션 동시 실패의 재발
- `TC-P7.T1.d` 종료 훅이 R-06 테스트를 계속 통과한다
  단언: P0.T7 테스트
  검출: `protected_repo()` 공용화 중 `__file__` 기준이 다시 cwd 기준이 되는 것

【통과】
- [ ] `G-P7.1` `cmd python3 scripts/claude-hooks/run-tests.py` (T4에서 만든다 — 그 전에는 5개 스위트 개별 `cmd`)
- [ ] `G-P7.2` `grep "def fast_forward_main" in scripts/**/*.py scripts/git-hooks/pre-commit` = 1
- [ ] `G-P7.3` `grep "def git(" in scripts/claude-hooks/*.py scripts/git-hooks/pre-commit` = 1
- [ ] `G-P7.4` `grep "AGENT_ENV = (" in scripts/**` = 1
- [ ] `G-P7.5` `grep "RESCUE_TTL = " in scripts/**` = 1
- [ ] `G-P7.6` `lines scripts/claude-hooks/main-tree-guard.py` ≤ 350 · `session-end-cleanup.py` ≤ 140 · `session-start-pull.py` ≤ 120 · `enter-worktree.py` ≤ 150 · `pre-commit` ≤ 80

### ▢ P7.T2 — `GIT_VERBS` 표 · `run.sh` 런처 [변경]
선행: T1 · 산출: `main-tree-guard.py`, `scripts/claude-hooks/run.sh`, `.claude/settings.json`, `.codex/hooks.json` · 되돌리기: 커밋 revert · 트리: `p7-tooling`

【테스트】
- `TC-P7.T2.a` `git worktree list`·`git tag -l`·`git stash list`는 통과, `git worktree add`·`git tag v1`·`git stash`는 거부
  단언: 여섯 명령을 메인 트리 cwd로 가드에 넣어 allow/deny
  검출: `MUTATING`/`ALLOWED` 정규식 쌍을 표로 바꾸며 `allow_first` 집합에서 `list`가 빠지는 것 — 과거 두 번의 오탐 사고(`main-tree-guard.py:72-83`)
- `TC-P7.T2.b` 두 하네스 설정이 같은 런처를 가리킨다
  단언: `settings.json`·`hooks.json`의 `command` 여섯 개가 모두 `scripts/claude-hooks/run.sh <이름>` 형태
  검출: 런처 6벌 중 하나가 옛 인라인으로 남아 "훅이 있는데 아무것도 안 도는" 것(`test-codex-hooks.py:6-7`)
- `TC-P7.T2.c` 스크립트가 없으면 런처는 조용히 0으로 끝난다(fail-open 유지)
  단언: 없는 이름 → exit 0, stdout 빈 JSON
  검출: 런처가 fail-closed가 되어 훅 파일 없는 클론에서 모든 도구 호출이 막히는 것

【통과】
- [ ] `G-P7.7` `cmd python3 scripts/claude-hooks/test-main-tree-guard.py` + `test-codex-hooks.py`
- [ ] `G-P7.8` `grep "MUTATING = |ALLOWED = " in scripts/claude-hooks/main-tree-guard.py` = 0
- [ ] `G-P7.9` `grep "rev-parse --show-toplevel" in .claude/settings.json .codex/hooks.json` = 6 (런처 위치 찾기 한 줄씩) · `grep "python3" in` 같은 두 파일 = 0

### ▢ P7.T3 — `_testkit.py` · 테스트 중복 제거 [신설]+[삭제]
선행: T2 · 산출: `scripts/claude-hooks/_testkit.py`, 여섯 `test-*.py` · 되돌리기: 커밋 revert · 트리: `p7-tooling`

【테스트】
- `TC-P7.T3.a` `isolated_repo(hooks=[...])`가 `_common.py`를 함께 심는다
  단언: 픽스처 디렉터리에 `_common.py` 존재, 훅이 import 성공
  검출: "파일 하나만 심는다"는 옛 제약이 남아 훅이 `ImportError`로 fail-open(=아무것도 안 막음)하며 테스트는 초록인 것
- `TC-P7.T3.b` 베어 origin 픽스처가 `symbolic-ref HEAD main`을 세운다
  단언: `git ls-remote --symref origin HEAD`에 `refs/heads/main`
  검출: `test-session-start-pull.py:44-45`가 적은 "그 파일만 지키고 있던" 교훈이 다시 한 파일에만 있는 것

【통과】
- [ ] `G-P7.10` `grep "def check(" in scripts/claude-hooks/test-*.py scripts/git-hooks/test-pre-commit.py` = 0
- [ ] `G-P7.11` `grep "ast.parse" in scripts/git-hooks/test-pre-commit.py` = 0
- [ ] `G-P7.12` `cmd` 여섯 스위트 전부 0

### ▢ P7.T4 — `test:hooks`를 verify·CI에 [변경]
선행: T3 · 산출: `scripts/claude-hooks/run-tests.py`, `package.json`, `.github/workflows/ci.yml` · 되돌리기: 커밋 revert · 트리: `p7-tooling`

【테스트】
- `TC-P7.T4.a` `run-tests.py`가 한 스위트라도 실패하면 종료코드 ≠ 0
  단언: 스위트 하나를 일부러 실패시키면 ≠ 0
  검출: 러너가 결과를 모으기만 하고 종료코드를 안 내는 것 — CI가 초록인데 훅이 깨진 상태
- `TC-P7.T4.b` 라이브 `.git/claude-worktree-owners.json`을 건드리지 않는다
  단언: 러너 실행 전후 그 파일의 해시 동일
  검출: `test-main-tree-guard`·`test-session-end-cleanup`이 격리 픽스처로 안 옮겨진 것

【통과】
- [ ] `G-P7.13` `grep "test:hooks" in package.json` = 2 (정의 + verify 안)
- [ ] `G-P7.14` `grep "test:hooks" in .github/workflows/ci.yml` ≥ 1
- [ ] `G-P7.15` `cmd npm run test:hooks`

### ▢ P7.T5 — `LineClient` · 데드라인 완결 [변경]+[삭제]
선행: 없음 · 산출: `apps/server/test/helpers.ts`, 6개 테스트 파일, `packages/testkit/src/deadline.ts`, 3개 프로브 테스트 · 되돌리기: 커밋 revert · 트리: `p7-tooling`

【테스트】
- `TC-P7.T5.a` `LineClient.read(until)`가 `SOCKET_DEADLINE_MS`에 거부된다
  단언: 응답 없는 서버에 read → `SOCKET_DEADLINE_MS ± 200ms`에 reject
  검출: 6개 수제 리더가 `4000`으로 남아 CI 부하에서 그 파일들만 플레이크
- `TC-P7.T5.b` 프로브 바깥 타임아웃이 `PROBE_DEADLINE_MS`의 배수다
  단언: `PROBE_PROCESS_TIMEOUT_MS === PROBE_DEADLINE_MS * 2`
  검출: 30/60/90s 리터럴 세 벌이 데드라인 변경을 안 따라가는 것

【통과】
- [ ] `G-P7.16` `grep "read timeout" in apps/server/test/** packages/*/test/**` = 0
- [ ] `G-P7.17` `grep "setTimeout(.*[0-9]{4,}\)" in apps/server/test/** packages/*/test/**` (deadline.ts 제외) = 0
- [ ] `G-P7.18` `grep "E2E_HOOK_TIMEOUT_MS" in apps/server/test/helpers.ts` = 1 (import만) · `in packages/testkit/src/deadline.ts` = 1
- [ ] `G-P7.19` `test apps/server/test/{e2e,imap-e2e,federation,managesieve-e2e,audit-surfaces}.test.ts` + `packages/proto-imap/test/scram-throttle.test.ts`

### ▢ P7.T6 — CI 컴포짓 · `workflow_call` [변경] (코드 미확인)
선행: 없음 · 산출: `.github/actions/setup/action.yml`, `ci.yml`, `d1-contract.yml`, `release.yml` · 되돌리기: 커밋 revert · 트리: `p7-tooling`

【테스트】
- `TC-P7.T6.a` `release.yml`이 `gate` 이름 문자열 없이 재검증한다 (코드 미확인)
  단언: `grep 'select(.name == "gate")'` = 0, `uses: ./.github/workflows/ci.yml` 존재
  검출: `gate` 잡 이름을 바꾸면 릴리즈가 "이 커밋에서 gate가 돈 적이 없다"로 죽는 것
- `TC-P7.T6.b` 두 워크플로가 같은 부트스트랩을 쓴다
  단언: `actions/checkout@` 직접 참조가 `action.yml` 1곳
  검출: node 버전·`persist-credentials`가 두 곳에서 갈라지는 것

【통과】
- [ ] `G-P7.20` `grep 'select(.name == "gate")' in .github/workflows/release.yml` = 0
- [ ] `G-P7.21` `grep "actions/checkout@" in .github/**` = 1
- [ ] `G-P7.22` `cmd` GitHub Actions 워크플로 문법 검사(`node scripts/gate.ts --lint-workflows` 또는 `actionlint`가 있으면 그것 — **없으면 이 검사는 `--explain`에 "도구 없음"을 적고 통과**; 실제 판정은 다음 CI 실행)

## 🚪 GATE P7

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P7.1~6 | 공용 모듈 | `cmd` · `grep` × 4 · `lines` × 5 | 0 / = 1 × 4 / ≤ 350·140·120·150·80 |
| G-P7.7~9 | 표·런처 | `cmd` · `grep` × 2 | 0 / = 0 / = 6 & = 0 |
| G-P7.10~12 | testkit | `grep` × 2 · `cmd` | = 0 / = 0 / 0 |
| G-P7.13~15 | verify·CI | `grep` × 2 · `cmd` | = 2 / ≥ 1 / 0 |
| G-P7.16~19 | 데드라인 | `grep` × 3 · `test` | = 0 / = 0 / = 1 & = 1 / 0 |
| G-P7.20~22 | CI | `grep` × 2 · `cmd` | = 0 / = 1 / 0 |
| G-P7.23 | 전체 검증 | `cmd npm run verify` (이제 `test:hooks` 포함) | 0 |
| G-P7.24 | 릴리즈 기록 | `json releases P7` + 태그 | 문자열 |

`node scripts/gate.ts P7 --seal`

가장 중요한 검사는 **G-P7.15**(`npm run test:hooks`가 verify 안에서 돈다)다. 훅은 fail-open이라
깨져도 아무 증상이 없다 — 도는 테스트만이 "가드가 살아 있다"의 증거이고, 이 계획이 진행되는
동안 워크트리 격리가 계속 작동한다는 것도 이 검사가 보장한다.

---

# P8 — 문서 · 재발 방지 🔒 잠김 (P1~P7 필요, P2x는 봉인 또는 면제)

**브랜치** 워크트리 `p8-docs`. 계획서 §10.

### ▢ P8.T1 — CLAUDE.md · AGENTS.md 소유권 표 · D-05 반영 [변경]
선행: 전부 · 산출: `CLAUDE.md`, `AGENTS.md`, (D-01 ①) `docs/PROTOCOLS.md` · 되돌리기: 커밋 revert · 트리: `p8-docs`

【작업】 계획서 §10 8-A의 표 8행 추가. D-05 결정대로 116행 또는 149행 삭제. 래칫 규약 한 줄.
【테스트】
- `TC-P8.T1.a` CLAUDE.md와 AGENTS.md가 트레일러 외에 한 글자도 다르지 않다
  단언: 두 파일에서 `Co-Authored-By` 줄의 모델 이름만 치환한 뒤 `diff` 종료코드 0 (= G-P8.1)
  검출: 한쪽만 고쳐 갈라지는 것 — 2026-08-10에 AGENTS.md가 Phase 6 이전 내용으로 추가됐던 사고의 재발
- `TC-P8.T1.b` 새 소유자 8행이 표에 있다
  단언: §소유권 표에 `dsn-params.ts`·`message-destroy.ts`·`db/chunk.ts`·`listener-guard`/`lanes`·`state-change.ts`·`system-send.ts`·`header-line.ts`·`_common.py` 행 (= G-P8.2)
  검출: 소유자를 만들어 놓고 규약에 안 적어 다음 사람이 옆에 두 번째 사본을 만드는 것 — 이 계획이 없애려던 사고의 재생산

【통과】
- [ ] `G-P8.1` `cmd diff <(sed 's/Claude Opus 5 (1M context)/X/' CLAUDE.md) <(sed 's/Claude Opus 5 (1M context)/X/' AGENTS.md)` 종료코드 0
- [ ] `G-P8.2` `grep "dsn-params.ts|message-destroy.ts|db/chunk.ts|listener-guard|state-change.ts|system-send.ts|header-line.ts|_common.py" in CLAUDE.md` = 8
- [ ] `G-P8.3` `grep "main 푸시는 배포를 트리거하지 않는다|main 푸시가 곧 라이브 배포다" in CLAUDE.md` = 1

### ▢ P8.T2 — 임시 갈림길 회수 · 래칫 최종 [삭제]
선행: T1 · 산출: `packages/store/src/chunk.ts`(re-export 삭제), `scripts/lint.ts`(`RATCHET`), 스냅샷·골든 파일 정리 여부 결정 ·
되돌리기: 커밋 revert · 트리: `p8-docs`

【작업】 1. P1.T8의 `store/chunk.ts` re-export 삭제, 호출자 `@ionosphere/db` 직접 import. 2. P5.T1의
`jmap-methods.snapshot.json`·P5.T4의 set 바이트 스냅샷은 **회귀 테스트로 남긴다**(회수 아님 — 명시).
P6.T4의 `glob-golden.json`도 남긴다. 3. `RATCHET`에서 `app.ts` 외 전부 삭제, `app.ts` 값은 P4 봉인 시점 줄 수.

【테스트】
- `TC-P8.T2.a` `@ionosphere/store`가 `chunk`를 re-export하지 않는다
  단언: `import { chunk } from "@ionosphere/store"` → `tsc` 오류(`@ts-expect-error` 테스트)
  검출: 임시 갈림길이 영구가 되는 것 — 두 import 경로가 공존하면 다음 사람이 어느 쪽이 정본인지 모른다

【통과】
- [ ] `G-P8.4` `grep "from \"./chunk.ts\"|export \* from \"@ionosphere/db\"" in packages/store/src/index.ts packages/store/src/chunk.ts` = 0 · `cmd test ! -e packages/store/src/chunk.ts`
- [ ] `G-P8.5` `json scripts/lint.ts RATCHET` 키 수 = 1 이고 그 키 = `apps/server/src/app.ts`, 값 ≤ 1922
- [ ] `G-P8.6` `cmd npm run lint`

## 🚪 GATE P8 — 최종

| id | 검사 | 명령 | 통과 기준 |
|:--|:--|:--|:--|
| G-P8.1~3 | 규약 문서 | `cmd diff` · `grep` × 2 | 0 / = 8 / = 1 |
| G-P8.4~6 | 회수·래칫 | `grep`+`cmd` · `json` · `cmd lint` | = 0 & 없음 / 1키·≤ 1922 / 0 |
| G-P8.7 | **1k 초과 파일** | `cmd`: `src/**/*.ts` 중 `wc -l > 1000`인 파일 목록 | = `[apps/server/src/app.ts]` 정확히 |
| G-P8.8 | 잔재 0 (계획서 §14) | `grep "PUSH_STATE_TYPES|moveMessage\(|script\.includes\(|as typeof t &|peerLimit \?\?|PROCESS_SCRAM_DECOY|report-type=delivery-status|read timeout" in {packages,apps,scripts}/**` (dsn.ts의 report-type 1건 제외) | = 0 |
| G-P8.9 | 표=코드 | `cmd node scripts/gate.ts --check-doc docs/plan/REFACTOR-2026-08-26-todo.md` — 문서 GATE 표의 `G-*` id 집합과 `gate-checks.ts`의 id 집합 동일 | 0 |
| G-P8.10 | 봉인 전부 | `json docs/plan/seals/{P0,P1,P2,P3,P4,P5,P6,P7}.json .sealed` = true × 8 · `P2x.json` `.sealed` = true (waived 허용) | 전부 |
| G-P8.11 | 봉인 유효 | `cmd node scripts/gate.ts --status` 출력에 `⚠ 무효` 0 | 0 |
| G-P8.12 | 순서 | `cmd node scripts/gate.ts --assert-order` | 0 |
| G-P8.13 | **릴리즈 9회** | `json releases` 키 수 = 9 (P0~P8, P2x 제외) · 각 값 `git tag -l` 존재 | 9 |
| G-P8.14 | 마이그레이션 수 | `cmd`: `ls packages/db/src/migrations | wc -l` − 봉인 P0 시점 수 | D-01 ① → 1, ② → 0 |
| G-P8.15 | 전체 검증 | `cmd npm run verify` | 0 |
| G-P8.16 | 결함 7건 회귀 | `test` P0.T2~T8의 7개 테스트 파일 | 0 |

`node scripts/gate.ts P8 --seal`

가장 중요한 검사는 **G-P8.7**이다. 이 계획의 최종 판정 지표(아래 표의 굵은 줄)이며, 래칫(`G-P8.5`)과
짝이 되어 "지금 1k 초과 파일이 조립 루트 하나뿐이고, 그것도 다시 커질 수 없다"를 기계가 말한다.

---

## 최종 목표표

계획서 §14 「전체 완료 기준」을 지표로 옮긴 것. 굵은 줄이 **최종 판정 지표** — 이 하나가 초록이면
이 계획의 주제(파일이 이음새대로 나뉘었고 다시 커질 수 없다)가 달성된 것이고, 나머지는 그 조건이다.

| 지표 | 시작값 (5e54d6b) | 목표 | 판정 검사 |
|:--|--:|--:|:--|
| **`src/**/*.ts` 중 1,000줄 초과 파일 수** | **7** | **1 (`app.ts`)** | **G-P8.7** |
| `app.ts` 줄 수 | 2072 | ≤ 1922 | G-P4.26 |
| `store.ts` / `proto-imap/engine.ts` / `proto-smtp/engine.ts` / `worker.ts` / `smtp-backend.ts` 줄 수 | 2203 / 2322 / 1238 / 1273 / 2126 | ≤ 1000 각각 | G-P1.22 · G-P2.16 · G-P3.17 · G-P3.23 · G-P4.18 |
| `jmap-backend.ts` | 1283 | ≤ 50 또는 없음 | G-P5.2 |
| `sieve/interpret.ts` | 979 | ≤ 300 | G-P6.9 |
| `core/glob.ts` | 314 | ≤ 150 | G-P6.14 |
| `UPDATE accounts SET modseq` in store.ts | 12 | 0 | G-P1.2 |
| `MAX_PARAMS_PER_STATEMENT = ` 정의 수 | 3 | 1 | G-P1.18 |
| `dsnWanted(…"failure")` 가드 수 (worker) | 2 | 3 → 0 (outcome.ts로) | G-P0.10 → G-P3.20 |
| `552 5.3.4` 문구 수 (proto-smtp) | 2 | 1 | G-P3.14 |
| `requireAuth(`/`requireSelected(` (imap engine) | 37 | 0 | G-P2.8 |
| `headerSafe` 정의 수 | 3 | 1 | G-P4.2 |
| `envFrom: "null-sender"` 조립 수 | 4 | 1 | G-P4.5 |
| `PUSH_STATE_TYPES` | 1 | 0 | G-P5.9 |
| `def fast_forward_main` / `def git(` / `AGENT_ENV` | 2 / 4 / 2 | 1 / 1 / 1 | G-P7.2~4 |
| `read timeout` 수제 리더 | 6 | 0 | G-P7.16 |
| 훅 테스트가 verify에 | 아니오 | 예 | G-P7.13 |
| glob 동치 골든 쌍 | 0 | 10,000 | G-P6.12 |
| 결함 7건 회귀 테스트 | 0 | 7 (부모 빨강 증명) | G-P0.7~19 |
| 릴리즈 | 0 | 9 | G-P8.13 |
| 스키마 변경 | 0 | D-01 ① 1 / ② 0 | G-P8.14 |

---

## 막혔을 때

**게이트가 빨간데 원인을 모른다** — `node scripts/gate.ts <단계> --explain`. 측정값과 상한이 나온다.
`grep` 검사면 `--explain`이 일치한 줄을 찍는다. `red-green`이 "부모도 초록"이면 그 테스트는 결함을
재현하지 못한 것이다 — 수정 커밋이 아니라 **테스트**를 고친다.

**봉인 후 회귀** — 되돌리면(`git revert`) R2가 그 단계와 후속을 ⚠ 무효로 만든다. 다시 고친 뒤
`--seal`을 **다시** 돌린다(R3 — 옛 봉인은 재사용되지 않는다). 후속 단계도 순서대로 재봉인.

**이동인지 변경인지 모른다** — `surface`가 답한다. 표면이 같고 numstat이 대칭이면 이동, 아니면
변경이고 `red-green` 또는 테스트 초록이 필요하다. "이동하면서 조금 고쳤다"는 커밋을 둘로 쪼갠다.

**위험한 단계 중간에 이탈해야 한다** — P1·P3·P6(T5)는 중간 커밋이 main에 있어도 안전하다
(각 커밋이 `verify` 초록 조건으로 push된다). 단 **P3.T2 ①(마이그레이션)은 커밋이 나갔으면 롤포워드만** —
계획서 §12. 이탈 전 `--status`로 현재 봉인 상태를 남기고, 워크트리는 `session-end-cleanup`이 회수한다.

**일정이 부족하다** — 자를 수 있는 것: P2x(면제 봉인), P6.T6·T7, P7.T5·T6, P4.T7. 자를 수 없는 것:
P0 전부, P1.T1~T5(결함의 구조적 원인), P3.T7(R-02의 구조적 원인), P4.T4(피어 제한 누락은 노출면).
자른 작업은 `(폐기)`가 아니라 `▢`로 남기고 P8 GATE의 해당 검사를 **표에서 지우지 말고** 다음 계획의 이월로 적는다 —
G-P8.9(표=코드)가 지우는 것을 막는다.

**결정 파일이 비어 단계가 안 열린다** — 의도된 동작이다. 결정 없이 진행하지 않는다.
D-05가 가장 먼저다(P0 봉인 전제).

---

## 코드 미확인 TC 목록

아래 TC는 계획 작성 시점에 해당 코드를 직접 열지 않고 리뷰어 보고와 계획서만으로 썼다. 착수 시
코드를 열어 단언·검출을 확정한다.

- `TC-P2x.T1.a`, `TC-P2x.T1.b` — `packages/proto-imap/src/server.ts:515-557`의 COMPRESS 구현 세부(zlib 옵션, 현재 가드 위치)
- `TC-P6.T7.a`, `TC-P6.T7.b` — `packages/mime/src/headers.ts:147-186` RFC 2231 누적 구조, `parse.ts:47-50` 상한 적용 지점
- `TC-P7.T6.a` — `.github/workflows/release.yml:55-73`의 check-runs 조회 로직과 `workflow_call` 전환 가능성
- `TC-P0.T8.a`, `TC-P0.T8.b` — R-07은 리뷰어 보고(`jmap-backend.ts:595`)이며 미실증. 작업 1이 실증 단계다.
