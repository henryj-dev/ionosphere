# ionosphere — 개발 규약

TypeScript 올인원 메일 플랫폼(SMTP/POP3/IMAP/JMAP/ManageSieve/LMTP 직접 구현).
**Node 전용**(2026-08-02 bun 지원 종료), 의존성 최소(npm 화이트리스트 pg·mysql2뿐).

세션을 이어받을 때 읽을 문서: `docs/SCHEMA.md`(동결 스키마) → `docs/PROTOCOLS.md`(기능 카탈로그)
→ `docs/OPERATIONS.md` → `PLAN.md`(원안 — **현재 상태 아님**).

⚠ **이 저장소는 공개이고 지금은 정본이다**(2026-08-23 `86b7812`). 예전에 있던 "비공개 정본 +
공개 스냅샷" 구조는 없어졌다. 그래서 `docs/STATUS.md`(라이브 실값의 정본)와 배포 스크립트는
**비공개 운영 저장소로 옮겨졌고 여기에는 없다** — 그 이름들을 참조하던 규약을 2026-08-24에
현재 구조로 고쳤다. 라이브 주소·자격증명이 필요하면 운영 저장소를 볼 것.

⚠ **이 파일은 `CLAUDE.md`의 사본이다**(트레일러 이름만 다르다). 규약을 고치면 **둘 다** 고칠 것 —
한쪽만 고쳐서 갈라진 적이 있다(2026-08-10 이 파일이 Phase 6 이전 내용으로 추가됐다).

## 검증 (완료 주장 전 필수)

```bash
npm run verify   # lint + typecheck + test + smoke
```

`scripts/lint.ts`는 아래 규약을 기계가 강제한다(의존성 0).
**tsconfig가 강제하는 영역은 잘 지켜지고 그렇지 않은 영역만 갈라졌다**는 게 코드 검수의 결론이라,
새 규약을 만들면 되도록 린터나 타입으로 강제할 것.

## 언어·문법

- **erasableSyntaxOnly** — `enum`·`namespace`·파라미터 프로퍼티 **금지**.
  정수 인코딩이 필요하면 `as const` 객체 + 유니온 타입(예: `packages/db/src/columns.ts`).
- **상대 import에 `.ts` 확장자 필수** — node가 타입 스트리핑으로 `.ts`를 직접 실행하기 때문.
- `import type` / `export type` (verbatimModuleSyntax).
- tsconfig: `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`.
  → 선택 필드는 조건부 스프레드로 넣는다: `...(x ? { k: x } : {})`.
- **주석은 한국어**. "무엇"보다 **"왜"**(특히 런타임 버그 회피·RFC 근거·과거 사고)를 적는다.
- **소스에 리터럴 제어문자 금지**(NUL·SOH). `"\0"` escape 또는 `String.fromCharCode(0)`.
  이 저장소에서 반복 발생한 사고 — diff·grep·툴 체인이 깨진다.

## 의존성

- `node:` 빌트인만. npm은 **pg·mysql2**만 허용(DB 드라이버).
- 런타임 전용 API 금지(`Bun.*` 전역) — `node:http`/`node:net`/`node:tls`로 작성. 린터가 강제한다.

## 아키텍처

- **순수 엔진 + 얇은 어댑터**: `packages/proto-*/src/engine.ts`는 I/O import **0개**인 상태머신,
  `server.ts`가 소켓 담당. 비동기 확인이 필요하면 액션을 emit하고 멈춘 뒤 `xxxResult()`로 재개.
- **스토어는 단일 원자 배치**: 한 논리 연산 = `db.batch()` 한 번. 낙관적 락은 `modseq_claims`.
- **다이얼렉트 분기 봉인**: `dialect` 식별자는 `packages/db/` 밖에 나오면 안 된다.
  유일한 탈출구는 계약으로 명시된 `insertIgnore()`.
- **패키지 순환 의존 금지**(린터가 검사). 의존 방향: `core → db → store → admin-cmd → api → apps/server`.
- **관리 기능은 3층**: `GUI(무상태) → API(HTTP 어댑터) → 명령 계층(@ionosphere/admin-cmd) → store/db`.
  CLI도 같은 명령을 부른다. **관리 기능을 추가할 때 API나 CLI에 직접 넣지 말 것** —
  `admin-cmd/registry.ts`에 명령을 하나 넣으면 REST 라우트·CLI 서브커맨드·GUI 탭이 동시에 생긴다.
  세 표면 중 한 곳에만 손으로 붙인 기능은 나머지 둘에서 빠지고, 그게 이 저장소의 반복 사고였다
  (스마트호스트는 CLI에만, 앱 비밀번호는 API에만, 계정 정지는 **어디에도** 없었다).
  명령은 I/O를 모른다 — 실패는 `CommandError`의 분류로만 표현하고 어댑터가 HTTP 상태코드나
  종료코드로 옮긴다. 화면이 필요로 하는 것(라벨·인자·파괴성·컬럼)도 명령이 서술한다.

## 소유권 (같이 바뀌는 것은 같이 둔다)

한쪽만 고쳐서 조용히 깨지던 값들은 소유 패키지로 승격했다. **새로 만들 때도 같은 규칙**:

| 값 | 소유 | 비고 |
|---|---|---|
| DB 컬럼 정수 인코딩 | `@ionosphere/db` (`columns.ts`) | `ADDRESS_KIND`, `MTA_QUEUE_STATUS`, `REF_KIND`, `BLOB_STATUS` — 스키마 소유 패키지 |
| 프로토콜 공통 한도·상한 | `@ionosphere/core` (`limits.ts`) | `MAX_MESSAGE_BYTES`, `MAX_RELAY_TARGETS`, `MAX_ALIAS_TARGETS`, `MAX_LISTENER_CONNECTIONS`, `MAX_RECEIVED_HOPS`, `POP3_IDLE_TIMEOUT_MS` — **생성 경로와 배달 경로가 같은 값을 봐야 하는 것은 전부 여기** |
| SASL 파싱 | `@ionosphere/core` (`sasl.ts`) | 4개 프로토콜 공유 정본 |
| 도메인 프로비저닝 | `@ionosphere/admin-cmd` (`domains.ts`) | GUI·REST·CLI 공용 `provisionDomain()` |
| **관리 명령 전부** | `@ionosphere/admin-cmd` (`registry.ts`) | 계정·도메인·알리아스·큐·릴레이·키 — 아래 §관리 3층 |
| 상태 인코딩 라벨 | `@ionosphere/admin-cmd` (`COMMAND_ENCODINGS`) | 값은 `@ionosphere/db`가 소유, 라벨만 여기. 세 표면이 같은 말을 하게 |

DB 값을 유니온 타입으로 두면 인코딩 변경 시 **모든 사용처가 컴파일 에러로 드러난다**.
DB → 타입 경계에서는 가드로 좁힐 것(`isAddressKind` 등).

## 설계 기준 (변경하기 쉬운 코드)

- **예측 가능성**: 같은 종류 함수는 반환 형태를 통일한다. 특히 실패 표현
  (`| null` vs throw vs `{ok}` 유니온)을 한 레이어 안에서 섞지 말 것.
  이름·시그니처로 드러나지 않는 부수효과(쓰기·네트워크) 금지 — 필요하면 이름에 드러낸다.
  타입이 `| null`인데 실제로 throw하면 호출자가 방어하지 못한다.
- **응집도**: 같이 수정되는 것은 같이 둔다. 같은 상수/변환이 두 곳에 복제되면 소유자를 정해 올린다.
- **결합도**: 옵션을 갈래마다 손으로 재작성하지 말 것(과거 JMAP만 레이트리밋을 우회한 원인).
  공통 옵션은 한 곳에서 만들어 전달한다(`inboundBackendOptions` 등).
- **가독성**: 조립 함수는 "단계 목록"으로 읽히게 하고 상세는 전용 함수로. 매직 넘버에는 이름을.
- **보안은 fail closed**: 실패 시 더 안전한 쪽으로. 예) 인증서 확보 실패가 평문 AUTH 개방으로
  이어지면 안 된다(`tlsConfigured`와 `implicitTls`를 분리하는 이유).

## 커밋

- 제목 한국어: `Phase N: ...` / `정리: ...` / `docs: ...`
- 본문에 **왜**와 **어떤 사고를 막는지**를 적는다.
- 트레일러: `Co-Authored-By: Codex Opus 5 (1M context) <noreply@anthropic.com>`

## 공개 저장소 (라이브 식별자 금지)

이 저장소는 **공개**다. 예전에는 비공개 정본에서 히스토리 없는 스냅샷을 내보냈는데(초기 커밋에
라이브 비밀번호가 평문으로 들어가 있어 세탁보다 스냅샷이 확실했다), 2026-08-23부터 이 저장소
자체가 정본이 됐다. **여기 쓰는 모든 것이 곧 공개된다** — 커밋 메시지와 Actions 로그까지.

- **공개 대상 파일에 라이브 식별자를 적지 말 것**(사설·공인 IP, IPv6, 인프라 호스트명, 서비스
  도메인, 배포 계정). 예시가 필요하면 예약 대역을 쓴다: `10.0.x.x` · `203.0.113.x` ·
  `2001:db8::` · `ionosphere.test`(우리 쪽) · `example.com`(상대 쪽) · `example.test`.
  ⚠ **우리 쪽 도메인에 `example.{com,net,org}`을 쓰지 말 것** — `admin-cmd/domains.ts`의
  `RESERVED_DOMAIN_NAMES`가 등록을 막아 도메인을 만드는 테스트가 400을 받는다. 같은 파일이
  `.test`를 픽스처용으로 일부러 허용해 두었다.
- 라이브 실값의 정본은 **비공개 운영 저장소**다. 여기에 두 벌로 적지 말 것.
- ⚠ **기계가 강제하지 않는다.** 예전엔 `npm run public:check`(`scripts/public-export.ts`의
  `LIVE_IDENTIFIERS` 목록)가 막았는데, 스냅샷 내보내기 구조가 없어지면서 그 스크립트도 함께
  사라졌다. 지금은 **사람이 지키는 규약**이다 — 커밋 전에 직접 볼 것.
- 추적하면 안 되는 파일(개인 메모·검수 보고서 등)은 `.gitignore`에 **사유와 함께** 넣는다.
  기존 항목들이 그 형식을 보여 준다.

## 릴리즈·배포

**main 푸시는 배포를 트리거하지 않는다.** 커밋은 쌓이고, 내보낼 시점은 사람이 정한다 —
Actions의 **Release & deploy**(`.github/workflows/release.yml`, `workflow_dispatch` 전용)를
한 번 실행하면 ① 그 커밋의 CI가 초록인지 확인하고 ② 태그와 릴리즈를 만든 뒤 ③ 배포 신호를 보낸다.

★왜 자동 배포가 아닌가: 이건 메일 서버다. 배포는 수신·발송이 잠깐 끊기는 일이고 마이그레이션이
끼면 되돌릴 수 없다. "머지했으니 나간다"보다 "지금 내보낸다"를 사람이 정하는 편이 맞다.

★실제 SSH 배포는 **여기 없다.** 이 저장소는 공개이고 Actions 로그도 공개인데, 배포는 내부
주소와 호스트 지문을 다루므로 로그에 한 줄이라도 찍히면 되돌릴 수 없다. 시크릿으로 옮겨도
부족하다 — GitHub는 시크릿의 **정확한 문자열**만 가리므로 `${target##*@}`로 잘라낸 IP는 그대로
나온다. 릴리즈까지만 여기서 하고, 배포는 대상·자격증명을 가진 **비공개 운영 저장소**가 그
태그를 받아 수행한다. 라이브 구성(호스트 역할·주소·백업 절차)의 정본도 그쪽이다.

마이그레이션이 포함된 릴리즈 전에는 DB 백업(`scripts/backup.sh`) — 절차는 운영 저장소 문서에 있다.

## 에이전트는 워크트리, 사람은 메인에서 작업

**에이전트**의 `Edit`/`Write`/트리 변경 git 명령은 메인 작업 트리에서 **항상 거부**된다.
단독 세션이어도 같다. **사람은 메인에서 수정·커밋·push 할 수 있다** — git `pre-commit`은
에이전트 하네스 환경 변수가 있을 때만 메인 커밋을 막는다.

작업 흐름:

    # 하네스 전용 도구가 있으면 그것을 쓰고, 없으면 모든 에이전트 공통 생성기:
    python3 scripts/claude-hooks/enter-worktree.py <이름>
    # 출력된 .claude/worktrees/<이름> 경로에서 작업·커밋
    ln -s ../../../node_modules node_modules   # 워크트리엔 의존성이 없다 (.claude/worktree-bootstrap.md)
    npm run verify
    git fetch origin && git rebase origin/main && git push origin HEAD:main

**대화(작업 사이클)가 끝났다고 선언하려면 이 push까지 끝나 있어야 한다 — 그것이 곧
「메인 브랜치로 머지」다.** 별도의 병합 절차는 없다. 워크트리에 커밋만 남기고 push를
미루면 그 사이클은 아직 메인에 반영되지 않은 것이다.
⚠ **이 저장소는 main 푸시가 곧 라이브 배포다**(3대 자동 배포). push 전에 `npm run verify`가
통과해 있어야 하고, 마이그레이션이 포함되면 §라이브 배포의 백업 절차를 먼저 밟는다.

메인은 세션 시작·종료에 자동 fast-forward된다 — 다만 이건 안전망일 뿐, **사용자는
기다리지 않고 언제든 메인 트리에서 직접 `git pull`(ff-only)을 받아도 된다.**
에이전트가 메인에서 통과하는 것: `Read`·`Grep`·`git status|log|diff|pull|fetch`,
그리고 `worktree list|remove|prune`·`stash list`·`tag -l` 같은 읽기·회수 계열.
**임의 `git worktree add`는 계속 거부된다** — 생성기를 거쳐야 소유자가 기록되고
종료·다음 시작에 자동 회수된다.
에이전트가 정말 메인에서 해야 하면 `touch .git/claude-main-tree-rescue`
(30분 TTL, **사용자 승인 후에만**). 사람은 이 파일이 필요 없다.

이 장치가 못 하는 것: 세 층 다 내부 오류 시 **통과**시키고(fail-open),
`git commit --no-verify`로 우회되며, `core.hooksPath`를 안 세운 클론에서는 git 층이 안 돈다
(머신마다 한 번 `bash scripts/git-hooks/install.sh`). **경계가 아니라 위생 장치다.**
