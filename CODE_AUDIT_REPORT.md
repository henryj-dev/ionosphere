# ionosphere 코드 전수 점검 보고서

점검일: 2026년 8월 25일 (초판) · 재검증·정정: 2026년 8월 25일

> **이 판에서 정정한 것** — 초판의 검증 결과(테스트 2건 실패)가 같은 커밋에서 재현되지 않아
> 검증 절을 다시 썼고, 그것을 근거로 삼았던 항목들의 심각도를 조정했다. CI 사실관계 오류
> 1건(방언 계약 테스트)과 도달 불가 항목 1건(고아 tenant)을 정정·철회했고, RFC 준수인 항목
> 1건(EXPN)을 철회했다. 초판이 놓쳤던 **메일 소실 결함 1건을 신규 최상위 항목으로 추가**했다.
> 철회·재분류 내역은 마지막 두 절에 남겼다.

## 점검 범위

문서 파일은 분석 대상에서 제외하고 `packages/`, `apps/`, `scripts/`의 TypeScript 코드와 테스트만 점검했습니다.
점검 대상은 약 520개 파일, 약 9.8만 줄입니다. 기준 커밋은 `47e4e4d`입니다.

검토 항목은 다음과 같습니다.

- 기능 오류와 프로토콜 상태 전이
- 데이터 무결성, 원자성, 동시성
- 인증·인가, TLS, SSRF, 입력 검증과 자원 고갈
- 미구현·더미 처리와 기능 연결 누락
- 테스트 공백과 실제 회귀

**선행 검수와의 관계** — 이 저장소에는 2026-08-23 검수(`docs/AUDIT-2026-08-23.md`)와 그 후속
작업 목록(`docs/AUDIT-2026-08-23-TODO.md`, A~H 전 항목 완료)이 이미 있습니다. 아래 항목 중
일부는 그 작업의 **잔여분**이거나 그 작업이 만든 **부작용**이므로, 해당하는 곳에 이력을
적었습니다. 우선순위 판단에는 "새로 생긴 것인가, 남은 것인가"가 중요합니다.

## 검증 결과

기준 커밋에서 `npm run verify`(lint → typecheck → test → smoke)가 **전 단계 통과**합니다.

```
ℹ tests 2383   ℹ pass 2380   ℹ fail 0   ℹ cancelled 0   ℹ skipped 3   duration_ms 29040
$ npm run verify   → exit 0
```

초판은 "2383개 중 2378 통과, 2 실패, smoke 미실행"이라고 적었으나 **같은 커밋에서 재현되지
않았습니다.** 실패로 보고했던 두 건에 대한 정정은 다음과 같습니다.

1. **STARTTLS 프로브** — `apps/server/test/access-starttls-probe.ts`는 파일명이 `.test.ts`가
   아니라 `npm test`의 글롭(`**/*.test.ts`)에 잡히지 않습니다. `access-starttls.test.ts`가
   하위 프로세스로 spawn하며, 재검증에서 통과했습니다. 프로브의 고정 대기 설계 자체는
   여전히 취약하므로 항목 15로 남깁니다.
2. **대형 `References`·`To` 헤더 100ms 상한** — 재검증에서 통과했습니다.

또한 CI는 `npm test -- --test-concurrency=2`로 **동시성을 고정**합니다
([.github/workflows/ci.yml:93](.github/workflows/ci.yml:93) — e2e가 리스너를 여럿 띄워
소켓 경쟁이 나기 때문이라고 주석에 명시). 기본 동시성(코어 수)으로 돌린 결과는 CI 조건이
아니므로, "병렬 부하에서 실패"를 결함의 실측 근거로 쓸 수 없습니다.

건너뛴 3건은 `dialect-contract.test.ts`의 환경 게이트 항목입니다(항목 16 참조).

## 심각도 기준

- **높음**: 메일 유실·오삭제, 테넌트 또는 보안 경계 침해, 서비스 거부가 직접 가능합니다.
- **중간**: 특정 구성이나 입력에서 기능 오류·데이터 불일치가 발생합니다.
- **낮음**: 기능 공백, 테스트 불안정, 운영 자동화의 제한입니다.

## 높음

### 1. 같은 메일함으로의 IMAP MOVE가 메일을 지운다 ★신규

위치:

- [packages/store/src/store.ts:1585](packages/store/src/store.ts:1585)
- [apps/server/src/imap-backend.ts:698](apps/server/src/imap-backend.ts:698)
- [packages/proto-imap/src/engine.ts:1390](packages/proto-imap/src/engine.ts:1390)

`copyOrMoveBatchAttempt()`에서 `op === "move"`이고 출발지와 목적지가 **같은 메일함**이면,
"이미 대상에 있다" 분기가 원본 멤버십을 `DELETE`하고 **다시 넣지 않습니다.** 목적지 조회
결과(`existingBy`)가 자기 자신이기 때문입니다.

`imap-backend.ts`의 어댑터에도 `proto-imap` 엔진에도 `from === to` 가드가 없어 그대로
스토어까지 내려갑니다. 클라이언트는 `OK [COPYUID …] MOVE completed`를 받습니다.

재현(스토어 직접 호출, SQLite 인메모리):

```
append 후         membership=1  messages=1  expunged=0  used_bytes=37  message_count=1
move 반환: {"pairs":[{"messageId":"01M0T5…","uid":1}]}          ← 성공 응답
same-mbx MOVE 후  membership=0  messages=1  expunged=1  used_bytes=37  message_count=1
listMessages(INBOX): 0 건
```

인증된 IMAP 사용자가 INBOX를 선택한 상태에서 `UID MOVE 1 INBOX` 한 줄이면 발동합니다.
결과는 셋입니다.

- 메일이 사라집니다. 사용자는 아무 표시도 하지 않았고 성공 응답을 받았습니다.
- `messages` 행이 어느 메일함에도 걸리지 않은 채 남아 계정 `used_bytes`·`message_count`를
  계속 점유합니다(위 재현의 37B / 1건).
- `blob_refs`가 살아 있어 블롭 GC도 회수하지 않습니다.

항목 2보다 우선합니다. 항목 2는 사용자가 이미 `\Deleted`를 단 메일만 지우지만, 이것은
아무 표시도 없는 메일을 지웁니다.

### 2. POP3 QUIT가 다른 세션의 `\Deleted` 메일까지 삭제함

위치:

- [apps/server/src/backend.ts:2043](apps/server/src/backend.ts:2043)
- [packages/store/src/store.ts:1226](packages/store/src/store.ts:1226)

POP3 세션이 삭제한 UID 목록을 `setDeleted()`에 전달한 뒤, `expunge()`는 **`uids` 없이**
호출합니다. `ExpungeInput.uids`는 생략 시 "그 메일함의 `deleted=1` 전량"을 뜻하므로
([packages/store/src/types.ts:121](packages/store/src/types.ts:121)), 삭제 범위가 세션 밖으로
넘어갑니다.

재현 시나리오:

1. IMAP에서 메시지 A에 `\Deleted` 설정 (EXPUNGE는 하지 않음)
2. POP3에서 메시지 B를 삭제하고 QUIT
3. A와 B가 모두 삭제됨

POP3 maildrop은 `!m.deleted`로 목록을 거르므로
([apps/server/src/backend.ts:1997](apps/server/src/backend.ts:1997)) **A는 그 POP3 세션에
보이지도 않는데** QUIT이 지웁니다. `\Deleted`를 휴지통 대용으로 쓰는 클라이언트(mutt 등)에서는
곧장 메일 유실입니다.

수정은 `expunge()`에 세션이 삭제한 UID를 넘기는 것으로 끝납니다 — UIDPLUS(UID EXPUNGE)
경로가 이미 그 인자를 지원합니다.

### 3. MTA-STS 정책 조회가 SSRF 방어 없이 HTTPS 요청을 수행함

위치:

- [apps/server/src/app.ts:1978](apps/server/src/app.ts:1978)
- [packages/mta-sts/src/fetch.ts:43](packages/mta-sts/src/fetch.ts:43)

`mta-sts.<recipient-domain>`을 전역 `fetch()`로 받습니다. 공격자가 소유한 도메인의 DNS를
사설 IP, loopback 또는 클라우드 메타데이터 주소로 지정하고 `_mta-sts` TXT 레코드를 추가하면,
메일 발송 워커가 내부 주소로 연결할 수 있습니다.

리다이렉트는 명시적으로 차단하고(RFC 8461 §3.3, 주석에 근거 기술) 본문 상한·타임아웃도
있지만, **DNS 해석 결과의 사설 주소 검사와 IP 고정이 없습니다.**

★처방이 이미 저장소 안에 있습니다 — 새로 만들 문제가 아닙니다.
[packages/webhook/src/http-client.ts](packages/webhook/src/http-client.ts)와
[packages/webhook/src/url-guard.ts](packages/webhook/src/url-guard.ts)가 DNS 리바인딩까지
막고, "공개 주소와 사설 주소가 섞이면 응답 전체를 거부한다"는 회귀 테스트까지 갖추고
있습니다(`packages/webhook/test/http-client.test.ts`). 같은 방어가 **한 경로에만 전파된
상태**이고, 이는 CLAUDE.md §응집도가 지목하는 형태입니다.

수정 방향: 가드된 HTTP 클라이언트를 `@ionosphere/core`로 승격하고 `app.ts`의 MTA-STS
페처가 그것을 쓰게 합니다(webhook → core 방향이라 의존 방향 규약에도 맞습니다).

## 중간

### 4. IMAP COPY가 계정 쿼터를 우회함

위치:

- [packages/store/src/store.ts:1641](packages/store/src/store.ts:1641)
- [packages/store/src/store.ts:1724](packages/store/src/store.ts:1724)
- (대조) [packages/store/src/store.ts:637](packages/store/src/store.ts:637) — append의 쿼터 검사

COPY 경로는 `mustGetAccount()`로 계정을 읽지만 `quota_bytes` 초과를 검사하지 않고
`used_bytes`와 `message_count`를 증가시킵니다.

재현(쿼터 1바이트로 조인 계정):

```
쿼터 1B에서 append: 거부됨 — quota exceeded
쿼터 1B + COPY×3 : messages=5  used_bytes=185  message_count=5   ← 3회 모두 성공
```

★이력: 2026-08-24 `4825bc8`(선행 검수 G2 결정)이 COPY를 "멤버십 추가"에서 "새 `messages`
행 생성"으로 바꾸면서 사본이 쿼터에 잡히도록 `used_bytes` 가산을 넣었는데,
`appendMessagesAttempt`의 **검사** 쪽이 따라오지 않았습니다. 즉 회계는 새 규격, 게이트는
예전 규격입니다.

JMAP 경로는 영향이 없습니다 — `copyMessage()`는 멤버십만 추가하고 `used_bytes`를 건드리지
않습니다([packages/store/src/store.ts:1921](packages/store/src/store.ts:1921)). 규격 차이에
따른 의도된 분기입니다.

블롭은 공유되므로 실제 디스크 증가는 제한적이고 인증이 필요합니다. 그래서 높음이 아니라
중간으로 둡니다 — 다만 회계값이 사실과 어긋나면 QUOTA(RFC 9208) 응답도 함께 틀립니다.

### 5. JMAP Email/set이 일부 변경만 남길 수 있음

위치:

- [apps/server/src/jmap-backend.ts:371](apps/server/src/jmap-backend.ts:371)
- [apps/server/src/jmap-backend.ts:381](apps/server/src/jmap-backend.ts:381)

`applyEmailPatch()`에서 키워드 변경, mailbox 추가, mailbox 삭제가 서로 다른 Store 호출로
순차 실행됩니다. 유효한 mailbox와 존재하지 않는 mailbox를 함께 지정하면 앞선 변경이 커밋된
뒤 뒤의 변경에서 실패할 수 있습니다.

응답은 `notUpdated`가 되지만 일부 변경은 남습니다. RFC 8620 §5.3은 한 레코드의 갱신이
전부 적용되거나 전혀 적용되지 않기를 요구하므로 계약 위반입니다.

### 6. JMAP EmailSubmission 거절 후 유령 submission이 남음

위치:

- [apps/server/src/jmap-backend.ts:567](apps/server/src/jmap-backend.ts:567)
- [apps/server/src/jmap-backend.ts:575](apps/server/src/jmap-backend.ts:575)

`createSubmission()`으로 `email_submissions` 행과 상태를 먼저 커밋한 뒤 MTA 큐에 적재합니다.
발송 정책, 레이트리밋 또는 도메인 검증으로 `enqueueMessage()`가 거절하면 submission 행은
남지만 응답은 `notCreated`가 됩니다. 실제 발송되지 않은 항목이 `EmailSubmission/get`에
나타납니다.

★이 항목은 **부분 수정의 잔여분**입니다. 같은 함수의 주석이 동일한 사고(선행 검수 5차 §9-5,
CRLF 주입 페이로드가 담긴 유령 행)를 기록하고 있고, 그 대응으로 **봉투 안전성 검사만**
행 생성 앞으로 당겨 놓았습니다. 정책·레이트리밋·도메인 검증 거절은 여전히 행 생성 뒤에
일어납니다. 행 id가 큐 입력에 필요해 순서를 뒤집을 수 없다는 제약이 그대로 남아 있으므로,
보상 삭제나 2단계 커밋(pending → confirmed) 중 하나를 골라야 합니다.

### 7. Thread 변경 state와 changes가 갱신되지 않음

위치:

- [packages/store/src/store.ts:756](packages/store/src/store.ts:756) — 유일한 `ENTITY.Thread` 기록
- [packages/store/src/store.ts:1338](packages/store/src/store.ts:1338) — expunge의 계정 UPDATE
- [packages/store/src/store.ts:1973](packages/store/src/store.ts:1973) — copyMessage의 계정 UPDATE
- [packages/store/src/jmap-store.ts:60](packages/store/src/jmap-store.ts:60)

Thread 변경 로그가 append 경로에서만 기록됩니다. expunge, mailbox membership 삭제,
IMAP COPY 등으로 Thread의 email 목록이 바뀌어도 `state_thread`와 `ENTITY.Thread` 로그가
갱신되지 않습니다(해당 경로의 계정 UPDATE는 `state_email`·`state_mailbox`만 올립니다).

따라서 `Thread/get` 결과는 바뀌지만 `Thread/changes`가 변경을 반환하지 않아 클라이언트의
스레드 캐시가 낡은 상태로 남습니다.

동기화 정확성 문제이고 메일 유실·보안 경계·서비스 거부 어디에도 해당하지 않아 중간으로
둡니다(초판은 높음이었습니다).

### 8. 대형 `References`·주소 헤더의 잔여 처리 비용 — 헤더 섹션 상한이 없음

위치:

- [packages/mime/src/ids.ts:13](packages/mime/src/ids.ts:13) — `extractMsgIdList()`
- [packages/mime/src/address.ts:9](packages/mime/src/address.ts:9) — `splitAddressEntries()`
- [packages/core/src/limits.ts:225](packages/core/src/limits.ts:225)

**정정**: 초판은 "모든 Message-ID와 주소 항목을 배열로 만들고 파싱한다"고 적었으나 절반은
틀립니다. `computeThreadRefHashes()`는 `MAX_THREAD_REFS=64`에서 `break`하고
`parseAddressList()`는 `MAX_ADDRESSES_PER_HEADER=256`에서 조기 반환합니다 — **해시와 파싱은
이미 상한 안에서 멈춥니다**(선행 검수 A2로 적용됨).

남은 비용은 그 **앞 단계**입니다. `extractMsgIdList()`의 전역 정규식 스캔과
`splitAddressEntries()`의 전체 항목 분리는 여전히 입력 전체를 훑고 배열을 만듭니다.
비용은 선형이고, 초판이 근거로 든 100ms 초과는 재검증에서 재현되지 않았습니다.

★근본 원인은 따로 있습니다 — **헤더 섹션 크기에 상한이 아예 없습니다.**
`core/limits.ts`에는 `MAX_MESSAGE_BYTES`(25MB)만 있고 헤더 블록이나 개별 헤더 줄에 대한
예산이 없습니다. MIME은 세로(`MAX_MIME_DEPTH`)·가로(`MAX_MIME_PARTS`)·리스트
(`MAX_THREAD_REFS`, `MAX_ADDRESSES_PER_HEADER`) 축을 모두 묶었는데 **헤더 섹션 자체의 축만**
비어 있습니다. 25MB짜리 `References:` 한 줄이 문법상 가능합니다.

수정 방향은 스트리밍 파서가 아니라 토크나이저 단계의 `MAX_HEADER_SECTION_BYTES` /
`MAX_HEADER_LINE_BYTES` 예산입니다. 그러면 이 항목의 잔여 비용도 함께 유계가 됩니다.

### 9. JMAP 세션 URL이 검증되지 않은 Host 헤더를 쓰고 스킴을 `http://`로 고정함

위치:

- [apps/server/src/jmap-server.ts:439](apps/server/src/jmap-server.ts:439)
- [apps/server/src/jmap-server.ts:466](apps/server/src/jmap-server.ts:466)

`externalBaseUrl`이 없으면 요청의 `Host` 헤더로 `apiUrl`, `uploadUrl`, `downloadUrl`,
`eventSourceUrl`을 구성합니다. 공격자가 임의 Host를 보내면 세션 응답의 후속 URL이 공격자
도메인을 가리킬 수 있습니다.

**추가**: Host만 문제가 아닙니다. `baseUrl()`은 스킴을 **`http://`로 하드코딩**합니다.
JMAP 리스너는 `node:http`로 뜨고 TLS는 프론트가 종단하므로, `externalBaseUrl`을 설정하지
않으면 세션이 광고하는 모든 URL이 평문 스킴이 됩니다.

★처방이 저장소 안에 있습니다. 호스트 허용목록(`HttpsFrontRoute.hosts`)이 이미 있고,
`http-redirect.ts`는 "Host가 문법에 안 맞으면 리다이렉트하지 않는다 / 내부 전용 이름은
리다이렉트조차 하지 않는다"는 규율을 세워 두었습니다. JMAP 세션도 같은 목록으로 Host를
검증해야 합니다.

현재는 `externalBaseUrl` 미설정 시 경고 로그만 남깁니다
([apps/server/src/jmap-server.ts:161](apps/server/src/jmap-server.ts:161)).
CLAUDE.md §보안은 fail closed를 요구하므로, 경고가 아니라 세션 응답 거부가 맞습니다.

### 10. Cloudflare DNS-01 자동 존 탐색이 첫 50개 존만 검사함

위치:

- [apps/server/src/cf-dns.ts:36](apps/server/src/cf-dns.ts:36)

자동 탐색 요청이 `/zones?per_page=50` 한 번으로 끝나며 페이지네이션이 없습니다. Cloudflare
계정에 50개를 초과하는 존이 있고 대상 존이 뒤쪽 페이지에 있으면 ACME DNS-01 발급과 갱신이
실패합니다.

**추가로 같은 파일에서:**

- `removeTxt`의 `dns_records` 조회에도 페이지네이션이 없습니다
  ([apps/server/src/cf-dns.ts:53](apps/server/src/cf-dns.ts:53)) — 챌린지 TXT가 많으면
  정리에 실패합니다.
- `cf()`가 `res.ok`를 확인하지 않고 곧바로 `res.json()`을 호출합니다
  ([apps/server/src/cf-dns.ts:25](apps/server/src/cf-dns.ts:25)). 5xx로 HTML이 오면 원인이
  JSON 파싱 오류로 둔갑해 진단이 어려워집니다.

애초에 목록을 순회할 필요가 없습니다 — `/zones?name=<zone>`으로 직접 조회하면 페이지네이션
문제 자체가 사라집니다.

### 11. JMAP Identity state가 항상 `"0"`으로 고정됨

위치:

- [apps/server/src/jmap-backend.ts:448](apps/server/src/jmap-backend.ts:448)
- [apps/server/src/jmap-backend.ts:480](apps/server/src/jmap-backend.ts:480) — `Identity/changes`
- [apps/server/src/jmap-backend.ts:1240](apps/server/src/jmap-backend.ts:1240)

Identity를 생성·수정·삭제해도 `Identity/get`의 state가 바뀌지 않고, `Identity/changes`도
항상 빈 변경과 `newState: "0"`을 돌려줍니다(코드 주석이 "신원 변경 추적 미구현"이라고
명시합니다). 다른 클라이언트는 변경을 영영 알 수 없고 `ifInState` 검사가 무력해집니다.

### 12. MySQL `INSERT IGNORE`가 데이터 오류까지 숨길 수 있음

위치:

- [packages/db/src/mysql.ts:173](packages/db/src/mysql.ts:173)

MySQL의 `INSERT IGNORE`는 중복키뿐 아니라 `NOT NULL`, 길이 초과, 잘못된 값 등의 오류도
경고나 값 보정으로 바꿉니다(STRICT_TRANS_TABLES 기본 모드에서도 그렇습니다). 호출자는
손상된 입력이 성공적으로 저장됐다고 오인할 수 있습니다.

`insertIgnore()`는 다이얼렉트 봉인 규약이 명시한 유일한 탈출구이고 호출처가 9곳
(`blobs`, `thread_refs`, `search_index`, `bayes_tokens`, `bayes_totals`, `report_sends`,
`vacation_sent`, `maildrop_locks`, `suppressions`, `dedup_tracking`)이라, 계약을 "중복키만
무시한다"로 좁히려면 PG의 `ON CONFLICT DO NOTHING`과 의미를 맞춰야 합니다.

### 13. 리포트 집계의 fallback UPDATE가 결과를 확인하지 않아 조용히 유실될 수 있음

위치:

- [packages/store/src/report-store.ts:68](packages/store/src/report-store.ts:68)
- [packages/store/src/report-store.ts:94](packages/store/src/report-store.ts:94)

**정정**: 초판은 "연결 오류·권한 오류 뒤에도 UPDATE가 성공처럼 처리된다"고 적었으나 그
경로는 성립하지 않습니다 — 연결·권한 오류라면 catch 안의 재시도 UPDATE도 똑같이 던지므로
호출자에게 전파됩니다.

실제 조용한 유실 경로는 다릅니다. 집계 INSERT가 **중복키가 아닌 사유**(길이 초과, 잘못된
값 등)로 실패하면 fallback UPDATE는 매칭 행이 없어 0행을 갱신하는데, 코드가 **그 결과를
확인하지 않고** 정상 반환합니다. 집계 1건이 아무 신호 없이 사라집니다.

수정은 catch 범위 조정이 아니라 fallback UPDATE의 `changes`를 확인하고 0이면 원 예외를
다시 던지는 것입니다.

## 낮음 및 기능 공백

### 14. 보고서 전송이 at-most-once로 설계돼 재시도 여지가 없음

위치:

- [packages/store/src/report-store.ts:158](packages/store/src/report-store.ts:158)
- [apps/server/src/reports.ts:141](apps/server/src/reports.ts:141)

전송 claim을 먼저 커밋한 뒤 실제 발송합니다. `sender.send()`가 실패해도 claim은 남아 다음
실행에서 이미 처리된 리포트로 간주됩니다.

**정정**: 이것은 간과가 아니라 **문서화된 트레이드오프**입니다. 두 곳의 주석이 근거를 적고
있습니다 — 보낸 뒤에 claim하면 그 사이에 죽었을 때 같은 리포트가 두 번 나가고, 받는 쪽은
중복으로 세어 통계가 부풀며 우리는 스팸처럼 보인다는 것(`vacation_sent`와 같은 규율).

남는 비판은 "선택지가 둘뿐"이라는 점입니다. claim 행에 시도 횟수와 상태를 두면 at-most-once를
유지하면서도 일시 장애를 재시도할 수 있습니다. 대상은 DMARC·TLS-RPT 집계, 즉 주기적
텔레메트리이고 메일 유실이 아니므로 낮음으로 둡니다(초판은 높음이었습니다).

### 15. STARTTLS 프로브가 고정 시간 대기에 의존함

위치:

- [apps/server/test/access-starttls-probe.ts:63](apps/server/test/access-starttls-probe.ts:63)
- [apps/server/test/access-starttls-probe.ts:85](apps/server/test/access-starttls-probe.ts:85)

TLS 업그레이드 후 응답을 고정 500ms만 기다린 뒤 소켓을 파괴하고 그때까지 모인 문자열로
판정합니다. scrypt 인증 응답이 늦어지면 빈 응답으로 실패합니다.

**정정**: 재검증에서 이 프로브는 통과했습니다. 초판의 "전체 실행에서 실패" 관측은 재현되지
않았습니다. 다만 같은 파일의 다른 대기는 이미 "기대한 표식이 오지 않으면 끊고 실패시킨다"는
규율로 바뀌어 있는데(업그레이드 대기) 이 마지막 단계만 시간 기반으로 남아 있습니다.
선행 검수 E10(시간 기반 플레이크)의 잔여분입니다.

수정: 기대 응답 표식(`OK`/`+OK`)이 나타날 때까지 읽고, 데드라인은 성공 조건이 아니라
실패 경로로만 씁니다.

### 16. D1 방언 계약 테스트만 CI에서 검증되지 않음

위치:

- [apps/server/test/dialect-contract.test.ts:99](apps/server/test/dialect-contract.test.ts:99)
- [.github/workflows/ci.yml:77](.github/workflows/ci.yml:77)

**정정**: 초판은 "PostgreSQL·MySQL·D1 계약 테스트가 기본적으로 건너뛰어진다 / 방언별 CI가
없다"고 적었으나 **CI에는 있습니다.** `ci.yml`이 `postgres:17`과 `mysql:8`을 서비스로 띄우고
`IONOSPHERE_TEST_PG_URL`·`IONOSPHERE_TEST_MYSQL_URL`을 job env로 넣어 Node 24·26 두 버전
모두에서 실제 연결로 계약을 검증합니다. 로컬에서의 skip은 설계된 동작입니다.

남는 공백은 **D1 하나**입니다. `IONOSPHERE_TEST_D1_ACCOUNT`/`_TOKEN`이 CI에 없어 지원 방언 중
D1만 자동 검증이 0입니다. Cloudflare 자격증명이 필요하므로 별도 워크플로(수동 또는 야간)로
분리하는 편이 현실적입니다.

### 17. MIME RFC 2231 파라미터 확장이 미구현됨

위치:

- [packages/mime/src/headers.ts:152](packages/mime/src/headers.ts:152)

`filename*0*=`, charset·언어 태그·percent-encoding 조합을 해석하지 않습니다. 코드 주석이
"Phase 0 스코프 밖"임을 명시하고 있으며, `name*=` 류는 base 키로 뭉뚱그려 저장하되
percent-encoding을 풀지 않습니다. 비ASCII 첨부 파일명이 잘못 표시되거나 유실될 수 있습니다.

### 18. MIME 미지원 charset이 latin1로 대체됨 — 의존성 없이 고칠 수 있다

위치:

- [packages/mime/src/encoding.ts:110](packages/mime/src/encoding.ts:110)

euc-kr, cp949 등 지원하지 않는 charset을 latin1 best-effort로 처리합니다. 해당 문자 집합의
메일 제목·본문·첨부 이름이 깨집니다.

**추가**: 이 항목은 "스코프 밖"으로 남길 이유가 거의 없습니다. Node의 `TextDecoder`는 ICU
기반이라 **의존성 0으로 euc-kr을 디코딩합니다**(확인: `new TextDecoder("euc-kr")`가 정상
동작). 다만 `cp949` 라벨은 `ERR_ENCODING_NOT_SUPPORTED`를 던지므로 별칭 매핑이 몇 줄
필요합니다.

수정 방향: 알려진 charset 분기 뒤에 `try { new TextDecoder(cs, { fatal: false }) } catch`를
두고, 실패할 때만 지금의 latin1 폴백으로 내려갑니다. "절대 throw 없음" 계약은 유지됩니다.

### 19. DNS-01 실행 조립이 Cloudflare 구현에 고정됨

위치:

- [packages/tls/src/types.ts:32](packages/tls/src/types.ts:32)
- [apps/server/src/main.ts:199](apps/server/src/main.ts:199)

일반 `DnsProvider` 계약은 있지만 실제 조립은 Cloudflare provider 하나에 고정되어 있습니다.
다른 DNS 공급자는 현재 DNS-01을 사용할 수 없습니다.

## 철회한 항목

초판에 있었으나 재검증에서 결함이 아님이 확인되어 뺍니다.

**초판 12. 동시 최초 사용자 생성에서 고아 tenant가 남을 수 있음** — 철회.
[apps/server/src/app.ts:1929](apps/server/src/app.ts:1929) `createUser()`의 호출자를 전수
조사하면 **테스트 파일뿐이고 프로덕션 경로가 0건**입니다. 함수 주석도 "dev/테스트
부트스트랩 … DNS 검증은 건너뛴다"라고 스스로 밝히고 있습니다. 온보딩 엔드포인트로 읽은
것이 오독이었습니다.

**초판 19. SMTP EXPN이 미구현됨** — 철회.
RFC 5321은 EXPN을 선택 사항으로 두고 `502` 응답을 허용합니다. 그리고 "열거 방지 정책을
일관화할 필요가 있다"는 지적과 달리 이미 일관돼 있습니다 — `handleVrfy()`가 RFC 5321 §7.3을
인용하며 **항상 252**를 반환해 사용자 열거를 막습니다
([packages/proto-smtp/src/engine.ts:1063](packages/proto-smtp/src/engine.ts:1063)).
결함이 아닙니다.

## 심각도 재분류 내역

| 항목 | 초판 | 이 판 | 근거 |
|---|---|---|---|
| 같은 메일함 MOVE (신규 1) | — | **높음** | 무표시 메일 소실 + 성공 응답, 재현 완료 |
| POP3 QUIT (초판 3) | 높음 | 높음 | 유지 |
| MTA-STS SSRF (초판 1) | 높음 | 높음 | 유지 |
| COPY 쿼터 (초판 4) | 높음 | 중간 | 인증 필요, 블롭 공유로 실디스크 증가 제한적 |
| 헤더 CPU (초판 2) | 높음 | 중간 | 상한은 이미 적용됨, 잔여는 선형, 실측 미재현 |
| Email/set·EmailSubmission (초판 5·6) | 높음 | 중간 | 데이터 불일치, 메일 유실 아님 |
| Thread state (초판 7) | 높음 | 중간 | 동기화 정확성 |
| 리포트 claim (초판 8) | 높음 | 낮음 | 의도된 트레이드오프, 텔레메트리 대상 |
| 고아 tenant (초판 12) | 중간 | 철회 | 프로덕션 호출자 0 |
| 방언 CI (초판 16) | 낮음 | 재작성 | PG·MySQL은 CI 있음, D1만 공백 |
| EXPN (초판 19) | 낮음 | 철회 | RFC 준수, VRFY도 이미 하드닝됨 |

## 우선 수정 순서

1. **같은 메일함 MOVE 가드** — `from === to`를 스토어에서 거부하거나 no-op으로 수렴 (항목 1)
2. **POP3 expunge 범위** — `expunge()`에 세션 UID 전달 (항목 2)
3. **COPY 쿼터 검사** — append와 같은 게이트를 COPY 경로에 적용 (항목 4)

   ★1~3은 모두 `copyOrMoveBatchAttempt`/`expungeAttempt` 두 함수라, 회귀 테스트를 한 번에
   붙일 수 있습니다.

4. **MTA-STS를 가드된 HTTP 클라이언트로** — webhook의 클라이언트를 core로 승격 (항목 3)
5. **JMAP Email/set·EmailSubmission 원자성** (항목 5·6)
6. **JMAP 세션 URL** — Host 허용목록 검증 + `externalBaseUrl` 미설정 시 fail closed (항목 9)
7. **헤더 섹션 크기 예산** 신설 — 항목 8의 잔여 비용을 유계로
8. **Thread·Identity state/change 로그 보강** (항목 7·11)
9. **리포트 fallback UPDATE 결과 확인** (항목 13), **Cloudflare 페이지네이션** (항목 10)
10. **D1 계약 워크플로 분리**, **euc-kr 디코딩** (항목 16·18)

---

⚠ 이 파일은 미수정 취약점의 위치와 재현 방법을 담고 있고 이 저장소는 공개입니다.
`docs/AUDIT-*.md`는 `.gitignore` 38행이 사유와 함께 제외하고 있으나 **저장소 루트의 이
파일은 그 패턴에 걸리지 않습니다.** 커밋 전에 `.gitignore`에 사유와 함께 추가하거나
`docs/AUDIT-2026-08-25.md`로 옮겨 기존 패턴에 태우십시오.
