# ionosphere 코드 전수 점검 보고서

점검일: 2026년 8월 25일

## 점검 범위

문서 파일은 분석 대상에서 제외하고 `packages/`, `apps/`, `scripts/`의 TypeScript 코드와 테스트만 점검했습니다.
점검 대상은 약 520개 파일, 약 9.8만 줄입니다.

검토 항목은 다음과 같습니다.

- 기능 오류와 프로토콜 상태 전이
- 데이터 무결성, 원자성, 동시성
- 인증·인가, TLS, SSRF, 입력 검증과 자원 고갈
- 미구현·더미 처리와 기능 연결 누락
- 테스트 공백과 실제 회귀

## 검증 결과

- `npm run lint`: 통과
- `npm run typecheck`: 통과
- 전체 테스트: 2383개 중 2378개 통과, 2개 실패, 3개 건너뜀
- `npm run smoke`: 앞 단계의 테스트 실패로 실행되지 않음

전체 테스트에서 실패한 항목은 다음과 같습니다.

1. STARTTLS 프로브: 병렬 부하에서 고정 500ms 대기 후 실패합니다. 프로브 단독 실행은 통과했습니다.
2. 대형 `References`·`To` 헤더 테스트: 저장 경로의 처리 시간이 100ms 상한을 초과했습니다.

## 심각도 기준

- **높음**: 메일 유실·오삭제, 테넌트 또는 보안 경계 침해, 서비스 거부가 직접 가능합니다.
- **중간**: 특정 구성이나 입력에서 기능 오류·데이터 불일치가 발생합니다.
- **낮음**: 기능 공백, 테스트 불안정, 운영 자동화의 제한입니다.

## 높음

### 1. MTA-STS 정책 조회가 SSRF 방어 없이 HTTPS 요청을 수행함

위치:

- [packages/mta-sts/src/fetch.ts:43](packages/mta-sts/src/fetch.ts:43)
- [apps/server/src/app.ts:1978](apps/server/src/app.ts:1978)

`mta-sts.<recipient-domain>`을 그대로 `fetch()`합니다. 공격자가 소유한 도메인의 DNS를 사설 IP, loopback 또는 클라우드 메타데이터 주소로 지정하고 `_mta-sts` TXT 레코드를 추가하면, 메일 발송 워커가 내부 주소로 연결할 수 있습니다.

리다이렉트는 차단하지만 DNS 해석 결과의 사설 주소 검사와 IP 고정이 없습니다. 웹훅 경로의 SSRF 방어도 이 경로에는 적용되지 않습니다.

### 2. 대형 `References`·주소 헤더가 CPU와 메모리를 과도하게 사용함

위치:

- [packages/mime/src/ids.ts:13](packages/mime/src/ids.ts:13)
- [packages/mime/src/address.ts:9](packages/mime/src/address.ts:9)
- [packages/mime/src/address.ts:181](packages/mime/src/address.ts:181)

상한은 저장 직전에 적용되지만, 그 전에 모든 Message-ID와 주소 항목을 배열로 만들고 파싱합니다. 따라서 한도 이하로 저장되더라도 입력을 분리·복사·해시하는 비용은 입력 크기에 비례합니다.

실제 2만 개 항목 테스트가 처리 시간 상한을 초과했습니다. SMTP 수신자가 헤더 하나로 이벤트 루프와 저장 워커를 점유시킬 수 있습니다.

### 3. POP3 QUIT가 다른 세션의 `\Deleted` 메일까지 삭제함

위치:

- [apps/server/src/backend.ts:2037](apps/server/src/backend.ts:2037)
- [packages/store/src/store.ts:1244](packages/store/src/store.ts:1244)

POP3 세션이 삭제한 UID 목록을 `setDeleted()`에 전달한 뒤, 메일함 전체를 대상으로 `expunge()`를 호출합니다.

재현 시나리오:

1. IMAP에서 메시지 A에 `\Deleted` 설정
2. POP3에서 메시지 B를 삭제하고 QUIT
3. A와 B가 모두 삭제됨

### 4. IMAP COPY가 계정 쿼터를 우회함

위치:

- [packages/store/src/store.ts:1461](packages/store/src/store.ts:1461)
- [packages/store/src/store.ts:1724](packages/store/src/store.ts:1724)

COPY 경로는 계정 정보를 읽지만 `quota_bytes` 초과를 검사하지 않고 `used_bytes`와 `message_count`를 증가시킵니다.

쿼터가 100바이트이고 100바이트 메일이 이미 존재하는 계정에서도 COPY가 성공해 사용량이 200바이트가 됩니다. COPY를 반복해 쿼터를 계속 초과할 수 있습니다.

### 5. JMAP Email/set이 일부 변경만 남길 수 있음

위치:

- [apps/server/src/jmap-backend.ts:371](apps/server/src/jmap-backend.ts:371)
- [apps/server/src/jmap-backend.ts:381](apps/server/src/jmap-backend.ts:381)

키워드 변경, mailbox 추가, mailbox 삭제가 서로 다른 Store 호출로 실행됩니다. 유효한 mailbox와 존재하지 않는 mailbox를 함께 지정하면 앞선 변경이 적용된 뒤 뒤의 변경에서 실패할 수 있습니다.

응답은 `notUpdated`가 되지만 일부 변경은 남아 JMAP set 요청의 원자적 기대와 어긋납니다.

### 6. JMAP EmailSubmission 거절 후 유령 submission이 남음

위치:

- [apps/server/src/jmap-backend.ts:567](apps/server/src/jmap-backend.ts:567)
- [apps/server/src/jmap-backend.ts:575](apps/server/src/jmap-backend.ts:575)

`email_submissions` 행과 상태를 먼저 커밋한 뒤 MTA 큐에 적재합니다. 발송 정책, 레이트리밋 또는 도메인 검증으로 enqueue가 거절되면 submission 행은 남지만 응답은 `notCreated`가 됩니다.

그 결과 실제 발송되지 않은 항목이 `EmailSubmission/get`에 나타날 수 있습니다.

### 7. Thread 변경 state와 changes가 갱신되지 않음

위치:

- [packages/store/src/store.ts:753](packages/store/src/store.ts:753)
- [packages/store/src/store.ts:1292](packages/store/src/store.ts:1292)
- [packages/store/src/store.ts:1697](packages/store/src/store.ts:1697)
- [packages/store/src/jmap-store.ts:256](packages/store/src/jmap-store.ts:256)

Thread 변경 로그가 append 경로에서만 기록됩니다. expunge, mailbox membership 삭제, IMAP COPY 등으로 Thread의 email 목록이 바뀌어도 `state_thread`와 `ENTITY.Thread` 로그가 갱신되지 않습니다.

따라서 `Thread/get` 결과는 바뀌지만 `Thread/changes`가 변경을 반환하지 않을 수 있습니다.

### 8. 보고서 전송 실패 후 영구 유실될 수 있음

위치:

- [packages/store/src/report-store.ts:166](packages/store/src/report-store.ts:166)
- [apps/server/src/reports.ts:145](apps/server/src/reports.ts:145)

전송 claim을 먼저 커밋한 뒤 실제 발송합니다. `sender.send()`가 실패해도 claim은 남아 다음 실행에서 이미 처리된 리포트로 간주됩니다.

일시적인 SMTP 또는 네트워크 장애가 DMARC·TLS 보고서의 영구 유실로 이어질 수 있습니다.

## 중간

### 9. JMAP 세션 URL이 검증되지 않은 Host 헤더를 사용함

위치:

- [apps/server/src/jmap-server.ts:439](apps/server/src/jmap-server.ts:439)
- [apps/server/src/jmap-server.ts:466](apps/server/src/jmap-server.ts:466)

`externalBaseUrl`이 없으면 요청의 `Host` 헤더로 `apiUrl`, `uploadUrl`, `downloadUrl`, `eventSourceUrl`을 구성합니다. 공격자가 임의 Host를 보내면 세션 응답의 후속 URL이 공격자 도메인을 가리킬 수 있습니다.

직접 노출된 JMAP 리스너나 잘못 구성된 프록시에서 클라이언트의 요청 대상이 변조될 수 있습니다.

### 10. Cloudflare DNS-01 자동 존 탐색이 첫 50개 존만 검사함

위치:

- [apps/server/src/cf-dns.ts:36](apps/server/src/cf-dns.ts:36)

자동 탐색 요청이 `/zones?per_page=50` 한 번으로 끝나며 페이지네이션이 없습니다. Cloudflare 계정에 50개를 초과하는 존이 있고 대상 존이 뒤쪽 페이지에 있으면 ACME DNS-01 발급과 갱신이 실패합니다.

### 11. JMAP Identity state가 항상 `"0"`으로 고정됨

위치:

- [apps/server/src/jmap-backend.ts:448](apps/server/src/jmap-backend.ts:448)
- [apps/server/src/jmap-backend.ts:1250](apps/server/src/jmap-backend.ts:1250)
- [apps/server/src/jmap-backend.ts:1268](apps/server/src/jmap-backend.ts:1268)

Identity를 생성·수정·삭제해도 `Identity/get`의 state가 바뀌지 않습니다. 클라이언트의 `ifInState` 검사가 변경을 감지하지 못하고 Identity 캐시가 오래된 상태로 남을 수 있습니다.

### 12. 동시 최초 사용자 생성에서 고아 tenant가 남을 수 있음

위치:

- [apps/server/src/app.ts:1943](apps/server/src/app.ts:1943)

동시에 최초 사용자를 생성하면 각 요청이 tenant를 먼저 생성한 뒤 도메인 claim에서 경쟁합니다. 한 요청이 claim 충돌로 실패해도 먼저 생성된 tenant가 정리되지 않습니다.

### 13. MySQL `INSERT IGNORE`가 데이터 오류까지 숨길 수 있음

위치:

- [packages/db/src/mysql.ts:173](packages/db/src/mysql.ts:173)

MySQL의 `INSERT IGNORE`는 중복키뿐 아니라 `NOT NULL`, 길이 초과, 잘못된 값 등의 오류도 경고나 값 보정으로 바꿀 수 있습니다. 호출자는 손상된 입력이 성공적으로 저장됐다고 오인할 수 있습니다.

### 14. 일반 DB 오류를 중복키 충돌로 오인해 리포트 집계가 유실될 수 있음

위치:

- [packages/store/src/report-store.ts:56](packages/store/src/report-store.ts:56)
- [packages/store/src/report-store.ts:93](packages/store/src/report-store.ts:93)

집계 INSERT의 모든 예외를 고유키 충돌로 간주하고 UPDATE로 전환합니다. 연결 오류·권한 오류·스키마 오류 뒤에도 UPDATE가 성공처럼 처리되어 집계가 조용히 유실될 수 있습니다.

## 낮음 및 기능 공백

### 15. STARTTLS 회귀 테스트가 병렬 실행에서 불안정함

위치:

- [apps/server/test/access-starttls-probe.ts:63](apps/server/test/access-starttls-probe.ts:63)
- [apps/server/test/access-starttls-probe.ts:82](apps/server/test/access-starttls-probe.ts:82)

TLS 업그레이드 후 응답을 고정 500ms만 기다립니다. 병렬 부하에서 scrypt 인증 응답이 늦어지면 빈 응답으로 실패합니다. 프로브 단독 실행은 통과했습니다.

### 16. PostgreSQL·MySQL·D1 계약 테스트가 기본적으로 건너뛰어짐

위치:

- [apps/server/test/dialect-contract.test.ts:71](apps/server/test/dialect-contract.test.ts:71)
- [apps/server/test/dialect-contract.test.ts:85](apps/server/test/dialect-contract.test.ts:85)
- [apps/server/test/dialect-contract.test.ts:99](apps/server/test/dialect-contract.test.ts:99)

환경 변수가 없으면 SQLite만 실제 검증됩니다. 배포 대상 dialect별 CI가 없으면 런타임 SQL 차이를 놓칠 수 있습니다.

### 17. MIME RFC 2231 파라미터 확장이 미구현됨

위치:

- [packages/mime/src/headers.ts:152](packages/mime/src/headers.ts:152)

`filename*0*=`, charset·언어 태그·percent-encoding 조합을 해석하지 않습니다. 비ASCII 첨부 파일명이 잘못 표시되거나 유실될 수 있습니다.

### 18. MIME 미지원 charset이 latin1로 대체됨

위치:

- [packages/mime/src/encoding.ts:96](packages/mime/src/encoding.ts:96)

euc-kr, cp949 등 지원하지 않는 charset을 latin1 best-effort로 처리합니다. 해당 문자 집합의 메일 제목·본문·첨부 이름이 깨질 수 있습니다.

### 19. SMTP EXPN이 미구현됨

위치:

- [packages/proto-smtp/src/engine.ts:847](packages/proto-smtp/src/engine.ts:847)

`EXPN` 요청에 항상 `502 Command not implemented`를 반환합니다. 보안상 사용자 열거를 막는 정책이라면 capability·응답 정책을 명시적으로 일관화할 필요가 있습니다.

### 20. DNS-01 실행 조립이 Cloudflare 구현에 고정됨

위치:

- [packages/tls/src/types.ts:32](packages/tls/src/types.ts:32)
- [apps/server/src/main.ts:199](apps/server/src/main.ts:199)

일반 `DnsProvider` 계약은 있지만 실제 조립은 Cloudflare provider 하나에 고정되어 있습니다. 다른 DNS 공급자는 현재 DNS-01을 사용할 수 없습니다.

## 우선 수정 순서

1. POP3/IMAP expunge 범위 수정
2. IMAP COPY 쿼터 검사와 동일 메일함 MOVE 방어
3. JMAP Email/set·EmailSubmission의 원자성 확보
4. MTA-STS fetch에 DNS 결과 사설 주소 차단과 IP 고정 적용
5. MIME 헤더 파서의 조기 중단·스트리밍 처리
6. 보고서 전송 claim을 성공 이후로 옮기거나 재시도 상태 도입
7. Thread·Identity state/change 로그 보강
8. Cloudflare 페이지네이션과 dialect별 필수 CI 추가
