# ionosphere

**TypeScript로 직접 구현한 올인원 메일 서버.**

> *이온층은 서로 보이지 않는 두 지점이 대화하게 해 주는 층이다 — 지평선 너머로 전파를 되돌려
> 보내 준다. 메일도 보내는 사람과 받는 사람이 직접 연결되지 않는다. 사이에 있는 무언가가
> 받아 두었다가 건넨다. 이 저장소가 그 사이에 있는 것이다.*

SMTP·POP3·IMAP·JMAP·ManageSieve·LMTP를 외부 MTA 없이 한 프로세스에서 처리한다.
Postfix·Dovecot·OpenDKIM을 조립하는 대신 프로토콜 상태머신을 직접 구현했다.

- **런타임 의존성 0** — `node:` 빌트인만 쓴다. SQLite는 `node:sqlite`가 내장이라
  DB 드라이버도 필요 없다(PostgreSQL·MySQL을 쓸 때만 `pg`·`mysql2`를 optional peer로 설치).
  DKIM·ARC·SPF·DMARC·MTA-STS·ACME·JOSE·ASN.1·MIME 파싱 전부 자체 구현이다.
- **Node 전용** — 런타임 전용 API를 쓰지 않고 `node:http`/`node:net`/`node:tls`로만 작성하며,
  린터가 이를 강제한다. 테스트도 `node --test`로 돈다(러너 의존성 0).
- **외부 서비스 불필요** — 인증서는 내장 ACME 클라이언트가 http-01로 받아온다. 계정도, DNS
  API 토큰도 필요 없다.

프로덕션에서 운영 중이다(발송·수신 양방향, DKIM/SPF/DMARC pass 실측). 테스트는 1,790여 개이고
`node --test`로 돌린다. CI가 lint·typecheck·전체 테스트·smoke를 전부 돌린다.

## 요구 사항

- **Node 24+**. CI와 라이브 모두 Node 24다. 더 낮은 버전은 시험하지 않았다 — `.ts`를 타입
  스트리핑으로 직접 실행할 수 있어야 하고 `node:sqlite`가 있어야 한다. `engines`에 적어
  두었지만 **npm은 기본이 경고**이고 코드에서 `process.version`을 막지도 않으니, 낮은
  버전에서는 문법 에러로 드러난다.
- 그 외 없음. 데이터베이스 서버도, 메시지 큐도, 외부 API 계정도 필요 없다.

## 빠르게 띄워 보기

아래 절차는 이 문서를 쓰기 전 실제로 처음부터 끝까지 실행해 확인한 것이다.

```bash
git clone <이 저장소> && cd ionosphere
npm install          # 워크스페이스 링크 + 개발 도구
# 런타임 의존성은 없다 — 받는 것은 typescript·@types와 PG/MySQL 어댑터 테스트용 드라이버뿐이다.
# ⚠ PostgreSQL/MySQL로 운영한다면 `--omit=dev`를 쓰지 말 것 — pg·mysql2가 devDependency다.

export IONOSPHERE_DB=./ionosphere.db
export IONOSPHERE_MASTER_KEY=$(openssl rand -hex 32)   # DKIM 개인키·비밀번호 암호화 키

# 1) 도메인 등록 — DKIM 키(RSA+Ed25519) 생성 후 넣어야 할 DNS 레코드를 출력한다
node apps/server/src/cli.ts add-domain example.test

# 2) 사용자 생성 (INBOX 포함)
node apps/server/src/cli.ts create-user alice@example.test 's3cret-pw'

# 3) 기동 — 자체서명 인증서를 자동 생성한다
IONOSPHERE_HOSTNAME=mail.example.test \
IONOSPHERE_TLS_MODE=selfsigned IONOSPHERE_TLS_DIR=./tls \
IONOSPHERE_SMTP_STARTTLS=1 \
IONOSPHERE_SMTP_PORT=2525 IONOSPHERE_IMAPS_PORT=9993 \
  node apps/server/src/main.ts
```

메일 한 통을 넣고 IMAP으로 읽어 보면 종단이 확인된다:

```bash
printf 'EHLO t\r\nMAIL FROM:<bob@out.test>\r\nRCPT TO:<alice@example.test>\r\nDATA\r\nSubject: hello\r\n\r\nit works\r\n.\r\nQUIT\r\n' \
  | nc 127.0.0.1 2525

printf 'a1 LOGIN alice@example.test s3cret-pw\r\na2 SELECT INBOX\r\na3 FETCH 1 BODY[TEXT]\r\na4 LOGOUT\r\n' \
  | openssl s_client -quiet -connect 127.0.0.1:9993
```

`IONOSPHERE_MASTER_KEY`를 빼면 기동이 거부된다 — DKIM 개인키와 스마트호스트 비밀번호가 평문으로
DB에 들어가기 때문이다. 의도한 경우에만 `IONOSPHERE_ALLOW_PLAINTEXT_SECRETS=1`로 명시한다.

## 리스너

포트는 **지정한 것만 열린다**. 역할별로 서버를 쪼개 띄울 수 있게 한 설계이고, 기본값이
없는 리스너는 env를 주지 않으면 아예 뜨지 않는다.

| 프로토콜 | env | 기본 |
|---|---|---|
| SMTP 수신 | `IONOSPHERE_SMTP_PORT` | 2525 (`off`로 끔) |
| Submission / 암시적 TLS | `IONOSPHERE_SUBMISSION_PORT` / `IONOSPHERE_SMTPS_PORT` | 없음 |
| IMAP / IMAPS | `IONOSPHERE_IMAP_PORT` / `IONOSPHERE_IMAPS_PORT` | 없음 |
| POP3 / POP3S | `IONOSPHERE_POP3_PORT` / `IONOSPHERE_POP3S_PORT` | 1110 / 없음 |
| JMAP | `IONOSPHERE_JMAP_PORT` | 없음 |
| ManageSieve | `IONOSPHERE_MANAGESIEVE_PORT` | 없음 |
| LMTP | `IONOSPHERE_LMTP_PORT` | 없음 |
| 관리 REST / autoconfig / 메트릭 | `IONOSPHERE_ADMIN_PORT` / `IONOSPHERE_AUTOCONFIG_PORT` / `IONOSPHERE_METRICS_PORT` | 없음 |
| HTTPS 프론트(TLS 종단 + Host 라우팅) | `IONOSPHERE_HTTPS_FRONT_PORT` | 없음 |
| 80 → 443 리다이렉트 | `IONOSPHERE_HTTP_REDIRECT_PORT` | 없음 |

기본값이 비특권 포트(2525·1110)인 것은 의도적이다 — root 없이 바로 띄워 볼 수 있어야 한다.
표준 포트로 쓰려면 `CAP_NET_BIND_SERVICE`를 주거나 앞단에서 리다이렉트한다.

### HTTP(S) 표면은 Host 화이트리스트로 닫혀 있다

관리 REST·autoconfig·JMAP·메트릭은 전부 HTTPS 프론트 뒤의 로컬 upstream이고, 프론트는
**이름을 명시한 요청만** 받는다. `IONOSPHERE_HOST_<서비스>`(콤마 구분)로 지정하며 미지정 서비스는
`{서비스}.localhost` 하나만 받는다 — 목록에 없는 Host는 404다(기본 upstream으로 흘리지 않는다).

이름마다 노출 범위도 나뉜다: `mta-sts.`·`autoconfig.`·JMAP은 공개, 관리 콘솔은
**연결이 착지한 인터페이스가 내부일 때만** 받는다. DNS로 이름을 숨기는 것과 다르다 —
공인 IP에 `Host:` 헤더를 직접 실어도 통과하지 못한다.

외부 리버스 프록시는 필요 없다. TLS 종단·SNI·Host 라우팅·리다이렉트가 전부 내장이다.

## TLS 인증서

`IONOSPHERE_TLS_MODE`로 고른다. **다섯 갈래 전부 외부 서비스 없이 성립한다.**

| 모드 | 용도 |
|---|---|
| `selfsigned` | 자체서명 자동 생성·자동 갱신. 개발·내부용 |
| `acme` | 내장 ACME(RFC 8555)로 Let's Encrypt 등에서 발급·자동 갱신 |
| `file` | 이미 있는 키·인증서 파일 경로 |
| `url` | 원격 엔드포인트에서 주기적으로 받아옴(호스트명 대조 포함) |
| `none` | TLS 비활성 |

`acme`의 챌린지는 `IONOSPHERE_TLS_ACME_CHALLENGE`로 고른다:

- **`http-01`(기본)** — 발급 동안만 80포트에 최소 리스너를 띄운다. 외부 계정·토큰 불필요.
  포트는 `IONOSPHERE_TLS_ACME_HTTP_PORT`로 바꿀 수 있다(앞단 프록시 뒤에 둘 때).
- `dns-01` — `_acme-challenge` TXT를 올린다. 저장소에 있는 `DnsProvider` 구현은 Cloudflare용
  하나뿐이라 이 갈래는 `IONOSPHERE_CF_DNS_TOKEN`이 필요하다. 다른 DNS를 쓰려면 `DnsProvider`
  (`setTxt`/`removeTxt` 두 메서드)를 구현해 넣으면 된다.

## 저장소 백엔드

| 영역 | 선택지 |
|---|---|
| 메타데이터 DB | SQLite(기본, 빌트인) / PostgreSQL / MySQL·MariaDB |
| 메시지 본문 | 로컬 파일시스템(기본) / S3 호환 오브젝트 스토리지 |

SQLite는 `IONOSPHERE_DB`에 파일 경로를 준다. PostgreSQL·MySQL은 `IONOSPHERE_DB_URL`에 연결 문자열을
준다(`postgres://…` / `mysql://…`) — 지정하면 `IONOSPHERE_DB`보다 우선한다. 서버와 관리 CLI가
**같은 규칙**을 쓰므로 한쪽만 다른 DB를 보는 일이 없다. 드라이버는 **동적으로만** 로드되므로
SQLite만 쓰면 `pg`·`mysql2`를 설치하지 않아도 된다.

여러 인스턴스가 한 DB를 공유하는 구성은 PostgreSQL(또는 MySQL)로 가야 한다 — SQLite는
단일 라이터 전제다.

이미 SQLite로 운영 중이라면 `scripts/migrate-to-sql.ts`로 옮긴다(스키마 적용 → 테이블별 복사 →
행 수 대조까지 한 번에. `--dry-run`으로 먼저 확인할 것).

Cloudflare D1 어댑터(`openD1`)도 있지만 env로 배선되어 있지 않다 — 계정 ID·토큰처럼 URL로
표현하기 어색한 설정이 필요해서, 쓰려면 코드에서 직접 열어 `IonosphereApp`에 주입해야 한다.

## 구현한 것

RFC를 직접 구현했다. 각 프로토콜은 **I/O import가 0개인 순수 상태머신**(`engine.ts`)과 소켓을
담당하는 얇은 어댑터(`server.ts`)로 나뉘어 있어, 프로토콜 동작이 네트워크 없이 테스트된다.

- **전송·접근**: SMTP(+ STARTTLS·SMTPUTF8·PIPELINING·SIZE·8BITMIME), Submission,
  IMAP4rev1(+ IDLE·CONDSTORE·QRESYNC·UIDPLUS·MOVE·ESEARCH·LIST-STATUS·SPECIAL-USE),
  POP3, JMAP, ManageSieve, LMTP
- **인증**: SASL **SCRAM-SHA-256**(RFC 7677)·PLAIN·LOGIN·XOAUTH2·OAUTHBEARER, 앱 비밀번호,
  OAuth 토큰. SCRAM은 네 프로토콜(SMTP·IMAP·POP3·ManageSieve) 전부에서 동작하며,
  서버가 평문 비밀번호를 쥐지 않고 상호 인증까지 한다. 계정 열거 방어 포함
  (없는 계정에도 결정적 가짜 salt로 교환을 끝까지 진행한다 — RFC 5802 §7).
  비밀번호 저장은 scrypt를 유지하고 SCRAM 키를 **함께** 둔다 — SCRAM의 PBKDF2로 갈아타면
  오프라인 대입 내성이 내려가기 때문이다. 기존 계정은 다음 로그인에 SCRAM 키가 생성된다.
  ⚠ **CRAM-MD5는 넣지 않는다**(결정). 서버가 평문 동등 비밀을 보관해야 하는데, 그건
  APOP을 거절한 것과 같은 이유다(`docs/PROTOCOLS.md` §3). SCRAM이 그 자리를 대신한다
- **스팸 판정**: 자체 점수 엔진 — DNSBL 가중치 + 헤더 휴리스틱 룰 + 계정별 나이브 베이즈.
  판정은 accept/**junk**/reject 세 갈래다(중간을 두어 오탐이 곧 유실이 되지 않게 한다).
  베이즈 토큰은 **해시로만** 저장하고(HMAC + 계정별 솔트) 계정 경계를 넘지 않는다 —
  DB를 열어도 남의 메일 단어를 읽을 수 없다. 학습은 사용자가 스팸으로 표시할 때만 일어난다.
- **메일 인증**: DKIM 서명·검증(RSA·Ed25519 — RFC 8463 준수), ARC 서명·검증·봉인, SPF, DMARC 판정,
  MTA-STS 정책 조회·적용, SRS. `add-domain`이 SPF·DKIM·DMARC·MTA-STS·TLS-RPT 레코드를 만들어 준다
  (DMARC·TLS-RPT 집계 리포트는 메일로 도착할 뿐 파서는 없다 — 읽는 것은 사람 몫)
- **DNSSEC·DANE**(`IONOSPHERE_DANE=1`, 기본 꺼짐): 루트 신뢰앵커부터 위임을 따라 내려가는 자체
  검증 리졸버(RRSIG·DS·DNSKEY, RSASHA256·ECDSAP256·Ed25519) 위에 RFC 7672 DANE를 올렸다.
  **DNSSEC로 검증된 TLSA만** 쓴다 — 검증 없이 믿으면 DNS를 속인 공격자가 우리로 하여금
  그의 인증서를 고정하게 만들 수 있다. TLSA가 있으면 TLS는 필수가 되고, 인증서가 맞지 않으면
  배달을 멈춘다(바운스가 아니라 지연 — 잠깐 끼어든 공격자가 정상 메일을 죽이면 안 되므로).
  ⚠ NSEC/NSEC3 부재 증명은 없다: 레코드를 **지우는** 공격은 DANE 미적용(=도입 이전 동작)으로
  귀결되고, 틀린 TLSA를 신뢰하는 경로는 없다
- **배달**: MX 직송 또는 스마트호스트 릴레이, 큐·재시도·바운스, 억제 목록, 별칭 팬아웃,
  전달 규칙, Sieve 필터링, 웹훅
- **검색**: 전용 토큰 색인(`search_index`) — NFKC 정규화 + 케이스폴드 + CJK 바이그램,
  라틴은 단어 단위. 제목·본문·From·To 필드별 검색
- **운영**: 관리 기능이 **GUI→API→CLI 3층**으로 분리돼 있다. 명령을 `@ionosphere/admin-cmd`에
  하나 정의하면 REST 라우트·CLI 서브커맨드·콘솔 탭이 **동시에** 생긴다 — 세 표면 중 한 곳에만
  기능이 있는 상태가 구조적으로 나오지 않는다. 콘솔은 무프레임워크 단일 페이지(외부 리소스 0)이고
  기능 목록을 갖지 않는다: 기동 시 서버에서 **명령 서술**을 받아 탭·표·폼을 그린다.
  그 밖에 Prometheus 메트릭, autoconfig/autodiscover, 블롭 GC, 마이그레이션, 낙관적 락(modseq)
- **접근 감사 로그**: 여덟 표면(IMAP·POP3·ManageSieve·SMTP·Submission·LMTP·JMAP·관리 REST)의
  "언제·누가·어디서·무엇을·성패"를 일별 JSONL로 남기고, 날짜가 바뀌면 오브젝트 스토리지로 이관.
  인증 성패뿐 아니라 **스로틀 차단**과 조회·상태 변경까지 남는다. 메일 본문·시브 스크립트·
  비밀번호는 **들어가지 않는다**(대상과 규모만 — 허용 목록 방식)

### 접근 감사 로그 env

| env | 기본 | 뜻 |
|---|---|---|
| `IONOSPHERE_AUDIT` | 없음(비활성) | `1`이면 켠다 |
| `IONOSPHERE_AUDIT_DIR` | `/var/lib/ionosphere/audit` | 일별 JSONL 위치(`0o700`, 파일 `0o600`) |
| `IONOSPHERE_AUDIT_FLUSH_MS` | 1000 | 버퍼 flush 주기 — SIGKILL 시 최대 이만큼 유실 |
| `IONOSPHERE_AUDIT_SHIP_INTERVAL_MS` | 3600000 | 이관 tick |
| `IONOSPHERE_AUDIT_LOCAL_RETAIN_DAYS` | 7 | 이관 실패로 남은 파일을 버리는 시점 |
| `IONOSPHERE_AUDIT_SHIP_HOST` | `IONOSPHERE_HOSTNAME` | 이관 키에 들어가는 인스턴스 이름 |
| `IONOSPHERE_AUDIT_S3_*` | 없음(로컬 전용) | `ENDPOINT`/`BUCKET`/`ACCESS_KEY`/`SECRET_KEY`/`REGION`/`PREFIX`/`PATH_STYLE`. 라이브는 전용 버킷 `ionosphere-audit` 사용 |

`IONOSPHERE_AUDIT_S3_*`는 **하나라도 있고 나머지가 없으면 기동을 세운다** — 부분 설정으로 조용히
이관이 안 되면 파일이 쌓이다 보존기간에 버려진다. 버킷은 블롭 버킷과 **분리**한다(같은 버킷을
쓰면 감사 기록의 접근권한·보존기간을 메일 본문과 따로 걸 수 없다). 여러 인스턴스가 한 버킷에
쓸 때 키에 호스트가 들어가는 이유는 같은 날짜 파일이 서로를 덮어쓰지 않게 하기 위해서다.

이관 키는 **최소권한**으로 준다 — shipper가 내는 호출은 PUT 하나뿐이므로 `s3:PutObject`만 있으면
된다(LIST·GET·DELETE 불필요). 이관이 되는지 한 시간 기다리지 않고 확인하려면
`node --experimental-strip-types scripts/audit-ship.ts --dry-run`으로 대상 파일 수만 세고,
실제 이관은 같은 스크립트를 `--dry-run` 없이 돌린다.

⚠ **볼륨**: 범위가 조회를 포함하므로 IMAP FETCH마다 한 줄이다. 줄당 ~200바이트면 초당 100 FETCH가
약 17MB/일·인스턴스. gzip이 JSONL에서 보통 10:1이라 이관 후 부피는 1/10이다.

## 개발

```bash
npm run verify   # lint + typecheck + test + smoke
```

`scripts/lint.ts`는 의존성 0으로 이 저장소의 규약을 기계로 강제한다(패키지 순환 의존,
다이얼렉트 분기 격리, 소유권 규칙 등). 새 규약은 되도록 린터나 타입으로 강제한다 —
tsconfig가 강제하는 영역만 잘 지켜졌다는 것이 과거 코드 검수의 결론이었다.

- [CLAUDE.md](CLAUDE.md) — 기여 규약과 설계 기준
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — 배치·리스너·TLS·DNS·백업 등 운영 가이드
- [docs/SCHEMA.md](docs/SCHEMA.md) — 동결된 DB 스키마
- [docs/PROTOCOLS.md](docs/PROTOCOLS.md) — 프로토콜별 구현 범위
- [SECURITY.md](SECURITY.md) — 취약점 신고 방법과 범위

**공개판은 히스토리 없는 스냅샷이다.** 초기 커밋에 운영 자격증명이 평문으로 들어간 적이 있어
히스토리를 가져오지 않는다. 같은 이유로 특정 인스턴스의 운영 기록(주소·구성 실값)은 공개하지
않는다 — 일반 운영에 필요한 것은 위 `docs/OPERATIONS.md`에 식별자 없이 정리해 두었다.

## 아직 안 되는 것

정직하게 적어 둔다.

- **ARC 라이브 실측 미완** — 벡터·round-trip 테스트는 통과하지만 실제 포워딩 경로를 통과한
  검증은 아직 없다.
- **Cloudflare D1 어댑터가 env로 배선되지 않음** — 코드에서 직접 열어 주입해야 한다.
- **Ed25519 DKIM은 주요 수신자가 검증하지 않는다** — 우리 서명은 RFC 8463을 지키지만
  Gmail은 `dkim=neutral (no key)`로 판정을 유보한다(2026-08-03 실측). RFC 8463이 SHOULD라
  지원이 고르지 않다. 그래서 `add-domain`이 **RSA + Ed25519 키를 둘 다** 만들고 발송 시
  **두 서명을 모두** 붙인다 — Ed25519 단독 서명은 그런 수신자에게 "서명 없음"과 같다.
  DNS에 두 selector를 모두 올릴 것.

## 라이선스

[MIT](LICENSE)
