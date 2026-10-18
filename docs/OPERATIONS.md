# 운영 가이드

이 문서는 **이 소프트웨어를 남의 인프라에 올릴 때** 필요한 것을 다룬다. 개발 규약은
[CLAUDE.md](../CLAUDE.md), 프로토콜 카탈로그는 [PROTOCOLS.md](PROTOCOLS.md),
스키마는 [SCHEMA.md](SCHEMA.md)에 있다.

> 운영자의 라이브 주소·자격증명 같은 실값은 여기 없다. 그런 것은 각자의 비공개 문서에 둘 것 —
> 이 저장소를 공개하는 방식 자체가 그렇게 갈라져 있다.

## 1. 배치 — 한 대로 시작한다

한 프로세스가 SMTP·POP3·IMAP·JMAP·ManageSieve·LMTP를 전부 처리한다. 나누는 것은 나중 일이고,
**나눌 때 코드를 고칠 필요는 없다** — 리스너와 워커가 이미 env로 개별 제어된다.

역할을 나눈다면 셋으로 나눈다.

| 역할 | 여는 것 | 성질 |
|---|---|---|
| **MX**(수신) | 25 | 인증 경로가 **아예 없다**(무인증 수신 프로파일) |
| **MRA**(접근) | 110·143·993·995·4190·JMAP | 외부 메일이 들어오지 않는다 |
| **MSA**(발송) | 587·465 | 인증 필수 |

나누는 이유는 장애 격리(하나가 죽어도 수신은 계속된다)·표면 축소·발송 IP 평판 분리다.

⚠ **발신 MTA는 리스너가 아니라 워커다.** 587을 여는 순간 큐 워커가 자동으로 딸려 온다.
발송 큐를 다른 인스턴스에 두려면 `IONOSPHERE_RUN_MTA_WORKER`로 명시해야 한다. 분리에서 가장
헷갈리는 지점이 여기다 — "587을 안 열었으니 이 노드는 발송을 안 한다"가 참이 아니다.

역할을 나누면 **셋이 공유해야 하는 것**이 생긴다. 하나라도 빠지면 조용히 깨진다.

| 공유 대상 | 빠뜨리면 |
|---|---|
| DB(PostgreSQL/MySQL) | 애초에 성립하지 않는다 |
| blobs(S3 호환) | **목록은 정상, 본문만 안 보인다.** 메타데이터는 DB에 있기 때문이다 |
| 인증서 | 같은 이름을 서빙하는데 노드마다 다른 인증서가 나간다 |

★blobs 항목이 특히 위험하다. 검증할 때 목록(`LIST`)이 아니라 **본문까지**(`FETCH BODY[TEXT]`)
읽어 볼 것.

## 2. 리스너 — 무엇을 어디에 붙이는가

서비스별로 `IONOSPHERE_LISTEN_<서비스>`로 지정한다. 지정하지 않으면 기본 동작이다.

```bash
IONOSPHERE_LISTEN_ADMIN=127.0.0.1:8080    # 주소 + 포트
IONOSPHERE_LISTEN_METRICS=10.0.0.1:       # 주소만(포트는 IONOSPHERE_METRICS_PORT) — 끝의 콜론이 필수
IONOSPHERE_LISTEN_POP3=off                # 포트가 설정돼 있어도 기동하지 않는다
IONOSPHERE_LISTEN_JMAP=[::]:8081          # IPv6은 대괄호
```

서비스 이름: `SMTP` `SUBMISSION` `SMTPS` `POP3` `POP3S` `IMAP` `IMAPS` `LMTP` `MANAGESIEVE`
`JMAP` `ADMIN` `AUTOCONFIG` `HTTPS_FRONT` `HTTP_REDIRECT` `METRICS`.

★**주소에 포트를 박지 말 것.** 박으면 포트의 정본이 두 곳이 되고, `IONOSPHERE_<서비스>_PORT`를
고쳐도 이쪽이 이긴다. 실제로 metrics 포트를 옮길 때 일부 노드만 안 바뀐 원인이 이것이었다.

**주소만 줄 때 끝에 콜론이 필요한 이유**: `0.0.0.0`과 `8080`은 형태만으로 구분되지 않는다.
"콜론이 있으면 앞이 주소"라는 규칙이면 사람이 읽고도 판단할 수 있다. 대괄호 없는 IPv6은
포트와 구분되지 않으므로 **추측하지 않고 거절한다**.

⚠ **파싱 실패는 기동을 막는다.** 오타를 무시하면 "열었다고 생각한 포트가 안 열려 있거나,
껐다고 생각한 포트가 열려 있는" 상태가 되는데 둘 다 조용하다. 시끄럽게 죽는 쪽을 골랐다.

### 지정하지 않았을 때의 기본 바인딩

| 표면 | 기본값 | 이유 |
|---|---|---|
| `metrics` | **항상 루프백** | 인증이 없다. 공개되면 큐 깊이·정지 계정 수가 샌다 |
| `admin` | 프론트가 있으면 루프백, 없으면 전 인터페이스 + 경고 | |
| `jmap`·`autoconfig` | `HTTPS_FRONT`가 있으면 루프백, 없으면 전 인터페이스 + 경고 | |
| `lmtp` | 루프백 | 신뢰 로컬 배달 전제 |
| 그 외 | 전 인터페이스 | 외부 MTA·클라이언트가 붙어야 한다 |

주소를 **명시하면** 이 판정을 돌리지 않는다. 운영자가 이미 골랐는데 "모든 인터페이스에
열린다" 경고가 뜨면 노이즈가 되어 진짜 경고를 묻기 때문이다.

### 인터페이스가 둘 이상이면

`0.0.0.0`은 **공인 인터페이스까지 포함한다**. 사내 전용 표면은 `0.0.0.0`이 아니라 사내
주소로 묶을 것 — 방화벽을 잘못 열어도 인터넷 쪽에 뜨지 않는다.

평문 표면(관리 API·JMAP)을 사내에 여는 것은 대개 얻는 게 없다. **같은 내용을 TLS로 주는
포트가 같은 호스트에 이미 있다.** 여는 것은 기능이 아니라 안전하지 않은 경로가 하나 더 생기는
것이고, 그 경로로 흐르는 게 하필 관리 토큰과 사용자 자격증명이다. 메트릭을 원격에서 가끔 볼
뿐이라면 바인딩을 여는 대신 SSH 터널이 낫다 — 인증이 없는 표면은 접근 통제를 SSH에 맡긴다.

## 3. 필수 환경변수

| 변수 | 없으면 |
|---|---|
| `IONOSPHERE_MASTER_KEY` | DKIM 개인키·비밀번호를 암호화할 수 없다. **분실하면 복호화 불가** |
| `IONOSPHERE_DB` 또는 `IONOSPHERE_DB_URL` | SQLite 파일 경로 / PostgreSQL·MySQL URL |
| `IONOSPHERE_HOSTNAME` | EHLO·`Received`·인증서 이름의 기준 |

`IONOSPHERE_MASTER_KEY`는 `openssl rand -hex 32`로 만든다. 백업 대상이며, DB 백업과 **다른 곳에**
둘 것 — 같이 두면 백업 하나가 유출됐을 때 암호화가 의미를 잃는다.

## 4. TLS

`IONOSPHERE_TLS_MODE`가 인증서 출처를 고른다.

| 모드 | 쓰임 |
|---|---|
| `none` | 개발 전용 |
| `selfsigned` | 내부 테스트. 클라이언트가 신뢰하지 않는다 |
| `file` | 이미 있는 PEM(`IONOSPHERE_TLS_DIR`) |
| `url` | 인증서 배포 서비스에서 당겨온다(`IONOSPHERE_TLS_URL_CERT`/`_KEY`). 여러 노드가 같은 것을 본다 |
| `acme` | **내장 ACME 클라이언트**(RFC 8555). http-01 또는 dns-01 |

`acme`는 계정 생성부터 갱신·핫리로드까지 프로세스 안에서 한다 — certbot도, cron도 필요 없다.
http-01은 `IONOSPHERE_TLS_ACME_HTTP_PORT`가 80에 닿아야 하고, dns-01은 DNS 제공자 토큰이 필요하다
(현재 내장 배선은 Cloudflare 하나뿐이다 — 다른 제공자면 `file`이나 `url`을 쓰는 편이 낫다).

⚠ **인증서 확보 실패가 평문 AUTH 개방으로 이어지면 안 된다.** 코드가 `tlsConfigured`와
`implicitTls`를 분리해 두는 이유다. 실패는 더 안전한 쪽으로 떨어진다.

### LDAP/AD directory

여러 provider는 `IONOSPHERE_DIRECTORIES` JSON 배열 하나로 설정한다. 배열 원소는 반드시
`provider`, `tenantId`, `transport`, `url`, `bindDn`, `bindPassword`, `baseDn`을 가진다.
`transport`는 `ldaps` 또는 `starttls`만 허용한다. CA를 직접 고정할 때는 `tlsCaFile`을 쓴다.

```text
IONOSPHERE_DIRECTORIES=[{"provider":"corp-ad","tenantId":"tenant-id","transport":"ldaps","url":"ldaps://directory.ionosphere.test","bindDn":"cn=service,dc=ionosphere,dc=test","bindPassword":"replace-me","baseDn":"dc=ionosphere,dc=test"}]
```

선택 필드는 `userBaseDn`, `groupBaseDn`, `userFilter`, `groupFilter`, `timeoutMs`, `serverName`,
`tlsCaFile`, `pageSize`, `maxEntries`, `nestedGroupMaxDepth`다. 부분 설정·중복 provider·평문 LDAP은
기동 전에 실패한다. 일반 LDAP의 속성명이 AD와 다르면 `attributes`에서 `objectGuid`, `objectSid`,
`upn`, `samAccountName`, `mail`, `displayName`, `groupMember`를 바꾼다. 설정 오류 로그에는 bind
password를 싣지 않는다.

`surfaces`는 그 provider로 디렉터리 로그인을 허용할 표면 목록이다. 이름은 앱 비밀번호의
`scopes`와 같다(`imap`, `pop3`, `submission`, `jmap`, `sieve`). 예를 들어 `"surfaces":["imap","jmap"]`
이면 그 provider의 계정은 IMAP·JMAP으로만 디렉터리 비밀번호 로그인이 된다. 다른 표면에서는
LDAP bind도 하지 않고 인증 실패로 응답한다. **생략하면 전부 허용**한다(기존 동작). 모르는 이름이나
빈 배열은 기동 전에 실패한다. provider를 끄려면 배열에서 항목을 뺀다.

운영 적용은 다음 순서다.

1. `IONOSPHERE_DIRECTORY_LOGIN`을 비운 채 provider 설정만 배포한다.
2. 관리 API/GUI의 `directory-sync`로 snapshot을 읽고 identity·group 수를 확인한다.
3. `directory-identity-list`에서 immutable key를 확인하고 `directory-identity-link`로 로컬
   account에 연결한 뒤 다시 동기화해 membership을 만든다.
4. LDAP fixture와 실제 테스트 계정의 실패/성공을 확인한다.
5. 마지막에 `IONOSPHERE_DIRECTORY_LOGIN=1`을 넣어 directory password 로그인을 연다.

로컬 비밀번호·앱 비밀번호는 먼저 검사한다. directory 장애·TLS 검증 실패·중복 login name은
directory 인증 실패로 닫히며, 기존 local credential까지 막지는 않는다. Kerberos/GSSAPI와
referral 자동 추적은 지원 범위가 아니다.

## 5. DNS

도메인을 등록하면 CLI가 넣어야 할 레코드를 출력한다(`add-domain`). 최소 구성은 이렇다.

| 레코드 | 목적 |
|---|---|
| `MX` | 수신 MTA를 가리킨다 |
| `SPF`(TXT) | 발송 IP. 릴레이를 경유하면 그쪽 `include:`도 필요하다 |
| `DKIM`(TXT, 셀렉터별) | 등록 시 생성된 공개키. RSA·Ed25519 이중 서명을 쓴다 |
| `DMARC`(TXT) | `p=none`으로 시작해 리포트를 보고 올린다 |
| `PTR` | 발송 IP의 역방향. **인프라 이름이어도 된다** |
| `MTA-STS`·`TLS-RPT` | 선택. 정책 파일은 서버가 서빙한다 |

★**PTR(인프라 이름)과 EHLO·MX·인증서(서비스 이름)를 억지로 맞추려 하지 말 것.** 둘이 다른 것은
결함이 아니라 의도된 분리다. 수신측이 요구하는 것은 PTR이 **존재하고 정방향과 맞물리는 것**이지
서비스 이름과 같은 것이 아니다.

★**Ed25519 DKIM이 `neutral`로 오는 것은 정상 종착 상태다**(RFC 8463은 SHOULD라 처리하지 않는
수신자가 있다). `neutral`을 `fail`로 읽지 말 것 — fail은 서명이 틀렸다는 뜻이고 neutral은 판정
유보다. 그래서 RSA와 이중 서명을 하고 RSA 쪽이 유효 서명이 된다.

### 릴레이를 경유해 보낸다면

아웃바운드 25가 막힌 환경(다수의 클라우드가 그렇다)에서는 스마트호스트를 쓴다. 이때 두 가지가
반복해서 문제가 된다.

1. **릴레이가 `Message-ID`를 재작성하면 DKIM이 깨진다.** 서명 대상 헤더가 바뀌기 때문이다.
   서명이 **존재하는 것**과 **검증을 통과하는 것**은 다른 사실이다 — 리포트로 확인할 것.
2. **내부 홉은 SPF로 고칠 수 없다.** 노드 사이의 배달은 수신측이 보기에 사설 주소에서 온
   접속이라 SPF 평가 대상이 아니다. 수신측에서 `IONOSPHERE_TRUSTED_RELAYS`(CIDR 목록)로
   예외를 둔다. 목록 밖 주소는 그대로 SPF를 평가받는다.

## 6. 데이터베이스와 백업

SQLite(`node:sqlite` 내장) · PostgreSQL(`pg`) · MySQL(`mysql2`) · Cloudflare D1을 지원한다.
방언 분기는 `@ionosphere/db` 안에 봉인돼 있어 다른 패키지는 어느 DB인지 모른다.

- 마이그레이션은 기동 시 적용된다. **마이그레이션이 포함된 배포 전에는 백업할 것**
  (`scripts/backup.sh`).
- 여러 노드를 롤링으로 올릴 때 **한 대만 새 코드면 나머지가 새 스키마를 낡은 코드로 읽는다.**
  스키마를 바꾸는 배포는 전부 올릴 것.
- 낙관적 락은 `modseq_claims`가 맡는다. 한 논리 연산은 `db.batch()` 한 번으로 원자적이다.

## 7. 관측성

- **메트릭**: Prometheus 형식. **인증이 없다** — 바인딩으로 통제한다.
- **감사 로그**: `IONOSPHERE_AUDIT`로 켠다. 로컬 보관 + S3 전송(`IONOSPHERE_AUDIT_S3_*`)을 지원한다.
- **구조화 로그**: `IONOSPHERE_LOG_FORMAT=json`.

관측에서 반복되는 함정 하나: **"돌았는데 할 일이 없었다"와 "아예 안 돌았다"가 겉으로 같다**
(블롭 GC 같은 주기 작업). 주기 작업을 믿기 전에 실행 자체를 세는 지표가 있는지 볼 것.

## 8. 관리 — 세 표면이 같은 것을 본다

관리 기능은 **GUI(무상태) → API(HTTP 어댑터) → 명령 계층(`@ionosphere/admin-cmd`) → store/db**
네 층이다. CLI도 같은 명령을 부른다.

**관리 기능을 API나 CLI에 직접 붙이지 말 것.** `admin-cmd/registry.ts`에 명령을 하나 넣으면
REST 라우트·CLI 서브커맨드·GUI 탭이 동시에 생긴다. 한 표면에만 손으로 붙인 기능은 나머지
둘에서 빠지고, 그게 이 저장소에서 반복된 사고였다.

### 관리 콘솔 로그인 (사람 세션)

관리 콘솔은 **사람 로그인**만 받는다. 사용자명·비밀번호에 TOTP까지 확인하고, 세션은 HttpOnly 쿠키로 다닌다.
Bearer 토큰 입력 칸은 없앴다. API 키(`api-key-create`)는 REST 자동화 전용으로 남는다.
콘솔 관리자(`admin_users`)는 메일 계정과 별개다.

처음 한 번은 이렇게 한다.

1. `IONOSPHERE_MASTER_KEY`가 설정돼 있는지 확인한다. 없으면 TOTP를 등록할 수 없다(평문 저장을 거부한다).
2. 호스트에서 첫 운영자를 만든다:
   `node apps/server/src/cli.ts admin-user-create --username=ops@ionosphere.test --role=owner`
   비밀번호는 stdin이나 환경변수로 받는다(argv에 남기지 않는다). 출력에 **일회용 TOTP 등록 코드**가 한 번 나온다.
   그 코드는 본인에게만 따로 전달한다. 24시간 안에 한 번만 쓸 수 있다.
3. 콘솔에 로그인하면 TOTP 등록 화면이 뜬다. 등록 코드를 넣고 인증 앱에 비밀을 넣은 뒤 6자리로 확정한다.
   확정하기 전에는 다른 화면을 쓸 수 없다. 확정하면 **복구 코드 10개**가 한 번 보인다. 안전한 곳에 적어 둔다.
4. 첫 관리자를 만든 뒤에는 `IONOSPHERE_ADMIN_TOKEN`(rootToken)을 쓰지 않는다. 부트스트랩 탈출구였고,
   MFA를 거치지 않는 경로다(회원 정책 결정 D4).

계약은 다음과 같다.

- 상태를 바꾸는 요청은 Origin이 콘솔과 같아야 하고 CSRF 토큰이 맞아야 한다. 443 프론트가 원본 Host를
  그대로 넘기므로 기본으로는 설정할 것이 없다. 오리진을 정확히 못박으려면
  `IONOSPHERE_ADMIN_ORIGIN=https://admin.<도메인>`을 넣는다.
- 로그아웃, 관리자 정지, 역할 하향은 **다음 요청부터** 반영된다. 세션은 매 요청 DB에서 확인한다.
- 파괴적 명령(2단계 확인 버튼이 붙는 것)과 권한·자격증명을 새로 만드는 명령(API 키·앱 비밀번호·관리자 생성 등,
  명령 서술의 `sensitive`)은 최근 MFA를 요구한다. 시간이 지났으면 콘솔이 6자리를 다시 묻는다.
- TOTP를 연속으로 5번 틀리면 1분 잠긴다. 그 뒤로는 틀릴 때마다 두 배로 늘고, 최대 24시간이다. 이 단계는
  비밀번호가 맞아야 닿으므로, 남이 비밀번호 없이 잠글 수는 없다.
- 등록 코드가 없으면 TOTP 등록을 시작할 수 없다. 비밀번호를 아는 사람이 본인보다 먼저 MFA를 차지하지 못하게 하려는 장치다.
- 인증 앱을 잃으면 로그인 화면의 "복구 코드" 칸에 복구 코드 하나를 넣는다. 그러면 TOTP가 지워지고, 다른 세션이 끊기고,
  새 등록 코드가 화면에 채워진다. 그 자리에서 새 장치를 등록하면 복구 코드도 새로 발급된다. 쓴 코드는 다시 못 쓴다.
- 복구 코드까지 잃었으면 다른 운영자 owner가 `admin-user-mfa-reset`을 부른다(콘솔에서는 최근 MFA 재확인이 필요하다).
  호스트 CLI로도 할 수 있다. 어느 쪽이든 새 등록 코드가 한 번 나오고, 그것을 본인에게 따로 전달한다.
  이 경로는 공통 복구 정책이 아니라 ionosphere의 **보조 경로**다.
- 마지막 활성 운영자 owner는 정지하거나 강등할 수 없다.
- 세션 수명(idle 30분·절대 12시간), step-up 창(10분), TOTP 잠금, 등록 코드 유효 기간(24시간), 복구 코드 개수(10개)는
  **임시 기본값**이다. 서비스 공통 회원정책의 수치가 정해지면 바꾼다.
- 등록 코드·복구 코드·MFA 초기화를 사용자에게 **통지하는 채널은 없다**. 관리 API 감사 로그에만 남는다.
- 호스트 CLI는 MFA를 거치지 않는 **비상 경로**다(회원 정책 결정 D4). 그 대신 `IONOSPHERE_AUDIT=1`이면 실행마다
  감사 로그에 `surface: "cli"` 줄이 남는다. 서버와 같은 `IONOSPHERE_AUDIT_DIR`을 써야 같은 파일에 쌓이고 함께 이관된다.
  명령 이름, 결과, OS 사용자, 호스트는 남고 인자 값(비밀번호·토큰)은 남지 않는다. 감사가 꺼져 있으면 CLI도 남기지 않는다.
- `IONOSPHERE_ADMIN_TOKEN`(rootToken)은 부트스트랩 전용이다. 활성 운영자 owner가 생긴 뒤에도 설정돼 있으면 기동할 때 경고한다.
  쓰일 때마다 감사 줄에 `rootAfterBootstrap: 1`이 붙고, 경고는 분당 한 번 남는다. 지금은 거부하지 않는다 —
  이후 릴리즈에서 거부로 바꾼다. 첫 운영자를 만들었으면 이 변수를 지울 것.

### 메일 계정 셀프서비스 (E2)

메일 사용자가 웹에서 직접 비밀번호를 바꾸고 앱 비밀번호를 발급·철회하는 화면이다. 기본으로 꺼져 있다.

- 켜기: `IONOSPHERE_SELF_SERVICE_PORT`(평문 upstream, 기본 루프백) + `IONOSPHERE_HOST_ACCOUNT=account.<도메인>`.
  443 프론트가 그 이름을 **공개** 라우트로 받는다. 443 기본 인증서에 그 이름이 들어 있어야 한다.
  오리진을 못박으려면 `IONOSPHERE_SELF_SERVICE_ORIGIN=https://account.<도메인>`.
- 로그인은 메일 계정의 **기본 비밀번호만** 받는다. 앱 비밀번호·OAuth 토큰·디렉터리 bind로는 들어오지 못한다.
- TOTP를 등록하지 않은 사용자는 앱 비밀번호 목록만 볼 수 있다. 비밀번호 변경, 앱 비밀번호 발급·철회는 TOTP 등록 뒤
  최근 MFA 재확인(step-up)을 거쳐야 한다. 면제는 없다(회원 정책 D3).
- 첫 TOTP 등록에는 **일회용 등록 코드**가 필요하다. 테넌트 관리자가 `account-mfa-reset`으로 발급해 본인에게 따로 전달한다.
  같은 명령이 분실 복구의 보조 경로다(TOTP·복구 코드를 지우고 셀프서비스 세션을 끊는다). 메일 클라이언트는 영향이 없다.
- 사용자가 인증 앱을 잃으면 로그인 화면의 복구 코드 칸을 쓴다(관리 콘솔과 같은 방식).
- 시도 제한은 IMAP·SMTP와 **같은 계정 키**를 쓴다. 같은 기본 비밀번호를 맞히는 시도라 한도를 하나로 묶는다.
- 비밀번호를 바꾸면 셀프서비스 웹 세션은 끊기고, 앱 비밀번호와 열린 메일 연결은 그대로다.
- 새 비밀번호는 10자 이상이어야 한다. 동시 로그인은 8개까지 처리하고 넘치면 503을 돌려준다(공개 표면의 CPU 보호).
- 감사 로그 표면은 `selfservice`다. 세션 수명·step-up·잠금·최소 길이 수치는 관리 콘솔과 같은 **임시 기본값**이다.

### 외부 OIDC 로그인 (E3)

관리 콘솔과 셀프서비스에 "IdP로 로그인" 버튼을 얹는다. 기본으로 꺼져 있다.

- 설정: `IONOSPHERE_OIDC_PROVIDERS` JSON 배열. 원소는
  `{ "id", "realm": "admin"|"account", "issuer", "clientId", "clientSecret", "tenantId"?, "scopes"?, "mfaContract"? }`이다.
  `realm=account`는 `tenantId`가 필수다. 형식 오류·평문 issuer(루프백 제외)·중복 id는 기동 전에 실패한다.
- 콜백 주소는 **설정된 오리진**으로만 만든다. admin 공급자가 있으면 `IONOSPHERE_ADMIN_ORIGIN`, account 공급자가 있으면
  `IONOSPHERE_SELF_SERVICE_ORIGIN`이 필요하다. IdP에는 다음 주소를 redirect URI로 등록한다.
  - `<오리진>/admin/session/oidc/callback`
  - `<오리진>/account/session/oidc/callback`
- 연결은 관리자가 한다. 자동 연결·JIT는 없고, 이메일로 찾지 않는다. 키는 언제나 sub다.
  - 관리자: `admin-identity-link --admin=... --provider=<id> --subject=<sub>`
  - 메일 계정: `oidc-identity-link --account=... --provider=<id> --subject=<sub>`(그 공급자의 테넌트 안에서)
  - 처음 로그인을 시도했다 실패하면 감사 로그의 `oidcUnlinkedSub`에 sub가 남는다.
- **MFA 증거 계약**(`mfaContract`): `{ "acceptAcr"?: [...], "requireAmrAll"?: [...], "maxAgeSec": N }`.
  - 응답의 acr이 목록에 있거나 amr에 지정한 값이 모두 있고, `auth_time`이 N초 안이면 그 로그인을 MFA로 인정한다.
  - 요청한 값(acr_values·max_age)이 아니라 **응답의 클레임**으로만 판정한다.
  - 계약이 없거나 응답이 충족하지 못하면 로컬 TOTP를 묻는다(생략·폴백 없음).
  - ⚠ lodestar는 지금 ID 토큰에 amr이 없고 acr에 신뢰 기기가 섞여, TOTP 계약을 적을 수 없다. 계약 없이 쓰고 로컬 TOTP를 요구한다.
- 지원 제한: 민감 작업의 재확인(step-up)은 언제나 **로컬 TOTP**다(IdP 재인증 step-up은 없다). 그래서 관리 콘솔 관리자는
  IdP 계약을 충족해도 로컬 TOTP를 먼저 등록해야 한다. 셀프서비스는 미등록이면 목록만 볼 수 있다(D3).
- IdP에서 사용자를 정지해도 이미 열린 세션은 그대로다(IdP 철회 신호를 받지 않는다). 세션 수명 안에서 유지되고,
  ionosphere 쪽 정지·연결 해제·세션 종료는 다음 요청부터 반영된다.

### 메일 클라이언트의 외부 OAuth (E4)

IMAP·POP3·SMTP 제출·JMAP·ManageSieve에서 IdP가 발급한 **access token**(JWT)으로 로그인한다. 기본으로 꺼져 있다.

- account 영역 OIDC 공급자에 `"mailAccessToken": { "audience", "requiredScope", "surfaces"? }`를 더한다.
  - `audience`는 메일 전용 값이어야 하고 웹 로그인 `clientId`와 **달라야** 한다. 같으면 기동이 실패한다(ID 토큰 혼용 차단).
  - 토큰에는 `requiredScope`가 있어야 한다(`scope` 문자열 또는 `scp`).
- 계정은 셀프서비스와 같은 연결(`oidc-identity-link`)을 쓴다. 토큰의 email로 찾지 않는다. SASL이 말한 사용자가 연결된
  계정 주소와 같아야 한다.
- 순서는 로컬 자격증명(비밀번호·앱 비밀번호·자체 발급 토큰) → 외부 access token → 디렉터리다. IdP가 죽어도 로컬은 동작한다.
- 헤더 `typ`가 `at+jwt`(RFC 9068)여야 한다. 지키지 않는 IdP만 `"requireAtJwtTyp": false`로 끈다(그러면 ID 토큰 차단의 근거가 aud 하나뿐이다).
- 토큰 수명은 **5분까지만** 받는다(exp − iat와 exp − 지금 둘 다, 시계 오차 없이). `"maxLifetimeSec"`로 더 짧게만 바꿀 수 있다.
- `azp`(토큰을 요청한 메일 앱)는 보지 않는다 — access token에서는 aud와 다른 것이 정상이다.
- 낯선 kid로 JWKS를 다시 받는 것은 공급자당 60초에 한 번이다(위조 토큰으로 IdP 요청을 증폭하지 못하게).
- JWT 모양의 값은 실패해도 디렉터리(LDAP) bind로 넘기지 않는다.
- **토큰 만료 = 연결 종료**(2026-10-18 이 창 사용자 결정): 외부 토큰으로 연 IMAP·POP3·ManageSieve·SMTP 제출 연결과
  JMAP EventSource는 토큰 exp에 닫힌다. 명령이 없어도 닫는다(타이머). JMAP 인증 캐시도 exp를 넘지 않는다.
  계정 정지는 별개로, 열린 연결의 다음 명령에서 막힌다(G2).
- **제품 예외(E4 전용, 2026-10-18 사용자 결정 "수명 상한을 낮추고 예외로 수용")**: introspection이 없어 토큰 수명 안의
  철회는 반영되지 않는다. 그 지연은 **최대 5분**(수명 상한)이다. 이 예외는 ionosphere E4(메일 클라이언트 외부 토큰)에만
  해당하고, 공통 정책의 "다음 보호 요청부터 반영" 기준과 다른 서비스에는 적용하지 않는다. IdP가 쓸 만한 introspection·철회
  신호를 주게 되면 다시 검토한다.

## 9. 운영에서 반복해서 틀리는 것

- **리스너가 떠 있는 것과 닿는 것은 다른 사실이다.** 방화벽이 별도 계층이면 `ss`로 확인한
  바인딩은 도달성의 증거가 아니다.
- **아웃바운드 25 차단과 수신 25는 다른 방향이다.** 다른 노드에서 자기 MX의 25번을 프로브해
  실패했다면 대개 출발지의 아웃바운드가 막힌 것이다. 수신 확인은 그 노드 자신에서 하거나
  수신 이벤트 로그로 판정한다.
- **문서에 적힌 리비전·상태를 근거로 쓰지 말 것.** 배포된 것과 화면에서 동작하는 것은 다른
  사실이다. 운영 상태는 명령으로 확인한다.
- **없는 것과 못 읽은 것은 다르다.** 조회 실패를 미등록으로 단정해 오진한 적이 있다.
