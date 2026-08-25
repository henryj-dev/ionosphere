# ionosphere

TypeScript로 구현한 Node.js 올인원 메일 플랫폼입니다.

SMTP 수신부터 IMAP·POP3·JMAP 접근, SMTP 발송, Sieve 필터, 도메인·계정 관리까지 하나의 저장소와 서버 프로세스에서 제공합니다. 프로토콜별 핵심 동작은 순수 상태머신으로 분리하고, 네트워크 소켓·HTTP·데이터베이스는 얇은 어댑터가 담당합니다.

> 이 README는 소스 코드와 테스트에서 확인되는 동작을 설명합니다. 배포 환경의 실제 주소·자격증명·호스트별 절차는 이 저장소에 넣지 않습니다.

## 한눈에 보기

| 영역 | 제공 기능 |
| --- | --- |
| 메일 수신 | SMTP, LMTP, alias, catch-all, forwarding, Sieve |
| 메일 접근 | IMAP, IMAPS, POP3, POP3S, JMAP |
| 메일 발송 | 큐, 재시도, MX 직송, 스마트호스트, DSN, DKIM |
| 인증 | PLAIN, LOGIN, SCRAM-SHA-256, XOAUTH2, OAUTHBEARER |
| 메일 보안 | SPF, DKIM, DMARC, MTA-STS, DANE/TLSA, SRS |
| 관리 | REST API, CLI, 브라우저 관리 콘솔 |
| 저장소 | SQLite, PostgreSQL, MySQL, 로컬 블롭, S3 호환 저장소 |
| 운영 | 메트릭, 감사 로그, blob GC, retention/reaper, webhook, push |

## 요구 사항

- Node.js 24 이상
- npm
- 기본 구성에서는 별도의 DB 서버나 외부 npm 런타임 의존성이 필요하지 않음
- PostgreSQL 사용 시 `pg`, MySQL 사용 시 `mysql2`

패키지의 런타임 코드는 `node:` 내장 모듈을 사용합니다. 테스트와 타입체크를 위해 루트 개발 의존성이 설치됩니다.

## 빠른 시작

아래는 로컬 SQLite, 로컬 블롭, 자체서명 인증서를 사용하는 개발용 구성입니다. `example.com`은 문서용 예시 도메인입니다.

```bash
npm install

export IONOSPHERE_DB="$PWD/ionosphere.db"
export IONOSPHERE_BLOBS="$PWD/blobs"
export IONOSPHERE_MASTER_KEY="$(openssl rand -hex 32)"

IONOSPHERE_HOSTNAME=mail.example.com \
IONOSPHERE_TLS_MODE=selfsigned \
IONOSPHERE_TLS_DIR="$PWD/tls" \
IONOSPHERE_SMTP_STARTTLS=1 \
IONOSPHERE_SMTP_PORT=2525 \
node apps/server/src/main.ts
```

기본으로 열리는 포트는 개발용 비특권 포트입니다.

- SMTP: `2525`
- POP3: `1110`

IMAP, IMAPS, Submission, JMAP, ManageSieve, 관리 API 등은 해당 포트 환경변수를 지정했을 때만 시작됩니다.

## 관리 CLI

관리 CLI는 서버와 같은 DB 선택 규칙을 사용합니다.

```bash
export IONOSPHERE_DB="$PWD/ionosphere.db"
export IONOSPHERE_MASTER_KEY="$(openssl rand -hex 32)"

node apps/server/src/cli.ts help
node apps/server/src/cli.ts help domain-add
node apps/server/src/cli.ts domain-add example.com
node apps/server/src/cli.ts account-create alice@example.com 'change-this-password'
```

일반 형식:

```text
node apps/server/src/cli.ts <command> [--key=value ...]
node apps/server/src/cli.ts help
node apps/server/src/cli.ts help <command>
```

스마트호스트 비밀번호와 TLS private key는 argv 대신 stdin 또는 환경변수로 입력하는 것이 안전합니다.

```bash
export IONOSPHERE_CLI_SECRET='secret-value'
export IONOSPHERE_SMARTHOST_SECRET='relay-password'
```

### 명령 목록

도메인:

- `domain-list`, `domain-add`, `domain-verify`
- `domain-disable`, `domain-enable`, `domain-release`

계정·자격증명:

- `account-list`, `account-create`, `account-suspend`
- `account-activate`, `account-delete`
- `app-password-list`, `app-password-create`
- `oauth-token-list`, `oauth-token-create`, `credential-revoke`

라우팅:

- `alias-list`, `alias-add`, `alias-remove`

발송 운영:

- `queue-list`, `queue-retry`, `queue-cancel`
- `suppression-list`, `suppression-remove`, `usage`
- `smarthost-list`, `smarthost-set`, `smarthost-remove`

테넌트·API key·TLS:

- `tenant-list`, `tenant-create`
- `api-key-list`, `api-key-create`, `api-key-revoke`
- `tls-status`, `tls-refresh`, `tls-upload`

도메인은 REST 경로에서 소유권 TXT·MX·SPF 검증을 통과해야 사용할 수 있습니다. CLI는 로컬 운영 도구라는 전제 때문에 기본적으로 검증 완화 호환 동작을 사용하며, 필요하면 `--preVerified=false`를 지정할 수 있습니다.

계정 삭제는 되돌릴 수 없는 드레인 작업입니다. 잠시 사용을 막으려면 `account-suspend`를 사용합니다. 앱 비밀번호와 OAuth token의 평문은 생성 시 한 번만 출력됩니다.

alias는 로컬 계정 여러 개 또는 외부 주소로 라우팅할 수 있으며 localpart가 `*`이면 catch-all입니다. 외부 forwarding에는 SRS 비밀키가 필요합니다.

```bash
export IONOSPHERE_SRS_SECRET="$(openssl rand -hex 32)"
```

API key scope는 `read`, `write`, `admin`입니다. `read`는 조회, `write`는 조회와 변경, `admin`은 전권입니다.

## 저장소 구성

### 데이터베이스

```bash
# SQLite
IONOSPHERE_DB=./ionosphere.db

# PostgreSQL
IONOSPHERE_DB_URL=postgres://user:password@db.example.com:5432/ionosphere

# MySQL
IONOSPHERE_DB_URL=mysql://user:password@db.example.com:3306/ionosphere
```

`IONOSPHERE_DB_URL`이 있으면 `IONOSPHERE_DB`보다 우선합니다. SQLite는 단일 writer 구성에 적합하고, 여러 서버가 동시에 상태를 공유하려면 PostgreSQL 또는 MySQL을 사용해야 합니다.

DB 드라이버는 지연 로드되므로 SQLite만 사용할 때 `pg`와 `mysql2`를 설치할 필요가 없습니다.

### 메시지 본문 블롭

기본 저장소는 로컬 파일시스템입니다.

```bash
IONOSPHERE_BLOBS=./blobs
```

S3 호환 저장소:

```bash
IONOSPHERE_S3_ENDPOINT=https://s3.example.com
IONOSPHERE_S3_BUCKET=ionosphere-mail
IONOSPHERE_S3_ACCESS_KEY=access-key
IONOSPHERE_S3_SECRET_KEY=secret-key
IONOSPHERE_S3_REGION=us-east-1
IONOSPHERE_S3_PREFIX=mail/
IONOSPHERE_S3_PATH_STYLE=1
IONOSPHERE_S3_TIMEOUT_MS=30000
```

S3의 endpoint, bucket, access key, secret key는 모두 지정해야 합니다. 일부만 지정하면 서버가 시작하지 않습니다. 로컬 파일에서 S3로 이전할 때는 다음을 사용해 기존 파일을 읽기 폴백으로 유지할 수 있습니다.

```bash
IONOSPHERE_S3_MIGRATE_FROM_FS=1
```

### 비밀값 저장

운영 구성의 기본:

```bash
IONOSPHERE_MASTER_KEY=strong-random-master-key
```

master key는 DKIM private key와 스마트호스트 비밀번호 등 저장 비밀을 봉인합니다. 개발 환경에서만 다음으로 평문 저장을 명시적으로 허용할 수 있습니다.

```bash
IONOSPHERE_ALLOW_PLAINTEXT_SECRETS=1
```

이 경우 경고가 발생하고 일부 비밀값이 `plain$` 형식으로 저장됩니다.

## 리스너와 네트워크

| 서비스 | 환경변수 | 기본값 |
| --- | --- | --- |
| SMTP 수신 | `IONOSPHERE_SMTP_PORT` | `2525` |
| POP3 | `IONOSPHERE_POP3_PORT` | `1110` |
| IMAP | `IONOSPHERE_IMAP_PORT` | 없음 |
| IMAPS | `IONOSPHERE_IMAPS_PORT` | 없음 |
| POP3S | `IONOSPHERE_POP3S_PORT` | 없음 |
| LMTP | `IONOSPHERE_LMTP_PORT` | 없음 |
| Submission | `IONOSPHERE_SUBMISSION_PORT` | 없음 |
| SMTPS | `IONOSPHERE_SMTPS_PORT` | 없음 |
| ManageSieve | `IONOSPHERE_MANAGESIEVE_PORT` | 없음 |
| JMAP | `IONOSPHERE_JMAP_PORT` | 없음 |
| 관리 API | `IONOSPHERE_ADMIN_PORT` | 없음 |
| Autoconfig | `IONOSPHERE_AUTOCONFIG_PORT` | 없음 |
| HTTPS front | `IONOSPHERE_HTTPS_FRONT_PORT` | 없음 |
| HTTP redirect | `IONOSPHERE_HTTP_REDIRECT_PORT` | 없음 |
| Metrics | `IONOSPHERE_METRICS_PORT` | 없음 |

포트 값은 `0`부터 `65535`까지의 정수입니다. SMTP와 POP3의 직접 포트 설정에서는 `0`을 테스트용 임시 포트로 사용할 수 있습니다. 포트를 끄려면 `off`, `false`, `no`, `disabled`를 사용합니다.

바인딩 주소와 포트는 `IONOSPHERE_LISTEN_<SERVICE>`로 덮어쓸 수 있습니다.

```bash
IONOSPHERE_LISTEN_ADMIN=127.0.0.1:8080
IONOSPHERE_LISTEN_METRICS=10.0.0.10:9090
IONOSPHERE_LISTEN_IMAP=0.0.0.0:143
IONOSPHERE_LISTEN_IMAPS='[::]:993'
IONOSPHERE_LISTEN_SMTP=off
```

지원 형식은 `8080`, `0.0.0.0:8080`, `127.0.0.1:`, `[::]:8080`, `off`입니다. IPv6 주소는 대괄호로 감싸야 하며, 인식할 수 없는 주소나 숫자형 IP 표기는 시작 시 거부됩니다.

## TLS와 인증서

전체 기본 인증서 소스:

```bash
IONOSPHERE_TLS_MODE=none
IONOSPHERE_TLS_MODE=selfsigned
IONOSPHERE_TLS_MODE=file
IONOSPHERE_TLS_MODE=url
IONOSPHERE_TLS_MODE=acme
IONOSPHERE_TLS_DIR=/var/lib/ionosphere/tls
IONOSPHERE_TLS_CN=mail.example.com
IONOSPHERE_TLS_SANS=mail.example.com,imap.example.com
```

파일 인증서:

```bash
IONOSPHERE_TLS_MODE=file
IONOSPHERE_TLS_CERT=/etc/ionosphere/tls/fullchain.pem
IONOSPHERE_TLS_KEY=/etc/ionosphere/tls/privkey.pem
```

기존 IMAPS 호환 변수:

```bash
IONOSPHERE_IMAPS_TLS_CERT=/etc/ionosphere/tls/fullchain.pem
IONOSPHERE_IMAPS_TLS_KEY=/etc/ionosphere/tls/privkey.pem
```

원격 인증서:

```bash
IONOSPHERE_TLS_MODE=url
IONOSPHERE_TLS_URL_CERT=https://cert.example.com/mail/cert.pem
IONOSPHERE_TLS_URL_KEY=https://cert.example.com/mail/key.pem
IONOSPHERE_TLS_URL_AUTH='Bearer token'
```

ACME:

```bash
IONOSPHERE_TLS_MODE=acme
IONOSPHERE_TLS_ACME_DOMAINS=mail.example.com
IONOSPHERE_TLS_ACME_EMAIL=admin@example.com
IONOSPHERE_TLS_ACME_CHALLENGE=http-01
IONOSPHERE_TLS_ACME_HTTP_PORT=80
```

`http-01`이 기본이며 발급 시점에만 challenge listener가 열립니다. Cloudflare DNS-01은 다음처럼 사용합니다.

```bash
IONOSPHERE_TLS_ACME_CHALLENGE=dns-01
IONOSPHERE_CF_DNS_TOKEN=cloudflare-api-token
IONOSPHERE_CF_ZONE_ID=zone-id
IONOSPHERE_TLS_ACME_DNS_PROVIDER=cloudflare
```

ACME `http-01` 포트와 HTTP redirect 포트가 같으면 서버는 시작하지 않습니다.

리스너별 인증서는 `IONOSPHERE_TLS_<LISTENER>_` 접두어를 사용합니다.

```bash
IONOSPHERE_TLS_SMTP_MODE=file
IONOSPHERE_TLS_SMTP_CERT=/etc/ionosphere/tls/smtp-cert.pem
IONOSPHERE_TLS_SMTP_KEY=/etc/ionosphere/tls/smtp-key.pem
IONOSPHERE_TLS_SMTP_CN=mx.example.com
```

지원 listener 이름은 `SMTP`, `SUBMISSION`, `SMTPS`, `IMAP`, `IMAPS`, `POP3`, `POP3S`, `MANAGESIEVE`, `HTTPS_FRONT`, `ADMIN_TLS`입니다.

## HTTP, JMAP, Autoconfig

JMAP:

```bash
IONOSPHERE_JMAP_PORT=8080
IONOSPHERE_JMAP_BASE_URL=https://mail.example.com
```

주요 경로:

```text
GET  /jmap/session
POST /jmap/api
POST /jmap/upload
GET  /jmap/download/<account>/<blob>
GET  /jmap/eventsource
```

Mailbox, Email, Email/query, EmailSubmission, Quota, VacationResponse, PushSubscription, SearchSnippet을 포함합니다. 요청 본문은 약 10 MB, 업로드 한 건은 50,000,000 bytes, SSE 연결은 256개, 인증 캐시는 10,000개로 제한됩니다.

자동설정:

```bash
IONOSPHERE_AUTOCONFIG_PORT=8081
IONOSPHERE_AUTOCONFIG_BRAND=Example Mail
IONOSPHERE_IMAP_HOST=imap.example.com
IONOSPHERE_SUBMISSION_HOST=smtp.example.com
IONOSPHERE_POP3_HOST=pop3.example.com
```

POP3 호스트는 포트를 열었다는 이유만으로 자동설정에 광고되지 않습니다. `IONOSPHERE_POP3_HOST`를 별도로 지정해야 합니다.

HTTPS front와 호스트 화이트리스트:

```bash
IONOSPHERE_HTTPS_FRONT_PORT=443
IONOSPHERE_HTTP_REDIRECT_PORT=80
IONOSPHERE_HOST_MTA_STS=mta-sts.example.com
IONOSPHERE_HOST_ADMIN=admin.example.com
IONOSPHERE_HOST_METRICS=metrics.example.com
```

서비스별 호스트는 콤마로 구분합니다. 화이트리스트에 없는 Host는 라우팅되지 않습니다. 미지정 서비스는 기본적으로 해당 서비스의 localhost 이름만 허용합니다. 관리 콘솔은 이름뿐 아니라 내부 노출 정책도 적용합니다.

## 관리 REST API

관리 API는 `IONOSPHERE_ADMIN_PORT`를 지정했을 때 시작합니다.

```bash
IONOSPHERE_ADMIN_PORT=8080
IONOSPHERE_ADMIN_TOKEN=bootstrap-root-token
```

요청 인증:

```http
Authorization: Bearer <api-key-or-root-token>
```

기능 영역:

```text
/v1/tenants
/v1/accounts
/v1/domains
/v1/aliases
/v1/api-keys
/v1/app-passwords
/v1/oauth-tokens
/v1/credentials
/v1/queue
/v1/suppressions
/v1/usage
/v1/smarthosts
/v1/tls
```

GET은 `read`, 그 외 method는 `write`가 필요합니다. `admin` scope와 root token은 전권입니다. root token은 bootstrap 용도이며 자동 회전 기능은 없습니다.

## 스마트호스트와 발송

```bash
IONOSPHERE_SMARTHOST=smtp.example.com
IONOSPHERE_SMARTHOST_PORT=587
IONOSPHERE_SMARTHOST_USER=relay-user
IONOSPHERE_SMARTHOST_PASS=relay-password
IONOSPHERE_SMARTHOST_TLS=required
```

TLS 모드는 `required`, `opportunistic`, `implicit`, `never`입니다. 587은 STARTTLS, 465는 implicit TLS로 사용하는 구성이 기준입니다.

발송 제한:

```bash
IONOSPHERE_RATE_PER_MINUTE=...
IONOSPHERE_RATE_PER_HOUR=...
IONOSPHERE_RATE_PER_DAY=...
IONOSPHERE_RELAY_PER_HOUR=...
IONOSPHERE_LOCAL_ONLY=1
IONOSPHERE_REQUIRE_SENDER_OWNERSHIP=0
```

`LOCAL_ONLY=1`은 외부 도메인 발송을 막지만 실제 스마트호스트 경로가 있으면 예외가 생길 수 있습니다. 발신자 소유권 검사는 기본 활성입니다.

## 메일 보안 정책

TLS 자료가 없거나 STARTTLS를 실제로 수행할 수 없는 표면에서는 평문 인증이 기본적으로 차단됩니다. 지원 인증 방식은 표면에 따라 다르지만 PLAIN, LOGIN, SCRAM-SHA-256, XOAUTH2, OAUTHBEARER가 구현되어 있습니다.

### SPF, DKIM, DMARC

수신 경로에서 SPF·DKIM·DMARC 결과를 평가하고 저장하며, 발송 경로에서는 DKIM 서명을 적용할 수 있습니다. 도메인 등록 시 DKIM 키와 DNS 레코드 안내가 생성됩니다.

### MTA-STS와 DANE

```bash
IONOSPHERE_MTA_STS_MODE=enforce
IONOSPHERE_MTA_STS_ENFORCE=1
IONOSPHERE_MX_HOST=mx.example.com
IONOSPHERE_DANE=1
```

MTA-STS 모드는 `enforce`, `testing`, `none`입니다. DANE를 켜면 DNSSEC로 검증된 TLSA 결과를 발송 TLS 연결에 사용할 수 있습니다. MTA-STS enforce는 MX, HTTPS front, Host whitelist가 모두 맞아야 합니다.

### SRS

```bash
IONOSPHERE_SRS_SECRET=strong-random-secret
```

외부 forwarding과 forwarding bounce reverse 경로를 활성화합니다. 값이 없거나 비어 있으면 활성화되지 않습니다.

## 스팸·남용·억제

코드에는 greylisting, SPF pass 발신자 면제, DNSBL 연동 지점, 계정별 Bayes 학습, bounce/complaint 감시, 자동 계정 정지, suppression 목록이 있습니다.

abuse 판정 기본값:

- 관찰 창: 24시간
- 최소 표본: 20건
- bounce rate: 10% 초과
- complaint rate: 0.3% 초과

## 주요 하드 리밋

| 항목 | 값 |
| --- | ---: |
| 최대 메시지 | 25 MiB |
| SMTP/LMTP 세션당 RCPT | 1000 |
| SMTP 세션당 오류 | 20 |
| listener 최대 연결 | 1024 |
| Received hop | 30 |
| SMTP/LMTP/POP3 명령 라인 | 4096 bytes |
| 헤더 전체 | 1 MiB |
| 헤더 한 줄 | 64 KiB |
| IMAP 라인 | 64 KiB |
| pending pipeline | 1 MiB |
| 인증 전 IMAP literal | 8 KiB |
| IMAP queued line | 1 MiB |
| MIME depth | 20 |
| MIME part 수 | 1024 |
| thread reference 수 | 64 |
| 헤더별 주소 수 | 256 |
| JMAP upload | 50,000,000 bytes |

이 값들은 환경변수로 바꾸는 설정값이 아니라 코드에서 보호하는 안전 상한입니다.

## 백그라운드 작업과 보존

```bash
IONOSPHERE_RUN_MTA_WORKER=1
IONOSPHERE_RUN_WEBHOOK_WORKER=1
IONOSPHERE_RUN_REAPER=1
```

MTA worker는 Submission이 켜져 있으면 기본 활성이고, webhook worker와 reaper는 기본 활성입니다.

블롭 GC:

```bash
IONOSPHERE_BLOB_GC=off
IONOSPHERE_BLOB_GC=mark
IONOSPHERE_BLOB_GC=sweep
IONOSPHERE_BLOB_GC_GRACE_MS=...
IONOSPHERE_BLOB_UPLOAD_TTL_MS=...
```

기본 GC 모드는 `mark`입니다. `sweep`은 실제 파일 삭제를 수행할 수 있습니다.

스토어 retention의 코드 기본값은 change log 30일, thread reference 180일, 완료·실패 큐 7일입니다.

## 감사 로그

```bash
IONOSPHERE_AUDIT=1
IONOSPHERE_AUDIT_DIR=/var/lib/ionosphere/audit
IONOSPHERE_AUDIT_FLUSH_MS=1000
IONOSPHERE_AUDIT_SHIP_INTERVAL_MS=60000
IONOSPHERE_AUDIT_LOCAL_RETAIN_DAYS=30
IONOSPHERE_AUDIT_SHIP_HOST=server-1
```

S3 이관:

```bash
IONOSPHERE_AUDIT_S3_ENDPOINT=https://audit-s3.example.com
IONOSPHERE_AUDIT_S3_BUCKET=ionosphere-audit
IONOSPHERE_AUDIT_S3_ACCESS_KEY=audit-access-key
IONOSPHERE_AUDIT_S3_SECRET_KEY=audit-secret-key
IONOSPHERE_AUDIT_S3_REGION=us-east-1
IONOSPHERE_AUDIT_S3_PREFIX=audit/
IONOSPHERE_AUDIT_S3_PATH_STYLE=1
```

감사 S3 설정이 일부만 있으면 서버는 시작하지 않습니다. 메일 블롭 버킷과 감사 버킷은 별도로 운영해야 합니다.

## 환경변수 요약

서버·CLI에서 참조되는 환경변수는 다음 범주로 나뉩니다.

### 기본·DB·저장소

```text
IONOSPHERE_HOSTNAME
IONOSPHERE_DB
IONOSPHERE_DB_URL
IONOSPHERE_BLOBS
IONOSPHERE_MASTER_KEY
IONOSPHERE_ALLOW_PLAINTEXT_SECRETS
IONOSPHERE_S3_ENDPOINT
IONOSPHERE_S3_BUCKET
IONOSPHERE_S3_ACCESS_KEY
IONOSPHERE_S3_SECRET_KEY
IONOSPHERE_S3_REGION
IONOSPHERE_S3_PREFIX
IONOSPHERE_S3_PATH_STYLE
IONOSPHERE_S3_TIMEOUT_MS
IONOSPHERE_S3_MIGRATE_FROM_FS
```

### 포트·바인딩

```text
IONOSPHERE_SMTP_PORT
IONOSPHERE_SUBMISSION_PORT
IONOSPHERE_SMTPS_PORT
IONOSPHERE_POP3_PORT
IONOSPHERE_POP3S_PORT
IONOSPHERE_IMAP_PORT
IONOSPHERE_IMAPS_PORT
IONOSPHERE_LMTP_PORT
IONOSPHERE_MANAGESIEVE_PORT
IONOSPHERE_JMAP_PORT
IONOSPHERE_ADMIN_PORT
IONOSPHERE_AUTOCONFIG_PORT
IONOSPHERE_HTTPS_FRONT_PORT
IONOSPHERE_HTTP_REDIRECT_PORT
IONOSPHERE_METRICS_PORT
IONOSPHERE_METRICS_HOST
IONOSPHERE_LISTEN_<SERVICE>
```

### TLS·ACME

```text
IONOSPHERE_TLS_MODE
IONOSPHERE_TLS_DIR
IONOSPHERE_TLS_CN
IONOSPHERE_TLS_SANS
IONOSPHERE_TLS_CERT
IONOSPHERE_TLS_KEY
IONOSPHERE_TLS_URL_CERT
IONOSPHERE_TLS_URL_KEY
IONOSPHERE_TLS_URL_AUTH
IONOSPHERE_TLS_ACME_DOMAINS
IONOSPHERE_TLS_ACME_EMAIL
IONOSPHERE_TLS_ACME_DIRECTORY
IONOSPHERE_TLS_ACME_CHALLENGE
IONOSPHERE_TLS_ACME_HTTP_PORT
IONOSPHERE_TLS_ACME_DNS_PROVIDER
IONOSPHERE_TLS_<LISTENER>_MODE
IONOSPHERE_TLS_<LISTENER>_CN
IONOSPHERE_TLS_<LISTENER>_SANS
IONOSPHERE_TLS_<LISTENER>_CERT
IONOSPHERE_TLS_<LISTENER>_KEY
IONOSPHERE_TLS_<LISTENER>_URL_CERT
IONOSPHERE_TLS_<LISTENER>_URL_KEY
IONOSPHERE_CF_DNS_TOKEN
IONOSPHERE_CF_ZONE_ID
```

### 정책·발송·서비스 호스트

```text
IONOSPHERE_HOST_<SERVICE>
IONOSPHERE_IMAP_HOST
IONOSPHERE_SUBMISSION_HOST
IONOSPHERE_POP3_HOST
IONOSPHERE_MX_HOST
IONOSPHERE_AUTOCONFIG_BRAND
IONOSPHERE_JMAP_BASE_URL
IONOSPHERE_ADMIN_TOKEN
IONOSPHERE_SMARTHOST
IONOSPHERE_SMARTHOST_PORT
IONOSPHERE_SMARTHOST_USER
IONOSPHERE_SMARTHOST_PASS
IONOSPHERE_SMARTHOST_TLS
IONOSPHERE_SMARTHOST_SECRET
IONOSPHERE_RATE_PER_MINUTE
IONOSPHERE_RATE_PER_HOUR
IONOSPHERE_RATE_PER_DAY
IONOSPHERE_RELAY_PER_HOUR
IONOSPHERE_LOCAL_ONLY
IONOSPHERE_REQUIRE_SENDER_OWNERSHIP
IONOSPHERE_SRS_SECRET
IONOSPHERE_MTA_STS_MODE
IONOSPHERE_MTA_STS_ENFORCE
IONOSPHERE_DANE
IONOSPHERE_SMTP_STARTTLS
IONOSPHERE_RECURSIVE_DNS
```

### 워커·GC·감사·로그

```text
IONOSPHERE_RUN_MTA_WORKER
IONOSPHERE_RUN_WEBHOOK_WORKER
IONOSPHERE_RUN_REAPER
IONOSPHERE_BLOB_GC
IONOSPHERE_BLOB_GC_GRACE_MS
IONOSPHERE_BLOB_UPLOAD_TTL_MS
IONOSPHERE_AUDIT
IONOSPHERE_AUDIT_DIR
IONOSPHERE_AUDIT_FLUSH_MS
IONOSPHERE_AUDIT_SHIP_INTERVAL_MS
IONOSPHERE_AUDIT_LOCAL_RETAIN_DAYS
IONOSPHERE_AUDIT_SHIP_HOST
IONOSPHERE_AUDIT_S3_ENDPOINT
IONOSPHERE_AUDIT_S3_BUCKET
IONOSPHERE_AUDIT_S3_ACCESS_KEY
IONOSPHERE_AUDIT_S3_SECRET_KEY
IONOSPHERE_AUDIT_S3_REGION
IONOSPHERE_AUDIT_S3_PREFIX
IONOSPHERE_AUDIT_S3_PATH_STYLE
IONOSPHERE_LOG_LEVEL
IONOSPHERE_LOG_FORMAT
```

## 개발과 검증

```bash
npm run lint
npm run typecheck
npm test
npm run smoke
npm run verify
```

`npm run verify`는 lint, typecheck, 전체 테스트, smoke를 순서대로 실행합니다.

주요 패키지:

```text
apps/server/             실행 가능한 메일 서버·CLI
packages/core/           공통 한도·인증·로깅·보안 유틸리티
packages/db/             SQLite/PostgreSQL/MySQL 추상화와 migration
packages/store/          계정·메일박스·메시지·블롭 저장소
packages/proto-*/        프로토콜 상태머신과 소켓 어댑터
packages/mta/            큐·SMTP client·발송 worker
packages/admin-cmd/      CLI·REST·GUI가 공유하는 관리 명령
packages/api/            관리 HTTP API
packages/tls/            인증서·ACME·TLS 자료 관리
packages/dns/            DNS wire·resolver·DNSSEC
packages/mail-auth/      SPF·DKIM·DMARC 관련 기능
packages/spam/           greylist·Bayes·스팸 연동
packages/webhook/        webhook worker와 저장소
scripts/                 검증·migration·보조 운영 스크립트
```

프로토콜 엔진은 네트워크 I/O 없이 테스트할 수 있도록 `engine.ts`에 상태 전이를 두고, 실제 연결은 `server.ts`가 처리합니다.

## 운영 체크리스트

1. 모든 서버와 CLI에 동일한 `IONOSPHERE_MASTER_KEY`가 설정되어 있는지 확인합니다.
2. 여러 서버가 같은 DB를 사용할 경우 메일 본문도 공용 S3로 둡니다.
3. 관리 API와 root/API key가 외부에 불필요하게 노출되지 않는지 확인합니다.
4. ACME `http-01`과 HTTP redirect가 같은 포트를 사용하지 않는지 확인합니다.
5. MTA-STS `enforce` 전에 MX, HTTPS front, Host whitelist를 맞춥니다.
6. 외부 forwarding을 사용하면 `IONOSPHERE_SRS_SECRET`이 비어 있지 않은지 확인합니다.
7. `IONOSPHERE_BLOB_GC=sweep` 전 mark 결과와 fallback read 상태를 확인합니다.
8. 감사 로그 S3는 메일 블롭과 다른 버킷·권한으로 운영합니다.
9. CLI의 일반 비밀번호를 argv로 넣으면 shell history에 남을 수 있습니다.
10. 시작 실패를 무시하지 말고 포트·TLS·S3·master key 설정 오류를 먼저 해결합니다.

## 라이선스

[MIT](LICENSE)
