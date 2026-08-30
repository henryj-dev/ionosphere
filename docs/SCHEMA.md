# 스토어 스키마 v2.1

> 상태: **동결** (v1 → 이중 리뷰 → v2 → 이중 재검증 → v2.1) · 전제: [PLAN.md](../PLAN.md) + [PROTOCOLS.md](PROTOCOLS.md) §0
>
> **적용된 마이그레이션(2026-08-30 기준 022까지)** — 정본은 `packages/db/src/migrations/`다.
> 코어 DDL은 001이고, 그 뒤는 아래 절에 따로 적었다:
>
> | # | 이름 | 어디에 |
> |---|---|---|
> | 001 | init | §4~§9 코어 DDL |
> | 002 | webhooks | §9-2 (`webhook_endpoints`·`webhook_deliveries`) |
> | 003 | forwarding | §9-1 재빌드 — `mta_queue.account_id` nullable(시스템 발송) |
> | 004 | blob_gc | §9-5 (+ 기존 큐 행의 `blob_refs` 백필) |
> | 005 | maildrop_lock | §7-5 `maildrop_locks`(인프로세스 잠금 → DB 잠금, 멀티 인스턴스 전제) |
> | 006 | address_fanout | §4 `address_targets`(주소 1개 → 계정 N개) + `addresses` 재빌드 |
> | 007 | smarthosts | §9-4b |
> | 008 | suppression_expiry | §9-2b |
> | 009 | complaints | **§9-2c** |
> | 010 | bayes_tokens | **§9-2d** |
> | 011 | queue_indexes | §9-4 |
> | 012 | dsn_delay_notice | §9-4 |
> | 013 | vacation | §9-2 |
> | 014 | expunged_floor | §6-3 |
> | 015 | vacation_response | §9-2 |
> | 016 | dsn_params | §9-4 |
> | 017 | reporting | §9-4 |
> | 018 | push_subscriptions | §9-2 |
> | 019 | identity_state | §4 |
> | 020 | mailbox_acl | **§4-1** |
> | 021 | directory_identity | **§4-2** |
> | 022 | header_projection | **§5-4** |
> | 023 | listing_indexes | **§5-5** |
>
> ⚠ 새 마이그레이션을 넣으면 **이 표와 해당 절을 같이 갱신할 것.** 009·010이 한동안 코드에만
> 있고 이 문서에 없었다 — "동결 스키마"를 자처하는 문서가 실제 테이블을 빠뜨리면, 그것을 읽고
> 설계하는 다음 사람이 없는 것으로 안다.
>
> 대상 백엔드: SQLite / PG / MySQL(MariaDB) / Cloudflare D1 — 보수적 공통 SQL 부분집합
>
> v1 대비 주요 변경: 동시성 잠금을 `modseq_claims` 전용 테이블로 분리(C1), change_log를 JMAP 시맨틱 전용으로
> 하고 QRESYNC 툼스톤을 `expunged`로 분리(C2/C3), modseq 물질화(`messages.modseq`), 블롭 2단계 GC,
> `\Deleted` per-membership 저장, UIDVALIDITY 재사용 방지, 벌크 작업 프로토콜, JMAP 제출 객체 추가

## 1. 설계 제약과 정책

1. **단일 원자 배치만** — 인터랙티브 트랜잭션 금지. 배치는 **에러 시에만** 전체 롤백
   (제약 위반 포함 — D1 `/raw` `{batch:[...]}`에서 UNIQUE 위반 시 전체 롤백 실측 확정, d1-jdbc DESIGN §9-2).
2. **RETURNING 금지** → 모든 id·UID·modseq는 앱이 사전 계산, 배치는 클라이언트에서 완전 조립.
3. **한도** (D1 최소 공통분모): 파라미터 100/문장 · 배치 1,000문장 · SQL 100KB(**문장당** —
   공식 문서 확정. 배치 요청 바디 총량 상한은 **미문서** → 코어 배치를 작게 유지하고
   search_index 등 대량 삽입은 후속 배치로 분리하는 §7 규율이 이 리스크도 흡수).
   다중행 INSERT 청크 수학은 §7-6.
4. **FK 제약 없음 (정책)** — 배치 문장 순서 자유도와 백엔드 편차 회피를 위해 의도적으로 미사용.
   참조 무결성은 레시피(§7)가 계약으로 보장하고, 고아 행은 지정된 스위퍼가 수거.
5. **승인된 다이얼렉트 분기는 upsert 하나** — "INSERT 없으면 무시"가 필요한 자리(§7에 명시된 곳만):
   SQLite/D1 `INSERT OR IGNORE` / MySQL `INSERT IGNORE` / PG `ON CONFLICT DO NOTHING`.
   그 외 SQL은 공통 부분집합만.
6. JSON 컬럼 금지. 블롭(원본)은 DB 밖 (FS/S3).

## 2. 규약

| 항목 | 규약 |
|---|---|
| 객체 id | 앱 생성 ULID `VARCHAR(26)`. JMAP id·IMAP OBJECTID로 그대로 노출. CHAR(26)은 PG bpchar 공백 패딩이 `''` 센티널(parent_id 등)을 깨뜨려 배제 — v2.1 구현 중 확정 |
| 해시 | sha256. 블롭 id는 hex 64자. 내부 매칭용(msgid_hash, ref_hash, key_hash)은 **hex 32자 절단**(128bit, 충돌 무시 가능) |
| IMAP UID / modseq | `BIGINT`. **2^53 미만 유지** (D1 wire가 JS number — 실질 위반 불가능하지만 명문화) |
| 시각 | `BIGINT` epoch millis. UIDVALIDITY만 epoch초(2^32 미만 wire 제약) |
| 불리언 | `SMALLINT` 0/1 |
| 주소류 | `VARCHAR(255)` (RFC 최장 254 수용). 정규화 소문자를 앱이 보장 — DB 콜레이션 불신 |
| MySQL 다이얼렉트 | 문자열 `utf8mb4_bin`(대소문자 구분을 타 백엔드와 일치), id/해시 컬럼은 `CHARACTER SET ascii`(인덱스 키 4배 절약). DDL 생성기가 처리 |
| 테넌시 | 모든 테이블에 `tenant_id` 또는 `account_id` 스코프. 예외는 `blobs`(§9-5)와 전역 인프라 테이블 |

## 3. 동시성 모델 v2

### 3-1. 2계층 구조

- **1차: 인프로세스 계정별 라이터 큐** — v1 배포는 단일 프로세스(PLAN §4)이므로 계정별
  비동기 뮤텍스 + 쓰기 코얼레싱(호환 가능한 대기 작업을 한 배치로 합침)이 기본 직렬화 수단.
  DB 왕복 재시도가 일상 경로에서 사라짐. D1처럼 왕복이 비싼 백엔드에서 특히 중요
  (스냅샷+배치 ≥2 RTT ≈ 계정당 수 회/초가 물리 한계 — 큐잉·코얼레싱으로 흡수).
  - **코얼레싱 실패 격리**: 합쳐진 배치가 제약 위반으로 롤백되면 **디코얼레스 후 개별 재시도** —
    무고한 동승 작업이 남의 위반으로 실패 확정되는 것 금지.
  - **백그라운드 잡(리퍼·MTA 파이널라이즈 등)도 계정 스코프 쓰기는 라이터 큐 경유** 의무.
    유일한 문서화된 예외: 검색 고아 스위퍼 (ULID 비재사용이라 고아는 영원히 고아 — 무클레임 안전).
- **2차: DB 레벨 낙관 잠금 = 교차 노드 안전망** — 미래 멀티 노드나 외부 프로세스(관리 CLI 등)가
  같은 DB를 쓸 때의 정합성 보루.

### 3-2. modseq_claims — 진짜 잠금

v1의 결함: change_log PK에 entity·object_id가 포함돼 **서로 다른 객체를 건드리는 두 배치가
같은 modseq로 동시 커밋 가능**했음 (JMAP 델타 유실·쿼터 우회). v2는 잠금을 전용 테이블로 분리:

```sql
CREATE TABLE modseq_claims (
  account_id  VARCHAR(26) NOT NULL,
  modseq      BIGINT   NOT NULL,
  PRIMARY KEY (account_id, modseq)
);
```

**규칙: 계정 스코프 쓰기 배치의 첫 문장은 반드시 `INSERT INTO modseq_claims (?, M+1)`.**
동시 쓰기가 선점했으면 PK 충돌 → 에러 → 전체 롤백 → 재시도. 이로써 §7의 모든 무가드
절대값 쓰기(`SET uidnext=…`)와 스냅샷 기반 쿼터 검사가 안전해짐.

### 3-3. 쓰기 절차

```
1. (라이터 큐 안에서) 스냅샷: accounts.modseq=M, 대상 mailbox.uidnext, 쿼터, 메일함 존재 여부
2. 배치 조립: 첫 문장 modseq_claims(M+1), 이후 모든 값 명시적
3. 실행. 제약 위반 에러 → 전체 롤백:
   - modseq_claims PK: 다른 라이터 선점
   - message_mailbox (mailbox_id, uid) PK: UID 경합
4. 재시도: 지터 백오프, 상한 N회. 재시도 시 스냅샷 전체 재수행 — 카운터만이 아니라
   **모든 전제조건(쿼터·메일함 존재·권한) 재검증**
5. 상한 도달: LMTP는 4xx tempfail(프로토콜 합법 백프레셔), IMAP/JMAP은 서버 오류 응답
```

- 한 배치 = 한 modseq. 코얼레싱된 배치도 modseq 하나(스펙 합법).
- 카운터는 상대 증분(`SET x=x+1`)이라 가드 불필요.
- modseq_claims는 change_log와 함께 GC (잠금 이력은 보존 불요, floor만 갱신 — §6-3).
- SQLite는 전역 단일 라이터임을 문서화 (계정 간에도 직렬화됨 — 소형 배포 전제).

**전역 불변식 (모든 클레임 배치의 의무 — 레시피가 생략 표기해도 항상 포함):**
1. 첫 문장 = `INSERT modseq_claims (acct, M+1)`
2. `UPDATE accounts SET modseq=M+1` + **change_log를 쓴 모든 entity의 `state_*=M+1`**
   (이거 빠지면 다음 스냅샷이 같은 M을 읽어 영구 클레임 충돌 라이브락)
3. change_log 행을 쓴 메일함마다 `highestmodseq=M+1`
§7 레시피는 이 불변식을 전제로 차이점만 기술한다.

## 4. DDL — 테넌시/신원

```sql
CREATE TABLE tenants (
  id            VARCHAR(26) PRIMARY KEY,
  name          VARCHAR(190) NOT NULL,
  status        SMALLINT NOT NULL DEFAULT 1,
  created_at    BIGINT NOT NULL
);

CREATE TABLE domains (
  id            VARCHAR(26) PRIMARY KEY,
  tenant_id     VARCHAR(26) NOT NULL,
  name          VARCHAR(255) NOT NULL,              -- A-label 정규화 소문자
  name_utf8     TEXT,
  status        SMALLINT NOT NULL DEFAULT 0,        -- 0 unverified / 1 active / 2 disabled
  verify_token  VARCHAR(64),
  claimed_at    BIGINT NOT NULL,                    -- unverified 만료 기준 (스쿼팅 방지)
  created_at    BIGINT NOT NULL
);
CREATE INDEX ix_domains_name ON domains(name);
-- unverified 클레임은 만료(claimed_at + TTL) 후 스위퍼가 정리 → 스쿼팅 차단.
-- "active name 유일성"은 앱 검사가 아니라 앵커 테이블이 강제 (테넌트 스코프 쓰기는
-- modseq_claims 밖이므로 check-then-act 금지 — 동시 교차 테넌트 활성화 차단):

CREATE TABLE domain_name_claims (
  name          VARCHAR(255) PRIMARY KEY,           -- 정규화 소문자
  domain_id     VARCHAR(26) NOT NULL
);
-- activate 배치가 INSERT (PK 충돌 → 패자 전체 롤백 — §3-2와 동일 메커니즘).
-- deactivate/만료 스위퍼가 DELETE. 인바운드 라우팅은 이 테이블 경유가 정본.

CREATE TABLE accounts (
  id                VARCHAR(26) PRIMARY KEY,           -- = JMAP accountId
  tenant_id         VARCHAR(26) NOT NULL,
  email             VARCHAR(255) NOT NULL,
  display_name      TEXT,
  kind              SMALLINT NOT NULL DEFAULT 0,    -- 0 user / 1 shared(v2) / 2 system
  status            SMALLINT NOT NULL DEFAULT 1,    -- 1 active / 0 suspended / 2 deleting
  modseq            BIGINT NOT NULL DEFAULT 0,      -- 현재값 캐시 (스냅샷용)
  changelog_floor   BIGINT NOT NULL DEFAULT 0,      -- GC가 지운 최고 modseq (§6-3)
  uidvalidity_last  BIGINT NOT NULL DEFAULT 0,      -- UIDVALIDITY 재사용 방지 카운터 (§5-1)
  quota_bytes       BIGINT NOT NULL DEFAULT 0,
  used_bytes        BIGINT NOT NULL DEFAULT 0,
  message_count     BIGINT NOT NULL DEFAULT 0,
  -- JMAP state 고수위 (max() 조회 금지 — GC 후 역행 방지, §6-3)
  state_email       BIGINT NOT NULL DEFAULT 0,
  state_mailbox     BIGINT NOT NULL DEFAULT 0,
  state_thread      BIGINT NOT NULL DEFAULT 0,
  state_submission  BIGINT NOT NULL DEFAULT 0,
  state_sieve       BIGINT NOT NULL DEFAULT 0,      -- Phase 4 (RFC 9661 SieveScript/changes) 예약
  permissions_version BIGINT NOT NULL DEFAULT 0,    -- 공유 메일함 권한 캐시 무효화 세대 (020)
  created_at        BIGINT NOT NULL
);
CREATE UNIQUE INDEX ux_accounts_email ON accounts(email);
CREATE INDEX ix_accounts_tenant ON accounts(tenant_id);

CREATE TABLE addresses (
  id            VARCHAR(26) PRIMARY KEY,
  tenant_id     VARCHAR(26) NOT NULL,
  domain_id     VARCHAR(26) NOT NULL,
  localpart     VARCHAR(255) NOT NULL,              -- 정규화 소문자. '*' = 캐치올
  forward_to    TEXT,                               -- 외부 릴레이 대상(콤마/공백 구분 다중)
  created_at    BIGINT NOT NULL
);
CREATE UNIQUE INDEX ux_addresses_route ON addresses(domain_id, localpart);
-- 라우팅: 정확 매치 → 캐치올('*') 순. detail(+tag) 제거는 앱 레이어.
-- 리터럴 로컬파트 "*"@domain(RFC 합법·실사용 전무)은 수신 거부로 문서화 — 센티널 충돌 제거

-- 006: 로컬 목적지의 **유일한** 원천. 주소 1개 → 계정 N개(팬아웃).
CREATE TABLE address_targets (
  address_id    VARCHAR(26) NOT NULL,
  account_id    VARCHAR(26) NOT NULL,
  PRIMARY KEY (address_id, account_id)
);
CREATE INDEX ix_address_targets_account ON address_targets(account_id);
-- addresses.account_id(단일 목적지)를 006에서 여기로 옮겼다. 목적지의 진실 원천이 둘이면
-- 한쪽만 고쳐 조용히 깨진다 — accounts.email과 addresses가 갈라져 크로스 테넌트 수신 탈취를
-- 만든 사고가 선례다. forward_to는 성격이 달라(외부 릴레이) addresses에 남는다.
-- 상한: 알리아스당 로컬 목적지 MAX_ALIAS_TARGETS(32, @ionosphere/api) — 수신 1통이 계정 수만큼
-- append로 증폭되므로 무제한이면 알리아스 하나로 테넌트 전체에 동시 쓰기를 걸 수 있다.
-- FK 미사용 정책이라 알리아스 삭제 시 address_targets를 **같은 배치에서 먼저** 지운다.

CREATE TABLE credentials (
  id            VARCHAR(26) PRIMARY KEY,
  account_id    VARCHAR(26) NOT NULL,
  kind          SMALLINT NOT NULL,                  -- 0 password / 1 app-password / 2 oauth(v2)
  label         VARCHAR(190),
  secret        TEXT NOT NULL,                      -- 자기서술 포맷: "argon2id$..." | "scram256$salt$iter$storedKey$serverKey"
                                                    -- SCRAM 키는 다음 PLAIN 로그인 때 지연 생성 (포맷 버전이 앞에)
  scopes        VARCHAR(190),
  last_used_at  BIGINT,
  created_at    BIGINT NOT NULL
);
CREATE INDEX ix_credentials_account ON credentials(account_id);

-- 관리 API 주체 (메일 계정과 별개 축)
CREATE TABLE api_keys (
  id            VARCHAR(26) PRIMARY KEY,
  tenant_id     VARCHAR(26) NOT NULL,
  label         VARCHAR(190),
  key_hash      VARCHAR(64) NOT NULL,
  scopes        VARCHAR(190) NOT NULL,
  created_at    BIGINT NOT NULL,
  revoked_at    BIGINT
);
CREATE INDEX ix_api_keys_tenant ON api_keys(tenant_id);
```

### 4-1. 공유 메일함 주체·ACL (마이그레이션 020)

```sql
CREATE TABLE principals (
  id            VARCHAR(26) PRIMARY KEY,
  tenant_id     VARCHAR(26) NOT NULL,
  kind          SMALLINT NOT NULL,                  -- account / group / anyone / authenticated
  account_id    VARCHAR(26),                         -- 로컬 계정 주체일 때만 채움
  provider      VARCHAR(32),                         -- local / ldap / ad
  external_key  VARCHAR(255),                       -- provider 내부의 안정적인 식별자
  display_name  VARCHAR(255),
  created_at    BIGINT NOT NULL
);
CREATE UNIQUE INDEX ux_principals_account ON principals(tenant_id, account_id);
CREATE UNIQUE INDEX ux_principals_external ON principals(tenant_id, kind, provider, external_key);

CREATE TABLE mailbox_acl (
  mailbox_id    VARCHAR(26) NOT NULL,
  principal_id  VARCHAR(26) NOT NULL,
  rights        VARCHAR(32) NOT NULL,               -- standard right만 저장; c/d는 앱에서 확장
  negative      SMALLINT NOT NULL DEFAULT 0,        -- 예약 필드; 020에서는 양수 ACL만 허용
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL,
  PRIMARY KEY (mailbox_id, principal_id)
);
CREATE INDEX ix_mailbox_acl_principal ON mailbox_acl(principal_id, mailbox_id);

CREATE TABLE account_memberships (
  account_id    VARCHAR(26) NOT NULL,
  principal_id  VARCHAR(26) NOT NULL,
  source        VARCHAR(32) NOT NULL,               -- local / ldap / ad
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (account_id, principal_id)
);
CREATE INDEX ix_account_memberships_principal ON account_memberships(principal_id, account_id);
```

`principals`는 `tenant_id`와 directory `provider`를 함께 키 범위에 넣어 동일한 외부 식별자가
다른 테넌트·디렉터리에서 충돌하지 않게 한다. FK는 공통 DDL 정책상 두지 않으며, 주체·ACL·멤버십
삭제는 Store의 한 원자 배치에서 역순으로 처리한다.

### 4-2. LDAP/AD directory identity (마이그레이션 021)

```sql
CREATE TABLE directory_identities (
  id            VARCHAR(26) PRIMARY KEY,
  tenant_id     VARCHAR(26) NOT NULL,
  provider      VARCHAR(32) NOT NULL,
  external_key  VARCHAR(512) NOT NULL,                -- objectGUID 우선, objectSid fallback
  account_id    VARCHAR(26),
  login_names   TEXT NOT NULL,                        -- UPN·sAMAccountName JSON 배열
  email         VARCHAR(255),
  display_name  VARCHAR(255),
  last_seen_at  BIGINT NOT NULL,
  status        SMALLINT NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX ux_directory_identity ON directory_identities(tenant_id, provider, external_key);

CREATE TABLE directory_group_members (
  tenant_id          VARCHAR(26) NOT NULL,
  provider            VARCHAR(32) NOT NULL,
  group_external_key  VARCHAR(512) NOT NULL,
  member_external_key VARCHAR(512) NOT NULL,
  group_external_hash CHAR(64) NOT NULL,
  member_external_hash CHAR(64) NOT NULL,
  last_seen_at        BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, provider, group_external_hash, member_external_hash)
);
```

동기화는 완전 snapshot을 한 배치로 반영한다. 조회 실패 때는 호출하지 않고 기존 행을 삭제하지
않으며, 성공한 snapshot에서 제거된 membership만 정리한 뒤 관련 `permissions_version`을 증가시킨다.

## 5. DDL — 메일 스토어 코어

### 5-1. mailboxes

```sql
CREATE TABLE mailboxes (
  id            VARCHAR(26) PRIMARY KEY,               -- 불변 MAILBOXID
  account_id    VARCHAR(26) NOT NULL,
  parent_id     VARCHAR(26) NOT NULL DEFAULT '',       -- '' = 루트 (센티널 — NULL이면 유니크 무력화)
  name          VARCHAR(255) NOT NULL,              -- UTF-8 네이티브
  role          VARCHAR(20),
  status        SMALLINT NOT NULL DEFAULT 1,        -- 1 active / 2 deleting (2단계 삭제, §7-7)
  uidvalidity   BIGINT NOT NULL,                    -- max(epoch초, accounts.uidvalidity_last+1); 발급 시 uidvalidity_last 갱신
  uidnext       BIGINT NOT NULL DEFAULT 1,
  highestmodseq BIGINT NOT NULL DEFAULT 0,
  acl_version   BIGINT NOT NULL DEFAULT 0,          -- ACL 변경 시 증가하는 권한 캐시 세대 (020)
  subscribed    SMALLINT NOT NULL DEFAULT 1,
  sort_order    BIGINT NOT NULL DEFAULT 0,
  total_count   BIGINT NOT NULL DEFAULT 0,
  unread_count  BIGINT NOT NULL DEFAULT 0,
  total_bytes   BIGINT NOT NULL DEFAULT 0,
  created_at    BIGINT NOT NULL
);
CREATE UNIQUE INDEX ux_mailboxes_name ON mailboxes(account_id, parent_id, name);
CREATE INDEX ix_mailboxes_account ON mailboxes(account_id);
```

- UIDVALIDITY: 삭제→같은 이름 재생성이 같은 초에 일어나도 `uidvalidity_last+1`이 단조증가 보장.
- `RENAME INBOX`의 특수 시맨틱(내용 이동+빈 INBOX 재생성)은 앱 레이어.

### 5-2. messages / message_mailbox

```sql
CREATE TABLE messages (
  id            VARCHAR(26) PRIMARY KEY,               -- 불변 EMAILID·JMAP Email id·POP3 UIDL
  account_id    VARCHAR(26) NOT NULL,
  blob_id       VARCHAR(64) NOT NULL,
  thread_id     VARCHAR(26) NOT NULL,
  modseq        BIGINT NOT NULL,                    -- ★물질화: 이 메시지를 마지막으로 건드린 modseq.
                                                    -- change_log GC와 무관하게 CONDSTORE 영구 보장
  size_bytes    BIGINT NOT NULL,
  received_at   BIGINT NOT NULL,
  subject       TEXT,
  subject_base  VARCHAR(190),                       -- 절단 허용 (스레딩 보조키 — 정확성 비필수)
  msgid_hash    VARCHAR(32),                        -- sha256/32hex 절단
  sent_at       BIGINT,
  preview       TEXT,
  has_attachment SMALLINT NOT NULL DEFAULT 0,
  created_at    BIGINT NOT NULL
);
CREATE INDEX ix_messages_account_received ON messages(account_id, received_at);
CREATE INDEX ix_messages_thread ON messages(account_id, thread_id);
CREATE INDEX ix_messages_msgid ON messages(account_id, msgid_hash);
CREATE INDEX ix_messages_modseq ON messages(account_id, modseq);   -- CHANGEDSINCE 스캔용

CREATE TABLE message_mailbox (
  mailbox_id    VARCHAR(26) NOT NULL,
  uid           BIGINT NOT NULL,
  message_id    VARCHAR(26) NOT NULL,
  savedate      BIGINT NOT NULL,
  deleted       SMALLINT NOT NULL DEFAULT 0,        -- ★IMAP \Deleted — 유일한 per-membership 플래그.
                                                    -- 지연 EXPUNGE·SEARCH DELETED·UNDELETE 지원
  PRIMARY KEY (mailbox_id, uid)
);
CREATE UNIQUE INDEX ux_mm_message ON message_mailbox(mailbox_id, message_id);
CREATE INDEX ix_mm_by_message ON message_mailbox(message_id);
```

### 5-4. typed header projection (마이그레이션 022)

`message_header_projection`은 allowlist 11개만 저장하는 읽기 모델이다. `date`는 epoch,
주소/참조는 JSON, 나머지는 display/sort 문자열로 분리한다. display 16 KiB, sort 4 KiB,
header occurrence 32개 상한은 projection에만 적용하고 MIME blob 원본은 보존한다.

```sql
CREATE TABLE message_header_projection (
  message_id    VARCHAR(26) NOT NULL,
  occurrence    SMALLINT NOT NULL,
  name          VARCHAR(190) NOT NULL,
  kind          VARCHAR(16) NOT NULL,
  display_value TEXT NOT NULL,
  sort_value    TEXT NOT NULL,
  date_value    BIGINT,
  address_value TEXT,
  PRIMARY KEY (message_id, name, occurrence)
);
CREATE INDEX ix_header_projection_date ON message_header_projection(name, date_value, message_id);
CREATE INDEX ix_header_projection_sort ON message_header_projection(name, sort_value, message_id);
```

### 5-5. listing indexes (마이그레이션 023)

UID 순서와 subject/header 정렬의 선두 인덱스를 추가한다. 목록 캐시는 프로세스 메모리의 bounded
LRU일 뿐이며, mailbox modseq와 ACL/permissions version이 바뀌면 key가 달라져 DB 결과를 다시 읽는다.

```sql
CREATE INDEX ix_mm_listing ON message_mailbox(mailbox_id, uid, message_id);
CREATE INDEX ix_messages_subject_sort ON messages(account_id, subject_base, id);
CREATE INDEX ix_header_projection_listing ON message_header_projection(name, sort_value, message_id);
```

MySQL에서는 `sort_value`가 TEXT이므로 어댑터가 해당 인덱스의 정렬 키를 512자 prefix로 변환한다.
원문 projection은 TEXT로 보존하고, SQLite·PostgreSQL에서는 전체 값을 인덱싱한다.

- IMAP `FETCH (MODSEQ)`/`CHANGEDSINCE` = `message_mailbox ⋈ messages WHERE messages.modseq > ?`.
- COPY 대상에 이미 있는 메시지: `ux_mm_message` 충돌 → **앱이 스냅샷에서 선검사해 no-op** (계약).
- 키워드 모델(확정): `\Deleted`만 membership 단위, 나머지 전부 메시지 단위 공유(Gmail 모델).
  Gmail이 `\Deleted`를 특수 취급하는 이유와 동일. imaptest의 공유 `$seen` 허용 여부는
  Phase 3 진입 전 1시간 스파이크로 확인(§11).

### 5-3. 키워드/주소/스레딩

```sql
CREATE TABLE message_keywords (
  account_id    VARCHAR(26) NOT NULL,                  -- ★스코프 추가 (역조회 인덱스용)
  message_id    VARCHAR(26) NOT NULL,
  keyword       VARCHAR(190) NOT NULL,              -- 소문자 저장(RFC 8621 규정). IMAP 표면은 관례 케이싱(\Seen) 복원
  PRIMARY KEY (message_id, keyword)
);
CREATE INDEX ix_keywords_reverse ON message_keywords(account_id, keyword);  -- hasKeyword 쿼리

CREATE TABLE message_addresses (
  account_id    VARCHAR(26) NOT NULL,                  -- ★스코프 추가 (전 테넌트 핫키 회피)
  message_id    VARCHAR(26) NOT NULL,
  kind          SMALLINT NOT NULL,
  pos           SMALLINT NOT NULL,
  name          TEXT,
  email         VARCHAR(255) NOT NULL,
  PRIMARY KEY (message_id, kind, pos)
);
CREATE INDEX ix_maddr_email ON message_addresses(account_id, email, kind);

CREATE TABLE thread_refs (
  account_id    VARCHAR(26) NOT NULL,
  ref_hash      VARCHAR(32) NOT NULL,
  thread_id     VARCHAR(26) NOT NULL,
  created_at    BIGINT NOT NULL,                    -- GC 기준 (스레드 활동 없으면 만료)
  PRIMARY KEY (account_id, ref_hash, thread_id)
);
```

- **스레드 병합(확정: v1은 no-merge)** — refs가 서로 다른 두 스레드에 매치하면 가장 오래된
  스레드를 선택, 병합하지 않음(합법 — 스레딩 알고리즘은 서버 재량). 병합은 v2 검토.
- thread_refs GC: created_at 기준 보존창(기본 180일) — 오래된 스레드로의 늦은 답장은 새 스레드가 됨(수용).

## 6. DDL — 변경로그/툼스톤 (v2: 역할 분리)

### 6-1. change_log — JMAP 시맨틱 전용

```sql
CREATE TABLE change_log (
  account_id    VARCHAR(26) NOT NULL,
  modseq        BIGINT NOT NULL,
  entity        SMALLINT NOT NULL,     -- 0 Email / 1 Mailbox / 2 Thread / 3 EmailSubmission / 4 SieveScript(예약)
  object_id     VARCHAR(26) NOT NULL,
  kind          SMALLINT NOT NULL,     -- 0 created / 1 updated / 2 destroyed(객체 소멸 시에만)
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (account_id, modseq, entity, object_id)
);
CREATE INDEX ix_chlog_entity ON change_log(account_id, entity, modseq);
```

- **kind=2는 객체가 정말 사라질 때만** (마지막 membership 제거, 메일함 삭제 완료).
  메일함 간 이동·일부 라벨 제거는 kind=1 updated — JMAP 클라이언트가 산 메일을 지우는 v1 결함 해소.
- 같은 배치에서 같은 객체에 여러 변화(이동+플래그): **행 1개, 강한 kind 우선**
  (destroyed > created > updated) — PK 충돌 원천 차단, `/changes` 쿼리 단순 유지.
  **예외: 같은 배치에서 created+destroyed(순생성·소멸 net-zero)면 행을 아예 쓰지 않음**
  (RFC 8620 §5.2 "생략" 규칙 — destroyed로 축약하면 클라이언트가 본 적 없는 id의 유령
  destroyed를 받음). 클레임·state 갱신은 그대로 수행.
- **`/changes` 응답 규칙(RFC 8620 §5.2)**: `modseq > sinceState` 행을 object_id로 집계 후
  created+updated→created, created+destroyed→생략, updated+destroyed→destroyed.
  `maxChanges` 페이징은 modseq 윈도 단위(윈도 내 dedup 후 잘라내기).

### 6-2. expunged — IMAP QRESYNC 툼스톤 전용 (Cyrus 모델)

```sql
CREATE TABLE expunged (
  mailbox_id    VARCHAR(26) NOT NULL,
  uid           BIGINT NOT NULL,
  modseq        BIGINT NOT NULL,
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (mailbox_id, uid)
);
CREATE INDEX ix_expunged_modseq ON expunged(mailbox_id, modseq);
```

- membership 제거(EXPUNGE·MOVE 원본측·메일함간 라벨 제거) 시마다 1행.
  VANISHED (EARLIER) = `WHERE mailbox_id=? AND modseq>?`.
- GC (기본 30일). **제약: expunged 보존창 ≥ change_log 보존창** — "창 밖" 판정은
  `changelog_floor` 하나로 공용 (`sinceModseq < floor` → 전체 재동기화). 별도 플로어 불요.

### 6-3. GC 플로어와 state 규칙

- `accounts.changelog_floor` = GC가 지운 최고 modseq. **`sinceState < floor` → JMAP
  `cannotCalculateChanges` / IMAP 전체 재동기화.** "빈 로그 = 변화 없음" 오판 차단.
- JMAP state 문자열 = `accounts.state_*` 고수위 컬럼 (배치가 갱신). `max(로그)` 조회 금지 —
  GC 후 state 역행 방지.

## 7. 배치 레시피 (계약)

> 구현 규율: 스토어의 **모든** 변이는 여기 정의된 레시피로만. 새 연산 = 새 레시피 문서화 필수.

### 7-1. AppendMessage (LMTP 배달·IMAP APPEND·JMAP import)

```
(계정 라이터 큐 안) 스냅샷: M, uidnext, 쿼터, 메일함 status=1 확인
배치:
  INSERT modseq_claims (acct, M+1)                    -- ★잠금
  upsert blobs (§1-5 승인 분기) + INSERT blob_refs (acct 포함)
  INSERT messages (…, modseq=M+1)
  INSERT message_addresses / message_keywords / thread_refs / message_text
  INSERT message_mailbox (mbx, uid, msgId, savedate, deleted=0)
  INSERT search_index 토큰 (다중행, 한도 근접 시 후속 배치로 분리 허용)
  INSERT message_auth (수신 경로일 때 — SPF/DKIM/DMARC 판정)
  INSERT change_log (M+1, Email, msgId, created)
  INSERT change_log (M+1, Mailbox, mbxId, updated)
  INSERT change_log (M+1, Thread, thrId, created|updated)
  UPDATE mailboxes SET uidnext=…, total_count+1, total_bytes+n
                       [, unread_count+1 — ★$seen 미포함일 때만 (APPEND (\Seen)·Sent 저장 주의)]
  UPDATE accounts SET used_bytes+n, message_count+1   (+ 전역 불변식 §3-3)
```

### 7-2. SetFlags / SetKeywords

```
message_keywords 삽입/삭제 + messages.modseq=M+1
change_log (Email, updated) + 소속 메일함마다 change_log (Mailbox, updated)  -- ★배지 카운트 통지
소속 메일함마다 unread_count 증분, highestmodseq=M+1
```

`\Deleted`는 여기가 아니라 `message_mailbox.deleted` UPDATE (동일하게 modseq·change_log 갱신).

### 7-3. Move / 라벨 제거

```
message_mailbox 원본행 DELETE + 대상행 INSERT(새 UID)
INSERT expunged (원본 mbx, uid, M+1)                  -- QRESYNC 재료
messages.modseq=M+1
change_log (Email, updated)                           -- ★destroyed 아님
change_log (Mailbox, updated) × 원본·대상, 카운터·highestmodseq 갱신
```

### 7-4. Expunge (deleted=1 대상)

```
message_mailbox DELETE + INSERT expunged × 각 행
마지막 membership이면: messages·message_keywords·message_addresses·message_text
  DELETE + blob_refs DELETE + change_log (Email, destroyed)
  (thread_refs는 삭제하지 않음 — PK에 message_id가 없고 행이 메시지 간 공유(insertIgnore
   dedup)돼 형제 답장의 스레드 연결을 끊을 수 있음. §5-3의 180일 GC에 위임 — v2.1 구현 중 확정)
아니면: change_log (Email, updated)
search_index는 **지연 정리**: 질의가 항상 messages와 조인(고아 필터), 주기 스위퍼가
  고아 포스팅 삭제 — message_id 인덱스 추가 비용 회피 (측정 후 재평가)
카운터·highestmodseq·state 갱신
```

### 7-5. POP3 QUIT

DELE 마크는 세션 상태 → QUIT 시 하나의 Expunge 배치. 동시 IMAP EXPUNGE와 경합하면
0행 DELETE로 자연 수렴. maildrop 잠금은 v1에서 인프로세스 세션 관리였고(`[IN-USE]`),
**마이그레이션 005가 DB 테이블로 옮겼다**:

```sql
CREATE TABLE maildrop_locks (
  account_id VARCHAR(26) PRIMARY KEY,     -- ★"계정당 최대 하나"를 DB가 강제 → 획득이 단일 문장
  owner      VARCHAR(64) NOT NULL,        -- 세션 식별자. 해제·갱신을 AND owner=? 로 가드
  expires_at BIGINT NOT NULL              -- 크래시한 MRA가 계정을 영원히 잠그지 않도록 TTL
);
```

★프로세스 메모리의 `Set` 하나로는 **MRA를 2대 이상 띄우는 순간 락이 서로를 못 본다**
(같은 프로세스에서 110/995 백엔드를 따로 만드는 현 `app.ts`도 마찬가지였다). 그러면 RFC 1939
§3의 배타 접근이 깨지고, 세션 A가 QUIT하며 지운 메시지를 세션 B가 RETR해 **조용한 데이터
사고**가 된다. `account_id`가 PK여야 획득이 단일 문장 check-and-set(INSERT 충돌 = 패배)이 된다 —
SELECT 후 INSERT는 두 MRA 사이에서 항상 진다. `owner` 가드가 없으면 락을 못 잡은 세션이
끊기면서 **남의 락을 푼다**. `schema_lock`과 형태가 같지만 수명(세션 수십 분 vs 부팅 몇 초)과
키(계정 vs 단일 상수)가 달라 테이블을 나눴다.
5,000행 초과 시 §7-6 다중 배치 (원자성 완화 수용 — POP3 시맨틱상 무해).

### 7-6. 벌크 작업 (COPY/MOVE/플래그 대량, >1 배치)

- **다중행 INSERT 청크**: 행/문장은 코드가 `floor(100 / 컬럼수)`로 **유도** (예시:
  message_mailbox 5col→20행, change_log 6col→16행, expunged 4col→25행 — 상수 하드코딩 금지,
  컬럼 추가 시 조용히 깨짐). 배치당 ≤1,000문장.
- 한 배치 = 한 modseq. 넘치면 **다중 배치 = 다중 modseq** — 배치별로 완결된 일관 상태를
  만들도록 청크 (예: MOVE는 메시지 단위로 완결되게 — RFC 6851상 부분 완료 합법).
- COPYUID/APPENDUID: UID를 연속 범위로 사전 할당해 응답 조립.
- 실패 중단 시: 이미 커밋된 배치는 유효한 상태 — 재개는 background_jobs(§9-4) 저널로.

### 7-7. 메일함 삭제 / 계정 삭제 (2단계)

```
배치 1 (원자):
  대상 + 모든 자손 메일함(트리는 스냅샷에서 확정, 메일함 수는 배치 한도 내):
    status=2(deleting) + ★유니크 키 비우기: name=id, parent_id='\x00reap'
    (id는 유일 → 툼스톤끼리 충돌 불가. 이걸 안 하면 같은 이름 재생성이
     ux_mailboxes_name 충돌로 리퍼 완료까지 불가 — DELETE+CREATE는 imaptest 기본 동작)
  change_log (Mailbox, destroyed) × 각 메일함
이후: background_jobs 저널 리퍼가 membership을 §7-6 청크로 드레인 → 마지막에 행 삭제
같은 이름 재생성: 배치 1 직후 즉시 가능 (새 ULID id + uidvalidity_last+1 — UID 공간 완전 분리)
계정 삭제 = accounts.status=2 + 전 메일함 동일 절차 + credentials/sieve/… 정리 저널.
  ★accounts.email은 비우지 않음 — 드레인 완료까지 주소 재등록 차단이 의도
  (드레인 중 신규 계정이 구 메일 수신하는 사고 방지)
```

**읽기 가시성 계약**: 모든 읽기 경로(IMAP LIST/SELECT/STATUS, JMAP Mailbox/get·Email/query,
POP3)는 `status=1`만 노출. status=2는 즉시 notFound/부재 — 드레인은 관측 불가여야 함.
accounts.status=2 동일.

### 7-8. 재시도 계약

재시도는 **스냅샷과 전제조건 전부 재수행** (쿼터·status·존재 검증 포함). 지터 백오프,
상한 도달 시 프로토콜별 합법 실패 응답 (§3-3).

### 7-9. EmailSubmission 라이프사이클 (전부 클레임 배치 — MTA 워커 포함)

```
Submit (JMAP Email/set+EmailSubmission/set 또는 SMTP submission):
  INSERT email_submissions (undo_status=0|1) + mta_queue 수신자별 행
  + change_log (M+1, EmailSubmission, id, created) + onSuccess 시 Email 변이 병합
Cancel (undoStatus=canceled):
  UPDATE email_submissions SET undo_status=2 WHERE id=? AND undo_status=0
  + mta_queue status=5 + change_log (EmailSubmission, updated)
  — 워커와의 경합은 §9-4 리스 규율(영향 행 수)로 판정
Finalize (MTA 워커, 최종 배달/바운스 확정):
  UPDATE email_submissions SET undo_status=1 + change_log (EmailSubmission, updated)
  ★워커도 계정 스코프 쓰기 — 라이터 큐 + 클레임 의무 (§3-1). 이거 생략하면
   entity=3에서 C1급 modseq 공유가 재발함
```

## 8. DDL — 검색

```sql
CREATE TABLE message_text (
  message_id    VARCHAR(26) NOT NULL,
  field         SMALLINT NOT NULL,
  content       TEXT NOT NULL,
  PRIMARY KEY (message_id, field)
);

CREATE TABLE search_index (
  account_id    VARCHAR(26) NOT NULL,
  token         VARCHAR(16) NOT NULL,
  field         SMALLINT NOT NULL,
  message_id    VARCHAR(26) NOT NULL,
  PRIMARY KEY (account_id, token, field, message_id)
);
```

- 토크나이저: NFKC → casefold → CJK 바이그램 + 라틴 단어. 앱 소유(`packages/store/src/tokenize.ts`).

> ⚠ **`message_text`와 `search_index`의 덮는 범위가 다르다(2026-07-31).**
> `message_text.content`는 본문 **전체**를 저장하지만 색인은 **필드당 64Ki자**에서 멈춘다
> (`MAX_INDEX_TEXT_CHARS`). 즉 아주 긴 본문에는 **저장돼 있는데 검색은 안 되는 꼬리**가 생긴다.
>
> 의도한 트레이드오프다. CJK 바이그램은 n글자에서 n-1개 토큰을 만들고 한글 음절 조합이
> 11,172²가지라 중복 제거가 사실상 듣지 않는다 — 실측으로 **25MB 한글 본문 한 통이 806만 토큰 ·
> RSS 1.3GB**를 만들어 512MB 힙에서 실제로 프로세스가 죽었다. 색인 대상은 **미인증 원격이 보낸
> 본문**이고 전 프로토콜이 단일 프로세스라 그 OOM은 메일 서비스 전체 중단이다(감사 5차 §9-9).
>
> 상한 초과분은 **버리고 던지지 않는다** — 호출자가 메일 저장·배달 경로라, 긴 본문 뒷부분이
> 검색되지 않는 것이 메일 유실·배달 실패보다 낫다. 반대로 **질의 쪽은 거부**한다(조용히 자르면
> 토큰이 줄어 더 넓게 매칭돼 사용자가 틀린 결과를 맞는 결과로 오해한다).
>
> **디스크 비용(2026-07-31 실제 DB 파일 실측)**: `search_index` 행당 **143~150바이트**다.
> 전 컬럼이 PRIMARY KEY라 26자 `account_id`와 26자 `message_id`가 **포스팅마다** 저장되고 별도
> 페이로드가 없어 **인덱스가 곧 데이터**다. 상한은 `tokenize()` 호출 단위이므로 메시지 하나의
> 최악은 4필드(subject·body·from·to)만큼 곱해져 **262,082행 / 38.6MB**다(정확히 4배).
> 상한이 없다면 25MB 본문 한 통이 **1,169.7MB**를 쓴다(실제 DB 파일로 실측 — 외삽 아님).
> ⚠ WAL도 함께 봐야 한다 — 상한 적용 케이스에서 WAL 정점(11.0MB)이 `.db`(9.9MB)보다 **컸다**.
- **인덱싱 필드는 백엔드별 설정** — 기본 (subject, from, to, body), **D1 어댑터 기본은
  (subject, from, to)** (10GB 한도 — body 역색인 제외, body 검색은 D1에서 미지원 광고).
- 고아 포스팅: 질의 시 messages 조인 필터 + 주기 스위퍼 (§7-4).

## 9. DDL — 보조 도메인

### 9-1. 발송 (JMAP EmailSubmission과 정렬)

```sql
-- JMAP EmailSubmission 객체 (계정 스코프, /changes 대상 — entity=3)
CREATE TABLE email_submissions (
  id            VARCHAR(26) PRIMARY KEY,
  account_id    VARCHAR(26) NOT NULL,
  identity_id   VARCHAR(26) NOT NULL,
  message_id    VARCHAR(26),                           -- 원본 Email (드래프트)
  blob_id       VARCHAR(64) NOT NULL,
  env_from      VARCHAR(255) NOT NULL,
  send_at       BIGINT NOT NULL,                    -- 예약 발송 (FUTURERELEASE 짝)
  undo_status   SMALLINT NOT NULL DEFAULT 0,        -- 0 pending(취소가능) / 1 final / 2 canceled
  created_at    BIGINT NOT NULL
);
CREATE INDEX ix_subm_account ON email_submissions(account_id, created_at);

-- 수신자 단위 큐 (submission 1 : N rcpt)
CREATE TABLE mta_queue (
  id            VARCHAR(26) PRIMARY KEY,
  tenant_id     VARCHAR(26) NOT NULL,
  account_id    VARCHAR(26) NOT NULL,                  -- ★미터링·레이트리밋 귀속
  submission_id VARCHAR(26),                           -- NULL = 시스템 발송(DSN 등)
  blob_id       VARCHAR(64) NOT NULL,
  env_from      VARCHAR(255) NOT NULL,              -- VERP 인코딩 반송 주소
  verp_token    VARCHAR(32),                        -- ★바운스 역상관
  rcpt          VARCHAR(255) NOT NULL,
  rcpt_domain   VARCHAR(255) NOT NULL,
  status        SMALLINT NOT NULL DEFAULT 0,        -- 0 queued / 1 in-flight / 2 done / 3 bounced / 4 deferred / 5 canceled
  attempts      SMALLINT NOT NULL DEFAULT 0,
  next_attempt  BIGINT NOT NULL,
  lease_until   BIGINT,                             -- ★크래시 복구: 만료 리스는 재획득 가능
  last_error    TEXT,
  created_at    BIGINT NOT NULL
  -- + complained_at BIGINT (마이그레이션 009 — §9-2c)
);
CREATE INDEX ix_queue_due ON mta_queue(status, next_attempt);
CREATE INDEX ix_queue_domain ON mta_queue(rcpt_domain, status);
CREATE INDEX ix_queue_account ON mta_queue(account_id, created_at);
CREATE INDEX ix_queue_verp ON mta_queue(verp_token);

CREATE TABLE identities (
  id            VARCHAR(26) PRIMARY KEY,
  account_id    VARCHAR(26) NOT NULL,
  email         VARCHAR(255) NOT NULL,
  name          TEXT,
  reply_to      TEXT,
  text_sig      TEXT,
  html_sig      TEXT,
  created_at    BIGINT NOT NULL
);
CREATE INDEX ix_identities_account ON identities(account_id);
```

### 9-2. suppressions / dkim_keys / sieve / dedup / push

```sql
CREATE TABLE suppressions (
  tenant_id     VARCHAR(26) NOT NULL,
  email         VARCHAR(255) NOT NULL,
  reason        SMALLINT NOT NULL,
  source        TEXT,
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, email)
);

CREATE TABLE dkim_keys (
  id            VARCHAR(26) PRIMARY KEY,
  domain_id     VARCHAR(26) NOT NULL,
  selector      VARCHAR(190) NOT NULL,
  algo          SMALLINT NOT NULL,
  private_key   TEXT NOT NULL,                      -- 마스터키로 암호화
  key_version   SMALLINT NOT NULL DEFAULT 1,        -- ★마스터키 로테이션 대비
  active        SMALLINT NOT NULL DEFAULT 1,
  created_at    BIGINT NOT NULL
);
CREATE UNIQUE INDEX ux_dkim_selector ON dkim_keys(domain_id, selector);

CREATE TABLE sieve_scripts (
  id            VARCHAR(26) PRIMARY KEY,
  account_id    VARCHAR(26) NOT NULL,
  name          VARCHAR(190) NOT NULL,
  content       TEXT NOT NULL,
  active        SMALLINT NOT NULL DEFAULT 0,
  created_at    BIGINT NOT NULL
);
CREATE UNIQUE INDEX ux_sieve_name ON sieve_scripts(account_id, name);

CREATE TABLE dedup_tracking (
  account_id    VARCHAR(26) NOT NULL,                  -- 전역 스코프(greylist)는 account_id='' 센티널
  scope         SMALLINT NOT NULL,                  -- 0 vacation / 1 sieve-duplicate / 2 greylist
  key_hash      VARCHAR(32) NOT NULL,
  expires_at    BIGINT NOT NULL,
  PRIMARY KEY (account_id, scope, key_hash)
);
CREATE INDEX ix_dedup_expiry ON dedup_tracking(expires_at);

CREATE TABLE push_subscriptions (
  id            VARCHAR(26) PRIMARY KEY,
  credential_id VARCHAR(26) NOT NULL,
  device_id     VARCHAR(190) NOT NULL,
  url           TEXT NOT NULL,
  keys_p256dh   TEXT,
  keys_auth     TEXT,
  types         VARCHAR(190),
  verified      SMALLINT NOT NULL DEFAULT 0,
  expires_at    BIGINT,
  created_at    BIGINT NOT NULL
);
```

### 9-2b. suppressions 만료 (마이그레이션 008)

```sql
ALTER TABLE suppressions ADD COLUMN expires_at BIGINT;   -- NULL = 만료 없음
CREATE INDEX ix_suppressions_expires ON suppressions(expires_at);
```

| reason | expires_at | 근거 |
|---|---|---|
| `hardBounce(0)` | NULL(영구) | 상대의 5xx 영구 거절 — 다시 보내도 같은 답이다 |
| `exhausted(1)` | now + 7일 | **우리가 포기한 것**이지 상대의 판정이 아니다 |

`exhausted`는 우리 쪽 DNS·네트워크 장애로도 발생한다. 영구로 두면 장애가 복구돼도 그때 큐에
있던 정상 수신자가 영영 막힌 채 남는다. 정본은 `@ionosphere/mta/suppression.ts`가 소유한다 —
만료 시각을 **정하는 쪽**(워커 적재)과 **판정하는 쪽**(게이트)이 떨어져 있으면 한쪽만 고쳐져
"만료를 넣었는데 아무도 안 본다"가 된다.

만료된 행은 **지우지 않는다**. 왜 한 번 막혔는지가 운영 정보고, 반복해서 exhausted에 걸리는
주소는 이력이 남아야 알아본다. 관리 API 목록은 `expiresAt`과 `active`를 함께 돌려준다.

**재개 안전성**: `ALTER ADD COLUMN`은 SQLite·MySQL에 `IF NOT EXISTS`가 없다. PostgreSQL은
드라이버가 `IF NOT EXISTS`로 바꿔 실행하고(문장 오류가 트랜잭션 전체를 중단시켜 삼킬 수 없다),
SQLite·MySQL·D1은 "이미 있음" 오류를 멱등 no-op으로 흡수한다(`packages/db/src/ddl.ts`).
MySQL이 `CREATE INDEX IF NOT EXISTS`를 흡수하던 장치를 넓힌 것이라 새 개념이 아니다.
실측: MySQL 8·PostgreSQL 16 컨테이너에서 008 문장 재적용 성공.

### 9-2c. 신고(FBL/ARF) 표시 (마이그레이션 009)

```sql
ALTER TABLE mta_queue ADD COLUMN complained_at BIGINT;    -- NULL = 신고 없음
CREATE INDEX ix_queue_complained ON mta_queue(account_id, complained_at);
```

**왜 새 테이블이 아니라 컬럼인가**: 신고는 "이 발송이 신고당했다"는 **발송 한 건의 속성**이다.
별도 테이블로 빼면 발송률 계산에서 매번 조인해야 하는데, `checkAccountAbuse`는 이미 `mta_queue`를
창(window)으로 집계한다 — 같은 질의 한 줄에 얹는 것이 자연스럽다.

★**`status`를 `complained`로 덮지 않는다.** 덮으면 **배달됐다는 사실이 사라진다.** 신고는 배달
이후에 도착하므로 둘 다 참이어야 하고, 분모(발송 수)가 무너지면 **신고율 자체가 틀린다.**
상관관계 키는 발송 시 메시지에 싣는 헤더 식별자다 — `verp_token`을 쓰지 않는 이유는 그것이
봉투 재작성(VERP)을 전제하는데 `enqueue.ts`가 그 작업을 미뤄 뒀기 때문이다(없는 전제를 기다리지 않는다).

### 9-2d. 계정별 베이즈 토큰 (마이그레이션 010)

```sql
CREATE TABLE bayes_tokens (
  account_id  VARCHAR(26) NOT NULL,
  token       VARCHAR(24) NOT NULL,               -- ★해시(HMAC + 계정별 솔트, 16자)
  spam_count  INTEGER NOT NULL DEFAULT 0,
  ham_count   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account_id, token)
);
CREATE TABLE bayes_totals (
  account_id  VARCHAR(26) PRIMARY KEY,
  spam_msgs   INTEGER NOT NULL DEFAULT 0,
  ham_msgs    INTEGER NOT NULL DEFAULT 0
);
```

PLAN §8의 "운영자는 사용자 메일 내용을 열람하지 않는다"와 양립시키는 장치가 **스키마에** 있다:
① `token`이 **해시**라 DB를 열어도 읽을 수 있는 단어가 없다 ② PK가 `(account_id, token)`이라
**계정 경계를 넘지 않는다**(전역 코퍼스를 만들면 한 사람의 메일이 남의 판정에 영향을 준다).
계정별 솔트는 별도 컬럼이 아니라 `accounts.id`에서 유도한다 — 솔트의 목적이 **계정 간 사전
재사용 차단**이지 비밀 유지가 아니라서, 새 비밀을 관리 대상에 추가하지 않는다.

`bayes_totals`가 따로 있는 이유: 사전 확률과 "학습 부족" 판정에 **메시지 건수**가 필요한데,
토큰 테이블에서 세면 토큰 수를 세는 것이지 메시지 수를 세는 게 아니다.

### 9-3. 메시지 인증 판정 (Phase 2)

```sql
-- 수신 시 판정 캐시 — $junk 결정·웹훅 페이로드·격리 리뷰가 원본 재파싱 없이 조회
CREATE TABLE message_auth (
  message_id    VARCHAR(26) PRIMARY KEY,
  spf           SMALLINT,                           -- 0 none/1 pass/2 fail/3 softfail/4 neutral/5 temperror/6 permerror
  dkim          SMALLINT,
  dmarc         SMALLINT,
  spam_score    BIGINT,                             -- x1000 고정소수점
  auth_details  TEXT                                -- Authentication-Results 원문
);
```

### 9-4. 인프라: 마이그레이션 / 백그라운드 잡

```sql
CREATE TABLE schema_migrations (
  version       BIGINT PRIMARY KEY,
  name          VARCHAR(190) NOT NULL,
  applied_at    BIGINT NOT NULL
);
-- D1은 트랜잭셔널 DDL 없음 → 마이그레이션은 "문장 단위 멱등"으로 작성
-- (IF NOT EXISTS·재실행 안전), 러너는 실패 지점부터 재개

CREATE TABLE background_jobs (
  id            VARCHAR(26) PRIMARY KEY,
  kind          SMALLINT NOT NULL,                  -- 0 mailbox-reap / 1 account-reap / 2 blob-gc / 3 index-sweep / 4 log-gc
  target_id     VARCHAR(26),
  cursor        TEXT,                               -- 재개 지점
  status        SMALLINT NOT NULL DEFAULT 0,
  lease_until   BIGINT,
  created_at    BIGINT NOT NULL
);
CREATE INDEX ix_jobs_due ON background_jobs(status, lease_until);
```

**리스 획득 규율** (mta_queue·background_jobs 공통, submission cancel 경합 포함):
리스 = 단일 조건부 UPDATE (`… WHERE id=? AND status=대기 AND (lease_until IS NULL OR
lease_until<now)`). **획득 판정은 영향 행 수 == 1** — 0행 UPDATE는 배치 성공으로 넘어가므로
성공/실패로는 판정 불가. 영향 행 수는 4개 백엔드 전부 제공(D1은 meta.changes)하며,
RETURNING 금지 원칙과 별개로 **승인된 메커니즘**이다. 중복 리스 = 중복 발송이므로 필수 규율.

### 9-4b. 아웃바운드 릴레이(스마트호스트) — 테넌트/발신 도메인 범위

```sql
CREATE TABLE smarthosts (
  tenant_id   VARCHAR(26)  NOT NULL,
  domain      VARCHAR(255) NOT NULL,   -- **발신자(envelope-from)의 도메인**. '' = 테넌트 기본
  host        VARCHAR(255) NOT NULL,
  port        INTEGER      NOT NULL,
  tls_mode    SMALLINT     NOT NULL,   -- SMARTHOST_TLS: 0 required / 1 opportunistic / 2 implicit / 3 never
  username    VARCHAR(255),            -- NULL이면 인증 없음
  secret      TEXT,                    -- seal()로 봉인(AES-256-GCM, IONOSPHERE_MASTER_KEY) — 평문 저장 금지
  max_rcpts   INTEGER,                 -- 세션당 RCPT TO 상한(제공자 계약). NULL이면 상한 없음
  created_at  BIGINT       NOT NULL,
  PRIMARY KEY (tenant_id, domain)
);
```

**해석 순서(좁은 것부터)**: 발신 도메인 → 테넌트 기본(`domain = ''`) → 전역 env(`IONOSPHERE_SMARTHOST`)
→ MX 직송. 릴레이는 "이 도메인을 이 계정으로 보낼 수 있는가"라는 제공자 계약에 묶여 있어
도메인별 지정이 항상 더 정확하다.

**PK가 (tenant_id, domain)인 이유**: "한 범위에 릴레이 하나"를 DB가 강제해야 한다. 애플리케이션이
`ORDER BY`로 승자를 고르면 중복 행이 들어간 순간 어느 쪽이 이길지 조회 계획·콜레이션에 달린다.
`domain`에 NULL 대신 빈 문자열 센티널을 쓰는 것도 같은 이유다 — **SQL에서 NULL은 NULL과 같지
않아** UNIQUE가 테넌트 기본 행의 중복을 막지 못한다.

**실패는 폴백이 아니다**: 해석 결과가 없으면(null) 다음 범위로 내려가지만, 조회·복호화가
*실패*하면 던져서 큐 항목을 deferred로 남긴다. 실패를 "설정 없음"으로 뭉개면 릴레이 전용으로
구성한 테넌트의 메일이 **인증 없이 25번 포트로** 새 나간다. `tls_mode`가 인코딩 밖일 때도
기본값으로 대체하지 않고 던지는 이유가 같다(뭉개면 자격증명이 평문으로 나갈 수 있다).

### 9-5. 블롭 — 2단계 GC + 테넌트 인가

```sql
CREATE TABLE blobs (
  id            VARCHAR(64) PRIMARY KEY,            -- sha256 hex (전역 dedup — 트레이드오프 §11)
  size_bytes    BIGINT NOT NULL,
  backend       SMALLINT NOT NULL DEFAULT 0,
  status        SMALLINT NOT NULL DEFAULT 0,        -- 0 live / 1 doomed (★GC 2단계)
  generation    BIGINT NOT NULL DEFAULT 0,          -- ★저장 경로 = hash/generation. 부활 시 +1
  doomed_at     BIGINT,
  created_at    BIGINT NOT NULL
);

CREATE TABLE blob_refs (
  blob_id       VARCHAR(64) NOT NULL,
  account_id    VARCHAR(26) NOT NULL,                  -- ★인가 축: 블롭 읽기/참조는 자기 계정 ref 필수
  ref_kind      SMALLINT NOT NULL,                  -- 0 message / 1 queue / 2 upload(만료 대상)
  ref_id        VARCHAR(26) NOT NULL,
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (blob_id, ref_kind, ref_id)
);
CREATE INDEX ix_blob_refs_account ON blob_refs(account_id, blob_id);
```

**GC 프로토콜 (데이터 손실 방지 계약 — 세대 분리로 파일 레이스 원천 제거):**

핵심: **저장 경로 = `hash/generation`**. 라이터와 GC가 절대 같은 경로를 다투지 않게 함
(단일 경로 방식은 "GC의 DB 재확인 → 파일 unlink" 사이에 라이터의 재업로드가 끼어드는
TOCTOU가 구조적으로 남음 — 검증 리뷰에서 확정).

1. 라이터 규칙: 배치는 항상 blobs **upsert**(§1-5 승인 분기). 스냅샷에서 `status=1(doomed)`이면
   **`generation+1` 경로에 본문을 먼저 업로드**한 후, 배치에 `UPDATE blobs SET status=0,
   generation=g+1 WHERE id=? AND generation=g` 포함 (가드 실패 감지는 영향 행 수 — §9-4 규율).
   "해시가 있으니 파일도 있겠지" 가정 금지.
2. GC 1단계(배치): `UPDATE blobs SET status=1, doomed_at=? WHERE id=? AND NOT EXISTS
   (SELECT 1 FROM blob_refs WHERE blob_id=?)` — 단일 문장 check-and-set.
   재확인 시 refs가 있으면 `status=0` 복원 (doomed 고착 방지).
3. GC 2단계: `doomed_at + 유예` 경과 후 재확인(여전히 doomed·refs 0) →
   **해당 generation 이하의 파일만 unlink** → 행은 유지(툼스톤 ~수십 바이트) 또는
   그 후 삭제. 라이터가 그 사이 부활했다면 새 generation 경로라 GC의 unlink와 무간섭.

**인가 규칙(계약)**: JMAP 등에서 클라이언트가 blobId를 참조하면 서버는
`blob_refs WHERE blob_id=? AND account_id=요청자` 존재를 반드시 검증. 전역 dedup의
해시 노출 트레이드오프는 §11 참조.

## 10. 프로토콜 요구 → 스키마 매핑 (v2 재검증)

| 요구 | 충족 (v2) |
|---|---|
| UID/UIDVALIDITY/UIDNEXT | mailboxes(+uidvalidity_last 재사용 방지) + message_mailbox PK |
| CONDSTORE 영구 MODSEQ | **messages.modseq 물질화** — GC 무관, ix_messages_modseq |
| QRESYNC VANISHED | **expunged 전용 테이블** (30일 창, 창 밖은 전체 재동기화) |
| \Deleted 지연 EXPUNGE | **message_mailbox.deleted** |
| OBJECTID / SAVEDATE / STATUS=SIZE / QUOTA | 불변 ULID / savedate / 증분 카운터 (쿼터 강제는 §3 잠금으로 유효) |
| 키워드 + 역조회 | message_keywords(account_id 스코프) + ix_keywords_reverse |
| JMAP /changes (dedup·state 불역행) | change_log(JMAP 전용 kind) + §6-1 집계 규칙 + state_* 고수위 |
| JMAP Identity/EmailSubmission/VacationResponse | identities / email_submissions(undo·sendAt, 레시피 §7-9) / VacationResponse는 **생성된 sieve 스크립트에 인코딩** (Stalwart 방식 — 별도 테이블 없음) |
| JMAP Blob/lookup + 인가 | blob_refs(account_id) + §9-5 인가 계약 |
| POP3 UIDL/maildrop/[IN-USE] | messages.id / INBOX membership / 인프로세스 세션 잠금 |
| LMTP 수신자별 부분 성공 | 계정 단위 배치 + blobs upsert(무고한 수신자 롤백 방지) |
| 벌크 작업 vs 배치 한도 | §7-6 청크 수학 + 다중 modseq 프로토콜 + background_jobs 재개 |
| 발송 미터링/레이트리밋/바운스 상관 | mta_queue(account_id, verp_token, lease_until) |
| 관리 API 주체 | api_keys |
| 인증 판정 캐시 | message_auth |
| 마이그레이션 (D1 비트랜잭셔널 DDL) | schema_migrations + 멱등 문장 규율 |

## 11. 확정 결정과 잔여 질문

**확정:**
- 키워드: 메시지 단위 공유 + `\Deleted`만 membership 단위 (Gmail 모델과 동일 구도)
- 스레드 병합: v1 no-merge (가장 오래된 스레드 채택)
- 해시 절단 32hex, VARCHAR(255) 주소, parent_id 센티널 `''`
- 전역 블롭 dedup 유지 + blob_refs 인가 계약. 해시 기반 존재 유추(dedup 오라클)는
  수용된 트레이드오프 (Stalwart/WildDuck 동일) — 규제 민감 테넌트용 per-tenant 솔트는 v2 옵션
- change_log 30일 / expunged 30일 / thread_refs 180일 / modseq_claims는 log와 동시 GC
- **imaptest 공유 `$seen` 허용 — 스파이크 완료(2026-07-23), 스키마 변경 불필요.** imaptest는
  플래그를 철저히 per-(user, mailbox) 단위로만 추적(checkpoint.c:411-429 — 같은 storage를 선택한
  클라이언트끼리만 비교)하고, 메일함 간 플래그 독립성을 검증하는 코드 경로가 없다(copybox COPY는
  tagged OK/NO만 확인, 사본 메타데이터 미생성 — client-state.c:1040-1057). 통과 조건 2개:
  ① copybox ≠ 테스트 메일함(통상 사용법) ② APPEND는 항상 새 메시지 row 생성(Message-ID dedup
  금지 — 우리 스키마의 기존 동작. COPY만 membership 공유).

**잔여 (구현 중 검증):**
1. search_index 실측 (행 수·조인 성능) 후 message_id 인덱스/포스팅 리스트 압축 재평가
2. 코얼레싱 윈도·"호환 가능" 판정 기준·재시도 상한 등 튜닝 값
3. D1 배치 요청 바디 총량 상한 실측 (문서 미기재 — §1-3의 보수 운용으로 커버 중)

**v2.1 재검증 이력**: 이중 재검증(architect·critic)에서 v1 발견 26건 전부 해소 확인.
신규 발견 반영: 블롭 GC generation 분리(파일 TOCTOU 제거), §7-7 툼스톤 유니크 키 비우기
(+자손 처리·읽기 가시성 계약), domain_name_claims 앵커(테넌트 스코프 레이스),
§3-3 전역 불변식(라이브락 방지), §7-9 제출 레시피, net-zero change_log 생략 규칙,
§9-4 리스 규율(영향 행 수), floor 공용 제약, 청크 상수 코드 유도.
```
