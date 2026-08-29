# 공유 메일함·권한·디렉터리·메일 목록 캐시 계획

상태: **계획만 작성됨 · 실행 승인 대기**
작성일: 2026-08-29
범위: 공유 메일함과 mailbox ACL, LDAP/Active Directory 연동, MIME header 및 listing 최적화

2026-08-29 재검토 반영:

- JMAP 표준에 없는 `mayReadSeen`을 제거하고 `mayRemoveItems`·`maySubmit`을 명시했다.
- `accounts.permissions_version`와 `mailboxes.acl_version`의 역할을 추가했다.
- LDAP group과 group principal의 연결을 스키마에 명시했다.
- JMAP partial account access와 Send-from identity 검사를 수용 기준에 추가했다.
- header projection을 단순 문자열 cache가 아닌 typed field codec으로 보강했다.
- JMAP 권한 변경 시 visibility delta를 추측하지 않고 `cannotCalculateChanges`로 전체 재동기화한다.
- principal의 tenant·directory provider 격리, ACL negative right의 1차 범위, IMAP virtual right을 고정했다.
- LDAP group 변경의 다중 shared account version 갱신, 실제 migration 번호, typed header 저장 구조를 확정했다.

이 문서는 DBMail과 비교하면서 확인한 ionosphere의 기능 공백을 메우기 위한 설계·실행 계획이다.
현재 코드에 기능을 추가하지 않는다. 실행할 때는 이 문서를 기준으로 별도의 실행 목록을 만들고,
각 단계의 테스트와 `npm run verify`를 통과한 뒤 다음 단계로 넘어간다.

관련 정본:

- [스토어 스키마](../SCHEMA.md)
- [프로토콜 기능 카탈로그](../PROTOCOLS.md)
- [운영 가이드](../OPERATIONS.md)
- [관리 명령 레지스트리](../../packages/admin-cmd/src/registry.ts)
- [RFC 4314 IMAP ACL](https://www.rfc-editor.org/rfc/rfc4314)
- [RFC 4511 LDAP](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 4513 LDAP 인증](https://www.rfc-editor.org/rfc/rfc4513)

---

## 0. 결론과 원칙

현재 mailbox 접근은 사실상 다음 구조다.

```text
로그인 → accountId 하나 → 그 account의 mailboxes
```

`mailboxes.account_id`와 `messages.account_id`는 데이터 경계를 표현하고, JMAP은 요청
`accountId`를 현재 계정과 대조한다. [`SCHEMA.md:230`](../SCHEMA.md:230),
[`proto-jmap/src/standard.ts`](../../packages/proto-jmap/src/standard.ts),
[`apps/server/src/jmap-backend.ts`](../../apps/server/src/jmap-backend.ts)

권장 방향:

1. 공유 메일함은 `accounts.kind=shared`인 독립 account로 표현한다.
2. 로그인 사용자·LDAP 그룹·특수 주체를 `Principal`로 추상화한다.
3. mailbox 접근 권한은 `packages/store`에서 최종 판정한다.
4. IMAP ACL 권한은 RFC 4314의 `lrswipkxta`를 내부 정본으로 사용한다.
5. LDAP와 AD는 `DirectoryProvider` 어댑터로 연결한다.
6. header cache는 원본 MIME의 대체물이 아니라 listing/search용 projection으로 둔다.
7. listing cache는 principal, mailbox modseq, ACL version을 key에 포함한다.

바꾸지 않을 것:

- `messages.account_id`를 nullable로 만들지 않는다.
- shared mailbox 때문에 message를 사용자별로 복제하지 않는다.
- ACL을 JSON이나 쉼표 문자열 하나로 저장하지 않는다.
- protocol engine에 DB·LDAP I/O를 넣지 않는다.
- header projection이 원본 MIME을 대체하지 않는다.

---

## 1. 목표 모델

### 1-1. 추가 검토에서 봉인한 결정

#### JMAP visibility 변경

ACL 또는 directory group membership 변경으로 기존에 보이던 객체가 보이지 않게 될 때,
현재 ACL만 다시 계산해 `destroyed` 목록을 추측하지 않는다. shared account의
`state_email`·`state_mailbox`·`state_thread`에 permission version을 포함한 opaque state를
사용하고, 요청의 이전 permission version과 현재 version이 다르면 해당 `/changes`는
`cannotCalculateChanges`로 응답한다. 클라이언트는 `/get`·`/query`를 다시 수행해 현재
보이는 집합을 확정한다.

이 정책은 권한 회수로 인한 데이터 존재 노출과 잘못된 `destroyed` 목록을 동시에 막는다.
per-principal visibility change log를 도입하기 전까지 shared account의 Email/Thread/Mailbox
changes에 공통 적용한다. permission version과 JMAP state 갱신은 ACL/group sync의 한 원자
배치에서 함께 수행한다.

#### Principal 식별 범위

`principals`의 외부 식별자는 전역 문자열이 아니다. `tenant_id`와 `provider`를 식별 범위에
포함한다. account principal은 `provider=null`, directory group principal은 해당 provider
값을 사용한다. 동일한 objectGUID/objectSid가 서로 다른 tenant/provider에서 재사용되어도
principal이 합쳐지지 않아야 한다.

#### ACL 1차 범위와 IMAP 호환성

1차 저장 모델은 positive standard right만 권위 있게 저장하고 `negative=0`만 허용한다.
negative right은 계산 규칙과 관리 UI가 함께 준비되는 후속 migration으로 미룬다.
RFC 4314의 호환용 virtual right `c`와 `d`는 입력 시 각각 `kx`, `et`(구현 정책에 따라
`x` 포함)로 확장하고, 응답 시 해당 virtual right을 함께 반환한다.

실제 검사 단위는 다음처럼 분리한다.

```text
CREATE                 → 새 mailbox의 nearest parent에 k
DELETE mailbox         → 대상 mailbox에 x
RENAME                 → 원본 mailbox에 x + 새 parent에 k
APPEND/COPY            → 대상 mailbox에 i; 복사 flag별 s/w/t는 권한 없으면 해당 flag만 제거
STORE \\Deleted        → t
EXPUNGE/CLOSE expunge → e
GETACL/SETACL/...     → a (ACL 정보가 mailbox 존재를 노출하지 않도록 l도 검사)
```

#### Shared mailbox 기본값

shared account에는 사람이 로그인하는 owner를 암묵적으로 만들지 않는다. 관리 명령으로
명시한 account principal 또는 tenant admin만 초기 ACL을 설정할 수 있다. shared mailbox의
`isSubscribed` 기본값은 false로 두고, 각 사용자의 구독 상태는 별도 사용자별 설정으로
관리한다.

#### Directory group version 전파

한 directory group의 membership 또는 group ACL 대상이 바뀌면 해당 group을 ACL에 포함한
모든 shared account를 찾아 각 account의 `permissions_version`을 증가시킨다. 이 작업은
account ID 오름차순의 writer queue를 획득한 뒤 하나의 DB batch로 수행하거나, 재시작 가능한
동기화 job으로 분할할 경우 각 batch의 완료 cursor를 기록한다. 부분 완료를 성공으로 보고하지
않으며, version 반영 전에는 해당 group 권한을 허용하지 않는다.

```text
accounts
├── alice@example.test       kind=user
├── bob@example.test         kind=user
└── support@example.test     kind=shared

alice ──────────────┐
bob ────────────────┼── ACL → support mailbox
LDAP helpdesk group ┘
```

공유 account는 JMAP의 독립 `accountId`가 된다. IMAP에서는 다음처럼 namespace를 붙인다.

```text
INBOX
Sent
Shared/Support
Shared/Support/Archive
```

이 모델의 장점은 기존 `messages.account_id`, `change_log.account_id`, `blob_refs.account_id`,
쿼터 및 검색 인덱스의 계정 경계를 유지한다는 점이다.

---

## 2. Phase 0 — ADR과 계약 고정

### D-01. shared mailbox 표현

**권고:** `kind=shared` 독립 account.

전역 mailbox 모델은 JMAP state, 검색·쿼터·blob 인가를 다시 정의해야 하므로 사용하지 않는다.

### D-02. Principal 종류

1차 구현은 다음 네 종류다.

```text
account
group
anyone
authenticated
```

`anyone`은 스키마에 준비하되 기본 ACL에는 만들지 않는다. negative rights는 후속 단계로
미룬다.

### D-03. 권한 결합

적용 가능한 account/group ACL은 union으로 결합하고, negative rights가 도입되면 마지막에
차감한다. owner는 항상 전체 권한을 얻되 owner ACL row를 중복 저장하지 않는다.

### D-04. LDAP transport

`DirectoryProvider`를 먼저 고정하고 transport를 별도 package로 격리한다.

- 의존성 정책을 유지하면 Node `net`/`tls`로 LDAPS·StartTLS·simple bind subset을 구현한다.
- 검증된 LDAP client 의존성을 허용할 수 있으면 transport만 외부 구현에 맡긴다.
- Kerberos/GSSAPI는 1차 범위에서 제외한다.

### D-05. version과 state

권한 cache와 JMAP partial-access 결과를 안전하게 무효화하기 위해 version의 소유자를
분리한다.

- `accounts.permissions_version`: shared account membership·directory group membership 변화
- `mailboxes.acl_version`: 해당 mailbox ACL 변화
- `mailboxes.highestmodseq`: 메일 내용·flag·membership 변화

ACL 변경은 `acl_version`을 증가시키고, shared account 접근 주체가 바뀌면
`permissions_version`을 증가시킨다. 권한 변화가 JMAP Mailbox projection에 영향을 주면
`state_mailbox`도 같은 원자 batch에서 갱신한다.

### D-06. credential precedence

directory password와 local credential을 섞지 않는다.

```text
directory password → DirectoryProvider 검증
앱 비밀번호/OAuth → local credentials 검증
directory 장애 → directory password 로그인 실패
```

로컬 account와 directory identity의 충돌은 immutable external key 매핑을 우선하고,
동일 이메일 주소라는 이유만으로 자동 병합하지 않는다.

### 완료 기준

- [ ] `accountId`와 `principalId`의 차이가 타입과 API에 드러난다.
- [ ] ACL 권한 매핑표와 directory 장애 정책이 고정된다.
- [ ] JMAP MailboxRights 필드와 IMAP rights 변환표가 RFC 8621 기준으로 고정된다.
- [ ] account/mailbox version과 JMAP state 갱신 규칙이 고정된다.
- [ ] 실제 주소·비밀번호·인프라 호스트명이 문서에 들어가지 않는다.

---

## 3. Phase 1 — Principal과 ACL 스키마

### 3-1. 타입

소유자: `packages/core/src/principal.ts`, `packages/core/src/rights.ts`

```ts
export const PRINCIPAL_KIND = {
  account: 0,
  group: 1,
  anyone: 2,
  authenticated: 3,
} as const;

export type PrincipalContext = {
  principalId: string;
  primaryAccountId: string;
  accessibleAccountIds: readonly string[];
  groupIds: readonly string[];
  authenticated: boolean;
};

export type MailboxOperation =
  | "lookup" | "read" | "seen" | "write" | "insert" | "post"
  | "create" | "delete" | "expunge" | "admin";
```

### 3-2. 테이블

소유자: `packages/db/src/migrations/<다음 번호>_mailbox_acl.ts`

```sql
CREATE TABLE principals (
  id            VARCHAR(26) PRIMARY KEY,
  tenant_id     VARCHAR(26) NOT NULL,
  kind          SMALLINT NOT NULL,
  account_id    VARCHAR(26),
  provider      VARCHAR(32),
  external_key  VARCHAR(255),
  display_name  TEXT,
  created_at    BIGINT NOT NULL
);

CREATE UNIQUE INDEX ux_principals_account ON principals(tenant_id, account_id);
CREATE UNIQUE INDEX ux_principals_external ON principals(tenant_id, kind, provider, external_key);

CREATE TABLE mailbox_acl (
  mailbox_id    VARCHAR(26) NOT NULL,
  principal_id  VARCHAR(26) NOT NULL,
  rights        VARCHAR(32) NOT NULL,
  negative      SMALLINT NOT NULL DEFAULT 0,
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL,
  PRIMARY KEY (mailbox_id, principal_id, negative)
);

CREATE INDEX ix_mailbox_acl_principal
  ON mailbox_acl(principal_id, mailbox_id);

CREATE TABLE account_memberships (
  account_id    VARCHAR(26) NOT NULL,
  principal_id  VARCHAR(26) NOT NULL,
  role          VARCHAR(32) NOT NULL,
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (account_id, principal_id)
);
```

기존 `accounts`와 `mailboxes`에는 version 컬럼을 추가한다. 실제 migration에서는 기존 테이블에
`ALTER TABLE`로 추가하고 기본값은 0으로 둔다.

```sql
ALTER TABLE accounts ADD COLUMN permissions_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN acl_version BIGINT NOT NULL DEFAULT 0;
```

`mailbox_acl.rights`가 mailbox 동작의 정본이다. `account_memberships`는 shared account에
접근 가능한 주체를 표현하고, `role`은 ACL preset을 선택하는 관리 입력값으로만 사용한다.
role과 mailbox rights를 서로 독립적인 권한 정본으로 취급하지 않는다.

부모 mailbox ACL은 1차 구현에서 자식 mailbox에 암묵적으로 상속하지 않는다. 상속이 필요하면
관리 명령이 subtree에 명시적 ACL을 materialize하고 그 작업을 별도 batch/job으로 기록한다.
암묵적 상속은 `GETACL` 응답과 실제 판정 결과가 달라질 위험이 있다.

### 3-3. 기존 데이터

기존 계정마다 account principal을 만들고, 기존 개인 mailbox는 owner의 암묵적 full rights로
계속 접근할 수 있어야 한다. owner 권한을 DB row로 중복 저장할지는 D-05로 고정하며, 권고는
암묵적 owner다.

### 3-4. rights parser

RFC 4314의 `l r s w i p k x t e a`를 지원한다. 중복은 정규화하고, 알 수 없는 문자·대문자·
잘못된 compatibility 문자는 오류로 반환한다. RFC 4314는 알 수 없는 권한을 조용히 무시하지
않도록 한다. [RFC 4314 §3.1](https://www.rfc-editor.org/rfc/rfc4314#section-3.1)

### 테스트

```text
TC-ACL-001 rights 중복 정규화
TC-ACL-002 unknown/uppercase rights 거부
TC-ACL-003 migration 뒤 개인 계정 접근 불변
TC-ACL-004 account/group/anyone 적용 주체 계산
```

---

## 4. Phase 2 — Store authorization

소유자: `packages/store/src/authorization.ts`, `packages/store/src/acl-store.ts`

```ts
export interface AuthorizationResult {
  allowed: boolean;
  rights: ReadonlySet<string>;
  reason: "owner" | "acl" | "group" | "missing" | "denied";
}

export function authorizeMailbox(
  ctx: PrincipalContext,
  mailboxId: string,
  operation: MailboxOperation,
): Promise<AuthorizationResult>;
```

권한 계산 순서:

```text
1. mailbox/account owner 확인
2. account principal ACL
3. group principal ACL union
4. authenticated/anyone ACL
5. negative ACL 차감
6. operation 필요 right 확인
```

### operation 매핑

| 동작 | right |
|---|---|
| LIST/LSUB | `l` |
| SELECT/EXAMINE/STATUS/FETCH/SEARCH | `r` |
| `\\Seen` STORE | `s` |
| 일반 flag STORE | `w` |
| `\\Deleted` STORE | `t` |
| APPEND/COPY | `i` |
| CREATE | `k` |
| DELETE/RENAME 원본 | `x` |
| EXPUNGE | `e` |
| ACL 명령 | `a` |

다음 Store 경계를 모두 바꾼다.

```text
listMailboxes, listMessages, getMessage, searchMessages
createMailbox, deleteMailbox, renameMailbox
appendMessage, copyMessage, moveMessage
setFlags, setDeleted, expunge
```

외부 공개 함수는 `accountId`만 받지 않고 `PrincipalContext`를 받는다. 저수준 mailboxId 함수는
authorization을 통과한 내부 호출만 사용할 수 있게 한다.

ACL 변경은 해당 account의 writer queue와 단일 `db.batch()`로 처리한다.

```text
modseq_claims(account, M+1)
ACL insert/update/delete
accounts.modseq 갱신
mailboxes.acl_version 갱신
accounts.permissions_version 갱신(주체 membership 변화 시)
```

두 version은 메모리 변수로만 관리하지 않고 DB에서 읽는다. shared account membership 또는
directory group membership 변화는 해당 shared account의 `permissions_version`을 증가시킨다.

### 완료 기준

- [ ] 모든 mailbox read/write 경로가 Store authorization을 통과한다.
- [ ] mailbox ID를 직접 알아도 권한 없이는 조회되지 않는다.
- [ ] ACL 변경은 원자 batch다.
- [ ] 개인 계정 기존 테스트가 그대로 초록이다.

---

## 5. Phase 3 — Shared account와 IMAP

### 5-1. 관리 명령

소유자: `packages/admin-cmd/src/accounts.ts`, `registry.ts`

```text
create-shared-account
delete-shared-account
list-shared-accounts
grant-account-membership
revoke-account-membership
list-mailbox-acl
grant-mailbox-access
revoke-mailbox-access
set-mailbox-acl
```

shared account 생성 순서:

```text
account(kind=shared) 생성
account principal 생성
기본 mailbox 생성
address_targets에 목적지 추가
초기 owner/manager ACL 설정
audit event 기록
```

기존 `address_targets` 팬아웃을 재사용한다. 수신 SMTP/LMTP에 shared 전용 분기문을 만들지 않는다.

### 5-2. IMAP namespace

`apps/server/src/imap-backend.ts`에서:

```text
1. primary account mailbox 조회
2. accessible shared account 조회
3. mailbox별 l 권한 필터
4. Shared/<account>/<mailbox>로 변환
5. path 충돌 검출
```

`LIST`에서 숨긴 mailbox는 `SELECT`에서도 거부한다. `findByPath()`와 모든 message operation이
같은 authorization 함수를 사용해야 한다.

### 5-3. IMAP ACL 명령

소유자: `packages/proto-imap/src/engine.ts`, `apps/server/src/imap-backend.ts`

```text
GETACL
SETACL
DELETEACL
LISTRIGHTS
MYRIGHTS
```

engine은 다음 backend action만 emit한다.

```ts
type ImapAclRequest =
  | { kind: "getAcl"; mailbox: string }
  | { kind: "setAcl"; mailbox: string; identifier: string; modification: string }
  | { kind: "deleteAcl"; mailbox: string; identifier: string }
  | { kind: "listRights"; mailbox: string; identifier: string }
  | { kind: "myRights"; mailbox: string };
```

### 테스트

```text
TC-IMAP-ACL-001 GETACL/MYRIGHTS
TC-IMAP-ACL-002 SETACL +rights/-rights/replace
TC-IMAP-ACL-003 DELETEACL
TC-IMAP-ACL-004 LISTRIGHTS 고정 응답
TC-IMAP-ACL-005 l 없는 mailbox는 LIST에 없음
TC-IMAP-ACL-006 r/i/e/a 없는 각 operation 거부
TC-IMAP-ACL-007 shared namespace path 충돌 없음
TC-IMAP-ACL-008 READ-ONLY session과 ACL rights의 교집합 적용
```

---

## 6. Phase 4 — JMAP shared account

현재 JMAP Session과 standard method는 primary account 하나를 중심으로 한다. [`standard.ts`](../../packages/proto-jmap/src/standard.ts)

### 6-1. Session

```ts
interface JmapSessionAccount {
  accountId: string;
  name: string;
  isPersonal: boolean;
  isShared: boolean;
}
```

`PrincipalContext.accessibleAccountIds`를 Session의 accounts로 변환한다. primary account는 기존
`primaryAccounts`에 유지하고 shared account만 추가한다. shared account를 노출하더라도
그 account 안의 mailbox·Email·Thread는 mailbox ACL에 따라 부분적으로만 보일 수 있다.

### 6-2. account 검증

`requireAccountId()`는 다음을 확인한다.

```text
primary account       → 허용
accessible shared     → 허용
그 외                 → accountNotFound
```

모듈마다 account 비교를 복제하지 않고 공통 함수 하나를 사용한다.

### 6-3. myRights

`OWNER_RIGHTS`를 제거하고 Store authorization 결과에서 생성한다.

```text
r   → mayReadItems
i   → mayAddItems
remove/delete operation → mayRemoveItems
s   → maySetSeen
w   → maySetKeywords
k   → mayCreateChild
x   → mayRename and/or mayDelete according to operation
p   → maySubmit
```

`mayReadSeen`은 JMAP 표준 필드가 아니므로 만들지 않는다. `mayRemoveItems`는 Email을
다른 mailbox로 옮기거나 삭제할 수 있는지에 따라 계산한다. JMAP MailboxRights의 표준
필드는 RFC 8621을 따른다. [RFC 8621 §2](https://www.rfc-editor.org/rfc/rfc8621#section-2)

### 6-4. JMAP partial account access

RFC 8621 §9.5에 따라 접근할 수 없는 데이터는 존재하지 않는 것처럼 처리한다.

```text
Mailbox/get/query
Email/get/query
Thread/get
Email/changes
Thread/changes
SearchSnippet/get
Blob download
Email/copy/import/set
```

모든 위 작업은 accessible mailbox 집합을 먼저 계산하고, 그 집합 밖의 mailbox에만 속한
Email·Thread·blob을 결과에서 제거한다. Thread가 접근 가능한 Email과 접근 불가능한
Email을 함께 가진 경우에도 접근 가능한 Email ID만 반환한다.

shared account 주소로 From을 사용하는 것은 mailbox read/write와 별개의 Identity 권한으로
취급한다. `EmailSubmission/set`은 `p`/`maySubmit`과 해당 Identity를 모두 확인한다.

### 테스트

```text
TC-JMAP-SHARED-001 Session에 shared account 노출
TC-JMAP-SHARED-002 inaccessible accountId → accountNotFound
TC-JMAP-SHARED-003 Mailbox/get myRights가 ACL과 일치
TC-JMAP-SHARED-004 shared Email/query 범위 확인
TC-JMAP-SHARED-005 shared Email/set에 i/w/t 적용
TC-JMAP-SHARED-006 개인 메시지와 shared 메시지 혼합 방지
TC-JMAP-SHARED-007 partial account에서 Email/Thread/blob 존재 은닉
TC-JMAP-SHARED-008 shared From Identity와 maySubmit 검사
```

---

## 7. Phase 5 — LDAP/Active Directory

### 7-1. DirectoryProvider

소유자: `packages/core/src/directory.ts`, `packages/store/src/directory-store.ts`

```ts
export interface DirectoryUser {
  externalKey: string;
  loginName: string;
  displayName: string | null;
  emailAddresses: readonly string[];
  groupKeys: readonly string[];
}

export interface DirectoryProvider {
  authenticate(username: string, password: string): Promise<DirectoryUser | null>;
  findUser(identifier: string): Promise<DirectoryUser | null>;
  listGroups(externalUserKey: string): Promise<readonly DirectoryGroup[]>;
}
```

### 7-2. 매핑 테이블

```sql
CREATE TABLE external_identities (
  id             VARCHAR(26) PRIMARY KEY,
  account_id     VARCHAR(26) NOT NULL,
  provider       VARCHAR(32) NOT NULL,
  external_key   VARCHAR(255) NOT NULL,
  login_name     VARCHAR(255) NOT NULL,
  last_synced_at BIGINT,
  UNIQUE (provider, external_key)
);

CREATE TABLE external_groups (
  id            VARCHAR(26) PRIMARY KEY,
  provider      VARCHAR(32) NOT NULL,
  external_key  VARCHAR(255) NOT NULL,
  display_name  VARCHAR(255) NOT NULL,
  principal_id  VARCHAR(26) NOT NULL UNIQUE,
  UNIQUE (provider, external_key)
);

CREATE TABLE principal_group_members (
  principal_id VARCHAR(26) NOT NULL,
  group_id     VARCHAR(26) NOT NULL,
  PRIMARY KEY (principal_id, group_id)
);
```

`external_groups.principal_id`는 `principals.kind=group` row를 가리킨다. directory group을
동기화할 때 group principal을 먼저 upsert한 뒤 `external_groups`와 연결한다. `mailbox_acl`은
directory의 외부 이름이 아니라 안정적인 group principal을 참조한다.

`external_key`는 AD objectGUID/objectSid 또는 directory가 보장하는 immutable key를 사용한다.
`mail`, `uid`, `sAMAccountName`은 login alias일 뿐 primary identity가 아니다.

`principal_group_members`는 문서와 코드에서 같은 이름을 사용한다. 이 테이블은
`principal_id` 사용자 principal과 `group_id` external group을 연결하며, directory sync는
한 사용자의 이전 membership을 새 집합으로 원자적으로 교체한다. 삭제된 group·identity의
ACL 행은 즉시 권한 계산에서 제외하고, 고아 row는 별도 sweeper가 회수한다.

### 7-3. 인증 흐름

```text
LDAP/AD bind
  ↓
사용자 검색·비밀번호 검증
  ↓
external identity 매핑
  ↓
group 동기화
  ↓
PrincipalContext 생성
  ↓
기존 IMAP/POP3/SMTP/JMAP 인증 결과로 반환
```

1차 지원 범위:

- LDAPS
- LDAP StartTLS
- simple bind
- 사용자·그룹 검색
- AD UPN 및 `sAMAccountName`
- TLS 인증서 검증과 연결/search/bind timeout

후순위:

- Kerberos/GSSAPI
- nested group 최적화
- password modify operation
- LDAP referral 자동 추적

자동 provisioning은 기본 off로 둔다.

```text
IONOSPHERE_DIRECTORY_PROVISION=off
```

새 로그인은 directory 장애 시 실패시킨다. shared mailbox의 `i/w/e/a` 권한은 stale group
cache만으로 허용하지 않는다.

directory 인증과 local credential의 우선순위는 D-06을 따른다. 기존 local app-password와
OAuth token은 directory password와 무관하게 local credential scope 검사를 통과해야 한다.

### 테스트

```text
TC-DIR-001 잘못된 비밀번호 거부
TC-DIR-002 bind timeout fail closed
TC-DIR-003 TLS 인증서 검증 실패
TC-DIR-004 immutable external key와 주소 변경
TC-DIR-005 group 추가 후 ACL 적용
TC-DIR-006 group 제거 후 ACL 회수
TC-DIR-007 nested group 순환 무한 재귀 방지
TC-DIR-008 directory 장애 중 admin/shared write 거부
```

---

## 8. Phase 6 — MIME header projection

현재 `messages.subject`, `preview`, `message_addresses`, `thread_refs`, `search_index`가
있으므로 MIME 전체를 DB에 넣지 않는다. [`SCHEMA.md:254`](../SCHEMA.md:254)

### 8-1. allowlist

```text
date, from, to, cc, reply-to, subject
message-id, in-reply-to, references, list-id, precedence
```

### 8-2. 테이블

```sql
CREATE TABLE message_headers (
  message_id    VARCHAR(26) NOT NULL,
  header_name   VARCHAR(190) NOT NULL,
  occurrence    SMALLINT NOT NULL,
  display_value TEXT NOT NULL,
  sort_value    TEXT,
  value_hash    VARCHAR(64),
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (message_id, header_name, occurrence)
);

CREATE INDEX ix_message_headers_message
  ON message_headers(message_id, header_name);

CREATE INDEX ix_message_headers_sort
  ON message_headers(header_name, sort_value, message_id);
```

`occurrence`는 동일한 header 여러 개를 보존한다. `display_value`는 응답용, `sort_value`는
정렬용 canonical value, `value_hash`는 재처리·진단용이다. 모든 header를 같은 문자열로
처리하지 않고 field별 typed codec을 둔다.

```text
Date                  → date_value(epoch millis)
Subject/List-Id       → text_value + unicode sort_value
From/To/Cc/Reply-To   → parsed address projection
Message-Id/References → normalized identifier list
```

저장 구조는 field별 projection table로 고정한다. 공통 원본 행에는 display 값만 두고, 다음
projection을 같은 message 저장 batch에 함께 쓴다.

```text
message_header_dates(message_id, header_name, occurrence, date_value)
message_header_text(message_id, header_name, occurrence, text_value, sort_value)
message_header_refs(message_id, header_name, occurrence, ref_pos, ref_value)
message_addresses(message_id, kind, pos, name, email)  // From/To/Cc/Reply-To 재사용
```

정렬·검색은 typed projection만 사용하고 `display_value`를 정렬 기준으로 사용하지 않는다.
각 projection은 동일한 message의 단일 ingest batch에 속하므로 partial projection은 원본
MIME을 훼손하지 않지만, 재처리 시 해당 message의 projection 전체를 idempotent하게 교체한다.

### 8-3. ingest와 backfill

현재 parser의 `ParsedMessage.headers`를 사용해 message 저장 batch 안에 projection을 넣는다.

```text
MIME parse → messages → message_addresses → message_headers
          → message_text/search_index → 하나의 writer batch
```

상한:

```text
header name 190 bytes
display value 16 KiB
sort value 4 KiB
header별 occurrence 32개
```

기존 메시지는 별도 checkpoint job으로 BlobStore 원본을 읽어 backfill한다. foreground writer와
같은 account에는 기존 writer queue를 사용하고, 재시작 시 마지막 checkpoint 다음부터 시작한다.

projection이 잘못되거나 잘려도 원본 MIME은 변하지 않아야 한다.

### 테스트

```text
TC-HEADER-001 allowlist 저장
TC-HEADER-002 duplicate header 보존
TC-HEADER-003 encoded-word display/sort 변환
TC-HEADER-004 길이·occurrence 상한
TC-HEADER-005 projection truncation과 원본 보존
TC-HEADER-006 backfill 재시작 시 중복·누락 없음
TC-HEADER-007 BlobStore read 실패 시 checkpoint·error 기록
```

---

## 9. Phase 7 — Listing query와 cache

### 9-1. query 분리

현재 `listMessages()`를 다음으로 나눈다. [`packages/store/src/store.ts:2177`](../../packages/store/src/store.ts)

```ts
listMailboxUids(input): Promise<readonly number[]>;
listMessageSummaries(input): Promise<readonly MessageSummary[]>;
queryMessageListing(input): Promise<MessageListPage>;
```

UID 순서, FETCH summary, SORT/THREAD/JMAP query를 같은 거대 쿼리로 처리하지 않는다.

### 9-2. 인덱스

기존 index와 중복되지 않는지 `describeDbSpec`와 각 adapter를 먼저 확인한 뒤 추가한다.

```sql
CREATE INDEX ix_message_mailbox_uid
  ON message_mailbox(mailbox_id, uid);

CREATE INDEX ix_message_mailbox_message
  ON message_mailbox(mailbox_id, message_id);

CREATE INDEX ix_messages_account_received_id
  ON messages(account_id, received_at, id);

CREATE INDEX ix_messages_account_sent_id
  ON messages(account_id, sent_at, id);
```

### 9-3. LRU cache

process-local bounded LRU부터 구현한다. 외부 distributed cache는 실제 부하가 확인된 뒤 검토한다.

```ts
interface ListingCacheKey {
  principalId: string;
  mailboxId: string;
  mailboxModseq: number;
  aclVersion: number;
  permissionsVersion: number;
  filterHash: string;
  sortHash: string;
  position: number;
  limit: number;
  queryFingerprint: string;
}
```

`aclVersion`과 `permissionsVersion`은 실제 DB에서 읽어 key를 만든다. shared account membership
변화는 여러 mailbox에 영향을 주므로 mailbox version만으로는 부족하다. filter/sort hash도
비결정적 JSON 직렬화가 아니라 canonical serializer를 사용한다. `queryFingerprint`에는
JMAP의 `collapseThreads`, `anchor`, `anchorOffset`, `position`, `limit`, `calculateTotal`,
IMAP SORT/THREAD 옵션과 projection field 집합을 정렬된 키 순서로 포함한다. unknown option은
캐시에 넣지 않고 요청 오류로 처리한다.

초기 제한:

```text
전체 메모리 상한 설정
mailbox당 결과 2,000개
TTL 5~30초
LRU eviction
process 종료 시 유실 허용
```

`mailboxId`만 cache key로 쓰면 shared mailbox 결과가 사용자 사이에 섞인다.

### 9-4. 무효화

다음 작업은 mailbox modseq 또는 ACL version을 증가시킨다.

```text
APPEND, STORE, COPY, MOVE, EXPUNGE
mailbox rename/delete
ACL 변경
shared account membership 변경
directory group membership 변경
```

직접 모든 LRU entry를 찾아 삭제하기보다 version mismatch로 자연스럽게 miss시키는 방식을
기본으로 한다.

### 테스트

```text
TC-LIST-001 UID index 사용과 결과 순서
TC-LIST-002 APPEND 후 이전 modseq cache miss
TC-LIST-003 STORE/EXPUNGE 즉시 반영
TC-LIST-004 사용자 A cache가 사용자 B에게 반환되지 않음
TC-LIST-005 ACL 변경 후 l/r 결과 변화
TC-LIST-006 동일 version/조건에서만 hit
TC-LIST-007 memory 상한과 LRU eviction
TC-LIST-008 multi-node stale cache version miss
```

---

## 10. Phase 8 — 관리 명령과 관측성

관리 기능은 `admin-cmd` registry를 정본으로 한다. [`registry.ts`](../../packages/admin-cmd/src/registry.ts)

추가 명령:

```text
create-shared-account
delete-shared-account
list-mailbox-acl
grant-mailbox-access
revoke-mailbox-access
set-mailbox-acl
link-directory-identity
unlink-directory-identity
sync-directory-groups
rebuild-message-headers
flush-listing-cache
```

각 명령은 label, arguments, destructive 여부, admin scope, output columns, audit event를
서술한다. API와 CLI는 registry에서 파생시키고 표면별로 직접 붙이지 않는다.

최소 metric:

```text
mailbox_acl_denied_total{operation}
mailbox_acl_changes_total
directory_bind_failures_total{provider,reason}
directory_group_sync_total{provider,result}
header_backfill_processed_total
header_backfill_errors_total{reason}
listing_cache_hits_total
listing_cache_misses_total{reason}
listing_query_duration_ms
```

password, bind credential, 전체 header 본문, 실제 directory filter를 로그에 남기지 않는다.

---

## 11. Migration과 배포 순서

현재 migration 정본은 `packages/db/src/index.ts`의 `allMigrations`다. 새 번호는 실제 마지막
migration 뒤에서 선택한다.

```text
M-020 principals + mailbox_acl + account_memberships + account/mailbox versions
M-021 external_identities + external_groups + principal_group_members
M-022 message_headers + typed header projections
M-023 listing indexes
```

실제 migration 파일과 `packages/db/src/index.ts`의 `allMigrations`에는 위 번호를 그대로
사용하고, `docs/SCHEMA.md`의 migration 표와 migration 전수 테스트도 같은 커밋에서 갱신한다.
기존 migration의 재실행·부분 적용·백업 복구를 SQLite, PostgreSQL, MySQL에서 각각 확인한다.

schema 변경과 대량 backfill은 같은 migration에 넣지 않는다.

배포 순서:

```text
1. M-A + 개인 account backfill, feature flag off
2. Store authorization read path, 개인 account 회귀 확인
3. shared account + IMAP ACL + namespace
4. JMAP accessible accounts + myRights
5. M-B + DirectoryProvider, directory login off
6. LDAP/AD fixture 검증 후 directory login 선택 활성화
7. M-C + ingest projection, 기존 필드 fallback 유지
8. header backfill 실행
9. M-D + query split
10. listing cache 관측 모드 후 실제 hit 활성화
```

migration 배포 전에는 운영 저장소의 DB backup/restore 절차를 수행한다. rollback은 기존
데이터를 DROP하는 방식이 아니라 feature flag off와 forward-fix migration으로 처리한다.

---

## 12. 위험과 대응

| 위험 | 대응 |
|---|---|
| ACL 검사가 한 경로에서 빠짐 | Store API를 PrincipalContext 기반으로 바꾸고 raw 함수 내부화 |
| shared/private 데이터 혼합 | shared account를 독립 accountId로 유지하고 모든 query에 account scope 적용 |
| IMAP/JMAP 권한 의미가 갈림 | rights 계산기 하나와 표면별 변환기만 허용 |
| LDAP stale group으로 권한 유지 | TTL, version, 민감 write/admin 권한 stale deny |
| LDAP transport 직접 구현 오류 | 별도 package, RFC fixture, 실제 directory fixture 병행 |
| listing cache 권한 누출 | key에 principalId·ACL version 포함 |
| header projection이 원본 대체 | BlobStore 원본 불변·projection 재생성 가능 |
| backfill이 foreground를 압박 | writer queue·checkpoint·rate limit·별도 metric |
| backend별 index 불일치 | 공통 SQL subset과 adapter 계약 테스트 |

---

## 13. 최종 수용 기준

### 기능

- [ ] shared account 생성·삭제
- [ ] 계정·group mailbox 권한 부여·회수
- [ ] IMAP ACL 5개 명령
- [ ] JMAP Session shared account 및 `myRights`
- [ ] JMAP partial account access가 Mailbox/Email/Thread/blob 전체에서 적용됨
- [ ] LDAP/AD external identity와 group 매핑
- [ ] allowlist header ingest 및 기존 메시지 backfill
- [ ] listing query 분리·index·bounded LRU

### 보안과 정합성

- [ ] 모든 mailbox read/write가 Store authorization 통과
- [ ] 개인/shared account 데이터 경계 유지
- [ ] ACL 변경 원자성
- [ ] ACL 변경 후 이전 cache 재사용 불가
- [ ] `permissions_version`/`acl_version`이 관련 cache와 JMAP Mailbox state를 무효화
- [ ] directory 장애 시 fail closed
- [ ] 민감정보가 로그에 없음

### 검증

```bash
npm run lint
npm run typecheck
npm test
npm run smoke
npm run verify
```

추가로 IMAP ACL interoperability, JMAP shared account end-to-end, LDAP/AD integration,
대형 mailbox EXPLAIN/latency, cache isolation, migration restore rehearsal을 수행한다.

---

## 14. 실행 배치 요약

```text
P0 ADR·계약 고정
P1 principals/mailbox_acl schema + rights parser
P2 Store authorization + 개인 account 회귀
P3 shared account provisioning + IMAP namespace
P4 IMAP ACL commands
P5 JMAP accessible accounts + myRights
P6 DirectoryProvider + LDAP/AD mapping
P7 message_headers + ingest projection + backfill
P8 listing query split + indexes + bounded LRU
P9 admin commands/API/CLI + metrics
P10 full interoperability/load/restore verification
```

성공 기준은 DBMail과 기능 수를 맞추는 것이 아니다. 다음 세 가지가 동시에 성립해야 한다.

1. 여러 개인 사용자와 directory group이 shared mailbox를 안전하게 사용한다.
2. IMAP·JMAP·관리 API가 같은 권한 판정을 사용한다.
3. header/listing 최적화가 권한·modseq·원본 MIME 정합성을 훼손하지 않는다.
