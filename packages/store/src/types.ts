import type { AddressKind } from "@ionosphere/db";
/** Store 연산 입출력 타입 — SCHEMA.md §7 레시피의 앱 레벨 계약. */

export interface CreateAccountInput {
  tenantId: string;
  email: string;
}

export interface CreateAccountResult {
  accountId: string;
  mailboxId: string;
}

export interface CreateMailboxInput {
  accountId: string;
  name: string;
  /** 생략 시 루트('') — SCHEMA.md §5-1 parent_id 센티널. */
  parentId?: string;
  role?: string;
}

export interface CreateMailboxResult {
  mailboxId: string;
  uidvalidity: number;
}

/** message_addresses 한 행 — kind/pos는 앱(프로토콜 레이어)이 사전 계산해 전달.
 * kind는 @ionosphere/db의 AddressKind 유니온 — number로 두면 인코딩 변경이 조용히 어긋난다. */
export interface AppendAddress {
  kind: AddressKind;
  pos: number;
  name: string | null;
  email: string;
}

export interface AppendEnvelope {
  subject: string | null;
  subjectBase: string | null;
  msgidHash: string | null;
  sentAt: number | null;
  preview: string | null;
  hasAttachment: boolean;
  addresses: readonly AppendAddress[];
  /** 스레딩용 참조 해시(자기 msgid_hash 포함 여부는 호출자 책임) — SCHEMA.md §5-3. */
  threadRefHashes: readonly string[];
}

/**
 * 검색 색인용 필드별 원문 텍스트 (SCHEMA.md §8) — appendMessage의 envelope에는 본문
 * 전체가 없으므로 호출자(백엔드)가 ParsedMessage에서 뽑아 별도로 전달한다.
 * 생략하면(undefined) message_text/search_index를 채우지 않는다(하위 호환 — 기존
 * appendMessage 호출부는 수정 없이 그대로 동작).
 *
 * ## 두 테이블의 **독자가 다르다** (2026-08-24 확정)
 *
 * 같은 입력에서 두 가지가 나가는데 용도가 갈린다. 여기 적어 두는 이유는, 예전에 이 계약이
 * 아무 데도 없어서 `message_text`가 "쓰기만 하고 아무도 읽지 않는 테이블"로 1년을 있었기
 * 때문이다 — 제목과 본문이 들어가는 테이블이라 순수 비용이자 프라이버시 표면이었다.
 *
 *  · `search_index` — **토큰**(단어/CJK 바이그램). 독자는 JMAP `Email/query`의
 *    `text`/`subject`/`body` 필터다. RFC 8621의 그 필터는 **구현체 정의**라 토큰 의미가
 *    허용된다. IMAP `SEARCH`는 이걸 **쓰지 않는다** — 부분 문자열이라 의미가 다르고,
 *    선필터로 쓰면 거짓 음성이 생긴다(proto-imap `search-criteria.ts` 머리 주석).
 *  · `message_text` — **원문 그대로**. 독자는 JMAP `SearchSnippet/get`(RFC 8621 §5)
 *    하나뿐이다(`getMessageTextForSnippets`). 조각에 "검색어가 어디 있는지"를 보여 주려면
 *    토큰이 아니라 원문이 있어야 한다.
 *
 * ⚠ `SearchSnippet/get`을 없애면 `message_text` **쓰기도 함께 없애야 한다.** 독자가 하나뿐인
 * 테이블이라 그 하나가 사라지면 다시 "아무도 안 읽는 저장"으로 돌아간다.
 */
export interface AppendSearchText {
  subject?: string;
  body?: string;
  from?: string;
  to?: string;
}

export interface AppendMessageInput {
  accountId: string;
  mailboxIds: readonly string[];
  blobId: string;
  /**
   * `putBlob()`이 실제로 기록한 세대. 생략 시 0(신규 블롭).
   * GC가 doomed로 찍은 블롭을 부활시킬 때만 0이 아니다 — SCHEMA.md §9-5 라이터 규칙.
   */
  blobGeneration?: number;
  sizeBytes: number;
  receivedAt: number;
  envelope: AppendEnvelope;
  /** 임의 케이싱 허용 — 스토어가 소문자로 정규화해 저장(SCHEMA.md §5-3). */
  keywords: readonly string[];
  /** 검색 색인 입력 — 생략 시 색인 생략(§8). */
  searchText?: AppendSearchText;
}

export interface AppendMessageResult {
  messageId: string;
  threadId: string;
  /** mailboxId → 그 메일함에서 할당된 UID. */
  uids: Map<string, number>;
  modseq: number;
}

export interface SetKeywordsInput {
  accountId: string;
  messageId: string;
  add: readonly string[];
  remove: readonly string[];
}

export interface SetDeletedInput {
  accountId: string;
  mailboxId: string;
  uids: readonly number[];
  deleted: boolean;
}

export interface ExpungeInput {
  accountId: string;
  mailboxId: string;
  /** 지정 시 해당 UID의 deleted=1만 삭제(UIDPLUS UID EXPUNGE). 생략 시 전체. */
  uids?: readonly number[];
}

export interface ExpungeResult {
  /** 툼스톤이 기록된 (uid, modseq) 목록. */
  expunged: readonly { uid: number; modseq: number }[];
}

export interface MoveMessageInput {
  accountId: string;
  messageId: string;
  fromMailboxId: string;
  toMailboxId: string;
}

/** IMAP COPY — 원본 유지, 대상 메일함에 membership 추가(메시지 row 공유). */
export interface CopyMessageInput {
  accountId: string;
  messageId: string;
  toMailboxId: string;
}

export interface DeleteMailboxInput {
  accountId: string;
  mailboxId: string;
}

export interface RenameMailboxInput {
  accountId: string;
  mailboxId: string;
  /** '' = 루트. */
  newParentId: string;
  newName: string;
}

export interface MoveMessageResult {
  uid: number;
  modseq: number;
}

/** listMessages() 행 — POP3 maildrop 뷰. */
export interface MessageListItem {
  uid: number;
  messageId: string;
  sizeBytes: number;
  deleted: boolean;
}

export interface MessageBlobRef {
  blobId: string;
  generation: number;
}

/** Store 생성자 옵션. */
export interface StoreOptions {
  /**
   * false면 body 필드는 색인/검색 대상에서 제외(subject/from/to만 색인) — SCHEMA.md §8
   * D1 어댑터 기본값(10GB 한도, body 역색인 제외). 기본값 true.
   */
  searchIndexBody?: boolean;
  /**
   * DB 보관 비밀의 봉인 키(secretbox). 미지정 시 `plain$` **평문 저장** — DKIM 개인키·
   * 스마트호스트 비밀번호와 같은 규율이고, 부팅 게이트도 같은 것을 쓴다
   * (`apps/server/src/main.ts`의 `assertSecretsAtRest`). 여기서 중복 게이트를 만들지 않는 이유:
   * 게이트가 두 곳에 있으면 한쪽만 완화됐을 때 조용히 평문으로 돌아간다.
   *
   * 현재 소비처는 `webhook_endpoints.secret`(정본) 뿐이다. DKIM 키는 조립층이 직접 복호한다.
   */
  masterKey?: string;
}

export interface SearchOptions {
  /** 기본 50. */
  limit?: number;
}

/** Store.search() 결과 행. uid는 메시지가 여러 메일함에 속할 수 있어 v1에서는 채우지 않는다. */
export interface SearchHit {
  messageId: string;
  uid?: number;
}

export interface AccountRow {
  id: string;
  tenantId: string;
  email: string;
  status: number;
  modseq: number;
  quotaBytes: number;
  usedBytes: number;
  messageCount: number;
}

/** JMAP 타입별 state 고수위 문자열 (SCHEMA §6-3 accounts.state_*). */
export interface JmapStates {
  email: string;
  mailbox: string;
  thread: string;
  submission: string;
}

/** change_log 엔티티 (SCHEMA §6-1). */
export type JmapEntity = "email" | "mailbox" | "thread" | "submission";

/** JMAP Email/get용 메시지 메타(블롭 제외 — 본문은 어댑터가 blobId로 별도 조회). */
export interface JmapEmailMeta {
  id: string;
  blobId: string;
  blobGeneration: number;
  threadId: string;
  size: number;
  receivedAt: number;
  subject: string | null;
  sentAt: number | null;
  hasAttachment: boolean;
  preview: string | null;
  mailboxIds: string[];
  /** message_keywords 원형(소문자 $seen 등) — JMAP keywords와 동일 표기. */
  keywords: string[];
  addresses: { kind: AddressKind; name: string | null; email: string }[];
}

/** Email/query 필터(v1 부분집합). */
export interface JmapEmailFilter {
  inMailbox?: string;
  before?: number;
  after?: number;
  minSize?: number;
  maxSize?: number;
  hasKeyword?: string;
  notKeyword?: string;
  /** RFC 8621 §4.4.1 전문 검색 — CJK 바이그램 FTS(search_index). 각 값의 모든 토큰 AND. */
  text?: string; // 모든 인덱스 필드(subject/body/from/to)
  subject?: string;
  body?: string;
  from?: string;
  to?: string;
}

export interface JmapEmailQueryResult {
  ids: string[];
  total: number;
}

/** 테넌트 사용량 스냅샷(PLAN §SaaS 미터링) — 청구/쿼터용 집계. 관측성(Prometheus)과는 별개. */
export interface TenantUsage {
  tenantId: string;
  /** 계정 수(전체) / 정지 아닌(status=1) 계정 수. */
  accounts: number;
  activeAccounts: number;
  /** 저장 메시지 총수 · 총 바이트 · 할당 쿼터 합(계정 카운터 합산). */
  messages: number;
  storageBytes: number;
  quotaBytes: number;
  /** 최근 창(기본 30일) 발송 미터 — 배달완료/바운스/대기 수(mta_queue). */
  window: { sinceMs: number; delivered: number; bounced: number; pending: number };
}

/**
 * JMAP `/changes` 결과 (RFC 8620 §5.2). cannotCalculate=true면 클라이언트가 전체 재동기화
 * (sinceState < changelog_floor 또는 잘못된 state). id는 dedup·§6-1 규칙 적용 완료.
 */
export type JmapChanges =
  | { cannotCalculate: true }
  | {
      cannotCalculate: false;
      oldState: string;
      newState: string;
      hasMoreChanges: boolean;
      created: string[];
      updated: string[];
      destroyed: string[];
    };

export interface MailboxRow {
  id: string;
  accountId: string;
  parentId: string;
  name: string;
  role: string | null;
  status: number;
  uidvalidity: number;
  uidnext: number;
  highestmodseq: number;
  totalCount: number;
  unreadCount: number;
  totalBytes: number;
  /** IMAP SUBSCRIBE 상태 (SCHEMA §5-1 subscribed, 기본 1). */
  subscribed: boolean;
}
