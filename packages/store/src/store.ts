/**
 * Store — 메시지 스토어 쓰기/읽기 경로 (SCHEMA.md §7 레시피 계약의 구현).
 *
 * 동시성 (SCHEMA.md §3):
 * - 1차 직렬화: 계정별 WriterQueue (§3-1) — 모든 계정 스코프 쓰기가 경유
 * - 2차 안전망: modseq_claims 낙관 잠금 (§3-2) — BatchConflictError 시 재시도(§3-3/§7-8)
 * - "재시도 가능한 클레임 경합" vs "시맨틱 충돌"(이름 중복 등)을 구분: 후자는 스냅샷
 *   재검증 단계에서 즉시 StoreError를 던지고 재시도 루프에 진입하지 않는다.
 */
import { ulid } from "@ionosphere/core";
import {
  BatchConflictError,
  BLOB_STATUS,
  isAddressKind,
  MTA_QUEUE_STATUS,
  PENDING_QUEUE_STATUSES,
  REF_KIND,
  type AddressKind,
  type DbDriver,
  type Statement,
} from "@ionosphere/db";
import { chunk, MAX_PARAMS_PER_STATEMENT, multiRowInsertStatements, queryInChunks, rowsPerStatement } from "./chunk.ts";
import { StoreConflictError, StoreError, StoreQuotaError } from "./errors.ts";
import { CHANGE_KIND, CHANGE_LOG_SQL, ENTITY, SEARCH_FIELD } from "./codes.ts";
import {
  createSubmission,
  getEmailsForJmap,
  getMessageTextForSnippets,
  getIdentities,
  getSubmissions,
  getThreadsForJmap,
  jmapChanges,
  jmapState,
  queryEmails,
} from "./jmap-store.ts";
import { tenantUsage } from "./usage-store.ts";
import type { AccountSnapshot, StoreInternals } from "./internals.ts";
import {
  deleteSieveScript,
  getActiveSieveScript,
  getSieveScript,
  listSieveScripts,
  putSieveScript,
  renameSieveScript,
  setActiveSieveScript,
} from "./sieve-store.ts";
import {
  addWebhookEndpoint,
  deleteWebhookEndpoint,
  enqueueWebhookDeliveries,
  listWebhookEndpoints,
} from "./webhook-store.ts";

import { tokenize, tokenizeQuery } from "./tokenize.ts";
import type {
  AccountRow,
  AppendMessageInput,
  AppendMessageResult,
  AppendSearchText,
  CreateAccountInput,
  CreateAccountResult,
  CreateMailboxInput,
  CreateMailboxResult,
  ExpungeInput,
  JmapChanges,
  JmapEmailFilter,
  JmapEmailMeta,
  JmapEmailQueryResult,
  JmapEntity,
  JmapStates,
  ExpungeResult,
  MailboxRow,
  MessageBlobRef,
  MessageListItem,
  CopyMessageInput,
  DeleteMailboxInput,
  MoveMessageInput,
  RenameMailboxInput,
  MoveMessageResult,
  SearchHit,
  SearchOptions,
  SetDeletedInput,
  SetKeywordsInput,
  StoreOptions,
  TenantUsage,
} from "./types.ts";
import { WriterQueue } from "./writer-queue.ts";

/** change_log.entity (SCHEMA.md §6-1) — enum 금지 정책이라 평범한 상수 객체로. */
/** change_log.kind (SCHEMA.md §6-1). */
/** blob_refs.ref_kind (SCHEMA.md §9-5). */
/** search_index.field / message_text.field (SCHEMA.md §8) — enum 금지 정책이라 평범한 상수 객체로. */
/** Store.search() 기본 결과 상한. */
const DEFAULT_SEARCH_LIMIT = 50;

/**
 * COPY 사본의 검색 부산물을 한 배치에 몇 문장까지 실을지. 토큰 하나가 문장 하나라
 * 큰 메일 여러 통이면 수천 문장이 되고, 그게 한 트랜잭션이면 라이터를 그만큼 붙잡는다.
 */
const COPY_ARTIFACT_STATEMENTS_PER_BATCH = 256;

const BLOB_UPSERT_COLUMNS = ["id", "size_bytes", "backend", "status", "generation", "created_at"] as const;

/**
 * 코얼레싱 그룹 최대 크기. 배치가 커질수록 커밋 오버헤드 절감은 포화되는 반면 한 트랜잭션이
 * 라이터를 붙잡는 시간과 실패 시 개별 폴백 비용은 선형으로 늘어난다. 32면 커밋 1회 비용이
 * 메시지당 0.0125ms까지 희석돼 이미 무시할 수준이다.
 */
const MAX_APPEND_GROUP = 32;

/**
 * 한 그룹 배치가 라이터를 붙잡는 시간의 보수적 상한(ms).
 *
 * 라이브 리눅스 실측: append 1건 ≈ 1.05ms(그중 커밋 0.40ms). 그룹은 커밋을 1회로 줄이므로
 * 32건 ≈ 32×0.65 + 0.40 ≈ 21ms. 느린 디스크·경합을 감안해 넉넉히 잡는다.
 */
const MAX_GROUP_COMMIT_MS = 40;

/**
 * 재시도 상한(§3-3) — 소진 시 StoreConflictError.
 *
 * ★멀티 인스턴스 전제로 재조정했다. 예전 값(5회, 지터 2^attempt)은 총 대기가 약 30ms라
 * **코얼레싱된 배치 하나가 커밋되는 시간(최대 ~40ms)보다도 짧았다.** 인프로세스에서는 라이터
 * 큐가 직렬화해 애초에 충돌할 상대가 없어 드러나지 않았지만, 서버를 나누면 다른 노드의 배치를
 * 통째로 기다려야 하므로 예산이 부족해 LMTP/SMTP에 4xx tempfail로 표면화된다.
 * 아래 값(10회 = 대기 9번, 상한 40ms)이면 총 대기가 **최소 183ms · 기대 274ms**로 최악 배치의
 * 4.6배를 견딘다. 여러 노드가 동시에 경합해도 몇 개까지는 흡수된다.
 * 그래도 소진되면 4xx tempfail이 맞다 — 무한정 늘리면 수신 지연이 클라이언트 타임아웃이 된다.
 */
const MAX_RETRY_ATTEMPTS = 10;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** 행들을 key로 묶어 value 배열로. 순서는 입력 순서 유지. */

/**
 * 지터 백오프 — 2^attempt ms 기저 + 동일 폭의 난수(full jitter로 재시도가 한꺼번에 몰리는 것 방지).
 *
 * 상한을 MAX_GROUP_COMMIT_MS로 두는 이유: 한 번의 대기가 "남의 배치 한 개"보다 훨씬 길어질 필요는
 * 없고, 무한정 커지면 정상 경합에서도 지연이 눈에 띄게 된다. 대신 시도 횟수로 총 예산을 확보한다.
 */
function jitterMs(attempt: number): number {
  const base = Math.min(2 ** attempt, MAX_GROUP_COMMIT_MS);
  return base + Math.random() * base;
}

function mapAccountRow(row: Record<string, unknown>): AccountRow {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    email: String(row.email),
    status: Number(row.status),
    modseq: Number(row.modseq),
    quotaBytes: Number(row.quota_bytes),
    usedBytes: Number(row.used_bytes),
    messageCount: Number(row.message_count),
  };
}

function mapMailboxRow(row: Record<string, unknown>): MailboxRow {
  return {
    id: String(row.id),
    accountId: String(row.account_id),
    parentId: String(row.parent_id),
    name: String(row.name),
    role: row.role == null ? null : String(row.role),
    status: Number(row.status),
    uidvalidity: Number(row.uidvalidity),
    uidnext: Number(row.uidnext),
    highestmodseq: Number(row.highestmodseq),
    totalCount: Number(row.total_count),
    unreadCount: Number(row.unread_count),
    totalBytes: Number(row.total_bytes),
    subscribed: Number(row.subscribed ?? 1) === 1,
    // 이 컬럼을 안 실어 온 질의도 있으므로 0(=아직 안 지웠다)로 떨어뜨린다.
    expungedFloor: Number(row.expunged_floor ?? 0),
  };
}

export class Store {
  private readonly db: DbDriver;
  private readonly writer = new WriterQueue();
  private readonly searchIndexBody: boolean;
  /** 하위 스토어 모듈(Sieve·웹훅 등)에 넘기는 내부 표면 — private 헬퍼를 노출하지 않는다. */
  private readonly internals: StoreInternals;

  constructor(db: DbDriver, opts: StoreOptions = {}) {
    this.db = db;
    this.searchIndexBody = opts.searchIndexBody ?? true;
    this.internals = {
      db: this.db,
      masterKey: opts.masterKey,
      writer: this.writer,
      withRetry: (fn) => this.withRetry(fn),
      mustGetAccount: (id) => this.mustGetAccount(id),
    };
  }

  // ── 재시도 루프 (§3-3/§7-8) ────────────────────────────────────────────
  private async withRetry<T>(fn: () => Promise<T>): Promise<T> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
      try {
        return await fn();
      } catch (err) {
        if (!(err instanceof BatchConflictError)) throw err;
        lastErr = err;
        if (attempt < MAX_RETRY_ATTEMPTS - 1) {
          await sleep(jitterMs(attempt));
        }
      }
    }
    throw new StoreConflictError(
      `재시도 상한(${MAX_RETRY_ATTEMPTS}회) 도달 — modseq 클레임 경합 지속 (SCHEMA.md §3-3)`,
      lastErr,
    );
  }

  private async mustGetAccount(accountId: string): Promise<AccountSnapshot> {
    const { rows } = await this.db.query({
      sql: "SELECT modseq, quota_bytes, used_bytes, uidvalidity_last, status FROM accounts WHERE id = ?",
      params: [accountId],
    });
    const row = rows[0];
    if (!row) throw new StoreError(`account not found: ${accountId}`);
    if (Number(row.status) !== 1) throw new StoreError(`account not active: ${accountId}`);
    return {
      modseq: Number(row.modseq),
      quotaBytes: Number(row.quota_bytes),
      usedBytes: Number(row.used_bytes),
      uidvalidityLast: Number(row.uidvalidity_last),
    };
  }

  // ── 부트스트랩 연산 (기존 계정에 대한 클레임 배치가 아니라 단발 생성) ─────
  async createTenant(name: string): Promise<{ tenantId: string }> {
    const id = ulid();
    const now = Date.now();
    await this.db.batch([
      { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, ?)", params: [id, name, now] },
    ]);
    return { tenantId: id };
  }

  async createAccount(input: CreateAccountInput): Promise<CreateAccountResult> {
    const email = input.email.toLowerCase(); // §2: 주소 정규화 소문자는 앱이 보장
    const { rows: tenantRows } = await this.db.query({
      sql: "SELECT id FROM tenants WHERE id = ?",
      params: [input.tenantId],
    });
    if (tenantRows.length === 0) throw new StoreError(`tenant not found: ${input.tenantId}`);

    const accountId = ulid();
    const mailboxId = ulid();
    const now = Date.now();
    // §5-1: max(epoch초, uidvalidity_last+1). 신규 계정의 uidvalidity_last 초기값은 0.
    const uidvalidity = Math.max(Math.floor(now / 1000), 1);

    try {
      await this.db.batch([
        {
          sql: `INSERT INTO accounts (id, tenant_id, email, kind, status, modseq, changelog_floor, uidvalidity_last, quota_bytes, used_bytes, message_count, state_email, state_mailbox, state_thread, state_submission, state_sieve, created_at)
                VALUES (?, ?, ?, 0, 1, 0, 0, ?, 0, 0, 0, 0, 0, 0, 0, 0, ?)`,
          params: [accountId, input.tenantId, email, uidvalidity, now],
        },
        {
          // 계정 생성 시 INBOX 자동 생성 (role='inbox') — 아직 어떤 클라이언트도 관측할 수 없는
          // 부트스트랩 상태라 change_log는 남기지 않는다(state_mailbox=0으로 유지, Mailbox/get은
          // change_log 없이도 현재 존재하는 객체를 그대로 반환하므로 초기 동기화에 문제 없음).
          sql: `INSERT INTO mailboxes (id, account_id, parent_id, name, role, status, uidvalidity, uidnext, highestmodseq, subscribed, sort_order, total_count, unread_count, total_bytes, created_at)
                VALUES (?, ?, '', 'INBOX', 'inbox', 1, ?, 1, 0, 1, 0, 0, 0, 0, ?)`,
          params: [mailboxId, accountId, uidvalidity, now],
        },
      ]);
    } catch (err) {
      if (err instanceof BatchConflictError) {
        // ux_accounts_email 충돌 — 시맨틱 충돌(이메일 중복)이지 재시도 대상 클레임 경합이 아님
        const { rows } = await this.db.query({ sql: "SELECT id FROM accounts WHERE email = ?", params: [email] });
        if (rows.length > 0) throw new StoreError(`account email already exists: ${email}`);
      }
      throw err;
    }

    return { accountId, mailboxId };
  }

  // ── 메일함 ──────────────────────────────────────────────────────────
  async createMailbox(input: CreateMailboxInput): Promise<CreateMailboxResult> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.createMailboxAttempt(input)));
  }

  private async createMailboxAttempt(input: CreateMailboxInput): Promise<CreateMailboxResult> {
    const acct = await this.mustGetAccount(input.accountId);
    const parentId = input.parentId ?? "";

    if (parentId !== "") {
      const { rows } = await this.db.query({
        sql: "SELECT id FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
        params: [parentId, input.accountId],
      });
      if (rows.length === 0) throw new StoreError(`parent mailbox not found: ${parentId}`);
    }

    // ux_mailboxes_name 사전 검사 — 시맨틱 충돌은 재시도하지 않고 즉시 던진다(§7-8).
    // 재시도 루프가 이 메서드를 다시 호출할 때마다 이 검사도 스냅샷과 함께 재수행된다.
    const { rows: existing } = await this.db.query({
      sql: "SELECT id FROM mailboxes WHERE account_id = ? AND parent_id = ? AND name = ?",
      params: [input.accountId, parentId, input.name],
    });
    if (existing.length > 0) throw new StoreError(`mailbox name already exists: ${input.name}`);

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const uidvalidity = Math.max(Math.floor(now / 1000), acct.uidvalidityLast + 1);
    const mailboxId = ulid();

    await this.db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
      {
        sql: `INSERT INTO mailboxes (id, account_id, parent_id, name, role, status, uidvalidity, uidnext, highestmodseq, subscribed, sort_order, total_count, unread_count, total_bytes, created_at)
              VALUES (?, ?, ?, ?, ?, 1, ?, 1, ?, 1, 0, 0, 0, 0, ?)`,
        params: [mailboxId, input.accountId, parentId, input.name, input.role ?? null, uidvalidity, nextModseq, now],
      },
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, mailboxId, CHANGE_KIND.created, now] },
      {
        sql: "UPDATE accounts SET modseq = ?, state_mailbox = ?, uidvalidity_last = ? WHERE id = ?",
        params: [nextModseq, nextModseq, uidvalidity, input.accountId],
      },
    ]);

    return { mailboxId, uidvalidity };
  }

  /**
   * 메일함 삭제 1단계 (§7-7) — status=2 전환 + 유니크 키 비우기(name을 id 센티널로).
   * 같은 이름 즉시 재생성(imaptest DELETE+CREATE)이 가능해진다. membership/메시지
   * 정리는 2단계 리퍼 소관(미구현 — 백그라운드 잡). 활성 자식이 있으면 거부.
   */
  async deleteMailbox(input: DeleteMailboxInput): Promise<void> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.deleteMailboxAttempt(input)));
  }

  private async deleteMailboxAttempt(input: DeleteMailboxInput): Promise<void> {
    const acct = await this.mustGetAccount(input.accountId);
    const { rows } = await this.db.query({
      sql: "SELECT id, role FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
      params: [input.mailboxId, input.accountId],
    });
    if (rows.length === 0) throw new StoreError(`mailbox not found or inactive: ${input.mailboxId}`);
    if (String(rows[0]?.role ?? "") === "inbox") throw new StoreError("cannot delete INBOX");

    const { rows: children } = await this.db.query({
      sql: "SELECT id FROM mailboxes WHERE account_id = ? AND parent_id = ? AND status = 1",
      params: [input.accountId, input.mailboxId],
    });
    if (children.length > 0) throw new StoreError("mailbox has children");

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    await this.db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
      {
        // name/parent를 자기 id 센티널로 — ux_mailboxes_name 해제(즉시 재생성 가능)
        sql: "UPDATE mailboxes SET status = 2, name = ?, parent_id = '', highestmodseq = ? WHERE id = ?",
        params: [input.mailboxId, nextModseq, input.mailboxId],
      },
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.mailboxId, CHANGE_KIND.destroyed, now] },
      {
        sql: "UPDATE accounts SET modseq = ?, state_mailbox = ? WHERE id = ?",
        params: [nextModseq, nextModseq, input.accountId],
      },
    ]);
  }

  /** 삭제(툼스톤 status=2) 대기 메일함 목록 — 2단계 리퍼가 배치로 수거. */
  async listReapableMailboxes(limit = 50): Promise<{ id: string; accountId: string }[]> {
    const { rows } = await this.db.query({
      sql: "SELECT id, account_id FROM mailboxes WHERE status = 2 ORDER BY highestmodseq LIMIT ?",
      params: [limit],
    });
    return rows.map((r) => ({ id: String(r.id), accountId: String(r.account_id) }));
  }

  /**
   * 메일함 삭제 2단계 (§7-7 리퍼) — 툼스톤 메일함의 membership/메시지를 실제로 정리하고 메일함
   * 행을 하드 삭제한다. 마지막 membership인 메시지는 완전 파기(계정 카운터·change_log destroyed),
   * 다른 메일함에도 있는 메시지는 detach만(Email updated). 활성(status=1) 메일함은 절대 건드리지 않음.
   * 반환: {purged, detached}.
   */
  async reapMailbox(accountId: string, mailboxId: string): Promise<{ purged: number; detached: number }> {
    return this.writer.run(accountId, () => this.withRetry(() => this.reapMailboxAttempt(accountId, mailboxId)));
  }

  private async reapMailboxAttempt(accountId: string, mailboxId: string): Promise<{ purged: number; detached: number }> {
    const { rows: mbx } = await this.db.query({
      sql: "SELECT id FROM mailboxes WHERE id = ? AND account_id = ? AND status = 2",
      params: [mailboxId, accountId],
    });
    if (mbx.length === 0) return { purged: 0, detached: 0 }; // 이미 수거됐거나 활성 — no-op

    const { rows: memRows } = await this.db.query({
      sql: `SELECT mm.message_id AS message_id, m.size_bytes AS size_bytes
            FROM message_mailbox mm JOIN messages m ON m.id = mm.message_id WHERE mm.mailbox_id = ?`,
      params: [mailboxId],
    });

    const now = Date.now();
    const stmts: Statement[] = [];
    let purged = 0;
    let detached = 0;

    if (memRows.length > 0) {
      const acct = await this.mustGetAccount(accountId);
      const messageIds = [...new Set(memRows.map((r) => String(r.message_id)))];
      const countRows = await queryInChunks(
        this.db,
        messageIds,
        (ph) => `SELECT message_id, COUNT(*) AS cnt FROM message_mailbox WHERE message_id IN (${ph}) GROUP BY message_id`,
      );
      const cnt = new Map(countRows.map((r) => [String(r.message_id), Number(r.cnt)]));
      const dying = messageIds.filter((id) => (cnt.get(id) ?? 0) <= 1);
      const dyingSet = new Set(dying);
      const surviving = messageIds.filter((id) => !dyingSet.has(id));

      const nextModseq = acct.modseq + 1;
      stmts.push({ sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [accountId, nextModseq] });
      stmts.push({ sql: "DELETE FROM message_mailbox WHERE mailbox_id = ?", params: [mailboxId] });

      for (const idChunk of chunk(dying, rowsPerStatement(1) - 1)) {
        const p = idChunk.map(() => "?").join(", ");
        stmts.push({ sql: `DELETE FROM messages WHERE id IN (${p})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM message_keywords WHERE message_id IN (${p})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM message_addresses WHERE message_id IN (${p})`, params: idChunk });
        // ★검색 부산물도 **여기서** 지운다. 예전엔 message_text·search_index만 남았고,
        //   message_text에는 제목과 본문 텍스트가 들어간다 — 사용자가 지운 메일의 본문이
        //   DB와 백업에 영구히 남는다는 뜻이었다(저장소 낭비 이전에 삭제 계약이 깨진 것).
        stmts.push({ sql: `DELETE FROM message_text WHERE message_id IN (${p})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM search_index WHERE message_id IN (${p})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM blob_refs WHERE ref_kind = ${REF_KIND.message} AND ref_id IN (${p})`, params: idChunk });
      }
      for (const id of dying) {
        stmts.push({ sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Email, id, CHANGE_KIND.destroyed, now] });
      }
      for (const idChunk of chunk(surviving, rowsPerStatement(1) - 1)) {
        const p = idChunk.map(() => "?").join(", ");
        stmts.push({ sql: `UPDATE messages SET modseq = ? WHERE id IN (${p})`, params: [nextModseq, ...idChunk] });
      }
      for (const id of surviving) {
        stmts.push({ sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Email, id, CHANGE_KIND.updated, now] });
      }

      const dyingBytes = memRows.filter((r) => dyingSet.has(String(r.message_id))).reduce((s, r) => s + Number(r.size_bytes), 0);
      stmts.push({
        sql: `UPDATE accounts SET modseq = ?, state_email = ?, used_bytes = used_bytes - ?, message_count = message_count - ? WHERE id = ?`,
        params: [nextModseq, nextModseq, dyingBytes, dying.length, accountId],
      });
      purged = dying.length;
      detached = surviving.length;
    }

    // expunged 잔재 정리 + 메일함 하드 삭제(툼스톤만)
    stmts.push({ sql: "DELETE FROM expunged WHERE mailbox_id = ?", params: [mailboxId] });
    stmts.push({ sql: "DELETE FROM mailboxes WHERE id = ? AND status = 2", params: [mailboxId] });
    await this.db.batch(stmts);
    return { purged, detached };
  }

  /** IMAP SUBSCRIBE/UNSUBSCRIBE 영속화 — 구독 플래그만 변경(카운터·modseq 배치 규율 준수). */
  async setSubscribed(accountId: string, mailboxId: string, subscribed: boolean): Promise<void> {
    return this.writer.run(accountId, () =>
      this.withRetry(async () => {
        const acct = await this.mustGetAccount(accountId);
        const { rows } = await this.db.query({
          sql: "SELECT subscribed FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
          params: [mailboxId, accountId],
        });
        if (rows.length === 0) throw new StoreError(`mailbox not found or inactive: ${mailboxId}`);
        const target = subscribed ? 1 : 0;
        if (Number(rows[0]?.subscribed) === target) return; // no-op — modseq 소모 없음
        const now = Date.now();
        const nextModseq = acct.modseq + 1;
        await this.db.batch([
          { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [accountId, nextModseq] },
          { sql: "UPDATE mailboxes SET subscribed = ?, highestmodseq = ? WHERE id = ?", params: [target, nextModseq, mailboxId] },
          { sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Mailbox, mailboxId, CHANGE_KIND.updated, now] },
          { sql: "UPDATE accounts SET modseq = ?, state_mailbox = ? WHERE id = ?", params: [nextModseq, nextModseq, accountId] },
        ]);
      }),
    );
  }

  /** 메일함 이름/위치 변경 — 자손 순환 방지 + 유니크 사전 검사(§7-8 시맨틱 충돌 즉시 던짐). */
  async renameMailbox(input: RenameMailboxInput): Promise<void> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.renameMailboxAttempt(input)));
  }

  private async renameMailboxAttempt(input: RenameMailboxInput): Promise<void> {
    const acct = await this.mustGetAccount(input.accountId);
    const { rows } = await this.db.query({
      sql: "SELECT id, role FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
      params: [input.mailboxId, input.accountId],
    });
    if (rows.length === 0) throw new StoreError(`mailbox not found or inactive: ${input.mailboxId}`);
    if (String(rows[0]?.role ?? "") === "inbox") throw new StoreError("cannot rename INBOX");

    if (input.newParentId !== "") {
      // 새 부모 존재 + 자기 자손 아님(순환 방지) — 부모 체인 상향 탐색
      let cursor: string = input.newParentId;
      for (let depth = 0; depth < 100 && cursor !== ""; depth++) {
        if (cursor === input.mailboxId) throw new StoreError("cannot move mailbox under its own descendant");
        const { rows: p } = await this.db.query({
          sql: "SELECT parent_id FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
          params: [cursor, input.accountId],
        });
        if (p.length === 0) throw new StoreError(`parent mailbox not found: ${input.newParentId}`);
        cursor = String(p[0]?.parent_id ?? "");
      }
    }

    const { rows: existing } = await this.db.query({
      sql: "SELECT id FROM mailboxes WHERE account_id = ? AND parent_id = ? AND name = ? AND id != ?",
      params: [input.accountId, input.newParentId, input.newName, input.mailboxId],
    });
    if (existing.length > 0) throw new StoreError(`mailbox name already exists: ${input.newName}`);

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    await this.db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
      {
        sql: "UPDATE mailboxes SET parent_id = ?, name = ?, highestmodseq = ? WHERE id = ?",
        params: [input.newParentId, input.newName, nextModseq, input.mailboxId],
      },
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.mailboxId, CHANGE_KIND.updated, now] },
      {
        sql: "UPDATE accounts SET modseq = ?, state_mailbox = ? WHERE id = ?",
        params: [nextModseq, nextModseq, input.accountId],
      },
    ]);
  }

  // ── 스레딩 (§5-3) ───────────────────────────────────────────────────
  private async resolveThread(accountId: string, hashes: readonly string[]): Promise<{ id: string; isNew: boolean }> {
    const uniqueHashes = [...new Set(hashes)];
    if (uniqueHashes.length === 0) return { id: ulid(), isNew: true };

    // lint-allow chunked-in-query: `GROUP BY thread_id … LIMIT 1`은 "가장 오래된 스레드 하나"를
    // 고르는 질의라 나눠 돌리면 답이 달라진다. 개수는 MAX_THREAD_REFS(64)가 상한이므로 안전하다.
    const placeholders = uniqueHashes.map(() => "?").join(", ");
    const { rows } = await this.db.query({
      sql: `SELECT thread_id, MIN(created_at) AS oldest FROM thread_refs
            WHERE account_id = ? AND ref_hash IN (${placeholders})
            GROUP BY thread_id ORDER BY oldest ASC LIMIT 1`,
      params: [accountId, ...uniqueHashes],
    });
    const row = rows[0];
    // no-merge 정책(§5-3): 여러 스레드에 매치해도 가장 오래된 것 하나만 채택, 병합하지 않음
    if (row) return { id: String(row.thread_id), isNew: false };
    return { id: ulid(), isNew: true };
  }

  private async getMailboxesForWrite(
    accountId: string,
    mailboxIds: readonly string[],
  ): Promise<{ id: string; uidnext: number }[]> {
    const ids = [...new Set(mailboxIds)];
    if (ids.length === 0) throw new StoreError("mailboxIds가 비어있음");
    // JMAP은 `maxMailboxesPerEmail: null`(무제한)을 광고하므로 이 목록도 유계가 아니다.
    const rows = await queryInChunks(
      this.db,
      ids,
      (ph) => `SELECT id, uidnext FROM mailboxes WHERE account_id = ? AND status = 1 AND id IN (${ph})`,
      [accountId],
    );
    const found = new Map(rows.map((r) => [String(r.id), Number(r.uidnext)]));
    for (const id of ids) {
      if (!found.has(id)) throw new StoreError(`mailbox not found or inactive: ${id}`);
    }
    return ids.map((id) => ({ id, uidnext: found.get(id)! }));
  }

  // ── AppendMessage (§7-1) ───────────────────────────────────────────
  /**
   * 메시지 1건 적재. 같은 계정에 동시에 몰린 적재는 라이터 큐가 한 배치로 합친다(§3-1) —
   * 호출자가 볼 수 있는 차이는 없다(WriterQueue.submitCoalesced 계약 주석 참조).
   */
  async appendMessage(input: AppendMessageInput): Promise<AppendMessageResult> {
    return this.writer.submitCoalesced(input.accountId, "append", input, this.runAppendGroup, MAX_APPEND_GROUP);
  }

  /**
   * 코얼레싱 그룹 실행부. 프로퍼티로 두는 이유는 **동일성**이다 — 매 호출 새 클로저를 만들면
   * 큐가 "같은 종류의 작업"인지 판별할 수 없다.
   */
  private readonly runAppendGroup = (items: AppendMessageInput[]): Promise<AppendMessageResult[]> =>
    this.withRetry(() => this.appendMessagesAttempt(items[0]!.accountId, items));

  /**
   * 같은 계정에 여러 메시지를 **한 배치**로 적재한다 (SCHEMA.md §3-1 "호환 가능한 대기 작업을
   * 한 배치로 합침"). 라이터 큐가 버스트를 모아 이 경로로 넘긴다.
   *
   * 왜 합치는가(실측): 라이브 리눅스에서 append 1건이 약 1.05ms인데 그중 커밋 오버헤드가
   * 0.40ms다 — 즉 40%가 "일"이 아니라 "트랜잭션 경계" 비용이다. K건을 한 배치로 묶으면 그
   * 경계를 1회로 줄인다(macOS에서는 커밋이 0.018ms라 이 이득이 보이지 않는다 — 로컬 측정만
   * 믿고 최적화를 판단하면 안 되는 자리다).
   *
   * 원자성·불변식은 단건과 동일하다: modseq 1개를 그룹 전체가 공유하고(§3-3 전역 불변식은
   * "change_log를 쓴 모든 entity의 state_*"를 요구할 뿐 메시지당 modseq를 요구하지 않는다),
   * modseq_claims도 1행이다. 그룹 중 하나라도 실패하면 배치 전체가 롤백된다.
   */
  async appendMessages(inputs: readonly AppendMessageInput[]): Promise<AppendMessageResult[]> {
    if (inputs.length === 0) return [];
    const accountId = inputs[0]!.accountId;
    for (const i of inputs) {
      if (i.accountId !== accountId) throw new StoreError("appendMessages: 한 그룹은 같은 계정이어야 한다");
    }
    return this.writer.run(accountId, () => this.withRetry(() => this.appendMessagesAttempt(accountId, [...inputs])));
  }

  private async appendMessagesAttempt(
    accountId: string,
    inputs: readonly AppendMessageInput[],
  ): Promise<AppendMessageResult[]> {
    const acct = await this.mustGetAccount(accountId);

    // 쿼터 검사 — 스냅샷마다 재검증(§7-1/§7-8), quota_bytes=0이면 무제한.
    // 그룹은 합계로 본다: 개별로 통과하고 합계로 초과하면 쿼터가 뚫린다.
    const totalBytes = inputs.reduce((n, i) => n + i.sizeBytes, 0);
    if (acct.quotaBytes > 0 && acct.usedBytes + totalBytes > acct.quotaBytes) {
      throw new StoreQuotaError(`quota exceeded: account=${accountId}`);
    }

    // 대상 메일함은 그룹 전체의 합집합을 한 번만 조회하고, uidnext는 로컬 커서로 이어 붙인다.
    const allMailboxIds = [...new Set(inputs.flatMap((i) => i.mailboxIds))];
    const mailboxRows = await this.getMailboxesForWrite(accountId, allMailboxIds);
    const uidCursor = new Map(mailboxRows.map((m) => [m.id, m.uidnext]));

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [accountId, nextModseq] },
    ];
    const results: AppendMessageResult[] = [];
    /** 그룹 안에서 새로 만든 스레드 참조 — 커밋 전이라 DB 조회로는 보이지 않는다. */
    const pendingThreads = new Map<string, string>();
    /** 메일함별 누적 델타(카운터 UPDATE를 메시지마다 내지 않고 한 번에 낸다). */
    const mbxDelta = new Map<string, { count: number; bytes: number; unread: number }>();
    const threadTouched = new Map<string, boolean>(); // threadId → isNew

    for (const input of inputs) {
      const threadId = await this.resolveThreadInGroup(accountId, input.envelope.threadRefHashes, pendingThreads);
      const messageId = ulid();
      const keywordsLower = [...new Set(input.keywords.map((k) => k.toLowerCase()))]; // §5-3 소문자 저장
      const blobGeneration = input.blobGeneration ?? 0;
      const hasSeen = keywordsLower.includes("$seen");

      stmts.push(
        // blobs upsert (§1-5 승인 분기) — 동일 콘텐츠 재사용 시 충돌 없이 무시
        {
          sql: this.db.insertIgnore("blobs", BLOB_UPSERT_COLUMNS),
          params: [input.blobId, input.sizeBytes, 0, BLOB_STATUS.live, blobGeneration, now],
        },
        // 부활(§9-5 라이터 규칙): GC가 doomed로 찍어둔 블롭이면 위 insertIgnore가 아무것도 안 한다.
        // 참조가 생겼는데 행이 doomed로 남아 있으면 GC가 파일을 지워 본문이 사라지므로, 여기서
        // 반드시 live로 되돌린다. generation은 되돌아가면 안 되므로(GC가 "이 세대 이하"만 지운다)
        // 단조 증가 가드를 건다.
        {
          sql: "UPDATE blobs SET status = ?, doomed_at = NULL, generation = ? WHERE id = ? AND generation <= ?",
          params: [BLOB_STATUS.live, blobGeneration, input.blobId, blobGeneration],
        },
        {
          sql: "INSERT INTO blob_refs (blob_id, account_id, ref_kind, ref_id, created_at) VALUES (?, ?, ?, ?, ?)",
          params: [input.blobId, accountId, REF_KIND.message, messageId, now],
        },
        {
          sql: `INSERT INTO messages (id, account_id, blob_id, thread_id, modseq, size_bytes, received_at, subject, subject_base, msgid_hash, sent_at, preview, has_attachment, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          params: [
            messageId,
            accountId,
            input.blobId,
            threadId.id,
            nextModseq,
            input.sizeBytes,
            input.receivedAt,
            input.envelope.subject,
            input.envelope.subjectBase,
            input.envelope.msgidHash,
            input.envelope.sentAt,
            input.envelope.preview,
            input.envelope.hasAttachment ? 1 : 0,
            now,
          ],
        },
      );

      // message_addresses / message_keywords — 다중행 청크(§7-6)
      const addrRows = input.envelope.addresses.map((a) => [accountId, messageId, a.kind, a.pos, a.name, a.email]);
      stmts.push(
        ...multiRowInsertStatements("message_addresses", ["account_id", "message_id", "kind", "pos", "name", "email"], addrRows),
      );
      const kwRows = keywordsLower.map((k) => [accountId, messageId, k]);
      stmts.push(...multiRowInsertStatements("message_keywords", ["account_id", "message_id", "keyword"], kwRows));

      // message_auth — Phase 2 인증 파이프라인 몫 (의도적 생략)
      // message_text / search_index는 아래에서 core batch 커밋 후 후속 배치로 채운다(§7-1: 검색은
      // eventual consistency 허용 — 원자적 core batch를 불리지 않는다).

      // thread_refs — insertIgnore는 단일행 SQL만 생성하므로 해시별 개별 문장
      const threadRefSql = this.db.insertIgnore("thread_refs", ["account_id", "ref_hash", "thread_id", "created_at"]);
      for (const refHash of new Set(input.envelope.threadRefHashes)) {
        stmts.push({ sql: threadRefSql, params: [accountId, refHash, threadId.id, now] });
      }

      // message_mailbox — 대상 메일함마다 UID 사전 할당(§1-2: RETURNING 금지, 앱이 사전 계산).
      // 그룹 안에서 같은 메일함에 여러 통이 들어가면 커서를 이어 붙여 UID가 겹치지 않게 한다.
      const uids = new Map<string, number>();
      const mmRows: unknown[][] = [];
      for (const mbxId of new Set(input.mailboxIds)) {
        const uid = uidCursor.get(mbxId)!;
        uidCursor.set(mbxId, uid + 1);
        uids.set(mbxId, uid);
        mmRows.push([mbxId, uid, messageId, now, 0]);
        const d = mbxDelta.get(mbxId) ?? { count: 0, bytes: 0, unread: 0 };
        d.count += 1;
        d.bytes += input.sizeBytes;
        if (!hasSeen) d.unread += 1;
        mbxDelta.set(mbxId, d);
      }
      stmts.push(
        ...multiRowInsertStatements("message_mailbox", ["mailbox_id", "uid", "message_id", "savedate", "deleted"], mmRows),
      );

      // change_log — Email은 메시지마다, Mailbox/Thread는 그룹 끝에서 한 번씩(§3-3/§7-1)
      stmts.push({ sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Email, messageId, CHANGE_KIND.created, now] });
      // 같은 스레드에 여러 통이 붙으면 "새로 생김"이 우선(첫 통이 만들었으므로)
      threadTouched.set(threadId.id, (threadTouched.get(threadId.id) ?? false) || threadId.isNew);

      results.push({ messageId, threadId: threadId.id, uids, modseq: nextModseq });
    }

    for (const mbxId of mbxDelta.keys()) {
      stmts.push({ sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Mailbox, mbxId, CHANGE_KIND.updated, now] });
    }
    for (const [threadId, isNew] of threadTouched) {
      stmts.push({
        sql: CHANGE_LOG_SQL,
        params: [accountId, nextModseq, ENTITY.Thread, threadId, isNew ? CHANGE_KIND.created : CHANGE_KIND.updated, now],
      });
    }

    // 메일함 카운터 — 누적 델타를 메일함당 UPDATE 한 번으로(§7-1)
    for (const [mbxId, d] of mbxDelta) {
      stmts.push({
        sql: `UPDATE mailboxes SET uidnext = ?, total_count = total_count + ?, total_bytes = total_bytes + ?, highestmodseq = ?${
          d.unread > 0 ? ", unread_count = unread_count + ?" : ""
        } WHERE id = ?`,
        params: d.unread > 0
          ? [uidCursor.get(mbxId)!, d.count, d.bytes, nextModseq, d.unread, mbxId]
          : [uidCursor.get(mbxId)!, d.count, d.bytes, nextModseq, mbxId],
      });
    }

    // 전역 불변식: accounts.modseq + change_log 쓴 모든 entity의 state_* (§3-3)
    stmts.push({
      sql: `UPDATE accounts SET used_bytes = used_bytes + ?, message_count = message_count + ?, modseq = ?, state_email = ?, state_mailbox = ?, state_thread = ? WHERE id = ?`,
      params: [totalBytes, inputs.length, nextModseq, nextModseq, nextModseq, nextModseq, accountId],
    });

    await this.db.batch(stmts);

    // 검색 색인 후속 배치 (§7-1/§8) — core batch 커밋 이후에만 시도. 여기서 실패해도
    // append 자체는 이미 성공했으므로 삼켜서 재시도 루프(withRetry)로 되돌리지 않는다
    // (되돌리면 core batch가 새 modseq로 통째로 재실행돼 메시지가 중복 생성된다).
    // 색인 **누락**(여기서 실패해 안 들어간 행)은 §7-4 질의 시 messages 조인 필터가 덮는다.
    // 색인 **고아**(메시지가 지워졌는데 남은 행)는 이제 없다 — 파기 경로가 함께 지운다(§7-4).
    for (const [i, input] of inputs.entries()) {
      if (!input.searchText) continue;
      try {
        await this.indexSearchText(accountId, results[i]!.messageId, input.searchText);
      } catch {
        // best-effort — 의도적으로 무시(위 주석 참조).
      }
    }

    return results;
  }

  /**
   * 그룹 안에서의 스레드 해석 — 커밋 전이라 앞선 메시지가 만든 thread_refs가 DB 조회로는
   * 보이지 않는다. 같은 배치에 같은 스레드 참조를 가진 두 통이 들어오면 서로 다른 스레드로
   * 갈라지므로, 로컬 오버레이를 먼저 본다.
   */
  private async resolveThreadInGroup(
    accountId: string,
    hashes: readonly string[],
    pending: Map<string, string>,
  ): Promise<{ id: string; isNew: boolean }> {
    for (const h of new Set(hashes)) {
      const local = pending.get(h);
      if (local !== undefined) return { id: local, isNew: false };
    }
    const resolved = await this.resolveThread(accountId, hashes);
    for (const h of new Set(hashes)) pending.set(h, resolved.id);
    return resolved;
  }

  /** message_text + search_index 채우기 — appendMessage의 후속 배치(§7-1/§8). */
  private async indexSearchText(accountId: string, messageId: string, searchText: AppendSearchText): Promise<void> {
    const fields: { field: number; text: string | undefined }[] = [
      { field: SEARCH_FIELD.subject, text: searchText.subject },
      { field: SEARCH_FIELD.from, text: searchText.from },
      { field: SEARCH_FIELD.to, text: searchText.to },
    ];
    if (this.searchIndexBody) {
      fields.push({ field: SEARCH_FIELD.body, text: searchText.body });
    }

    const textRows: unknown[][] = [];
    const indexRows: unknown[][] = [];
    for (const { field, text } of fields) {
      if (text == null || text === "") continue;
      textRows.push([messageId, field, text]);
      for (const token of tokenize(text)) {
        indexRows.push([accountId, token, field, messageId]);
      }
    }
    if (textRows.length === 0 && indexRows.length === 0) return;

    const stmts: Statement[] = [...multiRowInsertStatements("message_text", ["message_id", "field", "content"], textRows)];
    // insertIgnore는 단일행 SQL만 생성(§7-6 청크 헬퍼 docstring과 동일 이유) — 토큰별 개별 문장.
    // 같은 (account_id, token, field, message_id)는 PK라 재시도/중복 색인 시도에도 안전.
    const searchIndexSql = this.db.insertIgnore("search_index", ["account_id", "token", "field", "message_id"]);
    for (const row of indexRows) {
      stmts.push({ sql: searchIndexSql, params: row });
    }

    await this.db.batch(stmts);
  }

  // ── 검색 (§8) ─────────────────────────────────────────────────────────
  /**
   * 계정 스코프 토큰 AND 검색. 질의 토큰마다 search_index를 찾아 messages와 조인해
   * 고아 포스팅을 걸러내고(§7-4 지연 정리 계약), 모든 토큰을 포함하는(AND) 메시지만
   * received_at DESC로 반환한다.
   */
  async search(accountId: string, query: string, opts: SearchOptions = {}): Promise<SearchHit[]> {
    const tokens = tokenizeQuery(query);
    if (tokens.length === 0) return [];

    // IN 리스트 + account_id + HAVING count + LIMIT까지 한 문장 파라미터 100개 한도(§1-3) 안에
    // 들어와야 한다. 질의 토큰이 이 이상인 경우는 실사용에서 드물다고 SCHEMA.md §8이 전제 — 청크
    // 대신 상한 초과를 명시적으로 거부한다.
    const maxTokens = MAX_PARAMS_PER_STATEMENT - 3; // account_id(1) + HAVING(1) + LIMIT(1)
    if (tokens.length > maxTokens) {
      throw new StoreError(`search query has too many tokens (max ${maxTokens})`);
    }

    const limit = opts.limit ?? DEFAULT_SEARCH_LIMIT;
    // lint-allow chunked-in-query: `HAVING COUNT(DISTINCT si.token) = ?`가 AND 시맨틱이라
    // 나눠 돌리면 교집합이 깨진다. 위에서 maxTokens 초과를 명시적으로 거부해 상한을 건다.
    const placeholders = tokens.map(() => "?").join(", ");
    const { rows } = await this.db.query({
      sql: `SELECT si.message_id AS message_id, m.received_at AS received_at
            FROM search_index si
            JOIN messages m ON m.id = si.message_id
            WHERE si.account_id = ? AND si.token IN (${placeholders})
            GROUP BY si.message_id, m.received_at
            HAVING COUNT(DISTINCT si.token) = ?
            ORDER BY m.received_at DESC
            LIMIT ?`,
      params: [accountId, ...tokens, tokens.length, limit],
    });

    return rows.map((r) => ({ messageId: String(r.message_id) }));
  }

  /**
   * 테넌트 사용량 집계(PLAN §SaaS 미터링) — 계정 카운터 합산 + 최근 창 발송 미터(mta_queue).
   * 온디맨드 집계(영속 스냅샷 아님 — 청구 이력이 필요하면 상위에서 주기 저장). now/windowMs 주입 가능.
   */
  /** 테넌트 사용량(과금 미터링) — 구현은 usage-store.ts. */
  tenantUsage(tenantId: string, opts: { windowMs?: number; now?: number } = {}): Promise<TenantUsage> {
    return tenantUsage(this.internals, tenantId, opts);
  }

  /**
   * 계정 쿼터 현황 (IMAP QUOTA · JMAP Quota).
   *
   * ★데이터는 **이미 있었다** — `accounts.quota_bytes`/`used_bytes`/`message_count`를
   * `appendMessagesAttempt`가 스냅샷마다 검사한다(§7-1). 다만 그것을 **클라이언트에게 보여 줄
   * 길이 없어서**, 사용자는 쿼터가 찰 때까지 모르고 있다가 APPEND가 실패하는 것만 봤다.
   *
   * `quotaBytes === 0`은 무제한이다(스토어의 기존 계약 — 위 검사가 `> 0`일 때만 본다).
   */
  async getQuota(accountId: string): Promise<{ usedBytes: number; quotaBytes: number; messageCount: number }> {
    const { rows } = await this.db.query({
      sql: "SELECT quota_bytes, used_bytes, message_count FROM accounts WHERE id = ?",
      params: [accountId],
    });
    const row = rows[0];
    if (!row) throw new StoreError(`account not found: ${accountId}`);
    return {
      usedBytes: Number(row.used_bytes),
      quotaBytes: Number(row.quota_bytes),
      messageCount: Number(row.message_count),
    };
  }

  async setKeywords(input: SetKeywordsInput): Promise<void> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.setKeywordsAttempt(input)));
  }

  private async setKeywordsAttempt(input: SetKeywordsInput): Promise<void> {
    const acct = await this.mustGetAccount(input.accountId);

    const { rows: msgRows } = await this.db.query({
      sql: "SELECT id FROM messages WHERE id = ? AND account_id = ?",
      params: [input.messageId, input.accountId],
    });
    if (msgRows.length === 0) throw new StoreError(`message not found: ${input.messageId}`);

    const { rows: curRows } = await this.db.query({
      sql: "SELECT keyword FROM message_keywords WHERE message_id = ?",
      params: [input.messageId],
    });
    const current = new Set(curRows.map((r) => String(r.keyword)));

    const removeSet = new Set(input.remove.map((k) => k.toLowerCase()));
    const addList = [...new Set(input.add.map((k) => k.toLowerCase()))].filter((k) => !removeSet.has(k) && !current.has(k));
    const removeList = [...removeSet].filter((k) => current.has(k));

    if (addList.length === 0 && removeList.length === 0) return; // 실질 변화 없음 — modseq 소모 없음

    const wasSeen = current.has("$seen");
    const isSeen = (wasSeen || addList.includes("$seen")) && !removeList.includes("$seen");
    const seenToggled = wasSeen !== isSeen;

    const { rows: mmRows } = await this.db.query({
      sql: "SELECT mailbox_id FROM message_mailbox WHERE message_id = ?",
      params: [input.messageId],
    });
    const mailboxIds = mmRows.map((r) => String(r.mailbox_id));

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
    ];

    if (removeList.length > 0) {
      for (const removeChunk of chunk(removeList, rowsPerStatement(1) - 1)) {
        const placeholders = removeChunk.map(() => "?").join(", ");
        stmts.push({
          sql: `DELETE FROM message_keywords WHERE message_id = ? AND keyword IN (${placeholders})`,
          params: [input.messageId, ...removeChunk],
        });
      }
    }
    if (addList.length > 0) {
      const rows = addList.map((k) => [input.accountId, input.messageId, k]);
      stmts.push(...multiRowInsertStatements("message_keywords", ["account_id", "message_id", "keyword"], rows));
    }

    stmts.push({ sql: "UPDATE messages SET modseq = ? WHERE id = ?", params: [nextModseq, input.messageId] });
    stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, input.messageId, CHANGE_KIND.updated, now] });

    const unreadDelta = seenToggled ? (isSeen ? -1 : 1) : 0;
    for (const mbxId of mailboxIds) {
      stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, mbxId, CHANGE_KIND.updated, now] });
      stmts.push({
        sql: `UPDATE mailboxes SET highestmodseq = ?${unreadDelta !== 0 ? `, unread_count = unread_count + (${unreadDelta})` : ""} WHERE id = ?`,
        params: [nextModseq, mbxId],
      });
    }

    stmts.push(
      mailboxIds.length > 0
        ? {
            sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ? WHERE id = ?",
            params: [nextModseq, nextModseq, nextModseq, input.accountId],
          }
        : {
            sql: "UPDATE accounts SET modseq = ?, state_email = ? WHERE id = ?",
            params: [nextModseq, nextModseq, input.accountId],
          },
    );

    await this.db.batch(stmts);
  }

  /**
   * 여러 메시지의 키워드를 **한 배치**로 바꾼다 — `appendMessages`와 같은 그룹 배치 규율.
   *
   * ★왜 필요한가(2026-08-23 검수): IMAP `UID STORE 1:* +FLAGS \Seen`이 메시지마다
   * `setKeywords()`를 불렀다. 1만 통이면 **왕복 2만 번**이고 modseq도 1만 번 소모된다
   * (라이터 큐가 직렬화하므로 그 시간 동안 그 계정의 다른 쓰기가 전부 대기한다).
   *
   * 원자성·불변식은 단건과 같다: modseq 하나를 그룹 전체가 공유하고(§3-3 전역 불변식은
   * "change_log를 쓴 모든 entity의 state_*"를 요구할 뿐 메시지당 modseq를 요구하지 않는다)
   * `modseq_claims`도 1행이다. 하나라도 실패하면 배치 전체가 롤백된다.
   *
   * 반환은 **실제로 바뀐 메시지 id**다 — 호출자가 응답에 실을 대상을 알아야 하고,
   * "변화 없음"은 modseq를 소모하지 않는다는 단건의 성질을 그대로 유지한다.
   */
  async setKeywordsBatch(input: {
    accountId: string;
    messageIds: readonly string[];
    add: readonly string[];
    remove: readonly string[];
    /** true면 `add`를 목표 집합으로 보고 나머지를 전부 지운다(IMAP `STORE FLAGS`). */
    replace?: boolean;
  }): Promise<{ changed: string[] }> {
    if (input.messageIds.length === 0) return { changed: [] };
    return this.writer.run(input.accountId, () => this.withRetry(() => this.setKeywordsBatchAttempt(input)));
  }

  private async setKeywordsBatchAttempt(input: {
    accountId: string;
    messageIds: readonly string[];
    add: readonly string[];
    remove: readonly string[];
    replace?: boolean;
  }): Promise<{ changed: string[] }> {
    const acct = await this.mustGetAccount(input.accountId);
    const ids = [...new Set(input.messageIds)];

    // 계정 소유 확인 — 인가 축이다. 단건 경로가 하는 검사를 배치가 건너뛰면 안 된다.
    const ownRows = await queryInChunks(
      this.db,
      ids,
      (ph) => `SELECT id FROM messages WHERE account_id = ? AND id IN (${ph})`,
      [input.accountId],
    );
    const owned = new Set(ownRows.map((r) => String(r.id)));
    const targets = ids.filter((id) => owned.has(id));
    if (targets.length === 0) return { changed: [] };

    const curRows = await queryInChunks(
      this.db,
      targets,
      (ph) => `SELECT message_id, keyword FROM message_keywords WHERE message_id IN (${ph})`,
    );
    const currentBy = new Map<string, Set<string>>();
    for (const id of targets) currentBy.set(id, new Set());
    for (const r of curRows) currentBy.get(String(r.message_id))?.add(String(r.keyword));

    const mmRows = await queryInChunks(
      this.db,
      targets,
      (ph) => `SELECT message_id, mailbox_id FROM message_mailbox WHERE message_id IN (${ph})`,
    );
    const mailboxesBy = new Map<string, string[]>();
    for (const r of mmRows) {
      const id = String(r.message_id);
      const arr = mailboxesBy.get(id) ?? [];
      arr.push(String(r.mailbox_id));
      mailboxesBy.set(id, arr);
    }

    const addAll = [...new Set(input.add.map((k) => k.toLowerCase()))];
    const removeSet = new Set(input.remove.map((k) => k.toLowerCase()));
    const now = Date.now();
    const nextModseq = acct.modseq + 1;

    const changed: string[] = [];
    const keywordRows: unknown[][] = [];
    /** 메일함별 unread 델타 — 메시지마다 UPDATE를 내지 않고 합산해 한 번에 낸다. */
    const unreadDelta = new Map<string, number>();
    const touchedMailboxes = new Set<string>();
    const removeStmts: Statement[] = [];

    for (const id of targets) {
      const current = currentBy.get(id) ?? new Set<string>();
      // `replace`(STORE FLAGS)는 목표 집합 밖을 전부 지운다 — 단건 경로에서 호출자가 하던 계산이다.
      const target = new Set(addAll);
      const toRemove = input.replace
        ? [...current].filter((k) => !target.has(k))
        : [...removeSet].filter((k) => current.has(k));
      const toAdd = addAll.filter((k) => !current.has(k) && !(input.replace ? false : removeSet.has(k)));
      if (toAdd.length === 0 && toRemove.length === 0) continue; // 변화 없음 — modseq 소모하지 않는다

      changed.push(id);
      for (const k of toAdd) keywordRows.push([input.accountId, id, k]);
      for (const removeChunk of chunk(toRemove, rowsPerStatement(1) - 1)) {
        removeStmts.push({
          sql: `DELETE FROM message_keywords WHERE message_id = ? AND keyword IN (${removeChunk.map(() => "?").join(", ")})`,
          params: [id, ...removeChunk],
        });
      }

      const wasSeen = current.has("$seen");
      const isSeen = (wasSeen || toAdd.includes("$seen")) && !toRemove.includes("$seen");
      const delta = wasSeen === isSeen ? 0 : isSeen ? -1 : 1;
      for (const mbx of mailboxesBy.get(id) ?? []) {
        touchedMailboxes.add(mbx);
        if (delta !== 0) unreadDelta.set(mbx, (unreadDelta.get(mbx) ?? 0) + delta);
      }
    }
    if (changed.length === 0) return { changed: [] };

    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
      ...removeStmts,
      ...multiRowInsertStatements("message_keywords", ["account_id", "message_id", "keyword"], keywordRows),
    ];
    for (const idChunk of chunk(changed, rowsPerStatement(1) - 1)) {
      stmts.push({
        sql: `UPDATE messages SET modseq = ? WHERE id IN (${idChunk.map(() => "?").join(", ")})`,
        params: [nextModseq, ...idChunk],
      });
    }
    for (const id of changed) {
      stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, id, CHANGE_KIND.updated, now] });
    }
    for (const mbx of touchedMailboxes) {
      const delta = unreadDelta.get(mbx) ?? 0;
      stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, mbx, CHANGE_KIND.updated, now] });
      stmts.push({
        sql: `UPDATE mailboxes SET highestmodseq = ?${delta !== 0 ? ", unread_count = unread_count + ?" : ""} WHERE id = ?`,
        params: delta !== 0 ? [nextModseq, delta, mbx] : [nextModseq, mbx],
      });
    }
    stmts.push(
      touchedMailboxes.size > 0
        ? {
            sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ? WHERE id = ?",
            params: [nextModseq, nextModseq, nextModseq, input.accountId],
          }
        : {
            sql: "UPDATE accounts SET modseq = ?, state_email = ? WHERE id = ?",
            params: [nextModseq, nextModseq, input.accountId],
          },
    );

    await this.db.batch(stmts);
    return { changed };
  }

  // ── SetDeleted — \Deleted per-membership (§5-2) ─────────────────────
  async setDeleted(input: SetDeletedInput): Promise<void> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.setDeletedAttempt(input)));
  }

  private async setDeletedAttempt(input: SetDeletedInput): Promise<void> {
    const acct = await this.mustGetAccount(input.accountId);
    if (input.uids.length === 0) return;

    // ★메일함 소유 확인 — 이 스토어의 인가 축은 account_id인데 여기만 빠져 있었다
    // (expungeAttempt는 확인한다). 지금 호출자는 계정 스코프로 메일함을 고르므로 안전하지만,
    // 계약이 한 곳만 깨져 있으면 새 호출자가 그 구멍을 밟는다 — 남의 메일함 메시지를
    // \Deleted로 찍는 경로가 된다.
    const { rows: mbxRows } = await this.db.query({
      sql: "SELECT id FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
      params: [input.mailboxId, input.accountId],
    });
    if (mbxRows.length === 0) throw new StoreError(`mailbox not found or inactive: ${input.mailboxId}`);

    const rows = await queryInChunks(
      this.db,
      input.uids,
      (ph) => `SELECT uid, message_id, deleted FROM message_mailbox WHERE mailbox_id = ? AND uid IN (${ph})`,
      [input.mailboxId],
    );
    if (rows.length === 0) return;

    const deletedFlag = input.deleted ? 1 : 0;
    const targets = rows.filter((r) => Number(r.deleted) !== deletedFlag);
    if (targets.length === 0) return; // 전부 이미 목표 상태 — no-op

    const messageIds = [...new Set(targets.map((r) => String(r.message_id)))];
    const uids = targets.map((r) => Number(r.uid));

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
    ];

    /**
     * 고정 파라미터를 **정확히** 빼고 나머지를 uid IN-리스트에 배정한다 (§7-6 유도 기반).
     *
     * ★여기 `deleted = ?`와 `mailbox_id = ?`로 고정이 **둘**인데 예약은 하나뿐이라
     * 문장당 101개가 나갔다(2026-08-23 검수, 대형 메일함 테스트가 실측으로 잡았다).
     * D1 한도가 100이라 `UID STORE 1:* +FLAGS \Deleted`가 99통을 넘는 순간 깨진다.
     * 고정 개수를 세는 상수를 옆에 두어 문장이 바뀌면 같이 바뀌게 한다.
     */
    const DELETED_FIXED_PARAMS = 2; // deleted, mailbox_id
    for (const uidChunk of chunk(uids, rowsPerStatement(1) - DELETED_FIXED_PARAMS)) {
      const placeholders = uidChunk.map(() => "?").join(", ");
      stmts.push({
        sql: `UPDATE message_mailbox SET deleted = ? WHERE mailbox_id = ? AND uid IN (${placeholders})`,
        params: [deletedFlag, input.mailboxId, ...uidChunk],
      });
    }
    for (const idChunk of chunk(messageIds, rowsPerStatement(1) - 1)) {
      const placeholders = idChunk.map(() => "?").join(", ");
      stmts.push({ sql: `UPDATE messages SET modseq = ? WHERE id IN (${placeholders})`, params: [nextModseq, ...idChunk] });
    }
    for (const msgId of messageIds) {
      stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, msgId, CHANGE_KIND.updated, now] });
    }
    stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.mailboxId, CHANGE_KIND.updated, now] });
    stmts.push({ sql: "UPDATE mailboxes SET highestmodseq = ? WHERE id = ?", params: [nextModseq, input.mailboxId] });
    stmts.push({
      sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ? WHERE id = ?",
      params: [nextModseq, nextModseq, nextModseq, input.accountId],
    });

    await this.db.batch(stmts);
  }

  // ── Expunge (§7-4) ───────────────────────────────────────────────────
  async expunge(input: ExpungeInput): Promise<ExpungeResult> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.expungeAttempt(input)));
  }

  private async expungeAttempt(input: ExpungeInput): Promise<ExpungeResult> {
    const acct = await this.mustGetAccount(input.accountId);

    const { rows: mbxRows } = await this.db.query({
      sql: "SELECT id FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
      params: [input.mailboxId, input.accountId],
    });
    if (mbxRows.length === 0) throw new StoreError(`mailbox not found or inactive: ${input.mailboxId}`);

    // UIDPLUS UID EXPUNGE — uid 필터 지정 시 그 범위의 deleted=1만 (§7-4 변형).
    // 필터가 있으면 uid 수만큼 파라미터가 붙으므로 한도 안에서 나눠 돈다(`UID EXPUNGE 1:*`).
    const selectTargets = (ph: string): string =>
      `SELECT mm.uid AS uid, mm.message_id AS message_id, m.size_bytes AS size_bytes
            FROM message_mailbox mm JOIN messages m ON m.id = mm.message_id
            WHERE mm.mailbox_id = ? AND mm.deleted = 1${ph === "" ? "" : ` AND mm.uid IN (${ph})`}`;
    const targetRows =
      input.uids && input.uids.length > 0
        ? await queryInChunks(this.db, input.uids, selectTargets, [input.mailboxId])
        : (await this.db.query({ sql: selectTargets(""), params: [input.mailboxId] })).rows;
    if (targetRows.length === 0) return { expunged: [] };

    const targets = targetRows.map((r) => ({
      uid: Number(r.uid),
      messageId: String(r.message_id),
      sizeBytes: Number(r.size_bytes),
    }));
    const messageIds = [...new Set(targets.map((t) => t.messageId))];

    // 마지막 membership 판정 — 스냅샷 시점 전체 membership 카운트 (§7-4)
    const countRows = await queryInChunks(
      this.db,
      messageIds,
      (ph) => `SELECT message_id, COUNT(*) AS cnt FROM message_mailbox WHERE message_id IN (${ph}) GROUP BY message_id`,
    );
    const membershipCount = new Map(countRows.map((r) => [String(r.message_id), Number(r.cnt)]));

    // unread_count 조정용 $seen 보유 여부
    const seenRows = await queryInChunks(
      this.db,
      messageIds,
      (ph) => `SELECT message_id FROM message_keywords WHERE keyword = '$seen' AND message_id IN (${ph})`,
    );
    const seenSet = new Set(seenRows.map((r) => String(r.message_id)));

    const dyingIds = messageIds.filter((id) => (membershipCount.get(id) ?? 0) <= 1);
    const dyingSet = new Set(dyingIds);
    const survivingIds = messageIds.filter((id) => !dyingSet.has(id));

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
    ];

    const uids = targets.map((t) => t.uid);
    for (const uidChunk of chunk(uids, rowsPerStatement(1) - 1)) {
      const placeholders = uidChunk.map(() => "?").join(", ");
      stmts.push({
        sql: `DELETE FROM message_mailbox WHERE mailbox_id = ? AND uid IN (${placeholders})`,
        params: [input.mailboxId, ...uidChunk],
      });
    }

    const expungedRows = targets.map((t) => [input.mailboxId, t.uid, nextModseq, now]);
    stmts.push(...multiRowInsertStatements("expunged", ["mailbox_id", "uid", "modseq", "created_at"], expungedRows));

    if (dyingIds.length > 0) {
      for (const idChunk of chunk(dyingIds, rowsPerStatement(1) - 1)) {
        const ph = idChunk.map(() => "?").join(", ");
        stmts.push({ sql: `DELETE FROM messages WHERE id IN (${ph})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM message_keywords WHERE message_id IN (${ph})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM message_addresses WHERE message_id IN (${ph})`, params: idChunk });
        // ★검색 부산물도 **여기서** 지운다. 예전엔 message_text·search_index만 남았고,
        //   message_text에는 제목과 본문 텍스트가 들어간다 — 사용자가 지운 메일의 본문이
        //   DB와 백업에 영구히 남는다는 뜻이었다(저장소 낭비 이전에 삭제 계약이 깨진 것).
        stmts.push({ sql: `DELETE FROM message_text WHERE message_id IN (${ph})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM search_index WHERE message_id IN (${ph})`, params: idChunk });
        stmts.push({ sql: `DELETE FROM blob_refs WHERE ref_kind = ${REF_KIND.message} AND ref_id IN (${ph})`, params: idChunk });
        // ★편차 (실행 요약에 기재): SCHEMA.md §7-4 원문은 마지막 membership 소멸 시
        // thread_refs도 함께 DELETE하라고 명시한다. 하지만 thread_refs PK(§5-3)는
        // (account_id, ref_hash, thread_id)로 message_id 연결이 없어 "이 메시지가 만든 행"을
        // 정확히 스코프할 수 없다 — 같은 ref_hash를 형제 메시지가 재사용(insertIgnore로 dedup)한
        // 경우 삭제하면 형제 메시지의 스레딩 연속성이 깨진다(과잉 삭제 리스크). 대신 thread_refs는
        // 자체 보존창 GC(§5-3, 기본 180일)로 수거한다.
        // ⚠ 그 GC는 **아직 없다**(2026-08-23 검수) — 지금은 thread_refs만 무한 누적된다.
        //   search_index·message_text는 이 커밋부터 여기서 즉시 지우므로 더 이상 같은 부류가 아니다.
      }
      for (const id of dyingIds) {
        stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, id, CHANGE_KIND.destroyed, now] });
      }
    }
    if (survivingIds.length > 0) {
      for (const idChunk of chunk(survivingIds, rowsPerStatement(1) - 1)) {
        const ph = idChunk.map(() => "?").join(", ");
        stmts.push({ sql: `UPDATE messages SET modseq = ? WHERE id IN (${ph})`, params: [nextModseq, ...idChunk] });
      }
      for (const id of survivingIds) {
        stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, id, CHANGE_KIND.updated, now] });
      }
    }

    stmts.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.mailboxId, CHANGE_KIND.updated, now] });

    const dyingBytes = targets.filter((t) => dyingSet.has(t.messageId)).reduce((sum, t) => sum + t.sizeBytes, 0);
    const mailboxBytes = targets.reduce((sum, t) => sum + t.sizeBytes, 0);
    const unreadDelta = targets.filter((t) => !seenSet.has(t.messageId)).length;

    stmts.push({
      sql: `UPDATE mailboxes SET total_count = total_count - ?, total_bytes = total_bytes - ?, unread_count = unread_count - ?, highestmodseq = ? WHERE id = ?`,
      params: [targets.length, mailboxBytes, unreadDelta, nextModseq, input.mailboxId],
    });
    stmts.push({
      sql: `UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ?, used_bytes = used_bytes - ?, message_count = message_count - ? WHERE id = ?`,
      params: [nextModseq, nextModseq, nextModseq, dyingBytes, dyingIds.length, input.accountId],
    });

    await this.db.batch(stmts);

    return { expunged: targets.map((t) => ({ uid: t.uid, modseq: nextModseq })) };
  }

  /**
   * 단일 멤버십 제거 (JMAP Email/set mailboxIds 축소) — (message, mailbox) 하나만 제거.
   * 마지막 멤버십이면 메시지 파기(§7-4 규율 동일: 툼스톤·change_log destroyed·계정 카운터).
   * 반환: 파기 여부.
   */
  async removeMessageFromMailbox(accountId: string, messageId: string, mailboxId: string): Promise<{ destroyed: boolean }> {
    return this.writer.run(accountId, () => this.withRetry(() => this.removeMembershipAttempt(accountId, messageId, mailboxId)));
  }

  private async removeMembershipAttempt(accountId: string, messageId: string, mailboxId: string): Promise<{ destroyed: boolean }> {
    const acct = await this.mustGetAccount(accountId);
    const { rows } = await this.db.query({
      sql: `SELECT mm.uid AS uid, m.size_bytes AS size_bytes FROM message_mailbox mm
            JOIN messages m ON m.id = mm.message_id WHERE mm.message_id = ? AND mm.mailbox_id = ? AND m.account_id = ?`,
      params: [messageId, mailboxId, accountId],
    });
    const row = rows[0];
    if (!row) throw new StoreError(`message not in mailbox: ${messageId}`);
    const uid = Number(row.uid);
    const sizeBytes = Number(row.size_bytes);

    const { rows: cntRows } = await this.db.query({ sql: "SELECT COUNT(*) AS n FROM message_mailbox WHERE message_id = ?", params: [messageId] });
    const isLast = Number(cntRows[0]?.n ?? 0) <= 1;
    const { rows: seenRows } = await this.db.query({ sql: "SELECT 1 AS x FROM message_keywords WHERE message_id = ? AND keyword = '$seen'", params: [messageId] });
    const seen = seenRows.length > 0;

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [accountId, nextModseq] },
      { sql: "DELETE FROM message_mailbox WHERE mailbox_id = ? AND uid = ?", params: [mailboxId, uid] },
      { sql: "INSERT INTO expunged (mailbox_id, uid, modseq, created_at) VALUES (?, ?, ?, ?)", params: [mailboxId, uid, nextModseq, now] },
      { sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Mailbox, mailboxId, CHANGE_KIND.updated, now] },
      {
        sql: "UPDATE mailboxes SET total_count = total_count - 1, total_bytes = total_bytes - ?, unread_count = unread_count - ?, highestmodseq = ? WHERE id = ?",
        params: [sizeBytes, seen ? 0 : 1, nextModseq, mailboxId],
      },
    ];
    if (isLast) {
      stmts.push(
        { sql: "DELETE FROM messages WHERE id = ?", params: [messageId] },
        { sql: "DELETE FROM message_keywords WHERE message_id = ?", params: [messageId] },
        { sql: "DELETE FROM message_addresses WHERE message_id = ?", params: [messageId] },
        // 검색 부산물 — 위 청크 경로와 같은 이유로 함께 지운다(삭제 계약).
        { sql: "DELETE FROM message_text WHERE message_id = ?", params: [messageId] },
        { sql: "DELETE FROM search_index WHERE message_id = ?", params: [messageId] },
        { sql: `DELETE FROM blob_refs WHERE ref_kind = ${REF_KIND.message} AND ref_id = ?`, params: [messageId] },
        { sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Email, messageId, CHANGE_KIND.destroyed, now] },
        {
          sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ?, used_bytes = used_bytes - ?, message_count = message_count - 1 WHERE id = ?",
          params: [nextModseq, nextModseq, nextModseq, sizeBytes, accountId],
        },
      );
    } else {
      stmts.push(
        { sql: "UPDATE messages SET modseq = ? WHERE id = ?", params: [nextModseq, messageId] },
        { sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Email, messageId, CHANGE_KIND.updated, now] },
        { sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ? WHERE id = ?", params: [nextModseq, nextModseq, nextModseq, accountId] },
      );
    }
    await this.db.batch(stmts);
    return { destroyed: isLast };
  }

  /**
   * 여러 메시지를 **한 배치**로 복사/이동한다 (IMAP `UID COPY`/`UID MOVE`).
   *
   * ★왜 필요한가(2026-08-23 검수): 예전엔 메시지마다 `copyMessage()`/`moveMessage()`를 불렀다.
   * 왕복이 N번인 것보다 나쁜 것은 **원자성이 없다**는 점이다 — 중간에 실패하면 절반만 복사된
   * 채로 `COPYUID`가 나갔다. CLAUDE.md §아키텍처("한 논리 연산 = db.batch() 한 번")와
   * RFC 9051 §6.4.7("COPY가 실패하면 대상 메일함을 원상 복구해야 한다") 양쪽에 어긋난다.
   *
   * 대상 uid는 **사전 할당**한다(§1-2: RETURNING 금지). `appendMessages`가 그룹 안에서
   * uid 커서를 이어 붙이는 것과 같은 방식이다.
   *
   * 반환은 `(원본 uid, 새 uid)` 쌍 목록이고 **입력 순서를 지킨다** — `COPYUID`의 두 uid-set이
   * 위치로 대응하므로 순서가 어긋나면 클라이언트가 다른 메시지를 가리킨다.
   *
   * ## ★COPY는 **독립된 메시지**를 만든다 (2026-08-24, 감사 G2)
   *
   * 예전엔 같은 `message_id`로 `message_mailbox` 행만 더했다. 결과가 두 가지로 틀렸다:
   *  · 사본과 원본이 `message_keywords`를 **공유**해서, 한쪽에서 `\Seen`을 달면 다른 쪽도
   *    읽음이 됐다. RFC 9051 §6.4.7은 사본이 독립 플래그를 갖기를 요구한다.
   *  · `ux_mm_message(mailbox_id, message_id)` 때문에 **같은 메일함으로의 COPY가 조용한
   *    no-op**이었다. 클라이언트는 `COPYUID`로 성공을 받고 사본이 없는 것을 나중에 안다.
   *
   * 이제 copy는 `messages` 행을 새로 만들고 키워드·주소·검색 부산물을 복제한다. 블롭은
   * **공유하되** `blob_refs`에 참조를 하나 더 단다 — 원본을 지워도 사본의 원문이 남아야 한다.
   *
   * ★MOVE는 그대로 멤버십 이동이다. 이동은 "같은 메시지가 다른 자리로" 가는 것이라 새 행을
   * 만들 이유가 없고, 만들면 uid만 바뀌어야 할 자리에서 JMAP `Email` id까지 바뀐다.
   *
   * ★JMAP의 `copyMessage()`는 **바꾸지 않았다.** JMAP의 Email 모델에서는 키워드가 메시지의
   * 속성이고 한 Email이 여러 메일함에 속한다(RFC 8621 §4) — 거기서는 멤버십 추가가 맞다.
   * 두 표면이 다른 것은 **규격이 다르기 때문**이지 갈라진 것이 아니다.
   */
  async copyOrMoveMessages(input: {
    accountId: string;
    messageIds: readonly string[];
    fromMailboxId: string;
    toMailboxId: string;
    op: "copy" | "move";
  }): Promise<{ pairs: { messageId: string; uid: number }[] }> {
    if (input.messageIds.length === 0) return { pairs: [] };
    return this.writer.run(input.accountId, () => this.withRetry(() => this.copyOrMoveBatchAttempt(input)));
  }

  private async copyOrMoveBatchAttempt(input: {
    accountId: string;
    messageIds: readonly string[];
    fromMailboxId: string;
    toMailboxId: string;
    op: "copy" | "move";
  }): Promise<{ pairs: { messageId: string; uid: number }[] }> {
    const acct = await this.mustGetAccount(input.accountId);
    const ids = [...input.messageIds];

    const { rows: toMbxRows } = await this.db.query({
      sql: "SELECT uidnext FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
      params: [input.toMailboxId, input.accountId],
    });
    if (!toMbxRows[0]) throw new StoreError(`target mailbox not found: ${input.toMailboxId}`);
    let uidCursor = Number(toMbxRows[0].uidnext);

    /**
     * 크기·소유 — 계정 스코프로 함께 확인한다(인가 축).
     *
     * copy는 `messages` 행을 새로 만들므로 **모든 컬럼**이 필요하다. move는 크기만 쓰지만
     * 질의를 둘로 나누면 두 갈래가 서로 다른 스냅샷을 볼 수 있어 한 번에 읽는다.
     */
    const srcMsgRows = await queryInChunks(
      this.db,
      ids,
      (ph) => `SELECT id, blob_id, thread_id, size_bytes, received_at, subject, subject_base, msgid_hash, sent_at, preview, has_attachment
                 FROM messages WHERE account_id = ? AND id IN (${ph})`,
      [input.accountId],
    );
    const srcMsgBy = new Map(srcMsgRows.map((r) => [String(r.id), r]));
    const sizeBy = new Map(srcMsgRows.map((r) => [String(r.id), Number(r.size_bytes)]));

    const srcRows = await queryInChunks(
      this.db,
      ids,
      (ph) => `SELECT uid, message_id FROM message_mailbox WHERE mailbox_id = ? AND message_id IN (${ph})`,
      [input.fromMailboxId],
    );
    const srcUidBy = new Map(srcRows.map((r) => [String(r.message_id), Number(r.uid)]));

    /**
     * MOVE에서만 의미가 있다 — 이미 대상에 있는 메시지는 원본 멤버십만 걷어내면 된다.
     *
     * ★COPY는 이 표를 보지 않는다. 사본이 **새 message_id**를 갖게 된 뒤로는 `ux_mm_message`가
     * 걸릴 일이 없고, 같은 메일함으로의 COPY도 규격대로 사본을 하나 더 만든다(§6.4.7).
     * 예전엔 여기서 no-op으로 빠져 클라이언트가 성공을 받고도 사본이 없었다.
     */
    const existingBy =
      input.op === "move"
        ? new Map(
            (
              await queryInChunks(
                this.db,
                ids,
                (ph) => `SELECT uid, message_id FROM message_mailbox WHERE mailbox_id = ? AND message_id IN (${ph})`,
                [input.toMailboxId],
              )
            ).map((r) => [String(r.message_id), Number(r.uid)]),
          )
        : new Map<string, number>();

    /**
     * copy는 키워드를 **전부** 복제해야 하고(사본이 원본의 플래그를 그대로 갖고 시작한다,
     * §6.4.7), move는 `$seen` 여부만 있으면 된다(메일함 unread 카운터). 둘 다 필요하므로
     * 한 번에 읽어 copy는 전량을, move는 `$seen`만 쓴다.
     */
    const kwRows = await queryInChunks(
      this.db,
      ids,
      (ph) => `SELECT message_id, keyword FROM message_keywords WHERE account_id = ? AND message_id IN (${ph})`,
      [input.accountId],
    );
    const keywordsBy = new Map<string, string[]>();
    for (const r of kwRows) {
      const id = String(r.message_id);
      const list = keywordsBy.get(id);
      if (list) list.push(String(r.keyword));
      else keywordsBy.set(id, [String(r.keyword)]);
    }
    const seenSet = new Set(kwRows.filter((r) => String(r.keyword) === "$seen").map((r) => String(r.message_id)));

    // copy는 주소도 복제한다 — 없으면 사본의 ENVELOPE·JMAP Email에서 발신/수신자가 사라진다.
    const addrRows =
      input.op === "copy"
        ? await queryInChunks(
            this.db,
            ids,
            (ph) => `SELECT message_id, kind, pos, name, email FROM message_addresses WHERE account_id = ? AND message_id IN (${ph})`,
            [input.accountId],
          )
        : [];
    const addrBy = new Map<string, typeof addrRows>();
    for (const r of addrRows) {
      const id = String(r.message_id);
      const list = addrBy.get(id);
      if (list) list.push(r);
      else addrBy.set(id, [r]);
    }

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const pairs: { messageId: string; uid: number }[] = [];
    const stmts: Statement[] = [];
    const mmRows: unknown[][] = [];
    const expungedRows: unknown[][] = [];
    /** modseq를 올려 줄 **기존** 메시지들(move 대상). copy의 새 행은 처음부터 nextModseq다. */
    const touched: string[] = [];
    /** copy가 만드는 새 메시지들 — 아래 배치에서 행·참조·키워드·주소를 함께 넣는다. */
    const copiedIds: string[] = [];
    const msgRowsToInsert: unknown[][] = [];
    const blobRefRows: unknown[][] = [];
    const copiedKeywordRows: unknown[][] = [];
    const copiedAddrRows: unknown[][] = [];
    /** 검색 부산물 복제용 (원본 → 사본). 코어 배치 커밋 뒤에 처리한다(§7-1). */
    const copySources: { from: string; to: string }[] = [];
    /** 사본이 계정 사용량에 더하는 바이트 — 사본은 진짜 새 메시지다. */
    let copyBytes = 0;
    let addCount = 0;
    let addBytes = 0;
    let addUnread = 0;
    let delCount = 0;
    let delBytes = 0;
    let delUnread = 0;

    for (const id of ids) {
      const size = sizeBy.get(id);
      const srcUid = srcUidBy.get(id);
      if (size === undefined || srcUid === undefined) continue; // 소유가 아니거나 원본에 없다
      const unread = seenSet.has(id) ? 0 : 1;

      const existing = existingBy.get(id);
      if (existing !== undefined) {
        // 이미 대상에 있다 — 복사는 no-op. 이동이면 원본 멤버십만 걷어낸다.
        pairs.push({ messageId: id, uid: existing });
        if (input.op === "move") {
          stmts.push({
            sql: "DELETE FROM message_mailbox WHERE mailbox_id = ? AND uid = ?",
            params: [input.fromMailboxId, srcUid],
          });
          expungedRows.push([input.fromMailboxId, srcUid, nextModseq, now]);
          delCount += 1;
          delBytes += size;
          delUnread += unread;
          touched.push(id);
        }
        continue;
      }

      const newUid = uidCursor++;
      addCount += 1;
      addBytes += size;
      addUnread += unread;

      if (input.op === "move") {
        // 이동은 **같은 메시지**가 다른 자리로 가는 것이다 — 새 행을 만들면 uid만 바뀌어야 할
        // 자리에서 JMAP Email id까지 바뀐다.
        pairs.push({ messageId: id, uid: newUid });
        mmRows.push([input.toMailboxId, newUid, id, now, 0]);
        touched.push(id);
        stmts.push({
          sql: "DELETE FROM message_mailbox WHERE mailbox_id = ? AND uid = ?",
          params: [input.fromMailboxId, srcUid],
        });
        expungedRows.push([input.fromMailboxId, srcUid, nextModseq, now]);
        delCount += 1;
        delBytes += size;
        delUnread += unread;
        continue;
      }

      /**
       * ★COPY — **독립된 메시지**를 만든다(RFC 9051 §6.4.7). 사본은 원본의 플래그를 그대로
       * 갖고 시작하되 그 뒤로는 따로 움직인다.
       *
       * 블롭은 공유하고 `blob_refs`에 참조를 하나 더 단다 — 원본을 지워도 사본의 원문이
       * 남아야 하고, GC는 참조 수로 판단한다.
       *
       * `pairs`의 `messageId`는 **원본** id다 — 호출자가 그것으로 원본 uid를 되찾아
       * COPYUID의 첫 uid-set을 만든다. 새 id는 여기 밖으로 나가지 않는다.
       */
      const src = srcMsgBy.get(id)!;
      const copyId = ulid();
      copiedIds.push(copyId);
      pairs.push({ messageId: id, uid: newUid });
      mmRows.push([input.toMailboxId, newUid, copyId, now, 0]);

      msgRowsToInsert.push([
        copyId,
        input.accountId,
        String(src.blob_id),
        String(src.thread_id),
        nextModseq,
        size,
        Number(src.received_at),
        src.subject == null ? null : String(src.subject),
        src.subject_base == null ? null : String(src.subject_base),
        src.msgid_hash == null ? null : String(src.msgid_hash),
        src.sent_at == null ? null : Number(src.sent_at),
        src.preview == null ? null : String(src.preview),
        Number(src.has_attachment),
        now,
      ]);
      blobRefRows.push([String(src.blob_id), input.accountId, REF_KIND.message, copyId, now]);
      for (const kw of keywordsBy.get(id) ?? []) copiedKeywordRows.push([input.accountId, copyId, kw]);
      for (const a of addrBy.get(id) ?? []) {
        copiedAddrRows.push([input.accountId, copyId, Number(a.kind), Number(a.pos), a.name == null ? null : String(a.name), String(a.email)]);
      }
      copySources.push({ from: id, to: copyId });
      copyBytes += size;
    }

    if (touched.length === 0 && copiedIds.length === 0) return { pairs };

    const batch: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
      ...stmts,
      /**
       * ★순서 — `messages` 행이 `message_mailbox`·`message_keywords`보다 **먼저** 들어가야
       * 한다. 논리적 외래키(스키마에 FK 제약은 없지만 읽기 경로가 전제한다)이고, 중간 상태를
       * 다른 세션이 볼 수 있는 드라이버에서는 이 순서가 곧 가시성 순서다.
       */
      ...multiRowInsertStatements(
        "messages",
        ["id", "account_id", "blob_id", "thread_id", "modseq", "size_bytes", "received_at", "subject", "subject_base", "msgid_hash", "sent_at", "preview", "has_attachment", "created_at"],
        msgRowsToInsert,
      ),
      ...multiRowInsertStatements("blob_refs", ["blob_id", "account_id", "ref_kind", "ref_id", "created_at"], blobRefRows),
      ...multiRowInsertStatements("message_keywords", ["account_id", "message_id", "keyword"], copiedKeywordRows),
      ...multiRowInsertStatements("message_addresses", ["account_id", "message_id", "kind", "pos", "name", "email"], copiedAddrRows),
      ...multiRowInsertStatements("message_mailbox", ["mailbox_id", "uid", "message_id", "savedate", "deleted"], mmRows),
      ...multiRowInsertStatements("expunged", ["mailbox_id", "uid", "modseq", "created_at"], expungedRows),
    ];
    for (const idChunk of chunk([...new Set(touched)], rowsPerStatement(1) - 1)) {
      batch.push({
        sql: `UPDATE messages SET modseq = ? WHERE id IN (${idChunk.map(() => "?").join(", ")})`,
        params: [nextModseq, ...idChunk],
      });
    }
    for (const id of new Set(touched)) {
      // ★destroyed 아님 — 메일함 **이동**은 Email updated (§7-3)
      batch.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, id, CHANGE_KIND.updated, now] });
    }
    for (const id of copiedIds) {
      // ★사본은 **created**다 — 새 Email이므로. updated로 적으면 JMAP 클라이언트가 모르는
      //   id의 변경을 받고 그 자체로 재동기화를 유발한다.
      batch.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, id, CHANGE_KIND.created, now] });
    }
    if (addCount > 0) {
      batch.push({
        sql: `UPDATE mailboxes SET uidnext = ?, total_count = total_count + ?, total_bytes = total_bytes + ?, unread_count = unread_count + ?, highestmodseq = ? WHERE id = ?`,
        params: [uidCursor, addCount, addBytes, addUnread, nextModseq, input.toMailboxId],
      });
      batch.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.toMailboxId, CHANGE_KIND.updated, now] });
    }
    if (delCount > 0) {
      batch.push({
        sql: `UPDATE mailboxes SET total_count = total_count - ?, total_bytes = total_bytes - ?, unread_count = unread_count - ?, highestmodseq = ? WHERE id = ?`,
        params: [delCount, delBytes, delUnread, nextModseq, input.fromMailboxId],
      });
      batch.push({ sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.fromMailboxId, CHANGE_KIND.updated, now] });
    }
    /**
     * ★사본은 **진짜 새 메시지**라 계정 사용량에 더한다. 예전엔 멤버십만 늘려서 사본이
     * 쿼터에 잡히지 않았다 — COPY를 반복해 상한을 우회할 수 있었다는 뜻이다.
     * 블롭은 공유하지만 쿼터는 "메일함에 보이는 메일"의 크기를 세는 값이고, 메일함 단위
     * `total_bytes`가 예전부터 그렇게 세어 왔다(사본도 더했다).
     */
    if (copiedIds.length > 0) {
      batch.push({
        sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ?, used_bytes = used_bytes + ?, message_count = message_count + ? WHERE id = ?",
        params: [nextModseq, nextModseq, nextModseq, copyBytes, copiedIds.length, input.accountId],
      });
    } else {
      batch.push({
        sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ? WHERE id = ?",
        params: [nextModseq, nextModseq, nextModseq, input.accountId],
      });
    }

    await this.db.batch(batch);

    /**
     * 검색 부산물 복제 — 코어 배치 **뒤에** 돈다(§7-1: 검색은 eventual consistency 허용이라
     * 원자적 코어 배치를 불리지 않는다). 실패해도 복사 자체는 성립하고, 사본이 검색에 늦게
     * 잡힐 뿐이다. 이걸 빼면 사본이 JMAP 검색·조각에서 영영 보이지 않는다.
     */
    if (copySources.length > 0) await this.copySearchArtifacts(input.accountId, copySources);
    return { pairs };
  }

  /** COPY 사본의 `message_text`·`search_index` 복제. 실패는 삼킨다(위 주석의 eventual consistency). */
  private async copySearchArtifacts(accountId: string, pairs: readonly { from: string; to: string }[]): Promise<void> {
    try {
      const fromIds = pairs.map((p) => p.from);
      const toBy = new Map(pairs.map((p) => [p.from, p.to]));
      const textRows = await queryInChunks(
        this.db,
        fromIds,
        (ph) => `SELECT message_id, field, content FROM message_text WHERE message_id IN (${ph})`,
      );
      const idxRows = await queryInChunks(
        this.db,
        fromIds,
        (ph) => `SELECT message_id, token, field FROM search_index WHERE account_id = ? AND message_id IN (${ph})`,
        [accountId],
      );
      const stmts: Statement[] = [
        ...multiRowInsertStatements(
          "message_text",
          ["message_id", "field", "content"],
          textRows.map((r) => [toBy.get(String(r.message_id))!, Number(r.field), String(r.content)]),
        ),
      ];
      // insertIgnore는 단일행 SQL만 만든다(§7-6) — 토큰별 개별 문장.
      const idxSql = this.db.insertIgnore("search_index", ["account_id", "token", "field", "message_id"]);
      for (const r of idxRows) {
        stmts.push({ sql: idxSql, params: [accountId, String(r.token), Number(r.field), toBy.get(String(r.message_id))!] });
      }
      /**
       * 문장 수로 나눈다 — 토큰 하나가 문장 하나라(insertIgnore는 단일행만 만든다) 큰 메일
       * 여러 통을 복사하면 수천 문장이 된다. 한 배치가 라이터를 붙잡는 시간을 묶어 둔다.
       */
      for (const c of chunk(stmts, COPY_ARTIFACT_STATEMENTS_PER_BATCH)) await this.db.batch(c);
    } catch {
      /* 무시 — 사본이 검색에 늦게 잡힐 뿐, 복사 자체는 이미 커밋됐다 */
    }
  }

  /** 메시지 전체 파기 (JMAP Email/destroy) — 모든 멤버십 제거 + 메시지 파기. */
  async destroyMessage(accountId: string, messageId: string): Promise<void> {
    return this.writer.run(accountId, () => this.withRetry(() => this.destroyMessageAttempt(accountId, messageId)));
  }

  private async destroyMessageAttempt(accountId: string, messageId: string): Promise<void> {
    const acct = await this.mustGetAccount(accountId);
    const { rows: msgRows } = await this.db.query({ sql: "SELECT size_bytes FROM messages WHERE id = ? AND account_id = ?", params: [messageId, accountId] });
    if (!msgRows[0]) throw new StoreError(`message not found: ${messageId}`);
    const sizeBytes = Number(msgRows[0].size_bytes);

    const { rows: memberships } = await this.db.query({ sql: "SELECT mailbox_id, uid FROM message_mailbox WHERE message_id = ?", params: [messageId] });
    const { rows: seenRows } = await this.db.query({ sql: "SELECT 1 AS x FROM message_keywords WHERE message_id = ? AND keyword = '$seen'", params: [messageId] });
    const seen = seenRows.length > 0;

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const stmts: Statement[] = [
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [accountId, nextModseq] },
    ];
    for (const m of memberships) {
      const mbxId = String(m.mailbox_id);
      stmts.push(
        { sql: "DELETE FROM message_mailbox WHERE mailbox_id = ? AND uid = ?", params: [mbxId, Number(m.uid)] },
        { sql: "INSERT INTO expunged (mailbox_id, uid, modseq, created_at) VALUES (?, ?, ?, ?)", params: [mbxId, Number(m.uid), nextModseq, now] },
        { sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Mailbox, mbxId, CHANGE_KIND.updated, now] },
        {
          sql: "UPDATE mailboxes SET total_count = total_count - 1, total_bytes = total_bytes - ?, unread_count = unread_count - ?, highestmodseq = ? WHERE id = ?",
          params: [sizeBytes, seen ? 0 : 1, nextModseq, mbxId],
        },
      );
    }
    stmts.push(
      { sql: "DELETE FROM messages WHERE id = ?", params: [messageId] },
      { sql: "DELETE FROM message_keywords WHERE message_id = ?", params: [messageId] },
      { sql: "DELETE FROM message_addresses WHERE message_id = ?", params: [messageId] },
      // 검색 부산물 — 위 청크 경로와 같은 이유로 함께 지운다(삭제 계약).
      { sql: "DELETE FROM message_text WHERE message_id = ?", params: [messageId] },
      { sql: "DELETE FROM search_index WHERE message_id = ?", params: [messageId] },
      { sql: `DELETE FROM blob_refs WHERE ref_kind = ${REF_KIND.message} AND ref_id = ?`, params: [messageId] },
      { sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.Email, messageId, CHANGE_KIND.destroyed, now] },
      {
        sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ?, used_bytes = used_bytes - ?, message_count = message_count - 1 WHERE id = ?",
        params: [nextModseq, nextModseq, nextModseq, sizeBytes, accountId],
      },
    );
    await this.db.batch(stmts);
  }

  // ── MoveMessage (§7-3) ────────────────────────────────────────────────
  async moveMessage(input: MoveMessageInput): Promise<MoveMessageResult> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.moveMessageAttempt(input)));
  }

  private async moveMessageAttempt(input: MoveMessageInput): Promise<MoveMessageResult> {
    const acct = await this.mustGetAccount(input.accountId);

    const { rows: msgRows } = await this.db.query({
      sql: "SELECT size_bytes FROM messages WHERE id = ? AND account_id = ?",
      params: [input.messageId, input.accountId],
    });
    const msgRow = msgRows[0];
    if (!msgRow) throw new StoreError(`message not found: ${input.messageId}`);
    const sizeBytes = Number(msgRow.size_bytes);

    const { rows: fromRows } = await this.db.query({
      sql: "SELECT uid FROM message_mailbox WHERE mailbox_id = ? AND message_id = ?",
      params: [input.fromMailboxId, input.messageId],
    });
    const fromRow = fromRows[0];
    if (!fromRow) throw new StoreError(`message not in source mailbox: ${input.messageId}`);
    const fromUid = Number(fromRow.uid);

    const { rows: toMbxRows } = await this.db.query({
      sql: "SELECT uidnext FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
      params: [input.toMailboxId, input.accountId],
    });
    const toMbxRow = toMbxRows[0];
    if (!toMbxRow) throw new StoreError(`target mailbox not found: ${input.toMailboxId}`);
    const toUidNext = Number(toMbxRow.uidnext);

    // COPY 대상에 이미 있는 메시지: 스냅샷 선검사해 no-op (§5-2 계약, MOVE에도 동일 적용)
    const { rows: existingRows } = await this.db.query({
      sql: "SELECT uid FROM message_mailbox WHERE mailbox_id = ? AND message_id = ?",
      params: [input.toMailboxId, input.messageId],
    });
    if (existingRows.length > 0) {
      return { uid: Number(existingRows[0]!.uid), modseq: acct.modseq };
    }

    const { rows: seenRows } = await this.db.query({
      sql: "SELECT 1 AS x FROM message_keywords WHERE message_id = ? AND keyword = '$seen'",
      params: [input.messageId],
    });
    const seen = seenRows.length > 0;

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const newUid = toUidNext;

    await this.db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
      { sql: "DELETE FROM message_mailbox WHERE mailbox_id = ? AND uid = ?", params: [input.fromMailboxId, fromUid] },
      {
        sql: "INSERT INTO message_mailbox (mailbox_id, uid, message_id, savedate, deleted) VALUES (?, ?, ?, ?, 0)",
        params: [input.toMailboxId, newUid, input.messageId, now],
      },
      {
        sql: "INSERT INTO expunged (mailbox_id, uid, modseq, created_at) VALUES (?, ?, ?, ?)",
        params: [input.fromMailboxId, fromUid, nextModseq, now],
      },
      { sql: "UPDATE messages SET modseq = ? WHERE id = ?", params: [nextModseq, input.messageId] },
      // ★destroyed 아님 — 메일함 이동은 Email updated (§7-3)
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, input.messageId, CHANGE_KIND.updated, now] },
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.fromMailboxId, CHANGE_KIND.updated, now] },
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.toMailboxId, CHANGE_KIND.updated, now] },
      {
        sql: `UPDATE mailboxes SET total_count = total_count - 1, total_bytes = total_bytes - ?, unread_count = unread_count - ?, highestmodseq = ? WHERE id = ?`,
        params: [sizeBytes, seen ? 0 : 1, nextModseq, input.fromMailboxId],
      },
      {
        sql: `UPDATE mailboxes SET uidnext = ?, total_count = total_count + 1, total_bytes = total_bytes + ?, unread_count = unread_count + ?, highestmodseq = ? WHERE id = ?`,
        params: [newUid + 1, sizeBytes, seen ? 0 : 1, nextModseq, input.toMailboxId],
      },
      {
        sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ? WHERE id = ?",
        params: [nextModseq, nextModseq, nextModseq, input.accountId],
      },
    ]);

    return { uid: newUid, modseq: nextModseq };
  }

  // ── CopyMessage — IMAP COPY (§5-2 membership 공유, moveMessage 변형) ──
  async copyMessage(input: CopyMessageInput): Promise<MoveMessageResult> {
    return this.writer.run(input.accountId, () => this.withRetry(() => this.copyMessageAttempt(input)));
  }

  private async copyMessageAttempt(input: CopyMessageInput): Promise<MoveMessageResult> {
    const acct = await this.mustGetAccount(input.accountId);

    const { rows: msgRows } = await this.db.query({
      sql: "SELECT size_bytes FROM messages WHERE id = ? AND account_id = ?",
      params: [input.messageId, input.accountId],
    });
    const msgRow = msgRows[0];
    if (!msgRow) throw new StoreError(`message not found: ${input.messageId}`);
    const sizeBytes = Number(msgRow.size_bytes);

    const { rows: toMbxRows } = await this.db.query({
      sql: "SELECT uidnext FROM mailboxes WHERE id = ? AND account_id = ? AND status = 1",
      params: [input.toMailboxId, input.accountId],
    });
    const toMbxRow = toMbxRows[0];
    if (!toMbxRow) throw new StoreError(`target mailbox not found: ${input.toMailboxId}`);
    const toUidNext = Number(toMbxRow.uidnext);

    // 대상에 이미 있는 메시지: 선검사 no-op (§5-2 계약 — ux_mm_message 충돌 방지)
    const { rows: existingRows } = await this.db.query({
      sql: "SELECT uid FROM message_mailbox WHERE mailbox_id = ? AND message_id = ?",
      params: [input.toMailboxId, input.messageId],
    });
    if (existingRows.length > 0) {
      return { uid: Number(existingRows[0]!.uid), modseq: acct.modseq };
    }

    const { rows: seenRows } = await this.db.query({
      sql: "SELECT 1 AS x FROM message_keywords WHERE message_id = ? AND keyword = '$seen'",
      params: [input.messageId],
    });
    const seen = seenRows.length > 0;

    const now = Date.now();
    const nextModseq = acct.modseq + 1;
    const newUid = toUidNext;

    await this.db.batch([
      { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [input.accountId, nextModseq] },
      {
        sql: "INSERT INTO message_mailbox (mailbox_id, uid, message_id, savedate, deleted) VALUES (?, ?, ?, ?, 0)",
        params: [input.toMailboxId, newUid, input.messageId, now],
      },
      { sql: "UPDATE messages SET modseq = ? WHERE id = ?", params: [nextModseq, input.messageId] },
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Email, input.messageId, CHANGE_KIND.updated, now] },
      { sql: CHANGE_LOG_SQL, params: [input.accountId, nextModseq, ENTITY.Mailbox, input.toMailboxId, CHANGE_KIND.updated, now] },
      {
        sql: `UPDATE mailboxes SET uidnext = ?, total_count = total_count + 1, total_bytes = total_bytes + ?, unread_count = unread_count + ?, highestmodseq = ? WHERE id = ?`,
        params: [newUid + 1, sizeBytes, seen ? 0 : 1, nextModseq, input.toMailboxId],
      },
      {
        sql: "UPDATE accounts SET modseq = ?, state_email = ?, state_mailbox = ? WHERE id = ?",
        params: [nextModseq, nextModseq, nextModseq, input.accountId],
      },
    ]);

    return { uid: newUid, modseq: nextModseq };
  }

  // ── 읽기 경로 (status=1 가시성 계약 §7-7) ─────────────────────────────
  // ── JMAP 읽기 레이어 (RFC 8620 §5.2, SCHEMA §6) ──────────────────────
  /** JMAP 타입별 state 문자열 = accounts.state_* 고수위(§6-3, max(로그) 조회 금지). */
  // ── JMAP 쿼리 — 구현은 jmap-store.ts ────────────────────────────────────
  jmapState(accountId: string): Promise<JmapStates> {
    return jmapState(this.internals, accountId);
  }

  jmapChanges(accountId: string, entity: JmapEntity, sinceState: string, maxChanges: number): Promise<JmapChanges> {
    return jmapChanges(this.internals, accountId, entity, sinceState, maxChanges);
  }

  getEmailsForJmap(accountId: string, ids: readonly string[]): Promise<JmapEmailMeta[]> {
    return getEmailsForJmap(this.internals, accountId, ids);
  }

  /** `SearchSnippet/get`용 원문 — `message_text`의 유일한 독자다(jmap-store.ts 주석 참조). */
  getMessageTextForSnippets(accountId: string, ids: readonly string[]): Promise<Map<string, { subject: string | null; body: string | null }>> {
    return getMessageTextForSnippets(this.internals, accountId, ids);
  }

  queryEmails(accountId: string, filter: JmapEmailFilter, ascending: boolean, position: number, limit: number): Promise<JmapEmailQueryResult> {
    return queryEmails(this.internals, accountId, filter, ascending, position, limit);
  }

  getThreadsForJmap(accountId: string, ids: readonly string[] | null): Promise<{ id: string; emailIds: string[] }[]> {
    return getThreadsForJmap(this.internals, accountId, ids);
  }

  getIdentities(accountId: string): Promise<{ id: string; email: string; name: string | null; replyTo: string | null; textSignature: string; htmlSignature: string }[]> {
    return getIdentities(this.internals, accountId);
  }

  async getAccountTenantId(accountId: string): Promise<string | null> {
    const { rows } = await this.db.query({ sql: "SELECT tenant_id FROM accounts WHERE id = ?", params: [accountId] });
    return rows[0] ? String(rows[0].tenant_id) : null;
  }

  /** EmailSubmission 레코드 생성 (RFC 8621 §7) — state_submission·change_log 갱신. */
  createSubmission(
    accountId: string,
    input: { identityId: string; messageId: string | null; blobId: string; envFrom: string; sendAt: number; undoStatus: number },
  ): Promise<string> {
    return createSubmission(this.internals, accountId, input);
  }

  getSubmissions(accountId: string, ids: readonly string[] | null): Promise<{ id: string; identityId: string; emailId: string | null; envFrom: string; sendAt: number; undoStatus: number }[]> {
    return getSubmissions(this.internals, accountId, ids);
  }

  async getAccountByEmail(email: string): Promise<AccountRow | null> {
    const { rows } = await this.db.query({
      sql: "SELECT id, tenant_id, email, status, modseq, quota_bytes, used_bytes, message_count FROM accounts WHERE email = ?",
      params: [email.toLowerCase()],
    });
    const row = rows[0];
    return row ? mapAccountRow(row) : null;
  }

  async listMailboxes(accountId: string): Promise<MailboxRow[]> {
    const { rows } = await this.db.query({
      sql: `SELECT id, account_id, parent_id, name, role, status, uidvalidity, uidnext, highestmodseq, total_count, unread_count, total_bytes, subscribed, expunged_floor
            FROM mailboxes WHERE account_id = ? AND status = 1 ORDER BY sort_order, name`,
      params: [accountId],
    });
    return rows.map(mapMailboxRow);
  }

  // ── 수신 웹훅 (Phase 4) — 구현은 webhook-store.ts ────────────────────────
  addWebhookEndpoint(accountId: string, url: string, secret: string): Promise<string> {
    return addWebhookEndpoint(this.internals, accountId, url, secret);
  }

  listWebhookEndpoints(accountId: string): Promise<{ id: string; url: string; active: boolean }[]> {
    return listWebhookEndpoints(this.internals, accountId);
  }

  deleteWebhookEndpoint(accountId: string, id: string): Promise<void> {
    return deleteWebhookEndpoint(this.internals, accountId, id);
  }

  enqueueWebhookDeliveries(accountId: string, payload: string): Promise<number> {
    return enqueueWebhookDeliveries(this.internals, accountId, payload);
  }

  // ── Sieve 스크립트 저장소 — 구현은 sieve-store.ts ────────────────────────
  getActiveSieveScript(accountId: string): Promise<string | null> {
    return getActiveSieveScript(this.internals, accountId);
  }

  putSieveScript(accountId: string, name: string, content: string): Promise<void> {
    return putSieveScript(this.internals, accountId, name, content);
  }

  listSieveScripts(accountId: string): Promise<{ name: string; active: boolean }[]> {
    return listSieveScripts(this.internals, accountId);
  }

  getSieveScript(accountId: string, name: string): Promise<string | null> {
    return getSieveScript(this.internals, accountId, name);
  }

  deleteSieveScript(accountId: string, name: string): Promise<void> {
    return deleteSieveScript(this.internals, accountId, name);
  }

  setActiveSieveScript(accountId: string, name: string): Promise<void> {
    return setActiveSieveScript(this.internals, accountId, name);
  }

  renameSieveScript(accountId: string, from: string, to: string): Promise<void> {
    return renameSieveScript(this.internals, accountId, from, to);
  }

  async getMailboxByRole(accountId: string, role: string): Promise<MailboxRow | null> {
    const { rows } = await this.db.query({
      sql: `SELECT id, account_id, parent_id, name, role, status, uidvalidity, uidnext, highestmodseq, total_count, unread_count, total_bytes, subscribed
            FROM mailboxes WHERE account_id = ? AND role = ? AND status = 1 LIMIT 1`,
      params: [accountId, role],
    });
    const row = rows[0];
    return row ? mapMailboxRow(row) : null;
  }

  async getMailboxByName(accountId: string, parentId: string, name: string): Promise<MailboxRow | null> {
    const { rows } = await this.db.query({
      sql: `SELECT id, account_id, parent_id, name, role, status, uidvalidity, uidnext, highestmodseq, total_count, unread_count, total_bytes, subscribed
            FROM mailboxes WHERE account_id = ? AND parent_id = ? AND name = ? AND status = 1 LIMIT 1`,
      params: [accountId, parentId, name],
    });
    const row = rows[0];
    return row ? mapMailboxRow(row) : null;
  }

  /** POP3 maildrop 뷰 — UID 오름차순. */
  async listMessages(mailboxId: string): Promise<MessageListItem[]> {
    const { rows } = await this.db.query({
      sql: `SELECT mm.uid AS uid, mm.message_id AS message_id, mm.deleted AS deleted, m.size_bytes AS size_bytes
            FROM message_mailbox mm
            JOIN messages m ON m.id = mm.message_id
            JOIN mailboxes b ON b.id = mm.mailbox_id
            WHERE mm.mailbox_id = ? AND b.status = 1
            ORDER BY mm.uid ASC`,
      params: [mailboxId],
    });
    return rows.map((r) => ({
      uid: Number(r.uid),
      messageId: String(r.message_id),
      sizeBytes: Number(r.size_bytes),
      deleted: Number(r.deleted) === 1,
    }));
  }

  async getMessageBlob(messageId: string): Promise<MessageBlobRef | null> {
    const { rows } = await this.db.query({
      sql: `SELECT b.id AS blob_id, b.generation AS generation FROM messages m JOIN blobs b ON b.id = m.blob_id WHERE m.id = ?`,
      params: [messageId],
    });
    const row = rows[0];
    return row ? { blobId: String(row.blob_id), generation: Number(row.generation) } : null;
  }
}
