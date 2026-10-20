/**
 * 계정 삭제 드레인 — SCHEMA §7-7 「계정 삭제 = accounts.status=2 + 전 메일함 + credentials/sieve/… 정리」의 구현.
 *
 * ★왜 생겼나(2026-10-19 P8 확인): `account-delete`는 `status=2`로 바꾸기만 했고, 그 뒤를 맡을 드레인이
 * **어디에도 없었다.** 리퍼는 지운 메일함(mailboxes.status=2)만 수거했다. 그래서 탈퇴한 계정의 메일·본문
 * 색인·자격증명·sieve가 영구히 남았다. 회원 공통 기준은 「즉시 비노출 + 24시간 안 드레인」이다.
 *
 * 즉시 비노출은 이미 성립한다 — 로그인·열린 연결·웹 세션·SSO·수신 라우팅이 모두 `status=1`만 받는다.
 * 여기는 그 뒤에 **실제로 지우는** 일만 한다.
 *
 * 설계:
 * - 메시지는 쪽(page) 단위로 지운다. 한 쪽 = 한 배치라 쪽 안에서는 원자적이고, 중간에 서버가 죽어도
 *   다음 tick이 남은 것부터 이어 간다(모든 문장이 멱등한 DELETE다).
 * - change_log·modseq를 남기지 않는다. 계정이 이미 어떤 클라이언트에도 보이지 않으므로 변경을 알릴
 *   상대가 없다. 그래서 `Store.reapMailbox`(활성 계정 전제, `mustGetAccount`가 막는다)를 쓰지 않는다.
 * - accounts 행은 **마지막에** 지운다. 그 전까지 이메일 유니크 키가 주소 재등록을 막는다(§7-7 — 드레인
 *   중 새 계정이 옛 메일을 받는 사고 방지).
 * - 서버 세 대의 리퍼가 같은 계정을 함께 지울 수 있다. 문장이 전부 멱등해 결과는 같다.
 *
 * 지우지 않는 것:
 * - `identity_claims`(SSO sub·디렉터리 외부 키의 최초 주인) — 같은 식별자를 다른 계정에 다시 잇지 못하게 하는
 *   묘비라 계정이 사라져도 남긴다(마이그레이션 029). 디렉터리 외부 키는 SHA-256만 적는다.
 * - 블롭 파일 — `blob_refs`를 지우면 블롭 GC가 참조 0으로 보고 회수한다. GC가 `off`면 파일은 남는다.
 */
import { ACCOUNT_STATUS, MTA_QUEUE_STATUS, REF_KIND, type DbDriver, type Statement } from "@ionosphere/db";
import { chunk } from "./chunk.ts";
import { directoryClaimStatement } from "./directory-claims.ts";

/** 계정 드레인 마감 — 회원 공통 기준(2026-10-19 P8). 넘기면 지표가 overdue로 센다. */
export const ACCOUNT_DRAIN_DEADLINE_MS = 24 * 60 * 60 * 1000;

/**
 * 한 쪽에 담는 메시지 수. 가장 긴 문장(search_index·blob_refs)이 계정 id 2개 + 메시지 id를 받으므로
 * 문장당 파라미터 상한(`chunk.ts` MAX_PARAMS_PER_STATEMENT = 100) 안에 들게 98이다.
 */
const PAGE_MESSAGES = 98;
/**
 * 삭제 뒤 드레인을 시작하기까지의 유예. JMAP 인증 캐시(30초) 동안은 이미 열린 세션이 vacation·push·sieve를
 * 쓸 수 있다 — store의 그 쓰기들은 계정 상태를 보지 않는다. 드레인이 계정 행까지 지운 **뒤에** 그런 쓰기가
 * 들어오면 다시 찾을 계정 행이 없어 영구 고아가 된다. 캐시보다 넉넉히 기다린다. 24시간 마감에는 영향이 없다.
 */
export const ACCOUNT_DRAIN_GRACE_MS = 2 * 60 * 1000;
/** tick 한 번에 계정 하나당 지우는 쪽 수 — 리퍼 한 주기가 한 계정에 묶여 다른 일을 굶기지 않게. */
const DEFAULT_MAX_PAGES = 20;

export interface AccountDrainResult {
  /** 이번 호출로 지운 메시지 수. */
  messages: number;
  /** accounts 행까지 지워 드레인이 끝났으면 true. */
  done: boolean;
}

export interface AccountDrainStatus {
  /** 드레인 중인 계정 수(status=2). */
  pending: number;
  /** 마감(24시간)을 넘긴 계정 수. */
  overdue: number;
}

/** 드레인할 계정 — 오래된 것부터. 삭제한 지 유예(`ACCOUNT_DRAIN_GRACE_MS`)가 지난 것만. */
export async function listDrainingAccounts(db: DbDriver, limit = 10, now = Date.now()): Promise<string[]> {
  const { rows } = await db.query({
    sql: `SELECT id FROM accounts WHERE status = ${ACCOUNT_STATUS.deleting} AND (deleting_since IS NULL OR deleting_since <= ?)
            ORDER BY deleting_since, id LIMIT ?`,
    params: [now - ACCOUNT_DRAIN_GRACE_MS, limit],
  });
  return rows.map((r) => String(r.id));
}

/** 지표용 — 드레인 적체와 마감 초과 수. */
export async function accountDrainStatus(db: DbDriver, now = Date.now()): Promise<AccountDrainStatus> {
  const { rows } = await db.query({
    sql: `SELECT COUNT(*) AS pending,
                 SUM(CASE WHEN deleting_since IS NULL OR deleting_since < ? THEN 1 ELSE 0 END) AS overdue
            FROM accounts WHERE status = ${ACCOUNT_STATUS.deleting}`,
    params: [now - ACCOUNT_DRAIN_DEADLINE_MS],
  });
  return { pending: Number(rows[0]?.pending ?? 0), overdue: Number(rows[0]?.overdue ?? 0) };
}

/**
 * 계정 하나를 드레인한다. 메시지가 많으면 `maxPages`쪽까지만 하고 돌아온다(`done: false`) —
 * 다음 호출이 이어 간다. 계정이 없거나 `status=2`가 아니면 아무것도 지우지 않는다.
 */
export async function drainAccount(db: DbDriver, accountId: string, opts: { maxPages?: number; now?: number } = {}): Promise<AccountDrainResult> {
  if (!(await isDraining(db, accountId))) return { messages: 0, done: false };
  const maxPages = opts.maxPages ?? DEFAULT_MAX_PAGES;
  let messages = 0;
  for (let page = 0; page < maxPages; page++) {
    const { rows } = await db.query({ sql: "SELECT id FROM messages WHERE account_id = ? LIMIT ?", params: [accountId, PAGE_MESSAGES] });
    if (rows.length === 0) break;
    const ids = rows.map((r) => String(r.id));
    await db.batch(messagePageStatements(accountId, ids));
    messages += ids.length;
  }
  // 아직 메시지가 남았으면(쪽 상한) 계정 단위 정리는 다음 호출로 미룬다 — 메시지 쪽이 그 정리보다 먼저다.
  const { rows: left } = await db.query({ sql: "SELECT 1 AS x FROM messages WHERE account_id = ? LIMIT 1", params: [accountId] });
  if (left.length > 0) return { messages, done: false };

  /**
   * 발송 중(inFlight) 큐 항목은 지우지 않고 기다린다. 워커가 리스를 쥐고 SMTP 대화 중인 행을 지우면
   * 배달 결과를 쓸 곳이 사라진다. 리스는 짧아서 다음 tick이면 풀린다. 남아 있으면 accounts 행을 지우지 않는다.
   * 리스가 **만료된** 발송 중 행은 지운다 — 그대로 두면 워커가 회수해 탈퇴한 계정의 메일을 다시 보내려 한다.
   */
  const { rows: directoryLinks } = await db.query({
    sql: "SELECT tenant_id, provider, external_key FROM directory_identities WHERE account_id = ? AND provider NOT LIKE 'oidc:%'",
    params: [accountId],
  });
  const now = opts.now ?? Date.now();
  /**
   * D1은 배치당 문장 1000개가 상한이다. 묘비를 900개씩 먼저 남긴다 — 계정은 이미 삭제 중이고
   * 되살릴 수 없으므로 중간에 죽어도 다음 tick이 같은 INSERT IGNORE를 다시 하며 수렴한다.
   */
  for (const part of chunk(directoryLinks, 900)) {
    await db.batch(
      part.map((row) =>
        directoryClaimStatement(db, String(row.tenant_id), String(row.provider), String(row.external_key), accountId, now),
      ),
    );
  }
  const results = await db.batch([...accountStatements(accountId, now), finalDeleteStatement(accountId)]);
  return { messages, done: (results[results.length - 1]?.changes ?? 0) > 0 };
}

async function isDraining(db: DbDriver, accountId: string): Promise<boolean> {
  const { rows } = await db.query({ sql: `SELECT 1 AS x FROM accounts WHERE id = ? AND status = ${ACCOUNT_STATUS.deleting}`, params: [accountId] });
  return rows.length > 0;
}

/** 메시지 한 쪽 — 메시지에 매달린 행을 모두 지운다. `account_id` 조건은 남의 메시지를 지우지 않게 하는 이중 잠금이다. */
function messagePageStatements(accountId: string, ids: readonly string[]): Statement[] {
  const ph = ids.map(() => "?").join(", ");
  const owned = `(SELECT id FROM messages WHERE account_id = ? AND id IN (${ph}))`;
  const byMessage = (table: string, column = "message_id"): Statement => ({
    sql: `DELETE FROM ${table} WHERE ${column} IN ${owned}`,
    params: [accountId, ...ids],
  });
  return [
    byMessage("message_mailbox"),
    byMessage("message_keywords"),
    byMessage("message_addresses"),
    byMessage("message_header_projection"),
    // ★본문 텍스트와 검색 색인 — 남으면 지운 메일의 본문이 DB와 백업에 영구히 남는다(reapMailbox와 같은 이유).
    byMessage("message_text"),
    byMessage("message_auth"),
    /**
     * ★search_index·blob_refs는 계정 id를 **앞에** 건다. 두 테이블 모두 message_id만으로 찾는 인덱스가 없어
     * (PK가 각각 (account_id, token, …)·(blob_id, …)) 계정 조건이 없으면 쪽마다 모든 테넌트의 행을 훑는다 —
     * MySQL에서는 훑은 행에 잠금이 걸려 다른 계정의 수신이 막힌다(2026-10-19 리뷰).
     */
    { sql: `DELETE FROM search_index WHERE account_id = ? AND message_id IN ${owned}`, params: [accountId, accountId, ...ids] },
    { sql: `DELETE FROM blob_refs WHERE account_id = ? AND ref_kind = ${REF_KIND.message} AND ref_id IN ${owned}`, params: [accountId, accountId, ...ids] },
    // messages 행은 맨 끝 — 위 문장들이 owned 하위 질의로 이 행을 본다.
    { sql: `DELETE FROM messages WHERE account_id = ? AND id IN (${ph})`, params: [accountId, ...ids] },
  ];
}

/** 계정 단위 정리 — 메시지가 다 지워진 뒤에 돈다. */
function accountStatements(accountId: string, now: number): Statement[] {
  const mailboxes = "(SELECT id FROM mailboxes WHERE account_id = ?)";
  const principals = "(SELECT id FROM principals WHERE account_id = ?)";
  const byAccount = (table: string, column = "account_id"): Statement => ({ sql: `DELETE FROM ${table} WHERE ${column} = ?`, params: [accountId] });
  return [
    // 메일함과 거기 매달린 것. 메시지 쪽에서 못 지운 membership(다른 계정 메시지를 가리키는 일은 없다)도 여기서 마저.
    { sql: `DELETE FROM message_mailbox WHERE mailbox_id IN ${mailboxes}`, params: [accountId] },
    { sql: `DELETE FROM expunged WHERE mailbox_id IN ${mailboxes}`, params: [accountId] },
    // ACL — 이 계정 메일함에 걸린 권한과, 이 계정이 남의 메일함에 받은 권한 둘 다.
    { sql: `DELETE FROM mailbox_acl WHERE mailbox_id IN ${mailboxes}`, params: [accountId] },
    { sql: `DELETE FROM mailbox_acl WHERE principal_id IN ${principals}`, params: [accountId] },
    byAccount("mailboxes"),
    byAccount("search_index"),
    // 메시지 행 없이 남은 옛 고아(키워드·주소 — 주소에는 개인정보가 있다)까지 계정 id로 마저 지운다.
    byAccount("message_keywords"),
    byAccount("message_addresses"),
    byAccount("thread_refs"),
    byAccount("change_log"),
    byAccount("modseq_claims"),
    // 자격증명 — 기본 비밀번호·앱 비밀번호·OAuth 토큰. 웹 세션과 MFA 비밀도 함께.
    byAccount("credentials"),
    byAccount("account_sessions"),
    byAccount("account_mfa"),
    byAccount("account_recovery_codes"),
    byAccount("push_subscriptions", "subject_id"),
    byAccount("sieve_scripts"),
    byAccount("vacation_response"),
    byAccount("vacation_sent"),
    byAccount("identities"),
    byAccount("email_submissions"),
    {
      sql: `DELETE FROM mta_queue WHERE account_id = ? AND (status != ${MTA_QUEUE_STATUS.inFlight} OR lease_until IS NULL OR lease_until < ?)`,
      params: [accountId, now],
    },
    /**
     * 큐·업로드 블롭 참조 — 메시지 참조는 쪽에서 이미 지웠다. 바로 위에서 남겨 둔 발송 중 큐 행의 참조는 지우지 않는다 —
     * 지우면 워커가 본문을 다시 읽기 전에 블롭 GC가 그 파일을 회수 대상으로 찍는다.
     */
    {
      sql: `DELETE FROM blob_refs WHERE account_id = ?
              AND NOT (ref_kind = ${REF_KIND.queue} AND ref_id IN (SELECT id FROM mta_queue WHERE account_id = ?))`,
      params: [accountId, accountId],
    },
    byAccount("dedup_tracking"),
    byAccount("webhook_deliveries"),
    byAccount("webhook_endpoints"),
    byAccount("maildrop_locks"),
    byAccount("bayes_tokens"),
    byAccount("bayes_totals"),
    byAccount("account_memberships"),
    { sql: `DELETE FROM account_memberships WHERE principal_id IN ${principals}`, params: [accountId] },
    byAccount("principals"),
    byAccount("directory_identities"),
    // 주소→계정 연결. 주소 행(addresses) 자체는 계정을 모른다(마이그레이션 006) — 알리아스 소유라 지우지 않는다.
    byAccount("address_targets"),
  ];
}

/**
 * accounts 행 — 메시지와 발송 중 큐가 정말 비었을 때만. 쪽을 다 지운 뒤에도 그 사이 끼어든 배달이
 * 있을 수 있어(상태 확인과 저장 사이) 같은 문장 안에서 다시 본다.
 */
function finalDeleteStatement(accountId: string): Statement {
  return {
    sql: `DELETE FROM accounts WHERE id = ? AND status = ${ACCOUNT_STATUS.deleting}
            AND NOT EXISTS (SELECT 1 FROM messages WHERE account_id = ?)
            AND NOT EXISTS (SELECT 1 FROM mta_queue WHERE account_id = ?)`,
    params: [accountId, accountId, accountId],
  };
}
