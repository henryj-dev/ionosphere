/**
 * JMAP 전용 스토어 질의 (RFC 8620/8621) — Email/Mailbox/Thread state·changes·query,
 * Identity, EmailSubmission.
 *
 * 이전엔 이 코드가 Store 클래스 안에 있어서 **JMAP 프로토콜 의미론이 스토어 계층에 박혀
 * 있었다**. "Email/query에 필터를 추가" 같은 프로토콜 변경이 IMAP·POP3·CLI까지 쓰는
 * 1700줄짜리 store.ts를 건드리게 됐다. 이제 프로토콜 변경은 이 파일에서 끝난다.
 *
 * 공개 API는 Store가 그대로 위임하므로 호출부(jmap-backend)는 바뀌지 않는다.
 */
import { ulid } from "@ionosphere/core";
import { isAddressKind, type AddressKind } from "@ionosphere/db";
import { chunk, MAX_PARAMS_PER_STATEMENT, queryInChunks, rowsPerStatement } from "./chunk.ts";
import { CHANGE_KIND, CHANGE_LOG_SQL, ENTITY, groupBy, SEARCH_FIELD } from "./codes.ts";
import { tokenizeQuery } from "./tokenize.ts";
import { StoreError } from "./errors.ts";
import type { StoreInternals } from "./internals.ts";
import type {
  JmapChanges,
  JmapEmailFilter,
  JmapEmailMeta,
  JmapEmailQueryResult,
  JmapEntity,
  JmapStates,
} from "./types.ts";

export async function jmapState(s: StoreInternals, accountId: string): Promise<JmapStates> {
  const { rows } = await s.db.query({
    sql: "SELECT state_email, state_mailbox, state_thread, state_submission FROM accounts WHERE id = ?",
    params: [accountId],
  });
  const row = rows[0];
  if (!row) throw new StoreError(`account not found: ${accountId}`);
  return {
    email: String(Number(row.state_email)),
    mailbox: String(Number(row.state_mailbox)),
    thread: String(Number(row.state_thread)),
    submission: String(Number(row.state_submission)),
  };
}

/**
 * JMAP `/changes` (RFC 8620 §5.2, SCHEMA §6-1). change_log를 modseq 윈도로 읽어
 * object_id별 dedup(created+updated→created, created+destroyed→생략, updated+destroyed→destroyed).
 * sinceState < changelog_floor(또는 미래/불량 state) → cannotCalculate. maxChanges는 modseq
 * 경계 단위 페이징(경계를 쪼개지 않음 — 첫 그룹은 초과해도 항상 포함해 진행 보장).
 */
export async function jmapChanges(s: StoreInternals, accountId: string, entity: JmapEntity, sinceState: string, maxChanges: number): Promise<JmapChanges> {
  const since = Number(sinceState);
  if (!Number.isSafeInteger(since) || since < 0) return { cannotCalculate: true };

  const { rows: accRows } = await s.db.query({
    sql: "SELECT changelog_floor, state_email, state_mailbox, state_thread, state_submission FROM accounts WHERE id = ?",
    params: [accountId],
  });
  const acc = accRows[0];
  if (!acc) throw new StoreError(`account not found: ${accountId}`);

  const floor = Number(acc.changelog_floor);
  const stateCol = { email: "state_email", mailbox: "state_mailbox", thread: "state_thread", submission: "state_submission" }[entity];
  const currentState = Number(acc[stateCol]);
  if (since < floor || since > currentState) return { cannotCalculate: true };
  if (since === currentState) {
    return { cannotCalculate: false, oldState: sinceState, newState: sinceState, hasMoreChanges: false, created: [], updated: [], destroyed: [] };
  }

  const entityCode = { email: ENTITY.Email, mailbox: ENTITY.Mailbox, thread: ENTITY.Thread, submission: ENTITY.EmailSubmission }[entity];
  const { rows } = await s.db.query({
    sql: "SELECT modseq, object_id, kind FROM change_log WHERE account_id = ? AND entity = ? AND modseq > ? ORDER BY modseq ASC",
    params: [accountId, entityCode, since],
  });

  // modseq 그룹 단위로 누적 — 경계를 쪼개지 않음(maxChanges 초과해도 첫 그룹은 포함=진행 보장)
  const kinds = new Map<string, { c: boolean; u: boolean; d: boolean }>();
  let lastModseq = since;
  let stopped = false;
  let i = 0;
  while (i < rows.length) {
    const m = Number(rows[i]!.modseq);
    let j = i;
    const groupObjs: { obj: string; kind: number }[] = [];
    while (j < rows.length && Number(rows[j]!.modseq) === m) {
      groupObjs.push({ obj: String(rows[j]!.object_id), kind: Number(rows[j]!.kind) });
      j++;
    }
    const fresh = new Set(groupObjs.map((g) => g.obj).filter((o) => !kinds.has(o)));
    if (kinds.size > 0 && kinds.size + fresh.size > maxChanges) {
      stopped = true;
      break;
    }
    for (const g of groupObjs) {
      let e = kinds.get(g.obj);
      if (!e) {
        e = { c: false, u: false, d: false };
        kinds.set(g.obj, e);
      }
      if (g.kind === CHANGE_KIND.created) e.c = true;
      else if (g.kind === CHANGE_KIND.destroyed) e.d = true;
      else e.u = true;
    }
    lastModseq = m;
    i = j;
  }

  const created: string[] = [];
  const updated: string[] = [];
  const destroyed: string[] = [];
  for (const [obj, k] of kinds) {
    if (k.c && k.d) continue; // 순생성·소멸 net-zero → 생략(§6-1)
    else if (k.d) destroyed.push(obj);
    else if (k.c) created.push(obj);
    else updated.push(obj);
  }
  // 전부 소비했으면 newState=고수위(로그 없는 state 전진도 반영), 중단 시 마지막 포함 modseq
  return {
    cannotCalculate: false,
    oldState: sinceState,
    newState: stopped ? String(lastModseq) : String(currentState),
    hasMoreChanges: stopped,
    created,
    updated,
    destroyed,
  };
}

/**
 * JMAP Email/get 메타 조회 — 메시지 + membership + 키워드 + 주소를 계정 스코프로.
 * 본문(bodyStructure/bodyValues)은 어댑터가 blobId로 별도 조회(여기선 blobId/generation만).
 */
export async function getEmailsForJmap(s: StoreInternals, accountId: string, ids: readonly string[]): Promise<JmapEmailMeta[]> {
  if (ids.length === 0) return [];
  const out: JmapEmailMeta[] = [];
  for (const idChunk of chunk([...ids], rowsPerStatement(1) - 1)) {
    // lint-allow chunked-in-query: 바깥 chunk() 루프가 이미 한도를 건다(청크당 99개).
    const ph = idChunk.map(() => "?").join(", ");
    const { rows } = await s.db.query({
      sql: `SELECT m.id AS id, m.blob_id AS blob_id, m.thread_id AS thread_id, m.size_bytes AS size_bytes,
                   m.received_at AS received_at, m.subject AS subject, m.sent_at AS sent_at,
                   m.has_attachment AS has_attachment, m.preview AS preview, b.generation AS generation
            FROM messages m LEFT JOIN blobs b ON b.id = m.blob_id
            WHERE m.account_id = ? AND m.id IN (${ph})`,
      params: [accountId, ...idChunk],
    });
    if (rows.length === 0) continue;
    const foundIds = rows.map((r) => String(r.id));
    // lint-allow chunked-in-query: foundIds는 위 청크의 부분집합이라 같은 상한 안에 있다.
    const idPh = foundIds.map(() => "?").join(", ");
    const [mmRes, kwRes, addrRes] = await Promise.all([
      s.db.query({ sql: `SELECT message_id, mailbox_id FROM message_mailbox WHERE message_id IN (${idPh})`, params: foundIds }),
      s.db.query({ sql: `SELECT message_id, keyword FROM message_keywords WHERE message_id IN (${idPh})`, params: foundIds }),
      s.db.query({ sql: `SELECT message_id, kind, name, email FROM message_addresses WHERE message_id IN (${idPh}) ORDER BY kind, pos`, params: foundIds }),
    ]);
    const mailboxIds = groupBy(mmRes.rows, (r) => String(r.message_id), (r) => String(r.mailbox_id));
    const keywords = groupBy(kwRes.rows, (r) => String(r.message_id), (r) => String(r.keyword));
    // DB 행 → 타입 경계: 알 수 없는 kind는 버린다(스키마 변경 중 잔존 행 방어).
    const addresses = groupBy(addrRes.rows.filter((r) => isAddressKind(Number(r.kind))), (r) => String(r.message_id), (r) => ({
      kind: Number(r.kind) as AddressKind,
      name: r.name == null ? null : String(r.name),
      email: String(r.email),
    }));
    for (const r of rows) {
      const id = String(r.id);
      out.push({
        id,
        blobId: String(r.blob_id),
        blobGeneration: Number(r.generation ?? 0),
        threadId: String(r.thread_id),
        size: Number(r.size_bytes),
        receivedAt: Number(r.received_at),
        subject: r.subject == null ? null : String(r.subject),
        sentAt: r.sent_at == null ? null : Number(r.sent_at),
        hasAttachment: Number(r.has_attachment) === 1,
        preview: r.preview == null ? null : String(r.preview),
        mailboxIds: mailboxIds.get(id) ?? [],
        keywords: keywords.get(id) ?? [],
        addresses: addresses.get(id) ?? [],
      });
    }
  }
  return out;
}

/**
 * JMAP Email/query (RFC 8621 §4.4, v1 부분집합) — inMailbox/날짜/크기/키워드 필터 + receivedAt 정렬.
 * receivedAt DESC 기본(가장 흔한 뷰). 반환은 메시지 id + total.
 */
export async function queryEmails(s: StoreInternals, accountId: string, filter: JmapEmailFilter, ascending: boolean, position: number, limit: number): Promise<JmapEmailQueryResult> {
  const conds: string[] = ["m.account_id = ?"];
  const params: unknown[] = [accountId];
  if (filter.inMailbox) {
    conds.push("EXISTS (SELECT 1 FROM message_mailbox mm WHERE mm.message_id = m.id AND mm.mailbox_id = ?)");
    params.push(filter.inMailbox);
  }
  if (filter.after !== undefined) {
    conds.push("m.received_at >= ?");
    params.push(filter.after);
  }
  if (filter.before !== undefined) {
    conds.push("m.received_at < ?");
    params.push(filter.before);
  }
  if (filter.minSize !== undefined) {
    conds.push("m.size_bytes >= ?");
    params.push(filter.minSize);
  }
  if (filter.maxSize !== undefined) {
    conds.push("m.size_bytes < ?");
    params.push(filter.maxSize);
  }
  if (filter.hasKeyword) {
    conds.push("EXISTS (SELECT 1 FROM message_keywords k WHERE k.message_id = m.id AND k.keyword = ?)");
    params.push(filter.hasKeyword.toLowerCase());
  }
  if (filter.notKeyword) {
    conds.push("NOT EXISTS (SELECT 1 FROM message_keywords k WHERE k.message_id = m.id AND k.keyword = ?)");
    params.push(filter.notKeyword.toLowerCase());
  }
  // 전문 검색(FTS) — search_index CJK 바이그램. field=null이면 전 필드(text), 아니면 특정 필드.
  // 각 텍스트 필터의 모든 토큰을 (해당 필드에서) 포함하는 메시지만(AND). 토큰 없으면 매치 0.
  const ftsFilters: { field: number | null; value: string }[] = [];
  if (filter.text !== undefined) ftsFilters.push({ field: null, value: filter.text });
  if (filter.subject !== undefined) ftsFilters.push({ field: SEARCH_FIELD.subject, value: filter.subject });
  if (filter.body !== undefined) ftsFilters.push({ field: SEARCH_FIELD.body, value: filter.body });
  if (filter.from !== undefined) ftsFilters.push({ field: SEARCH_FIELD.from, value: filter.from });
  if (filter.to !== undefined) ftsFilters.push({ field: SEARCH_FIELD.to, value: filter.to });
  for (const f of ftsFilters) {
    const tokens = tokenizeQuery(f.value);
    if (tokens.length === 0) {
      conds.push("1 = 0"); // 인덱스 불가한 질의(토큰 없음) → 매치 없음
      continue;
    }
    if (tokens.length > MAX_PARAMS_PER_STATEMENT - 8) {
      throw new StoreError(`search filter has too many tokens (max ${MAX_PARAMS_PER_STATEMENT - 8})`);
    }
    const ph = tokens.map(() => "?").join(", ");
    const fieldCond = f.field === null ? "" : "AND si.field = ?";
    conds.push(
      `m.id IN (SELECT si.message_id FROM search_index si WHERE si.account_id = ? ${fieldCond} AND si.token IN (${ph}) GROUP BY si.message_id HAVING COUNT(DISTINCT si.token) = ?)`,
    );
    params.push(accountId);
    if (f.field !== null) params.push(f.field);
    params.push(...tokens, tokens.length);
  }
  const where = conds.join(" AND ");
  const { rows: countRows } = await s.db.query({ sql: `SELECT COUNT(*) AS n FROM messages m WHERE ${where}`, params });
  const total = Number(countRows[0]?.n ?? 0);
  const dir = ascending ? "ASC" : "DESC";
  // 안정 정렬용 2차 키 id — 동일 receivedAt 타이 브레이크
  const { rows } = await s.db.query({
    sql: `SELECT m.id AS id FROM messages m WHERE ${where} ORDER BY m.received_at ${dir}, m.id ${dir} LIMIT ? OFFSET ?`,
    params: [...params, limit, position],
  });
  return { ids: rows.map((r) => String(r.id)), total };
}

/**
 * JMAP Thread/get (RFC 8621 §3) — threadId별 소속 이메일 id(receivedAt 순). ids=null이면 전체 스레드.
 * 스레드는 ≥1 메시지가 그 thread_id를 가질 때만 "존재".
 */
export async function getThreadsForJmap(s: StoreInternals, accountId: string, ids: readonly string[] | null): Promise<{ id: string; emailIds: string[] }[]> {
  // 클라이언트가 주는 id 목록은 유계가 아니다 — 한도 안에서 나눠 돌린다(store/chunk.ts).
  const selectRows = (ph: string): string =>
    `SELECT id, thread_id FROM messages WHERE account_id = ?${ph === "" ? "" : ` AND thread_id IN (${ph})`} ORDER BY thread_id, received_at, id`;
  if (ids !== null && ids.length === 0) return [];
  const rows =
    ids === null
      ? (await s.db.query({ sql: selectRows(""), params: [accountId] })).rows
      : await queryInChunks(s.db, ids, selectRows, [accountId]);
  const byThread = new Map<string, string[]>();
  for (const r of rows) {
    const tid = String(r.thread_id);
    const arr = byThread.get(tid);
    if (arr) arr.push(String(r.id));
    else byThread.set(tid, [String(r.id)]);
  }
  return [...byThread.entries()].map(([id, emailIds]) => ({ id, emailIds }));
}

/**
 * JMAP Identity/get (RFC 8621 §6) — 발신 신원. identities 테이블 우선, 비어 있으면
 * 계정 이메일로 기본 신원 1개 합성(id=accountId, EmailSubmission이 참조 가능).
 */
export async function getIdentities(s: StoreInternals, accountId: string): Promise<{ id: string; email: string; name: string | null; replyTo: string | null; textSignature: string; htmlSignature: string }[]> {
  const { rows } = await s.db.query({
    sql: "SELECT id, email, name, reply_to, text_sig, html_sig FROM identities WHERE account_id = ? ORDER BY created_at",
    params: [accountId],
  });
  if (rows.length > 0) {
    return rows.map((r) => ({
      id: String(r.id),
      email: String(r.email),
      name: r.name == null ? null : String(r.name),
      replyTo: r.reply_to == null ? null : String(r.reply_to),
      textSignature: r.text_sig == null ? "" : String(r.text_sig),
      htmlSignature: r.html_sig == null ? "" : String(r.html_sig),
    }));
  }
  // 합성 기본 신원 — 계정 이메일
  const { rows: acc } = await s.db.query({ sql: "SELECT email FROM accounts WHERE id = ?", params: [accountId] });
  if (!acc[0]) return [];
  return [{ id: accountId, email: String(acc[0].email), name: null, replyTo: null, textSignature: "", htmlSignature: "" }];
}

/** 계정의 tenant_id (JMAP 발송 enqueue에 필요). */

export async function createSubmission(
  s: StoreInternals,
  accountId: string,
  input: { identityId: string; messageId: string | null; blobId: string; envFrom: string; sendAt: number; undoStatus: number },
): Promise<string> {
  return s.writer.run(accountId, () =>
    s.withRetry(async () => {
      const acct = await s.mustGetAccount(accountId);
      const id = ulid();
      const now = Date.now();
      const nextModseq = acct.modseq + 1;
      await s.db.batch([
        { sql: "INSERT INTO modseq_claims (account_id, modseq) VALUES (?, ?)", params: [accountId, nextModseq] },
        {
          sql: `INSERT INTO email_submissions (id, account_id, identity_id, message_id, blob_id, env_from, send_at, undo_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          params: [id, accountId, input.identityId, input.messageId, input.blobId, input.envFrom, input.sendAt, input.undoStatus, now],
        },
        { sql: CHANGE_LOG_SQL, params: [accountId, nextModseq, ENTITY.EmailSubmission, id, CHANGE_KIND.created, now] },
        { sql: "UPDATE accounts SET modseq = ?, state_submission = ? WHERE id = ?", params: [nextModseq, nextModseq, accountId] },
      ]);
      return id;
    }),
  );
}

/** EmailSubmission/get (RFC 8621 §7). ids=null이면 전체. */
export async function getSubmissions(s: StoreInternals, accountId: string, ids: readonly string[] | null): Promise<{ id: string; identityId: string; emailId: string | null; envFrom: string; sendAt: number; undoStatus: number }[]> {
  const selectRows = (ph: string): string =>
    `SELECT id, identity_id, message_id, env_from, send_at, undo_status FROM email_submissions WHERE account_id = ?${ph === "" ? "" : ` AND id IN (${ph})`} ORDER BY created_at`;
  if (ids !== null && ids.length === 0) return [];
  const rows =
    ids === null
      ? (await s.db.query({ sql: selectRows(""), params: [accountId] })).rows
      : await queryInChunks(s.db, ids, selectRows, [accountId]);
  return rows.map((r) => ({
    id: String(r.id),
    identityId: String(r.identity_id),
    emailId: r.message_id == null ? null : String(r.message_id),
    envFrom: String(r.env_from),
    sendAt: Number(r.send_at),
    undoStatus: Number(r.undo_status),
  }));
}

