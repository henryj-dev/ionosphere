/**
 * IonosphereImapBackend — proto-imap ImapBackend를 Store/BlobStore 위에 구현.
 *
 * 플래그 매핑(RFC 8621 정합 — 스토어 키워드는 소문자 JMAP 표기):
 *   \Seen↔$seen, \Answered↔$answered, \Flagged↔$flagged, \Draft↔$draft.
 *   \Deleted는 membership 컬럼(message_mailbox.deleted — SCHEMA §5-2 확정 모델).
 *   그 외 키워드는 소문자 저장 원형을 그대로 표면화(관례 케이싱 복원은 표준 4종만).
 *
 * 메일함 이름: IMAP 전체 경로(구분자 '/') ↔ 스토어 parent_id 트리를 여기서 변환.
 */
import { noopLogger, type Logger, type PrincipalContext } from "@ionosphere/core";
import { ADDRESS_KIND, type DbDriver } from "@ionosphere/db";
import { parseMessage, type ParsedAddress, type ParsedMessage } from "@ionosphere/mime";
import {
  authenticate,
  putBlob,
  queryInChunks,
  StoreError,
  StoreQuotaError,
  type AppendAddress,
  type BlobStore,
  type AppendMessageInput,
  type MailboxRow,
  Store,
  scramKeysFor,
  scramAuthorize,
} from "@ionosphere/store";
import type { ImapBackend, ImapBackendRequest, ImapBackendResponse, ImapFetchData, ImapMailbox, SeqRange } from "@ionosphere/proto-imap";
import { toAppendAddresses } from "./addresses.ts";

const DELIM = "/";

/** IMAP 시스템 플래그 ↔ 스토어 키워드. */
const FLAG_TO_KEYWORD: Record<string, string> = {
  "\\seen": "$seen",
  "\\answered": "$answered",
  "\\flagged": "$flagged",
  "\\draft": "$draft",
};
const KEYWORD_TO_FLAG: Record<string, string> = {
  $seen: "\\Seen",
  $answered: "\\Answered",
  $flagged: "\\Flagged",
  $draft: "\\Draft",
};

function flagToKeyword(flag: string): string | null {
  const lower = flag.toLowerCase();
  if (lower === "\\deleted") return null; // membership 컬럼 — 호출자가 분리 처리
  if (lower === "\\recent") return null; // rev2 — 미지원
  return FLAG_TO_KEYWORD[lower] ?? lower;
}

function keywordToFlag(keyword: string): string {
  return KEYWORD_TO_FLAG[keyword] ?? keyword;
}

interface PathedMailbox {
  row: MailboxRow;
  path: string;
}

export class IonosphereImapBackend implements ImapBackend {
  private readonly db: DbDriver;
  private readonly store: Store;
  private readonly blobs: BlobStore;
  private readonly log: Logger;

  constructor(db: DbDriver, store: Store, blobs: BlobStore, logger: Logger = noopLogger) {
    this.db = db;
    this.store = store;
    this.blobs = blobs;
    this.log = logger.child({ component: "imap" });
  }

  async authenticate(user: string, pass: string): Promise<{ accountId: string; credKind?: string | undefined } | null> {
    const result = await authenticate(this.db, user, pass, "imap");
    if (!result) {
      this.log.warn("auth failed", { user });
      return null;
    }
    this.log.info("auth ok", { user, accountId: result.accountId });
    // credKind를 어댑터로 올려 보낸다 — 감사 로그가 자격증명 종류를 남기는 유일한 경로다
    // (여기엔 IP가 없고 어댑터엔 종류가 없어서, 둘이 만나야 한 줄이 완성된다).
    return { accountId: result.accountId, ...(result.credKind ? { credKind: result.credKind } : {}) };
  }


  /**
   * SCRAM 저장 키 조회 — 없으면 null. **없다고 즉시 실패시키지 않는다**(엔진이 가짜 salt로
   * 교환을 끝까지 진행해 계정 열거를 막는다). 그래서 여기서 로그도 남기지 않는다 —
   * "그 사용자는 조회가 실패했다"가 로그로 새면 방어가 반쪽이 된다.
   */
  async scramKeys(user: string) {
    return await scramKeysFor(this.db, user);
  }

  /**
   * SCRAM 증명 통과 뒤의 최종 승인. **비밀번호를 증명한 것과 들어와도 되는 것은 다르다** —
   * 정지된 계정도 비밀번호는 맞을 수 있다. PLAIN 경로는 `authenticate`가 status=1을 함께
   * 보지만 SCRAM은 검증을 엔진이 하므로 이 확인이 따로 있어야 한다.
   */
  async scramAuthorize(user: string) {
    const ok = await scramAuthorize(this.db, user, "imap");
    if (!ok) {
      this.log.warn("scram authorize 실패 — 계정 없음/정지", { user });
      return null;
    }
    this.log.info("auth ok (scram)", { user, accountId: ok.accountId });
    return { accountId: ok.accountId, credKind: "password" as const };
  }

  async request(accountId: string, req: ImapBackendRequest): Promise<ImapBackendResponse> {
    try {
      switch (req.kind) {
        case "getQuota": {
          /**
           * 데이터는 이미 있었다(§7-1의 쿼터 검사가 같은 컬럼을 본다) — 보여 줄 표면만 없었다.
           * `quotaBytes === 0`은 무제한이고, 그 판정은 스토어의 기존 계약을 그대로 전달한다.
           */
          const q = await this.store.getQuota(accountId);
          return { kind: "quota", usedBytes: q.usedBytes, limitBytes: q.quotaBytes, messageCount: q.messageCount };
        }
        case "listMailboxes":
          return { kind: "mailboxes", mailboxes: (await this.pathedMailboxes(accountId)).map((p) => this.toImapMailbox(p)) };
        case "createMailbox":
          return await this.createMailbox(accountId, req.name);
        case "deleteMailbox":
          return await this.deleteMailbox(accountId, req.name);
        case "renameMailbox":
          return await this.renameMailbox(accountId, req.from, req.to);
        case "getAcl": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          const context = await this.principalContext(accountId);
          if (!(await this.hasMailboxRight(accountId, found.row.id, "admin"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
          const acl = await this.store.getMailboxAcl(context.tenantId, found.row.id);
          return { kind: "acl", mailbox: req.name, entries: acl.map((row) => ({ identifier: row.principalId, rights: row.rights })) };
        }
        case "setAcl": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          const context = await this.principalContext(accountId);
          if (!(await this.hasMailboxRight(accountId, found.row.id, "admin"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
          await this.store.setMailboxAcl(context.tenantId, found.row.id, req.identifier, req.rights);
          return { kind: "ok" };
        }
        case "deleteAcl": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          const context = await this.principalContext(accountId);
          if (!(await this.hasMailboxRight(accountId, found.row.id, "admin"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
          const deleted = await this.store.deleteMailboxAcl(context.tenantId, found.row.id, req.identifier);
          return deleted ? { kind: "ok" } : { kind: "no", code: "NONEXISTENT", message: "no such ACL" };
        }
        case "listRights":
        case "myRights": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          const context = await this.principalContext(accountId);
          const identifier = req.kind === "myRights" ? context.principalId : req.identifier;
          const acl = await this.store.getMailboxAcl(context.tenantId, found.row.id);
          const row = acl.find((entry) => entry.principalId === identifier);
          return { kind: "rights", mailbox: req.name, identifier, rights: row?.rights ?? "" };
        }
        case "setSubscribed": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          if (!(await this.hasMailboxRight(accountId, found.row.id, "write"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
          await this.store.setSubscribed(accountId, found.row.id, req.subscribed);
          return { kind: "ok" };
        }
        case "selectMailbox":
          return await this.selectMailbox(accountId, req.name);
        case "expungeMailbox": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          if (!(await this.hasMailboxRight(accountId, found.row.id, "expunge"))) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          await this.store.expunge({ accountId: found.row.accountId, mailboxId: found.row.id });
          return { kind: "ok" };
        }
        case "expunge": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          if (!(await this.hasMailboxRight(accountId, found.row.id, "expunge"))) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          const result = await this.store.expunge({
            accountId: found.row.accountId,
            mailboxId: found.row.id,
            ...(req.uids !== null ? { uids: req.uids } : {}),
          });
          return { kind: "expunged", uids: result.expunged.map((e) => e.uid) };
        }
        case "fetchMessages":
          return await this.fetchMessages(accountId, req);
        case "syncSince":
          return await this.syncSince(accountId, req);
        case "storeFlags":
          return await this.storeFlags(accountId, req);
        case "appendMessage":
          return await this.appendMessage(accountId, req);
        case "replaceMessage":
          return await this.replaceMessage(accountId, req);
        case "copyMessages":
          return await this.copyOrMove(accountId, req.from, req.to, req.uids, "copy");
        case "moveMessages":
          return await this.copyOrMove(accountId, req.from, req.to, req.uids, "move");
      }
    } catch (err) {
      /**
       * ★쿼터 초과는 **전용 응답 코드**로 알린다(RFC 9208 §5.1 `OVERQUOTA`).
       *
       * 예전엔 평범한 `NO`로 나가서 클라이언트가 "왜 실패했는지"를 표시할 방법이 없었다 —
       * 사용자에게는 원인 불명의 저장 실패로 보인다. `StoreQuotaError`는 `StoreError`의
       * 하위 타입이라 아래 분기에 먼저 걸렸었다(순서가 중요하다).
       */
      if (err instanceof StoreQuotaError) {
        this.log.warn("imap quota exceeded", { kind: req.kind });
        return { kind: "no", code: "OVERQUOTA", message: "quota exceeded" };
      }
      if (err instanceof StoreError) {
        this.log.warn("imap store error", { kind: req.kind, error: err.message });
        return { kind: "no", message: err.message };
      }
      throw err;
    }
  }

  // ── 경로 변환 ──────────────────────────────────────────────────────────────

  private async pathedMailboxes(accountId: string): Promise<PathedMailbox[]> {
    const rows = await this.store.listAccessibleMailboxes(await this.principalContext(accountId));
    const byId = new Map(rows.map((r) => [r.id, r]));
    const pathOf = (row: MailboxRow): string => {
      const segs: string[] = [row.name];
      let cur = row;
      for (let depth = 0; depth < 100 && cur.parentId !== ""; depth++) {
        const parent = byId.get(cur.parentId);
        if (!parent) break; // 부모가 비활성(status≠1) — 고아는 자기 이름만
        segs.unshift(parent.name);
        cur = parent;
      }
      return segs.join(DELIM);
    };
    return rows.map((row) => ({ row, path: pathOf(row) }));
  }

  /** 인증 계정에서 tenant·account principal·group membership을 한 번에 복원한다. */
  private async principalContext(accountId: string): Promise<PrincipalContext> {
    const account = await this.db.query({ sql: "SELECT tenant_id FROM accounts WHERE id = ? AND status = 1", params: [accountId] });
    const tenantId = String(account.rows[0]?.tenant_id ?? "");
    const principal = await this.db.query({ sql: "SELECT id FROM principals WHERE tenant_id = ? AND account_id = ?", params: [tenantId, accountId] });
    const memberships = await this.db.query({ sql: "SELECT principal_id FROM account_memberships WHERE account_id = ?", params: [accountId] });
    return {
      tenantId,
      principalId: String(principal.rows[0]?.id ?? accountId),
      primaryAccountId: accountId,
      accessibleAccountIds: [accountId],
      groupIds: memberships.rows.map((row) => String(row.principal_id)),
      authenticated: true,
    };
  }

  private async hasMailboxRight(accountId: string, mailboxId: string, operation: "read" | "insert" | "write" | "delete" | "expunge" | "create" | "admin"): Promise<boolean> {
    const decision = await this.store.authorizeMailbox(await this.principalContext(accountId), mailboxId, operation);
    return decision.allowed;
  }

  private toImapMailbox(p: PathedMailbox): ImapMailbox {
    return {
      name: p.path,
      role: p.row.role,
      subscribed: p.row.subscribed,
      uidvalidity: p.row.uidvalidity,
      uidnext: p.row.uidnext,
      highestmodseq: p.row.highestmodseq,
      totalCount: p.row.totalCount,
      unreadCount: p.row.unreadCount,
      totalBytes: p.row.totalBytes,
      // OBJECTID(RFC 8474) — 메일함 행의 ULID가 곧 불변 id다. 이름·UIDVALIDITY와 무관하다.
      mailboxId: p.row.id,
    };
  }

  private async findByPath(accountId: string, path: string): Promise<PathedMailbox | null> {
    const all = await this.pathedMailboxes(accountId);
    return all.find((p) => p.path === path) ?? null;
  }

  // ── 메일함 관리 ────────────────────────────────────────────────────────────

  private async createMailbox(accountId: string, path: string): Promise<ImapBackendResponse> {
    const all = await this.pathedMailboxes(accountId);
    if (all.some((p) => p.path === path)) {
      return { kind: "no", code: "ALREADYEXISTS", message: "mailbox exists" };
    }
    // 중간 계층 자동 생성 (RFC 9051 §6.3.4)
    const segs = path.split(DELIM).filter((s) => s.length > 0);
    if (segs.length === 0) return { kind: "no", message: "invalid mailbox name" };
    const byPath = new Map(all.map((p) => [p.path, p.row.id]));
    let parentId = "";
    let cur = "";
    for (const seg of segs) {
      cur = cur === "" ? seg : `${cur}${DELIM}${seg}`;
      const existing = byPath.get(cur);
      if (existing !== undefined) {
        parentId = existing;
        continue;
      }
      if (parentId === "") {
        const root = all.find((mailbox) => mailbox.row.parentId === "");
        if (!root || !(await this.hasMailboxRight(accountId, root.row.id, "create"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
      } else if (!(await this.hasMailboxRight(accountId, parentId, "create"))) {
        return { kind: "no", code: "NOPERM", message: "permission denied" };
      }
      const created = await this.store.createMailbox({ accountId, name: seg, ...(parentId !== "" ? { parentId } : {}) });
      byPath.set(cur, created.mailboxId);
      parentId = created.mailboxId;
    }
    return { kind: "ok" };
  }

  private async deleteMailbox(accountId: string, path: string): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, path);
    if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, found.row.id, "delete"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
    await this.store.deleteMailbox({ accountId, mailboxId: found.row.id });
    return { kind: "ok" };
  }

  private async renameMailbox(accountId: string, from: string, to: string): Promise<ImapBackendResponse> {
    const all = await this.pathedMailboxes(accountId);
    const src = all.find((p) => p.path === from);
    if (!src) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, src.row.id, "delete"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
    if (all.some((p) => p.path === to)) return { kind: "no", code: "ALREADYEXISTS", message: "mailbox exists" };

    const segs = to.split(DELIM).filter((s) => s.length > 0);
    const newName = segs[segs.length - 1];
    if (!newName) return { kind: "no", message: "invalid mailbox name" };
    // 새 부모 경로가 있으면 존재해야 함(자동 생성은 CREATE 소관 — 단순화)
    const parentPath = segs.slice(0, -1).join(DELIM);
    let newParentId = "";
    if (parentPath !== "") {
      const parent = all.find((p) => p.path === parentPath);
      if (!parent) return { kind: "no", code: "TRYCREATE", message: "parent mailbox does not exist" };
      if (!(await this.hasMailboxRight(accountId, parent.row.id, "create"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
      newParentId = parent.row.id;
    }
    await this.store.renameMailbox({ accountId, mailboxId: src.row.id, newParentId, newName });
    return { kind: "ok" };
  }

  // ── SELECT/FETCH 데이터 ────────────────────────────────────────────────────

  private async selectMailbox(accountId: string, path: string): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, path);
    if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, found.row.id, "read"))) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    const { rows } = await this.db.query({
      sql: `SELECT mm.uid AS uid,
                   EXISTS(SELECT 1 FROM message_keywords k WHERE k.message_id = mm.message_id AND k.keyword = '$seen') AS seen
            FROM message_mailbox mm WHERE mm.mailbox_id = ? ORDER BY mm.uid`,
      params: [found.row.id],
    });
    const uids = rows.map((r) => Number(r.uid));
    const firstUnseenIdx = rows.findIndex((r) => !Number(r.seen));
    // 메일함 현존 키워드 — SELECT `* FLAGS` 공지용(시스템 매핑 4종 제외한 원형 키워드 포함)
    const { rows: kwRows } = await this.db.query({
      sql: `SELECT DISTINCT k.keyword AS keyword FROM message_keywords k
            JOIN message_mailbox mm ON mm.message_id = k.message_id WHERE mm.mailbox_id = ?`,
      params: [found.row.id],
    });
    const keywords = kwRows
      .map((r) => keywordToFlag(String(r.keyword)))
      .filter((f) => !f.startsWith("\\")); // 시스템 플래그는 엔진이 상시 공지
    return {
      kind: "selected",
      mailbox: this.toImapMailbox(found),
      uids,
      firstUnseenSeq: firstUnseenIdx === -1 ? null : firstUnseenIdx + 1,
      keywords,
    };
  }

  private async fetchMessages(
    accountId: string,
    req: Extract<ImapBackendRequest, { kind: "fetchMessages" }>,
  ): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, req.name);
    if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, found.row.id, "read"))) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (req.uids.length === 0) return { kind: "messages", messages: [] };

    /**
     * ★파라미터 한도 안에서 나눠 돈다(`store/chunk.ts`). `UID FETCH 1:*`은 메일함 메시지
     * 수만큼 uid를 싣는데, 이 저장소가 정한 D1 한도는 문장당 100개다 — 예전엔 그 한도를
     * 쓰기 경로만 지키고 여기 읽기 경로는 지키지 않았다.
     * 청크마다 정렬되므로 합친 뒤 uid로 다시 정렬한다(호출자가 순서를 전제한다).
     */
    const rows = (
      await queryInChunks(
        this.db,
        req.uids,
        (ph) => `SELECT mm.uid AS uid, mm.message_id AS message_id, mm.savedate AS savedate, mm.deleted AS deleted,
                   m.size_bytes AS size_bytes, m.modseq AS modseq, m.received_at AS received_at,
                   m.subject_base AS subject_base, m.sent_at AS sent_at, m.thread_id AS thread_id
            FROM message_mailbox mm JOIN messages m ON m.id = mm.message_id
            WHERE mm.mailbox_id = ? AND mm.uid IN (${ph})`,
        [found.row.id],
      )
    ).sort((a, b) => Number(a.uid) - Number(b.uid));
    if (rows.length === 0) return { kind: "messages", messages: [] };

    const messageIds = [...new Set(rows.map((r) => String(r.message_id)))];

    // markSeen — 비PEEK BODY[] 계약: \Seen 선반영 후 갱신된 플래그 반환 (engine.ts)
    if (req.markSeen) {
      for (const messageId of messageIds) {
        await this.store.setKeywords({ accountId: found.row.accountId, messageId, add: ["$seen"], remove: [] });
      }
    }

    const kwRows = await queryInChunks(
      this.db,
      messageIds,
      (ph) => `SELECT message_id, keyword FROM message_keywords WHERE message_id IN (${ph})`,
    );
    const keywords = new Map<string, string[]>();
    for (const r of kwRows) {
      const id = String(r.message_id);
      const arr = keywords.get(id) ?? [];
      arr.push(keywordToFlag(String(r.keyword)));
      keywords.set(id, arr);
    }

    /**
     * SORT의 FROM/TO/CC 키는 주소가 필요하다. **요청했을 때만** 읽는다 — 평범한 FETCH가
     * 정렬 키 때문에 조인을 더 도는 것은 손해다.
     */
    const sortAddrs = new Map<string, { from: string; to: string; cc: string }>();
    if (req.needSortKeys) {
      const rows2 = await queryInChunks(
        this.db,
        messageIds,
        (ph) => `SELECT message_id, kind, pos, name, email FROM message_addresses
                   WHERE message_id IN (${ph}) ORDER BY kind, pos`,
        [],
      );
      for (const r of rows2) {
        const id = String(r.message_id);
        const cur = sortAddrs.get(id) ?? { from: "", to: "", cc: "" };
        /**
         * ★정렬 키는 **첫 주소 하나**다(RFC 5256 §3: "the first address"). 전부 이으면
         * 수신자가 많은 메일이 엉뚱한 자리로 간다.
         * 표시 이름이 있으면 그걸 쓰고 없으면 주소 — 클라이언트가 보는 것과 같은 문자열로
         * 정렬해야 사용자가 순서를 납득한다.
         */
        const key = (String(r.name ?? "").trim() || String(r.email)).toLowerCase();
        const kind = Number(r.kind);
        if (kind === ADDRESS_KIND.from && cur.from === "") cur.from = key;
        else if (kind === ADDRESS_KIND.to && cur.to === "") cur.to = key;
        else if (kind === ADDRESS_KIND.cc && cur.cc === "") cur.cc = key;
        sortAddrs.set(id, cur);
      }
    }

    const messages: ImapFetchData[] = [];
    for (const r of rows) {
      const messageId = String(r.message_id);
      const flags = [...(keywords.get(messageId) ?? [])];
      if (Number(r.deleted)) flags.push("\\Deleted");
      let raw: Uint8Array | undefined;
      if (req.needRaw) {
        try {
          const blob = await this.store.getMessageBlob(messageId);
          if (blob) raw = await this.blobs.get(blob.blobId, blob.generation);
        } catch {
          // 블롭 소실(동시 EXPUNGE 레이스) — 아래에서 생략 처리
        }
        // raw 요구인데 없음 → 죽어가는 메시지를 빈 데이터로 응답하면 메타데이터
        // 불일치(imaptest checkpoint)만 생김 — 응답에서 생략(엔진이 조용히 스킵)
        if (raw === undefined) continue;
      }
      const addrs = sortAddrs.get(messageId) ?? { from: "", to: "", cc: "" };
      messages.push({
        uid: Number(r.uid),
        flags,
        /**
         * ★INTERNALDATE는 **도착 시각**(`messages.received_at`)이다. 예전엔 `savedate`를
         * 실어 보내서, COPY한 사본의 INTERNALDATE가 원본과 달라졌다 — RFC 9051 §6.4.7은
         * 사본이 원본의 INTERNALDATE를 물려받기를 요구한다. `savedate`는 SAVEDATE(RFC 8514)의
         * 값이고 그건 아래 별도 필드다.
         */
        internalDateMs: Number(r.received_at),
        saveDateMs: Number(r.savedate),
        // OBJECTID — 메시지·스레드의 ULID를 그대로 쓴다(이미 불변이고 유일하다).
        emailId: messageId,
        threadId: String(r.thread_id ?? ""),
        size: Number(r.size_bytes),
        modseq: Number(r.modseq),
        ...(raw !== undefined ? { raw } : {}),
        ...(req.needSortKeys
          ? {
              sortKeys: {
                subjectBase: String(r.subject_base ?? "").toLowerCase(),
                sentAtMs: r.sent_at == null ? 0 : Number(r.sent_at),
                threadId: String(r.thread_id ?? ""),
                ...addrs,
              },
            }
          : {}),
      });
    }
    return { kind: "messages", messages };
  }

  // ── 플래그/APPEND/COPY/MOVE ───────────────────────────────────────────────

  private async storeFlags(
    accountId: string,
    req: Extract<ImapBackendRequest, { kind: "storeFlags" }>,
  ): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, req.name);
    if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, found.row.id, "write"))) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    const allRows = (
      await queryInChunks(
        this.db,
        req.uids,
        (ph) => `SELECT mm.uid AS uid, mm.message_id AS message_id, m.modseq AS modseq
            FROM message_mailbox mm JOIN messages m ON m.id = mm.message_id
            WHERE mm.mailbox_id = ? AND mm.uid IN (${ph})`,
        [found.row.id],
      )
    ).sort((a, b) => Number(a.uid) - Number(b.uid));
    // CONDSTORE UNCHANGEDSINCE — modseq 초과분은 건너뛰고 failed로 보고(RFC 7162)
    const failed: number[] = [];
    const rows =
      req.unchangedSince === undefined
        ? allRows
        : allRows.filter((r) => {
            const ok = Number(r.modseq) <= req.unchangedSince!;
            if (!ok) failed.push(Number(r.uid));
            return ok;
          });
    if (rows.length === 0) return { kind: "flagsUpdated", updated: [], ...(failed.length > 0 ? { failed } : {}) };

    const wantsDeleted = req.flags.some((f) => f.toLowerCase() === "\\deleted");
    const kwFlags = req.flags.map(flagToKeyword).filter((k): k is string => k !== null);

    /**
     * ★한 배치로 처리한다. 예전엔 메시지마다 `setKeywords()`를 불렀고, `mode==="set"`은
     * 그 위에 현재 키워드 조회를 하나 더 얹었다 — `UID STORE 1:* +FLAGS \Seen`이 1만 통이면
     * **왕복 2만 번**이고 modseq도 1만 번 소모된다(라이터 큐가 직렬화하므로 그동안 그 계정의
     * 다른 쓰기가 전부 대기한다). 목표 집합 계산은 스토어가 `replace`로 안에서 한다 —
     * 조회를 한 번 더 하지 않아도 되는 자리다.
     */
    await this.store.setKeywordsBatch({
      accountId,
      messageIds: [...new Set(rows.map((r) => String(r.message_id)))],
      add: req.mode === "remove" ? [] : kwFlags,
      remove: req.mode === "remove" ? kwFlags : [],
      ...(req.mode === "set" ? { replace: true } : {}),
    });

    // \Deleted — membership 단위 일괄 처리
    const uids = rows.map((r) => Number(r.uid));
    if (req.mode === "set") {
      await this.store.setDeleted({ accountId: found.row.accountId, mailboxId: found.row.id, uids, deleted: wantsDeleted });
    } else if (wantsDeleted) {
      await this.store.setDeleted({ accountId: found.row.accountId, mailboxId: found.row.id, uids, deleted: req.mode === "add" });
    }

    // 갱신된 플래그 재조회 (unchangedSince로 걸러진 uid는 제외)
    const okUids = rows.map((r) => Number(r.uid));
    const fetched = await this.fetchMessages(accountId, { kind: "fetchMessages", name: req.name, uids: okUids, needRaw: false, markSeen: false });
    if (fetched.kind !== "messages") return fetched;
    return {
      kind: "flagsUpdated",
      updated: fetched.messages.map((m) => ({ uid: m.uid, flags: m.flags, modseq: m.modseq })),
      ...(failed.length > 0 ? { failed } : {}),
    };
  }

  /** QRESYNC — expunged 툼스톤 + modseq 변경 델타 (SCHEMA §6-2). */
  private async syncSince(accountId: string, req: Extract<ImapBackendRequest, { kind: "syncSince" }>): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, req.name);
    if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, found.row.id, "read"))) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    /**
     * ★툼스톤 보존창 **밖**이면 `expunged`로는 답할 수 없다(migration 014의 `expunged_floor`).
     * 그때 그냥 "삭제 없음"으로 답하면 클라이언트가 유령 메시지를 영영 들고 있게 된다 —
     * 조용히 틀린 답이라 사용자가 알아차릴 방법도 없다.
     *
     * RFC 7162 §3.2.5.2가 이 상황의 답을 이미 두었다: 클라이언트가 준 known-uids에서 **현재
     * 존재하는 uid를 빼면** 사라진 uid가 정확히 나온다. known-uids가 없으면 규격이 정한 대로
     * `1:uidnext-1`로 간주한다. 툼스톤 없이도 정확하고, UIDVALIDITY를 올려 **모든**
     * 클라이언트의 캐시를 버리게 만들 이유가 없다(한 세션의 부재를 전원이 갚는 셈이 된다).
     */
    const vanished =
      req.sinceModseq >= found.row.expungedFloor
        ? await this.vanishedFromTombstones(found.row.id, req.sinceModseq)
        : await this.vanishedByDifference(found.row, req.knownUids ?? null);
    const { rows: changedRows } = await this.db.query({
      sql: `SELECT mm.uid AS uid FROM message_mailbox mm JOIN messages m ON m.id = mm.message_id
            WHERE mm.mailbox_id = ? AND m.modseq > ? ORDER BY mm.uid`,
      params: [found.row.id, req.sinceModseq],
    });
    const changedUids = changedRows.map((r) => Number(r.uid));
    const changed: { uid: number; flags: readonly string[]; modseq: number }[] = [];
    if (changedUids.length > 0) {
      const fetched = await this.fetchMessages(accountId, { kind: "fetchMessages", name: req.name, uids: changedUids, needRaw: false, markSeen: false });
      if (fetched.kind === "messages") {
        for (const m of fetched.messages) changed.push({ uid: m.uid, flags: m.flags, modseq: m.modseq });
      }
    }
    return { kind: "sync", vanished, changed };
  }

  /** 보존창 안 — 툼스톤이 곧 답이다(정확하고 작다). */
  private async vanishedFromTombstones(mailboxId: string, sinceModseq: number): Promise<number[]> {
    const { rows } = await this.db.query({
      sql: "SELECT uid FROM expunged WHERE mailbox_id = ? AND modseq > ? ORDER BY uid",
      params: [mailboxId, sinceModseq],
    });
    return rows.map((r) => Number(r.uid));
  }

  /**
   * 보존창 밖 — 후보 집합에서 현재 존재하는 uid를 뺀다 (RFC 7162 §3.2.5.2).
   *
   * ★비용은 후보 집합의 크기에 비례한다. known-uids를 준 클라이언트(실제 QRESYNC 구현은
   * 대부분 준다)는 자기가 아는 만큼만 후보가 되므로 작고, 안 준 경우에만 `1:uidnext-1`로
   * 커진다. 그 경로는 "보존창을 넘겨 떠나 있었고 known-uids도 안 준" 드문 조합이고,
   * 와이어로는 `formatUidSet`이 범위로 압축한다.
   */
  private async vanishedByDifference(row: MailboxRow, knownUids: readonly SeqRange[] | null): Promise<number[]> {
    const { rows } = await this.db.query({
      sql: "SELECT uid FROM message_mailbox WHERE mailbox_id = ?",
      params: [row.id],
    });
    const present = new Set(rows.map((r) => Number(r.uid)));

    const out: number[] = [];
    // known-uids 없음 → 규격이 정한 기본값 `1:<uidnext-1>`.
    const ranges: readonly SeqRange[] = knownUids ?? [{ from: 1, to: Math.max(0, row.uidnext - 1) }];
    /**
     * `*`는 "가장 큰 것"이다(RFC 9051 §6.4.8). 여기서는 `uidnext-1`로 닫는다 —
     * 열어 두면 존재하지 않는 uid를 무한히 세게 된다.
     */
    const maxUid = Math.max(0, row.uidnext - 1);
    const bound = (v: number | "*"): number => (v === "*" ? maxUid : v);
    for (const r of ranges) {
      // 시퀀스셋은 `5:1`처럼 뒤집혀 올 수 있다(§9 seq-range는 순서를 강제하지 않는다).
      const a = bound(r.from);
      const b = bound(r.to);
      const to = Math.min(Math.max(a, b), maxUid);
      for (let uid = Math.max(1, Math.min(a, b)); uid <= to; uid++) {
        if (!present.has(uid)) out.push(uid);
      }
    }
    out.sort((a, b) => a - b);
    return out;
  }

  /**
   * APPEND — 한 통이든 여러 통(MULTIAPPEND, RFC 3502)이든 **한 배치**로 넣는다.
   *
   * ★MULTIAPPEND의 요지는 편의가 아니라 **원자성**이다(§3: "either all messages are appended
   * or none"). 통마다 따로 넣으면 중간에 쿼터가 차서 절반만 들어간 채 `APPENDUID`가 나가고,
   * 클라이언트는 전부 들어간 줄 안다. `store.appendMessages`가 이미 그룹 배치라 그대로 쓴다.
   */
  private async appendMessage(
    accountId: string,
    req: Extract<ImapBackendRequest, { kind: "appendMessage" }>,
  ): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, req.name);
    if (!found) return { kind: "no", code: "TRYCREATE", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, found.row.id, "insert"))) return { kind: "no", code: "TRYCREATE", message: "no such mailbox" };
    const storageAccountId = found.row.accountId;

    const items = req.items ?? [{ raw: req.raw, flags: req.flags, ...(req.internalDateMs !== null ? { internalDateMs: req.internalDateMs } : {}) }];
    const inputs: AppendMessageInput[] = [];
    const deletedAt: boolean[] = [];
    for (const item of items) {
      const { blobId, size, generation } = await putBlob(this.db, this.blobs, item.raw);
      const parsed = parseMessage(item.raw);
      const keywords = item.flags.map(flagToKeyword).filter((k): k is string => k !== null);
      deletedAt.push(item.flags.some((f) => f.toLowerCase() === "\\deleted"));
      inputs.push({
        accountId: storageAccountId,
        mailboxIds: [found.row.id],
        blobId,
        blobGeneration: generation,
        sizeBytes: size,
        receivedAt: item.internalDateMs ?? Date.now(),
        envelope: {
          subject: parsed.subject,
          subjectBase: parsed.subjectBase,
          msgidHash: parsed.msgidHash,
          sentAt: parsed.sentAt,
          preview: parsed.preview,
          hasAttachment: parsed.hasAttachment,
          addresses: toAppendAddresses(parsed),
          threadRefHashes: parsed.threadRefHashes,
        },
        keywords,
        searchText: {
          ...(parsed.subject ? { subject: parsed.subject } : {}),
          ...(parsed.textBody ? { body: parsed.textBody } : {}),
          ...(parsed.from[0] ? { from: `${parsed.from[0].name ?? ""} ${parsed.from[0].email}` } : {}),
          ...(parsed.to.length > 0 ? { to: parsed.to.map((a) => a.email).join(" ") } : {}),
        },
      });
    }

    const results = await this.store.appendMessages(inputs);
    const uids = results.map((r) => r.uids.get(found.row.id)).filter((u): u is number => u !== undefined);
    if (uids.length !== inputs.length) return { kind: "no", message: "append failed" };

    // `\Deleted`는 키워드가 아니라 멤버십 플래그다 — 넣은 뒤 해당 통만 세운다.
    for (let i = 0; i < results.length; i++) {
      if (deletedAt[i] === true) await this.store.setDeleted({ accountId: storageAccountId, mailboxId: found.row.id, uids: [uids[i]!], deleted: true });
    }
    return { kind: "appended", uidvalidity: found.row.uidvalidity, uid: uids[0]!, uids };
  }

  /**
   * REPLACE (RFC 8508) — 넣고 **그다음에** 지운다.
   *
   * ★순서가 안전성의 전부다. 지우기를 먼저 하면 넣기가 실패했을 때 메일이 사라진다.
   * 이 순서면 최악이 사본 하나가 남는 것이고 사용자가 지울 수 있다 — `유실 > 지연`이라는
   * 이 저장소의 판단과 같은 방향이다.
   *
   * ★지우기 실패를 **삼킨다**(`expungedUid: null`). 새 메시지는 이미 들어갔으므로 여기서
   * 오류를 내면 클라이언트가 실패로 알고 다시 보내 중복이 하나 더 생긴다.
   */
  private async replaceMessage(
    accountId: string,
    req: Extract<ImapBackendRequest, { kind: "replaceMessage" }>,
  ): Promise<ImapBackendResponse> {
    const from = await this.findByPath(accountId, req.from);
    if (!from) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, from.row.id, "delete"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
    const to = await this.findByPath(accountId, req.to);
    if (!to) return { kind: "no", code: "TRYCREATE", message: "no such target mailbox" };

    const appended = await this.appendMessage(accountId, {
      kind: "appendMessage",
      name: req.to,
      flags: req.flags,
      internalDateMs: req.internalDateMs,
      raw: req.raw,
    });
    if (appended.kind !== "appended") return appended;

    let expungedUid: number | null = null;
    try {
      await this.store.setDeleted({ accountId: from.row.accountId, mailboxId: from.row.id, uids: [req.oldUid], deleted: true });
      const r = await this.store.expunge({ accountId: from.row.accountId, mailboxId: from.row.id, uids: [req.oldUid] });
      if (r.expunged.some((e) => e.uid === req.oldUid)) expungedUid = req.oldUid;
    } catch (err) {
      // 새 메시지는 이미 들어갔다 — 여기서 실패해도 명령은 성공이다(사본이 하나 남을 뿐).
      this.log.warn("REPLACE: 옛 메시지 정리 실패 — 사본이 남는다", {
        uid: req.oldUid,
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return { kind: "replaced", uidvalidity: to.row.uidvalidity, uid: appended.uid, expungedUid };
  }

  private async copyOrMove(
    accountId: string,
    fromPath: string,
    toPath: string,
    uids: readonly number[],
    op: "copy" | "move",
  ): Promise<ImapBackendResponse> {
    const from = await this.findByPath(accountId, fromPath);
    if (!from) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (!(await this.hasMailboxRight(accountId, from.row.id, "read"))) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    if (op === "move" && !(await this.hasMailboxRight(accountId, from.row.id, "delete"))) return { kind: "no", code: "NOPERM", message: "permission denied" };
    const to = await this.findByPath(accountId, toPath);
    if (!to) return { kind: "no", code: "TRYCREATE", message: "no such target mailbox" };
    if (!(await this.hasMailboxRight(accountId, to.row.id, "insert"))) return { kind: "no", code: "TRYCREATE", message: "no such target mailbox" };

    const rows = (
      await queryInChunks(
        this.db,
        uids,
        (ph) => `SELECT uid, message_id FROM message_mailbox WHERE mailbox_id = ? AND uid IN (${ph})`,
        [from.row.id],
      )
    ).sort((a, b) => Number(a.uid) - Number(b.uid));
    /**
     * ★한 배치로 처리한다. 예전엔 메시지마다 스토어를 불렀고, 왕복이 N번인 것보다 나쁜 것은
     * **원자성이 없다**는 점이었다 — 중간에 실패하면 절반만 복사된 채 `COPYUID`가 나갔다.
     * RFC 9051 §6.4.7은 COPY가 실패하면 대상 메일함을 원상 복구하라고 한다.
     */
    const uidByMessage = new Map(rows.map((r) => [String(r.message_id), Number(r.uid)]));
    const { pairs } = await this.store.copyOrMoveMessages({
      accountId: from.row.accountId,
      messageIds: rows.map((r) => String(r.message_id)),
      fromMailboxId: from.row.id,
      toMailboxId: to.row.id,
      op,
    });
    // COPYUID의 두 uid-set은 **위치로 대응**한다 — 순서가 어긋나면 다른 메시지를 가리킨다.
    const srcUids = pairs.map((p) => uidByMessage.get(p.messageId)!);
    const dstUids = pairs.map((p) => p.uid);
    return { kind: "copied", uidvalidity: to.row.uidvalidity, srcUids, dstUids };
  }
}
