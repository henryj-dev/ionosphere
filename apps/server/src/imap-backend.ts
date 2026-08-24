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
import { noopLogger, type Logger } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { parseMessage, type ParsedAddress, type ParsedMessage } from "@ionosphere/mime";
import {
  authenticate,
  putBlob,
  queryInChunks,
  StoreError,
  StoreQuotaError,
  type AppendAddress,
  type BlobStore,
  type MailboxRow,
  Store,
  scramKeysFor,
  scramAuthorize,
} from "@ionosphere/store";
import type { ImapBackend, ImapBackendRequest, ImapBackendResponse, ImapFetchData, ImapMailbox } from "@ionosphere/proto-imap";
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
    const result = await authenticate(this.db, user, pass);
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
    const ok = await scramAuthorize(this.db, user);
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
        case "setSubscribed": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          await this.store.setSubscribed(accountId, found.row.id, req.subscribed);
          return { kind: "ok" };
        }
        case "selectMailbox":
          return await this.selectMailbox(accountId, req.name);
        case "expungeMailbox": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          await this.store.expunge({ accountId, mailboxId: found.row.id });
          return { kind: "ok" };
        }
        case "expunge": {
          const found = await this.findByPath(accountId, req.name);
          if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
          const result = await this.store.expunge({
            accountId,
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
    const rows = await this.store.listMailboxes(accountId);
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
      const created = await this.store.createMailbox({ accountId, name: seg, ...(parentId !== "" ? { parentId } : {}) });
      byPath.set(cur, created.mailboxId);
      parentId = created.mailboxId;
    }
    return { kind: "ok" };
  }

  private async deleteMailbox(accountId: string, path: string): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, path);
    if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
    await this.store.deleteMailbox({ accountId, mailboxId: found.row.id });
    return { kind: "ok" };
  }

  private async renameMailbox(accountId: string, from: string, to: string): Promise<ImapBackendResponse> {
    const all = await this.pathedMailboxes(accountId);
    const src = all.find((p) => p.path === from);
    if (!src) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
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
      newParentId = parent.row.id;
    }
    await this.store.renameMailbox({ accountId, mailboxId: src.row.id, newParentId, newName });
    return { kind: "ok" };
  }

  // ── SELECT/FETCH 데이터 ────────────────────────────────────────────────────

  private async selectMailbox(accountId: string, path: string): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, path);
    if (!found) return { kind: "no", code: "NONEXISTENT", message: "no such mailbox" };
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
                   m.size_bytes AS size_bytes, m.modseq AS modseq
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
        await this.store.setKeywords({ accountId, messageId, add: ["$seen"], remove: [] });
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
      messages.push({
        uid: Number(r.uid),
        flags,
        internalDateMs: Number(r.savedate),
        size: Number(r.size_bytes),
        modseq: Number(r.modseq),
        ...(raw !== undefined ? { raw } : {}),
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
      await this.store.setDeleted({ accountId, mailboxId: found.row.id, uids, deleted: wantsDeleted });
    } else if (wantsDeleted) {
      await this.store.setDeleted({ accountId, mailboxId: found.row.id, uids, deleted: req.mode === "add" });
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
    const { rows: vanishedRows } = await this.db.query({
      sql: "SELECT uid FROM expunged WHERE mailbox_id = ? AND modseq > ? ORDER BY uid",
      params: [found.row.id, req.sinceModseq],
    });
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
    return { kind: "sync", vanished: vanishedRows.map((r) => Number(r.uid)), changed };
  }

  private async appendMessage(
    accountId: string,
    req: Extract<ImapBackendRequest, { kind: "appendMessage" }>,
  ): Promise<ImapBackendResponse> {
    const found = await this.findByPath(accountId, req.name);
    if (!found) return { kind: "no", code: "TRYCREATE", message: "no such mailbox" };

    const { blobId, size, generation } = await putBlob(this.db, this.blobs, req.raw);
    const parsed = parseMessage(req.raw);
    const keywords = req.flags.map(flagToKeyword).filter((k): k is string => k !== null);
    const wantsDeleted = req.flags.some((f) => f.toLowerCase() === "\\deleted");

    const result = await this.store.appendMessage({
      accountId,
      mailboxIds: [found.row.id],
      blobId,
      blobGeneration: generation,
      sizeBytes: size,
      receivedAt: req.internalDateMs ?? Date.now(),
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
    const uid = result.uids.get(found.row.id);
    if (uid === undefined) return { kind: "no", message: "append failed" };
    if (wantsDeleted) {
      await this.store.setDeleted({ accountId, mailboxId: found.row.id, uids: [uid], deleted: true });
    }
    return { kind: "appended", uidvalidity: found.row.uidvalidity, uid };
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
    const to = await this.findByPath(accountId, toPath);
    if (!to) return { kind: "no", code: "TRYCREATE", message: "no such target mailbox" };

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
      accountId,
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
