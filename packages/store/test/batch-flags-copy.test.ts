/**
 * 배치 키워드·복사/이동 — **왕복 수**와 **원자성**.
 *
 * 예전엔 IMAP 백엔드가 메시지마다 스토어를 불렀다:
 *  · `UID STORE 1:* +FLAGS \\Seen` 1만 통 → 왕복 2만 번, modseq 1만 소모
 *    (라이터 큐가 직렬화하므로 그동안 그 계정의 다른 쓰기가 전부 대기한다)
 *  · `UID COPY` 는 중간 실패 시 **절반만 복사된 채** COPYUID가 나갔다 —
 *    CLAUDE.md §아키텍처("한 논리 연산 = db.batch() 한 번")와 RFC 9051 §6.4.7 위반
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver, type Statement } from "@ionosphere/db";
import { FsBlobStore, putBlob, Store } from "@ionosphere/store";

const N = 40;

/** batch() 호출 횟수를 세고, 원하는 시점에 실패를 주입할 수 있는 드라이버. */
function instrument(inner: DbDriver): {
  db: DbDriver;
  batches: () => number;
  failNext: (on: (stmts: readonly Statement[]) => boolean) => void;
} {
  let batches = 0;
  let trigger: ((stmts: readonly Statement[]) => boolean) | null = null;
  const db: DbDriver = {
    dialect: inner.dialect,
    query: (s) => inner.query(s),
    batch: (stmts) => {
      batches++;
      if (trigger && trigger(stmts)) {
        trigger = null;
        return Promise.reject(new Error("주입된 실패"));
      }
      return inner.batch(stmts);
    },
    insertIgnore: (t, c) => inner.insertIgnore(t, c),
    close: () => inner.close(),
  };
  return { db, batches: () => batches, failNext: (on) => { trigger = on; } };
}

async function setup() {
  const raw = await openSqlite(":memory:");
  await migrate(raw, allMigrations);
  const inst = instrument(raw);
  const store = new Store(inst.db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-batch-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });
  const { mailboxId: target } = await store.createMailbox({ accountId, name: "Archive" });

  const messageIds: string[] = [];
  for (let i = 0; i < N; i++) {
    const bytes = new Uint8Array(Buffer.from(`From: s@x.test\r\nSubject: m${i}\r\n\r\nb${i}\r\n`));
    const { blobId, size, generation } = await putBlob(inst.db, blobs, bytes);
    const r = await store.appendMessage({
      accountId,
      mailboxIds: [mailboxId],
      blobId,
      blobGeneration: generation,
      sizeBytes: size,
      receivedAt: Date.now() + i,
      envelope: {
        subject: `m${i}`, subjectBase: `m${i}`, msgidHash: null, sentAt: null,
        preview: null, hasAttachment: false, addresses: [], threadRefHashes: [],
      },
      keywords: [],
    });
    messageIds.push(r.messageId);
  }
  return { ...inst, store, accountId, mailboxId, target, messageIds };
}

async function count(db: DbDriver, sql: string, params: unknown[] = []): Promise<number> {
  const { rows } = await db.query({ sql, params });
  return Number(rows[0]!.n);
}

describe("setKeywordsBatch", () => {
  test(`${N}통을 배치 한 번으로 처리한다`, async () => {
    const { db, store, accountId, messageIds, batches } = await setup();
    const before = batches();
    const { changed } = await store.setKeywordsBatch({ accountId, messageIds, add: ["$seen"], remove: [] });

    expect(changed).toHaveLength(N);
    // 배치 1회 + 실패 시 재시도 여유. 메시지당 1회였다면 N회다.
    expect(batches() - before <= 2).toBe(true);
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_keywords WHERE keyword = '$seen'")).toBe(N);
    await db.close();
  });

  test("modseq를 그룹 전체가 공유한다(통당 하나가 아니다)", async () => {
    const { db, store, accountId, messageIds } = await setup();
    const { rows: before } = await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [accountId] });
    await store.setKeywordsBatch({ accountId, messageIds, add: ["$flagged"], remove: [] });
    const { rows: after } = await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [accountId] });
    expect(Number(after[0]!.modseq) - Number(before[0]!.modseq)).toBe(1);
    await db.close();
  });

  test("unread_count가 정확히 줄어든다", async () => {
    const { db, store, accountId, mailboxId, messageIds } = await setup();
    expect(await count(db, "SELECT unread_count AS n FROM mailboxes WHERE id = ?", [mailboxId])).toBe(N);
    await store.setKeywordsBatch({ accountId, messageIds, add: ["$seen"], remove: [] });
    expect(await count(db, "SELECT unread_count AS n FROM mailboxes WHERE id = ?", [mailboxId])).toBe(0);
    // 되돌리면 원복 — 중복 계산이 있으면 여기서 어긋난다.
    await store.setKeywordsBatch({ accountId, messageIds, add: [], remove: ["$seen"] });
    expect(await count(db, "SELECT unread_count AS n FROM mailboxes WHERE id = ?", [mailboxId])).toBe(N);
    await db.close();
  });

  test("replace(STORE FLAGS)는 목표 집합 밖을 지운다", async () => {
    const { db, store, accountId, messageIds } = await setup();
    await store.setKeywordsBatch({ accountId, messageIds, add: ["$seen", "$flagged"], remove: [] });
    await store.setKeywordsBatch({ accountId, messageIds, add: ["$flagged"], remove: [], replace: true });
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_keywords WHERE keyword = '$seen'")).toBe(0);
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_keywords WHERE keyword = '$flagged'")).toBe(N);
    await db.close();
  });

  test("변화가 없으면 modseq를 소모하지 않는다", async () => {
    const { db, store, accountId, messageIds } = await setup();
    await store.setKeywordsBatch({ accountId, messageIds, add: ["$seen"], remove: [] });
    const { rows: before } = await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [accountId] });
    const { changed } = await store.setKeywordsBatch({ accountId, messageIds, add: ["$seen"], remove: [] });
    const { rows: after } = await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [accountId] });
    expect(changed).toHaveLength(0);
    expect(Number(after[0]!.modseq)).toBe(Number(before[0]!.modseq));
    await db.close();
  });
});

describe("copyOrMoveMessages", () => {
  test("COPY — 전량이 대상에 생기고 원본은 남는다", async () => {
    const { db, store, accountId, mailboxId, target, messageIds } = await setup();
    const { pairs } = await store.copyOrMoveMessages({
      accountId, messageIds, fromMailboxId: mailboxId, toMailboxId: target, op: "copy",
    });
    expect(pairs).toHaveLength(N);
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", [target])).toBe(N);
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", [mailboxId])).toBe(N);
    expect(await count(db, "SELECT total_count AS n FROM mailboxes WHERE id = ?", [target])).toBe(N);
    // uid는 대상 메일함에서 중복 없이 이어져야 한다.
    expect(new Set(pairs.map((p) => p.uid)).size).toBe(N);
    await db.close();
  });

  test("MOVE — 원본이 비고 expunged 툼스톤이 남는다", async () => {
    const { db, store, accountId, mailboxId, target, messageIds } = await setup();
    await store.copyOrMoveMessages({ accountId, messageIds, fromMailboxId: mailboxId, toMailboxId: target, op: "move" });
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", [mailboxId])).toBe(0);
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", [target])).toBe(N);
    expect(await count(db, "SELECT COUNT(*) AS n FROM expunged WHERE mailbox_id = ?", [mailboxId])).toBe(N);
    expect(await count(db, "SELECT total_count AS n FROM mailboxes WHERE id = ?", [mailboxId])).toBe(0);
    await db.close();
  });

  /**
   * ★원자성 — 이 파일의 핵심. 배치가 실패하면 **아무것도** 남으면 안 된다.
   * 예전 구현은 메시지마다 커밋해서 절반이 남았다.
   */
  test("중간 실패 시 아무것도 남지 않는다", async () => {
    const { db, store, accountId, mailboxId, target, messageIds, failNext } = await setup();
    failNext((stmts) => stmts.some((st) => st.sql.includes("INSERT INTO message_mailbox")));

    let threw = false;
    try {
      await store.copyOrMoveMessages({ accountId, messageIds, fromMailboxId: mailboxId, toMailboxId: target, op: "copy" });
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", [target])).toBe(0);
    expect(await count(db, "SELECT total_count AS n FROM mailboxes WHERE id = ?", [target])).toBe(0);
    // 원본도 그대로여야 한다.
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", [mailboxId])).toBe(N);
    await db.close();
  });

  test("이미 대상에 있으면 no-op이고 기존 uid를 돌려준다(§5-2)", async () => {
    const { db, store, accountId, mailboxId, target, messageIds } = await setup();
    const first = await store.copyOrMoveMessages({
      accountId, messageIds, fromMailboxId: mailboxId, toMailboxId: target, op: "copy",
    });
    const again = await store.copyOrMoveMessages({
      accountId, messageIds, fromMailboxId: mailboxId, toMailboxId: target, op: "copy",
    });
    expect(again.pairs.map((p) => p.uid)).toEqual(first.pairs.map((p) => p.uid));
    expect(await count(db, "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?", [target])).toBe(N);
    await db.close();
  });
});
