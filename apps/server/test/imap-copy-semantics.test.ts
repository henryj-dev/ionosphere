/**
 * IMAP COPY 시맨틱 (RFC 9051 §6.4.7) — 감사 G2의 결정을 IMAP 표면에서 고정한다.
 *
 * ★예전엔 같은 `message_id`로 `message_mailbox` 행만 더했다. 두 가지가 틀렸다:
 *  · 사본과 원본이 `message_keywords`를 **공유**해서 한쪽에 `\Seen`을 달면 다른 쪽도 읽음
 *  · `ux_mm_message` 제약 때문에 같은 메일함으로의 COPY가 **조용한 no-op**
 *
 * 아래는 그 둘이 각각 고쳐졌는지를 클라이언트가 보는 그대로(FETCH FLAGS·EXISTS) 확인한다.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { FsBlobStore, putBlob, Store } from "@ionosphere/store";
import { ImapEngine, type ImapAction, type ImapBackendRequest } from "@ionosphere/proto-imap";
import { IonosphereImapBackend } from "../src/imap-backend.ts";

const enc = new TextEncoder();
const RAW = enc.encode(["From: s@x.test", "To: a@x.test", "Subject: copy me", "", "hello body", ""].join("\r\n"));

interface Ctx {
  db: DbDriver;
  store: Store;
  accountId: string;
  inboxId: string;
  targetId: string;
  backend: IonosphereImapBackend;
}

async function setup(): Promise<Ctx> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-copy-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });
  const { mailboxId: targetId } = await store.createMailbox({ accountId, name: "Archive" });

  const { blobId, generation } = await putBlob(db, blobs, RAW);
  await store.appendMessage({
    accountId,
    mailboxIds: [mailboxId],
    blobId,
    blobGeneration: generation,
    sizeBytes: RAW.length,
    receivedAt: Date.now(),
    envelope: {
      subject: "copy me",
      subjectBase: "copy me",
      msgidHash: null,
      sentAt: null,
      preview: "hello body",
      hasAttachment: false,
      addresses: [],
      threadRefHashes: [],
    },
    keywords: ["$flagged"],
    searchText: { subject: "copy me", body: "hello body" },
  });
  return { db, store, accountId, inboxId: mailboxId, targetId, backend: new IonosphereImapBackend(db, store, blobs) };
}

/** 한 세션에서 여러 명령을 순서대로 돌린다 — SELECT 상태가 명령 사이에 유지돼야 한다. */
async function session(ctx: Ctx): Promise<{ run: (cmd: string) => Promise<string[]>; }> {
  const e = new ImapEngine({ hostname: "imap.test", secure: true });
  const out: string[] = [];
  const pump = async (actions: ImapAction[]): Promise<void> => {
    for (const a of actions) {
      if (a.kind === "reply") out.push(a.text);
      else if (a.kind === "replyBinary") out.push(new TextDecoder().decode(a.bytes).trimEnd());
      else if (a.kind === "backend") {
        await pump(e.backendResult(await ctx.backend.request(ctx.accountId, a.req as ImapBackendRequest)));
      }
    }
  };
  await pump(e.feed(enc.encode("a1 LOGIN u p\r\n")));
  await pump(e.authResult({ accountId: ctx.accountId }));
  return {
    run: async (cmd: string) => {
      out.length = 0;
      await pump(e.feed(enc.encode(cmd)));
      return [...out];
    },
  };
}

describe("IMAP COPY — 사본은 독립된 메시지다", () => {
  /**
   * ★핵심. 사본에 `\Seen`을 달아도 원본은 그대로여야 한다(§6.4.7). 예전엔 같은
   * `message_id`를 공유해서 한쪽에 단 플래그가 양쪽에 보였다.
   */
  test("사본의 플래그가 원본에 번지지 않는다", async () => {
    const ctx = await setup();
    const s = await session(ctx);

    await s.run("s1 SELECT INBOX\r\n");
    const copied = await s.run("c1 COPY 1 Archive\r\n");
    expect(copied.join("\n")).toContain("OK [COPYUID");

    // 사본에 \Seen을 단다
    await s.run("s2 SELECT Archive\r\n");
    await s.run("t1 STORE 1 +FLAGS (\\Seen)\r\n");
    const inArchive = await s.run("f1 FETCH 1 (FLAGS)\r\n");
    expect(inArchive.join("\n")).toContain("\\Seen");

    // 원본은 그대로 — 이게 이 파일이 존재하는 이유다
    await s.run("s3 SELECT INBOX\r\n");
    const inInbox = await s.run("f2 FETCH 1 (FLAGS)\r\n");
    expect(inInbox.join("\n")).not.toContain("\\Seen");
    // 원본의 기존 플래그는 사본에도 그대로 복제됐어야 한다(사본은 원본 상태로 시작한다)
    expect(inInbox.join("\n")).toContain("\\Flagged"); // $flagged는 IMAP 표면에서 시스템 플래그다
    expect(inArchive.join("\n")).toContain("\\Flagged");

    await ctx.db.close();
  });

  /**
   * ★예전엔 `ux_mm_message(mailbox_id, message_id)` 때문에 **조용한 no-op**이었다.
   * 클라이언트는 `COPYUID`로 성공을 받고 사본이 없는 것을 나중에 안다.
   */
  test("같은 메일함으로의 COPY가 사본을 만든다", async () => {
    const ctx = await setup();
    const s = await session(ctx);

    await s.run("s1 SELECT INBOX\r\n");
    const out = await s.run("c1 COPY 1 INBOX\r\n");
    expect(out.join("\n")).toContain("OK [COPYUID");

    // 다시 SELECT하면 2통이다
    const sel = await s.run("s2 SELECT INBOX\r\n");
    expect(sel.some((l) => l === "* 2 EXISTS")).toBe(true);

    await ctx.db.close();
  });

  /** 사본도 본문을 온전히 읽을 수 있어야 한다 — 블롭은 공유하되 참조가 따로 달린다. */
  test("사본의 본문을 읽을 수 있다", async () => {
    const ctx = await setup();
    const s = await session(ctx);
    await s.run("s1 SELECT INBOX\r\n");
    await s.run("c1 COPY 1 Archive\r\n");
    await s.run("s2 SELECT Archive\r\n");
    const out = await s.run("f1 FETCH 1 (BODY.PEEK[])\r\n");
    expect(out.join("\n")).toContain("hello body");
    await ctx.db.close();
  });

  /**
   * ★원본을 지워도 사본의 원문이 남아야 한다. 블롭을 공유하므로 `blob_refs`에 참조가
   * 하나 더 달려야 하고, 그러지 않으면 GC가 사본의 원문까지 지운다.
   */
  test("원본을 파기해도 사본의 본문이 남는다", async () => {
    const ctx = await setup();
    const s = await session(ctx);
    await s.run("s1 SELECT INBOX\r\n");
    await s.run("c1 COPY 1 Archive\r\n");

    const { rows } = await ctx.db.query({
      sql: "SELECT id FROM messages WHERE account_id = ? ORDER BY created_at",
      params: [ctx.accountId],
    });
    expect(rows).toHaveLength(2);
    await ctx.store.destroyMessage(ctx.accountId, String(rows[0]!.id));

    await s.run("s2 SELECT Archive\r\n");
    const out = await s.run("f1 FETCH 1 (BODY.PEEK[])\r\n");
    expect(out.join("\n")).toContain("hello body");
    await ctx.db.close();
  });

  /** MOVE는 그대로 **같은 메시지**가 옮겨 간다 — 새 행을 만들면 JMAP Email id가 바뀐다. */
  test("MOVE는 message_id를 바꾸지 않는다", async () => {
    const ctx = await setup();
    const before = await ctx.db.query({ sql: "SELECT id FROM messages WHERE account_id = ?", params: [ctx.accountId] });
    const s = await session(ctx);
    await s.run("s1 SELECT INBOX\r\n");
    await s.run("m1 MOVE 1 Archive\r\n");
    const after = await ctx.db.query({ sql: "SELECT id FROM messages WHERE account_id = ?", params: [ctx.accountId] });
    expect(after.rows.map((r) => String(r.id))).toEqual(before.rows.map((r) => String(r.id)));
    await ctx.db.close();
  });
});
