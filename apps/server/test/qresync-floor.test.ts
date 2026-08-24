/**
 * QRESYNC 툼스톤 보존창 (RFC 7162 §3.2.5.2) — 감사 D4.
 *
 * ★`expunged` 툼스톤은 여태 한 번도 지워지지 않았다. 지우지 못한 이유는 디스크가 아까워서가
 * 아니라, 지우면 오래 떠나 있던 클라이언트가 "삭제된 적 없다"는 답을 받고 **유령 메시지**를
 * 영영 들고 있게 되기 때문이다 — 조용히 틀린 답이라 사용자가 알아차릴 방법도 없다.
 *
 * 이제 하한(`mailboxes.expunged_floor`)이 있고, 그 아래 요청은 툼스톤 대신 **차집합**으로
 * 답한다: 클라이언트가 준 known-uids(없으면 `1:uidnext-1`)에서 현재 존재하는 uid를 뺀다.
 * 이 파일은 그 답이 툼스톤 경로와 **같은 결과**인지를 확인한다 — 같지 않으면 고친 게 아니다.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { FsBlobStore, putBlob, Store } from "@ionosphere/store";
import { IonosphereImapBackend } from "../src/imap-backend.ts";

const enc = new TextEncoder();

interface Ctx {
  db: DbDriver;
  store: Store;
  accountId: string;
  mailboxId: string;
  backend: IonosphereImapBackend;
  uids: number[];
}

/** 5통을 넣고 uid 2·4를 EXPUNGE한다 — 남는 것은 1·3·5. */
async function setup(): Promise<Ctx> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-qr-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });

  const uids: number[] = [];
  for (let i = 1; i <= 5; i++) {
    const raw = enc.encode(`From: s@x.test\r\nSubject: m${i}\r\n\r\nbody ${i}\r\n`);
    const { blobId, generation } = await putBlob(db, blobs, raw);
    const r = await store.appendMessage({
      accountId,
      mailboxIds: [mailboxId],
      blobId,
      blobGeneration: generation,
      sizeBytes: raw.length,
      receivedAt: Date.now(),
      envelope: { subject: `m${i}`, subjectBase: `m${i}`, msgidHash: null, sentAt: null, preview: "p", hasAttachment: false, addresses: [], threadRefHashes: [] },
      keywords: [],
      searchText: {},
    });
    uids.push(r.uids.get(mailboxId)!);
  }

  // uid 2·4를 파기 → expunged 툼스톤이 생긴다
  const { rows } = await db.query({
    sql: "SELECT message_id, uid FROM message_mailbox WHERE mailbox_id = ? ORDER BY uid",
    params: [mailboxId],
  });
  for (const r of rows) {
    if (Number(r.uid) === uids[1] || Number(r.uid) === uids[3]) {
      await store.destroyMessage(accountId, String(r.message_id));
    }
  }
  return { db, store, accountId, mailboxId, backend: new IonosphereImapBackend(db, store, blobs), uids };
}

async function sync(ctx: Ctx, sinceModseq: number, knownUids?: { from: number | "*"; to: number | "*" }[]): Promise<number[]> {
  const res = await ctx.backend.request(ctx.accountId, {
    kind: "syncSince",
    name: "INBOX",
    sinceModseq,
    ...(knownUids ? { knownUids } : {}),
  });
  if (res.kind !== "sync") throw new Error(`expected sync, got ${res.kind}`);
  return [...res.vanished];
}

async function raiseFloor(ctx: Ctx, floor: number): Promise<void> {
  await ctx.db.batch([{ sql: "UPDATE mailboxes SET expunged_floor = ? WHERE id = ?", params: [floor, ctx.mailboxId] }]);
}

describe("QRESYNC 보존창 하한", () => {
  test("하한 위 — 툼스톤이 답이다", async () => {
    const ctx = await setup();
    expect(await sync(ctx, 0)).toEqual([ctx.uids[1]!, ctx.uids[3]!]);
    await ctx.db.close();
  });

  /**
   * ★핵심 — 툼스톤을 지우고 하한을 올려도 **같은 답**이 나와야 한다.
   * 다르면 고친 것이 아니라 옮긴 것이다.
   */
  test("하한 아래 — 툼스톤을 지워도 차집합이 같은 답을 낸다", async () => {
    const ctx = await setup();
    const viaTombstones = await sync(ctx, 0);

    await ctx.db.batch([{ sql: "DELETE FROM expunged WHERE mailbox_id = ?", params: [ctx.mailboxId] }]);
    await raiseFloor(ctx, 9999);

    // known-uids로 "내가 아는 uid는 1~5"라고 알려 준다
    const viaDifference = await sync(ctx, 0, [{ from: 1, to: 5 }]);
    expect(viaDifference).toEqual(viaTombstones);
    await ctx.db.close();
  });

  /** §3.2.5.2 — known-uids가 없으면 `1:<uidnext-1>`로 간주한다. */
  test("known-uids가 없으면 1:uidnext-1로 간주한다", async () => {
    const ctx = await setup();
    await ctx.db.batch([{ sql: "DELETE FROM expunged WHERE mailbox_id = ?", params: [ctx.mailboxId] }]);
    await raiseFloor(ctx, 9999);

    const vanished = await sync(ctx, 0);
    // 남은 것은 1·3·5이므로 사라진 것은 2·4다. uidnext 밖은 세지 않는다.
    expect(vanished).toEqual([ctx.uids[1]!, ctx.uids[3]!]);
    await ctx.db.close();
  });

  /**
   * ★클라이언트가 아는 범위만 답한다 — 모르는 uid를 VANISHED로 보내면 쓸모없는 잡음이고,
   * 큰 메일함에서는 그 잡음이 응답을 통째로 부풀린다.
   */
  test("known-uids 범위 밖은 답하지 않는다", async () => {
    const ctx = await setup();
    await ctx.db.batch([{ sql: "DELETE FROM expunged WHERE mailbox_id = ?", params: [ctx.mailboxId] }]);
    await raiseFloor(ctx, 9999);

    const vanished = await sync(ctx, 0, [{ from: 1, to: 3 }]);
    expect(vanished).toEqual([ctx.uids[1]!]); // uid 4는 클라이언트가 모른다
    await ctx.db.close();
  });

  /** `*`는 uidnext-1로 닫는다 — 열어 두면 존재하지 않는 uid를 무한히 센다. */
  test("known-uids의 *는 uidnext-1로 닫힌다", async () => {
    const ctx = await setup();
    await ctx.db.batch([{ sql: "DELETE FROM expunged WHERE mailbox_id = ?", params: [ctx.mailboxId] }]);
    await raiseFloor(ctx, 9999);

    const vanished = await sync(ctx, 0, [{ from: 1, to: "*" }]);
    expect(vanished).toEqual([ctx.uids[1]!, ctx.uids[3]!]);
    await ctx.db.close();
  });

  /**
   * ★유령 방지 — 하한을 무시하고 툼스톤만 봤다면 여기서 **빈 배열**이 나온다.
   * 그게 이 작업 전의 동작이고, 클라이언트는 지워진 메일을 영영 들고 있게 된다.
   */
  test("툼스톤이 없어도 삭제를 놓치지 않는다", async () => {
    const ctx = await setup();
    await ctx.db.batch([{ sql: "DELETE FROM expunged WHERE mailbox_id = ?", params: [ctx.mailboxId] }]);
    await raiseFloor(ctx, 9999);
    expect((await sync(ctx, 0)).length).toBeGreaterThan(0);
    await ctx.db.close();
  });
});
