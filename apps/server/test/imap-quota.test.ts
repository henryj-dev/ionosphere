/**
 * IMAP QUOTA (RFC 9208) — 데이터는 **이미 있었고 보여 줄 표면만 없었다.**
 *
 * `accounts.quota_bytes`/`used_bytes`를 `appendMessagesAttempt`가 스냅샷마다 검사하는데
 * (§7-1) 클라이언트가 그것을 볼 방법이 없었다. 사용자에게는 쿼터가 찰 때까지 아무 신호가
 * 없다가 어느 날 APPEND가 **원인 불명으로** 실패하는 것으로 보인다.
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

async function setup(quotaBytes: number) {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-quota-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });
  if (quotaBytes > 0) {
    await db.batch([{ sql: "UPDATE accounts SET quota_bytes = ? WHERE id = ?", params: [quotaBytes, accountId] }]);
  }
  return { db, store, blobs, accountId, mailboxId, backend: new IonosphereImapBackend(db, store, blobs) };
}

/** 엔진을 authenticated 상태로 몰고 명령을 돌린다 — 백엔드 요청은 실제 백엔드가 답한다. */
async function run(backend: IonosphereImapBackend, accountId: string, command: string): Promise<string[]> {
  const e = new ImapEngine({ hostname: "imap.test", secure: true });
  const out: string[] = [];
  const pump = async (actions: ImapAction[]): Promise<void> => {
    for (const a of actions) {
      if (a.kind === "reply") out.push(a.text);
      else if (a.kind === "backend") await pump(await backend.request(accountId, a.req as ImapBackendRequest).then((r) => e.backendResult(r)));
    }
  };
  await pump(e.feed(enc.encode("a1 LOGIN u p\r\n")));
  await pump(e.authResult({ accountId }));
  out.length = 0;
  await pump(e.feed(enc.encode(command)));
  return out;
}

describe("IMAP QUOTA", () => {
  test("CAPABILITY가 QUOTA를 광고한다", async () => {
    const { db, backend, accountId } = await setup(0);
    const out = await run(backend, accountId, "a2 CAPABILITY\r\n");
    expect(out[0]).toContain("QUOTA");
    expect(out[0]).toContain("QUOTA=RES-STORAGE");
    await db.close();
  });

  test("GETQUOTAROOT — 루트와 사용량을 함께 답한다", async () => {
    const { db, backend, accountId } = await setup(10 * 1024 * 1024);
    const out = await run(backend, accountId, "a2 GETQUOTAROOT INBOX\r\n");
    expect(out.some((l) => l.startsWith('* QUOTAROOT "INBOX" ""'))).toBe(true);
    // STORAGE 단위는 KiB(§5.2) — 10MiB = 10240
    expect(out.some((l) => l.includes('* QUOTA "" (STORAGE 0 10240)'))).toBe(true);
    expect(out[out.length - 1]).toContain("a2 OK");
    await db.close();
  });

  test("GETQUOTA — 루트 이름으로 조회한다", async () => {
    const { db, backend, accountId } = await setup(1024 * 1024);
    const out = await run(backend, accountId, 'a2 GETQUOTA ""\r\n');
    expect(out.some((l) => l.includes('* QUOTA "" (STORAGE 0 1024)'))).toBe(true);
    await db.close();
  });

  test("없는 루트는 NONEXISTENT", async () => {
    const { db, backend, accountId } = await setup(1024);
    const out = await run(backend, accountId, 'a2 GETQUOTA "other"\r\n');
    expect(out[0]).toContain("NONEXISTENT");
    await db.close();
  });

  /**
   * ★한도 0(무제한)이면 STORAGE를 **싣지 않는다.** RFC 9208은 "한도 없음"을 표현하는 값을
   * 정의하지 않으므로, 0을 실으면 클라이언트가 "0바이트 허용"으로 읽고 업로드를 막는다.
   */
  test("무제한이면 STORAGE 항목을 싣지 않는다", async () => {
    const { db, backend, accountId } = await setup(0);
    const out = await run(backend, accountId, "a2 GETQUOTAROOT INBOX\r\n");
    const quota = out.find((l) => l.startsWith("* QUOTA "))!;
    expect(quota).toContain('* QUOTA "" ()');
    expect(quota).not.toContain("STORAGE");
    await db.close();
  });

  test("사용량이 실제 저장 바이트를 따라간다", async () => {
    const { db, store, blobs, accountId, mailboxId, backend } = await setup(10 * 1024 * 1024);
    const raw = new Uint8Array(Buffer.from("From: a@x.test\r\nSubject: s\r\n\r\n" + "x".repeat(5000) + "\r\n"));
    const { blobId, size, generation } = await putBlob(db, blobs, raw);
    await store.appendMessage({
      accountId, mailboxIds: [mailboxId], blobId, blobGeneration: generation, sizeBytes: size,
      receivedAt: Date.now(),
      envelope: { subject: "s", subjectBase: "s", msgidHash: null, sentAt: null, preview: null, hasAttachment: false, addresses: [], threadRefHashes: [] },
      keywords: [],
    });
    const out = await run(backend, accountId, "a2 GETQUOTAROOT INBOX\r\n");
    // 5000+바이트 → 올림하면 최소 5 KiB
    expect(out.some((l) => /\* QUOTA "" \(STORAGE ([5-9]|\d\d) 10240\)/.test(l))).toBe(true);
    await db.close();
  });

  /** 쿼터는 운영자가 정한다 — 클라이언트가 자기 한도를 올릴 수 있으면 쿼터가 아니다. */
  test("SETQUOTA는 거부한다", async () => {
    const { db, backend, accountId } = await setup(1024);
    const out = await run(backend, accountId, 'a2 SETQUOTA "" (STORAGE 999999)\r\n');
    expect(out[0]).toContain("NO [CANNOT]");
    await db.close();
  });

  /**
   * ★사용자가 보는 절반 — 쿼터를 넘겼을 때 **왜** 실패했는지 알려야 한다.
   * 예전엔 평범한 NO라 클라이언트가 원인을 표시할 수 없었다.
   */
  test("쿼터 초과 APPEND는 [OVERQUOTA]로 답한다", async () => {
    const { db, backend, accountId } = await setup(100); // 100바이트 — 무엇을 넣어도 넘는다
    const msg = "From: a@x.test\r\nSubject: big\r\n\r\n" + "y".repeat(500) + "\r\n";
    const literal = `a2 APPEND INBOX {${msg.length}}\r\n${msg}\r\n`;
    const out = await run(backend, accountId, literal);
    expect(out.some((l) => l.includes("[OVERQUOTA]"))).toBe(true);
    await db.close();
  });
});
