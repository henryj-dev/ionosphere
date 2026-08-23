/** JMAP EventSource push (RFC 8620 §7.3) — 상태 변화 시 StateChange를 SSE로 푸시. */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { createCredential, FsBlobStore, Store } from "@ionosphere/store";
import { JmapServer } from "../src/jmap-server.ts";

let db: DbDriver;
let store: Store;
let server: JmapServer;
let port: number;
let blobRoot: string;
let accountId: string;
let inboxId: string;
const auth = "Basic " + Buffer.from("u@test.local:pw-sse").toString("base64");

beforeAll(async () => {
  db = await openSqlite();
  await migrate(db, allMigrations);
  store = new Store(db);
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-sse-"));
  const { tenantId } = await store.createTenant("t");
  const acc = await store.createAccount({ tenantId, email: "u@test.local" });
  accountId = acc.accountId;
  inboxId = acc.mailboxId;
  await createCredential(db, { accountId, password: "pw-sse" });
  server = new JmapServer({ db, store, blobs: new FsBlobStore(blobRoot), hostname: "test.local", eventSourcePollMs: 40 });
  port = await server.listen(0, "127.0.0.1");
});

afterAll(async () => {
  await server.close();
  await db.close();
  rmSync(blobRoot, { recursive: true, force: true });
});

/** SSE 스트림에서 pred를 만족하는 텍스트가 누적될 때까지 읽는다(타임아웃 시 그때까지 텍스트). */
async function readUntil(res: Response, pred: (buf: string) => boolean, timeoutMs = 3000): Promise<string> {
  const reader = res.body!.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const deadline = Date.now() + timeoutMs;
  try {
    while (Date.now() < deadline) {
      const chunk = await Promise.race([
        reader.read(),
        new Promise<{ done: true; value: undefined }>((r) => setTimeout(() => r({ done: true, value: undefined }), deadline - Date.now())),
      ]);
      if (chunk.value) buf += dec.decode(chunk.value, { stream: true });
      if (pred(buf)) break;
      if (chunk.done) break;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return buf;
}

describe("GET /jmap/eventsource", () => {
  test("인증 없으면 401", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/jmap/eventsource`);
    expect(res.status).toBe(401);
    await res.body?.cancel();
  });

  test("연결 → 상태 변경(메일 append) → StateChange(Email) 푸시", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/jmap/eventsource?ping=0`, { headers: { authorization: auth } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");

    // 기준선 폴 이후 상태 변경 유발 — 살짝 대기 후 append
    await new Promise((r) => setTimeout(r, 120));
    await store.appendMessage({
      accountId,
      mailboxIds: [inboxId],
      blobId: "b".repeat(64),
      sizeBytes: 100,
      receivedAt: Date.now(),
      envelope: { subject: null, subjectBase: null, msgidHash: null, sentAt: null, preview: null, hasAttachment: false, addresses: [], threadRefHashes: [] },
      keywords: [],
    });

    const text = await readUntil(res, (b) => b.includes("event: state"));
    expect(text).toContain("event: state");
    expect(text).toContain('"@type":"StateChange"');
    expect(text).toContain(accountId);
    expect(text).toContain('"Email"');
  });

  test("closeafter=state → 첫 StateChange 후 스트림 종료", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/jmap/eventsource?closeafter=state`, { headers: { authorization: auth } });
    await new Promise((r) => setTimeout(r, 120));
    await store.appendMessage({
      accountId,
      mailboxIds: [inboxId],
      blobId: "c".repeat(64),
      sizeBytes: 100,
      receivedAt: Date.now(),
      envelope: { subject: null, subjectBase: null, msgidHash: null, sentAt: null, preview: null, hasAttachment: false, addresses: [], threadRefHashes: [] },
      keywords: [],
    });
    const text = await readUntil(res, (b) => b.includes("event: state"));
    expect(text).toContain("event: state");
  });
});
