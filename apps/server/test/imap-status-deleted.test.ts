/**
 * STATUS DELETED — 실제 스토어까지(엔진 단위 테스트는 packages/proto-imap/test/status-deleted.test.ts).
 *
 * 엔진이 `deletedCounts`를 요청하면 백엔드가 `message_mailbox.deleted`를 세어 돌려주는지 본다.
 * 예전엔 STATUS (DELETED)가 BAD였다 — IMAP4rev2를 광고하면서 rev2 필수 항목을 몰랐다.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { FsBlobStore, Store } from "@ionosphere/store";
import { ImapEngine, type ImapAction, type ImapBackendRequest } from "@ionosphere/proto-imap";
import { IonosphereImapBackend } from "../src/imap-backend.ts";

const enc = new TextEncoder();

async function setup() {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-status-deleted-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "a@x.test" });
  return { db, accountId, backend: new IonosphereImapBackend(db, store, blobs) };
}

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

function message(subject: string): string {
  return `From: a@x.test\r\nTo: a@x.test\r\nSubject: ${subject}\r\n\r\nbody\r\n`;
}

async function append(backend: IonosphereImapBackend, accountId: string, flags: string, subject: string): Promise<void> {
  const raw = message(subject);
  // LITERAL-(비동기 리터럴, 4096바이트 이하) — 한 번에 보낸다.
  const out = await run(backend, accountId, `ap APPEND INBOX (${flags}) {${Buffer.byteLength(raw)}+}\r\n${raw}\r\n`);
  expect(out.at(-1)).toMatch(/^ap OK/);
}

describe("STATUS DELETED — 실제 스토어", () => {
  test("★\\Deleted 표시 수를 센다 — STATUS와 LIST-STATUS 모두", async () => {
    const { db, backend, accountId } = await setup();
    await append(backend, accountId, "\\Deleted", "one");
    await append(backend, accountId, "\\Deleted \\Seen", "two");
    await append(backend, accountId, "\\Seen", "three");

    expect(await run(backend, accountId, "s STATUS INBOX (MESSAGES DELETED)\r\n")).toEqual([
      '* STATUS "INBOX" (MESSAGES 3 DELETED 2)',
      "s OK STATUS completed",
    ]);
    const list = await run(backend, accountId, 'l LIST "" "INBOX" RETURN (STATUS (DELETED))\r\n');
    expect(list).toContain('* STATUS "INBOX" (DELETED 2)');
    await db.close();
  });

  test("표시가 하나도 없으면 0", async () => {
    const { db, backend, accountId } = await setup();
    await append(backend, accountId, "\\Seen", "one");
    expect(await run(backend, accountId, "s STATUS INBOX (DELETED)\r\n")).toEqual(['* STATUS "INBOX" (DELETED 0)', "s OK STATUS completed"]);
    await db.close();
  });
});
