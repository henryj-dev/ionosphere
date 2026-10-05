/**
 * UID FETCH VANISHED (RFC 7162 §3.2.6) — 실제 스토어까지(엔진 단위는 packages/proto-imap/test/qresync-vanished-fetch.test.ts).
 *
 * 메시지를 실제로 지운 뒤(expunged 툼스톤) `UID FETCH … (CHANGEDSINCE n VANISHED)`가 그 uid를
 * `* VANISHED (EARLIER)`로 알려 주는지, 바뀐 메시지만 FETCH로 오는지 본다. 예전엔 이 요청이 BAD였다.
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
const dec = new TextDecoder();

async function session() {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-vanished-fetch-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "a@x.test" });
  const backend = new IonosphereImapBackend(db, store, blobs);
  const e = new ImapEngine({ hostname: "imap.test", secure: true });
  const out: string[] = [];
  const pump = async (actions: ImapAction[]): Promise<void> => {
    for (const a of actions) {
      if (a.kind === "reply") out.push(a.text);
      else if (a.kind === "replyBinary") out.push(dec.decode(a.bytes).replace(/\r\n$/, ""));
      else if (a.kind === "backend") await pump(await backend.request(accountId, a.req as ImapBackendRequest).then((r) => e.backendResult(r)));
    }
  };
  await pump(e.feed(enc.encode("a1 LOGIN u p\r\n")));
  await pump(e.authResult({ accountId }));
  /** 명령 하나를 보내고 그 명령이 만든 줄만 돌려준다. */
  const run = async (line: string): Promise<string[]> => {
    out.length = 0;
    await pump(e.feed(enc.encode(line)));
    return [...out];
  };
  return { db, run };
}

function message(subject: string): string {
  return `From: a@x.test\r\nTo: a@x.test\r\nSubject: ${subject}\r\n\r\nbody\r\n`;
}

describe("UID FETCH VANISHED — 실제 스토어", () => {
  test("★지운 메시지는 VANISHED (EARLIER)로, 바뀐 메시지는 FETCH로 온다", async () => {
    const { db, run } = await session();
    expect((await run("e1 ENABLE QRESYNC\r\n")).at(-1)).toMatch(/^e1 OK/);
    for (const s of ["one", "two", "three"]) {
      const raw = message(s);
      expect((await run(`ap APPEND INBOX {${Buffer.byteLength(raw)}+}\r\n${raw}\r\n`)).at(-1)).toMatch(/^ap OK/);
    }
    const sel = await run("s1 SELECT INBOX\r\n");
    const before = Number(/HIGHESTMODSEQ (\d+)/.exec(sel.join("\n"))?.[1]);
    expect(before > 0).toBe(true);

    // uid 2를 지우고, uid 3의 플래그를 바꾼다 — 둘 다 `before` 이후의 변화다.
    expect((await run("x1 UID STORE 2 +FLAGS (\\Deleted)\r\n")).at(-1)).toMatch(/^x1 OK/);
    expect((await run("x2 UID EXPUNGE 2\r\n")).at(-1)).toMatch(/^x2 OK/);
    expect((await run("x3 UID STORE 3 +FLAGS (\\Seen)\r\n")).at(-1)).toMatch(/^x3 OK/);

    const out = await run(`f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE ${before} VANISHED)\r\n`);
    // uid 2가 지워졌으므로 uid 3은 시퀀스 2다. 안 바뀐 uid 1은 CHANGEDSINCE로 걸러진다.
    expect(out).toHaveLength(3);
    expect(out[0]).toBe("* VANISHED (EARLIER) 2");
    expect(out[1]).toMatch(/^\* 2 FETCH \(FLAGS \(\\Seen\) UID 3 MODSEQ \(\d+\)\)$/);
    expect(out[2]).toBe("f1 OK UID FETCH completed");
    await db.close();
  });

  test("QRESYNC를 켜지 않으면 BAD — 규격(§3.2.6)이 요구한다", async () => {
    const { db, run } = await session();
    await run("s1 SELECT INBOX\r\n");
    expect(await run("f1 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)\r\n")).toEqual(["f1 BAD QRESYNC not enabled"]);
    await db.close();
  });
});
