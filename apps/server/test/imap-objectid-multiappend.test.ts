/**
 * OBJECTID(RFC 8474) · MULTIAPPEND(RFC 3502) — 백엔드까지 이어지는 확인.
 *
 * ★두 기능 다 **데이터가 이미 있었다.** 메일함·메시지·스레드가 전부 ULID를 갖고 있고
 * `store.appendMessages`는 처음부터 그룹 배치였다. 그래서 여기서 볼 것은 "동작하는가"보다
 * **약속을 지키는가**다: id는 불변인가, MULTIAPPEND는 정말 원자적인가.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { FsBlobStore, Store } from "@ionosphere/store";
import { ImapEngine, type ImapAction, type ImapBackendRequest } from "@ionosphere/proto-imap";
import { IonosphereImapBackend } from "../src/imap-backend.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

interface Ctx {
  db: DbDriver;
  store: Store;
  accountId: string;
  mailboxId: string;
  backend: IonosphereImapBackend;
}

async function setup(): Promise<Ctx> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-oid-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });
  return { db, store, accountId, mailboxId, backend: new IonosphereImapBackend(db, store, blobs) };
}

/** 인증된 세션 하나 — 명령 사이에 SELECT 상태가 유지된다. */
async function session(ctx: Ctx): Promise<(cmd: string) => Promise<string>> {
  const e = new ImapEngine({ hostname: "imap.test", secure: true });
  let out = "";
  const pump = async (actions: ImapAction[]): Promise<void> => {
    for (const a of actions) {
      if (a.kind === "reply") out += a.text + "\r\n";
      else if (a.kind === "replyBinary") out += dec.decode(a.bytes);
      else if (a.kind === "backend") await pump(e.backendResult(await ctx.backend.request(ctx.accountId, a.req as ImapBackendRequest)));
    }
  };
  await pump(e.feed(enc.encode("a1 LOGIN u p\r\n")));
  await pump(e.authResult({ accountId: ctx.accountId }));
  return async (cmd: string) => {
    out = "";
    await pump(e.feed(enc.encode(cmd)));
    return out;
  };
}

const MSG = (n: string): string => `From: s@x.test\r\nSubject: ${n}\r\n\r\nbody ${n}\r\n`;

describe("OBJECTID (RFC 8474)", () => {
  test("SELECT가 MAILBOXID를 낸다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const out = await run("s1 SELECT INBOX\r\n");
    expect(out).toContain(`[MAILBOXID (${ctx.mailboxId})]`);
    await ctx.db.close();
  });

  /**
   * ★이름을 바꿔도 **같은 id**여야 한다. 그게 이 확장의 존재 이유다 — 클라이언트가
   * "이름이 바뀐 것"과 "지우고 새로 만든 것"을 구분해 캐시를 지킨다.
   */
  test("이름을 바꿔도 MAILBOXID는 그대로다", async () => {
    const ctx = await setup();
    const { mailboxId } = await ctx.store.createMailbox({ accountId: ctx.accountId, name: "Old" });
    const run = await session(ctx);
    expect(await run("s1 SELECT Old\r\n")).toContain(`[MAILBOXID (${mailboxId})]`);
    await run("r1 RENAME Old New\r\n");
    expect(await run("s2 SELECT New\r\n")).toContain(`[MAILBOXID (${mailboxId})]`);
    await ctx.db.close();
  });

  test("STATUS MAILBOXID", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const out = await run("t1 STATUS INBOX (MAILBOXID MESSAGES)\r\n");
    expect(out).toContain(`MAILBOXID (${ctx.mailboxId})`);
    await ctx.db.close();
  });

  test("FETCH EMAILID / THREADID", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const raw = MSG("one");
    await run(`p1 APPEND INBOX {${raw.length}+}\r\n${raw}\r\n`);
    await run("s1 SELECT INBOX\r\n");
    const out = await run("f1 FETCH 1 (EMAILID THREADID)\r\n");

    const { rows } = await ctx.db.query({ sql: "SELECT id, thread_id FROM messages", params: [] });
    expect(out).toContain(`EMAILID (${String(rows[0]!.id)})`);
    expect(out).toContain(`THREADID (${String(rows[0]!.thread_id)})`);
    await ctx.db.close();
  });

  /** ★EMAILID는 **UID가 아니다** — 사본은 새 메시지라 다른 EMAILID를 갖는다. */
  test("COPY한 사본은 다른 EMAILID를 갖는다", async () => {
    const ctx = await setup();
    await ctx.store.createMailbox({ accountId: ctx.accountId, name: "Archive" });
    const run = await session(ctx);
    const raw = MSG("one");
    await run(`p1 APPEND INBOX {${raw.length}+}\r\n${raw}\r\n`);
    await run("s1 SELECT INBOX\r\n");
    const src = await run("f1 FETCH 1 (EMAILID)\r\n");
    await run("c1 COPY 1 Archive\r\n");
    await run("s2 SELECT Archive\r\n");
    const dst = await run("f2 FETCH 1 (EMAILID)\r\n");

    const idOf = (t: string): string => /EMAILID \(([^)]+)\)/.exec(t)![1]!;
    expect(idOf(src)).not.toBe(idOf(dst));
    await ctx.db.close();
  });

  /** 반대로 THREADID는 **같아야** 한다 — 사본도 같은 대화다. */
  test("사본의 THREADID는 원본과 같다", async () => {
    const ctx = await setup();
    await ctx.store.createMailbox({ accountId: ctx.accountId, name: "Archive" });
    const run = await session(ctx);
    const raw = MSG("one");
    await run(`p1 APPEND INBOX {${raw.length}+}\r\n${raw}\r\n`);
    await run("s1 SELECT INBOX\r\n");
    const src = await run("f1 FETCH 1 (THREADID)\r\n");
    await run("c1 COPY 1 Archive\r\n");
    await run("s2 SELECT Archive\r\n");
    const dst = await run("f2 FETCH 1 (THREADID)\r\n");
    const idOf = (t: string): string => /THREADID \(([^)]+)\)/.exec(t)![1]!;
    expect(idOf(src)).toBe(idOf(dst));
    await ctx.db.close();
  });
});

describe("MULTIAPPEND (RFC 3502)", () => {
  test("세 통을 한 번에 넣는다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const [a, b, c] = [MSG("a"), MSG("b"), MSG("c")];
    const out = await run(
      `p1 APPEND INBOX {${a.length}+}\r\n${a} {${b.length}+}\r\n${b} {${c.length}+}\r\n${c}\r\n`,
    );
    expect(out).toContain("OK [APPENDUID");
    const { rows } = await ctx.db.query({ sql: "SELECT COUNT(*) AS n FROM messages", params: [] });
    expect(Number(rows[0]!.n)).toBe(3);
    await ctx.db.close();
  });

  test("통마다 다른 플래그가 붙는다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const [a, b] = [MSG("a"), MSG("b")];
    await run(`p1 APPEND INBOX (\\Seen) {${a.length}+}\r\n${a} (\\Draft) {${b.length}+}\r\n${b}\r\n`);
    await run("s1 SELECT INBOX\r\n");
    const out = await run("f1 FETCH 1:2 (FLAGS)\r\n");
    expect(out).toContain("\\Seen");
    expect(out).toContain("\\Draft");
    await ctx.db.close();
  });

  /**
   * ★**전부 아니면 전무**(§3). 빈 메시지 하나가 섞이면 앞의 것도 들어가면 안 된다 —
   * 절반만 들어간 채 `APPENDUID`가 나가면 클라이언트는 전부 들어간 줄 안다.
   */
  test("하나가 잘못되면 아무것도 들어가지 않는다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const a = MSG("a");
    const out = await run(`p1 APPEND INBOX {${a.length}+}\r\n${a} {0+}\r\n\r\n`);
    expect(out).toContain("NO");
    const { rows } = await ctx.db.query({ sql: "SELECT COUNT(*) AS n FROM messages", params: [] });
    expect(Number(rows[0]!.n)).toBe(0);
    await ctx.db.close();
  });

  test("없는 메일함이면 TRYCREATE", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const a = MSG("a");
    const out = await run(`p1 APPEND Nope {${a.length}+}\r\n${a} {${a.length}+}\r\n${a}\r\n`);
    expect(out).toContain("[TRYCREATE]");
    await ctx.db.close();
  });
});

describe("REPLACE (RFC 8508)", () => {
  /** 드래프트 수정 — 새 것이 들어오고 옛 것이 사라진다. */
  test("한 명령으로 바꾼다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const oldRaw = MSG("old");
    await run(`p1 APPEND INBOX {${oldRaw.length}+}\r\n${oldRaw}\r\n`);
    await run("s1 SELECT INBOX\r\n");

    const newRaw = MSG("new");
    const out = await run(`r1 REPLACE 1 INBOX {${newRaw.length}+}\r\n${newRaw}\r\n`);
    expect(out).toContain("OK [APPENDUID");
    expect(out).toContain("EXPUNGE");

    await run("s2 SELECT INBOX\r\n");
    const fetched = await run("f1 FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])\r\n");
    expect(fetched).toContain("new");
    expect(fetched).not.toContain("old");
    await ctx.db.close();
  });

  test("다른 메일함으로도 바꿀 수 있다", async () => {
    const ctx = await setup();
    await ctx.store.createMailbox({ accountId: ctx.accountId, name: "Sent" });
    const run = await session(ctx);
    const oldRaw = MSG("draft");
    await run(`p1 APPEND INBOX {${oldRaw.length}+}\r\n${oldRaw}\r\n`);
    await run("s1 SELECT INBOX\r\n");
    const newRaw = MSG("sent");
    expect(await run(`r1 REPLACE 1 Sent {${newRaw.length}+}\r\n${newRaw}\r\n`)).toContain("OK [APPENDUID");

    const { rows } = await ctx.db.query({
      sql: "SELECT COUNT(*) AS n FROM message_mailbox WHERE mailbox_id = ?",
      params: [ctx.mailboxId],
    });
    expect(Number(rows[0]!.n)).toBe(0); // INBOX는 비었다
    await ctx.db.close();
  });

  /**
   * ★**옛 것을 먼저 지우지 않는다**(§3의 핵심). 없는 메일함으로 REPLACE하면 넣기가
   * 실패하는데, 그때 옛 메시지가 **남아 있어야** 한다 — 아니면 메일이 사라진다.
   */
  test("넣기가 실패하면 옛 메시지가 남는다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const oldRaw = MSG("old");
    await run(`p1 APPEND INBOX {${oldRaw.length}+}\r\n${oldRaw}\r\n`);
    await run("s1 SELECT INBOX\r\n");

    const newRaw = MSG("new");
    expect(await run(`r1 REPLACE 1 Nope {${newRaw.length}+}\r\n${newRaw}\r\n`)).toContain("NO");

    const { rows } = await ctx.db.query({ sql: "SELECT COUNT(*) AS n FROM messages", params: [] });
    expect(Number(rows[0]!.n)).toBe(1); // 옛 것이 그대로다
    await ctx.db.close();
  });

  /** §3 — REPLACE는 **한 통**을 바꾼다. 집합을 허용하면 뜻이 없다. */
  test("여러 통을 지정하면 NO", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const raw = MSG("a");
    await run(`p1 APPEND INBOX {${raw.length}+}\r\n${raw}\r\n`);
    await run(`p2 APPEND INBOX {${raw.length}+}\r\n${raw}\r\n`);
    await run("s1 SELECT INBOX\r\n");
    expect(await run(`r1 REPLACE 1:2 INBOX {${raw.length}+}\r\n${raw}\r\n`)).toContain("NO");
    await ctx.db.close();
  });

  test("UID REPLACE도 된다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    const oldRaw = MSG("old");
    await run(`p1 APPEND INBOX {${oldRaw.length}+}\r\n${oldRaw}\r\n`);
    await run("s1 SELECT INBOX\r\n");
    const newRaw = MSG("new");
    expect(await run(`r1 UID REPLACE 1 INBOX {${newRaw.length}+}\r\n${newRaw}\r\n`)).toContain("OK [APPENDUID");
    await ctx.db.close();
  });

  test("CAPABILITY가 REPLACE를 광고한다", async () => {
    const ctx = await setup();
    const run = await session(ctx);
    expect(await run("c1 CAPABILITY\r\n")).toContain("REPLACE");
    await ctx.db.close();
  });
});
