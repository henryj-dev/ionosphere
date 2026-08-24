/**
 * 대형 메일함 회귀 — `IN (…)` 파라미터 한도.
 *
 * `store/chunk.ts`가 문장당 파라미터 100개(D1 최소공통분모)를 정해 뒀는데, **쓰기 경로만**
 * 그 규율을 지켰다. `db.query()`로 가는 읽기 질의는 `uids.map(() => "?")`로 손수 조립돼
 * 개수 제한이 없었고, `UID FETCH 1:*`이 메일함 메시지 수만큼 파라미터를 만들었다:
 *   · D1  — 100개 초과 시 실패. **메시지 100통 넘는 메일함에서 IMAP이 통째로 깨진다**
 *   · PG  — 바인드 메시지 파라미터 수가 int16이라 65535개가 상한
 *
 * 여기서는 SQLite로 돌지만(라이브 기본), 검증하는 것은 **파라미터 수가 한도 안에 머무는가**다.
 * 그래서 드라이버를 감싸 문장별 파라미터 수를 실제로 세어 본다 — 방언을 바꾸지 않고도
 * D1에서 깨질 질의를 여기서 잡는다.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver, type Statement } from "@ionosphere/db";
import { FsBlobStore, putBlob, Store } from "@ionosphere/store";
import { IonosphereImapBackend } from "../src/imap-backend.ts";

/** D1 한도(SCHEMA §1-3). `store/chunk.ts MAX_PARAMS_PER_STATEMENT`와 같은 값이어야 한다. */
const D1_PARAM_LIMIT = 100;

/** 문장별 최대 파라미터 수를 기록하는 드라이버 래퍼. */
function countingDriver(inner: DbDriver): { db: DbDriver; worst: () => number } {
  let worst = 0;
  const note = (stmt: Statement): void => {
    worst = Math.max(worst, (stmt.params ?? []).length);
  };
  const db: DbDriver = {
    dialect: inner.dialect,
    query: (stmt) => {
      note(stmt);
      return inner.query(stmt);
    },
    batch: (stmts) => {
      for (const s of stmts) note(s);
      return inner.batch(stmts);
    },
    insertIgnore: (t, c) => inner.insertIgnore(t, c),
    close: () => inner.close(),
  };
  return { db, worst: () => worst };
}

const MESSAGES = 250; // D1 한도(100)를 확실히 넘기는 수

async function setup(): Promise<{
  db: DbDriver;
  backend: IonosphereImapBackend;
  accountId: string;
  worst: () => number;
}> {
  const raw = await openSqlite(":memory:");
  await migrate(raw, allMigrations);
  const { db, worst } = countingDriver(raw);
  const store = new Store(db);
  const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-big-")));
  const { tenantId } = await store.createTenant("t");
  const { accountId, mailboxId } = await store.createAccount({ tenantId, email: "a@x.test" });

  for (let i = 0; i < MESSAGES; i++) {
    const bytes = new Uint8Array(Buffer.from(`From: s@x.test\r\nSubject: m${i}\r\n\r\nbody ${i}\r\n`));
    const { blobId, size, generation } = await putBlob(db, blobs, bytes);
    await store.appendMessage({
      accountId,
      mailboxIds: [mailboxId],
      blobId,
      blobGeneration: generation,
      sizeBytes: size,
      receivedAt: Date.now() + i,
      envelope: {
        subject: `m${i}`,
        subjectBase: `m${i}`,
        msgidHash: null,
        sentAt: null,
        preview: null,
        hasAttachment: false,
        addresses: [],
        threadRefHashes: [],
      },
      keywords: [],
    });
  }
  return { db, backend: new IonosphereImapBackend(db, store, blobs), accountId, worst };
}

async function allUids(db: DbDriver): Promise<number[]> {
  const { rows } = await db.query({ sql: "SELECT uid FROM message_mailbox ORDER BY uid", params: [] });
  return rows.map((r) => Number(r.uid));
}

describe(`대형 메일함(${MESSAGES}통) — 파라미터 한도`, () => {
  test("UID FETCH 1:* 이 한도를 넘지 않는다", async () => {
    const { db, backend, accountId, worst } = await setup();
    const uids = await allUids(db);
    expect(uids).toHaveLength(MESSAGES);

    const res = await backend.request(accountId, {
      kind: "fetchMessages",
      name: "INBOX",
      uids,
      needRaw: false,
      markSeen: false,
    });
    expect(res.kind).toBe("messages");
    if (res.kind === "messages") {
      expect(res.messages).toHaveLength(MESSAGES);
      // 순서가 유지돼야 한다 — 청크마다 정렬되므로 합친 뒤 다시 정렬한다.
      expect(res.messages[0]!.uid).toBe(uids[0]!);
      expect(res.messages[MESSAGES - 1]!.uid).toBe(uids[MESSAGES - 1]!);
    }
    expect(worst() <= D1_PARAM_LIMIT).toBe(true);
    await db.close();
  });

  test("UID STORE 1:* +FLAGS 가 한도를 넘지 않는다", async () => {
    const { db, backend, accountId, worst } = await setup();
    const uids = await allUids(db);

    const res = await backend.request(accountId, {
      kind: "storeFlags",
      name: "INBOX",
      uids,
      mode: "add",
      flags: ["\\Seen"],
    });
    expect(res.kind).toBe("flagsUpdated");
    if (res.kind === "flagsUpdated") expect(res.updated).toHaveLength(MESSAGES);
    expect(worst() <= D1_PARAM_LIMIT).toBe(true);
    await db.close();
  });

  test("UID COPY 1:* 가 한도를 넘지 않는다", async () => {
    const { db, backend, accountId, worst } = await setup();
    const uids = await allUids(db);
    expect((await backend.request(accountId, { kind: "createMailbox", name: "Archive" })).kind).toBe("ok");

    const res = await backend.request(accountId, { kind: "copyMessages", from: "INBOX", to: "Archive", uids });
    expect(res.kind).toBe("copied");
    if (res.kind === "copied") expect(res.srcUids).toHaveLength(MESSAGES);
    expect(worst() <= D1_PARAM_LIMIT).toBe(true);
    await db.close();
  });

  test("EXPUNGE 1:* 가 한도를 넘지 않는다", async () => {
    const { db, backend, accountId, worst } = await setup();
    const uids = await allUids(db);
    await backend.request(accountId, { kind: "storeFlags", name: "INBOX", uids, mode: "add", flags: ["\\Deleted"] });

    const res = await backend.request(accountId, { kind: "expunge", name: "INBOX", uids });
    expect(res.kind).toBe("expunged");
    if (res.kind === "expunged") expect(res.uids).toHaveLength(MESSAGES);
    expect(worst() <= D1_PARAM_LIMIT).toBe(true);
    await db.close();
  });
});
