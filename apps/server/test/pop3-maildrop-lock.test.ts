/**
 * IonospherePop3Backend × maildrop 락 주입 — "락이 프로세스를 넘어 성립하는가"를 고정한다.
 *
 * 배경: app.ts는 110용·995용 IonospherePop3Backend를 **각각** 만든다. 인프로세스 락은 인스턴스
 * 필드라 두 백엔드가 서로를 못 봤다 → 같은 계정이 110과 995로 동시에 열렸고, MRA를 2대로
 * 늘리면 같은 일이 프로세스 사이에서도 벌어진다. 그러면 세션 A가 QUIT하며 expunge한 메시지를
 * 세션 B가 RETR해 "message vanished"로 터진다.
 *
 * 지금 app.ts는 `DbMaildropLock` **하나를 두 리스너가 공유**한다(app.ts openStorage 참조).
 * 여기서는 그 구조를 백엔드 수준에서 고정한다 — DB 락을 공유하면 배타성이 성립하고,
 * 인프로세스 락으로 되돌리면 성립하지 않는다는 대조를 나란히 둔다.
 */
import { afterAll, beforeAll, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { noopLogger } from "@ionosphere/core";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { InProcessMaildropLock } from "@ionosphere/proto-pop3";
import { DbMaildropLock, FsBlobStore, Store } from "@ionosphere/store";
import { IonospherePop3Backend } from "../src/backend.ts";

let db: DbDriver;
let store: Store;
let blobs: FsBlobStore;
let root: string;
let accountId: string;

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), "pop3-lock-"));
  db = await openSqlite();
  await migrate(db, allMigrations);
  store = new Store(db);
  blobs = new FsBlobStore(root);
  const { tenantId } = await store.createTenant("acme");
  const created = await store.createAccount({ tenantId, email: "pop-lock@acme.test" });
  accountId = created.accountId;
});

afterAll(async () => {
  await db.close();
  rmSync(root, { recursive: true, force: true });
});

test("DB 락을 공유하면 백엔드 인스턴스가 달라도 두 번째 openMaildrop은 [IN-USE]", async () => {
  const lock = new DbMaildropLock(db);
  const backend110 = new IonospherePop3Backend(db, store, blobs, noopLogger, lock);
  const backend995 = new IonospherePop3Backend(db, store, blobs, noopLogger, lock);

  expect((await backend110.openMaildrop(accountId)).ok).toBe(true);
  expect(await backend995.openMaildrop(accountId)).toEqual({ ok: false, inUse: true });

  // 락을 못 잡은 세션이 끊기며 부르는 release는 **남의 락을 풀면 안 된다**(어댑터는 항상 부른다).
  await backend995.releaseMaildrop(accountId);
  expect(await backend995.openMaildrop(accountId)).toEqual({ ok: false, inUse: true });

  // 진짜 소유자가 놓으면 그때 열린다.
  await backend110.releaseMaildrop(accountId);
  expect((await backend995.openMaildrop(accountId)).ok).toBe(true);
  await backend995.releaseMaildrop(accountId);
});

test("인프로세스 락은 인스턴스마다 따로다 — DB 락이 필요한 이유(대조군)", async () => {
  const a = new IonospherePop3Backend(db, store, blobs, noopLogger, new InProcessMaildropLock());
  const b = new IonospherePop3Backend(db, store, blobs, noopLogger, new InProcessMaildropLock());

  expect((await a.openMaildrop(accountId)).ok).toBe(true);
  expect((await b.openMaildrop(accountId)).ok).toBe(true); // ← 배타성 없음(문서화된 한계)

  await a.releaseMaildrop(accountId);
  await b.releaseMaildrop(accountId);
});
