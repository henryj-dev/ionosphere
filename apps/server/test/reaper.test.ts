/** MailboxReaper 워커 — tick이 툼스톤 메일함을 수거. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ACCOUNT_STATUS, allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { Store } from "@ionosphere/store";
import { MailboxReaper } from "../src/reaper.ts";

async function freshStore() {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  return { db, store: new Store(db) };
}

describe("MailboxReaper.tick", () => {
  test("툼스톤 메일함을 수거하고 개수 반환", async () => {
    const { db, store } = await freshStore();
    const { tenantId } = await store.createTenant("t");
    const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
    const { mailboxId } = await store.createMailbox({ accountId, name: "Junk" });
    await store.deleteMailbox({ accountId, mailboxId });

    const reaper = new MailboxReaper({ store });
    expect(await reaper.tick()).toBe(1);
    // 수거 후 재실행은 0
    expect(await reaper.tick()).toBe(0);
    const { rows } = await db.query({ sql: "SELECT 1 FROM mailboxes WHERE id = ?", params: [mailboxId] });
    expect(rows.length).toBe(0);
    await db.close();
  });

  test("툼스톤 없으면 0(무해)", async () => {
    const { db, store } = await freshStore();
    const reaper = new MailboxReaper({ store });
    expect(await reaper.tick()).toBe(0);
    await db.close();
  });

  test("accountDrain을 주면 삭제 중인 계정을 드레인해 계정 행까지 없앤다(SCHEMA §7-7)", async () => {
    const { db, store } = await freshStore();
    const { tenantId } = await store.createTenant("t");
    const { accountId } = await store.createAccount({ tenantId, email: "gone@x.test" });
    await db.batch([{ sql: "UPDATE accounts SET status = ?, deleting_since = ? WHERE id = ?", params: [ACCOUNT_STATUS.deleting, Date.now() - 10 * 60_000, accountId] }]);

    // 옵션 없이는 돌지 않는다 — 조립층이 켠다
    await new MailboxReaper({ store }).tick();
    expect((await db.query({ sql: "SELECT 1 FROM accounts WHERE id = ?", params: [accountId] })).rows.length).toBe(1);

    await new MailboxReaper({ store, accountDrain: { db } }).tick();
    expect((await db.query({ sql: "SELECT 1 FROM accounts WHERE id = ?", params: [accountId] })).rows.length).toBe(0);
    await db.close();
  });
});
