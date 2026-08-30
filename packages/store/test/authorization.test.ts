import { describe, expect, test } from "@ionosphere/testkit";
import { PRINCIPAL_KIND } from "@ionosphere/core";
import { authorizeMailbox } from "../src/authorization.ts";
import { setupFixture } from "./helpers.ts";

describe("mailbox authorization", () => {
  test("테넌트 밖 mailboxId는 존재를 숨기고 거부한다", async () => {
    const a = await setupFixture();
    const b = await setupFixture();
    const result = await authorizeMailbox(a.db, {
      tenantId: a.tenantId,
      principalId: "principal-a",
      primaryAccountId: a.accountId,
      accessibleAccountIds: [a.accountId],
      groupIds: [],
      authenticated: true,
    }, b.inboxId, "read");
    expect(result.allowed).toBe(false);
    expect(result.accountId).toBe(null);
    await a.db.close();
    await b.db.close();
  });

  test("shared account는 ACL positive right이 있어야 읽을 수 있다", async () => {
    const { db, tenantId, accountId, inboxId } = await setupFixture();
    const { rows: principalRows } = await db.query({ sql: "SELECT id FROM principals WHERE account_id = ?", params: [accountId] });
    const principalId = String(principalRows[0]!.id);
    await db.batch([
      { sql: "UPDATE accounts SET kind = 1 WHERE id = ?", params: [accountId] },
      { sql: "INSERT INTO mailbox_acl (mailbox_id, principal_id, rights, negative, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)", params: [inboxId, principalId, "lr", 1, 1] },
    ]);
    const result = await authorizeMailbox(db, {
      tenantId,
      principalId,
      primaryAccountId: accountId,
      accessibleAccountIds: [accountId],
      groupIds: [],
      authenticated: true,
    }, inboxId, "read");
    expect(result.allowed).toBe(true);
    await db.close();
  });

  test("negative 예약 행은 권한을 열지 않고 fail closed 한다", async () => {
    const { db, tenantId, accountId, inboxId } = await setupFixture();
    await db.batch([
      { sql: "UPDATE accounts SET kind = 1 WHERE id = ?", params: [accountId] },
      { sql: "INSERT INTO principals (id, tenant_id, kind, created_at) VALUES (?, ?, ?, ?)", params: ["principal-a", tenantId, PRINCIPAL_KIND.anyone, 1] },
      { sql: "INSERT INTO mailbox_acl (mailbox_id, principal_id, rights, negative, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)", params: [inboxId, "principal-a", "lr", 1, 1] },
    ]);
    const result = await authorizeMailbox(db, {
      tenantId,
      principalId: "principal-x",
      primaryAccountId: "other",
      accessibleAccountIds: [],
      groupIds: [],
      authenticated: false,
    }, inboxId, "read");
    expect(result.allowed).toBe(false);
    await db.close();
  });

  test("namespace 목록은 같은 테넌트의 ACL 허용 mailbox만 반환한다", async () => {
    const { db, store, tenantId, accountId, inboxId } = await setupFixture();
    const second = await store.createAccount({ tenantId, email: "second@acme.test", kind: 1 });
    const { rows: principalRows } = await db.query({ sql: "SELECT id FROM principals WHERE account_id = ?", params: [accountId] });
    const principalId = String(principalRows[0]!.id);
    await db.batch([
      { sql: "UPDATE accounts SET kind = 1 WHERE id = ?", params: [accountId] },
      { sql: "UPDATE accounts SET kind = 1 WHERE id = ?", params: [second.accountId] },
      { sql: "INSERT INTO mailbox_acl (mailbox_id, principal_id, rights, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", params: [inboxId, principalId, "l", 1, 1] },
    ]);
    const rows = await store.listAccessibleMailboxes({
      tenantId,
      principalId,
      primaryAccountId: accountId,
      accessibleAccountIds: [accountId],
      groupIds: [],
      authenticated: true,
    });
    expect(rows.map((row) => row.id)).toEqual([inboxId]);
    expect(rows.some((row) => row.accountId === second.accountId)).toBe(false);
    await db.close();
  });

  test("ACL CRUD는 canonical right과 acl_version을 함께 갱신한다", async () => {
    const { db, store, tenantId, accountId, inboxId } = await setupFixture();
    const { rows } = await db.query({ sql: "SELECT id FROM principals WHERE account_id = ?", params: [accountId] });
    const principalId = String(rows[0]!.id);
    await store.setMailboxAcl(tenantId, inboxId, principalId, "lrcd");
    const acl = await store.getMailboxAcl(tenantId, inboxId);
    expect(acl[0]?.rights).toBe("lrkxte");
    expect(acl[0]?.negative).toBe(false);
    expect(await store.deleteMailboxAcl(tenantId, inboxId, principalId)).toBe(true);
    expect(await store.getMailboxAcl(tenantId, inboxId)).toEqual([]);
    const version = await db.query({ sql: "SELECT acl_version FROM mailboxes WHERE id = ?", params: [inboxId] });
    expect(Number(version.rows[0]?.acl_version)).toBe(2);
    await db.close();
  });

  test("JMAP 계정 목록은 ACL로 보이는 shared account만 포함한다", async () => {
    const { db, store, tenantId, accountId, inboxId } = await setupFixture();
    const shared = await store.createAccount({ tenantId, email: "shared@acme.test", kind: 1 });
    const { rows: principalRows } = await db.query({ sql: "SELECT id FROM principals WHERE account_id = ?", params: [accountId] });
    const { rows: sharedMailboxRows } = await db.query({ sql: "SELECT id FROM mailboxes WHERE account_id = ?", params: [shared.accountId] });
    await store.setMailboxAcl(tenantId, String(sharedMailboxRows[0]!.id), String(principalRows[0]!.id), "l");
    const accounts = await store.listAccessibleAccounts({
      tenantId,
      principalId: String(principalRows[0]!.id),
      primaryAccountId: accountId,
      accessibleAccountIds: [accountId],
      groupIds: [],
      authenticated: true,
    });
    expect(accounts.map((account) => account.id)).toEqual([accountId, shared.accountId]);
    expect(accounts.find((account) => account.id === shared.accountId)?.kind).toBe(1);
    expect(inboxId).toBeTruthy();
    await db.close();
  });
});
