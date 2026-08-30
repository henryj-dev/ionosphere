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
    await db.batch([
      { sql: "UPDATE accounts SET kind = 1 WHERE id = ?", params: [accountId] },
      { sql: "INSERT INTO principals (id, tenant_id, kind, account_id, created_at) VALUES (?, ?, ?, ?, ?)", params: ["principal-a", tenantId, PRINCIPAL_KIND.account, accountId, 1] },
      { sql: "INSERT INTO mailbox_acl (mailbox_id, principal_id, rights, negative, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)", params: [inboxId, "principal-a", "lr", 1, 1] },
    ]);
    const result = await authorizeMailbox(db, {
      tenantId,
      principalId: "principal-a",
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
});
