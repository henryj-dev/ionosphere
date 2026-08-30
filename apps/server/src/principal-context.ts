import type { PrincipalContext } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";

/** 인증 주체의 tenant·local principal·group membership을 복원한다. */
export async function principalContext(db: DbDriver, accountId: string): Promise<PrincipalContext> {
  const account = await db.query({ sql: "SELECT tenant_id FROM accounts WHERE id = ? AND status = 1", params: [accountId] });
  const tenantId = String(account.rows[0]?.tenant_id ?? "");
  const principal = await db.query({ sql: "SELECT id FROM principals WHERE tenant_id = ? AND account_id = ?", params: [tenantId, accountId] });
  const memberships = await db.query({ sql: "SELECT principal_id FROM account_memberships WHERE account_id = ?", params: [accountId] });
  return {
    tenantId,
    principalId: String(principal.rows[0]?.id ?? accountId),
    primaryAccountId: accountId,
    accessibleAccountIds: [accountId],
    groupIds: memberships.rows.map((row) => String(row.principal_id)),
    authenticated: true,
  };
}
