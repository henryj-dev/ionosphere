import { MAILBOX_OPERATION_RIGHT, PRINCIPAL_KIND, formatMailboxRights, parseMailboxRights, type MailboxOperation, type PrincipalContext, type StandardMailboxRight } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { StoreError } from "./errors.ts";

export type MailboxAclRow = {
  mailboxId: string;
  principalId: string;
  principalKind: number;
  displayName: string | null;
  rights: string;
  negative: boolean;
};

/** 권한 판정 결과. 메일함 존재 여부는 호출자에게 노출하지 않는다. */
export type MailboxAuthorization = {
  allowed: boolean;
  mailboxId: string;
  accountId: string | null;
  right: StandardMailboxRight;
};

function principalIds(context: PrincipalContext): readonly string[] {
  const ids = new Set<string>([context.principalId, ...context.groupIds]);
  return [...ids];
}

/**
 * 한 번의 스냅샷 조회로 mailbox ACL을 계산한다.
 *
 * 개인 메일함은 기존 API와의 호환을 위해 소유 계정이 전권을 갖지만, shared
 * 계정은 ACL 행 없이는 열지 않는다. ACL의 negative 값은 아직 지원하지 않으므로
 * 하나라도 보이면 fail closed 한다(부분 구현이 거부를 허용으로 바꾸지 않게).
 */
export async function authorizeMailbox(
  db: DbDriver,
  context: PrincipalContext,
  mailboxId: string,
  operation: MailboxOperation,
): Promise<MailboxAuthorization> {
  const right = MAILBOX_OPERATION_RIGHT[operation];
  const mailbox = await db.query({
    sql: `SELECT m.id, m.account_id, a.tenant_id, a.kind
          FROM mailboxes m JOIN accounts a ON a.id = m.account_id
          WHERE m.id = ? AND a.tenant_id = ? AND m.status = 1 AND a.status = 1`,
    params: [mailboxId, context.tenantId],
  });
  const row = mailbox.rows[0];
  if (!row) return { allowed: false, mailboxId, accountId: null, right };

  const accountId = String(row.account_id);
  if (Number(row.kind) === 0 && context.accessibleAccountIds.includes(accountId)) {
    return { allowed: true, mailboxId, accountId, right };
  }

  const ids = principalIds(context);
  const acl = await db.query({
    sql: `SELECT acl.principal_id, p.kind, acl.rights, acl.negative
          FROM mailbox_acl acl JOIN principals p ON p.id = acl.principal_id
          WHERE acl.mailbox_id = ? AND p.tenant_id = ?`,
    params: [mailboxId, context.tenantId],
  });
  let granted = false;
  for (const aclRow of acl.rows) {
    const kind = Number(aclRow.kind);
    const principalMatches = ids.includes(String(aclRow.principal_id));
    const specialMatches = kind === PRINCIPAL_KIND.anyone || (context.authenticated && kind === PRINCIPAL_KIND.authenticated);
    if (!principalMatches && !specialMatches) continue;
    if (Number(aclRow.negative) !== 0) return { allowed: false, mailboxId, accountId, right };
    if (String(aclRow.rights).includes(right)) granted = true;
  }
  return { allowed: granted, mailboxId, accountId, right };
}

/** 테넌트 경계 안의 ACL을 반환한다. 없는 mailbox는 빈 목록으로 은닉한다. */
export async function getMailboxAcl(db: DbDriver, tenantId: string, mailboxId: string): Promise<MailboxAclRow[]> {
  const { rows } = await db.query({
    sql: `SELECT acl.mailbox_id, acl.principal_id, p.kind, p.display_name, acl.rights, acl.negative
          FROM mailbox_acl acl JOIN principals p ON p.id = acl.principal_id
          JOIN mailboxes m ON m.id = acl.mailbox_id JOIN accounts a ON a.id = m.account_id
          WHERE acl.mailbox_id = ? AND a.tenant_id = ? ORDER BY acl.principal_id`,
    params: [mailboxId, tenantId],
  });
  return rows.map((row) => ({
    mailboxId: String(row.mailbox_id),
    principalId: String(row.principal_id),
    principalKind: Number(row.kind),
    displayName: row.display_name == null ? null : String(row.display_name),
    rights: String(row.rights),
    negative: Number(row.negative) !== 0,
  }));
}

/** ACL 한 행과 acl_version을 하나의 원자 배치로 갱신한다. */
export async function setMailboxAcl(db: DbDriver, tenantId: string, mailboxId: string, principalId: string, rights: string, now = Date.now()): Promise<void> {
  const parsed = [...parseMailboxRights(rights)];
  const canonical = formatMailboxRights(parsed, false);
  const scope = await db.query({
    sql: `SELECT 1 AS ok FROM mailboxes m JOIN accounts a ON a.id = m.account_id
          JOIN principals p ON p.tenant_id = a.tenant_id WHERE m.id = ? AND a.tenant_id = ? AND p.id = ?`,
    params: [mailboxId, tenantId, principalId],
  });
  if (scope.rows.length === 0) throw new StoreError("ACL scope not found");
  await db.batch([
    { sql: db.insertIgnore("mailbox_acl", ["mailbox_id", "principal_id", "rights", "negative", "created_at", "updated_at"]), params: [mailboxId, principalId, canonical, 0, now, now] },
    { sql: "UPDATE mailbox_acl SET rights = ?, negative = 0, updated_at = ? WHERE mailbox_id = ? AND principal_id = ?", params: [canonical, now, mailboxId, principalId] },
    { sql: "UPDATE mailboxes SET acl_version = acl_version + 1 WHERE id = ?", params: [mailboxId] },
    { sql: "UPDATE accounts SET permissions_version = permissions_version + 1 WHERE id = (SELECT account_id FROM mailboxes WHERE id = ?)", params: [mailboxId] },
  ]);
}

/** ACL 삭제와 version 증가를 같은 배치에 넣는다. */
export async function deleteMailboxAcl(db: DbDriver, tenantId: string, mailboxId: string, principalId: string): Promise<boolean> {
  const scope = await db.query({
    sql: "SELECT 1 AS ok FROM mailbox_acl acl JOIN mailboxes m ON m.id = acl.mailbox_id JOIN accounts a ON a.id = m.account_id WHERE acl.mailbox_id = ? AND acl.principal_id = ? AND a.tenant_id = ?",
    params: [mailboxId, principalId, tenantId],
  });
  if (scope.rows.length === 0) return false;
  await db.batch([
    { sql: "DELETE FROM mailbox_acl WHERE mailbox_id = ? AND principal_id = ?", params: [mailboxId, principalId] },
    { sql: "UPDATE mailboxes SET acl_version = acl_version + 1 WHERE id = ?", params: [mailboxId] },
    { sql: "UPDATE accounts SET permissions_version = permissions_version + 1 WHERE id = (SELECT account_id FROM mailboxes WHERE id = ?)", params: [mailboxId] },
  ]);
  return true;
}
