import { MAILBOX_OPERATION_RIGHT, PRINCIPAL_KIND, type MailboxOperation, type PrincipalContext, type StandardMailboxRight } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";

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
