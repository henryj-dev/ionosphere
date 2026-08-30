import { createHash } from "node:crypto";
import { ulid } from "@ionosphere/core";
import type { DbDriver, Statement } from "@ionosphere/db";

// MySQL utf8mb4의 3072바이트 PK 한도 때문에 원문 키는 보존하고 PK에는 고정 길이 digest를 쓴다.
function externalKeyHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export interface DirectoryIdentitySync {
  externalKey: string;
  loginNames: readonly string[];
  email: string | null;
  displayName: string | null;
  accountId: string | null;
  groupExternalKeys: readonly string[];
}

export interface DirectoryGroupSync {
  externalKey: string;
  memberExternalKeys: readonly string[];
}

export interface DirectorySyncInput {
  tenantId: string;
  provider: string;
  now: number;
  identities: readonly DirectoryIdentitySync[];
  groups: readonly DirectoryGroupSync[];
}

/**
 * 디렉터리 snapshot을 한 배치로 반영한다. 외부 조회가 실패한 경우 호출하지 않으며,
 * snapshot에 없는 행을 지우지 않는 이유는 일시적인 LDAP 장애가 기존 권한을 삭제하면
 * 안 되기 때문이다. 변경된 계정의 permissions_version은 같은 원자 배치에서 올린다.
 */
export async function syncDirectorySnapshot(db: DbDriver, input: DirectorySyncInput): Promise<void> {
  if (!input.tenantId || !input.provider || !Number.isInteger(input.now)) throw new Error("directory sync 입력이 유효하지 않음");
  const statements: Statement[] = [];
  const affectedAccountIds = new Set<string>();
  const existingMemberships = await db.query({ sql: "SELECT DISTINCT am.account_id FROM account_memberships am JOIN accounts a ON a.id = am.account_id WHERE am.source = ? AND a.tenant_id = ?", params: ["directory", input.tenantId] });
  for (const row of existingMemberships.rows) affectedAccountIds.add(String(row.account_id));
  for (const identity of input.identities) if (identity.accountId) affectedAccountIds.add(identity.accountId);
  for (const accountId of affectedAccountIds) statements.push({ sql: "DELETE FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, "directory"] });
  statements.push({ sql: "DELETE FROM directory_group_members WHERE tenant_id = ? AND provider = ?", params: [input.tenantId, input.provider] });
  const groupKeys = [...new Set(input.identities.flatMap((identity) => identity.groupExternalKeys))];
  const groupPrincipalIds = new Map<string, string>();
  if (groupKeys.length > 0) {
    const existing = await db.query({ sql: `SELECT external_key, id FROM principals WHERE tenant_id = ? AND kind = 1 AND provider = ?`, params: [input.tenantId, input.provider] });
    for (const row of existing.rows) groupPrincipalIds.set(String(row.external_key), String(row.id));
  }

  for (const identity of input.identities) {
    const identityId = ulid();
    statements.push({
      sql: db.insertIgnore("directory_identities", ["id", "tenant_id", "provider", "external_key", "account_id", "login_names", "email", "display_name", "last_seen_at", "status"]).replace(/\?\)$/, "1)"),
      params: [identityId, input.tenantId, input.provider, identity.externalKey, identity.accountId, JSON.stringify(identity.loginNames), identity.email, identity.displayName, input.now],
    });
    statements.push({
      sql: `UPDATE directory_identities SET account_id = ?, login_names = ?, email = ?, display_name = ?, last_seen_at = ?, status = 1
        WHERE tenant_id = ? AND provider = ? AND external_key = ?`,
      params: [identity.accountId, JSON.stringify(identity.loginNames), identity.email, identity.displayName, input.now, input.tenantId, input.provider, identity.externalKey],
    });
    if (identity.accountId) {
      statements.push({
        sql: db.insertIgnore("principals", ["id", "tenant_id", "kind", "account_id", "provider", "external_key", "display_name", "created_at"]).replace("?, ?, ?,", "?, ?, 0,"),
        params: [ulid(), input.tenantId, identity.accountId, input.provider, identity.externalKey, identity.displayName, input.now],
      });
      statements.push({ sql: "UPDATE principals SET account_id = ?, display_name = ? WHERE tenant_id = ? AND kind = 0 AND provider = ? AND external_key = ?", params: [identity.accountId, identity.displayName, input.tenantId, input.provider, identity.externalKey] });
    }
    for (const groupExternalKey of identity.groupExternalKeys) {
      const groupPrincipalId = groupPrincipalIds.get(groupExternalKey) ?? ulid();
      groupPrincipalIds.set(groupExternalKey, groupPrincipalId);
      statements.push({
        sql: db.insertIgnore("principals", ["id", "tenant_id", "kind", "provider", "external_key", "display_name", "created_at"]).replace("?, ?, ?,", "?, ?, 1,"),
        params: [groupPrincipalId, input.tenantId, input.provider, groupExternalKey, groupExternalKey, input.now],
      });
      if (identity.accountId) {
        statements.push({
          sql: db.insertIgnore("account_memberships", ["account_id", "principal_id", "source", "created_at"]),
          params: [identity.accountId, groupPrincipalId, "directory", input.now],
        });
      }
    }
  }

  for (const group of input.groups) {
    for (const member of group.memberExternalKeys) {
      statements.push({
        sql: `${db.insertIgnore("directory_group_members", ["tenant_id", "provider", "group_external_key", "member_external_key", "group_external_hash", "member_external_hash", "last_seen_at"])}`,
        params: [input.tenantId, input.provider, group.externalKey, member, externalKeyHash(group.externalKey), externalKeyHash(member), input.now],
      });
      statements.push({ sql: "UPDATE directory_group_members SET last_seen_at = ? WHERE tenant_id = ? AND provider = ? AND group_external_key = ? AND member_external_key = ?", params: [input.now, input.tenantId, input.provider, group.externalKey, member] });
    }
  }

  for (const accountId of affectedAccountIds) {
    statements.push({ sql: "UPDATE accounts SET permissions_version = permissions_version + 1 WHERE id = ? AND tenant_id = ?", params: [accountId, input.tenantId] });
  }
  await db.batch(statements);
}
