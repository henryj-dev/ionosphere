import { createHash } from "node:crypto";
import { ulid, type DirectorySnapshot } from "@ionosphere/core";
import { ACCOUNT_STATUS, type DbDriver, type Statement } from "@ionosphere/db";

// MySQL utf8mb4의 3072바이트 PK 한도 때문에 원문 키는 보존하고 PK에는 고정 길이 digest를 쓴다.
function externalKeyHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** VARCHAR(32) 안에서 provider별로 충돌하지 않는 132-bit 안정 source를 만든다. */
export function directoryMembershipSource(provider: string): string {
  if (!provider || provider.length > 32) throw new Error("directory provider는 1~32자");
  return `directory:${createHash("sha256").update(provider, "utf8").digest("base64url").slice(0, 22)}`;
}

export interface DirectoryIdentitySync {
  externalKey: string;
  loginNames: readonly string[];
  email: string | null;
  displayName: string | null;
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
 * 외부 snapshot에는 로컬 account id를 섞지 않는다. 연결은 `directory-identity-link`만 바꾸고,
 * sync는 배치가 실행되는 순간 DB의 현재 연결을 읽는다. 예전에는 여기서 account_id를 미리 읽어
 * input에 넣었고, 그 뒤 관리자가 해제해도 오래된 input이 연결·그룹 권한을 되살렸다(2026-10-19 리뷰).
 */
export function directorySyncInputFromSnapshot(
  input: { tenantId: string; provider: string; now: number; snapshot: DirectorySnapshot },
): DirectorySyncInput {
  return {
    tenantId: input.tenantId,
    provider: input.provider,
    now: input.now,
    identities: input.snapshot.identities.map((identity) => ({ ...identity })),
    groups: input.snapshot.groups.map((group) => ({ externalKey: group.externalKey, memberExternalKeys: group.memberExternalKeys })),
  };
}

/**
 * `insertIgnore()`의 VALUES 자리에 조건부 SELECT를 넣는다. 네 방언 모두 같은 골격이다:
 * SQLite/D1 `INSERT OR IGNORE`, PG `… ON CONFLICT DO NOTHING`, MySQL `INSERT IGNORE`.
 *
 * 왜: account id를 배치 전에 읽어 VALUES로 넣으면 그 사이의 해제·삭제를 되돌린다. SELECT가 배치 시점의
 * `directory_identities`와 `accounts.status`를 다시 봐야 한다. 별도 다이얼렉트 분기는 만들지 않는다.
 */
function insertIgnoreSelect(
  db: DbDriver,
  table: string,
  columns: readonly string[],
  select: string,
  params: readonly unknown[],
): Statement {
  const marker = `VALUES (${columns.map(() => "?").join(", ")})`;
  const base = db.insertIgnore(table, columns);
  if (!base.includes(marker)) throw new Error(`insertIgnore SELECT 변환 실패: ${table}`);
  return { sql: base.replace(marker, select), params };
}

/**
 * 디렉터리 snapshot을 한 배치로 반영한다. 외부 조회가 실패한 경우 호출하지 않으며,
 * snapshot에 없는 행을 지우지 않는 이유는 일시적인 LDAP 장애가 기존 identity를 삭제하면 안 되기 때문이다.
 *
 * ★연결(account_id)은 절대 쓰지 않는다. metadata만 갱신하고 principal·membership은 이 배치 시점의 현재 연결에서
 * 조건부 SELECT로 만든다. 그래서 sync 입력을 만든 뒤 unlink/account-delete가 끼어도 연결과 권한이 되살아나지 않는다.
 */
export async function syncDirectorySnapshot(db: DbDriver, input: DirectorySyncInput): Promise<void> {
  if (!input.tenantId || !input.provider || !Number.isInteger(input.now)) throw new Error("directory sync 입력이 유효하지 않음");
  const membershipSource = directoryMembershipSource(input.provider);
  const statements: Statement[] = [];
  const affectedAccountIds = new Set<string>();

  // legacy source="directory"도 principal.provider로 범위를 좁혀 이 provider의 첫 동기화에서만 회수한다.
  const existingMemberships = await db.query({
    sql: `SELECT am.account_id, am.principal_id FROM account_memberships am
      JOIN accounts a ON a.id = am.account_id JOIN principals p ON p.id = am.principal_id
      WHERE a.tenant_id = ? AND p.provider = ? AND (am.source = ? OR am.source = ?)`,
    params: [input.tenantId, input.provider, "directory", membershipSource],
  });
  for (const row of existingMemberships.rows) {
    affectedAccountIds.add(String(row.account_id));
    statements.push({ sql: "DELETE FROM account_memberships WHERE account_id = ? AND principal_id = ?", params: [row.account_id, row.principal_id] });
  }
  const linkedAccounts = await db.query({
    sql: `SELECT d.account_id FROM directory_identities d JOIN accounts a ON a.id = d.account_id
           WHERE d.tenant_id = ? AND d.provider = ? AND d.account_id IS NOT NULL AND a.status != ${ACCOUNT_STATUS.deleting}`,
    params: [input.tenantId, input.provider],
  });
  for (const row of linkedAccounts.rows) affectedAccountIds.add(String(row.account_id));

  statements.push({ sql: "DELETE FROM directory_group_members WHERE tenant_id = ? AND provider = ?", params: [input.tenantId, input.provider] });
  const groupKeys = [...new Set(input.identities.flatMap((identity) => identity.groupExternalKeys))];
  const groupPrincipalIds = new Map<string, string>();
  if (groupKeys.length > 0) {
    const existing = await db.query({
      sql: "SELECT external_key, id FROM principals WHERE tenant_id = ? AND kind = 1 AND provider = ?",
      params: [input.tenantId, input.provider],
    });
    for (const row of existing.rows) groupPrincipalIds.set(String(row.external_key), String(row.id));
  }

  for (const identity of input.identities) {
    const identityId = ulid();
    // 새 identity는 무조건 연결 없음(NULL)으로 만든다. 연결은 관리 명령만 할 수 있다.
    statements.push({
      sql: db.insertIgnore("directory_identities", ["id", "tenant_id", "provider", "external_key", "account_id", "login_names", "email", "display_name", "last_seen_at", "status"]),
      params: [identityId, input.tenantId, input.provider, identity.externalKey, null, JSON.stringify(identity.loginNames), identity.email, identity.displayName, input.now, 1],
    });
    statements.push({
      sql: `UPDATE directory_identities SET login_names = ?, email = ?, display_name = ?, last_seen_at = ?, status = 1
             WHERE tenant_id = ? AND provider = ? AND external_key = ?`,
      params: [JSON.stringify(identity.loginNames), identity.email, identity.displayName, input.now, input.tenantId, input.provider, identity.externalKey],
    });

    /**
     * identity principal은 외부 주체 자체라 account_id를 갖지 않는다. 계정은 이미 `local` principal 하나가
     * `(tenant_id, account_id)` 유니크를 차지한다. 여기서 account_id를 넣으면 그 제약과 충돌하고, 해제 뒤
     * 오래된 sync가 계정 연결을 되살릴 수도 있다. 계정의 디렉터리 권한은 아래 그룹 membership이 맡는다.
     */
    statements.push({
      sql: db.insertIgnore("principals", ["id", "tenant_id", "kind", "provider", "external_key", "display_name", "created_at"]),
      params: [ulid(), input.tenantId, 0, input.provider, identity.externalKey, identity.displayName, input.now],
    });
    statements.push({
      sql: "UPDATE principals SET display_name = ? WHERE tenant_id = ? AND kind = 0 AND provider = ? AND external_key = ?",
      params: [identity.displayName, input.tenantId, input.provider, identity.externalKey],
    });

    for (const groupExternalKey of new Set(identity.groupExternalKeys)) {
      const groupPrincipalId = groupPrincipalIds.get(groupExternalKey) ?? ulid();
      groupPrincipalIds.set(groupExternalKey, groupPrincipalId);
      statements.push({
        sql: db.insertIgnore("principals", ["id", "tenant_id", "kind", "provider", "external_key", "display_name", "created_at"]),
        params: [groupPrincipalId, input.tenantId, 1, input.provider, groupExternalKey, groupExternalKey, input.now],
      });
      statements.push(
        insertIgnoreSelect(
          db,
          "account_memberships",
          ["account_id", "principal_id", "source", "created_at"],
          `SELECT d.account_id, ?, ?, ? FROM directory_identities d JOIN accounts a ON a.id = d.account_id
            WHERE d.tenant_id = ? AND d.provider = ? AND d.external_key = ? AND d.account_id IS NOT NULL
              AND a.status != ${ACCOUNT_STATUS.deleting}`,
          [groupPrincipalId, membershipSource, input.now, input.tenantId, input.provider, identity.externalKey],
        ),
      );
    }
  }

  for (const group of input.groups) {
    for (const member of group.memberExternalKeys) {
      statements.push({
        sql: db.insertIgnore("directory_group_members", ["tenant_id", "provider", "group_external_key", "member_external_key", "group_external_hash", "member_external_hash", "last_seen_at"]),
        params: [input.tenantId, input.provider, group.externalKey, member, externalKeyHash(group.externalKey), externalKeyHash(member), input.now],
      });
      statements.push({
        sql: "UPDATE directory_group_members SET last_seen_at = ? WHERE tenant_id = ? AND provider = ? AND group_external_key = ? AND member_external_key = ?",
        params: [input.now, input.tenantId, input.provider, group.externalKey, member],
      });
    }
  }

  // 사전 조회 뒤 새로 연결된 계정도 이 snapshot으로 membership이 생기므로, 배치 시점의 현재 연결을 다시 보고 버전을 올린다.
  statements.push({
    sql: `UPDATE accounts SET permissions_version = permissions_version + 1
           WHERE tenant_id = ? AND status != ${ACCOUNT_STATUS.deleting}
             AND id IN (SELECT account_id FROM directory_identities
                         WHERE tenant_id = ? AND provider = ? AND account_id IS NOT NULL)`,
    params: [input.tenantId, input.tenantId, input.provider],
  });
  // 반대로 사전 조회 뒤 해제된 계정은 membership 삭제를 캐시에 반영해야 하므로 개별 버전도 올린다.
  for (const accountId of affectedAccountIds) {
    statements.push({
      sql: `UPDATE accounts SET permissions_version = permissions_version + 1
             WHERE id = ? AND tenant_id = ? AND status != ${ACCOUNT_STATUS.deleting}
               AND id NOT IN (SELECT account_id FROM directory_identities
                               WHERE tenant_id = ? AND provider = ? AND account_id IS NOT NULL)`,
      params: [accountId, input.tenantId, input.tenantId, input.provider],
    });
  }
  await db.batch(statements);
}
