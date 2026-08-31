import { describe, expect, test } from "@ionosphere/testkit";
import { directoryMembershipSource, directorySyncInputFromSnapshot, syncDirectorySnapshot } from "../src/directory-sync.ts";
import { setupFixture } from "./helpers.ts";

describe("directory sync", () => {
  test("snapshot 반영과 permissions_version 증가는 한 배치로 성공한다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const before = await db.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: [accountId] });
    await syncDirectorySnapshot(db, {
      tenantId,
      provider: "ad",
      now: 100,
      identities: [{ externalKey: "guid:abc", loginNames: ["user@ionosphere.test"], email: "user@ionosphere.test", displayName: "User", accountId, groupExternalKeys: ["guid:group"] }],
      groups: [{ externalKey: "guid:group", memberExternalKeys: ["guid:abc"] }],
    });
    const identity = await db.query({ sql: "SELECT account_id, external_key FROM directory_identities WHERE tenant_id = ? AND provider = ?", params: [tenantId, "ad"] });
    const membership = await db.query({ sql: "SELECT source FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource("ad")] });
    const after = await db.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: [accountId] });
    expect(identity.rows[0]?.external_key).toBe("guid:abc");
    expect(identity.rows[0]?.account_id).toBe(accountId);
    expect(membership.rows.length).toBe(1);
    expect(Number(after.rows[0]?.permissions_version)).toBe(Number(before.rows[0]?.permissions_version) + 1);
    await db.close();
  });

  test("같은 snapshot 재적용은 identity와 membership을 중복 생성하지 않는다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const input = { tenantId, provider: "ldap", now: 200, identities: [{ externalKey: "sid:1", loginNames: ["user"], email: null, displayName: null, accountId, groupExternalKeys: ["sid:g"] }], groups: [] } as const;
    await syncDirectorySnapshot(db, input);
    await syncDirectorySnapshot(db, { ...input, now: 201 });
    const count = await db.query({ sql: "SELECT COUNT(*) AS count FROM directory_identities WHERE tenant_id = ?", params: [tenantId] });
    const memberships = await db.query({ sql: "SELECT COUNT(*) AS count FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource("ldap")] });
    expect(Number(count.rows[0]?.count)).toBe(1);
    expect(Number(memberships.rows[0]?.count)).toBe(1);
    await db.close();
  });

  test("완전 snapshot에서 그룹 제거가 membership과 권한 버전을 함께 갱신한다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const input = { tenantId, provider: "ad", now: 300, identities: [{ externalKey: "guid:2", loginNames: ["two"], email: null, displayName: null, accountId, groupExternalKeys: ["guid:g"] }], groups: [] } as const;
    await syncDirectorySnapshot(db, input);
    const before = await db.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: [accountId] });
    await syncDirectorySnapshot(db, { ...input, now: 301, identities: [{ ...input.identities[0], groupExternalKeys: [] }] });
    const memberships = await db.query({ sql: "SELECT COUNT(*) AS count FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource("ad")] });
    const after = await db.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: [accountId] });
    expect(Number(memberships.rows[0]?.count)).toBe(0);
    expect(Number(after.rows[0]?.permissions_version)).toBe(Number(before.rows[0]?.permissions_version) + 1);
    await db.close();
  });

  test("provider별 source는 32자 안정 문자열이고 한 provider 동기화가 다른 membership을 지우지 않는다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const identity = (provider: string, group: string) => ({ tenantId, provider, now: 400, identities: [{ externalKey: `${provider}:user`, loginNames: ["user"], email: null, displayName: null, accountId, groupExternalKeys: [group] }], groups: [] });
    await syncDirectorySnapshot(db, identity("ad-east", "ad-east:group"));
    await syncDirectorySnapshot(db, identity("ldap-west", "ldap-west:group"));
    const eastSource = directoryMembershipSource("ad-east");
    const westSource = directoryMembershipSource("ldap-west");
    expect(eastSource.length).toBe(32);
    expect(eastSource).toBe(directoryMembershipSource("ad-east"));
    expect(eastSource === westSource).toBe(false);

    await syncDirectorySnapshot(db, { ...identity("ad-east", "ad-east:group"), now: 401, identities: [{ ...identity("ad-east", "ad-east:group").identities[0]!, groupExternalKeys: [] }] });
    const rows = await db.query({ sql: "SELECT source FROM account_memberships WHERE account_id = ? ORDER BY source", params: [accountId] });
    expect(rows.rows.map((row) => String(row.source))).toEqual([westSource]);
    await db.close();
  });

  test("legacy directory source는 같은 provider principal만 회수한다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const first = { tenantId, provider: "legacy-ad", now: 500, identities: [{ externalKey: "legacy:user", loginNames: ["user"], email: null, displayName: null, accountId, groupExternalKeys: ["legacy:group"] }], groups: [] } as const;
    await syncDirectorySnapshot(db, first);
    await db.batch([{ sql: "UPDATE account_memberships SET source = ? WHERE account_id = ?", params: ["directory", accountId] }]);
    await syncDirectorySnapshot(db, { ...first, now: 501, identities: [{ ...first.identities[0], groupExternalKeys: [] }] });
    const rows = await db.query({ sql: "SELECT source FROM account_memberships WHERE account_id = ?", params: [accountId] });
    expect(rows.rows).toEqual([]);
    await db.close();
  });

  test("snapshot 변환은 기존 externalKey의 accountId만 유지하고 새 identity를 자동 연결하지 않는다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    await syncDirectorySnapshot(db, { tenantId, provider: "ad", now: 600, identities: [{ externalKey: "guid:known", loginNames: ["old"], email: null, displayName: null, accountId, groupExternalKeys: [] }], groups: [] });
    const converted = await directorySyncInputFromSnapshot(db, {
      tenantId,
      provider: "ad",
      now: 601,
      snapshot: {
        identities: [
          { externalKey: "guid:known", loginNames: ["new"], email: "new@ionosphere.test", displayName: "Known", groupExternalKeys: ["guid:group"] },
          { externalKey: "guid:new", loginNames: ["other"], email: null, displayName: null, groupExternalKeys: [] },
        ],
        groups: [{ externalKey: "guid:group", displayName: "Group", memberExternalKeys: ["guid:known"] }],
      },
    });
    expect(converted.identities.map((row) => row.accountId)).toEqual([accountId, null]);
    expect(converted.groups).toEqual([{ externalKey: "guid:group", memberExternalKeys: ["guid:known"] }]);
    await db.close();
  });
});
