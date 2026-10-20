import { describe, expect, test } from "@ionosphere/testkit";
import { ACCOUNT_STATUS } from "@ionosphere/db";
import { linkDirectoryIdentityWithClaim, unlinkDirectoryIdentityWithClaim } from "../src/directory-claims.ts";
import { directoryMembershipSource, directorySyncInputFromSnapshot, syncDirectorySnapshot, type DirectorySyncInput } from "../src/directory-sync.ts";
import { drainAccount } from "../src/account-drain.ts";
import { setupFixture } from "./helpers.ts";

function identityInput(
  tenantId: string,
  provider: string,
  externalKey: string,
  groupExternalKeys: readonly string[],
  now: number,
): DirectorySyncInput {
  return {
    tenantId,
    provider,
    now,
    identities: [{ externalKey, loginNames: ["user"], email: null, displayName: "User", groupExternalKeys }],
    groups: [],
  };
}

/** 첫 snapshot으로 identity를 만든 뒤 관리 연결을 거친다. sync가 account_id를 직접 쓰지 않는 계약을 지킨다. */
async function createAndLink(
  db: Awaited<ReturnType<typeof setupFixture>>["db"],
  input: DirectorySyncInput,
  accountId: string,
): Promise<void> {
  await syncDirectorySnapshot(db, input);
  const identity = input.identities[0]!;
  expect(
    await linkDirectoryIdentityWithClaim(db, {
      tenantId: input.tenantId,
      provider: input.provider,
      externalKey: identity.externalKey,
      accountId,
      displayName: identity.displayName,
      now: input.now,
    }),
  ).toBe("ok");
}

describe("directory sync", () => {
  test("snapshot metadata와 현재 연결을 바탕으로 membership·permissions_version을 한 배치로 갱신한다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const input = {
      tenantId,
      provider: "ad",
      now: 100,
      identities: [{ externalKey: "guid:abc", loginNames: ["user@ionosphere.test"], email: "user@ionosphere.test", displayName: "User", groupExternalKeys: ["guid:group"] }],
      groups: [{ externalKey: "guid:group", memberExternalKeys: ["guid:abc"] }],
    } as const;
    await createAndLink(db, input, accountId);
    const before = await db.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: [accountId] });
    await syncDirectorySnapshot(db, { ...input, now: 101 });

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
    const input = identityInput(tenantId, "ldap", "sid:1", ["sid:g"], 200);
    await createAndLink(db, input, accountId);
    await syncDirectorySnapshot(db, { ...input, now: 201 });
    await syncDirectorySnapshot(db, { ...input, now: 202 });
    const count = await db.query({ sql: "SELECT COUNT(*) AS count FROM directory_identities WHERE tenant_id = ?", params: [tenantId] });
    const memberships = await db.query({ sql: "SELECT COUNT(*) AS count FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource("ldap")] });
    expect(Number(count.rows[0]?.count)).toBe(1);
    expect(Number(memberships.rows[0]?.count)).toBe(1);
    await db.close();
  });

  test("완전 snapshot에서 그룹 제거가 membership과 권한 버전을 함께 갱신한다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const input = identityInput(tenantId, "ad", "guid:2", ["guid:g"], 300);
    await createAndLink(db, input, accountId);
    await syncDirectorySnapshot(db, input);
    const before = await db.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: [accountId] });
    await syncDirectorySnapshot(db, { ...input, now: 301, identities: [{ ...input.identities[0]!, groupExternalKeys: [] }] });
    const memberships = await db.query({ sql: "SELECT COUNT(*) AS count FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource("ad")] });
    const after = await db.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: [accountId] });
    expect(Number(memberships.rows[0]?.count)).toBe(0);
    expect(Number(after.rows[0]?.permissions_version)).toBe(Number(before.rows[0]?.permissions_version) + 1);
    await db.close();
  });

  test("provider별 source는 32자 안정 문자열이고 한 provider 동기화가 다른 membership을 지우지 않는다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const east = identityInput(tenantId, "ad-east", "ad-east:user", ["ad-east:group"], 400);
    const west = identityInput(tenantId, "ldap-west", "ldap-west:user", ["ldap-west:group"], 400);
    await createAndLink(db, east, accountId);
    await syncDirectorySnapshot(db, east);
    // 한 계정은 provider마다 identity 하나를 가질 수 있다.
    await createAndLink(db, west, accountId);
    await syncDirectorySnapshot(db, west);
    const eastSource = directoryMembershipSource("ad-east");
    const westSource = directoryMembershipSource("ldap-west");
    expect(eastSource.length).toBe(32);
    expect(eastSource).toBe(directoryMembershipSource("ad-east"));
    expect(eastSource === westSource).toBe(false);

    await syncDirectorySnapshot(db, { ...east, now: 401, identities: [{ ...east.identities[0]!, groupExternalKeys: [] }] });
    const rows = await db.query({ sql: "SELECT source FROM account_memberships WHERE account_id = ? ORDER BY source", params: [accountId] });
    expect(rows.rows.map((row) => String(row.source))).toEqual([westSource]);
    await db.close();
  });

  test("legacy directory source는 같은 provider principal만 회수한다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const input = identityInput(tenantId, "legacy-ad", "legacy:user", ["legacy:group"], 500);
    await createAndLink(db, input, accountId);
    await syncDirectorySnapshot(db, input);
    await db.batch([{ sql: "UPDATE account_memberships SET source = ? WHERE account_id = ?", params: ["directory", accountId] }]);
    await syncDirectorySnapshot(db, { ...input, now: 501, identities: [{ ...input.identities[0]!, groupExternalKeys: [] }] });
    const rows = await db.query({ sql: "SELECT source FROM account_memberships WHERE account_id = ?", params: [accountId] });
    expect(rows.rows).toEqual([]);
    await db.close();
  });

  test("snapshot 변환은 외부 정보만 옮기고 로컬 accountId를 싣지 않는다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const first = identityInput(tenantId, "ad", "guid:known", [], 600);
    await createAndLink(db, first, accountId);
    const converted = directorySyncInputFromSnapshot({
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
    expect(converted.identities).toEqual([
      { externalKey: "guid:known", loginNames: ["new"], email: "new@ionosphere.test", displayName: "Known", groupExternalKeys: ["guid:group"] },
      { externalKey: "guid:new", loginNames: ["other"], email: null, displayName: null, groupExternalKeys: [] },
    ]);
    expect(converted.groups).toEqual([{ externalKey: "guid:group", memberExternalKeys: ["guid:known"] }]);
    await db.close();
  });

  test("오래된 sync 입력은 연결 해제를 되돌리거나 membership을 되살리지 않는다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const input = identityInput(tenantId, "ad", "guid:stale", ["guid:group"], 700);
    await createAndLink(db, input, accountId);
    await syncDirectorySnapshot(db, input);
    // 외부 snapshot을 읽어 입력을 만든 뒤 관리자가 연결을 끊었다.
    const stale = { ...input, now: 701 };
    expect(await unlinkDirectoryIdentityWithClaim(db, { tenantId, provider: "ad", externalKey: "guid:stale", now: 702 })).toBe("ok");
    await syncDirectorySnapshot(db, stale);

    const identity = await db.query({ sql: "SELECT account_id FROM directory_identities WHERE tenant_id = ? AND provider = ? AND external_key = ?", params: [tenantId, "ad", "guid:stale"] });
    const memberships = await db.query({ sql: "SELECT 1 FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource("ad")] });
    expect(identity.rows[0]?.account_id).toBe(null);
    expect(memberships.rows).toEqual([]);
    await db.close();
  });

  test("오래된 sync 입력은 계정 드레인 뒤 연결·principal·membership 고아를 만들지 않는다", async () => {
    const { db, tenantId, accountId } = await setupFixture();
    const input = identityInput(tenantId, "ad", "guid:gone", ["guid:group"], 800);
    await createAndLink(db, input, accountId);
    await syncDirectorySnapshot(db, input);
    const stale = { ...input, now: 801 };
    await db.batch([{ sql: "UPDATE accounts SET status = ?, deleting_since = ? WHERE id = ?", params: [ACCOUNT_STATUS.deleting, 1, accountId] }]);
    expect((await drainAccount(db, accountId, { now: 802 })).done).toBe(true);
    await syncDirectorySnapshot(db, stale);

    const identity = await db.query({ sql: "SELECT account_id FROM directory_identities WHERE tenant_id = ? AND provider = ? AND external_key = ?", params: [tenantId, "ad", "guid:gone"] });
    const principal = await db.query({ sql: "SELECT account_id FROM principals WHERE tenant_id = ? AND kind = 0 AND provider = ? AND external_key = ?", params: [tenantId, "ad", "guid:gone"] });
    const memberships = await db.query({ sql: "SELECT 1 FROM account_memberships WHERE account_id = ?", params: [accountId] });
    expect(identity.rows[0]?.account_id).toBe(null);
    expect(principal.rows[0]?.account_id).toBe(null);
    expect(memberships.rows).toEqual([]);
    await db.close();
  });
});
