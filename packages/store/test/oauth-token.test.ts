/** OAuth 베어러 토큰(kind=2) — 생성·인증·목록·폐기. SASL 파싱은 core/proto 테스트가 커버. */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { authenticate, createCredential, createOAuthToken, generateOAuthToken, listCredentials, revokeCredential, Store } from "@ionosphere/store";

async function setup(): Promise<{ db: DbDriver; accountId: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
  await createCredential(db, { accountId, password: "primary-pw" }); // kind 0
  return { db, accountId };
}

test("generateOAuthToken: URL-safe, 매번 다름", () => {
  const t = generateOAuthToken();
  expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(generateOAuthToken()).not.toBe(t);
});

describe("OAuth 토큰", () => {
  test("생성 → 그 토큰으로 authenticate 성공(원문 검증)", async () => {
    const { db, accountId } = await setup();
    const { token } = await createOAuthToken(db, accountId, "gmail-app");
    expect(await authenticate(db, "u@x.test", token)).toMatchObject({ accountId });
    // 잘못된 토큰은 실패
    expect(await authenticate(db, "u@x.test", token + "x")).toBeNull();
  });

  test("인증 시 last_used_at 갱신, list는 kind=2만", async () => {
    const { db, accountId } = await setup();
    const { id, token } = await createOAuthToken(db, accountId, "dev");
    await createOAuthToken(db, accountId, "phone");
    const before = (await listCredentials(db, accountId, 2)).find((c) => c.id === id)!;
    expect(before.lastUsedAt).toBeNull();
    await authenticate(db, "u@x.test", token);
    const after = (await listCredentials(db, accountId, 2)).find((c) => c.id === id)!;
    expect(after.lastUsedAt).not.toBeNull();
    const list = await listCredentials(db, accountId, 2);
    expect(list.length).toBe(2);
    expect(list.every((c) => c.kind === 2)).toBe(true);
  });

  test("폐기(kind=2) → 인증 불가, 기본 비번은 폐기 대상 아님", async () => {
    const { db, accountId } = await setup();
    const { id, token } = await createOAuthToken(db, accountId, "t");
    expect(await revokeCredential(db, accountId, id)).toBe(true);
    expect(await authenticate(db, "u@x.test", token)).toBeNull();
    const primary = (await listCredentials(db, accountId, 0))[0]!;
    expect(await revokeCredential(db, accountId, primary.id)).toBe(false);
    expect(await authenticate(db, "u@x.test", "primary-pw")).toMatchObject({ accountId });
    await db.close();
  });
});
