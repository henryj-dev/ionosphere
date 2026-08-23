/** 앱 비밀번호 — 생성·인증(정규화)·last_used_at·목록·폐기. */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { authenticate, createAppPassword, createCredential, generateAppPassword, listCredentials, revokeCredential, Store } from "@ionosphere/store";

async function setup(): Promise<{ db: DbDriver; accountId: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
  await createCredential(db, { accountId, password: "primary-pw" }); // 기본 비번(kind 0)
  return { db, accountId };
}

describe("generateAppPassword", () => {
  test("4-4-4-4 소문자 형식, 매번 다름", () => {
    const a = generateAppPassword();
    expect(a).toMatch(/^[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}$/);
    expect(generateAppPassword()).not.toBe(a);
  });
});

describe("앱 비밀번호 인증", () => {
  test("생성 → 그 비번으로 인증 성공(하이픈 포함/제거/공백 모두)", async () => {
    const { db, accountId } = await setup();
    const { password } = await createAppPassword(db, accountId, "Thunderbird");
    expect(await authenticate(db, "u@x.test", password)).toMatchObject({ accountId }); // 원본(하이픈 포함)
    const compact = password.replace(/-/g, "");
    expect(await authenticate(db, "u@x.test", compact)).toMatchObject({ accountId }); // 하이픈 제거
    expect(await authenticate(db, "u@x.test", password.replace(/-/g, " "))).toMatchObject({ accountId }); // 공백
  });

  test("기본 비번도 여전히 동작, 틀린 앱비번은 실패", async () => {
    const { db, accountId } = await setup();
    await createAppPassword(db, accountId, "app");
    expect(await authenticate(db, "u@x.test", "primary-pw")).toMatchObject({ accountId });
    expect(await authenticate(db, "u@x.test", "wxyz-wxyz-wxyz-wxyz")).toBeNull();
  });

  test("인증 성공 시 last_used_at 갱신", async () => {
    const { db, accountId } = await setup();
    const { id, password } = await createAppPassword(db, accountId, "app");
    expect((await listCredentials(db, accountId, 1))[0]!.lastUsedAt).toBeNull();
    await authenticate(db, "u@x.test", password);
    const after = (await listCredentials(db, accountId, 1)).find((c) => c.id === id)!;
    expect(after.lastUsedAt).not.toBeNull();
  });
});

describe("목록·폐기", () => {
  test("listCredentials(kind=1) 앱 비번만, 라벨 노출", async () => {
    const { db, accountId } = await setup();
    await createAppPassword(db, accountId, "iPhone");
    await createAppPassword(db, accountId, "Laptop");
    const list = await listCredentials(db, accountId, 1);
    expect(list.map((c) => c.label).sort()).toEqual(["Laptop", "iPhone"]);
    // kind=0(기본 비번)은 제외
    expect(list.every((c) => c.kind === 1)).toBe(true);
  });

  test("폐기 → 인증 불가, 기본 비번은 폐기 대상 아님", async () => {
    const { db, accountId } = await setup();
    const { id, password } = await createAppPassword(db, accountId, "app");
    expect(await revokeCredential(db, accountId, id)).toBe(true);
    expect(await authenticate(db, "u@x.test", password)).toBeNull();
    // 기본 비번(kind 0) id로 폐기 시도 → 거부(false)
    const primary = (await listCredentials(db, accountId, 0))[0]!;
    expect(await revokeCredential(db, accountId, primary.id)).toBe(false);
    expect(await authenticate(db, "u@x.test", "primary-pw")).toMatchObject({ accountId });
    await db.close();
  });
});
