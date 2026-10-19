/**
 * 비밀번호 정규화(SASLprep)와 기존 해시의 재저장 — 2026-10-18 결정 2.
 *
 * 정규화 전 원문으로 만든 기존 해시도 로그인이 깨지면 안 되고, 맞으면 정규화한 값으로 다시 저장해야 한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, createHmac, pbkdf2Sync, randomBytes, scryptSync } from "node:crypto";
import { ADMIN_ROLE, allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { authenticate, createAdminUser, createCredential, hashSecret, scramKeysFor, Store, verifyAccountPrimaryPassword, verifyAdminPassword, verifySecret } from "@ionosphere/store";

/** 정규화 전 규칙으로 만든 해시 — 이 변경 전 저장소가 만들던 형식 그대로(SCRAM 세그먼트 없음). */
function legacyHash(raw: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(raw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString("base64")}$${hash.toString("base64")}`;
}

/** "Ⅸ"(U+2168)는 NFKC로 "IX"가 된다. */
const RAW = "\u2168abc-12!";
const NORMALIZED = "IXabc-12!";

async function waitFor(check: () => Promise<boolean>): Promise<void> {
  for (let i = 0; i < 50; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error("조건이 끝내 참이 되지 않았다");
}

describe("SASLprep 정규화", () => {
  test("새 해시는 정규화한 값으로 만든다 — 두 표기 모두 로그인된다", async () => {
    const stored = await hashSecret(RAW);
    expect(await verifySecret(RAW, stored)).toBe(true);
    expect(await verifySecret(NORMALIZED, stored)).toBe(true);
  });

  test("기존(원문) 해시도 로그인되고, 성공하면 정규화한 값으로 다시 저장한다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const store = new Store(db);
    const { tenantId } = await store.createTenant("t");
    const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
    const id = await createCredential(db, { accountId, password: "placeholder" });
    const legacy = legacyHash(RAW);
    await db.batch([{ sql: "UPDATE credentials SET secret = ? WHERE id = ?", params: [legacy, id] }]);
    // 예전 해시는 원문으로만 맞는다 — 정규화한 표기로는 아직 들어올 수 없다.
    expect(await authenticate(db, "u@x.test", NORMALIZED, "imap")).toBeNull();

    expect(await authenticate(db, "u@x.test", RAW, "imap")).toMatchObject({ accountId });
    const read = async (): Promise<string> => String((await db.query({ sql: "SELECT secret FROM credentials WHERE id = ?", params: [id] })).rows[0]!.secret);
    await waitFor(async () => (await read()) !== legacy);
    // 다시 저장된 뒤에는 정규화한 표기로도 들어오고, SCRAM 키도 정규화한 값으로 생긴다.
    expect(await authenticate(db, "u@x.test", NORMALIZED, "imap")).toMatchObject({ accountId });
    // SCRAM 키가 **정규화한 값**에서 만들어졌는지 코드와 독립된 계산(RFC 5802)으로 확인한다 — null이 아닌 것만 보면
    // 원문으로 잘못 만들어도 통과한다.
    const keys = await scramKeysFor(db, "u@x.test");
    expect(keys).not.toBeNull();
    const salted = pbkdf2Sync(NORMALIZED, keys!.salt, keys!.iterations, 32, "sha256");
    const storedKey = createHash("sha256").update(createHmac("sha256", salted).update("Client Key").digest()).digest();
    expect(storedKey.equals(keys!.storedKey)).toBe(true);
  });

  test("관리 콘솔 관리자도 원문 해시로 로그인되고, 정규화한 값으로 다시 저장된다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const id = (await createAdminUser(db, { username: "ops@ionosphere.test", role: ADMIN_ROLE.owner, password: "placeholder" }))!;
    const legacy = legacyHash(RAW);
    await db.batch([{ sql: "UPDATE admin_users SET password_hash = ? WHERE id = ?", params: [legacy, id] }]);
    expect(await verifyAdminPassword(db, "ops@ionosphere.test", RAW)).not.toBeNull();
    const read = async (): Promise<string> => String((await db.query({ sql: "SELECT password_hash FROM admin_users WHERE id = ?", params: [id] })).rows[0]!.password_hash);
    await waitFor(async () => (await read()) !== legacy);
    expect(await verifyAdminPassword(db, "ops@ionosphere.test", NORMALIZED)).not.toBeNull();
  });

  test("셀프서비스 로그인도 원문 해시로 로그인되고, 정규화한 값으로 다시 저장된다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const store = new Store(db);
    const { tenantId } = await store.createTenant("t");
    const { accountId } = await store.createAccount({ tenantId, email: "w@x.test" });
    const cid = await createCredential(db, { accountId, password: "placeholder" });
    const legacy = legacyHash(RAW);
    await db.batch([{ sql: "UPDATE credentials SET secret = ? WHERE id = ?", params: [legacy, cid] }]);
    expect(await verifyAccountPrimaryPassword(db, "w@x.test", RAW)).toMatchObject({ accountId });
    const read = async (): Promise<string> => String((await db.query({ sql: "SELECT secret FROM credentials WHERE id = ?", params: [cid] })).rows[0]!.secret);
    await waitFor(async () => (await read()) !== legacy);
    expect(await verifyAccountPrimaryPassword(db, "w@x.test", NORMALIZED)).toMatchObject({ accountId });
  });
});
