/**
 * 비밀번호 정규화(SASLprep)와 기존 해시의 재저장 — 2026-10-18 결정 2.
 *
 * 정규화 전 원문으로 만든 기존 해시도 로그인이 깨지면 안 되고, 맞으면 정규화한 값으로 다시 저장해야 한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { randomBytes, scryptSync } from "node:crypto";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { authenticate, createCredential, hashSecret, scramKeysFor, Store, verifySecret } from "@ionosphere/store";

/** 정규화 전 규칙으로 만든 해시 — 이 변경 전 저장소가 만들던 형식 그대로(SCRAM 세그먼트 없음). */
function legacyHash(raw: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(raw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString("base64")}$${hash.toString("base64")}`;
}

/** "Ⅸ"(U+2168)는 NFKC로 "IX"가 된다. */
const RAW = "Ⅸabc-12!";
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
    expect(await scramKeysFor(db, "u@x.test")).not.toBeNull();
  });
});
