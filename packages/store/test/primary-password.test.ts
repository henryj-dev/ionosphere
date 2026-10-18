/** 기본 비밀번호 교체 — 옛 비밀번호 무효·앱 비번 유지·중복 kind=0 수렴·SCRAM 갱신·삭제 중 거부. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ACCOUNT_STATUS, allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { authenticate, createAppPassword, createCredential, scramKeysFor, setPrimaryPassword, Store } from "@ionosphere/store";

async function setup(): Promise<{ db: DbDriver; accountId: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
  await createCredential(db, { accountId, password: "old-pw" });
  return { db, accountId };
}

describe("setPrimaryPassword", () => {
  test("새 비밀번호로만 로그인되고 옛 비밀번호는 실패한다", async () => {
    const { db, accountId } = await setup();
    expect(await setPrimaryPassword(db, accountId, "new-pw")).toBe(true);
    expect(await authenticate(db, "u@x.test", "new-pw", "imap")).toMatchObject({ accountId, credKind: "password" });
    expect(await authenticate(db, "u@x.test", "old-pw", "imap")).toBeNull();
  });

  test("앱 비밀번호는 그대로 살아 있다", async () => {
    const { db, accountId } = await setup();
    const { password } = await createAppPassword(db, accountId, "phone");
    await setPrimaryPassword(db, accountId, "new-pw");
    expect(await authenticate(db, "u@x.test", password, "imap")).toMatchObject({ accountId, credKind: "appPassword" });
  });

  test("kind=0 행이 여럿이어도 전부 무효가 되고 하나로 수렴한다", async () => {
    // createCredential은 kind=0 중복을 막지 않는다 — 하나만 고치면 나머지 옛 비밀번호가 계속 통과한다.
    const { db, accountId } = await setup();
    await createCredential(db, { accountId, password: "older-pw" });
    await setPrimaryPassword(db, accountId, "new-pw");
    expect(await authenticate(db, "u@x.test", "old-pw", "imap")).toBeNull();
    expect(await authenticate(db, "u@x.test", "older-pw", "imap")).toBeNull();
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM credentials WHERE account_id = ? AND kind = 0", params: [accountId] });
    expect(Number(rows[0]!.n)).toBe(1);
  });

  test("SCRAM 키도 새 비밀번호 것으로 바뀐다", async () => {
    const { db, accountId } = await setup();
    const before = await scramKeysFor(db, "u@x.test");
    await setPrimaryPassword(db, accountId, "new-pw");
    const after = await scramKeysFor(db, "u@x.test");
    expect(after).not.toBeNull();
    expect(after!.storedKey.equals(before!.storedKey)).toBe(false);
  });

  test("정지 계정은 바꿀 수 있고, 삭제 중 계정은 쓰지 않는다", async () => {
    const { db, accountId } = await setup();
    await db.batch([{ sql: "UPDATE accounts SET status = ? WHERE id = ?", params: [ACCOUNT_STATUS.suspended, accountId] }]);
    expect(await setPrimaryPassword(db, accountId, "new-pw")).toBe(true);

    await db.batch([{ sql: "UPDATE accounts SET status = ? WHERE id = ?", params: [ACCOUNT_STATUS.deleting, accountId] }]);
    expect(await setPrimaryPassword(db, accountId, "newer-pw")).toBe(false);
    // 옛 행이 지워지지도 않아야 한다 — 드레인 중 계정의 자격증명은 리퍼 몫이다.
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM credentials WHERE account_id = ? AND kind = 0", params: [accountId] });
    expect(Number(rows[0]!.n)).toBe(1);
  });

  test("없는 계정은 false", async () => {
    const { db } = await setup();
    expect(await setPrimaryPassword(db, "01NOSUCHACCOUNT000000000000", "pw")).toBe(false);
  });
});
