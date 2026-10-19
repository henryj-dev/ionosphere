/**
 * 기본 비밀번호 메일 접속 현황(이 창 결정 A의 관측 단계) — 앱 비밀번호로 옮겨야 할 계정을 찾는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { authenticate, createAppPassword, createCredential, scramAuthorize, Store } from "@ionosphere/store";
import { createRegistry } from "../src/registry.ts";
import { runCommand } from "../src/dispatch.ts";
import type { CommandContext } from "../src/types.ts";

async function setup() {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("acme");
  const make = async (email: string): Promise<string> => {
    const { accountId } = await store.createAccount({ tenantId, email });
    await createCredential(db, { accountId, password: "Primary-pw1" });
    return accountId;
  };
  return { db, store, tenantId, make, ctx: { db, store, tenantId, isRoot: false } as unknown as CommandContext };
}

describe("mail-password-usage", () => {
  test("기본 비밀번호로 메일에 접속한 계정만 나오고, 앱 비밀번호로만 쓰는 계정은 빠진다", async () => {
    const s = await setup();
    await s.make("primary@acme.test");
    const appOnly = await s.make("apponly@acme.test");
    await s.make("idle@acme.test");
    expect(await authenticate(s.db, "primary@acme.test", "Primary-pw1", "imap")).not.toBeNull();
    const { password } = await createAppPassword(s.db, appOnly, "phone");
    expect(await authenticate(s.db, "apponly@acme.test", password, "imap")).not.toBeNull();

    const r = await runCommand(createRegistry(), s.ctx, "mail-password-usage", {});
    expect(r.rows?.map((x) => x.email)).toEqual(["primary@acme.test"]);
    expect(r.rows?.[0]?.appPasswords).toBe(0);
  });

  test("기간 밖의 사용은 빠지고, 기간은 1~365일 정수만 받는다", async () => {
    const s = await setup();
    const id = await s.make("old@acme.test");
    await s.db.batch([{ sql: "UPDATE credentials SET last_used_at = ? WHERE account_id = ? AND kind = 0", params: [Date.now() - 30 * 86_400_000, id] }]);
    expect((await runCommand(createRegistry(), s.ctx, "mail-password-usage", { days: "14" })).rows).toHaveLength(0);
    expect((await runCommand(createRegistry(), s.ctx, "mail-password-usage", { days: "60" })).rows).toHaveLength(1);
    await expect(runCommand(createRegistry(), s.ctx, "mail-password-usage", { days: "0" })).rejects.toThrow(/1~365/);
  });

  test("SCRAM 로그인도 관측에 잡힌다(예전엔 마지막 사용 시각을 갱신하지 않았다)", async () => {
    const s = await setup();
    await s.make("scram@acme.test");
    expect(await scramAuthorize(s.db, "scram@acme.test", "imap")).not.toBeNull();
    expect((await runCommand(createRegistry(), s.ctx, "mail-password-usage", {})).rows?.map((x) => x.email)).toEqual(["scram@acme.test"]);
  });
});
