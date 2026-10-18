/** OIDC 연결 명령 — 설정된 공급자만, 디렉터리 명령으로 oidc: 행을 바꾸지 못함(2026-10-18 검토). */
import { describe, expect, test } from "@ionosphere/testkit";
import { ADMIN_ROLE, allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { createAdminUser, Store } from "@ionosphere/store";
import { createRegistry } from "../src/registry.ts";
import { runCommand } from "../src/dispatch.ts";
import type { CommandContext } from "../src/types.ts";

async function setup() {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("acme");
  const { tenantId: other } = await store.createTenant("other");
  const { accountId } = await store.createAccount({ tenantId, email: "alice@acme.test" });
  await createAdminUser(db, { username: "ops@ionosphere.test", role: ADMIN_ROLE.owner });
  const base = { db, store, oidcAccountProviders: [{ id: "corp", tenantId }], oidcAdminProviders: ["staff"] };
  return { db, tenantId, other, accountId, ctx: (t: string, root = false) => ({ ...base, tenantId: t, isRoot: root }) as CommandContext };
}

describe("OIDC 연결 명령", () => {
  test("이 테넌트에 설정된 공급자만 받는다", async () => {
    const s = await setup();
    const reg = createRegistry();
    await expect(runCommand(reg, s.ctx(s.tenantId), "oidc-identity-link", { account: "alice@acme.test", provider: "unknown", subject: "x" })).rejects.toThrow(/설정된 OIDC 공급자가 아닙니다/);
    await expect(runCommand(reg, s.ctx(s.other), "oidc-identity-link", { account: "alice@acme.test", provider: "corp", subject: "x" })).rejects.toThrow(/설정된 OIDC 공급자가 아닙니다/);
    const ok = await runCommand(reg, s.ctx(s.tenantId), "oidc-identity-link", { account: "alice@acme.test", provider: "corp", subject: "sub-1" });
    expect(ok.data?.accountId).toBe(s.accountId);
    await expect(runCommand(reg, s.ctx(s.tenantId), "oidc-identity-link", { account: "alice@acme.test", provider: "corp", subject: "sub-2" })).rejects.toThrow(/이미 연결/);
  });

  test("관리자 연결도 설정된 관리자 공급자만", async () => {
    const s = await setup();
    const reg = createRegistry();
    await expect(runCommand(reg, s.ctx("", true), "admin-identity-link", { admin: "ops@ionosphere.test", provider: "corp", subject: "x" })).rejects.toThrow(/관리자 OIDC 공급자가 아닙니다/);
    expect((await runCommand(reg, s.ctx("", true), "admin-identity-link", { admin: "ops@ionosphere.test", provider: "staff", subject: "x" })).message).toContain("연결됨");
  });

  test("디렉터리 명령은 oidc: 행을 다루지 않는다", async () => {
    const s = await setup();
    const reg = createRegistry();
    await expect(runCommand(reg, s.ctx(s.tenantId), "directory-identity-link", { provider: "oidc:corp", externalKey: "sub-1", accountId: s.accountId })).rejects.toThrow(/oidc-identity-link/);
    await expect(runCommand(reg, s.ctx(s.tenantId), "directory-identity-unlink", { provider: "oidc:corp", externalKey: "sub-1" })).rejects.toThrow(/oidc-identity-link/);
  });
});
