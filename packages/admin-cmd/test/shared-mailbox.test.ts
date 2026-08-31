import { describe, expect, test } from "@ionosphere/testkit";
import { createRegistry } from "../src/registry.ts";
import { runCommand } from "../src/dispatch.ts";
import type { CommandContext } from "../src/types.ts";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { Store } from "@ionosphere/store";

describe("shared mailbox admin surfaces", () => {
  test("registry descriptor 하나가 여덟 shared/cache 명령의 surface 정본이다", () => {
    const names = createRegistry().describe().filter((spec) => spec.group === "공유 메일함" || spec.group === "메일 캐시").map((spec) => spec.name);
    expect(names).toEqual(["shared-account-list", "mailbox-acl-list", "directory-identity-list", "directory-identity-link", "directory-identity-unlink", "directory-sync", "header-rebuild", "listing-cache-flush"]);
    expect(createRegistry().describe().filter((spec) => names.includes(spec.name)).every((spec) => spec.destructive === true || spec.readOnly)).toBe(true);
  });

  test("identity link/unlink는 tenant 경계와 provider membership 회수를 한 배치로 지킨다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const store = new Store(db);
    const { tenantId } = await store.createTenant("directory-admin");
    const account = await store.createAccount({ tenantId, email: "linked@ionosphere.test" });
    await db.batch([{ sql: "INSERT INTO directory_identities (id, tenant_id, provider, external_key, login_names, email, display_name, last_seen_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", params: ["identity-link", tenantId, "ad", "guid:linked", "[\"linked\"]", "linked@ionosphere.test", "Linked", 1, 1] }]);
    const ctx = { db, store, tenantId, isRoot: true } as CommandContext;
    await runCommand(createRegistry(), ctx, "directory-identity-link", { provider: "ad", externalKey: "guid:linked", accountId: account.accountId });
    expect((await db.query({ sql: "SELECT account_id FROM directory_identities WHERE id = ?", params: ["identity-link"] })).rows[0]?.account_id).toBe(account.accountId);
    await runCommand(createRegistry(), ctx, "directory-identity-unlink", { provider: "ad", externalKey: "guid:linked" });
    expect((await db.query({ sql: "SELECT account_id FROM directory_identities WHERE id = ?", params: ["identity-link"] })).rows[0]?.account_id).toBe(null);
    await db.close();
  });

  test("secret/filter/header를 관측 이벤트에 싣지 않는다", async () => {
    const events: unknown[] = [];
    const ctx = {
      db: {},
      store: {},
      tenantId: "tenant-test",
      isRoot: true,
      observer: { record: (event: unknown) => events.push(event) },
      sharedMailbox: { sync: async () => ({ message: "ok" }), rebuildHeaders: async () => ({ message: "ok" }), flushListingCache: async () => ({ message: "ok" }) },
    } as unknown as CommandContext;
    await runCommand(createRegistry(), ctx, "listing-cache-flush", { secret: "audit-secret", filter: "Subject: full header" });
    const serialized = JSON.stringify(events);
    expect(serialized.includes("audit-secret")).toBe(false);
    expect(serialized.includes("Subject: full header")).toBe(false);
    expect(serialized).toBe('[{"operation":"listing-cache-flush","outcome":"ok","reason":"success"}]');
  });

  test("관리 포트가 없으면 기능을 열지 않고 unavailable로 관측한다", async () => {
    const events: unknown[] = [];
    const ctx = { db: {}, store: {}, tenantId: "tenant-test", isRoot: true, observer: { record: (event: unknown) => events.push(event) } } as unknown as CommandContext;
    await expect(runCommand(createRegistry(), ctx, "listing-cache-flush", {})).rejects.toThrow("연결되지 않았습니다");
    expect(events).toEqual([{ operation: "listing-cache-flush", outcome: "fail", reason: "unavailable" }]);
  });
});
