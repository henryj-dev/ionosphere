import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";

describe("migrate", () => {
  test("001 전체 적용 + 테이블 존재 확인", async () => {
    const db = await openSqlite();
    const applied = await migrate(db, allMigrations);
    expect(applied).toBe(allMigrations.length);

    const { rows } = await db.query({
      sql: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
    });
    const tables = rows.map((r) => r.name);
    // SCHEMA.md v2.1 테이블 전수 (schema_migrations는 러너 소유)
    for (const t of [
      "tenants", "domains", "domain_name_claims", "accounts", "addresses",
      "credentials", "api_keys", "mailboxes", "messages", "message_mailbox",
      "message_keywords", "message_addresses", "thread_refs", "modseq_claims",
      "change_log", "expunged", "message_text", "search_index",
      "email_submissions", "mta_queue", "identities", "suppressions",
      "dkim_keys", "sieve_scripts", "dedup_tracking", "push_subscriptions",
      "message_auth", "background_jobs", "blobs", "blob_refs",
      "principals", "mailbox_acl", "account_memberships",
      "schema_migrations",
    ]) {
      expect(tables).toContain(t);
    }
    await db.close();
  });

  test("020 주체 식별자는 테넌트·provider 범위로 격리된다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    await db.batch([
      { sql: "INSERT INTO principals (id, tenant_id, kind, provider, external_key, created_at) VALUES (?, ?, ?, ?, ?, ?)", params: ["p-a", "tenant-a", 2, "ldap", "uid=alice", 1] },
      { sql: "INSERT INTO principals (id, tenant_id, kind, provider, external_key, created_at) VALUES (?, ?, ?, ?, ?, ?)", params: ["p-b", "tenant-b", 2, "ldap", "uid=alice", 1] },
      { sql: "INSERT INTO principals (id, tenant_id, kind, provider, external_key, created_at) VALUES (?, ?, ?, ?, ?, ?)", params: ["p-c", "tenant-a", 2, "ad", "uid=alice", 1] },
    ]);
    const { rows } = await db.query({ sql: "SELECT COUNT(*) AS count FROM principals" });
    expect(Number(rows[0]?.count)).toBe(3);
    await db.close();
  });

  test("재실행 멱등 (0건 적용)", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const second = await migrate(db, allMigrations);
    expect(second).toBe(0);
    await db.close();
  });
});
