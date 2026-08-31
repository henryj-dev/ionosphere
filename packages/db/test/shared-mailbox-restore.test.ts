import { copyFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";

describe("shared mailbox migration restore", () => {
  test("backup 복구 뒤 020~024 재개 시 ACL·version·projection이 보존된다", async () => {
    const root = await mkdtemp(join(tmpdir(), "ionosphere-restore-"));
    const sourcePath = join(root, "source.db");
    const backupPath = join(root, "backup.db");
    const restoredPath = join(root, "restored.db");
    try {
      const source = await openSqlite(sourcePath);
      await migrate(source, allMigrations.filter((migration) => migration.version <= 22));
      await source.batch([
        { sql: "INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)", params: ["tenant-restore", "restore", 1] },
        { sql: "INSERT INTO accounts (id, tenant_id, email, kind, permissions_version, created_at) VALUES (?, ?, ?, 1, 7, ?)", params: ["account-restore", "tenant-restore", "shared@ionosphere.test", 1] },
        { sql: "INSERT INTO mailboxes (id, account_id, name, uidvalidity, created_at) VALUES (?, ?, ?, ?, ?)", params: ["mailbox-restore", "account-restore", "INBOX", 1, 1] },
        { sql: "INSERT INTO principals (id, tenant_id, kind, created_at) VALUES (?, ?, 0, ?)", params: ["principal-restore", "tenant-restore", 1] },
        { sql: "INSERT INTO mailbox_acl (mailbox_id, principal_id, rights, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", params: ["mailbox-restore", "principal-restore", "lr", 1, 1] },
        { sql: "INSERT INTO message_header_projection (message_id, occurrence, name, kind, display_value, sort_value) VALUES (?, ?, ?, ?, ?, ?)", params: ["message-restore", 1, "subject", "text", "hello", "hello"] },
      ]);
      await source.close();
      await copyFile(sourcePath, backupPath);
      await copyFile(backupPath, restoredPath);
      const restored = await openSqlite(restoredPath);
      expect(await migrate(restored, allMigrations)).toBe(2);
      const acl = await restored.query({ sql: "SELECT rights FROM mailbox_acl WHERE mailbox_id = ?", params: ["mailbox-restore"] });
      const account = await restored.query({ sql: "SELECT permissions_version FROM accounts WHERE id = ?", params: ["account-restore"] });
      const header = await restored.query({ sql: "SELECT display_value FROM message_header_projection WHERE message_id = ?", params: ["message-restore"] });
      expect(acl.rows[0]?.rights).toBe("lr");
      expect(Number(account.rows[0]?.permissions_version)).toBe(7);
      expect(header.rows[0]?.display_value).toBe("hello");
      await restored.close();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
