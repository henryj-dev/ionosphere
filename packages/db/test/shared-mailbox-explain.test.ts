import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";

describe("shared mailbox listing indexes", () => {
  test("UID listing plan uses the mailbox leading index", async () => {
    const db = await openSqlite(":memory:");
    try {
      await migrate(db, allMigrations);
      const plan = await db.query({
        sql: "EXPLAIN QUERY PLAN SELECT message_id FROM message_mailbox WHERE mailbox_id = ? ORDER BY uid",
        params: ["mailbox-explain"],
      });
      const detail = plan.rows.map((row) => String(row.detail ?? "")).join(" ");
      expect(detail).toContain("ix_mm_listing");
    } finally {
      await db.close();
    }
  });
});
