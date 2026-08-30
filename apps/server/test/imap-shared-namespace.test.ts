import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { FsBlobStore, Store } from "@ionosphere/store";
import { IonosphereImapBackend } from "../src/imap-backend.ts";

describe("IMAP shared namespace", () => {
  test("shared provisioning은 account principal과 기본 INBOX를 만든다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const store = new Store(db);
    const { tenantId } = await store.createTenant("tenant");
    const created = await store.createAccount({ tenantId, email: "shared@ionosphere.test", kind: 1 });
    const { rows } = await db.query({ sql: "SELECT kind FROM accounts WHERE id = ?", params: [created.accountId] });
    expect(Number(rows[0]?.kind)).toBe(1);
    const principal = await db.query({ sql: "SELECT account_id FROM principals WHERE account_id = ?", params: [created.accountId] });
    expect(principal.rows).toHaveLength(1);
    await db.close();
  });

  test("l 없는 shared mailbox는 LIST·SELECT 모두 존재를 숨긴다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const store = new Store(db);
    const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-shared-")));
    const { tenantId } = await store.createTenant("tenant");
    const owner = await store.createAccount({ tenantId, email: "owner@ionosphere.test", kind: 1 });
    const reader = await store.createAccount({ tenantId, email: "reader@ionosphere.test" });
    const sharedMailbox = await store.createMailbox({ accountId: owner.accountId, name: "Shared" });
    expect(sharedMailbox.mailboxId).toBeTruthy();
    const backend = new IonosphereImapBackend(db, store, blobs);
    const list = await backend.request(reader.accountId, { kind: "listMailboxes" });
    expect(list.kind).toBe("mailboxes");
    if (list.kind === "mailboxes") expect(list.mailboxes.map((mailbox) => mailbox.name)).toEqual(["INBOX"]);
    const selected = await backend.request(reader.accountId, { kind: "selectMailbox", name: "Shared" });
    expect(selected).toEqual({ kind: "no", code: "NONEXISTENT", message: "no such mailbox" });
    await db.close();
  });
});
