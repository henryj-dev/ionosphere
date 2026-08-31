import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { FsBlobStore, ListingCache, Store, type JmapEmailQueryResult } from "@ionosphere/store";
import { SharedMailboxRuntime } from "../src/shared-mailbox-runtime.ts";

describe("shared mailbox runtime", () => {
  test("directory sync, header rebuild, listing flush가 실제 자원에 연결된다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-shared-runtime-")));
    const store = new Store(db);
    const { tenantId } = await store.createTenant("runtime");
    const account = await store.createAccount({ tenantId, email: "runtime@ionosphere.test" });
    const mailbox = (await store.listMailboxes(account.accountId))[0]!;
    const raw = new TextEncoder().encode("Subject: projected\r\nMessage-ID: <runtime@example.test>\r\n\r\nbody");
    const blob = await blobs.put(raw);
    await store.appendMessage({
      accountId: account.accountId,
      mailboxIds: [mailbox.id],
      blobId: blob.blobId,
      blobGeneration: blob.generation,
      sizeBytes: blob.size,
      receivedAt: 1,
      envelope: { subject: "projected", subjectBase: "projected", msgidHash: null, sentAt: null, preview: "body", hasAttachment: false, addresses: [], threadRefHashes: [] },
      keywords: [],
    });

    const listingCache = new ListingCache<JmapEmailQueryResult>({ ttlMs: 5000 });
    listingCache.set("cached", [{ ids: ["message"], total: 1 }]);
    const runtime = new SharedMailboxRuntime({
      db,
      blobs,
      listingCache,
      directorySources: {
        ad: {
          authenticate: async (loginName, password) => loginName === "runtime" && password === "directory-secret"
            ? { externalKey: "guid:runtime", loginNames: ["runtime"], email: "runtime@ionosphere.test", displayName: "Runtime" }
            : null,
          read: async () => ({
            identities: [{ externalKey: "guid:runtime", loginNames: ["runtime"], email: "runtime@ionosphere.test", displayName: "Runtime", accountId: account.accountId, groupExternalKeys: [] }],
            groups: [],
          }),
        },
      },
    });

    expect((await runtime.sync(tenantId, "ad")).data?.identities).toBe(1);
    expect(await runtime.authenticate("runtime", "directory-secret")).toEqual({ accountId: account.accountId, credKind: "directory:ad" });
    expect(await runtime.authenticate("runtime", "wrong")).toBe(null);
    expect((await db.query({ sql: "SELECT COUNT(*) AS n FROM directory_identities WHERE tenant_id = ? AND provider = ?", params: [tenantId, "ad"] })).rows[0]?.n).toBe(1);
    expect((await runtime.rebuildHeaders(10)).data?.processed).toBe(1);
    expect((await db.query({ sql: "SELECT display_value FROM message_header_projection WHERE name = ?", params: ["subject"] })).rows[0]?.display_value).toBe("projected");
    expect((await runtime.flushListingCache()).data?.entries).toBe(1);
    expect(listingCache.size).toBe(0);
    await runtime.close();
    await db.close();
  });
});
