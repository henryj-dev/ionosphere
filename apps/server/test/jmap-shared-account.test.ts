import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "@ionosphere/testkit";
import { MAIL_CAPABILITY, JmapEngine } from "@ionosphere/proto-jmap";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { FsBlobStore, ListingCache, Store, type JmapEmailQueryResult } from "@ionosphere/store";
import { buildMailModule } from "../src/jmap-backend.ts";

describe("JMAP shared account", () => {
  test("Mailbox/get은 ACL로 보이는 shared account와 myRights만 노출한다", async () => {
    const db = await openSqlite(":memory:");
    await migrate(db, allMigrations);
    const store = new Store(db);
    const blobs = new FsBlobStore(mkdtempSync(join(tmpdir(), "ion-jmap-shared-")));
    const { tenantId } = await store.createTenant("tenant");
    const actor = await store.createAccount({ tenantId, email: "actor@ionosphere.test" });
    const shared = await store.createAccount({ tenantId, email: "shared-jmap@ionosphere.test", kind: 1 });
    const { rows: actorPrincipal } = await db.query({ sql: "SELECT id FROM principals WHERE account_id = ?", params: [actor.accountId] });
    const { rows: sharedMailbox } = await db.query({ sql: "SELECT id FROM mailboxes WHERE account_id = ?", params: [shared.accountId] });
    const sharedMailboxId = String(sharedMailbox[0]!.id);
    await store.setMailboxAcl(tenantId, sharedMailboxId, String(actorPrincipal[0]!.id), "lr");
    const appended = await store.appendMessage({
      accountId: shared.accountId,
      mailboxIds: [sharedMailboxId],
      blobId: "01JMAPSHAREDBLOB000000000000",
      sizeBytes: 4,
      receivedAt: 1,
      envelope: { subject: "shared", subjectBase: "shared", msgidHash: null, sentAt: null, preview: "body", hasAttachment: false, addresses: [], threadRefHashes: [] },
      keywords: [],
    });
    const listingCache = new ListingCache<JmapEmailQueryResult>({ ttlMs: 5000 });
    const engine = new JmapEngine({
      modules: [buildMailModule(db, store, blobs, listingCache)],
      capabilities: [MAIL_CAPABILITY],
      sessionState: () => "0",
    });

    const response = await engine.handle({ using: [MAIL_CAPABILITY], methodCalls: [
      ["Mailbox/get", { accountId: shared.accountId, ids: null }, "c0"],
      ["Email/query", { accountId: shared.accountId, filter: { inMailbox: sharedMailboxId } }, "c1"],
      ["Email/get", { accountId: shared.accountId, ids: [appended.messageId], properties: ["id", "subject"] }, "c2"],
      ["Thread/get", { accountId: shared.accountId, ids: [appended.threadId] }, "c3"],
    ] }, actor.accountId);
    const [name, result] = response.methodResponses[0]!;
    expect(name).toBe("Mailbox/get");
    const list = (result as { list: { id: string; myRights: { mayReadItems: boolean; mayAddItems: boolean } }[] }).list;
    expect(list).toHaveLength(1);
    expect(list[0]?.id).toBe(sharedMailboxId);
    expect(list[0]?.myRights.mayReadItems).toBe(true);
    expect(list[0]?.myRights.mayAddItems).toBe(false);
    const query = response.methodResponses[1]![1] as { ids: string[] };
    expect(query.ids).toEqual([appended.messageId]);
    expect(listingCache.size).toBe(1);
    await engine.handle({ using: [MAIL_CAPABILITY], methodCalls: [["Email/query", { accountId: shared.accountId, filter: { inMailbox: sharedMailboxId } }, "cache-hit"]] }, actor.accountId);
    expect(listingCache.size).toBe(1);
    const email = response.methodResponses[2]![1] as { list: { id: string }[] };
    expect(email.list.map((item) => item.id)).toEqual([appended.messageId]);
    const thread = response.methodResponses[3]![1] as { list: { emailIds: string[] }[] };
    expect(thread.list[0]?.emailIds).toEqual([appended.messageId]);
    const queryState = (response.methodResponses[1]![1] as { queryState: string }).queryState;
    await store.setMailboxAcl(tenantId, sharedMailboxId, String(actorPrincipal[0]!.id), "lr");
    await engine.handle({ using: [MAIL_CAPABILITY], methodCalls: [["Email/query", { accountId: shared.accountId, filter: { inMailbox: sharedMailboxId } }, "acl-miss"]] }, actor.accountId);
    expect(listingCache.size).toBe(2);
    const stale = await engine.handle({ using: [MAIL_CAPABILITY], methodCalls: [["Email/changes", { accountId: shared.accountId, sinceState: queryState }, "c4"]] }, actor.accountId);
    expect(stale.methodResponses[0]).toEqual(["error", { type: "cannotCalculateChanges" }, "c4"]);
    await db.close();
  });
});
