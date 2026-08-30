import { describe, expect, test } from "@ionosphere/testkit";
import { projectHeaders, HEADER_PROJECTION_LIMITS } from "../src/header-projection.ts";
import { backfillHeaderProjection } from "../src/header-projection.ts";
import { setupFixture } from "./helpers.ts";

describe("header projection", () => {
  test("encoded-word subject와 Date를 typed 값으로 만든다", () => {
    const rows = projectHeaders("Subject: =?UTF-8?B?44GT44KT44Gr44Gh44Gv?=\r\nDate: Tue, 01 Jan 2030 00:00:00 +0000\r\nX-Private: secret\r\n\r\nbody");
    expect(rows[0]?.displayValue).toBe("こんにちは");
    expect(rows[1]?.kind).toBe("date");
    expect(rows[1]?.dateValue).toBe(1893456000000);
    expect(rows.length).toBe(2);
  });

  test("address와 Message-ID/References를 별도 typed projection으로 만든다", () => {
    const rows = projectHeaders("From: Alice <ALICE@EXAMPLE.TEST>\nTo: bob@example.test\nMessage-ID: <one@example.test>\nReferences: <zero@example.test> <one@example.test>\n\n");
    expect(rows.find((row) => row.name === "from")?.addressValue).toBe('["alice@example.test"]');
    expect(rows.find((row) => row.name === "message-id")?.kind).toBe("reference");
    expect(rows.find((row) => row.name === "references")?.addressValue).toBe('["<zero@example.test>","<one@example.test>"]');
  });

  test("접힌 header는 이어 붙이고 allowlist 밖은 저장하지 않는다", () => {
    const rows = projectHeaders("Subject: first\n second\nX-Ignored: no\n\n");
    expect(rows[0]?.displayValue).toBe("first second");
    expect(rows.some((row) => (row.name as string) === "x-ignored")).toBe(false);
  });

  test("display와 sort projection은 각각의 byte 상한을 넘지 않는다", () => {
    const rows = projectHeaders(`Subject: ${"가".repeat(20_000)}\n\n`);
    expect(new TextEncoder().encode(rows[0]!.displayValue).length).toBeLessThanOrEqual(HEADER_PROJECTION_LIMITS.displayBytes);
    expect(new TextEncoder().encode(rows[0]!.sortValue).length).toBeLessThanOrEqual(HEADER_PROJECTION_LIMITS.sortBytes);
  });

  test("header occurrence는 32개에서 잘리고 원본 해석은 계속된다", () => {
    const rows = projectHeaders(`${Array.from({ length: 40 }, (_, index) => `Received: hop-${index}`).join("\n")}\n\n`);
    expect(rows.length).toBe(32);
    expect(rows.at(-1)?.occurrence).toBe(32);
  });

  test("잘못된 Date는 null typed 값으로 남긴다", () => {
    expect(projectHeaders("Date: not-a-date\n\n")[0]?.dateValue).toBe(null);
  });

  test("backfill은 blob read 성공과 checkpoint를 한 batch로 반영한다", async () => {
    const { db, accountId } = await setupFixture();
    const messageId = "00000000000000000000000001";
    await db.batch([{ sql: "INSERT INTO messages (id, account_id, blob_id, thread_id, modseq, size_bytes, received_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", params: [messageId, accountId, "0".repeat(64), messageId, 1, 10, 1, 1] }]);
    const blobs = { put: async () => ({ blobId: "", size: 0, generation: 0 }), get: async () => new TextEncoder().encode("Subject: hello\n\nbody"), remove: async () => {} };
    expect(await backfillHeaderProjection(db, blobs)).toBe(1);
    const projection = await db.query({ sql: "SELECT display_value FROM message_header_projection WHERE message_id = ?", params: [messageId] });
    const checkpoint = await db.query({ sql: "SELECT last_message_id FROM header_backfill_checkpoints WHERE id = ?", params: ["default"] });
    expect(projection.rows[0]?.display_value).toBe("hello");
    expect(checkpoint.rows[0]?.last_message_id).toBe(messageId);
    await db.close();
  });

  test("blob read 실패 시 checkpoint가 전진하지 않는다", async () => {
    const { db, accountId } = await setupFixture();
    const messageId = "00000000000000000000000002";
    await db.batch([{ sql: "INSERT INTO messages (id, account_id, blob_id, thread_id, modseq, size_bytes, received_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", params: [messageId, accountId, "1".repeat(64), messageId, 1, 10, 1, 1] }]);
    const blobs = { put: async () => ({ blobId: "", size: 0, generation: 0 }), get: async () => { throw new Error("blob unavailable"); }, remove: async () => {} };
    await expect(backfillHeaderProjection(db, blobs)).rejects.toThrow("blob unavailable");
    const checkpoint = await db.query({ sql: "SELECT last_message_id FROM header_backfill_checkpoints WHERE id = ?", params: ["default"] });
    expect(checkpoint.rows[0]?.last_message_id).toBe("");
    await db.close();
  });
});
