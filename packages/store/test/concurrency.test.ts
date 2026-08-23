import { describe, expect, test } from "@ionosphere/testkit";
import { makeAppendInput, setupFixture } from "./helpers.ts";

/**
 * 라이터 큐가 코얼레싱(§3-1)을 하면서부터 "append 1건 = modseq 1"은 더 이상 성립하지 않는다.
 * 동시에 도착한 여러 통이 한 배치로 커밋되면 그 그룹은 modseq 하나를 공유한다 —
 * modseq는 **변경(배치) 단위** 버전 카운터지 메시지 카운터가 아니다(RFC 7162도 같은 전제).
 *
 * 그래서 여기서 고정하는 건 "몇이 되는가"가 아니라 그룹 크기와 무관하게 성립해야 하는 것들이다:
 * UID 유일·연속, change_log 건수, modseq 무결(gap 없음), accounts.modseq = 최대 modseq.
 */
describe("동시성 — 계정별 라이터 큐 직렬화 (SCHEMA.md §3-1)", () => {
  test("동일 계정에 20개 동시 appendMessage → 전부 성공, UID 1..20 유일, modseq 무결", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();

    const results = await Promise.all(
      Array.from({ length: 20 }, () => store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }))),
    );

    const uids = results.map((r) => r.uids.get(inboxId)!).sort((a, b) => a - b);
    expect(uids).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect(new Set(uids).size).toBe(20);

    const { rows: acctRows } = await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [accountId] });
    const accountModseq = Number(acctRows[0]?.modseq);

    // Email created 로그는 정확히 20건. modseq는 배치 단위라 20보다 작을 수 있다(코얼레싱).
    const { rows: logRows } = await db.query({
      sql: "SELECT modseq FROM change_log WHERE account_id = ? AND entity = 0 AND kind = 0 ORDER BY modseq ASC",
      params: [accountId],
    });
    expect(logRows).toHaveLength(20);
    const modseqs = logRows.map((r) => Number(r.modseq));
    expect(modseqs).toEqual([...modseqs].sort((a, b) => a - b)); // 단조 증가

    // 배치마다 정확히 +1 — 사용된 modseq 집합은 1..N 연속이어야 한다(gap = 유실된 변경)
    const distinct = [...new Set(modseqs)].sort((a, b) => a - b);
    expect(distinct).toEqual(Array.from({ length: distinct.length }, (_, i) => i + 1));
    expect(accountModseq).toBe(distinct[distinct.length - 1]!);
    expect(accountModseq).toBeLessThanOrEqual(20);

    // 메일함 카운터도 그룹 합계로 정확해야 한다(누적 델타를 한 번에 쓰므로 회귀 위험 지점)
    const { rows: mbxRows } = await db.query({
      sql: "SELECT uidnext, total_count, unread_count, highestmodseq FROM mailboxes WHERE id = ?",
      params: [inboxId],
    });
    expect(Number(mbxRows[0]!.uidnext)).toBe(21);
    expect(Number(mbxRows[0]!.total_count)).toBe(20);
    expect(Number(mbxRows[0]!.unread_count)).toBe(20);
    expect(Number(mbxRows[0]!.highestmodseq)).toBe(accountModseq);

    const list = await store.listMessages(inboxId);
    expect(list).toHaveLength(20);

    await db.close();
  });

  test("서로 다른 두 계정으로의 append는 서로를 막지 않고 각자 정확히 직렬화됨", async () => {
    const { store, db, accountId: acctA, inboxId: inboxA, tenantId } = await setupFixture();
    const { accountId: acctB, mailboxId: inboxB } = await store.createAccount({ tenantId, email: "b@acme.test" });

    const [resA, resB] = await Promise.all([
      Promise.all(Array.from({ length: 10 }, () => store.appendMessage(makeAppendInput({ accountId: acctA, mailboxIds: [inboxA] })))),
      Promise.all(Array.from({ length: 10 }, () => store.appendMessage(makeAppendInput({ accountId: acctB, mailboxIds: [inboxB] })))),
    ]);

    const uidsA = resA.map((r) => r.uids.get(inboxA)!).sort((a, b) => a - b);
    const uidsB = resB.map((r) => r.uids.get(inboxB)!).sort((a, b) => a - b);
    expect(uidsA).toEqual(Array.from({ length: 10 }, (_, i) => i + 1));
    expect(uidsB).toEqual(Array.from({ length: 10 }, (_, i) => i + 1));

    // 계정별 큐가 독립이므로 서로의 modseq에 영향을 주지 않는다(각자 1..N 연속).
    for (const [acct, mbx] of [
      [acctA, inboxA],
      [acctB, inboxB],
    ] as const) {
      const { rows } = await db.query({ sql: "SELECT modseq FROM accounts WHERE id = ?", params: [acct] });
      const modseq = Number(rows[0]?.modseq);
      expect(modseq).toBeGreaterThan(0);
      expect(modseq).toBeLessThanOrEqual(10);
      const { rows: mbxRows } = await db.query({
        sql: "SELECT total_count, highestmodseq FROM mailboxes WHERE id = ?",
        params: [mbx],
      });
      expect(Number(mbxRows[0]!.total_count)).toBe(10);
      expect(Number(mbxRows[0]!.highestmodseq)).toBe(modseq);
    }

    await db.close();
  });

  test("코얼레싱이 실제로 일어난다 — 동시 20건이 20배치보다 적게 커밋된다", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    await Promise.all(
      Array.from({ length: 20 }, () => store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] }))),
    );
    // 배치 수 = modseq_claims 행 수. 코얼레싱이 없으면 정확히 20이다.
    const { rows } = await db.query({
      sql: "SELECT COUNT(*) AS n FROM modseq_claims WHERE account_id = ?",
      params: [accountId],
    });
    expect(Number(rows[0]!.n)).toBeLessThan(20);
    await db.close();
  });

  test("그룹 안의 한 건이 실패해도 나머지는 성공한다 — 코얼레싱은 결과를 바꾸지 않는다", async () => {
    const { store, db, accountId, inboxId } = await setupFixture();
    // 존재하지 않는 메일함을 섞는다. 그룹이 통째로 실패하면 개별 재실행으로 성패가 갈려야 한다.
    const settled = await Promise.allSettled([
      store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] })),
      store.appendMessage(makeAppendInput({ accountId, mailboxIds: ["NOPE".padEnd(26, "0")] })),
      store.appendMessage(makeAppendInput({ accountId, mailboxIds: [inboxId] })),
    ]);
    expect(settled.map((s) => s.status)).toEqual(["fulfilled", "rejected", "fulfilled"]);

    const list = await store.listMessages(inboxId);
    expect(list).toHaveLength(2); // 실패한 한 건만 빠진다
    await db.close();
  });
});
