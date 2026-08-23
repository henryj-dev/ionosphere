/** JMAP state + /changes (SCHEMA §6-1 dedup, changelog_floor) 스토어 레이어 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { Store } from "@ionosphere/store";

async function fresh(): Promise<{ db: DbDriver; store: Store; accountId: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
  return { db, store, accountId };
}

/** change_log에 직접 행을 심는다(모드별 스토어 연산 대신 §6-1 dedup 로직만 결정적으로 검증). */
async function log(db: DbDriver, accountId: string, entity: number, modseq: number, objectId: string, kind: number): Promise<void> {
  await db.batch([
    { sql: "INSERT INTO change_log (account_id, modseq, entity, object_id, kind, created_at) VALUES (?, ?, ?, ?, ?, 0)", params: [accountId, modseq, entity, objectId, kind] },
  ]);
}
async function setState(db: DbDriver, accountId: string, col: string, v: number): Promise<void> {
  await db.batch([{ sql: `UPDATE accounts SET ${col} = ? WHERE id = ?`, params: [v, accountId] }]);
}
const EMAIL = 0;

describe("jmapState", () => {
  test("state_* 컬럼을 문자열로", async () => {
    const { db, store, accountId } = await fresh();
    await setState(db, accountId, "state_email", 7);
    await setState(db, accountId, "state_mailbox", 3);
    const s = await store.jmapState(accountId);
    expect(s.email).toBe("7");
    expect(s.mailbox).toBe("3");
    expect(s.thread).toBe("0");
    await db.close();
  });
});

describe("jmapChanges — §6-1 dedup", () => {
  test("created+updated→created, updated→updated, updated+destroyed→destroyed, created+destroyed→생략", async () => {
    const { db, store, accountId } = await fresh();
    // A: 생성(1) 후 수정(2) → created
    await log(db, accountId, EMAIL, 1, "A", 0);
    await log(db, accountId, EMAIL, 2, "A", 1);
    // B: 수정만(3) → updated
    await log(db, accountId, EMAIL, 3, "B", 1);
    // C: 수정(4) 후 삭제(5) → destroyed
    await log(db, accountId, EMAIL, 4, "C", 1);
    await log(db, accountId, EMAIL, 5, "C", 2);
    // D: 생성(6) 후 삭제(7) → 생략(net-zero)
    await log(db, accountId, EMAIL, 6, "D", 0);
    await log(db, accountId, EMAIL, 7, "D", 2);
    await setState(db, accountId, "state_email", 7);

    const r = await store.jmapChanges(accountId, "email", "0", 100);
    expect(r.cannotCalculate).toBe(false);
    if (r.cannotCalculate) return;
    expect(r.created.sort()).toEqual(["A"]);
    expect(r.updated.sort()).toEqual(["B"]);
    expect(r.destroyed.sort()).toEqual(["C"]);
    expect(r.newState).toBe("7");
    expect(r.hasMoreChanges).toBe(false);
  });

  test("sinceState 이후만 — since=3이면 modseq>3만", async () => {
    const { db, store, accountId } = await fresh();
    await log(db, accountId, EMAIL, 1, "A", 0);
    await log(db, accountId, EMAIL, 5, "B", 0);
    await setState(db, accountId, "state_email", 5);
    const r = await store.jmapChanges(accountId, "email", "3", 100);
    if (r.cannotCalculate) throw new Error("unexpected");
    expect(r.created).toEqual(["B"]);
    expect(r.newState).toBe("5");
  });

  test("since === currentState → 빈 변경", async () => {
    const { db, store, accountId } = await fresh();
    await setState(db, accountId, "state_email", 9);
    const r = await store.jmapChanges(accountId, "email", "9", 100);
    if (r.cannotCalculate) throw new Error("unexpected");
    expect(r).toMatchObject({ created: [], updated: [], destroyed: [], newState: "9", hasMoreChanges: false });
    await db.close();
  });

  test("sinceState < changelog_floor → cannotCalculate", async () => {
    const { db, store, accountId } = await fresh();
    await setState(db, accountId, "changelog_floor", 10);
    await setState(db, accountId, "state_email", 20);
    expect((await store.jmapChanges(accountId, "email", "5", 100)).cannotCalculate).toBe(true);
    // floor 이상은 OK
    expect((await store.jmapChanges(accountId, "email", "10", 100)).cannotCalculate).toBe(false);
    await db.close();
  });

  test("미래/불량 state → cannotCalculate", async () => {
    const { db, store, accountId } = await fresh();
    await setState(db, accountId, "state_email", 5);
    expect((await store.jmapChanges(accountId, "email", "6", 100)).cannotCalculate).toBe(true); // 미래
    expect((await store.jmapChanges(accountId, "email", "abc", 100)).cannotCalculate).toBe(true); // 불량
    expect((await store.jmapChanges(accountId, "email", "-1", 100)).cannotCalculate).toBe(true);
    await db.close();
  });

  test("maxChanges — modseq 경계 페이징, 경계 안 쪼갬, 진행 보장", async () => {
    const { db, store, accountId } = await fresh();
    // modseq 1: A,B (2개)  / modseq 2: C (1개) / modseq 3: D (1개)
    await log(db, accountId, EMAIL, 1, "A", 0);
    await log(db, accountId, EMAIL, 1, "B", 0);
    await log(db, accountId, EMAIL, 2, "C", 0);
    await log(db, accountId, EMAIL, 3, "D", 0);
    await setState(db, accountId, "state_email", 3);

    // maxChanges=1이지만 modseq 1 그룹(A,B)은 통째 포함(진행 보장), 그 다음에서 중단
    const p1 = await store.jmapChanges(accountId, "email", "0", 1);
    if (p1.cannotCalculate) throw new Error("unexpected");
    expect(p1.created.sort()).toEqual(["A", "B"]);
    expect(p1.newState).toBe("1");
    expect(p1.hasMoreChanges).toBe(true);

    // 이어서 since=1 → C(modseq2)까지, D(modseq3) 남아 중단
    const p2 = await store.jmapChanges(accountId, "email", "1", 1);
    if (p2.cannotCalculate) throw new Error("unexpected");
    expect(p2.created).toEqual(["C"]);
    expect(p2.newState).toBe("2");
    expect(p2.hasMoreChanges).toBe(true);

    const p3 = await store.jmapChanges(accountId, "email", "2", 1);
    if (p3.cannotCalculate) throw new Error("unexpected");
    expect(p3.created).toEqual(["D"]);
    expect(p3.newState).toBe("3");
    expect(p3.hasMoreChanges).toBe(false);
    await db.close();
  });
});
