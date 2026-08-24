/**
 * 마이그레이션 락 하트비트.
 *
 * 과거 결함: `staleMs`(기본 5분)는 "죽은 프로세스의 락을 뺏는" 장치인데 갱신이 없어서
 * **살아서 마이그레이션을 돌리는 중인 프로세스의 락도 그 시간이 지나면 뺏겼다.** 그러면
 * 락이 막으려던 바로 그 상황(동시 DDL)이 벌어진다 — 003·006처럼 `DROP` + `RENAME`을 쓰는
 * 재빌드가 겹치면 한쪽이 원본을 DROP한 사이 다른 쪽이 그 원본을 읽어 데이터가 사라진다.
 * 대형 재빌드일수록 위험이 커지는 구조라, 시간이 아니라 **생존 신호**로 판정해야 한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { migrate, openSqlite, type DbDriver, type Migration, type Statement } from "@ionosphere/db";

/** DDL 한 문장마다 지연을 넣어 "오래 걸리는 마이그레이션"을 만든다. */
function slowDriver(inner: DbDriver, delayMs: number): DbDriver {
  return {
    dialect: inner.dialect,
    query: (stmt: Statement) => inner.query(stmt),
    async batch(stmts: readonly Statement[]) {
      // 이 마이그레이션의 문장만 느리게 한다(락 획득·버전 기록은 그대로 빨라야 판정이 깨끗하다).
      const isDdl = stmts.some((s) => /CREATE TABLE IF NOT EXISTS slow_/i.test(s.sql));
      if (isDdl) await new Promise((r) => setTimeout(r, delayMs));
      return inner.batch(stmts);
    },
    insertIgnore: (table, columns) => inner.insertIgnore(table, columns),
    close: () => inner.close(),
  };
}

const slowMigration: Migration = {
  version: 9001,
  name: "slow-rebuild",
  statements: [
    "CREATE TABLE IF NOT EXISTS slow_a (id VARCHAR(26) PRIMARY KEY)",
    "CREATE TABLE IF NOT EXISTS slow_b (id VARCHAR(26) PRIMARY KEY)",
    "CREATE TABLE IF NOT EXISTS slow_c (id VARCHAR(26) PRIMARY KEY)",
  ],
};

describe("마이그레이션 락", () => {
  test("오래 걸리는 마이그레이션 중에도 리스가 갱신된다(뺏기지 않는다)", async () => {
    const inner = await openSqlite();
    // 문장당 120ms × 3문장 = 약 360ms. staleMs를 150으로 낮춰 "실행 시간 > staleMs"를 만든다.
    const db = slowDriver(inner, 120);
    const staleMs = 150;

    const started = Date.now();
    const applied = await migrate(db, [slowMigration], { owner: "runner-A", staleMs, pollMs: 10 });
    expect(applied).toBe(1);

    // 하트비트가 없으면 acquired_at이 획득 시점 그대로라, 실행 도중 stale로 판정돼 뺏힌다.
    // 여기서는 락이 해제된 뒤라 행이 없어야 하고(정상 종료), 실행 시간이 staleMs를 넘겼음을 확인한다.
    expect(Date.now() - started).toBeGreaterThan(staleMs);
    const { rows } = await db.query({ sql: "SELECT id FROM schema_lock" });
    expect(rows).toHaveLength(0); // 자기 락을 정상 해제

    await db.close();
  });

  /**
   * ★임계값에 **여유**를 둔다(2026-08-24 수정). 예전엔 `staleMs = 150`이었는데, 하트비트
   * 주기가 `staleMs/3 = 50ms`이고 그 갱신 질의 자체가 느린 드라이버를 타 120ms가 걸린다 —
   * 실제 간격이 170ms라 **부하가 없어도 아슬아슬**했고 전체 스위트에서 산발적으로 터졌다.
   * 여유를 주면 "하트비트가 도는가"를 재고, 안 주면 "이 머신이 지금 한가한가"를 잰다.
   */
  test("실행 중 다른 인스턴스가 stale로 판정해 뺏지 못한다", async () => {
    const inner = await openSqlite();
    /**
     * 문장당 400ms × 3 = 약 1.2초 — `staleMs`(900ms)를 **확실히 넘겨야** "안 뺏겼다"가
     * 하트비트 덕분이라는 뜻이 된다. 실행이 창보다 짧으면 갱신이 없어도 안 뺏긴다.
     */
    const db = slowDriver(inner, 400);
    // 하트비트 주기 300ms + 갱신 질의(느리지 않다) ≈ 300ms 간격 — 900ms 창 안에 넉넉히 든다.
    const staleMs = 900;

    // A가 도는 동안 B가 계속 획득을 시도한다. 하트비트가 없으면 staleMs 경과 후 B가 성공한다.
    /** 하트비트 UPDATE가 몇 번 돌았나 — 이 값이 0이면 "안 뺏겼다"는 우연이다. */
    let renewals = 0;
    const observed: DbDriver = {
      ...db,
      async batch(stmts: readonly Statement[]) {
        if (stmts.some((st) => /UPDATE schema_lock SET acquired_at/i.test(st.sql))) renewals += 1;
        return db.batch(stmts);
      },
    };
    const runA = migrate(observed, [slowMigration], { owner: "runner-A", staleMs, pollMs: 10 });

    let stolen = false;
    const probe = (async (): Promise<void> => {
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 20));
        const [res] = await inner.batch([
          {
            sql: "UPDATE schema_lock SET owner = 'thief', acquired_at = ? WHERE id = 'migrate' AND acquired_at < ?",
            params: [Date.now(), Date.now() - staleMs],
          },
        ]);
        if ((res?.changes ?? 0) === 1) {
          stolen = true;
          return;
        }
      }
    })();

    await runA;
    await probe;

    expect(stolen).toBe(false);
    // ★뺏기지 않은 것만으로는 부족하다 — 하트비트가 **실제로 돌았는지**를 함께 본다.
    //   갱신이 없어도 실행이 창보다 짧으면 안 뺏기므로, 그 갈래를 배제한다.
    expect(renewals).toBeGreaterThan(0);
    await db.close();
  });
});
