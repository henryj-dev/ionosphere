/**
 * 베이즈 토큰 저장소 — `BayesStore` 계약이 실제 DB에서 성립하는지.
 *
 * 분류 로직은 `packages/spam`이 덮는다. 여기서 보는 것은 **계정 경계**와 **누적**이다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { classify, hashTokens, train } from "@ionosphere/spam";
import { createBayesStore } from "../src/bayes-store.ts";

async function freshStore(): Promise<{ db: Awaited<ReturnType<typeof openSqlite>>; store: ReturnType<typeof createBayesStore> }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  return { db, store: createBayesStore(db) };
}

describe("createBayesStore", () => {
  test("학습이 누적되고 카운트를 되읽는다", async () => {
    const { db, store } = await freshStore();
    const toks = hashTokens("s", ["alpha", "beta"]);
    await store.train("a1", toks, "spam");
    await store.train("a1", toks, "spam");
    await store.train("a1", toks, "ham");

    const counts = await store.counts("a1", toks);
    expect(counts.get(toks[0]!)).toEqual({ spam: 2, ham: 1 });
    expect(await store.totals("a1")).toEqual({ spam: 2, ham: 1 });
    await db.close();
  });

  test("★계정 경계를 넘지 않는다", async () => {
    const { db, store } = await freshStore();
    const toks = hashTokens("s", ["shared-word"]);
    await store.train("a1", toks, "spam");

    // 다른 계정에서는 보이지 않아야 한다 — 한 사람의 메일이 다른 사람의 판정에 영향을 주면 안 된다.
    expect((await store.counts("a2", toks)).size).toBe(0);
    expect(await store.totals("a2")).toEqual({ spam: 0, ham: 0 });
    await db.close();
  });

  test("모르는 토큰은 결과에서 빠진다(0으로 만들어내지 않는다)", async () => {
    const { db, store } = await freshStore();
    await store.train("a1", hashTokens("s", ["known"]), "spam");
    const unknown = hashTokens("s", ["never-seen"]);
    expect((await store.counts("a1", unknown)).size).toBe(0);
    await db.close();
  });

  test("★토큰이 많아도 한 번에 처리된다 (파라미터 한도 분할)", async () => {
    const { db, store } = await freshStore();
    // D1의 문장당 파라미터 한도(100)를 넘는 양 — 분할이 없으면 여기서 깨진다.
    const many = hashTokens("s", Array.from({ length: 500 }, (_, i) => `t${i}`));
    await store.train("a1", many, "spam");
    const got = await store.counts("a1", many);
    expect(got.size).toBe(many.length);
    await db.close();
  });

  test("★실제 DB로 학습 → 분류가 끝까지 동작한다", async () => {
    const { db, store } = await freshStore();
    const SALT = "a1";
    for (let i = 0; i < 8; i++) await train(store, "a1", SALT, "무료 대출 지금 신청 viagra cheap", "spam");
    for (let i = 0; i < 8; i++) await train(store, "a1", SALT, "회의 일정 공유 meeting agenda", "ham");

    const spam = await classify(store, "a1", SALT, "무료 대출 viagra");
    expect(spam.probability).not.toBeNull();
    expect(spam.probability!).toBeGreaterThan(0.5);
    await db.close();
  });
});
