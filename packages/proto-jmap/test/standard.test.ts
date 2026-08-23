/** 표준 /get·/changes 헬퍼 테스트 (RFC 8620 §5.1/§5.2) — 가짜 소스로 순수 검증. */
import { describe, expect, test } from "@ionosphere/testkit";
import { standardGet, standardChanges, type ChangesResult, type GetSource, type JmapObject } from "../src/standard.ts";
import { MethodError } from "../src/types.ts";

const ACC = "acc1";
const OBJECTS: JmapObject[] = [
  { id: "m1", name: "INBOX", role: "inbox", sortOrder: 1 },
  { id: "m2", name: "Sent", role: "sent", sortOrder: 2 },
];

const getSource: GetSource = {
  state: async () => "s5",
  get: async (_acc, ids) => {
    if (ids === null) return { list: OBJECTS, notFound: [] };
    const list = OBJECTS.filter((o) => ids.includes(o.id));
    const found = new Set(list.map((o) => o.id));
    return { list, notFound: ids.filter((i) => !found.has(i)) };
  },
};

describe("standardGet", () => {
  test("ids=null → 전체 + state", async () => {
    const r = await standardGet({ accountId: ACC, ids: null }, ACC, getSource);
    expect(r.accountId).toBe(ACC);
    expect(r.state).toBe("s5");
    expect((r.list as JmapObject[]).map((o) => o.id)).toEqual(["m1", "m2"]);
    expect(r.notFound).toEqual([]);
  });

  test("특정 ids + notFound", async () => {
    const r = await standardGet({ accountId: ACC, ids: ["m2", "ghost"] }, ACC, getSource);
    expect((r.list as JmapObject[]).map((o) => o.id)).toEqual(["m2"]);
    expect(r.notFound).toEqual(["ghost"]);
  });

  test("properties 필터 — id는 항상 포함", async () => {
    const r = await standardGet({ accountId: ACC, ids: ["m1"], properties: ["name"] }, ACC, getSource);
    expect(r.list).toEqual([{ id: "m1", name: "INBOX" }]);
  });

  test("accountId 불일치 → accountNotFound", async () => {
    await expect(standardGet({ accountId: "other" }, ACC, getSource)).rejects.toMatchObject({ type: "accountNotFound" });
  });

  test("accountId 누락·잘못된 ids 타입 → invalidArguments", async () => {
    await expect(standardGet({}, ACC, getSource)).rejects.toMatchObject({ type: "invalidArguments" });
    await expect(standardGet({ accountId: ACC, ids: [1, 2] }, ACC, getSource)).rejects.toBeInstanceOf(MethodError);
  });
});

describe("standardChanges", () => {
  const ok: ChangesResult = { cannotCalculate: false, oldState: "3", newState: "7", hasMoreChanges: true, created: ["a"], updated: ["b"], destroyed: [] };
  const source = (r: ChangesResult, capture?: (max: number) => void) => ({
    changes: async (_a: string, _s: string, max: number) => {
      capture?.(max);
      return r;
    },
  });

  test("정상 변경 셋 반환", async () => {
    const r = await standardChanges({ accountId: ACC, sinceState: "3" }, ACC, source(ok));
    expect(r).toEqual({ accountId: ACC, oldState: "3", newState: "7", hasMoreChanges: true, created: ["a"], updated: ["b"], destroyed: [] });
  });

  test("maxChanges 기본값 500, 지정 시 전달", async () => {
    let seen = -1;
    await standardChanges({ accountId: ACC, sinceState: "0" }, ACC, source(ok, (m) => (seen = m)));
    expect(seen).toBe(500);
    await standardChanges({ accountId: ACC, sinceState: "0", maxChanges: 10 }, ACC, source(ok, (m) => (seen = m)));
    expect(seen).toBe(10);
  });

  test("cannotCalculate → cannotCalculateChanges", async () => {
    await expect(standardChanges({ accountId: ACC, sinceState: "0" }, ACC, source({ cannotCalculate: true }))).rejects.toMatchObject({
      type: "cannotCalculateChanges",
    });
  });

  test("sinceState 누락·maxChanges 불량 → invalidArguments", async () => {
    await expect(standardChanges({ accountId: ACC }, ACC, source(ok))).rejects.toMatchObject({ type: "invalidArguments" });
    await expect(standardChanges({ accountId: ACC, sinceState: "0", maxChanges: 0 }, ACC, source(ok))).rejects.toMatchObject({ type: "invalidArguments" });
  });
});
