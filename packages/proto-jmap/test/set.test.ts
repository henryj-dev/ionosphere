/** 표준 /set 헬퍼(RFC 8620 §5.3) — 가짜 소스로 봉투·SetError·ifInState·createdIds 검증. */
import { describe, expect, test } from "@ionosphere/testkit";
import { standardSet, SetItemError, type SetSource } from "../src/set.ts";
import type { MethodContext } from "../src/types.ts";

const ACC = "acc1";
function ctx(): MethodContext {
  return { accountId: ACC, createdIds: {} };
}

/** 인메모리 소스 — 생성 시 seq id, 특정 이름은 SetItemError. */
function memSource(state = "0"): SetSource & { store: Map<string, Record<string, unknown>>; seq: number } {
  const store = new Map<string, Record<string, unknown>>();
  const self = {
    store,
    seq: 0,
    state: async () => state,
    create: async (_a: string, props: Record<string, unknown>) => {
      if (props.name === "BAD") throw new SetItemError("invalidProperties", { properties: ["name"] });
      const id = `id${++self.seq}`;
      store.set(id, { ...props });
      return { id, serverProps: { id } };
    },
    update: async (_a: string, id: string, patch: Record<string, unknown>) => {
      const cur = store.get(id);
      if (!cur) throw new SetItemError("notFound");
      store.set(id, { ...cur, ...patch });
      return null;
    },
    destroy: async (_a: string, id: string) => {
      if (!store.has(id)) throw new SetItemError("notFound");
      store.delete(id);
    },
  };
  return self;
}

describe("standardSet", () => {
  test("create — created + createdIds 갱신", async () => {
    const src = memSource();
    const c = ctx();
    const r = await standardSet({ accountId: ACC, create: { tmp1: { name: "Work" } } }, ACC, c, src);
    expect((r.created as Record<string, { id: string }>).tmp1!.id).toBe("id1");
    expect(c.createdIds.tmp1).toBe("id1"); // 이후 참조 가능
    expect(r.notCreated).toEqual({});
  });

  test("create 실패 → notCreated에 SetError", async () => {
    const r = await standardSet({ accountId: ACC, create: { t: { name: "BAD" } } }, ACC, ctx(), memSource());
    expect(r.created).toEqual({});
    expect((r.notCreated as Record<string, { type: string }>).t!.type).toBe("invalidProperties");
  });

  test("update #creationId 해석 — 같은 요청 내 생성분 참조", async () => {
    const src = memSource();
    const r = await standardSet(
      { accountId: ACC, create: { tmp: { name: "A" } }, update: { "#tmp": { name: "B" } } },
      ACC,
      ctx(),
      src,
    );
    expect(Object.keys(r.created as object)).toEqual(["tmp"]);
    expect(src.store.get("id1")!.name).toBe("B"); // 생성 후 즉시 수정 반영
  });

  test("destroy + 미해석 creationId → notDestroyed", async () => {
    const src = memSource();
    const c = ctx();
    await standardSet({ accountId: ACC, create: { a: { name: "X" } } }, ACC, c, src);
    const r = await standardSet({ accountId: ACC, destroy: ["id1", "#ghost"] }, ACC, c, src);
    expect(r.destroyed).toEqual(["id1"]);
    expect((r.notDestroyed as Record<string, { type: string }>)["#ghost"]!.type).toBe("notFound");
  });

  test("ifInState 불일치 → stateMismatch(MethodError)", async () => {
    await expect(standardSet({ accountId: ACC, ifInState: "99", create: {} }, ACC, ctx(), memSource("5"))).rejects.toMatchObject({
      type: "stateMismatch",
    });
  });

  test("ifInState 일치 → 정상 진행, oldState/newState 포함", async () => {
    const r = await standardSet({ accountId: ACC, ifInState: "5", create: { a: { name: "Y" } } }, ACC, ctx(), memSource("5"));
    expect(r.oldState).toBe("5");
    expect(r.newState).toBe("5");
    expect(r.notCreated).toEqual({});
  });

  test("소스가 create 미지원 → forbidden", async () => {
    const src: SetSource = { state: async () => "0" };
    const r = await standardSet({ accountId: ACC, create: { a: {} } }, ACC, ctx(), src);
    expect((r.notCreated as Record<string, { type: string }>).a!.type).toBe("forbidden");
  });

  test("예기치 못한 예외 → serverFail SetError(요청 전체는 안 죽음)", async () => {
    const src: SetSource = {
      state: async () => "0",
      create: async () => {
        throw new Error("boom");
      },
    };
    const r = await standardSet({ accountId: ACC, create: { a: {} } }, ACC, ctx(), src);
    expect((r.notCreated as Record<string, { type: string }>).a!.type).toBe("serverFail");
  });
});
