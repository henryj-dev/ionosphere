/**
 * 프로토타입 체인에 닿는 키에 대한 심층방어(감사 L-11).
 *
 * 2026-07-30 감사 판정은 "현재 영향 없음"이었다 — 오염되는 것은 전부 per-call 객체이고
 * 전역 `Object.prototype`은 무사하며, 이 값으로 뒤집을 보안 플래그·상한이 없다.
 * 그래도 막아 둔 이유는 **인자 객체에 플래그 하나만 늘어나면 그날부터 우회 경로**이기 때문이고,
 * 이 파일은 그 방어가 조용히 빠지지 않게 붙잡아 두는 자리다.
 *
 * 마지막 테스트가 가장 중요하다: 전역 `Object.prototype`은 어느 경로로도 오염되지 않는다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { evalPointer } from "../src/pointer.ts";
import { standardSet, type SetSource } from "../src/set.ts";
import { JmapEngine } from "../src/engine.ts";
import { MethodError, type CapabilityModule, type MethodContext } from "../src/types.ts";

const ACC = "acc1";
const CAP = "urn:test";

function ctx(): MethodContext {
  return { accountId: ACC, createdIds: {} };
}

/** 받은 인자를 그대로 되돌려주는 모듈 — 백레퍼런스 해석 결과를 눈으로 보기 위한 것. */
function echoModule(): CapabilityModule {
  return {
    capability: CAP,
    methods: {
      "Echo/get": async (args: Record<string, unknown>) => ({ ...args, list: [{ id: "m1" }] }),
    },
  };
}

function engine(): JmapEngine {
  return new JmapEngine({ modules: [echoModule()], capabilities: [CAP], sessionState: () => "0" });
}

/**
 * ★객체 리터럴로는 이 테스트를 쓸 수 없다 — `{ __proto__: x }`는 **키를 만들지 않고
 * 프로토타입을 지정하는 문법**이라 `Object.entries`에 아예 안 잡힌다. 반면 `JSON.parse`는
 * `__proto__`를 평범한 소유 키로 만든다. 그리고 실제 입력은 언제나 후자다(HTTP 본문 파싱).
 * 즉 리터럴로 짠 테스트는 통과하면서 진짜 경로는 하나도 안 건드린다.
 */
function fromJson(json: string): Record<string, unknown> {
  return JSON.parse(json) as Record<string, unknown>;
}

describe("JSON 포인터는 상속 프로퍼티를 따라가지 않는다", () => {
  const doc = { list: [{ id: "m1" }] };

  test("/__proto__ · /constructor는 undefined(=invalidResultReference)", () => {
    // `token in value`였다면 둘 다 참이라 Object.prototype·생성자 함수가 그대로 흘러나왔다.
    expect(evalPointer(doc, "/__proto__")).toBeUndefined();
    expect(evalPointer(doc, "/constructor")).toBeUndefined();
    expect(evalPointer(doc, "/list/0/__proto__")).toBeUndefined();
    expect(evalPointer(doc, "/constructor/prototype")).toBeUndefined();
  });

  test("정상 경로는 그대로 동작한다", () => {
    expect(evalPointer(doc, "/list/0/id")).toBe("m1");
    expect(evalPointer(doc, "/list/*/id")).toEqual(["m1"]);
  });
});

describe("메서드 인자 이름", () => {
  test("__proto__ 인자는 invalidArguments로 거절된다", async () => {
    const res = await engine().handle(
      { using: [CAP], methodCalls: [["Echo/get", fromJson(`{"accountId":"${ACC}","__proto__":{"polluted":true}}`), "c0"]] },
      ACC,
    );
    const [name, args] = res.methodResponses[0]!;
    expect(name).toBe("error");
    expect((args as { type: string }).type).toBe("invalidArguments");
  });

  test("백레퍼런스 이름(#__proto__)도 거절된다", async () => {
    const res = await engine().handle(
      {
        using: [CAP],
        methodCalls: [
          ["Echo/get", { accountId: ACC }, "c0"],
          [
            "Echo/get",
            fromJson(`{"accountId":"${ACC}","#__proto__":{"resultOf":"c0","name":"Echo/get","path":"/list"}}`),
            "c1",
          ],
        ],
      },
      ACC,
    );
    const [name, args] = res.methodResponses[1]!;
    expect(name).toBe("error");
    expect((args as { type: string }).type).toBe("invalidArguments");
  });

  test("평범한 인자 이름은 그대로 통과한다 — 가드가 과하지 않은지", async () => {
    const res = await engine().handle({ using: [CAP], methodCalls: [["Echo/get", { accountId: ACC, ids: ["x"] }, "c0"]] }, ACC);
    const [name, args] = res.methodResponses[0]!;
    expect(name).toBe("Echo/get");
    expect((args as { ids: string[] }).ids).toEqual(["x"]);
  });
});

describe("standardSet의 creationId", () => {
  function source(): SetSource {
    return {
      state: async () => "0",
      create: async (_a, props) => ({ id: "id1", serverProps: { id: "id1", ...props } }),
      update: async () => null,
      destroy: async () => {},
    };
  }

  test("__proto__ creationId는 notCreated로 **보고된다**(조용히 사라지지 않는다)", async () => {
    const out = await standardSet(fromJson(`{"accountId":"${ACC}","create":{"__proto__":{"name":"x"}}}`), ACC, ctx(), source());

    // 집계 객체가 평범한 `{}`였다면 이 대입이 프로토타입 교체가 돼 키 자체가 남지 않았다.
    const notCreated = out.notCreated as Record<string, { type: string }>;
    expect(Object.keys(notCreated)).toEqual(["__proto__"]);
    expect(notCreated["__proto__"]!.type).toBe("invalidProperties");
    expect(Object.keys(out.created as object)).toHaveLength(0);
  });

  test("#__proto__ 참조는 미해석 creationId(notFound)로 떨어진다", async () => {
    // 예전엔 `createdIds["__proto__"]`가 Object.prototype을 돌려줘, 타입이 string인 자리에
    // 객체가 흘러 소스의 update(acc, id, …)까지 내려갔다.
    const out = await standardSet({ accountId: ACC, update: { "#__proto__": { name: "y" } } }, ACC, ctx(), source());

    const notUpdated = out.notUpdated as Record<string, { type: string }>;
    expect(notUpdated["#__proto__"]!.type).toBe("notFound");
    expect(Object.keys(out.updated as object)).toHaveLength(0);
  });

  test("정상 creationId와 #참조는 그대로 동작한다", async () => {
    const c = ctx();
    const created = await standardSet({ accountId: ACC, create: { a: { name: "x" } } }, ACC, c, source());
    expect((created.created as Record<string, { id: string }>)["a"]!.id).toBe("id1");
    expect(c.createdIds["a"]).toBe("id1");

    const updated = await standardSet({ accountId: ACC, update: { "#a": { name: "y" } } }, ACC, c, source());
    expect(Object.keys(updated.updated as object)).toEqual(["id1"]);
  });

  test("응답이 JSON으로 그대로 나간다 — 프로토타입 없는 객체를 써도 직렬화가 깨지지 않는다", async () => {
    const out = await standardSet({ accountId: ACC, create: { a: { name: "x" } } }, ACC, ctx(), source());
    const round = JSON.parse(JSON.stringify(out)) as { created: Record<string, unknown> };
    expect(Object.keys(round.created)).toEqual(["a"]);
  });
});

describe("전역 Object.prototype", () => {
  afterEach(() => {
    // 오염이 새면 다른 테스트 파일까지 오염된 채로 돈다 — 여기서 확실히 지운다.
    delete (Object.prototype as Record<string, unknown>)["polluted"];
  });

  test("어느 경로로도 오염되지 않는다", async () => {
    const poison = `{"accountId":"${ACC}","__proto__":{"polluted":1}}`;
    await engine().handle({ using: [CAP], methodCalls: [["Echo/get", fromJson(poison), "c0"]] }, ACC);
    await standardSet(fromJson(`{"accountId":"${ACC}","create":{"__proto__":{"polluted":1}}}`), ACC, ctx(), {
      state: async () => "0",
      create: async () => ({ id: "id1", serverProps: {} }),
    });
    evalPointer({ list: [] }, "/__proto__/polluted");

    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(MethodError.prototype).toBeDefined(); // 참조만 — 위 경로들이 클래스 프로토타입에 손대지 않는다
  });
});
