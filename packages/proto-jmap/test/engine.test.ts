/** JmapEngine 디스패치·백레퍼런스·에러·Core/echo 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { JmapEngine } from "../src/engine.ts";
import { coreModule } from "../src/core.ts";
import { CORE_CAPABILITY, MAIL_CAPABILITY } from "../src/session.ts";
import { MethodError, RequestError, type CapabilityModule, type JmapRequest } from "../src/types.ts";

const ACCOUNT = "acc1";

/** 테스트용 Mail 모듈 — Mailbox/get은 고정 목록, Foo/fail은 MethodError. */
const mailModule: CapabilityModule = {
  capability: MAIL_CAPABILITY,
  methods: {
    "Mailbox/get": async (args) => ({
      accountId: args.accountId,
      state: "s1",
      list: [
        { id: "mb1", name: "INBOX" },
        { id: "mb2", name: "Sent" },
      ],
      notFound: [],
    }),
    "Email/get": async (args) => ({ accountId: args.accountId, state: "e1", list: [], notFound: args.ids ?? [] }),
    "Foo/fail": async () => {
      throw new MethodError("forbidden", { description: "nope" });
    },
    "Foo/boom": async () => {
      throw new Error("unexpected");
    },
  },
};

function engine(): JmapEngine {
  return new JmapEngine({
    modules: [coreModule, mailModule],
    capabilities: [CORE_CAPABILITY, MAIL_CAPABILITY],
    sessionState: () => "sess-1",
  });
}

function req(methodCalls: JmapRequest["methodCalls"], using: string[] = [CORE_CAPABILITY, MAIL_CAPABILITY]): JmapRequest {
  return { using, methodCalls };
}

describe("Core/echo + 봉투", () => {
  test("echo는 인자 그대로, sessionState 포함", async () => {
    const res = await engine().handle(req([["Core/echo", { hello: "world", n: 1 }, "c0"]]), ACCOUNT);
    expect(res.methodResponses).toEqual([["Core/echo", { hello: "world", n: 1 }, "c0"]]);
    expect(res.sessionState).toBe("sess-1");
  });

  test("여러 호출 순서대로 응답", async () => {
    const res = await engine().handle(
      req([
        ["Core/echo", { a: 1 }, "c0"],
        ["Mailbox/get", { accountId: ACCOUNT, ids: null }, "c1"],
      ]),
      ACCOUNT,
    );
    expect(res.methodResponses.map((r) => r[2])).toEqual(["c0", "c1"]);
    expect(res.methodResponses[1]![0]).toBe("Mailbox/get");
  });
});

describe("백레퍼런스", () => {
  test("앞선 Mailbox/get 결과의 /list/*/id를 뒤 호출 ids로 치환", async () => {
    const res = await engine().handle(
      req([
        ["Mailbox/get", { accountId: ACCOUNT, ids: null }, "c0"],
        ["Email/get", { accountId: ACCOUNT, "#ids": { resultOf: "c0", name: "Mailbox/get", path: "/list/*/id" } }, "c1"],
      ]),
      ACCOUNT,
    );
    // Email/get이 ids=["mb1","mb2"]를 받아 notFound로 되돌려줌(테스트 핸들러)
    expect(res.methodResponses[1]).toEqual(["Email/get", { accountId: ACCOUNT, state: "e1", list: [], notFound: ["mb1", "mb2"] }, "c1"]);
  });

  test("resultOf 이름 불일치·경로 없음 → invalidResultReference", async () => {
    const wrongName = await engine().handle(
      req([
        ["Mailbox/get", { accountId: ACCOUNT }, "c0"],
        ["Email/get", { "#ids": { resultOf: "c0", name: "Email/get", path: "/list/*/id" } }, "c1"],
      ]),
      ACCOUNT,
    );
    expect(wrongName.methodResponses[1]).toEqual(["error", { type: "invalidResultReference", description: "resultOf=c0 name=Email/get" }, "c1"]);

    const badPath = await engine().handle(
      req([
        ["Mailbox/get", { accountId: ACCOUNT }, "c0"],
        ["Email/get", { "#ids": { resultOf: "c0", name: "Mailbox/get", path: "/nope" } }, "c1"],
      ]),
      ACCOUNT,
    );
    expect(badPath.methodResponses[1]![0]).toBe("error");
    expect((badPath.methodResponses[1]![1] as { type: string }).type).toBe("invalidResultReference");
  });
});

describe("에러 처리", () => {
  test("미등록 메서드 → unknownMethod", async () => {
    const res = await engine().handle(req([["Nope/nope", {}, "c0"]]), ACCOUNT);
    expect(res.methodResponses[0]).toEqual(["error", { type: "unknownMethod" }, "c0"]);
  });

  test("using에 없는 capability의 메서드 → unknownMethod", async () => {
    const res = await engine().handle(req([["Mailbox/get", { accountId: ACCOUNT }, "c0"]], [CORE_CAPABILITY]), ACCOUNT);
    expect(res.methodResponses[0]).toEqual(["error", { type: "unknownMethod" }, "c0"]);
  });

  test("MethodError → error invocation(부가필드 포함), 뒤 호출은 계속", async () => {
    const res = await engine().handle(
      req([
        ["Foo/fail", {}, "c0"],
        ["Core/echo", { ok: true }, "c1"],
      ]),
      ACCOUNT,
    );
    expect(res.methodResponses[0]).toEqual(["error", { type: "forbidden", description: "nope" }, "c0"]);
    expect(res.methodResponses[1]).toEqual(["Core/echo", { ok: true }, "c1"]);
  });

  test("핸들러의 예기치 못한 예외 → serverFail(요청 전체는 안 죽음)", async () => {
    const res = await engine().handle(req([["Foo/boom", {}, "c0"]]), ACCOUNT);
    expect(res.methodResponses[0]).toEqual(["error", { type: "serverFail" }, "c0"]);
  });

  test("미지원 capability 요청 → RequestError(unknownCapability)", async () => {
    await expect(engine().handle(req([["Core/echo", {}, "c0"]], ["urn:bogus"]), ACCOUNT)).rejects.toBeInstanceOf(RequestError);
  });

  test("maxCalls 초과 → RequestError(limit)", async () => {
    const e = new JmapEngine({ modules: [coreModule], capabilities: [CORE_CAPABILITY], sessionState: () => "s", maxCalls: 2 });
    const calls: JmapRequest["methodCalls"] = [
      ["Core/echo", {}, "c0"],
      ["Core/echo", {}, "c1"],
      ["Core/echo", {}, "c2"],
    ];
    await expect(e.handle(req(calls, [CORE_CAPABILITY]), ACCOUNT)).rejects.toBeInstanceOf(RequestError);
  });
});
