/** ResultReference 언랩 + JSON 포인터(RFC 6901 + JMAP `*`) 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { asResultReference, evalPointer } from "../src/pointer.ts";

describe("asResultReference", () => {
  test("정상 ResultReference 값 검증", () => {
    const rr = asResultReference({ resultOf: "c0", name: "Mailbox/get", path: "/list/*/id" });
    expect(rr).toEqual({ resultOf: "c0", name: "Mailbox/get", path: "/list/*/id" });
  });

  test("형태 불일치는 null", () => {
    expect(asResultReference({ ids: ["x"] })).toBeNull();
    expect(asResultReference(["a"])).toBeNull();
    expect(asResultReference("s")).toBeNull();
    expect(asResultReference({ resultOf: "c0" })).toBeNull(); // name/path 누락
    expect(asResultReference({ resultOf: "c0", name: "M/get", path: 3 })).toBeNull(); // path 타입 오류
  });
});

describe("evalPointer", () => {
  const doc = {
    list: [
      { id: "m1", role: "inbox" },
      { id: "m2", role: null },
    ],
    accountId: "a1",
    nested: { deep: [1, 2, 3] },
  };

  test("객체/배열 인덱스 경로", () => {
    expect(evalPointer(doc, "/accountId")).toBe("a1");
    expect(evalPointer(doc, "/list/0/id")).toBe("m1");
    expect(evalPointer(doc, "/nested/deep/2")).toBe(3);
  });

  test("`*` 배열 순회 + 평탄화", () => {
    expect(evalPointer(doc, "/list/*/id")).toEqual(["m1", "m2"]);
  });

  test("빈 경로는 루트, 없는 경로는 undefined", () => {
    expect(evalPointer(doc, "")).toBe(doc);
    expect(evalPointer(doc, "/nope")).toBeUndefined();
    expect(evalPointer(doc, "/list/9/id")).toBeUndefined();
    expect(evalPointer(doc, "no-slash")).toBeUndefined();
  });

  test("~1/~0 이스케이프", () => {
    expect(evalPointer({ "a/b": 1, "c~d": 2 }, "/a~1b")).toBe(1);
    expect(evalPointer({ "a/b": 1, "c~d": 2 }, "/c~0d")).toBe(2);
  });
});
