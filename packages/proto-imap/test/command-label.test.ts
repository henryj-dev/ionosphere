/**
 * 명령 라벨 집합이 엔진과 어긋나지 않는가.
 *
 * 라벨은 닫힌 집합이라 엔진에 명령을 추가하고 여기를 잊으면 그 명령이 "unknown"으로 세어진다
 * (안전하지만 관측이 흐려진다). 그래서 엔진 소스의 명령 분기를 읽어 목록과 대조한다 —
 * 사람이 두 곳을 맞추는 규율 대신 테스트가 갈라짐을 잡는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { readFileSync } from "node:fs";
import { IMAP_COMMAND_LABELS, imapCommandLabel } from "../src/command-label.ts";

const engineSrc = readFileSync(new URL("../src/engine.ts", import.meta.url), "utf8");

/**
 * 블록을 `default:`까지 자르므로, 그 안에 중첩 switch가 생기면 그 뒤의 case가 검사에서 빠진다
 * (그래도 개수 가드는 통과해 헛되이 초록이 된다 — 검수 지적). 중첩이 생기면 이 테스트를 고치라고
 * 먼저 실패시킨다.
 */
function assertNoNestedSwitch(block: string): void {
  expect((block.match(/switch \(/g) ?? []).length).toBe(1);
}

function casesIn(block: string): string[] {
  return [...block.matchAll(/case "([A-Z]+)":/g)].map((m) => m[1]!);
}

describe("IMAP 명령 라벨", () => {
  test("★엔진이 받는 최상위 명령은 전부 라벨이 있다(UID 제외 — 하위 명령으로 센다)", () => {
    const start = engineSrc.indexOf("switch (cmd.name) {");
    const end = engineSrc.indexOf("default:", start);
    assertNoNestedSwitch(engineSrc.slice(start, end));
    const names = casesIn(engineSrc.slice(start, end)).filter((n) => n !== "UID");
    expect(names.length).toBeGreaterThan(30);
    const labels = new Set<string>(IMAP_COMMAND_LABELS);
    expect(names.filter((n) => !labels.has(n))).toEqual([]);
  });

  test("★엔진이 받는 UID 하위 명령은 전부 `UID X` 라벨이 있다", () => {
    const start = engineSrc.indexOf("private cmdUid(");
    const end = engineSrc.indexOf("default:", start);
    assertNoNestedSwitch(engineSrc.slice(start, end));
    const subs = casesIn(engineSrc.slice(start, end));
    expect(subs.length).toBeGreaterThan(5);
    const labels = new Set<string>(IMAP_COMMAND_LABELS);
    expect(subs.filter((n) => !labels.has(`UID ${n}`))).toEqual([]);
  });

  test("모르는 명령·UID 하위 명령은 unknown 하나로 묶는다(라벨이 상대 입력으로 늘지 않는다)", () => {
    expect(imapCommandLabel({ tag: "a", name: "XYZZY", args: [] })).toBe("unknown");
    expect(imapCommandLabel({ tag: "a", name: "UID", args: [{ kind: "atom", value: "BOGUS" }] })).toBe("unknown");
    expect(imapCommandLabel({ tag: "a", name: "UID", args: [{ kind: "atom", value: "fetch" }] })).toBe("UID FETCH");
    expect(imapCommandLabel({ tag: "a", name: "NOOP", args: [] })).toBe("NOOP");
  });
});
