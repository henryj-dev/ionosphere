/** 자격증명 만료 타이머 — 만료 시각에 한 번 부르고, 연결이 먼저 닫히면 부르지 않는다. */
import { describe, expect, test } from "@ionosphere/testkit";
import { EventEmitter } from "node:events";
import { armAuthExpiry } from "@ionosphere/core";

function fakeSocket(): EventEmitter & { destroyed: boolean } {
  return Object.assign(new EventEmitter(), { destroyed: false });
}

describe("armAuthExpiry", () => {
  test("만료 시각에 onExpire를 부른다", async () => {
    const s = fakeSocket();
    let fired = 0;
    armAuthExpiry(s, Date.now() + 50, () => fired++);
    await new Promise((r) => setTimeout(r, 120));
    expect(fired).toBe(1);
  });

  test("연결이 먼저 닫히면 부르지 않는다, 만료가 없으면 걸지 않는다", async () => {
    const s = fakeSocket();
    let fired = 0;
    armAuthExpiry(s, Date.now() + 50, () => fired++);
    s.emit("close");
    armAuthExpiry(fakeSocket(), undefined, () => fired++);
    armAuthExpiry(fakeSocket(), null, () => fired++);
    await new Promise((r) => setTimeout(r, 120));
    expect(fired).toBe(0);
  });
});
