/**
 * 개명 전환 호환 계층 — 구 `MAILER_*`를 새 `IONOSPHERE_*`로 넘긴다.
 *
 * 이 테스트가 지키는 것은 "코드 배포와 env 교체를 따로 할 수 있다"는 성질이다. 이게 깨지면
 * 새 코드가 옛 env를 못 읽은 채 기본값으로 기동한다 — 마스터키가 없으면 DKIM 개인키를 못 연다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { applyLegacyEnvAliases, LegacyEnvConflictError } from "../src/env-legacy.ts";

describe("applyLegacyEnvAliases", () => {
  test("구 이름을 새 이름으로 넘긴다", () => {
    const env: Record<string, string | undefined> = { MAILER_HOSTNAME: "mx.mailer.test" };
    const moved = applyLegacyEnvAliases(env);
    expect(env["IONOSPHERE_HOSTNAME"]).toBe("mx.mailer.test");
    expect(moved).toEqual(["MAILER_HOSTNAME"]);
  });

  test("접두사가 다른 변수는 건드리지 않는다", () => {
    const env: Record<string, string | undefined> = { PATH: "/usr/bin", MAILERX: "x" };
    expect(applyLegacyEnvAliases(env)).toEqual([]);
    expect(env["IONOSPHERE_"]).toBe(undefined);
    expect(Object.keys(env).sort()).toEqual(["MAILERX", "PATH"]);
  });

  test("새 이름이 이미 있으면 새 이름이 이긴다 — 같은 값이면 조용히 통과", () => {
    const env: Record<string, string | undefined> = { MAILER_DB: "a.db", IONOSPHERE_DB: "a.db" };
    expect(applyLegacyEnvAliases(env)).toEqual([]);
    expect(env["IONOSPHERE_DB"]).toBe("a.db");
  });

  test("★두 이름이 다른 값이면 기동을 막는다 — 어느 쪽이 의도인지 알 수 없다", () => {
    const env: Record<string, string | undefined> = { MAILER_DB: "old.db", IONOSPHERE_DB: "new.db" };
    expect(() => applyLegacyEnvAliases(env)).toThrow(LegacyEnvConflictError);
  });

  test("비밀값은 오류 메시지에 값을 남기지 않는다 — 저널에 그대로 찍힌다", () => {
    const env: Record<string, string | undefined> = { MAILER_MASTER_KEY: "old", IONOSPHERE_MASTER_KEY: "new" };
    let message = "";
    try {
      applyLegacyEnvAliases(env);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message.includes("MASTER_KEY")).toBe(true);
    expect(message.includes("old") || message.includes("new")).toBe(false);
  });

  test("값이 undefined인 항목은 넘기지 않는다", () => {
    const env: Record<string, string | undefined> = { MAILER_DB: undefined };
    expect(applyLegacyEnvAliases(env)).toEqual([]);
    expect("IONOSPHERE_DB" in env).toBe(false);
  });
});
