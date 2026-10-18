/**
 * 자격증명·권한을 만드는 명령은 사람 세션에서 step-up을 요구해야 한다(`sensitive` 또는 `destructive`).
 *
 * 새 명령을 추가한 사람이 플래그를 잊으면 그 명령만 오래된 세션으로 통과한다. 그래서 구조로 고정한다:
 *  - 비밀 인자(`type: "secret"`)를 받는 명령
 *  - 평문 비밀을 돌려주는 것으로 알려진 명령(아래 목록)
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ALL_COMMANDS } from "../src/registry.ts";

const RETURNS_SECRET = ["api-key-create", "app-password-create", "oauth-token-create"];

describe("민감 명령 표시", () => {
  test("비밀을 받거나 돌려주는 쓰기 명령은 전부 sensitive 또는 destructive다", () => {
    const missing = ALL_COMMANDS.filter((c) => !c.spec.readOnly)
      .filter((c) => c.spec.args.some((a) => a.type === "secret") || RETURNS_SECRET.includes(c.spec.name))
      .filter((c) => c.spec.sensitive !== true && c.spec.destructive !== true)
      .map((c) => c.spec.name);
    expect(missing).toEqual([]);
  });

  test("권한을 새로 여는 명령도 표시돼 있다", () => {
    for (const name of ["admin-user-create", "admin-user-activate", "tenant-create", "account-activate", "smarthost-set", "tls-upload", "alias-add"]) {
      const c = ALL_COMMANDS.find((x) => x.spec.name === name);
      expect(c?.spec.sensitive === true || c?.spec.destructive === true).toBe(true);
    }
  });
});
