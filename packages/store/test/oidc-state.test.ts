/** OIDC 인가 상태 — 1회용, 영역·만료 확인, 진행 중 상한. */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { MAX_PENDING_OIDC_STATES, saveOidcLoginState, takeOidcLoginState } from "@ionosphere/store";

describe("OIDC 인가 상태", () => {
  test("한 번만 쓰이고, 영역이 다르거나 만료되면 null", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const now = 1_800_000_000_000;
    await saveOidcLoginState(db, { state: "s1", provider: "corp", realm: "admin", nonce: "n", codeVerifier: "v" }, now);
    expect(await takeOidcLoginState(db, "s1", "account", now)).toBeNull(); // 영역이 다르면 소비되고 거절
    expect(await takeOidcLoginState(db, "s1", "admin", now)).toBeNull(); // 이미 소비됨
    await saveOidcLoginState(db, { state: "s2", provider: "corp", realm: "admin", nonce: "n", codeVerifier: "v" }, now);
    expect((await takeOidcLoginState(db, "s2", "admin", now))?.provider).toBe("corp");
    await saveOidcLoginState(db, { state: "s3", provider: "corp", realm: "admin", nonce: "n", codeVerifier: "v" }, now);
    expect(await takeOidcLoginState(db, "s3", "admin", now + 11 * 60_000)).toBeNull();
  });

  test("진행 중인 상태가 상한에 닿으면 새 시작을 거절한다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const now = 1_800_000_000_000;
    await db.batch(
      Array.from({ length: MAX_PENDING_OIDC_STATES }, (_, i) => ({
        sql: "INSERT INTO oidc_login_states (state_hash, provider, realm, nonce, code_verifier, created_at, expires_at) VALUES (?, 'corp', 'admin', 'n', 'v', ?, ?)",
        params: [`h${i}`, now, now + 600_000],
      })),
    );
    expect(await saveOidcLoginState(db, { state: "x", provider: "corp", realm: "admin", nonce: "n", codeVerifier: "v" }, now)).toBe(false);
  });
});
