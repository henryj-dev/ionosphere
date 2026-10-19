/**
 * 앱 비밀번호·자체 발급 토큰의 무작위 비밀 저장(2026-10-18 결정 1-2, 이 창 결정 B).
 *
 * - 새 앱 비밀번호는 128비트 이상(소문자 28자), 저장은 sha256$, 로그인은 해시값으로 바로 찾는다.
 * - 예전 16자 앱 비밀번호(scrypt 저장)는 계속 받는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, CREDENTIAL_KIND, migrate, openSqlite } from "@ionosphere/db";
import { authenticate, createAppPassword, createCredential, createOAuthToken, generateAppPassword, Store } from "@ionosphere/store";

async function setup() {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("t");
  const { accountId } = await store.createAccount({ tenantId, email: "u@x.test" });
  await createCredential(db, { accountId, password: "Primary-pw1" });
  return { db, accountId };
}

describe("앱 비밀번호 — 128비트 이상", () => {
  test("소문자 28자, 4자씩 7묶음 — log2(26^28) > 128", () => {
    const pw = generateAppPassword();
    expect(pw).toMatch(/^[a-z]{4}(-[a-z]{4}){6}$/);
    expect(28 * Math.log2(26)).toBeGreaterThan(128);
    expect(generateAppPassword()).not.toBe(pw);
  });

  test("저장은 sha256$이고, 하이픈·공백·대문자를 섞어 입력해도 로그인된다", async () => {
    const { db, accountId } = await setup();
    const { id, password } = await createAppPassword(db, accountId, "phone");
    const { rows } = await db.query({ sql: "SELECT secret FROM credentials WHERE id = ?", params: [id] });
    expect(String(rows[0]!.secret)).toMatch(/^sha256\$[0-9a-f]{64}$/);
    expect(await authenticate(db, "u@x.test", password, "imap")).toMatchObject({ accountId, credKind: "appPassword", credentialId: id });
    const sloppy = password.replace(/-/g, " ").toUpperCase();
    expect(await authenticate(db, "u@x.test", sloppy, "imap")).toMatchObject({ credentialId: id });
    // 마지막 글자를 **다른** 글자로 바꾼다. 늘 "a"로 바꾸면 원래 끝이 "a"일 때(1/26) 같은 비밀번호가 되어 CI가 가끔 깨졌다.
    const last = password.slice(-1);
    expect(await authenticate(db, "u@x.test", password.slice(0, -1) + (last === "a" ? "b" : "a"), "imap")).toBeNull();
  });

  test("표면 제한은 빠른 경로에서도 지킨다", async () => {
    const { db, accountId } = await setup();
    const { password } = await createAppPassword(db, accountId, "imap-only", "imap");
    expect(await authenticate(db, "u@x.test", password, "imap")).not.toBeNull();
    expect(await authenticate(db, "u@x.test", password, "submission")).toBeNull();
    // 표면이 막힌 새 앱 비밀번호가 예전(scrypt) 루프로 넘어가도 맞는 것이 없다.
    expect(await authenticate(db, "u@x.test", password.replace(/-/g, ""), "pop3")).toBeNull();
  });

  test("예전 16자 앱 비밀번호(scrypt 저장)는 계속 받는다", async () => {
    const { db, accountId } = await setup();
    const legacy = "abcdefghijklmnop";
    await createCredential(db, { accountId, password: legacy, kind: CREDENTIAL_KIND.appPassword, label: "old" });
    expect(await authenticate(db, "u@x.test", "abcd-efgh-ijkl-mnop", "imap")).toMatchObject({ credKind: "appPassword" });
  });

  test("자체 발급 토큰도 sha256$로 저장하고 바로 찾는다", async () => {
    const { db, accountId } = await setup();
    const { id, token } = await createOAuthToken(db, accountId, "cli");
    const { rows } = await db.query({ sql: "SELECT secret FROM credentials WHERE id = ?", params: [id] });
    expect(String(rows[0]!.secret)).toMatch(/^sha256\$/);
    expect(await authenticate(db, "u@x.test", token, "imap")).toMatchObject({ credentialId: id, credKind: "oauthToken" });
    // 토큰은 원문이 저장 키다 — 앱 비밀번호처럼 정규화(하이픈 제거·소문자)한 값으로는 맞지 않는다.
    if (token.replace(/-/g, "").toLowerCase() !== token) expect(await authenticate(db, "u@x.test", token.replace(/-/g, "").toLowerCase(), "imap")).toBeNull();
  });

  test("기본 비밀번호는 여전히 scrypt로 확인한다(빠른 경로가 기본 비밀번호를 찾지 않는다)", async () => {
    const { db, accountId } = await setup();
    expect(await authenticate(db, "u@x.test", "Primary-pw1", "imap")).toMatchObject({ accountId, credKind: "password" });
  });
});
