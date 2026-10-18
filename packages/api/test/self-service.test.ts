/**
 * 메일 계정 셀프서비스 — 실소켓 HTTP로 계약을 고정한다(회원 정책 E2, 결정 D3).
 *
 *  - 로그인은 기본 비밀번호만(앱 비밀번호로는 못 들어온다).
 *  - TOTP 미등록이면 목록만 보고 민감 작업은 못 한다(면제 없음). 첫 등록에는 관리자가 발급한 일회용 코드가 필요하다.
 *  - 민감 작업은 최근 MFA(step-up). 비밀번호 변경은 현재 비밀번호도 확인한다.
 *  - 자기 계정의 자격증명만 철회할 수 있다(같은 테넌트의 남의 것은 404).
 *  - 비밀번호를 바꿔도 앱 비밀번호(메일 클라이언트)는 살아 있고, 웹 세션은 끊긴다.
 *  - 계정 정지는 다음 요청부터 반영된다. 스로틀은 메일 프로토콜과 같은 계정 키를 쓴다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { AuthFailureThrottle, base32Decode, hotp, totpStep } from "@ionosphere/core";
import { ACCOUNT_STATUS, allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { authenticate, createAppPassword, createCredential, Store } from "@ionosphere/store";
import { createRegistry, runCommand, type CommandContext } from "@ionosphere/admin-cmd";
import { SelfServiceServer, type SelfServiceDeps } from "../src/self-service.ts";

const KEY = "self-service-test-key";
const EMAIL = "alice@acme.test";
const PASSWORD = "alice-primary-pw";

interface Fx {
  db: DbDriver;
  server: SelfServiceServer;
  base: string;
  tenantId: string;
  accountId: string;
}
let fx: Fx | undefined;
afterEach(async () => {
  if (fx) {
    await fx.server.close();
    await fx.db.close();
    fx = undefined;
  }
});

async function setup(overrides: Partial<SelfServiceDeps> = {}): Promise<Fx> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("acme");
  const { accountId } = await store.createAccount({ tenantId, email: EMAIL });
  await createCredential(db, { accountId, password: PASSWORD });
  const server = new SelfServiceServer({ db, store, masterKey: KEY, ...overrides });
  const port = await server.listen(0, "127.0.0.1");
  fx = { db, server, base: `http://127.0.0.1:${port}`, tenantId, accountId };
  return fx;
}

interface Session {
  cookie: string;
  csrf: string;
}
async function req(
  f: Fx,
  method: string,
  path: string,
  opts: { body?: unknown; session?: Session; csrf?: string | null; origin?: string | null } = {},
): Promise<{ status: number; json: Record<string, unknown>; setCookie: string | null }> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  const origin = opts.origin === undefined ? f.base : opts.origin;
  if (origin !== null) headers.origin = origin;
  if (opts.session) headers.cookie = opts.session.cookie;
  const csrf = opts.csrf === undefined ? opts.session?.csrf : opts.csrf;
  if (csrf) headers["x-csrf-token"] = csrf;
  const res = await fetch(f.base + path, { method, headers, ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}) });
  const text = await res.text();
  return { status: res.status, json: text ? (JSON.parse(text) as Record<string, unknown>) : {}, setCookie: res.headers.get("set-cookie") };
}

async function login(f: Fx, extra: Record<string, string> = {}, password = PASSWORD): Promise<{ status: number; session: Session; json: Record<string, unknown> }> {
  const r = await req(f, "POST", "/account/session/login", { body: { email: EMAIL, password, ...extra } });
  return { status: r.status, session: { cookie: (r.setCookie ?? "").split(";")[0] ?? "", csrf: String(r.json.csrfToken ?? "") }, json: r.json };
}

/** 테넌트 관리자가 셀프서비스 등록 코드를 발급한다(관리 명령 경로 그대로). */
async function issueCode(f: Fx): Promise<string> {
  const ctx = { db: f.db, store: new Store(f.db), tenantId: f.tenantId, isRoot: false } as CommandContext;
  const r = await runCommand(createRegistry(), ctx, "account-mfa-reset", { account: EMAIL });
  return r.secret!.value;
}

function codeNow(secret: string, offset = 0): string {
  return hotp(base32Decode(secret)!, totpStep(Date.now()) + offset);
}

async function enrolled(f: Fx): Promise<{ session: Session; secret: string; recoveryCodes: string[] }> {
  // 발급이 먼저다 — 발급(초기화)은 그 계정의 셀프서비스 세션을 끊는다(account-mfa-reset 주석).
  const enrollCode = await issueCode(f);
  const { session } = await login(f);
  const enroll = await req(f, "POST", "/account/session/mfa/enroll", { session, body: { enrollCode } });
  expect(enroll.status).toBe(200);
  const secret = String(enroll.json.secret);
  const confirm = await req(f, "POST", "/account/session/mfa/confirm", { session, body: { code: codeNow(secret) } });
  expect(confirm.status).toBe(200);
  return { session, secret, recoveryCodes: confirm.json.recoveryCodes as string[] };
}

describe("셀프서비스", () => {
  test("기본 비밀번호로만 들어온다 — 앱 비밀번호·틀린 비밀번호는 같은 401", async () => {
    const f = await setup();
    const { password: appPw } = await createAppPassword(f.db, f.accountId, "phone");
    const bad = await login(f, {}, "nope");
    const app = await login(f, {}, appPw);
    for (const r of [bad, app]) {
      expect(r.status).toBe(401);
      expect(r.json).toEqual({ error: "invalid credentials" });
    }
    const ok = await login(f);
    expect(ok.status).toBe(200);
    expect(ok.json.mfaEnrolled).toBe(false);
    expect(ok.session.cookie).toStartWith("__Host-ionosphere_account=");
  });

  test("★TOTP 미등록이면 목록만 보고 민감 작업은 못 한다(면제 없음), 등록 코드 없이는 등록도 못 한다", async () => {
    const f = await setup();
    const { session } = await login(f);
    expect((await req(f, "GET", "/account/app-passwords", { session })).status).toBe(200);
    expect((await req(f, "POST", "/account/app-passwords", { session, body: { label: "x" } })).json.code).toBe("mfa_required");
    expect((await req(f, "POST", "/account/password", { session, body: { currentPassword: PASSWORD, newPassword: "n" } })).json.code).toBe("mfa_required");
    const noCode = await req(f, "POST", "/account/session/mfa/enroll", { session, body: {} });
    expect(noCode.json.code).toBe("invalid_enroll_code");
  });

  test("등록 뒤에는 TOTP 없이 로그인할 수 없고, 앱 비밀번호 발급·자기 것 철회가 된다", async () => {
    const f = await setup();
    const { secret } = await enrolled(f);
    expect((await login(f)).status).toBe(401);
    const { session } = await login(f, { totp: codeNow(secret, 1) });
    const made = await req(f, "POST", "/account/app-passwords", { session, body: { label: "laptop" } });
    expect(made.status).toBe(200);
    const plain = (made.json.__secret as { value: string }).value;
    expect((await authenticate(f.db, EMAIL, plain, "imap"))?.accountId).toBe(f.accountId);
    const list = (await req(f, "GET", "/account/app-passwords", { session })).json.rows as { id: string }[];
    expect((await req(f, "POST", `/account/credentials/${encodeURIComponent(list[0]!.id)}/revoke`, { session, body: {} })).status).toBe(200);
    expect(await authenticate(f.db, EMAIL, plain, "imap")).toBeNull();
  });

  test("★같은 테넌트의 남의 자격증명은 철회할 수 없다(404)", async () => {
    const f = await setup();
    const store = new Store(f.db);
    const { accountId: bob } = await store.createAccount({ tenantId: f.tenantId, email: "bob@acme.test" });
    const { id: bobCred, password: bobPw } = await createAppPassword(f.db, bob, "bob-phone");
    const { secret } = await enrolled(f);
    const { session } = await login(f, { totp: codeNow(secret, 1) });
    const r = await req(f, "POST", `/account/credentials/${encodeURIComponent(bobCred)}/revoke`, { session, body: {} });
    expect(r.status).toBe(404);
    expect((await authenticate(f.db, "bob@acme.test", bobPw, "imap"))?.accountId).toBe(bob);
  });

  test("민감 작업은 최근 MFA가 필요하다 — 오래되면 step_up, 재인증 뒤 통과", async () => {
    const f = await setup({ stepUpMs: 1500 });
    const { session, secret } = await enrolled(f);
    await new Promise((r) => setTimeout(r, 1600));
    expect((await req(f, "POST", "/account/app-passwords", { session, body: {} })).json.code).toBe("step_up");
    expect((await req(f, "POST", "/account/session/mfa/verify", { session, body: { code: codeNow(secret, 1) } })).status).toBe(200);
    expect((await req(f, "POST", "/account/app-passwords", { session, body: {} })).status).toBe(200);
  });

  test("★비밀번호 변경: 현재 비밀번호 확인, 웹 세션은 끊기고 앱 비밀번호는 산다", async () => {
    const f = await setup();
    const { password: appPw } = await createAppPassword(f.db, f.accountId, "phone");
    const { session } = await enrolled(f);
    expect((await req(f, "POST", "/account/password", { session, body: { currentPassword: "wrong", newPassword: "new-password-1" } })).status).toBe(401);
    expect((await req(f, "POST", "/account/password", { session, body: { currentPassword: PASSWORD, newPassword: "short" } })).json.code).toBe("weak_password");
    const ok = await req(f, "POST", "/account/password", { session, body: { currentPassword: PASSWORD, newPassword: "new-password-1" } });
    expect(ok.status).toBe(200);
    expect((await req(f, "GET", "/account/session", { session })).status).toBe(401);
    expect(await authenticate(f.db, EMAIL, PASSWORD, "imap")).toBeNull();
    expect((await authenticate(f.db, EMAIL, "new-password-1", "imap"))?.accountId).toBe(f.accountId);
    expect((await authenticate(f.db, EMAIL, appPw, "imap"))?.accountId).toBe(f.accountId);
  });

  test("CSRF·Origin: 상태 변경은 둘 다 맞아야 한다", async () => {
    const f = await setup();
    const { session } = await login(f);
    expect((await req(f, "POST", "/account/session/mfa/enroll", { session, body: {}, csrf: null })).json.code).toBe("csrf");
    expect((await req(f, "POST", "/account/session/mfa/enroll", { session, body: {}, origin: "https://evil.example.com" })).json.code).toBe("csrf");
    expect((await req(f, "POST", "/account/session/login", { body: { email: EMAIL, password: PASSWORD }, origin: "https://evil.example.com" })).status).toBe(403);
  });

  test("계정 정지는 다음 요청부터 반영된다", async () => {
    const f = await setup();
    const { session } = await login(f);
    await f.db.batch([{ sql: "UPDATE accounts SET status = ? WHERE id = ?", params: [ACCOUNT_STATUS.suspended, f.accountId] }]);
    expect((await req(f, "GET", "/account/session", { session })).status).toBe(401);
  });

  test("복구 코드로 들어오면 TOTP가 지워지고 새 등록 코드가 응답에 실린다", async () => {
    const f = await setup();
    const { recoveryCodes } = await enrolled(f);
    const r = await login(f, { recoveryCode: recoveryCodes[0]! });
    expect(r.status).toBe(200);
    expect(r.json.mfaEnrolled).toBe(false);
    expect(String(r.json.enrollCode)).toMatch(/^[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}$/);
    // 재등록 전에는 민감 작업을 못 한다 — 복구 코드는 "MFA 통과"가 아니라 "다시 등록할 자격"이다.
    expect((await req(f, "POST", "/account/app-passwords", { session: r.session, body: {} })).json.code).toBe("mfa_required");
    const enroll = await req(f, "POST", "/account/session/mfa/enroll", { session: r.session, body: { enrollCode: r.json.enrollCode } });
    expect(enroll.status).toBe(200);
    expect((await req(f, "POST", "/account/session/mfa/confirm", { session: r.session, body: { code: codeNow(String(enroll.json.secret)) } })).status).toBe(200);
    expect((await req(f, "POST", "/account/app-passwords", { session: r.session, body: {} })).status).toBe(200);
  });

  test("★스로틀은 메일 프로토콜과 같은 계정 키를 쓴다 — IMAP 대입이 웹 대입 한도를 함께 쓴다", async () => {
    const throttle = new AuthFailureThrottle();
    const f = await setup({ authThrottle: throttle });
    for (let i = 0; i < 30; i++) throttle.recordFailure({ account: EMAIL });
    expect((await login(f)).status).toBe(429);
  });

  test("기본 비밀번호(kind=0)는 셀프서비스로 철회할 수 없다", async () => {
    const f = await setup();
    const { rows } = await f.db.query({ sql: "SELECT id FROM credentials WHERE account_id = ? AND kind = 0", params: [f.accountId] });
    const { secret } = await enrolled(f);
    const { session } = await login(f, { totp: codeNow(secret, 1) });
    expect((await req(f, "POST", `/account/credentials/${encodeURIComponent(String(rows[0]!.id))}/revoke`, { session, body: {} })).status).toBe(404);
    expect((await authenticate(f.db, EMAIL, PASSWORD, "imap"))?.accountId).toBe(f.accountId);
  });
});
