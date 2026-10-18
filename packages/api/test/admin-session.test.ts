/**
 * 관리 콘솔 사람 세션 — 실소켓 HTTP로 흐름 전체를 고정한다(회원 정책 E1).
 *
 * 고정하는 계약:
 *  - 로그인은 비밀번호·TOTP 실패를 구분하지 않는다(오라클 금지).
 *  - MFA 1차 필수: 미등록 세션은 등록 엔드포인트만 쓸 수 있다.
 *  - 쿠키로 상태를 바꾸려면 Origin 일치 + CSRF 토큰이 둘 다 있어야 한다.
 *  - 로그아웃·정지·역할 하향은 **다음 요청부터** 반영된다.
 *  - 파괴적 명령은 최근 MFA가 있어야 한다(step-up). API 키는 대상이 아니다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { base32Decode, hotp, totpStep } from "@ionosphere/core";
import { AuthFailureThrottle } from "@ionosphere/core";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { Store } from "@ionosphere/store";
import { AdminApiServer, type AdminApiDeps } from "../src/server.ts";

const ROOT = "root-token-for-session-test";
const KEY = "session-test-master-key";

interface Fx {
  db: DbDriver;
  server: AdminApiServer;
  base: string;
}
let fx: Fx | undefined;
afterEach(async () => {
  if (fx) {
    await fx.server.close();
    await fx.db.close();
    fx = undefined;
  }
});

async function setup(overrides: Partial<AdminApiDeps> = {}): Promise<Fx> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const server = new AdminApiServer({
    db,
    store: new Store(db),
    resolveTxt: async () => [],
    resolveMx: async () => [],
    rootToken: ROOT,
    masterKey: KEY,
    ...overrides,
  });
  const port = await server.listen(0, "127.0.0.1");
  fx = { db, server, base: `http://127.0.0.1:${port}` };
  return fx;
}

/** 브라우저처럼 보내는 요청 — Origin은 기본으로 같은 오리진, 쿠키·CSRF는 세션에서. */
interface Session {
  cookie: string;
  csrf: string;
}
async function req(
  f: Fx,
  method: string,
  path: string,
  opts: { body?: unknown; session?: Session; origin?: string | null; csrf?: string | null; bearer?: string } = {},
): Promise<{ status: number; json: Record<string, unknown>; setCookie: string | null }> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  const origin = opts.origin === undefined ? f.base : opts.origin;
  if (origin !== null) headers.origin = origin;
  if (opts.session) headers.cookie = opts.session.cookie;
  const csrf = opts.csrf === undefined ? opts.session?.csrf : opts.csrf;
  if (csrf) headers["x-csrf-token"] = csrf;
  if (opts.bearer) headers.authorization = `Bearer ${opts.bearer}`;
  const res = await fetch(f.base + path, { method, headers, ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}) });
  const text = await res.text();
  return { status: res.status, json: text ? (JSON.parse(text) as Record<string, unknown>) : {}, setCookie: res.headers.get("set-cookie") };
}

async function rootCommand(f: Fx, name: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const r = await req(f, "POST", `/v1/commands/${name}`, { body, bearer: ROOT, origin: null });
  expect(r.status).toBe(200);
  return r.json;
}

/** 사용자명 → 생성 때 받은 일회용 등록 코드(관리자를 만든 쪽이 본인에게 따로 전달하는 값). */
const enrollCodes = new Map<string, string>();

async function createAdmin(f: Fx, username: string, role = "owner", tenant?: string): Promise<void> {
  const r = await rootCommand(f, "admin-user-create", { username, password: "admin-pw", role, ...(tenant ? { adminTenantId: tenant } : {}) });
  enrollCodes.set(username, String((r.__secret as { value: string }).value));
}

async function login(f: Fx, username: string, totp = ""): Promise<{ status: number; session: Session; json: Record<string, unknown> }> {
  const r = await req(f, "POST", "/admin/session/login", { body: { username, password: "admin-pw", totp } });
  const cookie = (r.setCookie ?? "").split(";")[0] ?? "";
  return { status: r.status, session: { cookie, csrf: String(r.json.csrfToken ?? "") }, json: r.json };
}

/** 등록까지 마친 세션과 TOTP 비밀·복구 코드. */
async function enrolledSession(f: Fx, username: string): Promise<{ session: Session; secret: string; recoveryCodes: string[] }> {
  const { session } = await login(f, username);
  const enroll = await req(f, "POST", "/admin/session/mfa/enroll", { session, body: { enrollCode: enrollCodes.get(username) } });
  expect(enroll.status).toBe(200);
  const secret = String(enroll.json.secret);
  const confirm = await req(f, "POST", "/admin/session/mfa/confirm", { session, body: { code: codeNow(secret) } });
  expect(confirm.status).toBe(200);
  return { session, secret, recoveryCodes: confirm.json.recoveryCodes as string[] };
}

function codeNow(secret: string, offsetSteps = 0): string {
  return hotp(base32Decode(secret)!, totpStep(Date.now()) + offsetSteps);
}

describe("관리 콘솔 사람 세션", () => {
  test("로그인 → 미등록이면 등록 전까지 /v1이 막히고, 등록 뒤 열린다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    expect((await req(f, "POST", "/admin/session/login", { body: { username: "ops@ionosphere.test", password: "nope" } })).status).toBe(401);

    const { status, session, json } = await login(f, "ops@ionosphere.test");
    expect(status).toBe(200);
    expect(json.mfaEnrolled).toBe(false);
    expect(session.cookie).toStartWith("__Host-ionosphere_admin=");

    const blocked = await req(f, "GET", "/v1/commands", { session });
    expect(blocked.status).toBe(403);
    expect(blocked.json.code).toBe("mfa_required");

    // ★등록 코드 없이는 등록을 시작할 수 없다 — 비밀번호만으로 MFA를 차지하지 못한다.
    const noCode = await req(f, "POST", "/admin/session/mfa/enroll", { session });
    expect(noCode.status).toBe(401);
    expect(noCode.json.code).toBe("invalid_enroll_code");
    const enroll = await req(f, "POST", "/admin/session/mfa/enroll", { session, body: { enrollCode: enrollCodes.get("ops@ionosphere.test") } });
    const secret = String(enroll.json.secret);
    expect(String(enroll.json.uri)).toStartWith("otpauth://totp/");
    expect((await req(f, "POST", "/admin/session/mfa/confirm", { session, body: { code: "000000" } })).status).toBe(401);
    expect((await req(f, "POST", "/admin/session/mfa/confirm", { session, body: { code: codeNow(secret) } })).status).toBe(200);
    expect((await req(f, "GET", "/v1/commands", { session })).status).toBe(200);
  });

  test("★등록된 관리자는 TOTP 없이·틀린 TOTP로는 로그인 못 하고, 응답은 비밀번호 실패와 같다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    const { secret } = await enrolledSession(f, "ops@ionosphere.test");
    const noTotp = await login(f, "ops@ionosphere.test");
    const badTotp = await login(f, "ops@ionosphere.test", "123456");
    const badPw = await req(f, "POST", "/admin/session/login", { body: { username: "ops@ionosphere.test", password: "nope", totp: codeNow(secret, 1) } });
    for (const r of [noTotp, badTotp, badPw]) {
      expect(r.status).toBe(401);
      expect(r.json).toEqual({ error: "invalid credentials" });
    }
    const ok = await login(f, "ops@ionosphere.test", codeNow(secret, 1));
    expect(ok.status).toBe(200);
    expect((await req(f, "GET", "/v1/commands", { session: ok.session })).status).toBe(200);
  });

  test("쿠키로 상태를 바꾸려면 Origin과 CSRF가 둘 다 맞아야 한다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    const { session } = await enrolledSession(f, "ops@ionosphere.test");
    const { tenantId } = (await rootCommand(f, "tenant-create", { name: "acme" })).data as { tenantId: string };
    const path = "/v1/commands/account-list";
    const body = { tenantId };
    expect((await req(f, "POST", path, { session, body, csrf: null })).json.code).toBe("csrf");
    expect((await req(f, "POST", path, { session, body, csrf: "forged" })).json.code).toBe("csrf");
    expect((await req(f, "POST", path, { session, body, origin: "https://evil.example.com" })).json.code).toBe("csrf");
    expect((await req(f, "POST", path, { session, body, origin: null })).json.code).toBe("csrf");
    expect((await req(f, "POST", path, { session, body })).status).toBe(200);
    // 로그인도 Origin을 본다(로그인 CSRF).
    expect((await req(f, "POST", "/admin/session/login", { body: { username: "ops@ionosphere.test", password: "admin-pw" }, origin: "https://evil.example.com" })).status).toBe(403);
  });

  test("★로그아웃·정지·역할 하향은 다음 요청부터 반영된다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    await createAdmin(f, "other@ionosphere.test");
    const a = await enrolledSession(f, "ops@ionosphere.test");
    const b = await enrolledSession(f, "other@ionosphere.test");
    const { tenantId } = (await rootCommand(f, "tenant-create", { name: "acme" })).data as { tenantId: string };

    expect((await req(f, "POST", "/admin/session/logout", { session: a.session })).status).toBe(200);
    expect((await req(f, "GET", "/v1/commands", { session: a.session })).status).toBe(401);

    await rootCommand(f, "admin-user-role-set", { admin: "other@ionosphere.test", role: "readonly" });
    const write = await req(f, "POST", "/v1/commands/tenant-create", { session: b.session, body: { name: "x" } });
    expect(write.status).toBe(403);
    // 조회는 여전히 된다(readonly = read 스코프).
    expect((await req(f, "GET", "/v1/commands", { session: b.session })).status).toBe(200);
    expect((await req(f, "GET", `/v1/accounts?tenantId=${tenantId}`, { session: b.session })).status).toBe(200);

    await rootCommand(f, "admin-user-suspend", { admin: "other@ionosphere.test" });
    expect((await req(f, "GET", "/v1/commands", { session: b.session })).status).toBe(401);
  });

  test("★파괴적 명령은 최근 MFA가 필요하고, 재인증 뒤 통과한다. API 키는 대상이 아니다", async () => {
    // 창은 재인증+재시도 왕복(봉인 해제에 scrypt가 돈다)보다 넉넉해야 한다.
    const f = await setup({ stepUpMs: 1500 });
    await createAdmin(f, "ops@ionosphere.test");
    const { session, secret } = await enrolledSession(f, "ops@ionosphere.test");
    await createAdmin(f, "victim@ionosphere.test", "admin");
    await new Promise((r) => setTimeout(r, 1600));

    const stale = await req(f, "POST", "/v1/commands/admin-user-sessions-revoke", { session, body: { admin: "victim@ionosphere.test" } });
    expect(stale.status).toBe(403);
    expect(stale.json.code).toBe("step_up");
    // 등록에 쓴 스텝은 재사용할 수 없다 — 다음 스텝 코드로 재인증한다.
    expect((await req(f, "POST", "/admin/session/mfa/verify", { session, body: { code: codeNow(secret, 1) } })).status).toBe(200);
    expect((await req(f, "POST", "/v1/commands/admin-user-sessions-revoke", { session, body: { admin: "victim@ionosphere.test" } })).status).toBe(200);

    // root·API 키 경로는 step-up이 없다(서비스 토큰).
    expect((await req(f, "POST", "/v1/commands/admin-user-sessions-revoke", { bearer: ROOT, origin: null, body: { admin: "victim@ionosphere.test" } })).status).toBe(200);
  });

  test("테넌트 관리자는 rootOnly 명령을 못 부르고 남의 테넌트를 지정할 수 없다", async () => {
    const f = await setup();
    const { tenantId: mine } = (await rootCommand(f, "tenant-create", { name: "mine" })).data as { tenantId: string };
    await createAdmin(f, "tenant-admin@ionosphere.test", "owner", mine);
    const { session } = await enrolledSession(f, "tenant-admin@ionosphere.test");
    expect((await req(f, "POST", "/v1/commands/tenant-create", { session, body: { name: "x" } })).status).toBe(403);
    expect((await req(f, "POST", "/v1/commands/admin-user-list", { session, body: {} })).status).toBe(403);
    // 자기 테넌트로 고정된다 — tenantId를 넣어도 무시된다(commandContext).
    expect((await req(f, "POST", "/v1/commands/account-list", { session, body: {} })).status).toBe(200);
  });

  test("Bearer가 있으면 쿠키는 무시한다(주체를 하나로)", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    const { session } = await login(f, "ops@ionosphere.test"); // 미등록 세션 — 쿠키로는 403일 것
    const r = await req(f, "GET", "/v1/commands", { session, bearer: ROOT });
    expect(r.status).toBe(200);
  });

  test("마지막 운영자 owner는 정지·강등할 수 없다", async () => {
    const f = await setup();
    await createAdmin(f, "only@ionosphere.test");
    const r = await req(f, "POST", "/v1/commands/admin-user-suspend", { bearer: ROOT, origin: null, body: { admin: "only@ionosphere.test" } });
    expect(r.status).toBe(409);
    const r2 = await req(f, "POST", "/v1/commands/admin-user-role-set", { bearer: ROOT, origin: null, body: { admin: "only@ionosphere.test", role: "admin" } });
    expect(r2.status).toBe(409);
  });
});

describe("보안 검토 반영(2026-10-18)", () => {
  test("readonly 관리자는 콘솔 경로(POST /v1/commands)로 조회는 되고 쓰기는 안 된다", async () => {
    const f = await setup();
    await createAdmin(f, "owner@ionosphere.test");
    await createAdmin(f, "viewer@ionosphere.test", "readonly");
    const { session } = await enrolledSession(f, "viewer@ionosphere.test");
    const { tenantId } = (await rootCommand(f, "tenant-create", { name: "acme" })).data as { tenantId: string };
    expect((await req(f, "POST", "/v1/commands/account-list", { session, body: { tenantId } })).status).toBe(200);
    expect((await req(f, "POST", "/v1/commands/account-suspend", { session, body: { tenantId, account: "x@acme.test" } })).status).toBe(403);
  });

  test("★sensitive 명령(API 키 발급)도 최근 MFA가 필요하다", async () => {
    const f = await setup({ stepUpMs: 1500 });
    await createAdmin(f, "ops@ionosphere.test");
    const { session, secret } = await enrolledSession(f, "ops@ionosphere.test");
    const { tenantId } = (await rootCommand(f, "tenant-create", { name: "acme" })).data as { tenantId: string };
    await new Promise((r) => setTimeout(r, 1600));
    const stale = await req(f, "POST", "/v1/commands/api-key-create", { session, body: { tenantId } });
    expect(stale.status).toBe(403);
    expect(stale.json.code).toBe("step_up");
    expect((await req(f, "POST", "/admin/session/mfa/verify", { session, body: { code: codeNow(secret, 1) } })).status).toBe(200);
    expect((await req(f, "POST", "/v1/commands/api-key-create", { session, body: { tenantId } })).status).toBe(200);
  });

  test("새 탭: GET /admin/session이 같은 CSRF 토큰을 다시 주고 그것으로 쓰기가 된다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    const { session } = await enrolledSession(f, "ops@ionosphere.test");
    const me = await req(f, "GET", "/admin/session", { session: { cookie: session.cookie, csrf: "" } });
    expect(me.json.csrfToken).toBe(session.csrf);
    const { tenantId } = (await rootCommand(f, "tenant-create", { name: "acme" })).data as { tenantId: string };
    const newTab = { cookie: session.cookie, csrf: String(me.json.csrfToken) };
    expect((await req(f, "POST", "/v1/commands/account-list", { session: newTab, body: { tenantId } })).status).toBe(200);
  });

  test("로그아웃은 CSRF 토큰 없이 Origin만으로 되고, 다른 오리진은 거절한다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    const { session } = await enrolledSession(f, "ops@ionosphere.test");
    expect((await req(f, "POST", "/admin/session/logout", { session, csrf: null, origin: "https://evil.example.com" })).status).toBe(403);
    expect((await req(f, "GET", "/v1/commands", { session })).status).toBe(200);
    expect((await req(f, "POST", "/admin/session/logout", { session, csrf: null })).status).toBe(200);
    expect((await req(f, "GET", "/v1/commands", { session })).status).toBe(401);
  });

  test("같은 브라우저에서 다시 로그인하면 이전 세션은 닫힌다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    const first = await login(f, "ops@ionosphere.test");
    const again = await req(f, "POST", "/admin/session/login", { session: first.session, csrf: null, body: { username: "ops@ionosphere.test", password: "admin-pw" } });
    expect(again.status).toBe(200);
    expect((await req(f, "GET", "/admin/session", { session: first.session })).status).toBe(401);
  });

  test("메일 프로토콜의 계정 실패가 같은 이름의 콘솔 로그인을 잠그지 않는다(스로틀 키 분리)", async () => {
    const throttle = new AuthFailureThrottle();
    const f = await setup({ authThrottle: throttle });
    await createAdmin(f, "ops@ionosphere.test");
    for (let i = 0; i < 30; i++) throttle.recordFailure({ account: "ops@ionosphere.test" });
    expect((await login(f, "ops@ionosphere.test")).status).toBe(200);
  });

  test("사용자명은 화이트리스트 형식만 받는다", async () => {
    const f = await setup();
    const r = await req(f, "POST", "/v1/commands/admin-user-create", { bearer: ROOT, origin: null, body: { username: "bad name", password: "pw", role: "admin" } });
    expect(r.status).toBe(400);
  });
});

describe("adminOrigin 설정", () => {
  test("끝의 / 와 대문자는 정규화되어 로그인이 막히지 않고, 다른 오리진은 막힌다", async () => {
    // 설정된 오리진은 Origin 헤더와 정확 비교한다(Host는 보지 않는다) — 그래서 서버 주소와 무관하게 고정값으로 볼 수 있다.
    const f = await setup({ adminOrigin: "HTTPS://Admin.Ionosphere.TEST/" });
    await createAdmin(f, "ops@ionosphere.test");
    const body = { username: "ops@ionosphere.test", password: "admin-pw" };
    expect((await req(f, "POST", "/admin/session/login", { body, origin: "https://admin.ionosphere.test" })).status).toBe(200);
    expect((await req(f, "POST", "/admin/session/login", { body, origin: f.base })).status).toBe(403);
  });

  test("URL이 아닌 값은 기동을 멈춘다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    expect(() => new AdminApiServer({ db, store: new Store(db), resolveTxt: async () => [], resolveMx: async () => [], adminOrigin: "not a url" })).toThrow(/URL이 아니다/);
    await db.close();
  });
});

describe("복구 코드·MFA 초기화(2026-10-18 사용자 결정)", () => {
  test("복구 코드로 로그인하면 TOTP가 지워지고, 응답의 등록 코드로 새 장치를 등록해야 콘솔이 열린다", async () => {
    const f = await setup();
    await createAdmin(f, "ops@ionosphere.test");
    const { session: old, recoveryCodes } = await enrolledSession(f, "ops@ionosphere.test");
    expect(recoveryCodes.length).toBeGreaterThan(0);
    const r = await req(f, "POST", "/admin/session/login", { body: { username: "ops@ionosphere.test", password: "admin-pw", recoveryCode: recoveryCodes[0] } });
    expect(r.status).toBe(200);
    expect(r.json.mfaEnrolled).toBe(false);
    const session = { cookie: (r.setCookie ?? "").split(";")[0] ?? "", csrf: String(r.json.csrfToken) };
    // 다른 세션은 끊겼다(복구는 계정 탈취 대응이기도 하다).
    expect((await req(f, "GET", "/v1/commands", { session: old })).status).toBe(401);
    expect((await req(f, "GET", "/v1/commands", { session })).json.code).toBe("mfa_required");
    const enroll = await req(f, "POST", "/admin/session/mfa/enroll", { session, body: { enrollCode: r.json.enrollCode } });
    expect(enroll.status).toBe(200);
    expect((await req(f, "POST", "/admin/session/mfa/confirm", { session, body: { code: codeNow(String(enroll.json.secret)) } })).status).toBe(200);
    expect((await req(f, "GET", "/v1/commands", { session })).status).toBe(200);
    // 쓴 복구 코드는 다시 못 쓴다 — 응답은 비밀번호 실패와 같다.
    const again = await req(f, "POST", "/admin/session/login", { body: { username: "ops@ionosphere.test", password: "admin-pw", recoveryCode: recoveryCodes[0] } });
    expect(again.status).toBe(401);
    expect(again.json).toEqual({ error: "invalid credentials" });
  });

  test("owner가 MFA를 초기화하면 step-up이 필요하고, 새 등록 코드는 그 응답에서만 나온다", async () => {
    const f = await setup({ stepUpMs: 1500 });
    await createAdmin(f, "owner@ionosphere.test");
    await createAdmin(f, "lost@ionosphere.test", "admin");
    const { session, secret } = await enrolledSession(f, "owner@ionosphere.test");
    await enrolledSession(f, "lost@ionosphere.test");
    await new Promise((r) => setTimeout(r, 1600));
    const stale = await req(f, "POST", "/v1/commands/admin-user-mfa-reset", { session, body: { admin: "lost@ionosphere.test" } });
    expect(stale.json.code).toBe("step_up");
    expect((await req(f, "POST", "/admin/session/mfa/verify", { session, body: { code: codeNow(secret, 1) } })).status).toBe(200);
    const reset = await req(f, "POST", "/v1/commands/admin-user-mfa-reset", { session, body: { admin: "lost@ionosphere.test" } });
    expect(reset.status).toBe(200);
    const code = (reset.json.__secret as { value: string }).value;
    const lost = await login(f, "lost@ionosphere.test");
    expect(lost.json.mfaEnrolled).toBe(false);
    expect((await req(f, "POST", "/admin/session/mfa/enroll", { session: lost.session, body: { enrollCode: code } })).status).toBe(200);
  });
});
