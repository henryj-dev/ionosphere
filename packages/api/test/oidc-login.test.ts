/**
 * 외부 OIDC 웹 로그인 — 루프백의 가짜 IdP(실제 HTTP·RSA 서명)로 흐름 전체를 고정한다(회원 정책 E3).
 *
 *  - 연결되지 않은 sub는 들어오지 못한다(자동 연결·JIT 없음).
 *  - IdP MFA 계약이 없으면 로컬 TOTP를 요구한다(관리 콘솔 /v1 차단). 계약을 충족하면 바로 열린다(로컬 TOTP 등록 전제).
 *  - state는 1회용이고 브라우저 쿠키와 같아야 하며, ID 토큰 nonce가 달라도 거절한다.
 *  - 메일 계정 영역은 그 공급자의 테넌트 안에서 연결된 계정으로 셀프서비스 세션을 연다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { createServer, type Server } from "node:http";
import { generateKeyPairSync, sign } from "node:crypto";
import { base32Decode, hotp, OidcClient, totpStep, type Jwk, type MfaEvidenceContract } from "@ionosphere/core";
import { ADMIN_ROLE, allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import {
  createAdminUser,
  createCredential,
  issueAdminEnrollCode,
  beginAdminTotpEnrollment,
  confirmAdminTotpEnrollment,
  linkAccountOidcIdentity,
  linkAdminIdentity,
  Store,
} from "@ionosphere/store";
import { AdminApiServer } from "../src/server.ts";
import { SelfServiceServer } from "../src/self-service.ts";
import { OidcLoginFlow } from "../src/oidc-login.ts";

const KEY = "oidc-test-master-key";

/** 가짜 IdP — discovery·jwks·token. authorize는 쓰지 않는다(테스트가 인가 URL에서 state·nonce를 읽는다). */
async function fakeIdp(): Promise<{ issuer: string; close: () => Promise<void>; next: (c: Record<string, unknown>) => void }> {
  const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
  let claims: Record<string, unknown> = {};
  let issuer = "";
  const server: Server = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    res.setHeader("content-type", "application/json");
    if (u.pathname === "/.well-known/openid-configuration") {
      res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` }));
    } else if (u.pathname === "/jwks") {
      res.end(JSON.stringify({ keys: [{ ...(key.publicKey.export({ format: "jwk" }) as Jwk), kid: "k1", alg: "RS256" }] }));
    } else if (u.pathname === "/token") {
      const input = `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "k1" })).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}`;
      res.end(JSON.stringify({ id_token: `${input}.${sign("RSA-SHA256", Buffer.from(input), key.privateKey).toString("base64url")}` }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  issuer = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return { issuer, close: () => new Promise((r) => server.close(() => r())), next: (c) => (claims = c) };
}

interface Ctx {
  db: DbDriver;
  idp: Awaited<ReturnType<typeof fakeIdp>>;
  base: string;
  close: () => Promise<void>;
}
let ctx: Ctx | undefined;
afterEach(async () => {
  if (ctx) {
    await ctx.close();
    await ctx.idp.close();
    await ctx.db.close();
    ctx = undefined;
  }
});

function totpNow(secret: string, offset = 0): string {
  return hotp(base32Decode(secret)!, totpStep(Date.now()) + offset);
}

/** 시작 → (IdP) → 콜백. 브라우저가 하는 일을 흉내 낸다. 콜백 응답을 돌려준다. */
async function ssoLogin(
  base: string,
  prefix: "/admin" | "/account",
  idp: Ctx["idp"],
  claims: (nonce: string) => Record<string, unknown>,
  tamper: { stateCookie?: string; replay?: boolean } = {},
): Promise<{ location: string; cookie: string; replayLocation?: string }> {
  const start = await fetch(`${base}${prefix}/session/oidc/start?provider=corp`, { redirect: "manual" });
  expect(start.status).toBe(302);
  const authUrl = new URL(start.headers.get("location")!);
  const state = authUrl.searchParams.get("state")!;
  const stateCookie = (start.headers.get("set-cookie") ?? "").split(";")[0]!;
  idp.next(claims(authUrl.searchParams.get("nonce")!));
  const cb = `${base}${prefix}/session/oidc/callback?code=c1&state=${encodeURIComponent(state)}`;
  const cookieHeader = tamper.stateCookie ?? stateCookie;
  const res = await fetch(cb, { redirect: "manual", headers: { cookie: cookieHeader } });
  const setCookies = res.headers.getSetCookie();
  const session = setCookies.find((c) => c.startsWith("__Host-ionosphere_admin=") || c.startsWith("__Host-ionosphere_account="));
  const out: { location: string; cookie: string; replayLocation?: string } = { location: res.headers.get("location") ?? "", cookie: session ? session.split(";")[0]! : "" };
  if (tamper.replay) {
    const again = await fetch(cb, { redirect: "manual", headers: { cookie: stateCookie } });
    out.replayLocation = again.headers.get("location") ?? "";
  }
  return out;
}

function idClaims(issuer: string, sub: string, extra: Record<string, unknown> = {}) {
  return (nonce: string) => ({ iss: issuer, aud: "client-1", sub, nonce, exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000), ...extra });
}

async function adminSetup(contract?: MfaEvidenceContract): Promise<Ctx & { adminId: string; secret: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const idp = await fakeIdp();
  const adminId = (await createAdminUser(db, { username: "ops@ionosphere.test", role: ADMIN_ROLE.owner, password: "pw" }))!;
  const secret = (await beginAdminTotpEnrollment(db, adminId, (await issueAdminEnrollCode(db, adminId))!, KEY))!;
  await confirmAdminTotpEnrollment(db, adminId, totpNow(secret), KEY);
  const client = new OidcClient({ id: "corp", issuer: idp.issuer, clientId: "client-1", clientSecret: "s", ...(contract ? { mfaContract: contract } : {}) });
  let base = "";
  const server = new AdminApiServer({
    db,
    store: new Store(db),
    resolveTxt: async () => [],
    resolveMx: async () => [],
    masterKey: KEY,
    oidc: new OidcLoginFlow({ db, realm: "admin", providers: new Map([["corp", { client }]]), callbackUrl: "https://admin.ionosphere.test/admin/session/oidc/callback" }),
  });
  const port = await server.listen(0, "127.0.0.1");
  base = `http://127.0.0.1:${port}`;
  ctx = { db, idp, base, close: () => server.close() };
  return { ...ctx, adminId, secret };
}

describe("OIDC 로그인 — 관리 콘솔", () => {
  test("연결되지 않은 sub는 실패로 돌아가고 세션이 없다", async () => {
    const c = await adminSetup();
    const r = await ssoLogin(c.base, "/admin", c.idp, idClaims(c.idp.issuer, "nobody"));
    expect(r.location).toBe("/admin?sso=failed");
    expect(r.cookie).toBe("");
  });

  test("★계약 없음: 연결된 sub로 들어와도 로컬 TOTP 전까지 /v1이 막힌다", async () => {
    const c = await adminSetup();
    await linkAdminIdentity(c.db, "corp", "sub-ops", c.adminId);
    const r = await ssoLogin(c.base, "/admin", c.idp, idClaims(c.idp.issuer, "sub-ops", { acr: "mfa", auth_time: Math.floor(Date.now() / 1000) }));
    expect(r.location).toBe("/admin");
    const blocked = await fetch(`${c.base}/v1/commands`, { headers: { cookie: r.cookie } });
    expect(blocked.status).toBe(403);
    expect(((await blocked.json()) as { code: string }).code).toBe("mfa_required");
    const me = (await (await fetch(`${c.base}/admin/session`, { headers: { cookie: r.cookie } })).json()) as { csrfToken: string };
    const v = await fetch(`${c.base}/admin/session/mfa/verify`, {
      method: "POST",
      headers: { cookie: r.cookie, origin: c.base, "x-csrf-token": me.csrfToken, "content-type": "application/json" },
      body: JSON.stringify({ code: totpNow(c.secret, 1) }),
    });
    expect(v.status).toBe(200);
    expect((await fetch(`${c.base}/v1/commands`, { headers: { cookie: r.cookie } })).status).toBe(200);
  });

  test("계약 충족(acr 일치·최근 auth_time): 로컬 TOTP 없이 /v1이 열린다", async () => {
    const c = await adminSetup({ acceptAcr: ["urn:corp:totp"], maxAgeSec: 300 });
    await linkAdminIdentity(c.db, "corp", "sub-ops", c.adminId);
    const r = await ssoLogin(c.base, "/admin", c.idp, idClaims(c.idp.issuer, "sub-ops", { acr: "urn:corp:totp", auth_time: Math.floor(Date.now() / 1000) }));
    expect((await fetch(`${c.base}/v1/commands`, { headers: { cookie: r.cookie } })).status).toBe(200);
  });

  test("계약은 있지만 응답이 충족하지 못하면(오래된 auth_time) 로컬 TOTP를 묻는다", async () => {
    const c = await adminSetup({ acceptAcr: ["urn:corp:totp"], maxAgeSec: 300 });
    await linkAdminIdentity(c.db, "corp", "sub-ops", c.adminId);
    const r = await ssoLogin(c.base, "/admin", c.idp, idClaims(c.idp.issuer, "sub-ops", { acr: "urn:corp:totp", auth_time: Math.floor(Date.now() / 1000) - 3600 }));
    expect((await fetch(`${c.base}/v1/commands`, { headers: { cookie: r.cookie } })).status).toBe(403);
  });

  test("★state는 1회용이고, 브라우저 state 쿠키와 다르거나 nonce가 다르면 거절한다", async () => {
    const c = await adminSetup();
    await linkAdminIdentity(c.db, "corp", "sub-ops", c.adminId);
    const replay = await ssoLogin(c.base, "/admin", c.idp, idClaims(c.idp.issuer, "sub-ops"), { replay: true });
    expect(replay.location).toBe("/admin");
    expect(replay.replayLocation).toBe("/admin?sso=failed");
    const forged = await ssoLogin(c.base, "/admin", c.idp, idClaims(c.idp.issuer, "sub-ops"), { stateCookie: "__Host-ionosphere_oidc_admin=attacker" });
    expect(forged.location).toBe("/admin?sso=failed");
    const badNonce = await ssoLogin(c.base, "/admin", c.idp, (_n) => idClaims(c.idp.issuer, "sub-ops")("other-nonce"));
    expect(badNonce.location).toBe("/admin?sso=failed");
    const badAud = await ssoLogin(c.base, "/admin", c.idp, (n) => ({ ...idClaims(c.idp.issuer, "sub-ops")(n), aud: "someone-else" }));
    expect(badAud.location).toBe("/admin?sso=failed");
  });

  test("공급자 목록은 로그인 화면이 버튼을 그리는 근거다", async () => {
    const c = await adminSetup();
    const r = (await (await fetch(`${c.base}/admin/session/oidc/providers`)).json()) as { providers: string[] };
    expect(r.providers).toEqual(["corp"]);
  });
});

describe("OIDC 로그인 — 메일 계정 셀프서비스", () => {
  test("그 테넌트에서 연결된 계정으로 셀프서비스 세션이 열린다, 다른 테넌트의 같은 sub는 아니다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const idp = await fakeIdp();
    const store = new Store(db);
    const { tenantId } = await store.createTenant("acme");
    const { tenantId: other } = await store.createTenant("other");
    const { accountId } = await store.createAccount({ tenantId, email: "alice@acme.test" });
    const { accountId: elsewhere } = await store.createAccount({ tenantId: other, email: "alice@other.test" });
    await createCredential(db, { accountId, password: "pw-long-enough" });
    // 다른 테넌트에 같은 sub 행이 있는 상황(공급자를 다른 테넌트로 옮겼던 경우) — 연결 명령으로는 이제 만들 수 없어
    // (sub의 최초 주인 기록은 테넌트와 무관하게 하나다, 마이그레이션 029) 행을 직접 넣는다. 조회가 테넌트를 넘지 않는지만 본다.
    await db.batch([
      {
        sql: `INSERT INTO directory_identities (id, tenant_id, provider, external_key, account_id, login_names, email, display_name, last_seen_at, status)
              VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, 1)`,
        params: ["01HZOTHERTENANTROW00000000", other, "oidc:corp", "sub-alice", elsewhere, "[]", Date.now()],
      },
    ]);
    const client = new OidcClient({ id: "corp", issuer: idp.issuer, clientId: "client-1", clientSecret: "s" });
    const server = new SelfServiceServer({
      db,
      store,
      masterKey: KEY,
      oidc: new OidcLoginFlow({ db, realm: "account", providers: new Map([["corp", { client, tenantId }]]), callbackUrl: "https://account.ionosphere.test/account/session/oidc/callback" }),
    });
    const port = await server.listen(0, "127.0.0.1");
    const base = `http://127.0.0.1:${port}`;
    ctx = { db, idp, base, close: () => server.close() };

    const miss = await ssoLogin(base, "/account", idp, idClaims(idp.issuer, "sub-alice"));
    expect(miss.location).toBe("/account?sso=failed");

    await linkAccountOidcIdentity(db, tenantId, "corp", "sub-alice", accountId);
    const ok = await ssoLogin(base, "/account", idp, idClaims(idp.issuer, "sub-alice"));
    expect(ok.location).toBe("/account");
    const me = (await (await fetch(`${base}/account/session`, { headers: { cookie: ok.cookie } })).json()) as { email: string; mfaEnrolled: boolean };
    expect(me.email).toBe("alice@acme.test");
    // 로컬 TOTP 미등록 — 민감 작업은 여전히 막힌다(D3).
    const csrf = ((await (await fetch(`${base}/account/session`, { headers: { cookie: ok.cookie } })).json()) as { csrfToken: string }).csrfToken;
    const made = await fetch(`${base}/account/app-passwords`, { method: "POST", headers: { cookie: ok.cookie, origin: base, "x-csrf-token": csrf, "content-type": "application/json" }, body: "{}" });
    expect(((await made.json()) as { code: string }).code).toBe("mfa_required");
  });
});
