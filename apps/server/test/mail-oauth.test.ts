/**
 * 메일 클라이언트용 외부 OAuth access token(E4) — 검증기 단위 + IMAP XOAUTH2 실소켓 e2e.
 *
 *  - 메일 audience·scope가 맞고 연결된 sub이며 SASL 사용자가 그 계정이면 들어온다.
 *  - ID 토큰(aud=clientId)·scope 없음·만료·연결 안 됨·사용자 불일치·허용 안 된 표면은 전부 같은 실패.
 *  - 로컬 자격증명이 먼저이고, JWT 모양이 아니면 IdP를 부르지 않는다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { createServer, type Server } from "node:http";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign } from "node:crypto";
import type { Jwk } from "@ionosphere/core";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { linkAccountOidcIdentity, Store } from "@ionosphere/store";
import { MailOAuthVerifier } from "../src/mail-oauth.ts";
import { oidcProvidersFromJson, type ParsedOidcProvider } from "../src/oidc-config.ts";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
let idp: Server;
let issuer = "";
let jwksCalls = 0;

function token(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "k1", typ: "at+jwt" }): string {
  const input = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}`;
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), key.privateKey).toString("base64url")}`;
}
function mailClaims(sub: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: issuer, aud: "mail-api", sub, scope: "openid mail", exp: now + 300, iat: now, ...extra };
}

beforeAll(async () => {
  idp = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    res.setHeader("content-type", "application/json");
    if (u.pathname === "/.well-known/openid-configuration") {
      res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/a`, token_endpoint: `${issuer}/t`, jwks_uri: `${issuer}/jwks` }));
    } else if (u.pathname === "/jwks") {
      jwksCalls++;
      res.end(JSON.stringify({ keys: [{ ...(key.publicKey.export({ format: "jwk" }) as Jwk), kid: "k1", alg: "RS256" }] }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
  await new Promise<void>((r) => idp.listen(0, "127.0.0.1", r));
  const a = idp.address();
  issuer = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterAll(async () => {
  await new Promise<void>((r) => idp.close(() => r()));
});

function providers(tenantId: string, surfaces?: string[]): ParsedOidcProvider[] {
  return oidcProvidersFromJson(
    JSON.stringify([
      {
        id: "corp",
        realm: "account",
        tenantId,
        issuer,
        clientId: "web-client",
        clientSecret: "not-a-live-secret",
        mailAccessToken: { audience: "mail-api", requiredScope: "mail", ...(surfaces ? { surfaces } : {}) },
      },
    ]),
  );
}

async function fixture(surfaces?: string[]): Promise<{ db: DbDriver; v: MailOAuthVerifier; accountId: string }> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);
  const { tenantId } = await store.createTenant("acme");
  const { accountId } = await store.createAccount({ tenantId, email: "alice@acme.test" });
  await store.createAccount({ tenantId, email: "bob@acme.test" });
  await linkAccountOidcIdentity(db, tenantId, "corp", "sub-alice", accountId);
  return { db, v: new MailOAuthVerifier(db, providers(tenantId, surfaces)), accountId };
}

describe("MailOAuthVerifier", () => {
  test("메일 audience·scope·연결·사용자가 맞으면 계정과 credKind를 돌려준다", async () => {
    const f = await fixture();
    const r = await f.v.authenticate("Alice@acme.test", token(mailClaims("sub-alice")), "imap");
    expect(r).toMatchObject({ accountId: f.accountId, credKind: "oauth:corp" });
    // 만료 시각을 함께 올린다 — 어댑터가 그 시각에 연결을 닫는다.
    expect(typeof r?.expiresAt === "number" && r.expiresAt > Date.now()).toBe(true);
    await f.db.close();
  });

  test("★ID 토큰(aud=웹 clientId)·scope 없음·만료·연결 안 됨·사용자 불일치는 전부 null", async () => {
    const f = await fixture();
    const now = Math.floor(Date.now() / 1000);
    for (const t of [
      token(mailClaims("sub-alice", { aud: "web-client", nonce: "n" })),
      token(mailClaims("sub-alice", { scope: "openid profile" })),
      token(mailClaims("sub-alice", { exp: now - 600 })),
      token(mailClaims("sub-nobody")),
    ]) {
      expect(await f.v.authenticate("alice@acme.test", t, "imap")).toBeNull();
    }
    expect(await f.v.authenticate("bob@acme.test", token(mailClaims("sub-alice")), "imap")).toBeNull();
    await f.db.close();
  });

  test("scp 배열 형식의 scope도 읽는다", async () => {
    const f = await fixture();
    const t = token({ ...mailClaims("sub-alice"), scope: undefined, scp: ["mail"] });
    expect((await f.v.authenticate("alice@acme.test", t, "imap"))?.accountId).toBe(f.accountId);
    await f.db.close();
  });

  test("허용 표면 밖이면 null, JWT 모양이 아니면 IdP를 부르지 않는다", async () => {
    const f = await fixture(["imap"]);
    expect(await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice")), "submission")).toBeNull();
    const before = jwksCalls;
    expect(await f.v.authenticate("alice@acme.test", "plain-password", "imap")).toBeNull();
    expect(jwksCalls).toBe(before);
    await f.db.close();
  });

  test("설정: audience가 clientId와 같거나 admin 영역이면 기동 전에 거부한다", () => {
    const base = { id: "corp", realm: "account", tenantId: "t", issuer, clientId: "web-client", clientSecret: "x" };
    expect(() => oidcProvidersFromJson(JSON.stringify([{ ...base, mailAccessToken: { audience: "web-client", requiredScope: "mail" } }]))).toThrow(/clientId와 달라야/);
    expect(() => oidcProvidersFromJson(JSON.stringify([{ ...base, realm: "admin", mailAccessToken: { audience: "m", requiredScope: "mail" } }]))).toThrow(/realm=account/);
  });
});

describe("IMAP XOAUTH2 e2e(외부 access token)", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  const SOH = String.fromCharCode(1);
  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-mail-oauth-"));
    // 테넌트 id는 앱이 만든 뒤에야 알 수 있다 — 먼저 띄우고, 공급자 설정은 그 테넌트로 만든다.
    const probe = new IonosphereApp({ hostname: "test.local", dbPath: join(blobRoot, "db.sqlite"), blobRoot, resolver: offlineResolver() });
    await probe.start();
    await probe.createUser("alice@acme.test", "local-pw-long");
    const { rows } = await probe.db.query({ sql: "SELECT id, tenant_id FROM accounts WHERE email = ?", params: ["alice@acme.test"] });
    const tenantId = String(rows[0]!.tenant_id);
    await linkAccountOidcIdentity(probe.db, tenantId, "corp", "sub-alice", String(rows[0]!.id));
    await probe.stop();
    app = new IonosphereApp({ hostname: "test.local", dbPath: join(blobRoot, "db.sqlite"), blobRoot, imapPort: 0, submissionPort: 0, resolver: offlineResolver(), oidcProviders: providers(tenantId) });
    await app.start();
  }, E2E_HOOK_TIMEOUT_MS);
  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  /** 연결을 열고 XOAUTH2로 인증한 뒤, 명령 없이 기다린다. 서버가 닫으면 그때까지 받은 전부를 돌려준다. */
  async function idleAfterAuth(port: number, greet: string, authLine: (ir: string) => string, okPrefix: string, user: string, tok: string): Promise<string> {
    const s = connect(port, "127.0.0.1");
    let buf = "";
    s.on("data", (c) => (buf += c.toString("latin1")));
    const closed = new Promise<void>((r) => s.once("close", () => r()));
    const until = Date.now() + 8000;
    while (!buf.includes(greet)) {
      if (Date.now() > until) throw new Error(`no greeting: ${buf}`);
      await new Promise((r) => setTimeout(r, 10));
    }
    const ir = Buffer.from(`user=${user}${SOH}auth=Bearer ${tok}${SOH}${SOH}`).toString("base64");
    s.write(authLine(ir));
    while (!buf.includes(okPrefix)) {
      if (Date.now() > until) throw new Error(`no auth ok: ${buf}`);
      await new Promise((r) => setTimeout(r, 10));
    }
    await Promise.race([closed, new Promise((r) => setTimeout(r, 7000))]);
    s.destroy();
    return buf;
  }

  test("★토큰이 만료되면 명령이 없어도 IMAP 연결을 닫는다(사용자 결정 2026-10-18)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const out = await idleAfterAuth(app.imapPort, "* OK", (ir) => `a1 AUTHENTICATE XOAUTH2 ${ir}\r\n`, "a1 OK", "alice@acme.test", token(mailClaims("sub-alice", { iat: now, exp: now + 2 })));
    expect(out).toContain("* BYE authentication expired");
  }, 15_000);

  test("★토큰이 만료되면 SMTP 제출 연결을 421로 닫는다", async () => {
    const now = Math.floor(Date.now() / 1000);
    const s = connect(app.submissionPort, "127.0.0.1");
    let buf = "";
    s.on("data", (c) => (buf += c.toString("latin1")));
    const closed = new Promise<void>((r) => s.once("close", () => r()));
    const waitFor = async (needle: string) => {
      const until = Date.now() + 8000;
      while (!buf.includes(needle)) {
        if (Date.now() > until) throw new Error(`timeout ${needle}: ${buf}`);
        await new Promise((r) => setTimeout(r, 10));
      }
    };
    await waitFor("220");
    s.write("EHLO client.example.com\r\n");
    await waitFor("250 ");
    const ir = Buffer.from(`user=alice@acme.test${SOH}auth=Bearer ${token(mailClaims("sub-alice", { iat: now, exp: now + 2 }))}${SOH}${SOH}`).toString("base64");
    s.write(`AUTH XOAUTH2 ${ir}\r\n`);
    await waitFor("235");
    let serverClosed = false;
    await Promise.race([closed.then(() => (serverClosed = true)), new Promise((r) => setTimeout(r, 7000))]);
    expect(buf).toContain("421 4.7.0 Authentication expired");
    // ★연결이 완전히 끊겨야 한다 — 쓰기 쪽만 닫으면 421을 무시한 클라이언트가 계속 제출할 수 있다.
    expect(serverClosed).toBe(true);
    s.destroy();
  }, 15_000);

  async function imapAuth(user: string, tok: string): Promise<string> {
    const s = connect(app.imapPort, "127.0.0.1");
    let buf = "";
    s.on("data", (c) => (buf += c.toString("latin1")));
    const wait = async (needle: string) => {
      const until = Date.now() + 4000;
      while (!buf.includes(needle)) {
        if (Date.now() > until) throw new Error(`timeout ${needle}: ${buf}`);
        await new Promise((r) => setTimeout(r, 10));
      }
    };
    await wait("* OK");
    const ir = Buffer.from(`user=${user}${SOH}auth=Bearer ${tok}${SOH}${SOH}`).toString("base64");
    s.write(`a1 AUTHENTICATE XOAUTH2 ${ir}\r\n`);
    await wait("a1 ");
    s.destroy();
    return buf.split("\r\n").find((l) => l.startsWith("a1 ")) ?? "";
  }

  test("연결된 sub의 메일 access token으로 IMAP에 들어오고, ID 토큰으로는 못 들어온다", async () => {
    expect(await imapAuth("alice@acme.test", token(mailClaims("sub-alice")))).toStartWith("a1 OK");
    expect(await imapAuth("alice@acme.test", token(mailClaims("sub-alice", { aud: "web-client" })))).toStartWith("a1 NO");
  });
});

describe("보안 검토 반영(2026-10-18)", () => {
  test("azp가 메일 앱 클라이언트여도 받는다(access token의 azp는 aud와 다른 것이 정상)", async () => {
    const f = await fixture();
    expect((await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice", { azp: "thunderbird" })), "imap"))?.accountId).toBe(f.accountId);
    await f.db.close();
  });

  test("★typ가 at+jwt가 아니면(ID 토큰 형태) 거절한다", async () => {
    const f = await fixture();
    expect(await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice"), { alg: "RS256", kid: "k1", typ: "JWT" }), "imap")).toBeNull();
    expect(await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice"), { alg: "RS256", kid: "k1" }), "imap")).toBeNull();
    await f.db.close();
  });

  test("★수명 상한 5분(사용자 결정): 넘으면 거절, iat를 비우거나 과거로 꾸며도 통하지 않는다", async () => {
    const f = await fixture();
    const now = Math.floor(Date.now() / 1000);
    expect((await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice", { iat: now, exp: now + 299 })), "imap"))?.accountId).toBe(f.accountId);
    expect(await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice", { iat: now, exp: now + 301 })), "imap")).toBeNull();
    expect(await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice", { iat: undefined, exp: now + 600 })), "imap")).toBeNull();
    // 발급은 오래전으로 꾸미고 수명은 짧아 보이게 해도, 남은 수명(exp − 지금)이 상한을 넘으면 거절한다.
    expect(await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice", { iat: now + 500, exp: now + 600 })), "imap")).toBeNull();
    await f.db.close();
  });

  test("설정으로 수명 상한을 5분보다 길게 바꿀 수 없다", () => {
    const base = { id: "corp", realm: "account", tenantId: "t", issuer, clientId: "web-client", clientSecret: "x" };
    expect(() => oidcProvidersFromJson(JSON.stringify([{ ...base, mailAccessToken: { audience: "m", requiredScope: "mail", maxLifetimeSec: 3600 } }]))).toThrow(/300초 이하/);
    expect(oidcProvidersFromJson(JSON.stringify([{ ...base, mailAccessToken: { audience: "m", requiredScope: "mail", maxLifetimeSec: 120 } }]))[0]!.mailAccessToken?.maxLifetimeSec).toBe(120);
  });

  test("★위조 kid를 여러 번 보내도 JWKS 강제 재요청은 간격당 한 번뿐이다", async () => {
    const f = await fixture();
    await f.v.authenticate("alice@acme.test", token(mailClaims("sub-alice")), "imap"); // 캐시 채우기
    const before = jwksCalls;
    const forged = () => token(mailClaims("sub-alice"), { alg: "RS256", kid: `forged-${Math.random()}`, typ: "at+jwt" });
    await Promise.all(Array.from({ length: 20 }, () => f.v.authenticate("alice@acme.test", forged(), "imap")));
    for (let i = 0; i < 5; i++) await f.v.authenticate("alice@acme.test", forged(), "imap");
    expect(jwksCalls - before).toBeLessThanOrEqual(1);
    await f.db.close();
  });
});
