/**
 * AdminApiServer 통합테스트 — 인메모리 sqlite + 실소켓 node:http(임시 포트) + fetch() 클라이언트.
 */
import { afterAll, afterEach, describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { authenticate, Store } from "@ionosphere/store";
import { AdminApiServer, type AdminApiDeps } from "../src/server.ts";

const ROOT_TOKEN = "root-secret-test-token";

/** 가변 리졸버 홀더 — deps.resolveTxt/resolveMx 클로저가 이 객체의 메서드를 참조하므로
 *  테스트 도중 `resolvers.txt = ...`로 갈아끼우면 이미 등록된 서버 인스턴스에도 즉시 반영된다. */
interface Resolvers {
  txt: (name: string) => Promise<string[]>;
  mx: (name: string) => Promise<{ exchange: string; preference: number }[]>;
}

interface Fixture {
  db: DbDriver;
  server: AdminApiServer;
  port: number;
  baseUrl: string;
  resolvers: Resolvers;
}

let fx: Fixture | undefined;

async function setup(overrides: Partial<AdminApiDeps> = {}): Promise<Fixture> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const store = new Store(db);

  const resolvers: Resolvers = {
    txt: async (_name: string) => [],
    mx: async (_name: string) => [],
  };

  const deps: AdminApiDeps = {
    db,
    store,
    resolveTxt: (name) => resolvers.txt(name),
    resolveMx: (name) => resolvers.mx(name),
    rootToken: ROOT_TOKEN,
    ...overrides,
  };
  const server = new AdminApiServer(deps);
  const port = await server.listen(0, "127.0.0.1");
  const fixture: Fixture = { db, server, port, baseUrl: `http://127.0.0.1:${port}`, resolvers };
  fx = fixture;
  return fixture;
}

afterEach(async () => {
  if (fx) {
    await fx.server.close();
    await fx.db.close();
    fx = undefined;
  }
});

/**
 * ★node:test는 파일 프로세스가 **열린 핸들이 없어야** 끝난다. 이 파일은 fixture를 33개
 * 만들고 afterEach가 33번 다 정리하는데도 `TCPServerWrap`이 하나 남아 프로세스가 안 죽었다
 * (실측: `--test-force-exit`을 주면 33/33 통과 — 테스트 로직은 정상이다).
 *
 * 원인을 서버·fetch·fixture 누수에서 각각 좁혀 봤지만 개별 재현이 되지 않았고, 같은 구조의
 * 다른 파일(domain-guards·provision-domain·store·mta·mail-auth)은 전부 정상 종료한다.
 * 이 파일만의 누적 상태로 보이는데 원인을 특정하지 못했다.
 *
 * 그래서 **파일이 끝날 때 남은 소켓을 명시적으로 끊는다.** 감추는 것이 아니라, 테스트가
 * 자기가 연 것을 자기가 닫는다는 뜻이다 — `--test-force-exit`(전역 플래그로 모든 누수를
 * 덮는 것)을 쓰지 않는 이유가 그것이다. 원인을 찾으면 이 훅을 지운다.
 */
afterAll(() => {
  // node의 활성 핸들 중 이 파일이 만든 리스너가 남아 있으면 끊는다.
  for (const h of (process as unknown as { _getActiveHandles?: () => { close?: () => void }[] })._getActiveHandles?.() ?? []) {
    if (typeof h.close === "function" && h.constructor?.name === "Server") h.close();
  }
});

function authHeader(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

async function bootstrapTenant(f: Fixture): Promise<{ tenantId: string; apiKey: string }> {
  const tenantRes = await fetch(`${f.baseUrl}/v1/tenants`, {
    method: "POST",
    headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
    body: JSON.stringify({ name: "acme" }),
  });
  expect(tenantRes.status).toBe(200);
  const { tenantId } = (await tenantRes.json()) as { tenantId: string };

  const keyRes = await fetch(`${f.baseUrl}/v1/api-keys`, {
    method: "POST",
    headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
    body: JSON.stringify({ tenantId }),
  });
  expect(keyRes.status).toBe(200);
  const { key } = (await keyRes.json()) as { id: string; key: string; scopes: string };
  return { tenantId, apiKey: key };
}

/**
 * 도메인 생성 → 리졸버에 토큰/MX/SPF 심기 → verify까지 한 번에(status=1).
 * 계정·알리아스 생성이 **검증된 소유 도메인**을 요구하므로 대부분의 테스트에 필요하다.
 */
async function provisionVerifiedDomain(f: Fixture, apiKey: string, name: string): Promise<string> {
  // 멱등 — 같은 이름을 두 번 프로비저닝하면 domain_name_claims PK 충돌로 verify가 409가 된다.
  const { rows } = await f.db.query({ sql: "SELECT id FROM domains WHERE name = ? AND status = 1", params: [name] });
  const existing = rows[0];
  if (existing) return String(existing.id);

  const createRes = await fetch(`${f.baseUrl}/v1/domains`, {
    method: "POST",
    headers: { ...authHeader(apiKey), "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  expect(createRes.status).toBe(200);
  const created = (await createRes.json()) as { domainId: string; verifyToken: string };

  const prevTxt = f.resolvers.txt;
  const prevMx = f.resolvers.mx;
  f.resolvers.txt = async (n: string) => {
    if (n === `_ionosphere-verify.${name}`) return [created.verifyToken];
    if (n === name) return ["v=spf1 -all"];
    return prevTxt(n);
  };
  f.resolvers.mx = async (n: string) =>
    n === name ? [{ exchange: `mx.${name}`, preference: 10 }] : prevMx(n);

  const verifyRes = await fetch(`${f.baseUrl}/v1/domains/${created.domainId}/verify`, {
    method: "POST",
    headers: authHeader(apiKey),
  });
  expect(await verifyRes.json()).toEqual({ status: "active" });
  return created.domainId;
}

describe("AdminApiServer", () => {
  test("GET /healthz — 인증 없이 200", async () => {
    const f = await setup();
    const res = await fetch(`${f.baseUrl}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  test("인증 없이/잘못된 키로 보호 라우트 접근 시 401", async () => {
    const f = await setup();

    const noAuth = await fetch(`${f.baseUrl}/v1/accounts`);
    expect(noAuth.status).toBe(401);

    const badAuth = await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader("bogus-key") });
    expect(badAuth.status).toBe(401);

    const domains = await fetch(`${f.baseUrl}/v1/domains`, { headers: authHeader("bogus-key") });
    expect(domains.status).toBe(401);

    const queue = await fetch(`${f.baseUrl}/v1/queue`, { headers: authHeader("bogus-key") });
    expect(queue.status).toBe(401);
  });

  test("root 토큰 → 테넌트 생성 → api-key 발급(평문 1회) → 발급된 키로 인증 성공", async () => {
    const f = await setup();
    const { tenantId, apiKey } = await bootstrapTenant(f);
    expect(tenantId).toBeTruthy();
    expect(apiKey.startsWith("amk_")).toBe(true);

    const res = await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(apiKey) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([]);
  });

  test("root 토큰이 아닌 키로 /v1/tenants 호출 시 403", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const res = await fetch(`${f.baseUrl}/v1/tenants`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ name: "other" }),
    });
    expect(res.status).toBe(403);
  });

  test("계정 생성 → 목록 반영 → store.authenticate로 설정한 비밀번호 인증 성공", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    await provisionVerifiedDomain(f, apiKey, "acme.test");

    const createRes = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "user@acme.test", password: "s3cret-pw" }),
    });
    expect(createRes.status).toBe(200);
    const { accountId } = (await createRes.json()) as { accountId: string };
    expect(accountId).toBeTruthy();

    const listRes = await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(apiKey) });
    const list = (await listRes.json()) as { email: string; status: number }[];
    expect(list).toHaveLength(1);
    expect(list[0]!.email).toBe("user@acme.test");
    expect(list[0]!.status).toBe(1);

    const authResult = await authenticate(f.db, "user@acme.test", "s3cret-pw", "imap");
    expect(authResult?.accountId).toBe(accountId);

    const wrongPw = await authenticate(f.db, "user@acme.test", "nope", "imap");
    expect(wrongPw).toBeNull();
  });

  test("DELETE /v1/accounts/:id — status=2 소프트 삭제", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    await provisionVerifiedDomain(f, apiKey, "acme.test");
    const createRes = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "gone@acme.test", password: "pw12345" }),
    });
    const { accountId } = (await createRes.json()) as { accountId: string };

    const delRes = await fetch(`${f.baseUrl}/v1/accounts/${accountId}`, {
      method: "DELETE",
      headers: authHeader(apiKey),
    });
    expect(delRes.status).toBe(200);

    const { rows } = await f.db.query({ sql: "SELECT status FROM accounts WHERE id = ?", params: [accountId] });
    expect(Number(rows[0]!.status)).toBe(2);
  });

  /**
   * 크로스 테넌트 주소 선점 회귀 — 계정 생성에 도메인 소유 게이트가 없던 시절, 남의 검증된
   * 도메인 이름으로 계정을 만들 수 있었다. accounts.email이 전역 UNIQUE라 진짜 소유 테넌트는
   * 그 주소를 영영 만들 수 없게 되고(선점 DoS), 수신 라우팅 폴백은 그 계정으로 배달했다.
   * 게이트는 알리아스 갈래에만 손으로 적혀 있었다 — 그래서 공용 헬퍼로 올렸다.
   */
  test("남의 검증된 도메인으로 계정 생성 시 404 — 주소 선점 차단", async () => {
    const f = await setup();
    const victim = await bootstrapTenant(f);
    await provisionVerifiedDomain(f, victim.apiKey, "victim.test");

    const attacker = await bootstrapTenant(f);
    const squat = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(attacker.apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "ceo@victim.test", password: "pw12345" }),
    });
    expect(squat.status).toBe(404);

    // 선점이 막혔으니 진짜 소유자는 그대로 만들 수 있어야 한다(UNIQUE 충돌 없음).
    const legit = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(victim.apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "ceo@victim.test", password: "pw12345" }),
    });
    expect(legit.status).toBe(200);
  });

  test("미검증 소유 도메인으로 계정 생성 시 409 — 조용한 no-op 대신 즉시 실패", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const createRes = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ name: "pending.test" }),
    });
    expect(createRes.status).toBe(200);

    const res = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "user@pending.test", password: "pw12345" }),
    });
    expect(res.status).toBe(409);
  });

  test("도메인 생성 → verifyToken/dnsInstructions 반환, 가짜 리졸버에 토큰 없으면 verify 실패", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);

    const createRes = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ name: "example.test" }),
    });
    expect(createRes.status).toBe(200);
    const created = (await createRes.json()) as {
      domainId: string;
      verifyToken: string;
      dnsInstructions: { type: string; name: string; value: string; purpose: string }[];
    };
    expect(created.verifyToken).toMatch(/^[0-9a-f]{32}$/);
    // 생성 시 검증 토큰 + DKIM 2종 + SPF/DMARC 안내까지 일괄 반환(add-domain 일원화)
    expect(created.dnsInstructions[0]).toMatchObject({
      type: "TXT",
      name: "_ionosphere-verify.example.test",
      value: created.verifyToken,
    });
    const names = created.dnsInstructions.map((r) => r.name);
    expect(names).toContain("rsa1._domainkey.example.test");
    expect(names).toContain("ed1._domainkey.example.test");
    expect(names).toContain("_dmarc.example.test");
    // MTA-STS + TLS-RPT 발행 레코드(Phase 5)
    expect(names).toContain("_mta-sts.example.test");
    expect(names).toContain("_smtp._tls.example.test");
    expect(created.dnsInstructions.find((r) => r.name === "_mta-sts.example.test")?.value).toMatch(/^v=STSv1; id=/);
    // dkim_keys가 생성 시점에 프로비저닝됐는지 (rsa1/ed1 active)
    const { rows: keyRows } = await f.db.query({
      sql: "SELECT selector FROM dkim_keys WHERE domain_id = ? ORDER BY selector",
      params: [created.domainId],
    });
    expect(keyRows.map((r) => String(r.selector))).toEqual(["ed1", "rsa1"]);

    // 가짜 리졸버가 아직 토큰을 리턴하지 않음 — verify 실패해야 함
    const verifyRes = await fetch(`${f.baseUrl}/v1/domains/${created.domainId}/verify`, {
      method: "POST",
      headers: authHeader(apiKey),
    });
    expect(verifyRes.status).toBe(200);
    const failed = (await verifyRes.json()) as { status: string; checks?: Record<string, boolean> };
    expect(failed.status).toBe("failed");
    expect(failed.checks).toEqual({ token: false, mx: false, spf: false });

    const { rows } = await f.db.query({ sql: "SELECT status FROM domains WHERE id = ?", params: [created.domainId] });
    expect(Number(rows[0]!.status)).toBe(0);
  });

  /**
   * 개명(mailer → ionosphere) 전에 검증을 마친 도메인은 `_mailer-verify` 레코드를 이미 게시해
   * 두었다. 새 이름만 본다면 그 도메인들이 재검증에서 전부 실패하고 비활성으로 떨어진다 —
   * 남의 DNS를 우리가 고칠 수는 없다. 이 테스트가 그 호환을 지킨다.
   */
  test("★개명 전 이름(_mailer-verify)으로 게시된 레코드도 검증을 통과한다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);

    const createRes = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ name: "legacy-verify.test" }),
    });
    const created = (await createRes.json()) as { domainId: string; verifyToken: string };

    // 새 이름은 없고 **구 이름만** 게시된 상태를 만든다.
    f.resolvers.txt = async (name: string) => {
      if (name === "_mailer-verify.legacy-verify.test") return [created.verifyToken];
      if (name === "legacy-verify.test") return ["v=spf1 -all"];
      return [];
    };
    f.resolvers.mx = async (_name: string) => [{ exchange: "mx.legacy-verify.test", preference: 10 }];

    const verifyRes = await fetch(`${f.baseUrl}/v1/domains/${created.domainId}/verify`, {
      method: "POST",
      headers: authHeader(apiKey),
    });
    expect(verifyRes.status).toBe(200);
    expect(await verifyRes.json()).toEqual({ status: "active" });
  });

  test("verify 성공(토큰+MX+SPF 모두 통과) → status=1 + domain_name_claims 앵커 행 생성", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);

    const createRes = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ name: "verified.test" }),
    });
    const created = (await createRes.json()) as { domainId: string; verifyToken: string };

    f.resolvers.txt = async (name: string) => {
      if (name === "_ionosphere-verify.verified.test") return [created.verifyToken];
      if (name === "verified.test") return ["v=spf1 -all"];
      return [];
    };
    f.resolvers.mx = async (_name: string) => [{ exchange: "mx.verified.test", preference: 10 }];

    const verifyRes = await fetch(`${f.baseUrl}/v1/domains/${created.domainId}/verify`, {
      method: "POST",
      headers: authHeader(apiKey),
    });
    expect(verifyRes.status).toBe(200);
    expect(await verifyRes.json()).toEqual({ status: "active" });

    const { rows: domainRows } = await f.db.query({
      sql: "SELECT status FROM domains WHERE id = ?",
      params: [created.domainId],
    });
    expect(Number(domainRows[0]!.status)).toBe(1);

    const { rows: claimRows } = await f.db.query({
      sql: "SELECT domain_id FROM domain_name_claims WHERE name = ?",
      params: ["verified.test"],
    });
    expect(claimRows).toHaveLength(1);
    expect(claimRows[0]!.domain_id).toBe(created.domainId);

    // 재검증 idempotent — 이미 active면 그대로 active 반환
    const reverify = await fetch(`${f.baseUrl}/v1/domains/${created.domainId}/verify`, {
      method: "POST",
      headers: authHeader(apiKey),
    });
    expect(await reverify.json()).toEqual({ status: "active" });
  });

  test("이미 활성화된 이름을 다른 테넌트가 클레임 시도 → 409 (anchor PK 충돌)", async () => {
    const f = await setup();
    const { apiKey: apiKeyA } = await bootstrapTenant(f);
    const { apiKey: apiKeyB } = await bootstrapTenant(f);

    f.resolvers.txt = async (name: string) => {
      if (name === "_ionosphere-verify.shared.test") return ["will-be-overridden"];
      if (name === "shared.test") return ["v=spf1 -all"];
      return [];
    };
    f.resolvers.mx = async () => [{ exchange: "mx.shared.test", preference: 10 }];

    const createA = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKeyA), "content-type": "application/json" },
      body: JSON.stringify({ name: "shared.test" }),
    });
    const domainA = (await createA.json()) as { domainId: string; verifyToken: string };

    const createB = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKeyB), "content-type": "application/json" },
      body: JSON.stringify({ name: "shared.test" }),
    });
    const domainB = (await createB.json()) as { domainId: string; verifyToken: string };

    // 각 도메인 행마다 실제 토큰이 다르므로, 리졸버가 "현재 검증중인 토큰"을 리턴하도록 동적으로 맞춘다
    const tokens = new Set([domainA.verifyToken, domainB.verifyToken]);
    f.resolvers.txt = async (name: string) => {
      if (name === "_ionosphere-verify.shared.test") return [...tokens];
      if (name === "shared.test") return ["v=spf1 -all"];
      return [];
    };

    const verifyA = await fetch(`${f.baseUrl}/v1/domains/${domainA.domainId}/verify`, {
      method: "POST",
      headers: authHeader(apiKeyA),
    });
    expect(verifyA.status).toBe(200);
    expect(await verifyA.json()).toEqual({ status: "active" });

    const verifyB = await fetch(`${f.baseUrl}/v1/domains/${domainB.domainId}/verify`, {
      method: "POST",
      headers: authHeader(apiKeyB),
    });
    expect(verifyB.status).toBe(409);

    const { rows: domainBRows } = await f.db.query({
      sql: "SELECT status FROM domains WHERE id = ?",
      params: [domainB.domainId],
    });
    expect(Number(domainBRows[0]!.status)).toBe(0); // 롤백되어 unverified 그대로
  });

  test("GET /v1/queue — 직접 삽입한 mta_queue 행 반영 + status 필터", async () => {
    const f = await setup();
    const { tenantId, apiKey } = await bootstrapTenant(f);

    await f.db.batch([
      {
        sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
              VALUES ('q1', ?, 'acct1', NULL, 'blob1', 'from@acme.test', 'verp1', 'to@remote.test', 'remote.test', 0, 0, 1000, NULL, NULL, 1000)`,
        params: [tenantId],
      },
      {
        sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
              VALUES ('q2', ?, 'acct1', NULL, 'blob2', 'from@acme.test', 'verp2', 'to2@remote.test', 'remote.test', 2, 3, 2000, NULL, 'bounced', 2000)`,
        params: [tenantId],
      },
    ]);

    const allRes = await fetch(`${f.baseUrl}/v1/queue`, { headers: authHeader(apiKey) });
    expect(allRes.status).toBe(200);
    const all = (await allRes.json()) as { id: string; status: number }[];
    expect(all).toHaveLength(2);

    const filteredRes = await fetch(`${f.baseUrl}/v1/queue?status=2`, { headers: authHeader(apiKey) });
    const filtered = (await filteredRes.json()) as { id: string; status: number; lastError: string | null }[];
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.id).toBe("q2");
    expect(filtered[0]!.lastError).toBe("bounced");
  });

  test("잘못된 JSON 바디 → 400 (500 아님)", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);

    const res = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: "{not valid json",
    });
    expect(res.status).toBe(400);
  });

  test("TLS 관리 — status/refresh/upload(root 전용), 미구성 시 501", async () => {
    const uploadedCalls: { cert: string; key: string }[] = [];
    const status = { mode: "selfsigned" as const, enabled: true, source: "test", sans: ["mx.test"], selfSigned: true, notAfter: Date.now() + 1000 };
    const f = await setup({
      tls: {
        status: async () => status,
        refresh: async () => ({ ...status, source: "refreshed" }),
        upload: async (cert, key) => {
          uploadedCalls.push({ cert, key });
          return { ...status, source: "uploaded" };
        },
      },
    });
    const { apiKey } = await bootstrapTenant(f);

    // root: status
    const st = await fetch(`${f.baseUrl}/v1/tls`, { headers: authHeader(ROOT_TOKEN) });
    expect(st.status).toBe(200);
    expect(((await st.json()) as { mode: string }).mode).toBe("selfsigned");
    // 테넌트 키 → 403
    expect((await fetch(`${f.baseUrl}/v1/tls`, { headers: authHeader(apiKey) })).status).toBe(403);
    // refresh
    const rf = await fetch(`${f.baseUrl}/v1/tls/refresh`, { method: "POST", headers: authHeader(ROOT_TOKEN) });
    expect(((await rf.json()) as { source: string }).source).toBe("refreshed");
    // upload
    const up = await fetch(`${f.baseUrl}/v1/tls/upload`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ cert: "CERTPEM", key: "KEYPEM" }),
    });
    expect(up.status).toBe(200);
    expect(uploadedCalls[0]).toEqual({ cert: "CERTPEM", key: "KEYPEM" });

    // tls 미구성 → 501
    const f2 = await setup();
    expect((await fetch(`${f2.baseUrl}/v1/tls`, { headers: authHeader(ROOT_TOKEN) })).status).toBe(501);
  });

  test("GET / 및 /admin → 관리 콘솔 HTML(무인증)", async () => {
    const f = await setup();
    for (const path of ["/", "/admin"]) {
      const res = await fetch(`${f.baseUrl}${path}`); // 토큰 없이
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/html");
      const html = await res.text();
      expect(html).toContain("ionosphere 관리 콘솔");
      expect(html).toContain("Bearer 토큰");
      /**
       * ★콘솔은 **무상태 스키마 구동**이다 — 기능 목록을 HTML에 갖고 있지 않고
       * `/v1/commands`로 받아 그린다. 그래서 "도메인 해제 버튼이 있는가"를 HTML에서 찾지
       * 않는다(예전엔 그렇게 확인했고, 그래서 API에 있는 기능이 화면에서 빠지는 회귀가
       * 생겼다). 대신 **서술을 받아 오는 배선**이 살아 있는지를 고정한다 — 이게 끊기면
       * 화면은 아무것도 그리지 못한다.
       */
      expect(html).toContain('api("GET", "/v1/commands")');
      expect(html).toContain('"/v1/commands/" + encodeURIComponent(name)');
    }
  });

  /**
   * 기능이 화면에 나타나는지는 **서술로** 확인한다. 명령을 추가하면 화면이 따라오고,
   * 이 테스트는 그 연결(서버가 무엇을 할 수 있다고 말하는가)만 본다.
   */
  test("GET /v1/commands — 화면이 그릴 근거(서술+인코딩)를 내려준다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const res = await fetch(`${f.baseUrl}/v1/commands`, { headers: authHeader(apiKey) });
    expect(res.status).toBe(200);
    const meta = (await res.json()) as {
      commands: { name: string; group: string; readOnly: boolean; destructive?: boolean; args: unknown[] }[];
      encodings: Record<string, { values: Record<string, number>; labels: Record<string, string> }>;
    };

    const names = meta.commands.map((c) => c.name);
    // 화면에서 도메인을 놓을 수 있어야 한다(예전 회귀) — 이제는 명령이 있으면 버튼이 생긴다.
    expect(names).toContain("domain-release");
    // 계정 정지 — 인코딩과 자동 집행에는 있었는데 사람이 쓸 입구가 없던 기능.
    expect(names).toContain("account-suspend");
    expect(names).toContain("account-activate");
    // 파괴적 표시가 실려야 화면이 2단계 확인을 건다(화면이 목록을 들면 새 명령에서 빠진다).
    expect(meta.commands.find((c) => c.name === "domain-release")?.destructive).toBe(true);

    /**
     * ★상태 인코딩은 **서버가 준다**. 화면이 사본을 들고 있다 스키마와 어긋나
     * 0을 "대기", 2를 "비활성"으로 표시한 적이 있다 — 실제로는 0=정지(가역),
     * 2=삭제 드레인(비가역)이라, 운영자가 "되살리지" 하고 누르면 되돌릴 수 없는 삭제였다.
     */
    expect(meta.encodings.accountStatus?.values.deleting).toBe(2);
    expect(meta.encodings.accountStatus?.values.suspended).toBe(0);
    expect(meta.encodings.suppressionReason?.values.hardBounce).toBe(0);
    expect(meta.encodings.accountStatus?.labels.deleting).toBeTruthy();
  });

  test("POST /v1/commands/:name — 콘솔이 쓰는 범용 입구", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    // 조회 명령: rows로 답한다.
    const list = await fetch(`${f.baseUrl}/v1/commands/account-list`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(list.status).toBe(200);
    expect(Array.isArray(((await list.json()) as { rows: unknown[] }).rows)).toBe(true);

    // 없는 명령은 404 — 화면이 낡은 서술로 부르면 조용히 통과하면 안 된다.
    const bogus = await fetch(`${f.baseUrl}/v1/commands/no-such-command`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: "{}",
    });
    expect(bogus.status).toBe(404);

    // root 전용 명령은 테넌트 키로 403(판단 근거는 명령 서술, 집행은 어댑터).
    const rootOnly = await fetch(`${f.baseUrl}/v1/commands/tenant-list`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: "{}",
    });
    expect(rootOnly.status).toBe(403);
  });

  test("shared mailbox 관리 명령은 조립층이 주입한 실제 포트를 호출한다", async () => {
    let flushes = 0;
    const f = await setup({
      sharedMailbox: {
        sync: async () => ({ message: "sync" }),
        rebuildHeaders: async () => ({ message: "headers" }),
        flushListingCache: async () => { flushes++; return { data: { entries: 3 }, message: "flushed" }; },
      },
    });
    const { apiKey } = await bootstrapTenant(f);
    const response = await fetch(`${f.baseUrl}/v1/commands/listing-cache-flush`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(200);
    expect((await response.json() as { data: { entries: number } }).data.entries).toBe(3);
    expect(flushes).toBe(1);
  });

  /**
   * ★콘솔 JS는 TS 템플릿 리터럴 안에 문자열로 들어 있어 **tsc가 문법을 보지 않는다** —
   * 따옴표 하나가 깨져도 빌드는 통과하고 브라우저에서만 백지가 된다. 실제로 이 파일의
   * 백틱 규약을 어겨 화면이 통째로 죽은 적이 있다. 그래서 파싱만이라도 여기서 강제한다.
   *
   * `new Function`으로 **구문 검사만** 한다(실행하지 않는다 — document가 없다).
   */
  test("관리 콘솔의 인라인 스크립트가 문법적으로 유효하다", async () => {
    const f = await setup();
    const html = await (await fetch(`${f.baseUrl}/admin`)).text();
    const script = html.slice(html.indexOf("<script>") + "<script>".length, html.lastIndexOf("</script>"));
    expect(script.length).toBeGreaterThan(1000);
    new Function(script); // 구문 오류면 여기서 throw
    /**
     * ★상태 인코딩이 **화면에 박혀 있지 않은지**를 본다(예전과 반대 방향의 검사다).
     * 인코딩은 런타임에 `/v1/commands`가 준다 — 스크립트에 숫자가 굳어 있으면 그 사본이
     * 다시 스키마와 어긋날 수 있고, 그것이 "되살리려다 삭제한" 사고의 뿌리였다.
     */
    expect(script).toContain("state.encodings");
    expect(script.includes('"deleting":2')).toBe(false);
    expect(script.includes('"hardBounce":0')).toBe(false);
    // 템플릿 리터럴 안에서 백틱을 쓰면 문자열이 조기 종료된다(과거 사고). 남아 있으면 안 된다.
    expect(script.includes("`")).toBe(false);
  });

  // ── 앱 비밀번호(cli.ts 전용이던 기능의 API 노출) ──────────────────────
  async function createAccount(f: Fixture, apiKey: string, email: string, password: string): Promise<string> {
    // 계정 주소는 **검증된 소유 도메인**이어야 한다 — 도메인 준비를 테스트마다 반복하지 않는다.
    await provisionVerifiedDomain(f, apiKey, email.slice(email.lastIndexOf("@") + 1));
    const res = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    expect(res.status).toBe(200);
    return ((await res.json()) as { accountId: string }).accountId;
  }

  test("앱 비밀번호 — 발급 평문은 응답 1회만, 목록엔 절대 없음, 폐기하면 인증 실패", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const accountId = await createAccount(f, apiKey, "ap@acme.test", "primary-pw");

    const createRes = await fetch(`${f.baseUrl}/v1/accounts/${accountId}/app-passwords`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ label: "iPhone Mail" }),
    });
    expect(createRes.status).toBe(200);
    const created = (await createRes.json()) as { id: string; label: string; password: string };
    expect(created.label).toBe("iPhone Mail");
    expect(created.password).toMatch(/^[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}$/);

    // 발급된 평문으로 실제 로그인이 되어야 한다(store 인증 경로까지 태운다)
    expect((await authenticate(f.db, "ap@acme.test", created.password, "imap"))?.accountId).toBe(accountId);

    const listRes = await fetch(`${f.baseUrl}/v1/accounts/${accountId}/app-passwords`, { headers: authHeader(apiKey) });
    expect(listRes.status).toBe(200);
    const listText = await listRes.text();
    // 평문도, 해시가 담긴 secret 필드도 응답에 나오면 안 된다(콘솔이 그대로 화면에 뿌린다).
    expect(listText).not.toContain(created.password);
    expect(listText).not.toContain(created.password.replace(/-/g, ""));
    expect(listText).not.toContain("secret");
    const list = JSON.parse(listText) as { id: string; label: string | null; createdAt: number; lastUsedAt: number | null }[];
    expect(list).toHaveLength(1);
    expect(list[0]!.id).toBe(created.id);
    expect(list[0]!.label).toBe("iPhone Mail");
    expect(list[0]!.lastUsedAt).toBeGreaterThan(0); // 위 authenticate가 기록

    const revokeRes = await fetch(`${f.baseUrl}/v1/credentials/${created.id}`, {
      method: "DELETE",
      headers: authHeader(apiKey),
    });
    expect(revokeRes.status).toBe(200);
    expect(await revokeRes.json()).toEqual({ revoked: true });

    // 폐기 후에는 그 앱 비밀번호로 인증 불가, 기본 비밀번호는 그대로 살아 있어야 한다
    expect(await authenticate(f.db, "ap@acme.test", created.password, "imap")).toBeNull();
    expect((await authenticate(f.db, "ap@acme.test", "primary-pw", "imap"))?.accountId).toBe(accountId);

    const afterRes = await fetch(`${f.baseUrl}/v1/accounts/${accountId}/app-passwords`, { headers: authHeader(apiKey) });
    expect(await afterRes.json()).toEqual([]);
  });

  test("앱 비밀번호 — 테넌트 격리: 남의 계정에 발급/조회/폐기 불가(404)", async () => {
    const f = await setup();
    const { apiKey: keyA } = await bootstrapTenant(f);
    const { apiKey: keyB } = await bootstrapTenant(f);
    const accountA = await createAccount(f, keyA, "victim@acme.test", "pw-a");

    const madeA = await fetch(`${f.baseUrl}/v1/accounts/${accountA}/app-passwords`, {
      method: "POST",
      headers: { ...authHeader(keyA), "content-type": "application/json" },
      body: JSON.stringify({ label: "a" }),
    });
    const credA = (await madeA.json()) as { id: string };

    // 테넌트 B의 키로 A의 계정을 건드리는 3가지 경로 전부 차단
    const crossCreate = await fetch(`${f.baseUrl}/v1/accounts/${accountA}/app-passwords`, {
      method: "POST",
      headers: { ...authHeader(keyB), "content-type": "application/json" },
      body: JSON.stringify({ label: "stolen" }),
    });
    expect(crossCreate.status).toBe(404);

    const crossList = await fetch(`${f.baseUrl}/v1/accounts/${accountA}/app-passwords`, { headers: authHeader(keyB) });
    expect(crossList.status).toBe(404);

    const crossRevoke = await fetch(`${f.baseUrl}/v1/credentials/${credA.id}`, {
      method: "DELETE",
      headers: authHeader(keyB),
    });
    expect(crossRevoke.status).toBe(404);

    // 실제로 아무것도 안 만들어졌고/안 지워졌는지 확인
    const stillThere = await fetch(`${f.baseUrl}/v1/accounts/${accountA}/app-passwords`, { headers: authHeader(keyA) });
    expect((await stillThere.json()) as unknown[]).toHaveLength(1);
  });

  test("DELETE /v1/credentials/:id — 기본 비밀번호(kind=0)는 폐기 거부(계정 잠금 방지)", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const accountId = await createAccount(f, apiKey, "lock@acme.test", "primary-pw");
    const { rows } = await f.db.query({
      sql: "SELECT id FROM credentials WHERE account_id = ? AND kind = 0",
      params: [accountId],
    });
    const primaryId = String(rows[0]!.id);

    const res = await fetch(`${f.baseUrl}/v1/credentials/${primaryId}`, { method: "DELETE", headers: authHeader(apiKey) });
    expect(res.status).toBe(400);
    expect((await authenticate(f.db, "lock@acme.test", "primary-pw", "imap"))?.accountId).toBe(accountId);
  });

  test("목록 응답에 id 포함 — 콘솔이 행마다 계정/도메인을 지목할 수 있어야 한다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const accountId = await createAccount(f, apiKey, "row@acme.test", "pw");
    const domainRes = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ name: "rows.test" }),
    });
    const { domainId } = (await domainRes.json()) as { domainId: string };

    const accounts = (await (await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(apiKey) })).json()) as { id: string }[];
    expect(accounts[0]!.id).toBe(accountId);
    // 계정의 도메인(acme.test)도 함께 존재하므로 순서가 아니라 **포함**으로 확인한다.
    const domains = (await (await fetch(`${f.baseUrl}/v1/domains`, { headers: authHeader(apiKey) })).json()) as { id: string }[];
    expect(domains.map((d) => d.id)).toContain(domainId);
  });

  // ── 인증 실패 스로틀(443 공개 노출 대비) ────────────────────────────
  test("인증 실패 스로틀 — 연속 실패 한도 초과 시 429 + Retry-After", async () => {
    const f = await setup();
    for (let i = 0; i < 10; i++) {
      const res = await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader("bogus-token") });
      expect(res.status).toBe(401);
    }
    const blocked = await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader("bogus-token") });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);

    // 차단은 토큰이 아니라 IP 기준이라 올바른 토큰도 잠시 막힌다(브루트포스 방어의 대가)
    expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(ROOT_TOKEN) })).status).toBe(429);
    // 인증이 필요 없는 경로(콘솔·healthz)는 여전히 열려 있어야 한다 — 운영자가 화면조차 못 보면 안 된다
    expect((await fetch(`${f.baseUrl}/healthz`)).status).toBe(200);
    expect((await fetch(`${f.baseUrl}/`)).status).toBe(200);
  });

  test("인증 실패 스로틀 — 성공하면 카운터 리셋(오타 뒤 정상 로그인이 벌받지 않는다)", async () => {
    const f = await setup();
    for (let i = 0; i < 9; i++) {
      expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader("bogus-token") })).status).toBe(401);
    }
    // 성공 → 실패 기록 삭제
    expect((await fetch(`${f.baseUrl}/v1/accounts?tenantId=t`, { headers: authHeader(ROOT_TOKEN) })).status).toBe(200);
    // 리셋되지 않았다면 이 9회 중 두 번째부터 429가 나온다
    for (let i = 0; i < 9; i++) {
      expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader("bogus-token") })).status).toBe(401);
    }
  });

  test("인증 실패 스로틀 — 성공 요청은 세지 않는다(정상 운영 무영향)", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    for (let i = 0; i < 20; i++) {
      expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(apiKey) })).status).toBe(200);
    }
  });

  test("GET /v1/usage → 테넌트 사용량 집계(계정 생성 반영)", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    // 인증 없으면 401
    expect((await fetch(`${f.baseUrl}/v1/usage`, { headers: authHeader("bogus") })).status).toBe(401);

    await provisionVerifiedDomain(f, apiKey, "acme.test");
    await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "u1@acme.test", password: "pw" }),
    });
    const res = await fetch(`${f.baseUrl}/v1/usage`, { headers: authHeader(apiKey) });
    expect(res.status).toBe(200);
    const usage = (await res.json()) as { accounts: number; activeAccounts: number; messages: number; window: { delivered: number } };
    expect(usage.accounts).toBe(1);
    expect(usage.activeAccounts).toBe(1);
    expect(usage.messages).toBe(0);
    expect(usage.window.delivered).toBe(0);
  });

  /**
   * scopes가 저장·전달만 되고 검사되지 않아, read 전용으로 발급한 키가 계정 생성·삭제까지
   * 전권을 가졌다. 강제는 라우트마다가 아니라 메서드 기반 단일 관문이라 새 라우트도 자동으로 덮인다.
   */
  test("scopes 강제 — read 키는 조회만, 변경은 403", async () => {
    const f = await setup();
    const { tenantId } = await bootstrapTenant(f);
    const keyRes = await fetch(`${f.baseUrl}/v1/api-keys`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ tenantId, scopes: "read" }),
    });
    const { key: readKey } = (await keyRes.json()) as { key: string };

    // 조회는 통과
    expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(readKey) })).status).toBe(200);

    // 변경은 403 — 예전에는 200으로 계정이 만들어졌다
    const create = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(readKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "nope@acme.test", password: "pw" }),
    });
    expect(create.status).toBe(403);

    const del = await fetch(`${f.baseUrl}/v1/accounts/whatever`, { method: "DELETE", headers: authHeader(readKey) });
    expect(del.status).toBe(403);
  });

  test("scopes 강제 — write 키는 조회도 된다(변경만 되는 키는 쓸 수 없다)", async () => {
    const f = await setup();
    const { tenantId } = await bootstrapTenant(f);
    const keyRes = await fetch(`${f.baseUrl}/v1/api-keys`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ tenantId, scopes: "write" }),
    });
    const { key: writeKey } = (await keyRes.json()) as { key: string };

    expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(writeKey) })).status).toBe(200);
    await provisionVerifiedDomain(f, writeKey, "acme.test");
    const create = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(writeKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "ok@acme.test", password: "pw" }),
    });
    expect(create.status).toBe(200);
  });

  /**
   * 발급만 있고 목록·폐기가 없어서, 유출된 키를 빼려면 DB를 직접 UPDATE해야 했다.
   * 폐기는 행 삭제가 아니라 `revoked_at` 스탬프 — 감사 로그의 apiKeyId가 고아가 되면 안 된다.
   */
  test("GET/DELETE /v1/api-keys — 목록에 평문이 없고, 폐기 후 그 키로는 401", async () => {
    const f = await setup();
    const { tenantId, apiKey } = await bootstrapTenant(f);
    const keyRes = await fetch(`${f.baseUrl}/v1/api-keys`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ tenantId, label: "ops-laptop" }),
    });
    const victim = (await keyRes.json()) as { id: string; key: string };

    const listRes = await fetch(`${f.baseUrl}/v1/api-keys`, { headers: authHeader(apiKey) });
    expect(listRes.status).toBe(200);
    const rows = (await listRes.json()) as { id: string; label: string | null; revokedAt: number | null }[];
    expect(rows.length).toBe(2); // 부트스트랩 키 + 방금 발급한 키
    // 평문도 해시도 새 나가면 안 된다 — 목록은 "무엇이 살아 있나"만 답한다.
    expect(JSON.stringify(rows).includes(victim.key)).toBe(false);
    expect(JSON.stringify(rows).includes("key_hash")).toBe(false);
    expect(rows.find((r) => r.id === victim.id)?.label).toBe("ops-laptop");

    // 폐기 전에는 그 키로 인증이 된다
    expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(victim.key) })).status).toBe(200);

    const del = await fetch(`${f.baseUrl}/v1/api-keys/${victim.id}`, { method: "DELETE", headers: authHeader(apiKey) });
    expect(del.status).toBe(200);
    expect((await del.json()) as { selfRevoked: boolean }).toEqual({ revoked: true, selfRevoked: false });

    // 인증 질의가 revoked_at IS NULL을 보므로 즉시 막힌다
    expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(victim.key) })).status).toBe(401);

    // 행은 남아 있고 revokedAt이 찍혀 있다(감사 로그의 apiKeyId를 되짚을 수 있어야 한다)
    const after = (await (await fetch(`${f.baseUrl}/v1/api-keys`, { headers: authHeader(apiKey) })).json()) as {
      id: string;
      revokedAt: number | null;
    }[];
    expect(after.length).toBe(2);
    expect(typeof after.find((r) => r.id === victim.id)?.revokedAt).toBe("number");
  });

  /** 재폐기가 폐기 시각을 현재로 밀면 감사 기록의 시점이 틀어진다 — 조건에 revoked_at IS NULL을 둔 이유. */
  test("이미 폐기된 키를 다시 폐기하면 404이고 revokedAt이 갱신되지 않는다", async () => {
    const f = await setup();
    const { tenantId, apiKey } = await bootstrapTenant(f);
    const keyRes = await fetch(`${f.baseUrl}/v1/api-keys`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ tenantId }),
    });
    const { id } = (await keyRes.json()) as { id: string };

    expect((await fetch(`${f.baseUrl}/v1/api-keys/${id}`, { method: "DELETE", headers: authHeader(apiKey) })).status).toBe(200);
    const { rows } = await f.db.query({ sql: "SELECT revoked_at FROM api_keys WHERE id = ?", params: [id] });
    const first = Number(rows[0]!.revoked_at);

    const again = await fetch(`${f.baseUrl}/v1/api-keys/${id}`, { method: "DELETE", headers: authHeader(apiKey) });
    expect(again.status).toBe(404);
    const { rows: rows2 } = await f.db.query({ sql: "SELECT revoked_at FROM api_keys WHERE id = ?", params: [id] });
    expect(Number(rows2[0]!.revoked_at)).toBe(first);
  });

  /** 남의 테넌트 키를 폐기하면 서비스 거부가 된다. id 존재 여부도 새면 안 되므로 404로 뭉갠다. */
  test("남의 테넌트 API 키는 폐기되지 않고 404 — 목록에도 보이지 않는다", async () => {
    const f = await setup();
    const a = await bootstrapTenant(f);
    const tenantB = await fetch(`${f.baseUrl}/v1/tenants`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ name: "other" }),
    });
    const { tenantId: bId } = (await tenantB.json()) as { tenantId: string };
    const bKeyRes = await fetch(`${f.baseUrl}/v1/api-keys`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ tenantId: bId }),
    });
    const bKey = (await bKeyRes.json()) as { id: string; key: string };

    const rows = (await (await fetch(`${f.baseUrl}/v1/api-keys`, { headers: authHeader(a.apiKey) })).json()) as {
      id: string;
    }[];
    expect(rows.some((r) => r.id === bKey.id)).toBe(false);

    const del = await fetch(`${f.baseUrl}/v1/api-keys/${bKey.id}`, { method: "DELETE", headers: authHeader(a.apiKey) });
    expect(del.status).toBe(404);
    // 실제로 살아 있어야 한다 — 404를 돌려주고 몰래 지우면 최악이다
    expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(bKey.key) })).status).toBe(200);
  });

  /**
   * 자기 키 폐기는 **막지 않는다** — 유출 대응에서 가장 급한 폐기가 그것이다.
   * 대신 `selfRevoked`로 알려 콘솔이 "이제 401이 됩니다"를 띄울 수 있게 한다.
   */
  test("자기 자신을 폐기할 수 있고 selfRevoked로 알린다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const rows = (await (await fetch(`${f.baseUrl}/v1/api-keys`, { headers: authHeader(apiKey) })).json()) as {
      id: string;
    }[];
    const selfId = rows[0]!.id;

    const del = await fetch(`${f.baseUrl}/v1/api-keys/${selfId}`, { method: "DELETE", headers: authHeader(apiKey) });
    expect(del.status).toBe(200);
    expect((await del.json()) as { selfRevoked: boolean }).toEqual({ revoked: true, selfRevoked: true });
    expect((await fetch(`${f.baseUrl}/v1/accounts`, { headers: authHeader(apiKey) })).status).toBe(401);
  });

  test("모르는 scopes는 발급 시점에 400 — 오타가 권한 0인 키로 굳지 않게", async () => {
    const f = await setup();
    const { tenantId } = await bootstrapTenant(f);
    const res = await fetch(`${f.baseUrl}/v1/api-keys`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: JSON.stringify({ tenantId, scopes: "read-only" }),
    });
    expect(res.status).toBe(400);
  });

  /**
   * 계정 비활성화 시 그 계정을 가리키던 알리아스 목적지를 함께 정리해야 한다.
   * FK 미사용 정책이라 DB가 대신 지워 주지 않는다 — 마이그레이션 006이 이 정리를 위해
   * ix_address_targets_account를 만들어 뒀는데 정작 정리 코드가 없었다.
   */
  test("DELETE /v1/accounts/:id — 알리아스 목적지(address_targets)도 정리", async () => {
    const f = await setup();
    const { apiKey, tenantId } = await bootstrapTenant(f);
    await provisionVerifiedDomain(f, apiKey, "acme.test");
    const keepId = await createAccount(f, apiKey, "keep@acme.test", "pw");
    const goneId = await createAccount(f, apiKey, "gone@acme.test", "pw");

    const aliasRes = await fetch(`${f.baseUrl}/v1/aliases`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ address: "team@acme.test", targetAccountIds: [keepId, goneId] }),
    });
    expect(aliasRes.status).toBe(200);

    const countTargets = async (): Promise<number> => {
      const { rows } = await f.db.query({ sql: "SELECT COUNT(*) AS n FROM address_targets" });
      return Number(rows[0]!.n);
    };
    expect(await countTargets()).toBe(2);

    const del = await fetch(`${f.baseUrl}/v1/accounts/${goneId}`, { method: "DELETE", headers: authHeader(apiKey) });
    expect(del.status).toBe(200);

    expect(await countTargets()).toBe(1); // 죽은 계정 목적지만 사라진다
    const { rows } = await f.db.query({ sql: "SELECT account_id FROM address_targets" });
    expect(String(rows[0]!.account_id)).toBe(keepId);

    // 남은 알리아스는 그대로 동작해야 한다(팬아웃 일부 정리가 알리아스를 죽이면 안 된다)
    const listed = (await (await fetch(`${f.baseUrl}/v1/aliases`, { headers: authHeader(apiKey) })).json()) as {
      accountIds: string[];
    }[];
    expect(listed[0]!.accountIds).toEqual([keepId]);
    expect(tenantId).toBeTruthy();
  });

  /**
   * 상한이 없으면 인증된 키 하나로 메모리를 고갈시킬 수 있었다. JMAP은 요청·업로드 모두
   * 상한이 있는데 관리 API만 빠져 있었다.
   *
   * ⚠ 초과해도 요청 스트림을 끊지 않는다 — `req.destroy()`로 끊으면 응답이 클라이언트에
   * 도달하지 못해 fetch가 그대로 매달린다(실측으로 확인하고 고친 부분이다).
   */
  test("과대 바디는 413으로 거절하고 연결은 정상 종료된다", async () => {
    const f = await setup();
    const res = await fetch(`${f.baseUrl}/v1/tenants`, {
      method: "POST",
      headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
      body: "x".repeat(2 * 1024 * 1024),
    });
    expect(res.status).toBe(413);
    expect((await res.json()) as { error: string }).toMatchObject({ error: expect.stringContaining("too large") });

    // 서버가 살아 있어야 한다(소켓을 끊고 죽지 않았는지)
    expect((await fetch(`${f.baseUrl}/healthz`)).status).toBe(200);
  });

  /**
   * 배달 경로(backend.ts relayCopy)는 MAX_RELAY_TARGETS 초과 시 fail closed로 아무것도
   * 릴레이하지 않는다. 생성 시 통과시키면 그 주소로 온 메일이 영구 451 루프에 빠진다 —
   * 팬아웃 상한은 400으로 막으면서 이쪽만 배달 시점 검사였던 비대칭을 없앤다.
   */
  test("POST /v1/aliases — 포워딩 대상이 상한을 넘으면 400", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    await provisionVerifiedDomain(f, apiKey, "acme.test");

    const res = await fetch(`${f.baseUrl}/v1/aliases`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({
        address: "many@acme.test",
        forwardTo: "a@x.test,b@x.test,c@x.test,d@x.test,e@x.test",
      }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()) as { error: string }).toMatchObject({ error: expect.stringContaining("포워딩 대상") });
  });

  test("POST /v1/aliases — 상한 이내 포워딩은 통과", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    await provisionVerifiedDomain(f, apiKey, "acme.test");

    const res = await fetch(`${f.baseUrl}/v1/aliases`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ address: "few@acme.test", forwardTo: "a@x.test, b@x.test" }),
    });
    expect(res.status).toBe(200);
  });

  test("POST /v1/aliases — 비활성 계정을 목적지로 지정하면 404", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    await provisionVerifiedDomain(f, apiKey, "acme.test");
    const goneId = await createAccount(f, apiKey, "gone2@acme.test", "pw");
    await fetch(`${f.baseUrl}/v1/accounts/${goneId}`, { method: "DELETE", headers: authHeader(apiKey) });

    const res = await fetch(`${f.baseUrl}/v1/aliases`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ address: "dead@acme.test", targetAccountIds: [goneId] }),
    });
    // 만들어 봐야 라우팅이 걸러내 조용한 no-op이 된다 — 즉시 실패로 알린다.
    expect(res.status).toBe(404);
  });

  /**
   * 차단 목록에 잘못 올라간 수신자를 되돌릴 수 있어야 한다 — 예전엔 조회·해제 경로가 아예 없어
   * DB를 직접 만지는 것 말고는 방법이 없었다. 일시 장애가 영구 차단으로 굳던 문제와 짝이다.
   */
  test("GET/DELETE /v1/suppressions — 조회와 해제", async () => {
    const f = await setup();
    const { apiKey, tenantId } = await bootstrapTenant(f);
    await f.db.batch([
      {
        sql: "INSERT INTO suppressions (tenant_id, email, reason, source, created_at) VALUES (?, ?, 1, 'mta-max-attempts', ?)",
        params: [tenantId, "blocked@remote.test", Date.now()],
      },
    ]);

    const listed = (await (await fetch(`${f.baseUrl}/v1/suppressions`, { headers: authHeader(apiKey) })).json()) as {
      email: string;
      reason: number;
    }[];
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({ email: "blocked@remote.test", reason: 1 });

    const del = await fetch(`${f.baseUrl}/v1/suppressions/${encodeURIComponent("blocked@remote.test")}`, {
      method: "DELETE",
      headers: authHeader(apiKey),
    });
    expect(del.status).toBe(200);

    const after = (await (await fetch(`${f.baseUrl}/v1/suppressions`, { headers: authHeader(apiKey) })).json()) as unknown[];
    expect(after).toHaveLength(0);

    // 없는 주소는 404 — 다른 테넌트 것을 지우려는 시도도 여기로 수렴한다.
    const missing = await fetch(`${f.baseUrl}/v1/suppressions/${encodeURIComponent("nobody@remote.test")}`, {
      method: "DELETE",
      headers: authHeader(apiKey),
    });
    expect(missing.status).toBe(404);
  });

  /**
   * 미검증 도메인의 알리아스는 수신 라우팅이 무시하므로(backend.ts resolveRoute의 d.status=1)
   * 만들어 봐야 조용한 no-op이고, 캐치올을 미리 심는 탈취 셋업의 발판이기도 하다.
   * 조용한 실패 대신 즉시 실패로 알린다.
   */
  test("POST /v1/aliases — 미검증 도메인은 409로 거절", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f);
    const created = await fetch(`${f.baseUrl}/v1/domains`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ name: "unverified.test" }),
    });
    expect(created.status).toBe(200);

    const res = await fetch(`${f.baseUrl}/v1/aliases`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ address: "catchall@unverified.test", forwardTo: "elsewhere@remote.test" }),
    });
    expect(res.status).toBe(409);
    expect((await res.json()) as { error: string }).toMatchObject({ error: expect.stringContaining("not verified") });
  });
});
