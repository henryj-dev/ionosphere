/**
 * 도메인 생성·해제 가드 회귀 테스트 (감사 5차 H-4 생성경로 / L-6 / L-7 / L-12).
 *
 * 지키려는 것:
 *  · 예약·공용 도메인은 REST와 CLI **양쪽** 경로에서 거부된다(검사가 provisionDomain 안에 있으므로).
 *  · 남이 status=1로 보유한 이름은 DKIM 키를 만들기 **전에** 409로 막힌다.
 *  · 소유권 토큰 비교가 길이가 다른 입력에 던지지 않는다(timingSafeEqual 직접 호출의 함정).
 *  · 해제하면 다른 테넌트가 같은 이름을 검증할 수 있고, 자원이 남아 있으면 해제가 거부된다.
 *  · 관리 콘솔 HTML에 보안 헤더가 붙는다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { Store } from "@ionosphere/store";
import { AdminApiServer, type AdminApiDeps } from "../src/server.ts";
import { DomainNameError, provisionDomain } from "@ionosphere/admin-cmd";

const ROOT_TOKEN = "root-secret-test-token";

interface Resolvers {
  txt: (name: string) => Promise<string[]>;
  mx: (name: string) => Promise<{ exchange: string; preference: number }[]>;
}

interface Fixture {
  db: DbDriver;
  server: AdminApiServer;
  baseUrl: string;
  resolvers: Resolvers;
}

let fx: Fixture | undefined;

async function setup(): Promise<Fixture> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const resolvers: Resolvers = { txt: async () => [], mx: async () => [] };
  const server = new AdminApiServer({
    db,
    store: new Store(db),
    resolveTxt: (name) => resolvers.txt(name),
    resolveMx: (name) => resolvers.mx(name),
    rootToken: ROOT_TOKEN,
  } satisfies AdminApiDeps);
  const port = await server.listen(0, "127.0.0.1");
  const fixture: Fixture = { db, server, baseUrl: `http://127.0.0.1:${port}`, resolvers };
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

function authHeader(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

async function bootstrapTenant(f: Fixture, name: string): Promise<{ tenantId: string; apiKey: string }> {
  const tenantRes = await fetch(`${f.baseUrl}/v1/tenants`, {
    method: "POST",
    headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  const { tenantId } = (await tenantRes.json()) as { tenantId: string };
  const keyRes = await fetch(`${f.baseUrl}/v1/api-keys`, {
    method: "POST",
    headers: { ...authHeader(ROOT_TOKEN), "content-type": "application/json" },
    body: JSON.stringify({ tenantId }),
  });
  const { key } = (await keyRes.json()) as { key: string };
  return { tenantId, apiKey: key };
}

function createDomain(f: Fixture, apiKey: string, name: string): Promise<Response> {
  return fetch(`${f.baseUrl}/v1/domains`, {
    method: "POST",
    headers: { ...authHeader(apiKey), "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
}

/** 리졸버에 토큰/MX/SPF를 심고 verify까지. 반환은 verify 응답 상태. */
async function verifyDomain(f: Fixture, apiKey: string, domainId: string, name: string, token: string): Promise<number> {
  const prevTxt = f.resolvers.txt;
  const prevMx = f.resolvers.mx;
  f.resolvers.txt = async (n) => {
    if (n === `_ionosphere-verify.${name}`) return [token];
    if (n === name) return ["v=spf1 -all"];
    return prevTxt(n);
  };
  f.resolvers.mx = async (n) => (n === name ? [{ exchange: `mx.${name}`, preference: 10 }] : prevMx(n));
  const res = await fetch(`${f.baseUrl}/v1/domains/${domainId}/verify`, {
    method: "POST",
    headers: authHeader(apiKey),
  });
  return res.status;
}

describe("도메인 생성 가드 (H-4 생성경로)", () => {
  test("예약·공용 도메인은 400으로 거부, DKIM 키 행도 남지 않는다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");

    for (const bad of ["gmail.com", "mail.localhost", "x.local", "foo.invalid", "example.com", "a.onion"]) {
      const res = await createDomain(f, apiKey, bad);
      expect([bad, res.status]).toEqual([bad, 400]);
    }
    // 거부된 이름은 행 자체가 없어야 한다 — 예전엔 도메인 행 + DKIM 키 2개가 그대로 생겼다.
    const { rows } = await f.db.query({ sql: "SELECT id FROM domains", params: [] });
    expect(rows.length).toBe(0);
    const { rows: keys } = await f.db.query({ sql: "SELECT id FROM dkim_keys", params: [] });
    expect(keys.length).toBe(0);
  });

  test("형식이 틀린 이름을 거부한다(레이블·길이·IP·비ASCII)", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");

    for (const bad of [
      "nodot",
      "-lead.test",
      "trail-.test",
      "double..test",
      "1.2.3.4",
      "한글.test",
      "under_score.test",
      `${"a".repeat(64)}.test`,
    ]) {
      const res = await createDomain(f, apiKey, bad);
      expect([bad, res.status]).toEqual([bad, 400]);
    }
  });

  test("정상 도메인은 통과한다 — 가드가 과하지 않은지", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");

    for (const good of ["ionosphere.test", "mail.example.com", "xn--9t4b11yi5a.com", "a-b.co.kr", "ok.test"]) {
      const res = await createDomain(f, apiKey, good);
      expect([good, res.status]).toEqual([good, 200]);
    }
  });

  test("CLI 경로(provisionDomain 직접 호출)도 같은 판정을 받는다", () => {
    // 검사가 호출자가 아니라 provisionDomain 안에 있어야 REST·CLI가 갈라지지 않는다.
    expect(() => provisionDomain({ domainId: "d", tenantId: "t", name: "gmail.com", preVerified: true })).toThrow(
      DomainNameError,
    );
    expect(() => provisionDomain({ domainId: "d", tenantId: "t", name: "ok.test", preVerified: true })).not.toThrow();
  });

  test("다른 테넌트가 status=1로 보유한 이름은 **생성 시점에** 409", async () => {
    const f = await setup();
    const a = await bootstrapTenant(f, "a");
    const b = await bootstrapTenant(f, "b");

    const createA = await createDomain(f, a.apiKey, "held.test");
    const domainA = (await createA.json()) as { domainId: string; verifyToken: string };
    expect(await verifyDomain(f, a.apiKey, domainA.domainId, "held.test", domainA.verifyToken)).toBe(200);

    const createB = await createDomain(f, b.apiKey, "held.test");
    expect(createB.status).toBe(409);
    // B의 DKIM 키가 만들어지지 않았는지 — 예전엔 생성이 통과해 키가 2세트가 됐다(H-4 ③).
    const { rows } = await f.db.query({ sql: "SELECT id FROM domains WHERE name = ?", params: ["held.test"] });
    expect(rows.length).toBe(1);
  });

  test("아직 아무도 검증하지 않은 이름은 두 테넌트가 함께 만들 수 있다(경합은 verify가 판정)", async () => {
    const f = await setup();
    const a = await bootstrapTenant(f, "a");
    const b = await bootstrapTenant(f, "b");
    expect((await createDomain(f, a.apiKey, "race.test")).status).toBe(200);
    expect((await createDomain(f, b.apiKey, "race.test")).status).toBe(200);
  });

  test("같은 테넌트가 같은 이름을 두 번 만들 수 없다 — 활성 DKIM 키 2세트 방지", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");
    expect((await createDomain(f, apiKey, "dup.test")).status).toBe(200);
    expect((await createDomain(f, apiKey, "dup.test")).status).toBe(409);
  });
});

describe("소유권 토큰 비교 (L-6)", () => {
  test("길이가 다른 TXT 값에도 던지지 않고 검증 실패로 떨어진다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");
    const created = (await (await createDomain(f, apiKey, "timing.test")).json()) as { domainId: string };

    // timingSafeEqual을 그대로 쓰면 길이가 다를 때 던진다 → 500. 해시 후 비교라 정상 200 + failed.
    f.resolvers.txt = async (n) => {
      if (n === "_ionosphere-verify.timing.test") return ["", "short", "x".repeat(500)];
      if (n === "timing.test") return ["v=spf1 -all"];
      return [];
    };
    f.resolvers.mx = async () => [{ exchange: "mx.timing.test", preference: 10 }];

    const res = await fetch(`${f.baseUrl}/v1/domains/${created.domainId}/verify`, {
      method: "POST",
      headers: authHeader(apiKey),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "failed", checks: { token: false, mx: true, spf: true } });
  });

  test("길이가 같지만 다른 값도 통과하지 않는다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");
    const created = (await (await createDomain(f, apiKey, "wrong.test")).json()) as {
      domainId: string;
      verifyToken: string;
    };
    const wrong = created.verifyToken.slice(0, -1) + (created.verifyToken.endsWith("0") ? "1" : "0");
    expect(await verifyDomain(f, apiKey, created.domainId, "wrong.test", wrong)).toBe(200);
    const { rows } = await f.db.query({
      sql: "SELECT status FROM domains WHERE id = ?",
      params: [created.domainId],
    });
    expect(Number(rows[0]!.status)).toBe(0);
  });
});

describe("도메인 해제 (L-7)", () => {
  test("해제하면 다른 테넌트가 같은 이름을 검증할 수 있다", async () => {
    const f = await setup();
    const a = await bootstrapTenant(f, "a");
    const b = await bootstrapTenant(f, "b");

    const domainA = (await (await createDomain(f, a.apiKey, "moved.test")).json()) as {
      domainId: string;
      verifyToken: string;
    };
    expect(await verifyDomain(f, a.apiKey, domainA.domainId, "moved.test", domainA.verifyToken)).toBe(200);

    // 해제 전에는 B가 만들 수조차 없다(위 생성 가드).
    expect((await createDomain(f, b.apiKey, "moved.test")).status).toBe(409);

    const release = await fetch(`${f.baseUrl}/v1/domains/${domainA.domainId}`, {
      method: "DELETE",
      headers: authHeader(a.apiKey),
    });
    expect(release.status).toBe(200);
    expect(await release.json()).toEqual({ released: true });

    // 앵커·DKIM 키까지 함께 정리됐는가(고아 행이 남으면 다음 검증이 PK 충돌로 막힌다).
    const { rows: claims } = await f.db.query({
      sql: "SELECT name FROM domain_name_claims WHERE name = ?",
      params: ["moved.test"],
    });
    expect(claims.length).toBe(0);
    const { rows: keys } = await f.db.query({
      sql: "SELECT id FROM dkim_keys WHERE domain_id = ?",
      params: [domainA.domainId],
    });
    expect(keys.length).toBe(0);

    const domainB = (await (await createDomain(f, b.apiKey, "moved.test")).json()) as {
      domainId: string;
      verifyToken: string;
    };
    expect(await verifyDomain(f, b.apiKey, domainB.domainId, "moved.test", domainB.verifyToken)).toBe(200);
  });

  test("알리아스가 남아 있으면 409 — 조용히 지우지 않는다", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");
    const d = (await (await createDomain(f, apiKey, "busy.test")).json()) as {
      domainId: string;
      verifyToken: string;
    };
    expect(await verifyDomain(f, apiKey, d.domainId, "busy.test", d.verifyToken)).toBe(200);

    const alias = await fetch(`${f.baseUrl}/v1/aliases`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ address: "info@busy.test", forwardTo: "elsewhere@ok.test" }),
    });
    expect(alias.status).toBe(200);

    const blocked = await fetch(`${f.baseUrl}/v1/domains/${d.domainId}`, {
      method: "DELETE",
      headers: authHeader(apiKey),
    });
    expect(blocked.status).toBe(409);
    // 거부됐으면 아무것도 지워지지 않았어야 한다.
    const { rows } = await f.db.query({ sql: "SELECT id FROM domains WHERE id = ?", params: [d.domainId] });
    expect(rows.length).toBe(1);

    // 알리아스를 치우면 그때 해제된다 — 거부가 영구 봉쇄가 아니라 "먼저 정리하라"임을 확인.
    const { aliasId } = (await alias.json()) as { aliasId: string };
    await fetch(`${f.baseUrl}/v1/aliases/${aliasId}`, { method: "DELETE", headers: authHeader(apiKey) });
    const ok = await fetch(`${f.baseUrl}/v1/domains/${d.domainId}`, {
      method: "DELETE",
      headers: authHeader(apiKey),
    });
    expect(ok.status).toBe(200);
  });

  test("계정이 남아 있으면 409 — 비활성 계정도 막는다(email이 전역 UNIQUE라서)", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");
    const d = (await (await createDomain(f, apiKey, "acct.test")).json()) as {
      domainId: string;
      verifyToken: string;
    };
    expect(await verifyDomain(f, apiKey, d.domainId, "acct.test", d.verifyToken)).toBe(200);

    const acc = await fetch(`${f.baseUrl}/v1/accounts`, {
      method: "POST",
      headers: { ...authHeader(apiKey), "content-type": "application/json" },
      body: JSON.stringify({ email: "u@acct.test", password: "pw123456" }),
    });
    expect(acc.status).toBe(200);
    const { accountId } = (await acc.json()) as { accountId: string };

    expect((await fetch(`${f.baseUrl}/v1/domains/${d.domainId}`, { method: "DELETE", headers: authHeader(apiKey) })).status).toBe(409);

    // 비활성화(status=2)만으로는 여전히 막힌다 — accounts 행이 남아 email을 붙잡고 있다.
    await fetch(`${f.baseUrl}/v1/accounts/${accountId}`, { method: "DELETE", headers: authHeader(apiKey) });
    expect((await fetch(`${f.baseUrl}/v1/domains/${d.domainId}`, { method: "DELETE", headers: authHeader(apiKey) })).status).toBe(409);
  });

  test("남의 도메인은 해제할 수 없다(404)", async () => {
    const f = await setup();
    const a = await bootstrapTenant(f, "a");
    const b = await bootstrapTenant(f, "b");
    const d = (await (await createDomain(f, a.apiKey, "mine.test")).json()) as { domainId: string };

    const res = await fetch(`${f.baseUrl}/v1/domains/${d.domainId}`, {
      method: "DELETE",
      headers: authHeader(b.apiKey),
    });
    expect(res.status).toBe(404);
    const { rows } = await f.db.query({ sql: "SELECT id FROM domains WHERE id = ?", params: [d.domainId] });
    expect(rows.length).toBe(1);
  });

  test("미검증 도메인도 해제된다 — 오타로 잡은 이름을 되돌리는 통로", async () => {
    const f = await setup();
    const { apiKey } = await bootstrapTenant(f, "acme");
    const d = (await (await createDomain(f, apiKey, "typo.test")).json()) as { domainId: string };
    const res = await fetch(`${f.baseUrl}/v1/domains/${d.domainId}`, {
      method: "DELETE",
      headers: authHeader(apiKey),
    });
    expect(res.status).toBe(200);
  });
});

describe("관리 콘솔 보안 헤더 (L-12)", () => {
  test("GET / 와 /admin 응답에 CSP·프레임·nosniff 헤더가 붙는다", async () => {
    const f = await setup();
    for (const path of ["/", "/admin"]) {
      const res = await fetch(`${f.baseUrl}${path}`);
      expect(res.status).toBe(200);
      const csp = res.headers.get("content-security-policy") ?? "";
      // 토큰이 localStorage에 있으므로 외부로 실어 나갈 통로(connect-src)와 스크립트 출처가 핵심.
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("script-src 'unsafe-inline'");
      expect(csp).toContain("connect-src 'self'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(res.headers.get("x-frame-options")).toBe("DENY");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      // 페이지는 인라인 CSS/JS만 쓴다 — CSP가 그 둘을 막으면 콘솔이 통째로 죽는다.
      expect(csp).toContain("style-src 'unsafe-inline'");
      expect((await res.text()).includes("<script>")).toBe(true);
    }
  });
});
