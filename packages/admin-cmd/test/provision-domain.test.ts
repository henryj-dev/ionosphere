/**
 * 회귀 테스트 — REST(createDomain)와 CLI(add-domain)의 도메인 생성이 **같은 컬럼**을 쓰는지.
 *
 * 과거 결함: 두 경로가 각자 INSERT를 작성해 컬럼 목록이 갈라졌다.
 *   REST: (id, tenant_id, name, name_utf8, status, verify_token, claimed_at, created_at) status=0
 *   CLI : (id, tenant_id, name,            status,               claimed_at, created_at) status=1
 * CLI 경로는 verify_token·name_utf8을 빼먹어서 **CLI로 만든 도메인은 이후 API로 재검증 불가**였다.
 * 이제 provisionDomain 하나가 두 경우를 만들고, 진짜 차이(즉시 활성)만 preVerified로 남는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { ulid } from "@ionosphere/core";
import { provisionDomain } from "../src/index.ts";

async function freshDb() {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  const tenantId = ulid();
  await db.batch([
    { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, ?, 1, ?)", params: [tenantId, "t", Date.now()] },
  ]);
  return { db, tenantId };
}

describe("provisionDomain — REST/CLI 단일 경로", () => {
  test("검증 대기(REST)는 status=0이고 이름 앵커를 아직 넣지 않는다", async () => {
    const { db, tenantId } = await freshDb();
    const domainId = ulid();
    const prov = provisionDomain({ domainId, tenantId, name: "rest.test", masterKey: "mk" });
    await db.batch(prov.statements);

    const { rows } = await db.query({ sql: "SELECT status, verify_token, name_utf8 FROM domains WHERE id = ?", params: [domainId] });
    expect(Number(rows[0]!.status)).toBe(0);
    expect(String(rows[0]!.verify_token)).toBe(prov.verifyToken);

    const claims = await db.query({ sql: "SELECT COUNT(*) AS n FROM domain_name_claims WHERE name = ?", params: ["rest.test"] });
    expect(Number(claims.rows[0]!.n)).toBe(0); // verify 성공 시 별도로 등록
    await db.close();
  });

  test("preVerified(CLI)는 status=1 + 앵커 즉시 — 그래도 verify_token은 저장된다", async () => {
    const { db, tenantId } = await freshDb();
    const domainId = ulid();
    const prov = provisionDomain({ domainId, tenantId, name: "cli.test", masterKey: "mk", preVerified: true });
    await db.batch(prov.statements);

    const { rows } = await db.query({ sql: "SELECT status, verify_token FROM domains WHERE id = ?", params: [domainId] });
    expect(Number(rows[0]!.status)).toBe(1);
    // ★핵심: 예전 CLI 경로는 여기가 NULL이라 재검증이 불가능했다.
    expect(rows[0]!.verify_token).not.toBeNull();
    expect(String(rows[0]!.verify_token)).toBe(prov.verifyToken);

    const claims = await db.query({ sql: "SELECT COUNT(*) AS n FROM domain_name_claims WHERE name = ?", params: ["cli.test"] });
    expect(Number(claims.rows[0]!.n)).toBe(1);
    await db.close();
  });

  test("두 경로 모두 DKIM 키 2종(rsa1/ed1)을 만든다", async () => {
    const { db, tenantId } = await freshDb();
    const a = ulid();
    const b = ulid();
    await db.batch(provisionDomain({ domainId: a, tenantId, name: "a.test", masterKey: "mk" }).statements);
    await db.batch(provisionDomain({ domainId: b, tenantId, name: "b.test", masterKey: "mk", preVerified: true }).statements);
    for (const id of [a, b]) {
      const { rows } = await db.query({ sql: "SELECT selector FROM dkim_keys WHERE domain_id = ? ORDER BY selector", params: [id] });
      expect(rows.map((r) => String(r.selector))).toEqual(["ed1", "rsa1"]);
    }
    await db.close();
  });

  test("masterKey 없으면 sealed=false로 평문 저장을 알린다", () => {
    const prov = provisionDomain({ domainId: ulid(), tenantId: ulid(), name: "x.test" });
    expect(prov.sealed).toBe(false);
    const withKey = provisionDomain({ domainId: ulid(), tenantId: ulid(), name: "x.test", masterKey: "mk" });
    expect(withKey.sealed).toBe(true);
  });

  test("DNS 안내에 소유권 검증 토큰과 DKIM 레코드가 함께 들어간다", () => {
    const prov = provisionDomain({ domainId: ulid(), tenantId: ulid(), name: "dns.test", masterKey: "mk" });
    const names = prov.dnsRecords.map((r) => r.name);
    expect(names).toContain("_ionosphere-verify.dns.test");
    expect(names).toContain("rsa1._domainkey.dns.test");
    expect(names).toContain("ed1._domainkey.dns.test");
  });
});
