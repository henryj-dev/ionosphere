/**
 * 감사 5차 H-4 ③ 회귀 — DKIM 서명 키 조회가 `domains.status`를 보지 않았다.
 *
 * `domains.name`에는 UNIQUE 제약이 없고(001_init: 평범한 인덱스) 전역 유일성은
 * `domain_name_claims`가 **status=1인 행 하나만** 보장한다. 그래서 임의 테넌트가
 * `victim.com` 미검증 행 + DKIM 키를 하나 더 만들 수 있었고, 그러면 활성 키가 2세트가 되어
 * `ORDER BY k.algo DESC` 동률에서 **어느 행이 뽑히는지 비결정적**이었다 —
 * 정당 테넌트의 메일이 DNS에 없는 키로 서명돼 수신측에서 `dkim=fail`이 된다.
 *
 * 같은 쿼리가 C-1의 DKIM 서명 탈취에도 쓰였다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { ulid } from "@ionosphere/core";
import { provisionDkimKeys } from "@ionosphere/api";
import { StoreDkimHook } from "../src/backend.ts";

async function freshDb(): Promise<DbDriver> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  return db;
}

/** 도메인 행 + DKIM 키를 심는다. status를 인자로 받는다. */
async function seedDomainWithKey(db: DbDriver, name: string, status: 0 | 1): Promise<string> {
  const tenantId = ulid();
  const domainId = ulid();
  const now = Date.now();
  const dkim = provisionDkimKeys(domainId, name, undefined);
  await db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      params: [domainId, tenantId, name, status, now, now],
    },
    ...dkim.statements,
  ]);
  return tenantId;
}

describe("DKIM 키 선택은 검증된 도메인만 본다 (H-4 ③)", () => {
  test("미검증(status=0) 도메인의 활성 키는 선택되지 않는다", async () => {
    const db = await freshDb();
    await seedDomainWithKey(db, "unverified.test", 0);

    const hook = new StoreDkimHook(db, undefined);
    // 이제 배열을 돌려준다(이중 서명) — 빈 배열이 "서명할 키 없음"이다.
    expect(await hook.selectorFor("unverified.test")).toHaveLength(0);

    await db.close();
  });

  test("검증된 도메인의 키는 정상 선택된다(기존 동작 불변)", async () => {
    const db = await freshDb();
    await seedDomainWithKey(db, "verified.test", 1);

    const hook = new StoreDkimHook(db, undefined);
    const keys = await hook.selectorFor("verified.test");
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) expect(k.selector.length).toBeGreaterThan(0);

    await db.close();
  });

  test("공격 테넌트가 심은 미검증 중복 행은 정당 테넌트의 키 선택을 흔들지 못한다", async () => {
    const db = await freshDb();
    await seedDomainWithKey(db, "victim.test", 1); // 정당 테넌트(검증됨)
    const legit = await new StoreDkimHook(db, undefined).selectorFor("victim.test");
    expect(legit.length).toBeGreaterThan(0);

    // 공격 테넌트가 같은 이름으로 미검증 행 + 자기 키를 추가한다.
    await seedDomainWithKey(db, "victim.test", 0);

    // 여러 번 조회해도 정당 테넌트의 셀렉터 집합만 나와야 한다.
    // ★이중 서명으로 바뀌어 "키 하나"가 아니라 "집합"을 비교한다 — 미검증 행의 키가 섞여
    //   들어오면 길이나 원소가 달라지므로 H-4 방어는 그대로 고정된다.
    const expected = legit.map((k) => k.selector).sort();
    for (let i = 0; i < 5; i += 1) {
      const got = await new StoreDkimHook(db, undefined).selectorFor("victim.test");
      expect(got.map((k) => k.selector).sort()).toEqual(expected);
    }

    await db.close();
  });

  test("★활성 키가 여러 개면 전부 돌려준다 (이중 서명 — Ed25519 단독이면 Gmail이 neutral을 낸다)", async () => {
    const db = await freshDb();
    await seedDomainWithKey(db, "dual.test", 1);

    const before = await new StoreDkimHook(db, undefined).selectorFor("dual.test");
    // 같은 도메인에 두 번째 키를 심는다(실제 프로비저닝은 RSA+Ed25519 두 개를 만든다).
    await seedDomainWithKey(db, "dual.test", 1);
    const after = await new StoreDkimHook(db, undefined).selectorFor("dual.test");

    // 예전 구현은 LIMIT 1이라 키가 늘어도 항상 1개였다 — 그게 Ed25519 단독 서명의 원인이었다.
    expect(after.length).toBeGreaterThan(before.length);

    await db.close();
  });
});
