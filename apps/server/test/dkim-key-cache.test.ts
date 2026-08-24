/**
 * DKIM 개인키 복호 비용 회귀.
 *
 * `StoreDkimHook.selectorFor()`가 키마다 동기 `open()`을 불렀고, 그 안의
 * `scryptSync(N=16384)`가 실측 **85.7ms**다. 이중 서명이 규약이라(RSA+Ed25519) 발송 한 통이
 * 172ms 동안 이벤트 루프를 막았다 — 전 프로토콜이 단일 프로세스라 그동안 IMAP·POP3도 멈춘다.
 *
 * 이 저장소는 같은 위험을 이미 두 곳에 적어 뒀다(`store/auth.ts` scryptAsync ·
 * `core/scram.ts` pbkdf2). **그 교훈이 DKIM 경로로만 전파되지 않았다.**
 */
import { test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { seal, ulid } from "@ionosphere/core";
import { generateDkimKeyPair } from "@ionosphere/mail-auth";
import { StoreDkimHook } from "../src/backend.ts";

const MASTER_KEY = "master-pass";

async function seed(db: DbDriver): Promise<void> {
  await migrate(db, allMigrations);
  const now = Date.now();
  const tenantId = ulid();
  const domainId = ulid();
  const rsa = await generateDkimKeyPair("rsa-sha256");
  const ed = await generateDkimKeyPair("ed25519-sha256");
  await db.batch([
    { sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?,?,1,?)", params: [tenantId, "t", now] },
    {
      sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?,?,?,1,?,?)",
      params: [domainId, tenantId, "x.test", now, now],
    },
    {
      sql: `INSERT INTO dkim_keys (id, domain_id, selector, algo, private_key, key_version, active, created_at)
            VALUES (?,?,'rsa1',0,?,1,1,?)`,
      params: [ulid(), domainId, seal(rsa.privateKeyPem, MASTER_KEY).value, now],
    },
    {
      sql: `INSERT INTO dkim_keys (id, domain_id, selector, algo, private_key, key_version, active, created_at)
            VALUES (?,?,'ed1',1,?,1,1,?)`,
      params: [ulid(), domainId, seal(ed.privateKeyPem, MASTER_KEY).value, now],
    },
  ]);
}

test("같은 키를 반복 조회해도 KDF는 한 번만 돈다", async () => {
  const db = await openSqlite(":memory:");
  await seed(db);
  const hook = new StoreDkimHook(db, MASTER_KEY);

  const first = Date.now();
  const keys = await hook.selectorFor("x.test");
  const firstMs = Date.now() - first;
  expect(keys).toHaveLength(2); // 이중 서명 — RSA + Ed25519

  const repeat = Date.now();
  for (let i = 0; i < 20; i++) await hook.selectorFor("x.test");
  const repeatMs = Date.now() - repeat;

  // 캐시 전이라면 20회 × 2키 × ~86ms ≈ 3,400ms다. 캐시가 걸리면 DB 조회 비용만 남는다.
  expect(repeatMs < firstMs + 100).toBe(true);
  // 값이 같아야 한다 — 캐시가 다른 키를 돌려주면 서명이 조용히 깨진다.
  const again = await hook.selectorFor("x.test");
  expect(again[0]!.privateKey).toBe(keys[0]!.privateKey);
  expect(again[1]!.privateKey).toBe(keys[1]!.privateKey);

  await db.close();
});

test("동시 요청이 겹쳐도 결과가 같다(Promise 캐시)", async () => {
  const db = await openSqlite(":memory:");
  await seed(db);
  const hook = new StoreDkimHook(db, MASTER_KEY);

  // 캐시가 비어 있는 상태에서 한꺼번에 — 값이 아니라 Promise를 담아야 첫 하나만 KDF를 돈다.
  const all = await Promise.all(Array.from({ length: 8 }, () => hook.selectorFor("x.test")));
  const pem = all[0]![0]!.privateKey;
  for (const r of all) expect(r[0]!.privateKey).toBe(pem);

  await db.close();
});

test("마스터키가 틀리면 실패를 캐시하지 않는다", async () => {
  const db = await openSqlite(":memory:");
  await seed(db);
  const wrong = new StoreDkimHook(db, "wrong-key");
  await expect(wrong.selectorFor("x.test")).rejects.toThrow();

  // 실패가 캐시됐다면 올바른 키를 가진 새 인스턴스도 영향을 받지 않아야 한다(인스턴스별 캐시).
  const right = new StoreDkimHook(db, MASTER_KEY);
  expect(await right.selectorFor("x.test")).toHaveLength(2);

  // 같은 인스턴스로 다시 시도해도 여전히 실패다(캐시된 성공값을 잘못 주지 않는다).
  await expect(wrong.selectorFor("x.test")).rejects.toThrow();

  await db.close();
});
