/**
 * StoreSmarthostResolver — DB 행 → 릴레이 설정 변환과 범위 우선순위.
 *
 * 워커 쪽 계약(폴백 금지·세션 분할·테넌트 격리)은 packages/mta/test/smarthost.test.ts가 지킨다.
 * 여기서는 **DB 경계**만 본다: 어느 행이 이기는가, 비밀은 봉인돼 있는가, 깨진 값에 어떻게 반응하는가.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { seal, ulid } from "@ionosphere/core";
import { allMigrations, migrate, openSqlite, SMARTHOST_TENANT_DEFAULT, SMARTHOST_TLS, type DbDriver } from "@ionosphere/db";
import { CLOUDFLARE_EMAIL_PRESET, StoreSmarthostResolver } from "../src/smarthost.ts";

const MASTER_KEY = "test-master-key";

async function freshDb(): Promise<DbDriver> {
  const db = await openSqlite(":memory:");
  await migrate(db, allMigrations);
  return db;
}

async function insertSmarthost(
  db: DbDriver,
  o: { tenantId: string; domain: string; host: string; port?: number; tlsMode?: number; username?: string; secret?: string; maxRcpts?: number },
): Promise<void> {
  await db.batch([
    {
      sql: `INSERT INTO smarthosts (tenant_id, domain, host, port, tls_mode, username, secret, max_rcpts, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      params: [
        o.tenantId,
        o.domain,
        o.host,
        o.port ?? 587,
        o.tlsMode ?? SMARTHOST_TLS.required,
        o.username ?? null,
        o.secret == null ? null : seal(o.secret, MASTER_KEY).value,
        o.maxRcpts ?? null,
        Date.now(),
      ],
    },
  ]);
}

describe("범위 우선순위", () => {
  test("발신 도메인 지정이 테넌트 기본을 이긴다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: SMARTHOST_TENANT_DEFAULT, host: "default.relay.test" });
    await insertSmarthost(db, { tenantId, domain: "ionosphere.test", host: "specific.relay.test" });

    const resolver = new StoreSmarthostResolver(db, MASTER_KEY);
    expect((await resolver.resolve(tenantId, "ionosphere.test"))?.host).toBe("specific.relay.test");
    // 지정이 없는 도메인은 테넌트 기본으로 떨어진다
    expect((await resolver.resolve(tenantId, "other.test"))?.host).toBe("default.relay.test");
    await db.close();
  });

  test("설정이 하나도 없으면 null — 워커가 전역/MX로 내려갈 수 있게", async () => {
    const db = await freshDb();
    const resolver = new StoreSmarthostResolver(db, MASTER_KEY);
    expect(await resolver.resolve(ulid(), "nobody.test")).toBeNull();
    await db.close();
  });

  test("다른 테넌트의 설정은 보이지 않는다", async () => {
    const db = await freshDb();
    const mine = ulid();
    const theirs = ulid();
    await insertSmarthost(db, { tenantId: theirs, domain: SMARTHOST_TENANT_DEFAULT, host: "theirs.relay.test" });

    const resolver = new StoreSmarthostResolver(db, MASTER_KEY);
    expect(await resolver.resolve(mine, "anything.test")).toBeNull();
    await db.close();
  });

  test("발신 도메인은 대소문자를 가리지 않는다 — 봉투 주소는 대문자로도 온다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: "ionosphere.test", host: "specific.relay.test" });

    const resolver = new StoreSmarthostResolver(db, MASTER_KEY);
    expect((await resolver.resolve(tenantId, "Ionosphere.test"))?.host).toBe("specific.relay.test");
    await db.close();
  });
});

describe("자격증명", () => {
  test("봉인된 비밀번호가 복호화돼 SASL 자격증명이 된다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: SMARTHOST_TENANT_DEFAULT, host: "relay.test", username: "api_token", secret: "tok-secret" });

    const got = await new StoreSmarthostResolver(db, MASTER_KEY).resolve(tenantId, "x.test");
    expect(got?.auth).toEqual({ user: "api_token", pass: "tok-secret" });
    await db.close();
  });

  test("DB에 평문이 남지 않는다 — 봉인 문자열이어야 한다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: SMARTHOST_TENANT_DEFAULT, host: "relay.test", username: "api_token", secret: "tok-secret" });

    const { rows } = await db.query({ sql: "SELECT secret FROM smarthosts", params: [] });
    const stored = String(rows[0]!.secret);
    expect(stored).not.toContain("tok-secret");
    expect(stored.startsWith("enc$")).toBe(true);
    await db.close();
  });

  test("사용자명이 없으면 auth를 만들지 않는다 — 인증 없는 내부 릴레이", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: SMARTHOST_TENANT_DEFAULT, host: "relay.test" });

    const got = await new StoreSmarthostResolver(db, MASTER_KEY).resolve(tenantId, "x.test");
    expect(got?.auth).toBeUndefined();
    await db.close();
  });

  /**
   * 마스터키가 틀리면 `open()`이 던지고, 그 예외는 워커에서 지연으로 처리된다.
   * **평문으로 강등해서 보내지 않는다** — 그러면 릴레이 자격증명이 그대로 노출된다.
   */
  test("마스터키가 틀리면 조용히 넘어가지 않고 던진다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: SMARTHOST_TENANT_DEFAULT, host: "relay.test", username: "api_token", secret: "tok" });

    await expect(new StoreSmarthostResolver(db, "wrong-key").resolve(tenantId, "x.test")).rejects.toThrow();
    await db.close();
  });
});

describe("깨진 값", () => {
  /**
   * tls_mode가 인코딩 밖이면 기본값으로 뭉개지 않고 던진다. 뭉개면 "required로 저장했는데
   * 값이 깨져서 평문으로 나갔다"가 가능해진다 — 실패는 안전한 쪽으로 기울어야 한다.
   */
  test("알 수 없는 tls_mode는 기본값으로 대체되지 않고 던진다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: SMARTHOST_TENANT_DEFAULT, host: "relay.test", tlsMode: 99 });

    await expect(new StoreSmarthostResolver(db, MASTER_KEY).resolve(tenantId, "x.test")).rejects.toThrow("tls_mode");
    await db.close();
  });
});

describe("캐시", () => {
  test("TTL 안에서는 DB를 다시 읽지 않는다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await insertSmarthost(db, { tenantId, domain: SMARTHOST_TENANT_DEFAULT, host: "relay.test" });

    let queries = 0;
    const counting: DbDriver = { ...db, query: (stmt) => (queries++, db.query(stmt)) };
    const resolver = new StoreSmarthostResolver(counting, MASTER_KEY);
    await resolver.resolve(tenantId, "x.test");
    await resolver.resolve(tenantId, "x.test");
    expect(queries).toBe(1);

    // 설정을 바꾼 뒤에는 무효화로 즉시 반영된다(관리 명령이 같은 프로세스일 때).
    resolver.invalidate();
    await resolver.resolve(tenantId, "x.test");
    expect(queries).toBe(2);
    await db.close();
  });

  test("'설정 없음'도 캐시한다 — 릴레이를 안 쓰는 테넌트가 매 그룹마다 DB를 때리면 안 된다", async () => {
    const db = await freshDb();
    let queries = 0;
    const counting: DbDriver = { ...db, query: (stmt) => (queries++, db.query(stmt)) };
    const resolver = new StoreSmarthostResolver(counting, MASTER_KEY);
    expect(await resolver.resolve(ulid(), "x.test")).toBeNull();
    expect(queries).toBe(1);
    await db.close();
  });
});

describe("Cloudflare 프리셋", () => {
  /**
   * 문서(https://developers.cloudflare.com/email-service/api/send-emails/smtp/)가 못 박은 값들이다.
   * 특히 포트와 TLS 모드는 짝이라 한쪽만 틀리면 연결이 성립하지 않거나 자격증명이 평문으로 나간다.
   * 사용자명이 계정 이메일이 아니라 리터럴 `api_token`인 것도 자주 틀리는 자리라 못 박아 둔다.
   */
  test("465 implicit TLS, 사용자명은 리터럴 api_token, 세션당 RCPT 50", () => {
    expect(CLOUDFLARE_EMAIL_PRESET.host).toBe("smtp.mx.cloudflare.net");
    expect(CLOUDFLARE_EMAIL_PRESET.port).toBe(465);
    expect(CLOUDFLARE_EMAIL_PRESET.tls).toBe("implicit");
    expect(CLOUDFLARE_EMAIL_PRESET.username).toBe("api_token");
    expect(CLOUDFLARE_EMAIL_PRESET.maxRcptsPerSession).toBe(50);
  });
});
