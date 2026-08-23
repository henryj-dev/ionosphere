/**
 * 587 릴레이(스마트호스트) 발송 모드 테스트 — 상대는 실제 @ionosphere/proto-smtp SmtpServer를
 * submission 프로파일(AUTH 필수)로 세운다. TLS는 smtp-client.test.ts와 동일한 이유로
 * 미설정 서버 + allowInsecureAuth로 검증(bun test의 서버측 TLS 업그레이드 버그,
 * oven-sh/bun#25044). tls:"required" 경로는 "미광고 시 발송 중단"만 여기서 검증한다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { sendSmtp } from "../src/smtp-client.ts";
import { MtaWorker, type BlobReader, type MxRecord, type SmarthostOptions, type SmarthostResolver } from "../src/worker.ts";
import { freshDb } from "./helpers.ts";
import { ulid } from "@ionosphere/core";

interface Delivered {
  mailFrom: string;
  rcptTo: string[];
  raw: Uint8Array;
  authenticatedAs: string | null;
}

let activeServers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

/** submission 프로파일 릴레이 서버 — AUTH 필수, 자격증명은 relay-user/relay-pass 고정. */
function relayServer(): { start: () => Promise<number>; delivered: Delivered[] } {
  const delivered: Delivered[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      delivered.push({ mailFrom: env.mailFrom, rcptTo: env.rcptTo, raw: env.raw, authenticatedAs: env.authenticatedAs });
      return { ok: true };
    },
    authenticate: async (user, pass) => ({ ok: user === "relay-user" && pass === "relay-pass" }),
  };
  const server = new SmtpServer({
    hostname: "smarthost.test",
    maxSizeBytes: 10_000_000,
    profile: "submission",
    allowInsecureAuth: true, // 테스트 전용 — TLS 미설정 서버라 평문 AUTH 허용 필요
    backend,
  });
  activeServers.push(server);
  return { start: () => server.listen(0, "127.0.0.1"), delivered };
}

function fakeBlobs(blobId: string, raw: Uint8Array): BlobReader {
  return {
    get: async (id) => {
      if (id !== blobId) throw new Error(`unexpected blobId: ${id}`);
      return raw;
    },
  };
}

async function insertQueueRow(db: Awaited<ReturnType<typeof freshDb>>, blobId: string): Promise<string> {
  const id = ulid();
  const now = Date.now();
  await db.batch([
    {
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, 0, 0, ?, NULL, NULL, ?)`,
      params: [id, ulid(), ulid(), blobId, "alice@sender.test", "0".repeat(16), "bob@remote.test", "remote.test", now, now],
    },
  ]);
  return id;
}

describe("sendSmtp — SASL AUTH (릴레이 클라이언트측)", () => {
  test("AUTH PLAIN(initial-response) 성공 → 인증 사용자로 배달", async () => {
    const relay = relayServer();
    const port = await relay.start();

    const raw = new TextEncoder().encode("Subject: via relay\r\n\r\nhello\r\n");
    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "alice@sender.test",
      rcptTo: ["bob@remote.test"],
      raw,
      tls: "never",
      auth: { user: "relay-user", pass: "relay-pass" },
    });

    expect(result.ok).toBe(true);
    expect(relay.delivered).toHaveLength(1);
    // NUL 구분 PLAIN 인코딩이 서버측 파서와 왕복 일치하는지 — authenticatedAs로 검증
    expect(relay.delivered[0]?.authenticatedAs).toBe("relay-user");
    expect(relay.delivered[0]?.raw).toEqual(raw);
  });

  test("AUTH 실패(잘못된 자격증명) → ok=false, permanent=false (바운스 금지 계약)", async () => {
    const relay = relayServer();
    const port = await relay.start();

    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "alice@sender.test",
      rcptTo: ["bob@remote.test"],
      raw: new TextEncoder().encode("Subject: x\r\n\r\nbody\r\n"),
      tls: "never",
      auth: { user: "relay-user", pass: "wrong" },
    });

    expect(result.ok).toBe(false);
    expect(result.permanent).toBe(false); // 5xx여도 자격증명 문제는 재시도 대상
    expect(relay.delivered).toHaveLength(0);
  });

  test("tls:'required'인데 서버가 STARTTLS 미광고 → 평문 진행 금지, deferred 결과", async () => {
    const relay = relayServer();
    const port = await relay.start();

    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "alice@sender.test",
      rcptTo: ["bob@remote.test"],
      raw: new TextEncoder().encode("Subject: x\r\n\r\nbody\r\n"),
      tls: "required",
      auth: { user: "relay-user", pass: "relay-pass" },
    });

    expect(result.ok).toBe(false);
    expect(result.code).toBe(0);
    expect(result.permanent).toBe(false);
    expect(result.message).toContain("STARTTLS required");
    expect(relay.delivered).toHaveLength(0);
  });
});

describe("MtaWorker — 스마트호스트 릴레이 모드", () => {
  test("smarthost 지정 시 MX 조회를 생략하고 릴레이로 발송(AUTH 포함) → status=done", async () => {
    const relay = relayServer();
    const port = await relay.start();
    const db = await freshDb();
    const blobId = "a".repeat(64);
    const raw = new TextEncoder().encode("Subject: smarthost\r\n\r\nrelayed body\r\n");
    const rowId = await insertQueueRow(db, blobId);

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      // MX 리졸버가 호출되면 실패 — smarthost 모드가 MX 경로를 완전히 우회함을 증명
      resolveMx: async () => {
        throw new Error("resolveMx must not be called in smarthost mode");
      },
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port, auth: { user: "relay-user", pass: "relay-pass" }, tls: "never" },
    });

    const processed = await worker.tick();
    expect(processed).toBe(1);

    expect(relay.delivered).toHaveLength(1);
    expect(relay.delivered[0]?.authenticatedAs).toBe("relay-user");
    expect(relay.delivered[0]?.rcptTo).toEqual(["bob@remote.test"]);

    const { rows } = await db.query({ sql: "SELECT status FROM mta_queue WHERE id = ?", params: [rowId] });
    expect(Number(rows[0]?.status)).toBe(2); // done
    await db.close();
  });

  test("릴레이 AUTH 실패 → deferred(재시도), 바운스/suppression 없음", async () => {
    const relay = relayServer();
    const port = await relay.start();
    const db = await freshDb();
    const blobId = "c".repeat(64);
    const rowId = await insertQueueRow(db, blobId);

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, new TextEncoder().encode("Subject: x\r\n\r\nbody\r\n")),
      resolveMx: async () => {
        throw new Error("resolveMx must not be called in smarthost mode");
      },
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port, auth: { user: "relay-user", pass: "wrong" }, tls: "never" },
    });

    await worker.tick();

    expect(relay.delivered).toHaveLength(0);
    const { rows } = await db.query({ sql: "SELECT status, attempts, last_error FROM mta_queue WHERE id = ?", params: [rowId] });
    expect(Number(rows[0]?.status)).toBe(4); // deferred — 자격증명 문제로 수신자를 바운스시키지 않는다
    expect(Number(rows[0]?.attempts)).toBe(1);
    const { rows: sup } = await db.query({ sql: "SELECT COUNT(*) AS n FROM suppressions", params: [] });
    expect(Number(sup[0]?.n)).toBe(0);
    await db.close();
  });

  /**
   * ★릴레이가 **5xx**를 낼 때도 수신자를 억제하지 않는다 — 위 테스트(AUTH 실패)는 4xx라
   * 이 갈래를 지키지 못했다.
   *
   * 2026-08-03 라이브에서 이것이 실제로 틀렸다: Cloudflare 릴레이가
   * `550 5.6.0 From: header does not match mail from`을 냈는데(SRS 포워딩에서는 From: 헤더와
   * envelope MAIL FROM이 구조적으로 어긋난다) 우리는 하드바운스로 읽고 **무고한 Gmail 주소를
   * 영구 차단**했다. 그 주소는 Gmail이 거절한 적조차 없다 — 릴레이는 수신자가 아니라
   * 우리 submission을 심사하는 중간자다.
   *
   * hardBounce는 만료가 없어(`suppressionExpiresAt`) 되돌리기 어려운 쪽이다. 그래서 여기서는
   * 억제하지 않는 것이 fail closed다: 잘못 억제하면 정상 수신자에게 영구히 못 보내고,
   * 억제하지 않으면 같은 설정 오류로 한 번 더 실패할 뿐이다.
   */
  test("★릴레이가 5xx를 내면 큐는 닫지만 수신자를 억제하지 않는다(수신자 판정이 아니다)", async () => {
    const delivered: Delivered[] = [];
    const backend: SmtpBackend = {
      // RCPT는 통과 — 거절은 DATA 이후다(라이브에서 만난 형태 그대로).
      verifyRecipient: async () => ({ ok: true }),
      deliver: async () => ({
        ok: false,
        code: 550,
        enhanced: "5.6.0",
        message: "From: header does not match mail from",
      }),
      authenticate: async (user, pass) => ({ ok: user === "relay-user" && pass === "relay-pass" }),
    };
    const server = new SmtpServer({
      hostname: "smarthost.test",
      maxSizeBytes: 10_000_000,
      backend,
      allowInsecureAuth: true,
    });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const db = await freshDb();
    const blobId = "d".repeat(64);
    const rowId = await insertQueueRow(db, blobId);

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, new TextEncoder().encode("Subject: relay 5xx\r\n\r\nbody\r\n")),
      resolveMx: async () => {
        throw new Error("resolveMx must not be called in smarthost mode");
      },
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port, auth: { user: "relay-user", pass: "relay-pass" }, tls: "never" },
    });

    expect(await worker.tick()).toBe(1);
    expect(delivered).toHaveLength(0);

    const { rows } = await db.query({ sql: "SELECT status, last_error FROM mta_queue WHERE id = ?", params: [rowId] });
    // 큐 행은 닫는다 — 재시도해도 같은 답이므로 매달아 두면 안 된다.
    expect(Number(rows[0]?.status)).toBe(3); // bounced
    // 사유가 남아야 원인을 알 수 있다(코드만으론 다음 행동이 갈리지 않는다).
    expect(String(rows[0]?.last_error)).toContain("does not match mail from");

    // ★핵심: 수신자는 억제되지 않는다.
    const { rows: sup } = await db.query({ sql: "SELECT COUNT(*) AS n FROM suppressions", params: [] });
    expect(Number(sup[0]?.n)).toBe(0);
    await db.close();
  });
});

/**
 * ── 테넌트/발신 도메인별 해석(마이그레이션 007) ──────────────────────────────
 *
 * 위 테스트들은 전역 설정 하나만 있던 시절의 계약이다. 여기서는 **범위**를 검증한다:
 *  ① 해석기 결과가 전역 설정을 이긴다(좁은 범위 우선).
 *  ② 해석기가 null이면 전역으로 내려간다 — "설정 없음"은 실패가 아니다.
 *  ③ **해석 실패는 MX 직송으로 폴백하지 않는다** — 이게 보안 계약이다.
 *  ④ 세션당 RCPT 상한으로 쪼갠다(제공자 상한 초과분이 조용히 사라지는 것을 막는다).
 *  ⑤ 그룹 키의 테넌트 격리 — 남의 릴레이 자격증명으로 나가지 않는다.
 */

const SCOPE_BLOB = "d".repeat(64);
const SCOPE_RAW = new TextEncoder().encode("Subject: scope\r\n\r\nbody\r\n");

/** 인증 없이 받는 릴레이 — 범위 해석만 보는 테스트라 AUTH는 변수에서 뺀다. */
async function plainRelay(): Promise<{ port: number; delivered: Delivered[] }> {
  const delivered: Delivered[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      delivered.push({ mailFrom: env.mailFrom, rcptTo: env.rcptTo, raw: env.raw, authenticatedAs: env.authenticatedAs });
      return { ok: true };
    },
  };
  const server = new SmtpServer({ hostname: "relay.test", maxSizeBytes: 10_000_000, backend });
  activeServers.push(server);
  return { port: await server.listen(0, "127.0.0.1"), delivered };
}

const scopeBlobs: BlobReader = { get: async () => SCOPE_RAW };
const mxToLocalhost = async (): Promise<MxRecord[]> => [{ exchange: "127.0.0.1", priority: 10 }];

async function insertScopedRow(
  db: Awaited<ReturnType<typeof freshDb>>,
  o: { tenantId: string; rcpt: string; envFrom?: string; rcptDomain?: string },
): Promise<string> {
  const id = ulid();
  const now = Date.now();
  await db.batch([
    {
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, 0, 0, ?, NULL, NULL, ?)`,
      params: [id, o.tenantId, ulid(), SCOPE_BLOB, o.envFrom ?? "s@sender.test", "0".repeat(16), o.rcpt, o.rcptDomain ?? "remote.test", now, now],
    },
  ]);
  return id;
}

/** 고정 응답 해석기. 호출 인자를 기록해 그룹 분할까지 함께 관찰한다. */
function fixedResolver(value: SmarthostOptions | null): SmarthostResolver & { calls: { tenantId: string; senderDomain: string }[] } {
  const calls: { tenantId: string; senderDomain: string }[] = [];
  return {
    calls,
    resolve: async (tenantId, senderDomain) => {
      calls.push({ tenantId, senderDomain });
      return value;
    },
  };
}

describe("스마트호스트 범위 해석", () => {
  test("① 해석기가 돌려준 릴레이가 전역 설정을 이긴다", async () => {
    const db = await freshDb();
    const scoped = await plainRelay();
    const global = await plainRelay();
    const tenantId = ulid();
    await insertScopedRow(db, { tenantId, rcpt: "a@remote.test" });

    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port: global.port, tls: "never" },
      smarthostResolver: fixedResolver({ host: "127.0.0.1", port: scoped.port, tls: "never" }),
    }).tick();

    expect(scoped.delivered).toHaveLength(1);
    expect(global.delivered).toHaveLength(0);
    await db.close();
  });

  test("② 해석기가 null이면 전역 설정으로 내려간다 — 설정 없음은 실패가 아니다", async () => {
    const db = await freshDb();
    const global = await plainRelay();
    await insertScopedRow(db, { tenantId: ulid(), rcpt: "a@remote.test" });

    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port: global.port, tls: "never" },
      smarthostResolver: fixedResolver(null),
    }).tick();

    expect(global.delivered).toHaveLength(1);
    await db.close();
  });

  test("해석기는 (테넌트, 발신 도메인)으로 불린다 — 수신 도메인이 아니다", async () => {
    const db = await freshDb();
    const relay = await plainRelay();
    const tenantId = ulid();
    await insertScopedRow(db, { tenantId, rcpt: "a@recipient.test", rcptDomain: "recipient.test", envFrom: "me@ionosphere.test" });

    const resolver = fixedResolver({ host: "127.0.0.1", port: relay.port, tls: "never" });
    await new MtaWorker({ db, blobs: scopeBlobs, resolveMx: mxToLocalhost, ehloName: "client.test", smarthostResolver: resolver }).tick();

    expect(resolver.calls).toEqual([{ tenantId, senderDomain: "ionosphere.test" }]);
    await db.close();
  });

  /**
   * ★이 테스트가 이 절의 이유다.
   *
   * 해석 실패를 "설정 없음"으로 뭉개면, 릴레이 전용으로 구성한 테넌트의 메일이 DB가 잠깐
   * 흔들리는 동안 **인증 없이 MX로 직접** 나간다. 제공자 밖 발송이라 SPF·평판이 함께 깨지고,
   * 아웃바운드 25가 막힌 환경이면 그대로 전량 실패한다. 지연시키고 다시 시도해야 한다.
   */
  test("③ 해석기가 던지면 MX 직송으로 새지 않고 deferred로 남는다", async () => {
    const db = await freshDb();
    const mx = await plainRelay();
    const id = await insertScopedRow(db, { tenantId: ulid(), rcpt: "a@remote.test" });

    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      // MX 직송이 **성공할 수 있는** 상태로 둔다 — 폴백이 있었다면 여기로 배달된다.
      resolveMx: mxToLocalhost,
      port: mx.port,
      ehloName: "client.test",
      smarthostResolver: {
        resolve: async () => {
          throw new Error("DB 연결 끊김");
        },
      },
    }).tick();

    expect(mx.delivered).toHaveLength(0);
    const { rows } = await db.query({ sql: "SELECT status, last_error FROM mta_queue WHERE id = ?", params: [id] });
    expect(Number(rows[0]?.status)).toBe(4); // deferred
    /**
     * 감사 5차 M-11 — `last_error`는 `GET /v1/queue`로 **테넌트에게 반환**되므로 우리 인프라
     * 상세(릴레이 구성·DB 오류 문구)를 담으면 안 된다. 상세는 로그로만 간다.
     * 예전 이 단언은 `"smarthost resolve failed"`(내부 문구)가 저장되기를 요구하고 있었다.
     */
    expect(String(rows[0]?.last_error)).toBe("relay configuration unavailable");
    expect(String(rows[0]?.last_error)).not.toContain("DB 연결 끊김");
    await db.close();
  });

  test("④ maxRcptsPerSession을 넘는 수신자는 여러 세션으로 쪼개 보낸다", async () => {
    const db = await freshDb();
    const relay = await plainRelay();
    const tenantId = ulid();
    for (let i = 0; i < 5; i++) await insertScopedRow(db, { tenantId, rcpt: `r${i}@remote.test` });

    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      ehloName: "client.test",
      smarthostResolver: fixedResolver({ host: "127.0.0.1", port: relay.port, tls: "never", maxRcptsPerSession: 2 }),
    }).tick();

    // 2 + 2 + 1. 상한이 없으면 5개짜리 세션 하나가 되고 제공자가 초과분을 거절한다.
    expect(relay.delivered.map((d) => d.rcptTo.length)).toEqual([2, 2, 1]);
    expect(relay.delivered.flatMap((d) => d.rcptTo).sort()).toEqual([
      "r0@remote.test",
      "r1@remote.test",
      "r2@remote.test",
      "r3@remote.test",
      "r4@remote.test",
    ]);
    await db.close();
  });

  test("상한이 없으면 종전대로 한 세션에 몰아 보낸다", async () => {
    const db = await freshDb();
    const relay = await plainRelay();
    const tenantId = ulid();
    for (let i = 0; i < 5; i++) await insertScopedRow(db, { tenantId, rcpt: `r${i}@remote.test` });

    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      ehloName: "client.test",
      smarthostResolver: fixedResolver({ host: "127.0.0.1", port: relay.port, tls: "never" }),
    }).tick();

    expect(relay.delivered).toHaveLength(1);
    expect(relay.delivered[0]?.rcptTo).toHaveLength(5);
    await db.close();
  });

  /**
   * ⑤ 그룹 키에 tenant_id가 없으면 두 테넌트의 수신자가 한 그룹이 되고, 그 그룹은 첫 행의
   * 테넌트로 해석한 릴레이를 탄다 — 남의 자격증명으로 나가고 남의 발송 한도를 쓴다.
   * 나머지 키(수신 도메인·발신자·블롭)를 일부러 전부 같게 두어 그것만 검사한다.
   */
  test("⑤ 같은 발신자·수신 도메인이라도 테넌트가 다르면 각자의 릴레이로 나간다", async () => {
    const db = await freshDb();
    const relayA = await plainRelay();
    const relayB = await plainRelay();
    const tenantA = ulid();
    const tenantB = ulid();
    await insertScopedRow(db, { tenantId: tenantA, rcpt: "a@remote.test" });
    await insertScopedRow(db, { tenantId: tenantB, rcpt: "b@remote.test" });

    const byTenant: Record<string, number> = { [tenantA]: relayA.port, [tenantB]: relayB.port };
    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      ehloName: "client.test",
      smarthostResolver: { resolve: async (tenantId) => ({ host: "127.0.0.1", port: byTenant[tenantId]!, tls: "never" }) },
    }).tick();

    expect(relayA.delivered.flatMap((d) => d.rcptTo)).toEqual(["a@remote.test"]);
    expect(relayB.delivered.flatMap((d) => d.rcptTo)).toEqual(["b@remote.test"]);
    await db.close();
  });
});

/**
 * ── 로컬 수신 도메인은 릴레이를 타지 않는다 ─────────────────────────────
 *
 * 태우면 우리 → 제공자 → (제공자가 MX 조회) → 우리로 한 바퀴 돈다. 제공자 쿼터를 내부 메일이
 * 쓰고, 사내 메일 본문이 제3자를 통과하며, 봉투 발신자가 제공자 바운스 주소로 재작성돼
 * 배달 결과를 우리가 못 본다.
 */
async function seedDomain(db: Awaited<ReturnType<typeof freshDb>>, name: string): Promise<void> {
  await db.batch([
    {
      sql: "INSERT INTO domains (id, tenant_id, name, name_utf8, status, verify_token, claimed_at, created_at) VALUES (?, ?, ?, NULL, 1, NULL, ?, ?)",
      params: [ulid(), ulid(), name, Date.now(), Date.now()],
    },
  ]);
}

describe("로컬 수신 도메인 — 릴레이 우회", () => {
  test("★수신 도메인이 우리 것이면 릴레이를 고르지 않고 MX로 간다", async () => {
    const db = await freshDb();
    await seedDomain(db, "remote.test"); // 이 테스트에서만 "우리 도메인"으로 취급
    const relay = await plainRelay();
    const mx = await plainRelay();
    await insertScopedRow(db, { tenantId: ulid(), rcpt: "a@remote.test" });

    const resolver = fixedResolver({ host: "127.0.0.1", port: relay.port, tls: "never" });
    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      port: mx.port,
      ehloName: "client.test",
      smarthostResolver: resolver,
    }).tick();

    expect(mx.delivered).toHaveLength(1);
    expect(relay.delivered).toHaveLength(0);
    // 해석기를 부를 이유조차 없다 — 판정이 릴레이 선택보다 앞선다
    expect(resolver.calls).toHaveLength(0);
    await db.close();
  });

  test("전역 스마트호스트가 있어도 로컬 도메인은 우회한다", async () => {
    const db = await freshDb();
    await seedDomain(db, "remote.test");
    const global = await plainRelay();
    const mx = await plainRelay();
    await insertScopedRow(db, { tenantId: ulid(), rcpt: "a@remote.test" });

    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      port: mx.port,
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port: global.port, tls: "never" },
    }).tick();

    expect(mx.delivered).toHaveLength(1);
    expect(global.delivered).toHaveLength(0);
    await db.close();
  });

  test("우리 도메인이 아니면 종전대로 릴레이를 탄다", async () => {
    const db = await freshDb();
    await seedDomain(db, "ours.test"); // 수신 도메인(remote.test)과 다르다
    const relay = await plainRelay();
    const mx = await plainRelay();
    await insertScopedRow(db, { tenantId: ulid(), rcpt: "a@remote.test" });

    await new MtaWorker({
      db,
      blobs: scopeBlobs,
      resolveMx: mxToLocalhost,
      port: mx.port,
      ehloName: "client.test",
      smarthostResolver: fixedResolver({ host: "127.0.0.1", port: relay.port, tls: "never" }),
    }).tick();

    expect(relay.delivered).toHaveLength(1);
    expect(mx.delivered).toHaveLength(0);
    await db.close();
  });
});
