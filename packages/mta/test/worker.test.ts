/**
 * MtaWorker 통합테스트 — 상대는 실제 @ionosphere/proto-smtp SmtpServer(port override로 연결),
 * resolveMx는 127.0.0.1로 주입. TLS는 smtp-client.test.ts와 동일한 이유로 미설정 서버만
 * 사용(SmtpServer 자체의 서버측 TLS 업그레이드가 bun test에서 걸리는 알려진 버그).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { dkimVerify, generateDkimKeyPair } from "@ionosphere/mail-auth";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { MtaWorker, type BlobReader, type DkimHook, type MxRecord } from "../src/worker.ts";
import { enqueueMessage as realEnqueueMessage } from "../src/enqueue.ts";
import { SUPPRESSION_REASON } from "@ionosphere/db";
import { fakeTenantAccount, freshDb, verifiedDomain } from "./helpers.ts";
import { buildMtaStsPolicy } from "@ionosphere/mta-sts";

interface Delivered {
  mailFrom: string;
  rcptTo: string[];
  raw: Uint8Array;
}

let activeServers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

async function startServer(backend: SmtpBackend): Promise<number> {
  const server = new SmtpServer({ hostname: "mx.test", maxSizeBytes: 10_000_000, backend });
  activeServers.push(server);
  return server.listen(0, "127.0.0.1");
}

function acceptingBackend(): { backend: SmtpBackend; delivered: Delivered[] } {
  const delivered: Delivered[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      delivered.push({ mailFrom: env.mailFrom, rcptTo: env.rcptTo, raw: env.raw });
      return { ok: true };
    },
  };
  return { backend, delivered };
}

/** resolveMx는 호스트만 결정한다 — 실제 접속 포트는 MtaWorkerOptions.port로 별도 오버라이드. */
function mxToLocalhost(): (domain: string) => Promise<MxRecord[]> {
  return async () => [{ exchange: "127.0.0.1", priority: 10 }];
}

function fakeBlobs(blobId: string, raw: Uint8Array): BlobReader {
  return {
    get: async (id) => {
      if (id !== blobId) throw new Error(`unexpected blobId: ${id}`);
      return raw;
    },
  };
}

async function insertQueueRowDirect(
  db: Awaited<ReturnType<typeof freshDb>>,
  overrides: Partial<{
    tenantId: string;
    accountId: string;
    rcpt: string;
    rcptDomain: string;
    envFrom: string;
    blobId: string;
    status: number;
    attempts: number;
    nextAttempt: number;
    leaseUntil: number | null;
  }> = {},
): Promise<string> {
  const id = ulid();
  const now = Date.now();
  const tenantId = overrides.tenantId ?? ulid();
  const accountId = overrides.accountId ?? ulid();
  const rcpt = overrides.rcpt ?? "bob@example.test";
  await db.batch([
    {
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
      params: [
        id,
        tenantId,
        accountId,
        overrides.blobId ?? "b".repeat(64),
        overrides.envFrom ?? "bounce@sender.test",
        "0".repeat(16),
        rcpt,
        overrides.rcptDomain ?? "example.test",
        overrides.status ?? 0,
        overrides.attempts ?? 0,
        overrides.nextAttempt ?? now,
        overrides.leaseUntil ?? null,
        now,
      ],
    },
  ]);
  return id;
}

async function getRow(db: Awaited<ReturnType<typeof freshDb>>, id: string): Promise<Record<string, unknown>> {
  const { rows } = await db.query({ sql: "SELECT * FROM mta_queue WHERE id = ?", params: [id] });
  const row = rows[0];
  if (!row) throw new Error(`row not found: ${id}`);
  return row;
}

/**
 * 이 파일의 테스트는 **발신자 소유 검증의 대상이 아니다** — 각자 다른 게이트(도메인·레이트리밋·
 * 필드 정확성)를 본다. 소유 검증은 기본 on이라 가짜 accountId로는 전부 걸리므로 여기서만 끈다.
 * 검증 자체의 회귀는 sender-ownership.test.ts가 지킨다.
 */
const enqueueMessage: typeof realEnqueueMessage = (db, input, opts) =>
  realEnqueueMessage(db, input, { requireSenderOwnership: false, ...opts });

describe("MtaWorker — 정상 발송", () => {
  test("tick: queued 행 → 리스 획득 → 발송 성공 → status=2(done), 백엔드가 메시지 수신", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: hello\r\n\r\nbody\r\n");
    const blobId = "b".repeat(64);

    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    const enq = await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId,
      sizeBytes: raw.length,
      envFrom: "sender@sender.test",
      rcpts: ["bob@example.test"],
    });
    const id = enq.queuedIds[0]!;

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
    });

    const processed = await worker.tick();
    expect(processed).toBe(1);

    const row = await getRow(db, id);
    expect(Number(row.status)).toBe(2); // done
    expect(row.last_error).toBeNull();

    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.mailFrom).toBe("sender@sender.test");
    expect(delivered[0]?.rcptTo).toEqual(["bob@example.test"]);
    /**
     * ★바이트 완전 일치를 요구하지 않는다. 발송 경로는 원문 **위에** 헤더를 얹는다
     * (FBL 상관관계 `X-Ionosphere-Feedback-Id`, DKIM 서명 등). 완전 일치로 검사하면 헤더가
     * 하나 늘 때마다 "배달은 멀쩡한데" 깨진다 — 검사 대상은 **원문이 온전히 갔는가**다.
     */
    const sent = new TextDecoder().decode(delivered[0]!.raw);
    expect(sent).toContain("Subject: hello");
    expect(sent).toContain("body");
    // 상관관계 헤더가 실제로 실려야 신고(ARF)를 우리 발송에 되돌릴 수 있다.
    expect(sent).toContain("X-Ionosphere-Feedback-Id:");

    await db.close();
  });

  test("DKIM 훅 제공 시 DKIM-Signature 헤더가 붙고 dkimVerify로 pass 검증됨", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("From: alice@sender.test\r\nTo: bob@example.test\r\nSubject: dkim\r\n\r\nbody\r\n");
    const blobId = "c".repeat(64);

    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    await enqueueMessage(db, {
      tenantId,
      accountId,
      blobId,
      sizeBytes: raw.length,
      envFrom: "alice@sender.test",
      rcpts: ["bob@example.test"],
    });

    const keyPair = generateDkimKeyPair("rsa-sha256");
    const dkim: DkimHook = {
      selectorFor: async (domain) => {
        expect(domain).toBe("sender.test");
        return [{ selector: "mta-sel", privateKey: keyPair.privateKeyPem, algorithm: "rsa-sha256" }];
      },
    };

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      dkim,
      ehloName: "worker.test",
      port,
    });

    const processed = await worker.tick();
    expect(processed).toBe(1);
    expect(delivered).toHaveLength(1);

    const deliveredRaw = delivered[0]!.raw;
    const text = new TextDecoder().decode(deliveredRaw);
    expect(text).toContain("DKIM-Signature:");

    const resolveTxt = async (name: string): Promise<string[]> => {
      expect(name).toBe("mta-sel._domainkey.sender.test");
      return [keyPair.dnsRecord];
    };
    const verifyResults = await dkimVerify(deliveredRaw, resolveTxt);
    expect(verifyResults).toHaveLength(1);
    expect(verifyResults[0]?.result).toBe("pass");

    await db.close();
  });

  test("MX 우선순위 낮은 값 먼저 시도 — 1순위(priority 5)가 연결 불가면 2순위(priority 10)로 폴백", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: mx\r\n\r\nbody\r\n");
    const blobId = "d".repeat(64);

    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    await enqueueMessage(db, { tenantId, accountId, blobId, sizeBytes: raw.length, envFrom: "a@sender.test", rcpts: ["b@example.test"] });

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      // priority 5(더 낮음 → 먼저 시도)는 DNS 해석 자체가 실패하는 호스트 — 연결 레벨 실패
      // (code=0)로 즉시 떨어짐 → 워커가 다음 순위인 127.0.0.1(실제 서버, priority 10)로
      // 폴백하는지 검증한다. (127.0.0.2 등 미할당 루프백 별칭은 OS별로 즉시 거부되지 않고
      // 그냥 행(hang)할 수 있어 DNS 실패 쪽이 테스트 환경에 안전함)
      resolveMx: async () => [
        { exchange: "nonexistent.invalid.mta-test.example", priority: 5 },
        { exchange: "127.0.0.1", priority: 10 },
      ],
      ehloName: "worker.test",
      port,
      // 연결 거부는 즉시 일어나므로 짧은 타임아웃으로도 테스트가 느려지지 않음을 보장
    });

    const processed = await worker.tick();
    expect(processed).toBe(1);
    expect(delivered).toHaveLength(1);
    await db.close();
  });
});

describe("MtaWorker — 일시 실패(4xx) 재시도 경로", () => {
  test("451 응답 → status=4(deferred), attempts=1, next_attempt 미래; 만료 전 재틱은 처리 안 함", async () => {
    const db = await freshDb();
    const backend: SmtpBackend = {
      verifyRecipient: async () => ({ ok: true }),
      deliver: async () => ({ ok: false, code: 451, enhanced: "4.3.0", message: "Try again later" }),
    };
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: transient\r\n\r\nbody\r\n");
    const blobId = "e".repeat(64);
    const id = await insertQueueRowDirect(db, { blobId, rcpt: "bob@example.test", rcptDomain: "example.test" });

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
    });

    const processed = await worker.tick();
    expect(processed).toBe(1);

    const row = await getRow(db, id);
    expect(Number(row.status)).toBe(4); // deferred
    expect(Number(row.attempts)).toBe(1);
    expect(Number(row.next_attempt)).toBeGreaterThan(Date.now());
    expect(row.lease_until).toBeNull();

    // 재시도 시각 전 재틱 — 아직 due가 아니므로 처리되지 않음
    const secondTick = await worker.tick();
    expect(secondTick).toBe(0);

    // next_attempt를 과거로 직접 UPDATE해 due로 만들면 재시도됨
    await db.batch([{ sql: "UPDATE mta_queue SET next_attempt = ? WHERE id = ?", params: [Date.now() - 1000, id] }]);
    const thirdTick = await worker.tick();
    expect(thirdTick).toBe(1);
    const rowAfterRetry = await getRow(db, id);
    expect(Number(rowAfterRetry.attempts)).toBe(2);

    await db.close();
  });
});

describe("MtaWorker — 영구 실패(5xx)", () => {
  test("550 응답 → status=3(bounced) + suppressions 행 생성", async () => {
    const db = await freshDb();
    const backend: SmtpBackend = {
      verifyRecipient: async () => ({ ok: false, code: 550, enhanced: "5.1.1", message: "No such user" }),
      deliver: async () => ({ ok: true }),
    };
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: bounce\r\n\r\nbody\r\n");
    const blobId = "f".repeat(64);
    const tenantId = ulid();
    const id = await insertQueueRowDirect(db, { tenantId, blobId, rcpt: "nouser@example.test", rcptDomain: "example.test" });

    const worker = new MtaWorker({ db, blobs: fakeBlobs(blobId, raw), resolveMx: mxToLocalhost(), ehloName: "worker.test", port });
    const processed = await worker.tick();
    expect(processed).toBe(1);

    const row = await getRow(db, id);
    expect(Number(row.status)).toBe(3); // bounced
    expect(row.last_error).not.toBeNull();

    const { rows: supp } = await db.query({
      sql: "SELECT * FROM suppressions WHERE tenant_id = ? AND email = ?",
      params: [tenantId, "nouser@example.test"],
    });
    expect(supp).toHaveLength(1);
    expect(Number(supp[0]?.reason)).toBe(0); // hard-bounce

    await db.close();
  });

  /**
   * ★RCPT는 수락되고 **DATA 이후**에 거절되는 조합 — 라이브에서 진단을 불가능하게 만든 형태다.
   *
   * 2026-08-03 포워딩 실측에서 큐가 계속 실패하는데 `last_error`가 **"250"**이었다.
   * `applyOutcome`이 `rc ? rc.code : result.code`로 **RCPT 단계** 코드를 기록해서, RCPT의 250이
   * 실제 실패 코드(550)를 덮은 것이다. 250은 성공 코드라 운영자는 성공 코드를 보면서 실패를
   * 디버깅하게 된다 — 이 값은 `GET /v1/queue`로 테넌트에게도 그대로 간다.
   *
   * 기존 550 테스트는 **RCPT 단계** 거절이라 이 결함을 잡지 못했고, `last_error`가 null이
   * 아닌 것만 확인해서 `"250"`이 들어가도 통과했다. 그래서 단계와 내용을 함께 고정한다.
   */
  test("★RCPT 수락 후 DATA에서 550 → last_error에 RCPT의 250이 아니라 실패 사유가 남는다", async () => {
    const db = await freshDb();
    const backend: SmtpBackend = {
      // RCPT는 통과시킨다 — 이게 이 테스트의 핵심 조건이다.
      verifyRecipient: async () => ({ ok: true }),
      // 거절은 DATA 이후에 일어난다(스마트호스트의 From: 헤더 검사가 이 형태였다).
      deliver: async () => ({
        ok: false,
        code: 550,
        enhanced: "5.6.0",
        message: "From: header does not match mail from",
      }),
    };
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: data-stage bounce\r\n\r\nbody\r\n");
    const blobId = "e".repeat(64);
    const tenantId = ulid();
    const id = await insertQueueRowDirect(db, { tenantId, blobId, rcpt: "who@example.test", rcptDomain: "example.test" });

    const worker = new MtaWorker({ db, blobs: fakeBlobs(blobId, raw), resolveMx: mxToLocalhost(), ehloName: "worker.test", port });
    expect(await worker.tick()).toBe(1);

    const row = await getRow(db, id);
    expect(Number(row.status)).toBe(3); // bounced — 550은 영구 실패다
    const err = String(row.last_error);
    // 실패 코드가 남아야 한다. RCPT 단계의 250이 아니다.
    expect(err).toContain("550");
    expect(err).not.toContain("250");
    // 코드만으로는 다음 행동이 갈리지 않는다 — 원격이 준 **사유**가 남아야 한다.
    expect(err).toContain("does not match mail from");

    await db.close();
  });
});

describe("MtaWorker — maxAttempts 소진", () => {
  test("attempts가 maxAttempts에 도달하면 4xx 응답이어도 status=3(bounced)로 전환", async () => {
    const db = await freshDb();
    const backend: SmtpBackend = {
      verifyRecipient: async () => ({ ok: true }),
      deliver: async () => ({ ok: false, code: 451, enhanced: "4.3.0", message: "Try again later" }),
    };
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: exhaust\r\n\r\nbody\r\n");
    const blobId = "g".repeat(64);
    const tenantId = ulid();
    // maxAttempts=2로 낮춰 소진을 빠르게 관측
    const id = await insertQueueRowDirect(db, { tenantId, blobId, rcpt: "x@example.test", rcptDomain: "example.test", attempts: 1 });

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
      maxAttempts: 2,
    });

    await worker.tick();
    const row = await getRow(db, id);
    expect(Number(row.status)).toBe(3); // bounced (attempts 2 >= maxAttempts 2)
    expect(Number(row.attempts)).toBe(2);

    const { rows: supp } = await db.query({
      sql: "SELECT * FROM suppressions WHERE tenant_id = ? AND email = ?",
      params: [tenantId, "x@example.test"],
    });
    expect(supp).toHaveLength(1);
    // 상대가 계속 4xx를 준 "포기"이지 영구 거절이 아니다 — 사유가 갈려 있어야 운영자가 해제 판단을 한다.
    expect(Number(supp[0]!.reason)).toBe(SUPPRESSION_REASON.exhausted);

    await db.close();
  });

  /**
   * 회귀: 예전엔 이 경로도 하드바운스로 기록해 차단 목록에 넣었다. 원인이 대개 **우리 쪽**인데
   * (자체 DNS·네트워크 장애) 수신자를 영구 차단하는 셈이었고, 해제할 API조차 없었다.
   * 몇 시간짜리 장애 한 번이면 그 사이 큐에 있던 정상 수신자가 전부 차단 목록에 올랐다.
   */
  test("수신자와 한 마디도 못 나눈 실패(MX 조회 불가)는 차단 목록을 만들지 않는다", async () => {
    const db = await freshDb();
    const raw = new TextEncoder().encode("Subject: dns-down\r\n\r\nbody\r\n");
    const blobId = "h".repeat(64);
    const tenantId = ulid();
    const id = await insertQueueRowDirect(db, {
      tenantId,
      blobId,
      rcpt: "victim@example.test",
      rcptDomain: "example.test",
      attempts: 1,
    });

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: async () => {
        throw new Error("SERVFAIL — 우리 리졸버가 죽었다");
      },
      ehloName: "worker.test",
      maxAttempts: 2,
    });

    await worker.tick();
    const row = await getRow(db, id);
    expect(Number(row.status)).toBe(3); // 큐 행은 닫힌다(bounced)

    const { rows: supp } = await db.query({
      sql: "SELECT * FROM suppressions WHERE tenant_id = ? AND email = ?",
      params: [tenantId, "victim@example.test"],
    });
    expect(supp).toHaveLength(0); // ★수신자에 대해 알아낸 게 없으므로 벌하지 않는다

    await db.close();
  });
});

describe("MtaWorker — 한 tick 처리량 상한", () => {
  /**
   * 회귀: due 행 SELECT에 LIMIT이 없어 큐가 10만 건이면 한 tick이 전량을 메모리에 올리고
   * 행마다 리스 UPDATE를 날렸다(왕복 10만 번). 그러면 한 사이클이 끝나기 전에 리스(5분)가
   * 만료되기 시작하고, 재기동 시 진행이 통째로 날아간다.
   */
  test("batchSize를 넘는 행은 다음 tick으로 넘긴다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    for (let i = 0; i < 5; i++) {
      await insertQueueRowDirect(db, { tenantId, rcpt: `r${i}@example.test`, rcptDomain: "example.test" });
    }

    // MX 조회를 실패시켜 배달 경로를 타지 않게 한다 — 여기서 보는 건 "몇 건을 잡았는가"뿐이다.
    const worker = new MtaWorker({
      db,
      blobs: { get: async () => new Uint8Array(0) },
      resolveMx: async () => {
        throw new Error("no mx");
      },
      ehloName: "worker.test",
      batchSize: 2,
    });

    expect(await worker.tick()).toBe(2);
    expect(await worker.tick()).toBe(2);

    await db.close();
  });
});

describe("MtaWorker — 크래시 복구", () => {
  test("status=1이고 lease_until이 과거인 행은 due로 재처리됨", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: recover\r\n\r\nbody\r\n");
    const blobId = "h".repeat(64);
    const id = await insertQueueRowDirect(db, {
      blobId,
      rcpt: "r@example.test",
      rcptDomain: "example.test",
      status: 1, // in-flight (죽은 워커가 리스만 잡고 죽은 상태 시뮬레이션)
      leaseUntil: Date.now() - 1000,
    });

    const worker = new MtaWorker({ db, blobs: fakeBlobs(blobId, raw), resolveMx: mxToLocalhost(), ehloName: "worker.test", port });
    const processed = await worker.tick();
    expect(processed).toBe(1);

    const row = await getRow(db, id);
    expect(Number(row.status)).toBe(2);
    expect(delivered).toHaveLength(1);

    await db.close();
  });
});

describe("MtaWorker — 리스 경합", () => {
  test("두 워커가 같은 행들을 동시에 tick() → 각 행은 정확히 한 번만 처리됨(백엔드가 정확히 N통 수신)", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: race\r\n\r\nbody\r\n");

    const N = 6;
    const blobIds: string[] = [];
    const ids: string[] = [];
    for (let i = 0; i < N; i++) {
      // 그룹핑이 rcpt_domain+env_from+blob_id 조합이라 각 행을 서로 다른 blobId로 두어
      // 그룹당 1행 = deliver() 호출 1회가 되도록 함(관찰을 단순화).
      const blobId = i.toString(16).padStart(2, "0").repeat(32);
      blobIds.push(blobId);
      const id = await insertQueueRowDirect(db, {
        blobId,
        envFrom: `sender${i}@sender.test`,
        rcpt: `rcpt${i}@example.test`,
        rcptDomain: "example.test",
      });
      ids.push(id);
    }

    const blobMap = new Map(blobIds.map((b) => [b, raw]));
    const blobs: BlobReader = {
      get: async (id) => {
        const found = blobMap.get(id);
        if (!found) throw new Error(`unexpected blobId: ${id}`);
        return found;
      },
    };

    const workerA = new MtaWorker({ db, blobs, resolveMx: mxToLocalhost(), ehloName: "worker.test", port });
    const workerB = new MtaWorker({ db, blobs, resolveMx: mxToLocalhost(), ehloName: "worker.test", port });

    const [countA, countB] = await Promise.all([workerA.tick(), workerB.tick()]);
    expect(countA + countB).toBe(N);

    expect(delivered).toHaveLength(N);

    for (const id of ids) {
      const row = await getRow(db, id);
      expect(Number(row.status)).toBe(2); // done — 정확히 한 번 처리됨
    }

    await db.close();
  });
});

describe("MtaWorker — onResult 관측 훅", () => {
  test("성공은 sent, 550은 bounced를 아웃컴으로 방출", async () => {
    // 성공 경로
    const db1 = await freshDb();
    const { backend: okBackend } = acceptingBackend();
    const port1 = await startServer(okBackend);
    const raw = new TextEncoder().encode("Subject: t\r\n\r\nb\r\n");
    const blobId = "1".repeat(64);
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db1, tenantId, "sender.test");
    await enqueueMessage(db1, { tenantId, accountId, blobId, sizeBytes: raw.length, envFrom: "s@sender.test", rcpts: ["a@example.test"] });
    const sentOutcomes: string[] = [];
    const w1 = new MtaWorker({
      db: db1,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port: port1,
      onResult: (o) => sentOutcomes.push(o),
    });
    await w1.tick();
    expect(sentOutcomes).toEqual(["sent"]);
    await db1.close();

    // 550 → bounced
    const db2 = await freshDb();
    const rejectBackend: SmtpBackend = {
      verifyRecipient: async () => ({ ok: false, code: 550, enhanced: "5.1.1", message: "no user" }),
      deliver: async () => ({ ok: true }),
    };
    const port2 = await startServer(rejectBackend);
    const blobId2 = "2".repeat(64);
    const tid2 = ulid();
    await insertQueueRowDirect(db2, { tenantId: tid2, blobId: blobId2, rcpt: "x@example.test", rcptDomain: "example.test" });
    const bounceOutcomes: string[] = [];
    const w2 = new MtaWorker({
      db: db2,
      blobs: fakeBlobs(blobId2, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port: port2,
      onResult: (o) => bounceOutcomes.push(o),
    });
    await w2.tick();
    expect(bounceOutcomes).toEqual(["bounced"]);
    await db2.close();
  });

  test("451 재시도 대상은 deferred를 방출", async () => {
    const db = await freshDb();
    const backend: SmtpBackend = {
      verifyRecipient: async () => ({ ok: true }),
      deliver: async () => ({ ok: false, code: 451, enhanced: "4.3.0", message: "later" }),
    };
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: d\r\n\r\nb\r\n");
    const blobId = "3".repeat(64);
    const tid = ulid();
    await insertQueueRowDirect(db, { tenantId: tid, blobId, rcpt: "y@example.test", rcptDomain: "example.test" });
    const outcomes: string[] = [];
    const w = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
      onResult: (o) => outcomes.push(o),
    });
    await w.tick();
    expect(outcomes).toEqual(["deferred"]);
    await db.close();
  });

  test("onResult가 던져도 워커는 정상 진행(삼킴)", async () => {
    const db = await freshDb();
    const { backend } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: t\r\n\r\nb\r\n");
    const blobId = "4".repeat(64);
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    await enqueueMessage(db, { tenantId, accountId, blobId, sizeBytes: raw.length, envFrom: "s@sender.test", rcpts: ["a@example.test"] });
    const w = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
      onResult: () => {
        throw new Error("boom");
      },
    });
    const processed = await w.tick();
    expect(processed).toBe(1); // 훅 예외에도 처리 완료
    await db.close();
  });
});

describe("MtaWorker — MTA-STS 발신측 강제(opt-in)", () => {
  function stsDeps(policyMx: string[], mode: "enforce" | "testing"): { resolveTxt: (n: string) => Promise<string[]>; httpsGet: (u: string) => Promise<string> } {
    return {
      resolveTxt: async (n) => (n.startsWith("_mta-sts.") ? ["v=STSv1; id=v1"] : []),
      httpsGet: async () => buildMtaStsPolicy({ mx: policyMx, mode }),
    };
  }

  test("enforce + MX가 정책과 불일치 → deferred(배달 안 함)", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: t\r\n\r\nb\r\n");
    const blobId = "9".repeat(64);
    const id = await insertQueueRowDirect(db, { tenantId: ulid(), blobId, rcpt: "u@example.test", rcptDomain: "example.test" });
    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(), // exchange=127.0.0.1
      ehloName: "worker.test",
      port,
      mtaSts: stsDeps(["mail.other.test"], "enforce"), // 127.0.0.1과 불일치
    });
    await worker.tick();
    expect(Number((await getRow(db, id)).status)).toBe(4); // deferred
    expect(delivered).toHaveLength(0);
    await db.close();
  });

  test("enforce + MX 일치하나 평문 서버(STARTTLS 불가) → deferred(다운그레이드 배달 금지)", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend); // TLS 미구성 평문 서버
    const raw = new TextEncoder().encode("Subject: t\r\n\r\nb\r\n");
    const blobId = "8".repeat(64);
    const id = await insertQueueRowDirect(db, { tenantId: ulid(), blobId, rcpt: "u@example.test", rcptDomain: "example.test" });
    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
      mtaSts: stsDeps(["127.0.0.1"], "enforce"), // MX 일치 → tls:required 강제
    });
    await worker.tick();
    expect(Number((await getRow(db, id)).status)).toBe(4); // STARTTLS 불가 → deferred
    expect(delivered).toHaveLength(0);
    await db.close();
  });

  /**
   * 감사 5차 M-1 회귀 — 정책 페치 실패가 fail-open이었다. 공격자가 정책 조회를 방해하기만
   * 하면 enforce가 opportunistic으로 떨어져 평문·미검증 배달이 됐다. RFC 8461 §5는 이 상황에서
   * **캐시된 정책을 계속 쓰라**고 요구한다.
   */
  test("정책 재조회가 실패해도 캐시된 enforce 정책을 계속 강제한다(M-1)", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend); // 평문 서버 — enforce면 배달 불가
    const raw = new TextEncoder().encode("Subject: t\r\n\r\nb\r\n");
    const blobId = "b".repeat(64);

    // 첫 조회는 성공(enforce, MX 일치), 두 번째부터는 페치가 실패한다.
    let calls = 0;
    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
      mtaSts: {
        resolveTxt: async (n: string) => (n.startsWith("_mta-sts.") ? ["v=STSv1; id=v1"] : []),
        httpsGet: async () => {
          calls += 1;
          if (calls > 1) throw new Error("정책 서버 도달 불가");
          return buildMtaStsPolicy({ mx: ["127.0.0.1"], mode: "enforce" });
        },
        cacheTtlMs: 0, // 매 배달마다 재조회하게 만들어 실패 경로를 태운다
      },
    });

    const first = await insertQueueRowDirect(db, { tenantId: ulid(), blobId, rcpt: "u@example.test", rcptDomain: "example.test" });
    await worker.tick();
    expect(Number((await getRow(db, first)).status)).toBe(4); // enforce → 평문이라 deferred

    // 두 번째 배달: 페치가 실패한다. 예전엔 여기서 opportunistic으로 떨어져 **배달됐다**.
    const second = await insertQueueRowDirect(db, { tenantId: ulid(), blobId, rcpt: "v@example.test", rcptDomain: "example.test" });
    await worker.tick();
    expect(calls).toBeGreaterThan(1); // 실제로 재조회를 시도했다
    expect(Number((await getRow(db, second)).status)).toBe(4); // 캐시 정책이 유지돼 여전히 deferred
    expect(delivered).toHaveLength(0); // 평문 다운그레이드 배달 0

    await db.close();
  });

  test("testing 모드 → 정상 배달(report-only, opportunistic)", async () => {
    const db = await freshDb();
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);
    const raw = new TextEncoder().encode("Subject: t\r\n\r\nb\r\n");
    const blobId = "7".repeat(64);
    const { tenantId, accountId } = fakeTenantAccount();
    await verifiedDomain(db, tenantId, "sender.test");
    await enqueueMessage(db, { tenantId, accountId, blobId, sizeBytes: raw.length, envFrom: "s@sender.test", rcpts: ["u@example.test"] });
    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: mxToLocalhost(),
      ehloName: "worker.test",
      port,
      mtaSts: stsDeps(["127.0.0.1"], "testing"),
    });
    await worker.tick();
    expect(delivered).toHaveLength(1); // testing은 관측만 — 평문 배달 진행
    await db.close();
  });
});
