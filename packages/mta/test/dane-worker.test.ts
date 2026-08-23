/**
 * 워커의 DANE 분기 — 조회 결과가 배달 판단으로 이어지는지.
 *
 * `dane-send.test.ts`는 소켓 위의 대조를 본다. 여기서 보는 것은 **큐의 결정**이다:
 * 조작 신호(bogus)를 받은 MX로 계속 보내지 않는가, 그리고 TLSA가 있으면 평문 상대에게
 * 흘리지 않는가. 이 분기가 없으면 위쪽 고정이 아무리 정확해도 우회된다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { MtaWorker, type BlobReader, type MxRecord, type TlsaLookup } from "../src/worker.ts";
import { enqueueMessage as realEnqueueMessage } from "../src/enqueue.ts";
import { fakeTenantAccount, freshDb, verifiedDomain } from "./helpers.ts";
import { TLSA_MATCHING, TLSA_SELECTOR, TLSA_USAGE } from "@ionosphere/mail-auth";

let activeServers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

const enqueueMessage: typeof realEnqueueMessage = (db, input, opts) =>
  realEnqueueMessage(db, input, { requireSenderOwnership: false, ...opts });

/** 무엇이든 받아주는 평문 SMTP 서버(TLS 미설정 = STARTTLS 미광고). */
async function acceptingServer(): Promise<{ port: number; delivered: string[] }> {
  const delivered: string[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      delivered.push(env.mailFrom);
      return { ok: true };
    },
  };
  const server = new SmtpServer({ hostname: "mx.test", maxSizeBytes: 10_000_000, backend });
  activeServers.push(server);
  return { port: await server.listen(0, "127.0.0.1"), delivered };
}

const mxToLocalhost = (): ((domain: string) => Promise<MxRecord[]>) => async () => [
  { exchange: "127.0.0.1", priority: 10 },
];

function fakeBlobs(blobId: string, raw: Uint8Array): BlobReader {
  return {
    get: async (id) => {
      if (id !== blobId) throw new Error(`unexpected blobId: ${id}`);
      return raw;
    },
  };
}

/** 큐에 한 통 넣고 워커를 한 번 돌린 뒤 행 상태를 돌려준다. */
async function runOnce(resolveTlsa: (mxHost: string, port: number) => Promise<TlsaLookup>, port: number) {
  const db = await freshDb();
  const raw = new TextEncoder().encode("Subject: dane\r\n\r\nbody\r\n");
  const blobId = "d".repeat(64);
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

  const worker = new MtaWorker({ db, blobs: fakeBlobs(blobId, raw), resolveMx: mxToLocalhost(), ehloName: "worker.test", port, resolveTlsa });
  await worker.tick();

  const { rows } = await db.query({ sql: "SELECT * FROM mta_queue WHERE id = ?", params: [id] });
  const row = rows[0]!;
  await db.close();
  return row;
}

const okTlsa: TlsaLookup = {
  kind: "tlsa",
  set: {
    records: [
      { usage: TLSA_USAGE.DANE_EE, selector: TLSA_SELECTOR.SPKI, matchingType: TLSA_MATCHING.SHA256, data: new Uint8Array(32) },
    ],
    dnssecValidated: true,
  },
};

describe("MtaWorker — DANE", () => {
  test("TLSA 없음(none) → 평소대로 배달된다", async () => {
    const { port, delivered } = await acceptingServer();
    const row = await runOnce(async () => ({ kind: "none" }), port);

    expect(Number(row.status)).toBe(2); // done
    expect(delivered).toHaveLength(1);
  });

  test("★bogus면 그 MX로 보내지 않는다 — 조작 신호를 무시하고 배달하면 안 된다", async () => {
    const { port, delivered } = await acceptingServer();
    const row = await runOnce(async () => ({ kind: "bogus", reason: "서명 검증 실패" }), port);

    expect(delivered).toHaveLength(0); // 연결조차 하지 않았다
    expect(Number(row.status)).toBe(4); // deferred — 재시도 대상이지 바운스가 아니다
    expect(String(row.last_error)).toContain("TLSA");
  });

  test("★TLSA가 있으면 STARTTLS 없는 상대에게 흘리지 않는다", async () => {
    // 상대가 TLSA를 게시했는데 평문만 준다 = 다운그레이드. 배달 대신 지연이 맞다.
    const { port, delivered } = await acceptingServer();
    const row = await runOnce(async () => okTlsa, port);

    expect(delivered).toHaveLength(0);
    expect(Number(row.status)).toBe(4);
    expect(String(row.last_error)).toContain("STARTTLS");
  });

  test("조회가 던져도 배달은 계속된다 — DANE는 있으면 강화, 없으면 그대로", async () => {
    const { port, delivered } = await acceptingServer();
    const row = await runOnce(async () => {
      throw new Error("dns down");
    }, port);

    expect(Number(row.status)).toBe(2);
    expect(delivered).toHaveLength(1);
  });
});
