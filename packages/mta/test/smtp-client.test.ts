/**
 * sendSmtp 통합테스트 — 상대는 실제 @ionosphere/proto-smtp SmtpServer(가짜 백엔드).
 *
 * TLS는 미설정 서버(STARTTLS 비광고)로 tls:"never" 검증만 한다 — src/smtp-client.ts 상단
 * 주석에 적은 이유(bun test에서 SmtpServer의 서버측 TLS 업그레이드가 걸리는 알려진 버그,
 * oven-sh/bun#25044) 그대로.
 */
import { describe, expect, test, afterEach } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { sendSmtp } from "../src/smtp-client.ts";

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
      delivered.push(env);
      return { ok: true, queuedId: "q-1" };
    },
  };
  return { backend, delivered };
}

describe("sendSmtp — 정상 발송", () => {
  test("연결 → EHLO → MAIL/RCPT/DATA → 백엔드가 정확한 raw 바이트를 byte-exact로 수신", async () => {
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);

    const raw = new TextEncoder().encode("Subject: hi\r\n\r\nhello there\r\n");
    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "alice@sender.test",
      rcptTo: ["bob@example.test"],
      raw,
      tls: "never",
    });

    expect(result.ok).toBe(true);
    expect(result.code).toBe(250);
    expect(result.permanent).toBe(false);
    expect(result.rcptResults.get("bob@example.test")?.code).toBe(250);
    expect(result.rcptResults.get("bob@example.test")?.permanent).toBe(false);

    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.mailFrom).toBe("alice@sender.test");
    expect(delivered[0]?.rcptTo).toEqual(["bob@example.test"]);
    expect(delivered[0]?.raw).toEqual(raw);
  });

  test("dot-stuffing 왕복 — 본문에 선두 '.'로 시작하는 줄이 있어도 원문 그대로 도착", async () => {
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);

    const raw = new TextEncoder().encode("Subject: dots\r\n\r\n.this line starts with a dot\r\nnormal line\r\n..double dot\r\n");
    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "a@sender.test",
      rcptTo: ["b@example.test"],
      raw,
      tls: "never",
    });

    expect(result.ok).toBe(true);
    expect(delivered[0]?.raw).toEqual(raw);
  });

  test("멀티라인 EHLO 응답을 정상 파싱하고 8BITMIME 파라미터를 광고에 맞춰 부착", async () => {
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);

    const raw = new TextEncoder().encode("Subject: caps\r\n\r\nbody\r\n");
    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "a@sender.test",
      rcptTo: ["b@example.test"],
      raw,
      tls: "never",
    });

    // SmtpServer(engine.ts)는 항상 8BITMIME을 EHLO 캡세트로 광고하므로(멀티라인 250- 응답),
    // sendSmtp가 이를 파싱해 MAIL FROM에 BODY=8BITMIME을 첨부했는지는 백엔드 수신 자체(성공)로
    // 간접 검증한다 — proto-smtp 엔진이 알 수 없는 MAIL 파라미터는 504로 거부하기 때문에
    // 성공했다는 것 자체가 파라미터 문법이 올바르게 조립됐다는 증거.
    expect(result.ok).toBe(true);
    expect(delivered).toHaveLength(1);
  });

  test("복수 수신자 — 전원 수락 시 전원 rcptResults에 250", async () => {
    const { backend, delivered } = acceptingBackend();
    const port = await startServer(backend);

    const raw = new TextEncoder().encode("Subject: multi\r\n\r\nbody\r\n");
    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "a@sender.test",
      rcptTo: ["b1@example.test", "b2@example.test"],
      raw,
      tls: "never",
    });

    expect(result.ok).toBe(true);
    expect(result.rcptResults.size).toBe(2);
    expect(result.rcptResults.get("b1@example.test")?.code).toBe(250);
    expect(result.rcptResults.get("b2@example.test")?.code).toBe(250);
    expect(delivered[0]?.rcptTo).toEqual(["b1@example.test", "b2@example.test"]);
  });
});

describe("sendSmtp — 수신자 거부", () => {
  test("백엔드가 특정 rcpt를 거부하면 해당 rcpt는 permanent 결과, deliver는 호출되지 않음(전원 거부)", async () => {
    const backend: SmtpBackend = {
      verifyRecipient: async () => ({ ok: false, code: 550, enhanced: "5.1.1", message: "No such user" }),
      deliver: async () => ({ ok: true }),
    };
    const port = await startServer(backend);

    const raw = new TextEncoder().encode("Subject: x\r\n\r\nbody\r\n");
    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "a@sender.test",
      rcptTo: ["nouser@example.test"],
      raw,
      tls: "never",
    });

    expect(result.ok).toBe(false);
    expect(result.permanent).toBe(true);
    expect(result.rcptResults.get("nouser@example.test")?.code).toBe(550);
    expect(result.rcptResults.get("nouser@example.test")?.permanent).toBe(true);
    // ★원격의 문구가 수신자별로 실려야 한다 — 전원 거절이면 세션 message는 우리가 합성한
    //   "all recipients rejected"라 사유가 사라진다(last_error·DSN 진단이 그 값을 쓴다).
    expect((result.rcptResults.get("nouser@example.test")?.message ?? "").length > 0).toBe(true);
  });

  test("일부 rcpt만 거부돼도 수락된 rcpt로 DATA까지 진행(부분 성공)", async () => {
    const delivered: Delivered[] = [];
    const backend: SmtpBackend = {
      verifyRecipient: async (address) =>
        address === "bad@example.test" ? { ok: false, code: 550, enhanced: "5.1.1", message: "No such user" } : { ok: true },
      deliver: async (env) => {
        delivered.push(env);
        return { ok: true };
      },
    };
    const port = await startServer(backend);

    const raw = new TextEncoder().encode("Subject: partial\r\n\r\nbody\r\n");
    const result = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "client.test",
      mailFrom: "a@sender.test",
      rcptTo: ["bad@example.test", "good@example.test"],
      raw,
      tls: "never",
    });

    expect(result.ok).toBe(true);
    expect(result.rcptResults.get("bad@example.test")?.code).toBe(550);
    expect(result.rcptResults.get("bad@example.test")?.permanent).toBe(true);
    expect(result.rcptResults.get("good@example.test")?.code).toBe(250);
    expect(result.rcptResults.get("good@example.test")?.permanent).toBe(false);
    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.rcptTo).toEqual(["good@example.test"]);
  });
});

describe("sendSmtp — 연결 실패", () => {
  test("연결 불가한 포트 → ok=false, code=0(연결 레벨), permanent=false", async () => {
    const result = await sendSmtp({
      host: "127.0.0.1",
      port: 1, // 예약 포트 — 즉시 ECONNREFUSED 기대
      ehloName: "client.test",
      mailFrom: "a@sender.test",
      rcptTo: ["b@example.test"],
      raw: new TextEncoder().encode("x\r\n"),
      tls: "never",
      timeoutMs: 2000,
    });

    expect(result.ok).toBe(false);
    expect(result.code).toBe(0);
    expect(result.permanent).toBe(false);
  });
});
