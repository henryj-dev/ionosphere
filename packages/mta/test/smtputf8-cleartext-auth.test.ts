/**
 * 발신 클라이언트의 두 게이트 — SMTPUTF8(RFC 6531)과 평문 회선 AUTH 금지.
 *
 * 둘 다 "우리가 광고하거나 인지하고 있는데 발신 경로만 몰랐다"는 형태였다:
 *  · 수신 엔진은 SMTPUTF8을 광고하고 파라미터를 파싱해 두면서 **쓰는 곳이 없었고**,
 *    발신 클라이언트는 상대의 광고를 보지도 파라미터를 붙이지도 않았다
 *  · `verifyPeer` 주석이 "스마트호스트는 AUTH PLAIN으로 자격증명을 실어 보낸다"고 위험을
 *    적어 뒀는데, STARTTLS가 실패해도 그대로 AUTH를 보냈다
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { sendSmtp } from "../src/smtp-client.ts";

let servers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => s.close()));
  servers = [];
});

/** TLS 미설정 서버 — STARTTLS를 광고하지 않고 SMTPUTF8은 엔진이 항상 광고한다. */
async function startPlain(): Promise<{ port: number; delivered: { mailFrom: string }[] }> {
  const delivered: { mailFrom: string }[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      delivered.push({ mailFrom: env.mailFrom });
      return { ok: true };
    },
    // AUTH를 광고시키기 위해 백엔드에 authenticate를 둔다(평문이라 엔진은 여전히 거부한다).
    authenticate: async () => ({ ok: true }),
  };
  const server = new SmtpServer({ hostname: "mx.test", maxSizeBytes: 1_000_000, backend, allowInsecureAuth: true });
  servers.push(server);
  return { port: await server.listen(0, "127.0.0.1"), delivered };
}

const RAW = new TextEncoder().encode("Subject: hi\r\n\r\nbody\r\n");

describe("평문 회선 AUTH 금지", () => {
  /**
   * ★막는 것은 **조용한 강등**이다 — 설정은 TLS를 말하는데 STARTTLS가 광고되지 않아
   * 실제로는 평문이 되는 경우. 자격증명을 흘리느니 늦게 보낸다(permanent=false).
   */
  test("opportunistic인데 STARTTLS가 없으면 AUTH를 보내지 않는다", async () => {
    const { port } = await startPlain();
    const r = await sendSmtp({
      host: "127.0.0.1",
      port,
      ehloName: "c.test",
      mailFrom: "a@x.test",
      rcptTo: ["b@y.test"],
      raw: RAW,
      tls: "opportunistic", // 상대가 STARTTLS를 광고하지 않으므로 평문으로 남는다
      auth: { user: "u", pass: "secret" },
    });
    expect(r.ok).toBe(false);
    expect(r.permanent).toBe(false); // 영구 실패로 굳히면 안 된다 — 상대 설정이 흔들린 것일 수 있다
    expect(r.message).toContain("cleartext");
  });

  /**
   * ★`never`는 막지 않는다 — 운영자가 **명시적으로 고른** 구성이고(smarthosts.tls_mode)
   * 루프백·신뢰된 사설 링크에는 합리적일 수 있다. 여기서 닫으려는 것은 그 선택이 아니다.
   */
  test("tls:never는 명시적 선택이므로 AUTH가 나간다", async () => {
    const { port } = await startPlain();
    const r = await sendSmtp({
      host: "127.0.0.1", port, ehloName: "c.test",
      mailFrom: "a@x.test", rcptTo: ["b@y.test"], raw: RAW, tls: "never",
      auth: { user: "u", pass: "p" },
    });
    // 상대 백엔드가 인증을 수락하므로 발송까지 간다 — 게이트에 걸리지 않았다는 뜻이다.
    expect(r.message).not.toContain("cleartext");
  });

  test("auth를 안 주면 평문이어도 정상 발송한다(기존 동작)", async () => {
    const { port, delivered } = await startPlain();
    const r = await sendSmtp({
      host: "127.0.0.1", port, ehloName: "c.test",
      mailFrom: "a@x.test", rcptTo: ["b@y.test"], raw: RAW, tls: "never",
    });
    expect(r.ok).toBe(true);
    expect(delivered).toHaveLength(1);
  });
});

describe("SMTPUTF8 (RFC 6531)", () => {
  test("비ASCII 봉투 주소는 SMTPUTF8을 광고하는 상대에게 나간다", async () => {
    const { port, delivered } = await startPlain(); // 엔진은 SMTPUTF8을 항상 광고한다
    const r = await sendSmtp({
      host: "127.0.0.1", port, ehloName: "c.test",
      mailFrom: "보낸이@x.test", rcptTo: ["받는이@y.test"], raw: RAW, tls: "never",
    });
    expect(r.ok).toBe(true);
    expect(delivered[0]!.mailFrom).toBe("보낸이@x.test");
  });

  test("ASCII 주소는 SMTPUTF8을 붙이지 않는다(기존 동작 불변)", async () => {
    const { port, delivered } = await startPlain();
    const r = await sendSmtp({
      host: "127.0.0.1", port, ehloName: "c.test",
      mailFrom: "a@x.test", rcptTo: ["b@y.test"], raw: RAW, tls: "never",
    });
    expect(r.ok).toBe(true);
    expect(delivered[0]!.mailFrom).toBe("a@x.test");
  });

  /**
   * ★상대가 미지원이면 **영구 실패**다. 주소 자체가 그 경로로는 표현될 수 없으므로 재시도해도
   * 같고, RFC 6531 §3.2의 다운그레이드(ASCII 대체 주소)는 우리가 가진 정보로 만들 수 없다 —
   * 없는 주소를 지어내는 것보다 정직하게 실패하는 편이 낫다.
   */
  test("미지원 상대에게는 raw UTF-8을 흘리지 않고 영구 실패한다", async () => {
    // SMTPUTF8을 광고하지 않는 상대를 흉내낸다 — 최소 SMTP 응답만 하는 서버.
    const { createServer } = await import("node:net");
    const srv = createServer((sock) => {
      sock.write("220 legacy.test ESMTP\r\n");
      sock.on("data", (d) => {
        const line = d.toString("latin1");
        if (line.startsWith("EHLO")) sock.write("250-legacy.test\r\n250 8BITMIME\r\n");
        else if (line.startsWith("QUIT")) sock.end("221 bye\r\n");
        else sock.write("250 ok\r\n");
      });
    });
    const port = await new Promise<number>((res) => srv.listen(0, "127.0.0.1", () => {
      const a = srv.address();
      res(typeof a === "object" && a !== null ? a.port : 0);
    }));

    const r = await sendSmtp({
      host: "127.0.0.1", port, ehloName: "c.test",
      mailFrom: "보낸이@x.test", rcptTo: ["b@y.test"], raw: RAW, tls: "never",
    });
    srv.close();

    expect(r.ok).toBe(false);
    expect(r.permanent).toBe(true);
    expect(r.message).toContain("SMTPUTF8");
  });
});
