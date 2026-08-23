/**
 * DANE 발송 경로 — TLSA 고정이 **실제 소켓 위에서** 성립하는지.
 *
 * `mail-auth/test/dane.test.ts`는 대조 함수를 본다. 여기서 보는 것은 배선이다:
 * 진짜 TLS 핸드셰이크에서 뽑은 인증서가 TLSA와 맞는가, 안 맞으면 **정말 배달을 멈추는가**,
 * 그리고 TLSA가 있으면 TLS가 **필수가 되는가**.
 *
 * 픽스처는 proto-smtp의 자체서명 인증서다 — DANE를 쓰는 MX 상당수가 자체서명이라
 * 조건이 현실과 같다(공개 CA 사슬 없음 → PKIX로는 절대 통과 못 함 → TLSA만이 근거).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, TLSSocket as TLSSocketCtor, type Server } from "node:tls";
import { createServer as netCreateServer, type Server as NetServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sendSmtp } from "../src/smtp-client.ts";
import { TLSA_MATCHING, TLSA_SELECTOR, TLSA_USAGE, type DaneTlsaSet } from "@ionosphere/mail-auth";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "../../proto-smtp/test/fixtures");
const cert = readFileSync(join(fixtures, "cert.pem"));
const key = readFileSync(join(fixtures, "key.pem"));

/** 상대가 실제로 제시할 인증서의 SPKI 해시 — TLSA에 게시됐어야 할 값. */
const SPKI_SHA256 = new Uint8Array(
  createHash("sha256")
    .update(new X509Certificate(cert).publicKey.export({ format: "der", type: "spki" }))
    .digest(),
);

function tlsaSet(data: Uint8Array, over: Partial<DaneTlsaSet> = {}): DaneTlsaSet {
  return {
    records: [{ usage: TLSA_USAGE.DANE_EE, selector: TLSA_SELECTOR.SPKI, matchingType: TLSA_MATCHING.SHA256, data }],
    dnssecValidated: true,
    ...over,
  };
}

let servers: Server[] = [];
let plainServers: NetServer[] = [];
afterEach(async () => {
  await Promise.all([
    ...servers.map((s) => new Promise<void>((r) => s.close(() => r()))),
    ...plainServers.map((s) => new Promise<void>((r) => s.close(() => r()))),
  ]);
  servers = [];
  plainServers = [];
});

/** 배달까지 끝나는 최소 암시적 TLS SMTP 서버. */
async function tlsSmtpServer(): Promise<number> {
  const server = createServer({ key, cert }, (socket) => {
    let inData = false;
    socket.write("220 dane.test ESMTP\r\n");
    socket.on("data", (chunk: Buffer) => {
      for (const line of chunk.toString("utf8").split("\r\n")) {
        if (inData) {
          if (line === ".") {
            inData = false;
            socket.write("250 queued\r\n");
          }
          continue;
        }
        if (!line) continue;
        if (/^EHLO/i.test(line)) socket.write("250 dane.test\r\n");
        else if (/^DATA/i.test(line)) {
          inData = true;
          socket.write("354 go\r\n");
        } else if (/^QUIT/i.test(line)) socket.end("221 bye\r\n");
        else socket.write("250 ok\r\n");
      }
    });
    socket.on("error", () => {
      /* 클라이언트가 DANE 불일치로 끊는 것이 정상 경로다 */
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  return typeof addr === "object" && addr !== null ? addr.port : 0;
}

/**
 * STARTTLS로 승격하는 SMTP 서버 — **실제 MX 배달이 타는 경로**다.
 *
 * implicit(465)만 테스트하면 25번 직송의 DANE 검사가 무커버리지로 남는다. 서버측 업그레이드
 * (`new TLSSocket({isServer:true})`)는 과거 bun에서 멈추던 자리라 파일 머리말에 경고가 있지만,
 * 이 저장소는 2026-08-02부터 Node 전용이라 그 제약이 없다.
 */
async function starttlsSmtpServer(): Promise<number> {
  const server = netCreateServer((socket) => {
    let inData = false;
    const wire = (s: NodeJS.ReadWriteStream & { write(b: string): boolean }): void => {
      s.on("data", (chunk: Buffer) => {
        for (const line of chunk.toString("utf8").split("\r\n")) {
          if (inData) {
            if (line === ".") {
              inData = false;
              s.write("250 queued\r\n");
            }
            continue;
          }
          if (!line) continue;
          if (/^EHLO/i.test(line)) s.write("250-starttls.test\r\n250 STARTTLS\r\n");
          else if (/^STARTTLS/i.test(line)) {
            s.write("220 go ahead\r\n");
            const tls = new TLSSocketCtor(socket, { isServer: true, key, cert });
            // 승격 뒤에는 평문 소켓의 리스너가 아니라 TLS 소켓의 리스너가 받아야 한다.
            socket.removeAllListeners("data");
            tls.on("error", () => {});
            wire(tls as unknown as NodeJS.ReadWriteStream & { write(b: string): boolean });
            return;
          } else if (/^DATA/i.test(line)) {
            inData = true;
            s.write("354 go\r\n");
          } else if (/^QUIT/i.test(line)) s.write("221 bye\r\n");
          else s.write("250 ok\r\n");
        }
      });
    };
    socket.write("220 starttls.test ESMTP\r\n");
    wire(socket);
    socket.on("error", () => {});
  });
  plainServers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  return typeof addr === "object" && addr !== null ? addr.port : 0;
}

/** STARTTLS를 광고하지 않는 평문 서버 — 다운그레이드 시도 상대. */
async function plaintextSmtpServer(): Promise<number> {
  const server = netCreateServer((socket) => {
    socket.write("220 plain.test ESMTP\r\n");
    socket.on("data", (chunk: Buffer) => {
      for (const line of chunk.toString("utf8").split("\r\n").filter(Boolean)) {
        if (/^EHLO/i.test(line)) socket.write("250 plain.test\r\n");
        else if (/^QUIT/i.test(line)) socket.end("221 bye\r\n");
        else socket.write("250 ok\r\n");
      }
    });
    socket.on("error", () => {});
  });
  plainServers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  return typeof addr === "object" && addr !== null ? addr.port : 0;
}

/**
 * TLS 상대는 "localhost"로 붙는다 — node가 SNI servername에 IP를 허용하지 않기 때문이고,
 * 픽스처 인증서의 CN도 localhost다. 평문 서버는 그 제약이 없어 127.0.0.1 그대로 쓴다.
 */
const baseOpts = {
  ehloName: "mx.test",
  mailFrom: "a@test.local",
  rcptTo: ["b@remote.test"],
  raw: new TextEncoder().encode("Subject: hi\r\n\r\nbody\r\n"),
  timeoutMs: 5000,
};

describe("DANE 발송", () => {
  test("★TLSA와 맞으면 배달된다 — 공개 CA 사슬이 없어도", async () => {
    // PKIX로는 절대 통과 못 하는 자체서명이다. 통과했다면 근거는 TLSA뿐이다.
    const port = await tlsSmtpServer();
    const res = await sendSmtp({ ...baseOpts, host: "localhost", port, tls: "implicit", dane: tlsaSet(SPKI_SHA256) });

    expect(res.ok).toBe(true);
    expect(res.dane).toBe("match");
  });

  test("★TLSA와 다르면 배달하지 않는다 — 중간자 신호", async () => {
    const port = await tlsSmtpServer();
    const wrong = new Uint8Array(SPKI_SHA256);
    wrong[0] = (wrong[0]! ^ 0xff) & 0xff; // 한 바이트만 다르다
    const res = await sendSmtp({ ...baseOpts, host: "localhost", port, tls: "implicit", dane: tlsaSet(wrong) });

    expect(res.ok).toBe(false);
    expect(res.dane).toBe("mismatch");
    // ★영구 실패로 굳히지 않는다 — 굳히면 잠깐 끼어든 공격자가 정상 메일을 죽일 수 있다.
    expect(res.permanent).toBe(false);
    expect(res.message).toContain("DANE mismatch");
  });

  test("★DNSSEC 미검증 TLSA는 PKIX를 끄지 못한다", async () => {
    // 검증되지 않은 TLSA로 rejectUnauthorized가 꺼지면, DNS를 속인 공격자가 우리의
    // 인증서 검증을 **없애는** 데 TLSA를 쓸 수 있다. 그 경로가 없어야 한다.
    const port = await tlsSmtpServer();
    const res = await sendSmtp({
      ...baseOpts,
      host: "localhost",
      port,
      tls: "implicit",
      dane: tlsaSet(SPKI_SHA256, { dnssecValidated: false }),
    });

    expect(res.ok).toBe(false);
    expect(res.dane).toBeUndefined();
    expect(res.message).toMatch(/self.?signed|certificate|altnames/i);
  });

  test("★TLSA가 있으면 TLS는 필수가 된다 — opportunistic이어도", async () => {
    // 상대가 TLSA를 게시했는데 STARTTLS를 안 준다 = 다운그레이드. 평문으로 흘리면 안 된다.
    const port = await plaintextSmtpServer();
    const res = await sendSmtp({ ...baseOpts, host: "127.0.0.1", port, tls: "opportunistic", dane: tlsaSet(SPKI_SHA256) });

    expect(res.ok).toBe(false);
    expect(res.permanent).toBe(false);
    expect(res.message).toContain("STARTTLS required");
  });

  test("★STARTTLS 승격 뒤에도 대조한다 — 25번 직송이 타는 경로", async () => {
    const port = await starttlsSmtpServer();
    const res = await sendSmtp({ ...baseOpts, host: "localhost", port, tls: "opportunistic", dane: tlsaSet(SPKI_SHA256) });

    expect(res.ok).toBe(true);
    expect(res.dane).toBe("match");
  });

  test("★STARTTLS 승격 뒤 불일치면 배달하지 않는다", async () => {
    const port = await starttlsSmtpServer();
    const wrong = new Uint8Array(SPKI_SHA256);
    wrong[31] = (wrong[31]! ^ 0xff) & 0xff;
    const res = await sendSmtp({ ...baseOpts, host: "localhost", port, tls: "opportunistic", dane: tlsaSet(wrong) });

    expect(res.ok).toBe(false);
    expect(res.dane).toBe("mismatch");
    expect(res.permanent).toBe(false);
  });

  test("이해할 수 없는 TLSA뿐이면 평소대로 진행한다(TLS 강제 없음)", async () => {
    // usage 0(PKIX-TA)은 SMTP에서 무시한다. 무시한 결과가 "TLS 강제"면 상대가 게시한
    // 무의미한 레코드 하나로 배달이 막힌다.
    const port = await plaintextSmtpServer();
    const res = await sendSmtp({
      ...baseOpts,
      host: "127.0.0.1",
      port,
      tls: "opportunistic",
      dane: tlsaSet(SPKI_SHA256, {
        records: [
          { usage: TLSA_USAGE.PKIX_TA, selector: TLSA_SELECTOR.SPKI, matchingType: TLSA_MATCHING.SHA256, data: SPKI_SHA256 },
        ],
      }),
    });

    // 평문 서버가 전부 250을 주므로 배달은 성립한다 — 강제가 걸리지 않았다는 증거.
    expect(res.message).not.toContain("STARTTLS required");
    expect(res.dane).toBeUndefined();
  });
});
