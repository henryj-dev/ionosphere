/**
 * 바이러스 검사 훅 조립 검증 — 훅이 실제 수신 경로에 걸리는지.
 *
 * 판정 자체의 계약은 `packages/spam/test/virus.test.ts`가 덮는다. 여기서 보는 것은
 * ① 스캐너를 안 주면 **아무 일도 일어나지 않는다**(기본 비활성)
 * ② 감염 판정이 SMTP 응답 554로 나온다
 * ③ 판정 불가가 451이라 **상대가 재시도한다**(메일이 사라지지 않는다)
 * ④ 스캐너가 **원본 바이트**를 받는다 — 우리가 헤더를 얹기 전 것이어야 서명이 맞는다
 */
import { afterAll, beforeAll, describe, expect, test, SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DnsNotFoundError, type DnsResolver } from "@ionosphere/mail-auth";
import type { VirusScanner } from "@ionosphere/spam";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS } from "./helpers.ts";

function offline(): DnsResolver {
  const nf = (): never => {
    throw new DnsNotFoundError("none");
  };
  return { txt: async () => nf(), mx: async () => nf(), a: async () => nf(), aaaa: async () => nf(), ptr: async () => nf() };
}

/** relay(25) 경로로 한 통 보내고 마지막 응답 줄을 돌려준다. */
function relaySend(port: number, from: string, to: string, body = "hi"): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const msg = `From: ${from}\r\nTo: ${to}\r\nSubject: av\r\n\r\n${body}\r\n.\r\n`;
    const steps = [`EHLO t\r\n`, `MAIL FROM:<${from}>\r\n`, `RCPT TO:<${to}>\r\n`, `DATA\r\n`, msg];
    let stage = -1;
    let buf = "";
    const t = setTimeout(() => {
      s.destroy();
      reject(new Error("timeout"));
    }, SOCKET_DEADLINE_MS);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (line.startsWith("250-")) continue;
        if (line.startsWith("4") || line.startsWith("5")) {
          clearTimeout(t);
          s.write("QUIT\r\n");
          s.destroy();
          resolve(line);
          return;
        }
        if (stage === steps.length - 1) {
          clearTimeout(t);
          s.write("QUIT\r\n");
          s.destroy();
          resolve(line);
          return;
        }
        stage++;
        s.write(steps[stage]!);
      }
    });
    s.on("error", reject);
  });
}

/** 본문에 표식이 있으면 감염으로 보는 가짜 스캐너 — 받은 바이트도 기록한다. */
function markerScanner(marker: string): VirusScanner & { seen: string[] } {
  const seen: string[] = [];
  return {
    seen,
    async scan(raw: Uint8Array) {
      const text = new TextDecoder().decode(raw);
      seen.push(text);
      return text.includes(marker)
        ? { verdict: "infected" as const, signature: "Test-Marker" }
        : { verdict: "clean" as const };
    },
  };
}

async function startApp(extra: Record<string, unknown>): Promise<{ app: IonosphereApp; root: string }> {
  const root = mkdtempSync(join(tmpdir(), "ionosphere-av-"));
  const app = new IonosphereApp({
    hostname: "mx.test",
    dbPath: ":memory:",
    blobRoot: root,
    smtpPort: 0,
    pop3Port: 0,
    resolver: offline(),
    runMtaWorker: false,
    ...extra,
  });
  await app.start();
  await app.createUser("rcpt@mx.test", "pw");
  return { app, root };
}

describe("바이러스 검사 훅 조립", () => {
  let scanner: VirusScanner & { seen: string[] };
  let app: IonosphereApp;
  let root: string;

  beforeAll(async () => {
    scanner = markerScanner("XX-BAD-XX");
    ({ app, root } = await startApp({ virusScanner: scanner }));
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(root, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("깨끗하면 그대로 받는다", async () => {
    expect(await relaySend(app.smtpPort, "a@ext.test", "rcpt@mx.test", "normal body")).toStartWith("250");
  });

  test("★감염 판정 → 554로 거부하고 시그니처 이름을 싣는다", async () => {
    const r = await relaySend(app.smtpPort, "a@ext.test", "rcpt@mx.test", "XX-BAD-XX");
    expect(r).toStartWith("554");
    expect(r).toContain("Test-Marker");
  });

  test("★스캐너는 우리가 헤더를 얹기 전 **원본**을 본다", async () => {
    scanner.seen.length = 0;
    await relaySend(app.smtpPort, "a@ext.test", "rcpt@mx.test", "plain");
    const seen = scanner.seen.at(-1) ?? "";
    expect(seen).toContain("plain");
    // Received·Authentication-Results는 이 게이트 **뒤에** 붙는다. 스캐너가 우리 헤더가
    // 얹힌 바이트를 보면 첨부 서명·해시가 원본과 달라져 오탐/미탐의 원인이 된다.
    expect(seen).not.toContain("Authentication-Results:");
    expect(seen.startsWith("Received:")).toBe(false);
  });
});

describe("바이러스 검사 훅 — 판정 불가", () => {
  test("★451로 defer한다 — 스캐너 장애가 메일을 버리지 않는다", async () => {
    const broken: VirusScanner = {
      scan: async () => {
        throw new Error("scanner down");
      },
    };
    const { app, root } = await startApp({ virusScanner: broken });
    try {
      const r = await relaySend(app.smtpPort, "a@ext.test", "rcpt@mx.test");
      expect(r).toStartWith("451");
    } finally {
      await app.stop();
      rmSync(root, { recursive: true, force: true });
    }
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("바이러스 검사 훅 — 기본 비활성", () => {
  test("스캐너를 안 주면 아무 일도 일어나지 않는다", async () => {
    const { app, root } = await startApp({});
    try {
      // 감염 표식이 들어 있어도 그대로 받는다 — 훅이 없으면 게이트 자체가 없다.
      expect(await relaySend(app.smtpPort, "a@ext.test", "rcpt@mx.test", "XX-BAD-XX")).toStartWith("250");
    } finally {
      await app.stop();
      rmSync(root, { recursive: true, force: true });
    }
  }, E2E_HOOK_TIMEOUT_MS);
});
