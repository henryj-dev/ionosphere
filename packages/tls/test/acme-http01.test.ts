/**
 * ACME http-01 — 리스너와 클라이언트를 **실제 HTTP로 맞물려** 확인한다.
 *
 * ★왜 목이 아니라 실제 소켓인가: http-01의 핵심 규격은 "본문이 key authorization **원문**"
 * (RFC 8555 §8.3)인데, `HttpChallengeResponder`를 목으로 두고 `set()` 호출만 보면 그 값이 실제로
 * 어떤 바이트로 서빙되는지 확인하지 못한다. dns-01처럼 해시해 올려도 목 테스트는 통과한다.
 * 그래서 여기서는 목 CA가 **자기가 만든 토큰으로 진짜 GET을 날려** 응답 본문을 검증한다.
 * 이게 없으면 "서명이 있다"를 "검증 통과"로 읽는 것과 같은 종류의 착각이 남는다.
 */
import { afterAll, describe, expect, test } from "@ionosphere/testkit";
import { createHash, createPrivateKey } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ACME_HTTP_PREFIX,
  acmeCertSource,
  generateAccountKey,
  generateSelfSigned,
  httpChallengeServer,
  jwkThumbprint,
  publicJwk,
  requestCertificate,
} from "../src/index.ts";

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-acme-http-"));
  dirs.push(d);
  return d;
}

const TOKEN = "tok-http-01-abc";

/**
 * 목 CA — 챌린지 응답(POST /chal/1)을 받으면 `challengeBase`로 **실제 GET**을 보내
 * 본문이 `<token>.<thumbprint>`인지 검사한다. 틀리면 authz를 invalid로 돌린다(진짜 CA와 같은 방향).
 */
function mockHttp01Ca(challengeBase: string, accountKeyPem: string, certPem: string) {
  const BASE = "https://acme.mock";
  const expected = `${TOKEN}.${jwkThumbprint(publicJwk(accountKeyPem))}`;
  let nonce = 0;
  let authzValid = false;
  let finalized = false;
  const fetched: { status: number; body: string }[] = [];

  const headers = (extra: Record<string, string> = {}) => new Headers({ "replay-nonce": `nonce-${nonce++}`, ...extra });
  const json = (status: number, body: unknown, extra?: Record<string, string>) => {
    const h = headers(extra);
    h.set("content-type", "application/json");
    return new Response(JSON.stringify(body), { status, headers: h });
  };

  const f = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.endsWith("/directory")) return json(200, { newNonce: `${BASE}/nonce`, newAccount: `${BASE}/acct`, newOrder: `${BASE}/order` });
    if (url.endsWith("/nonce")) return new Response(null, { status: 200, headers: headers() });
    if (url.endsWith("/acct")) return json(201, { status: "valid" }, { location: `${BASE}/acct/1` });
    if (url.endsWith("/order") && method === "POST") {
      return json(201, { status: "pending", authorizations: [`${BASE}/authz/1`], finalize: `${BASE}/finalize` }, { location: `${BASE}/order/1` });
    }
    if (url.endsWith("/authz/1")) {
      return json(200, {
        identifier: { value: "mx.test.local" },
        status: authzValid ? "valid" : "pending",
        // 진짜 CA처럼 두 종류를 함께 준다 — 클라이언트가 http-01을 **골라내는지**까지 확인된다.
        challenges: [
          { type: "dns-01", url: `${BASE}/chal-dns/1`, token: "tok-dns" },
          { type: "http-01", url: `${BASE}/chal/1`, token: TOKEN },
        ],
      });
    }
    if (url.endsWith("/chal/1")) {
      // ★CA 검증 시늉이 아니라 실제 GET — 리스너가 열려 있고 본문이 규격대로여야 통과한다.
      const res = await fetch(`${challengeBase}${ACME_HTTP_PREFIX}${TOKEN}`);
      const body = await res.text();
      fetched.push({ status: res.status, body });
      authzValid = res.status === 200 && body === expected;
      return json(200, { type: "http-01", status: authzValid ? "valid" : "invalid", url: `${BASE}/chal/1` });
    }
    if (url.endsWith("/finalize")) {
      finalized = true;
      return json(200, { status: "processing" });
    }
    if (url.endsWith("/order/1")) return json(200, finalized ? { status: "valid", certificate: `${BASE}/cert/1` } : { status: "processing" });
    if (url.endsWith("/cert/1")) {
      const h = headers();
      h.set("content-type", "application/pem-certificate-chain");
      return new Response(certPem, { status: 200, headers: h });
    }
    return new Response("not found", { status: 404, headers: headers() });
  }) as unknown as typeof fetch;

  return { fetch: f, fetched, expected };
}

describe("http-01 챌린지 리스너", () => {
  test("등록된 토큰만 200 + 본문은 keyAuthorization 원문", async () => {
    const server = httpChallengeServer({ port: 0, host: "127.0.0.1" });
    const port = await server.listen();
    try {
      await server.set("abc", "abc.thumb");
      const ok = await fetch(`http://127.0.0.1:${port}${ACME_HTTP_PREFIX}abc`);
      expect(ok.status).toBe(200);
      expect(await ok.text()).toBe("abc.thumb");
      // ★해시가 아니라 원문이어야 한다(RFC 8555 §8.3) — dns-01 값과 다름을 못 박는다.
      expect(await (await fetch(`http://127.0.0.1:${port}${ACME_HTTP_PREFIX}abc`)).text()).not.toBe(
        createHash("sha256").update("abc.thumb").digest("base64url"),
      );

      // 미등록 토큰·다른 경로·다른 메서드는 전부 404 (표면을 좁게 유지)
      expect((await fetch(`http://127.0.0.1:${port}${ACME_HTTP_PREFIX}nope`)).status).toBe(404);
      expect((await fetch(`http://127.0.0.1:${port}/`)).status).toBe(404);
      expect((await fetch(`http://127.0.0.1:${port}/etc/passwd`)).status).toBe(404);
      expect((await fetch(`http://127.0.0.1:${port}${ACME_HTTP_PREFIX}abc`, { method: "POST" })).status).toBe(404);

      // 쿼리스트링이 붙어도 토큰을 찾아야 한다(경로만 보고 자르는지)
      expect((await fetch(`http://127.0.0.1:${port}${ACME_HTTP_PREFIX}abc?x=1`)).status).toBe(200);

      // remove 후에는 사라진다 — 발급이 끝난 뒤 값이 남아 있으면 안 된다
      await server.remove("abc");
      expect((await fetch(`http://127.0.0.1:${port}${ACME_HTTP_PREFIX}abc`)).status).toBe(404);
    } finally {
      await server.close();
    }
  });

  test("close가 등록분을 비운다 (재기동 시 낡은 토큰이 남지 않는다)", async () => {
    const server = httpChallengeServer({ port: 0, host: "127.0.0.1" });
    const p1 = await server.listen();
    await server.set("t1", "t1.x");
    await server.close();
    // 닫힌 뒤 그 포트로는 아예 못 붙는다
    await expect(fetch(`http://127.0.0.1:${p1}${ACME_HTTP_PREFIX}t1`)).rejects.toThrow();
    const p2 = await server.listen();
    try {
      expect((await fetch(`http://127.0.0.1:${p2}${ACME_HTTP_PREFIX}t1`)).status).toBe(404);
    } finally {
      await server.close();
    }
  });

  test("토큰 형식이 아니면 set이 거부한다 (base64url만)", async () => {
    const server = httpChallengeServer({ port: 0, host: "127.0.0.1" });
    await expect(server.set("../../etc/passwd", "x")).rejects.toThrow(/토큰 형식/);
    await expect(server.set("", "x")).rejects.toThrow(/토큰 형식/);
  });
});

describe("requestCertificate (목 CA가 실제 GET으로 검증하는 http-01)", () => {
  test("발급 성공 — CA가 받은 본문이 keyAuthorization 원문", async () => {
    const server = httpChallengeServer({ port: 0, host: "127.0.0.1" });
    const port = await server.listen();
    try {
      const accountKeyPem = generateAccountKey();
      const certPem = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] }).certPem;
      const ca = mockHttp01Ca(`http://127.0.0.1:${port}`, accountKeyPem, certPem);
      const result = await requestCertificate(
        {
          directoryUrl: "https://acme.mock/directory",
          accountKeyPem,
          challenge: { type: "http-01", http: server },
          fetch: ca.fetch,
          pollIntervalMs: 5,
          pollMaxTries: 20,
        },
        ["mx.test.local"],
      );
      expect(result.certPem).toBe(certPem);
      expect(() => createPrivateKey(result.keyPem)).not.toThrow();
      expect(ca.fetched).toEqual([{ status: 200, body: ca.expected }]);
    } finally {
      await server.close();
    }
  });

  /**
   * dns-01은 TXT 전파를 기다려야 하지만 http-01은 게시가 곧 유효하다. 기본 15초를 그대로 두면
   * 발급마다 이유 없이 15초씩 늘어나므로 http-01 경로에서는 대기를 건너뛴다.
   */
  test("http-01은 dnsPropagationMs를 기다리지 않는다", async () => {
    const server = httpChallengeServer({ port: 0, host: "127.0.0.1" });
    const port = await server.listen();
    try {
      const accountKeyPem = generateAccountKey();
      const certPem = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] }).certPem;
      const ca = mockHttp01Ca(`http://127.0.0.1:${port}`, accountKeyPem, certPem);
      const started = Date.now();
      await requestCertificate(
        {
          directoryUrl: "https://acme.mock/directory",
          accountKeyPem,
          challenge: { type: "http-01", http: server },
          fetch: ca.fetch,
          dnsPropagationMs: 30_000, // 지켜졌다면 이 테스트가 타임아웃으로 죽는다
          pollIntervalMs: 5,
        },
        ["mx.test.local"],
      );
      expect(Date.now() - started).toBeLessThan(5_000);
    } finally {
      await server.close();
    }
  });

  /**
   * `open`/`close` 훅 — 80포트를 상시 점유하지 않기 위한 장치다. 발급 전에 열리고,
   * **실패해도** 닫혀야 한다(닫히지 않으면 다음 갱신이 EADDRINUSE로 죽는다).
   */
  test("open/close 훅이 발급 전후로 불린다 — 실패 경로에서도 닫힌다", async () => {
    const server = httpChallengeServer({ port: 0, host: "127.0.0.1" });
    const calls: string[] = [];
    const failing = (async () => new Response("boom", { status: 500 })) as unknown as typeof fetch;
    await expect(
      requestCertificate(
        {
          directoryUrl: "https://acme.mock/directory",
          accountKeyPem: generateAccountKey(),
          challenge: {
            type: "http-01",
            http: server,
            open: async () => void calls.push("open"),
            close: async () => void calls.push("close"),
          },
          fetch: failing,
        },
        ["mx.test.local"],
      ),
    ).rejects.toThrow();
    expect(calls).toEqual(["open", "close"]);
  });

  test("acmeCertSource가 http-01 challenge로 조립된다 (dns 프로바이더 없이)", () => {
    expect(() =>
      acmeCertSource({
        domains: ["mx.test.local"],
        directoryUrl: "https://acme.mock/directory",
        challenge: { type: "http-01", http: httpChallengeServer({ port: 0 }) },
        dir: tmp(),
      }),
    ).not.toThrow();
  });
});
