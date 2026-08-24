/**
 * HTTP 리스너 하드닝(감사 L-3) + MTA-STS 페치 하드닝(L-8).
 *
 * L-3의 요지: 메일 리스너 6종은 전부 `MAX_LISTENER_CONNECTIONS`를 걸고 있었는데 HTTP 리스너
 * 4종(443 프론트·관리 API·autoconfig·metrics)에는 연결 수 상한도 타임아웃도 **하나도 없었다**.
 * 그중 443은 MTA-STS 정책 배포 때문에 방화벽으로 막을 수 없는 공개 표면이고, 전 프로토콜이
 * 단일 프로세스라 slowloris로 fd가 마르면 25·587·993이 함께 죽는다.
 *
 * 값이 아니라 **걸려 있는지**를 본다 — 값은 limits.ts가 소유하므로 여기서 다시 못박으면
 * 튜닝할 때마다 두 곳을 고쳐야 한다. 빠지는 사고를 잡는 것이 이 테스트의 목적이다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HTTP_HEADERS_TIMEOUT_MS, HTTP_REQUEST_TIMEOUT_MS, MAX_LISTENER_CONNECTIONS } from "@ionosphere/core";
import { fetchMtaStsPolicy, IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "../../../packages/proto-smtp/test/fixtures");
const imapsTls = { key: readFileSync(join(fixtures, "key.pem")), cert: readFileSync(join(fixtures, "cert.pem")) };

const running: { app: IonosphereApp; blobRoot: string }[] = [];

afterEach(async () => {
  for (const r of running.splice(0)) {
    await r.app.stop();
    rmSync(r.blobRoot, { recursive: true, force: true });
  }
});

async function startApp(extra: Partial<ConstructorParameters<typeof IonosphereApp>[0]>): Promise<IonosphereApp> {
  const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-harden-"));
  const app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    resolver: offlineResolver(),
    runMtaWorker: false,
    runWebhookWorker: false,
    runReaper: false,
    blobGcMode: "off",
    ...extra,
  });
  await app.start();
  running.push({ app, blobRoot });
  return app;
}

/** 리스너 래퍼가 들고 있는 실제 서버 객체 — 하드닝은 여기에 걸린다. */
interface Hardened {
  maxConnections?: number;
  headersTimeout?: number;
  requestTimeout?: number;
}
function serverOf(holder: unknown): Hardened {
  return (holder as { server: Hardened }).server;
}

function expectHardened(server: Hardened | undefined, label: string): void {
  expect(server, label).toBeDefined();
  expect(server!.maxConnections, `${label}: maxConnections`).toBe(MAX_LISTENER_CONNECTIONS);
  expect(server!.headersTimeout, `${label}: headersTimeout`).toBe(HTTP_HEADERS_TIMEOUT_MS);
  expect(server!.requestTimeout, `${label}: requestTimeout`).toBe(HTTP_REQUEST_TIMEOUT_MS);
}

describe("HTTP 리스너 하드닝", () => {
  test("metrics·autoconfig·jmap·443 프론트·관리 API에 상한과 타임아웃이 걸린다", async () => {
    const app = await startApp({
      metricsPort: 0,
      autoconfigPort: 0,
      jmapPort: 0,
      httpsFrontPort: 0,
      adminPort: 0,
      adminRootToken: "t",
      imapsTls,
    });
    const peek = app as unknown as Record<string, unknown>;

    expect(app.httpsFrontPort).toBeGreaterThan(0); // 443 프론트가 실제로 떴는지 먼저 확인
    expectHardened(serverOf(peek["metricsServer"]), "metrics");
    expectHardened(serverOf(peek["autoconfig"]), "autoconfig");
    expectHardened(serverOf(peek["jmap"]), "jmap");
    expectHardened(serverOf(peek["httpsFront"]), "https-front");
    // 관리 API는 rootToken 하나가 전 테넌트 권한이라 연결 고갈에 특히 민감하다.
    expectHardened(serverOf(peek["admin"]), "admin");
  }, E2E_HOOK_TIMEOUT_MS);

  /**
   * 인증서 교체는 bun에서 리스너를 재생성한다(node는 setSecureContext). 재생성 경로에서
   * 하드닝이 빠지면 갱신 뒤부터 조용히 무방비가 되고, 그 사실은 90일 뒤에나 드러난다.
   */
  test("인증서 교체 뒤에도 443 프론트에 그대로 걸려 있다", async () => {
    const app = await startApp({ jmapPort: 0, httpsFrontPort: 0, imapsTls });
    const front = (app as unknown as Record<string, unknown>)["httpsFront"] as { reloadTls(m: typeof imapsTls): Promise<void> };

    await front.reloadTls(imapsTls);

    expectHardened(serverOf(front), "https-front(재생성 후)");
  }, E2E_HOOK_TIMEOUT_MS);

  /** 하드닝 전 기본값과 실제로 다른지 — 같으면 이 테스트는 아무것도 안 지키는 셈이다. */
  test("node 기본 headersTimeout보다 짧다", () => {
    const bare = createHttpServer();
    expect(HTTP_HEADERS_TIMEOUT_MS).toBeLessThan(bare.headersTimeout);
    bare.close();
  });
});

/**
 * MTA-STS 정책 페치(감사 L-8) — RFC 8461 §3.3.
 *
 * 정책의 신뢰 근거는 "`mta-sts.<도메인>`의 유효한 인증서로 받았다"는 사실 하나뿐이다.
 * 리다이렉트를 따라가면 그 근거가 상대가 지정한 아무 호스트로 옮겨간다(http:// 다운그레이드,
 * 사설 대역 SSRF). 본문 상한이 없으면 큐 워커가 상대가 흘려보내는 만큼 메모리를 문다.
 */
describe("MTA-STS 페치", () => {
  const servers: ReturnType<typeof createHttpServer>[] = [];
  afterEach(() => {
    for (const s of servers.splice(0)) s.close();
  });

  test("https가 아니면 페치조차 하지 않는다", async () => {
    await expect(fetchMtaStsPolicy("http://mta-sts.example.test/.well-known/mta-sts.txt")).rejects.toThrow(/https/);
  });

  test("3xx는 따라가지 않고 실패한다", async () => {
    // 평문 서버로 충분하다 — 위 https 가드보다 **뒤**의 분기를 보기 위해 URL 검사만 우회한다.
    let followed = false;
    const server = createHttpServer((req, res) => {
      if (req.url === "/redirected") {
        followed = true;
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: 86400\n");
        return;
      }
      res.writeHead(302, { location: "/redirected" });
      res.end();
    });
    servers.push(server);
    const port = await listen(server);

    await expect(fetchViaHttp(`http://127.0.0.1:${port}/.well-known/mta-sts.txt`)).rejects.toThrow(/리다이렉트/);
    expect(followed).toBe(false); // 두 번째 요청 자체가 없어야 한다
  });

  test("거대한 본문은 상한에서 거절된다", async () => {
    const server = createHttpServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      // Content-Length를 안 준다 — 상한이 헤더가 아니라 실제 바이트에 걸려야 한다.
      const chunk = "x".repeat(64 * 1024);
      for (let i = 0; i < 8; i++) res.write(chunk);
      res.end();
    });
    servers.push(server);
    const port = await listen(server);

    await expect(fetchViaHttp(`http://127.0.0.1:${port}/.well-known/mta-sts.txt`)).rejects.toThrow(/상한/);
  });

  test("정상 정책은 그대로 돌려준다", async () => {
    const body = "version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: 86400\n";
    const server = createHttpServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(body);
    });
    servers.push(server);
    const port = await listen(server);

    expect(await fetchViaHttp(`http://127.0.0.1:${port}/.well-known/mta-sts.txt`)).toBe(body);
  });
});

function listen(server: ReturnType<typeof createHttpServer>): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve(typeof addr === "object" && addr !== null ? addr.port : 0);
    });
  });
}

/**
 * 테스트용 우회 — 로컬에 유효한 인증서를 세우지 않고 **스킴 가드 이후의 동작**(리다이렉트 거절·
 * 본문 상한)을 보기 위해, https 접두사 검사만 임시로 통과시키고 나머지는 그대로 태운다.
 * 스킴 가드 자체는 위의 별도 테스트가 본다.
 */
async function fetchViaHttp(httpUrl: string): Promise<string> {
  return await fetchMtaStsPolicy(httpUrl.replace("http://", "https://"), {
    request: httpRequest,
    lookup: (_hostname, _options, callback) => callback(null, "127.0.0.1", 4),
  });
}
