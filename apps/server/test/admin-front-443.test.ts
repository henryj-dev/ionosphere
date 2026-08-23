/**
 * 관리 콘솔을 **443에도** 얹는 경로(`adminHostPrefix`) — 8443과 달리 방화벽으로 막을 수 없다.
 *
 * 여기서 고정하는 계약:
 *  ① `admin.` 이름으로 443에 오면 관리 콘솔 upstream으로 간다(다른 이름은 그대로 JMAP)
 *  ② 그 이름에는 **adminTls 소스의 인증서**를 SNI로 제시한다 — 443 기본 인증서에는 admin 이름이
 *     없고, 기본 인증서를 admin 것으로 바꾸면 MTA-STS 정책 서빙이 이름 불일치로 깨진다(enforce
 *     모드에서는 **수신이 막힌다**). 갈라내는 것 말고 답이 없다.
 *  ③ adminTls 소스가 갱신되면 **443 라우트의 사본도 함께** 바뀐다 — 8443만 갱신하면 admin
 *     이름만 만료 인증서를 계속 제시한다(143·110이 재적재 목록에서 빠졌던 사고와 같은 부류).
 *  ④ `adminHostPrefix`를 주지 않으면 443에 아무것도 얹지 않는다(기본 동작 불변).
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { request } from "node:https";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:tls";
import { selfSignedCertSource } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
let baseDir: string;
let adminDir: string;
const TOKEN = "root-token-admin-443";

/** SNI 이름을 지정해 GET — 443은 이름마다 다른 인증서·다른 upstream이라 둘 다 이름에 달렸다. */
function get(
  port: number,
  path: string,
  servername: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "GET",
        rejectUnauthorized: false,
        servername,
        headers: { host: servername, ...headers },
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (c: string) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: body.slice(0, 400) }));
      },
    );
    req.on("error", reject);
    req.setTimeout(10_000, () => {
      req.destroy();
      reject(new Error("timeout"));
    });
    req.end();
  });
}

/** 그 이름으로 핸드셰이크했을 때 상대가 제시하는 인증서의 CN. */
function peerCn(port: number, servername: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect({ host: "127.0.0.1", port, servername, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate();
      sock.end();
      resolve(cert && cert.subject ? String(cert.subject.CN ?? "") : "");
    });
    sock.on("error", reject);
  });
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "mailer-admin443-"));
  baseDir = mkdtempSync(join(tmpdir(), "mailer-admin443-base-"));
  adminDir = mkdtempSync(join(tmpdir(), "mailer-admin443-adm-"));
  app = new IonosphereApp({
    hostname: "mx.test.local",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    pop3Port: 0,
    adminPort: 0,
    adminRootToken: TOKEN,
    jmapPort: 0,
    httpsFrontPort: 0,
    serviceHosts: { admin: ["admin.test.local"], jmap: ["mx.test.local"] },
    // 443 기본 자료: mx만. admin 이름은 여기 없다 — 라이브와 같은 상황이다.
    certSource: selfSignedCertSource({ commonName: "mx.test.local", sans: ["mx.test.local"], dir: baseDir }),
    // adminTls 소스: admin 전용 발급물(라이브의 cert-api `mailer-admin`에 대응).
    certSources: {
      adminTls: selfSignedCertSource({
        commonName: "admin.test.local",
        sans: ["admin.test.local"],
        dir: adminDir,
      }),
    },
    runMtaWorker: false,
    resolver: offlineResolver(),
  });
  await app.start();
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  for (const d of [blobRoot, baseDir, adminDir]) rmSync(d, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("443에 얹은 관리 콘솔", () => {
  test("admin 이름으로 443에 오면 콘솔이 서빙된다", async () => {
    const r = await get(app.httpsFrontPort, "/", "admin.test.local");
    expect(r.status).toBe(200);
    expect(r.body).toContain("ionosphere 관리 콘솔");
  });

  test("토큰 없이는 관리 API가 401 — 443의 방어선은 이것 하나뿐이다", async () => {
    const noAuth = await get(app.httpsFrontPort, "/v1/tls", "admin.test.local");
    expect(noAuth.status).toBe(401);
    const withAuth = await get(app.httpsFrontPort, "/v1/tls", "admin.test.local", {
      authorization: `Bearer ${TOKEN}`,
    });
    expect(withAuth.status).toBe(200);
  });

  test("★admin 이름에만 전용 인증서 — 기본 자료는 그대로다", async () => {
    expect(await peerCn(app.httpsFrontPort, "admin.test.local")).toBe("admin.test.local");
    // 여기가 admin으로 바뀌면 MTA-STS 정책이 이름 불일치로 깨지고 enforce에서 수신이 막힌다.
    expect(await peerCn(app.httpsFrontPort, "mta-sts.test.local")).toBe("mx.test.local");
    expect(await peerCn(app.httpsFrontPort, "mx.test.local")).toBe("mx.test.local");
  });

  test("admin이 아닌 이름은 443에서 관리 API에 닿지 않는다", async () => {
    const r = await get(app.httpsFrontPort, "/v1/tls", "mx.test.local", { authorization: `Bearer ${TOKEN}` });
    expect(r.status).not.toBe(200);
    expect(r.body).not.toContain("ionosphere 관리 콘솔");
  });

  test("★adminTls 갱신이 443 라우트에도 반영된다 — 8443만 갱신하면 여기가 만료로 남는다", async () => {
    const renewed = selfSignedCertSource({
      commonName: "admin2.test.local",
      sans: ["admin2.test.local"],
      dir: mkdtempSync(join(tmpdir(), "mailer-admin443-renew-")),
    });
    const m = await renewed.resolve();
    expect(m).not.toBeNull();

    // 갱신 감시가 부르는 것과 같은 경로(reloadTlsFor에 그 소스를 준다).
    await app.reloadTlsFor(m!, app.opts.certSources!.adminTls);

    expect(await peerCn(app.httpsFrontPort, "admin.test.local")).toBe("admin2.test.local");
    // 기본 자료는 건드리지 않는다 — 같이 갈아치우면 mx·mta-sts가 깨진다.
    expect(await peerCn(app.httpsFrontPort, "mx.test.local")).toBe("mx.test.local");
  });
});

describe("adminHostPrefix 미지정 시(기본 동작)", () => {
  test("443에 관리 콘솔이 얹히지 않는다", async () => {
    const root = mkdtempSync(join(tmpdir(), "mailer-admin443-off-"));
    const dir = mkdtempSync(join(tmpdir(), "mailer-admin443-off-cert-"));
    const off = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot: root,
      smtpPort: 0,
      pop3Port: 0,
      adminPort: 0,
      adminRootToken: TOKEN,
      jmapPort: 0,
      httpsFrontPort: 0,
      certSource: selfSignedCertSource({ commonName: "mx.test.local", sans: ["mx.test.local"], dir }),
      runMtaWorker: false,
      resolver: offlineResolver(),
    });
    await off.start();
    try {
      const r = await get(off.httpsFrontPort, "/v1/tls", "admin.test.local", { authorization: `Bearer ${TOKEN}` });
      expect(r.status).not.toBe(200);
      // SNI 라우트가 없으므로 어떤 이름이든 기본 인증서다.
      expect(await peerCn(off.httpsFrontPort, "admin.test.local")).toBe("mx.test.local");
    } finally {
      await off.stop();
      rmSync(root, { recursive: true, force: true });
      rmSync(dir, { recursive: true, force: true });
    }
  }, E2E_HOOK_TIMEOUT_MS);
});
