/**
 * 웹 이름 → 계정 셀프서비스 301 (443 로컬 리다이렉트).
 *
 * 여기서 고정하는 계약:
 *  ① 웹 이름으로 443에 오면 **프록시하지 않고** 설정한 URL 그대로 301을 돌려준다(경로·쿼리 미보존)
 *  ② HEAD는 본문이 없고, 다른 이름(프록시 라우트)·모르는 이름(404)의 동작은 그대로다
 *  ③ 설정 짝이 안 맞거나 URL이 위험하면 **기동 시점에** 실패한다(fail closed)
 *  ④ webTls 소스의 인증서는 웹 이름에만 붙고, 그 소스의 갱신은 웹 라우트만 바꾼다
 *     (admin·기본 자료는 그대로) — 143·110이 재적재 목록에서 빠졌던 사고와 같은 부류를 막는다
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { createServer } from "node:http";
import * as https from "node:https";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:tls";
import { generateSelfSigned, selfSignedCertSource, type CertSource, type TlsMaterial } from "@ionosphere/tls";
import { IonosphereApp, webRedirectConfig } from "../src/app.ts";
import { HttpsFrontServer, parseRedirectTarget } from "../src/https-front.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const TARGET = "https://account.ionosphere.test/";

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function req(port: number, host: string, method = "GET", path = "/x?y=1", body?: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const r = https.request(
      { host: "127.0.0.1", port, path, method, servername: host, headers: { host }, rejectUnauthorized: false },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (c: string) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }));
      },
    );
    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

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

/** 비동기 인증서 재적재가 끝날 때까지 제한 시간 안에서 확인한다 — 고정 sleep은 느린 CI에서 흔들린다. */
async function waitForPeerCn(port: number, servername: string, expected: string): Promise<void> {
  const deadline = Date.now() + 2_000;
  for (;;) {
    if ((await peerCn(port, servername)) === expected) return;
    if (Date.now() >= deadline) throw new Error(`${servername} 인증서가 ${expected}로 바뀌지 않았다`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe("parseRedirectTarget", () => {
  test("절대 https URL을 파서 정규형으로 돌려준다(빈 경로는 /, 호스트 소문자)", () => {
    expect(parseRedirectTarget("https://Account.Ionosphere.test")).toBe("https://account.ionosphere.test/");
    // 쿼리는 운영자가 적었을 때만 남는다.
    expect(parseRedirectTarget("https://account.ionosphere.test/login?from=web")).toBe(
      "https://account.ionosphere.test/login?from=web",
    );
  });

  test("https 외 스킴·상대 URL·자격증명·프래그먼트·공백·제어문자는 거부", () => {
    for (const bad of [
      "http://account.ionosphere.test/",
      "javascript:alert(1)",
      "//account.ionosphere.test/",
      "/account",
      "https://user:pw@account.ionosphere.test/",
      "https://user@account.ionosphere.test/",
      "https://account.ionosphere.test/#top",
      "https://account.ionosphere.test/#",
      "https://account.ionosphere.test/\r\nset-cookie: x=1",
      "https://account.ionosphere.test/\t",
      " https://account.ionosphere.test/",
    ]) {
      expect(() => parseRedirectTarget(bad)).toThrow();
    }
  });
});

describe("webRedirectConfig (기동 검증)", () => {
  test("둘 다 없으면 꺼진 상태(undefined)", () => {
    expect(webRedirectConfig({}, undefined)).toBeUndefined();
    expect(webRedirectConfig(undefined, undefined)).toBeUndefined();
  });

  test("이름만·URL만 있으면 기동 실패 — 짝이 안 맞는 설정은 드리프트다", () => {
    expect(() => webRedirectConfig({ web: ["ionosphere.test"] }, undefined)).toThrow("IONOSPHERE_WEB_REDIRECT_URL");
    expect(() => webRedirectConfig({}, TARGET)).toThrow("IONOSPHERE_HOST_WEB");
  });

  test("여러 이름을 소문자로 정규화하고 중복을 없앤다", () => {
    const c = webRedirectConfig({ web: ["Ionosphere.test", "www.ionosphere.test", "ionosphere.test"] }, TARGET);
    expect(c).toEqual({ hosts: ["ionosphere.test", "www.ionosphere.test"], location: TARGET });
  });

  test("다른 서비스 이름과 겹치면 거부(기본 이름 포함)", () => {
    expect(() =>
      webRedirectConfig({ web: ["account.ionosphere.test"], account: ["account.ionosphere.test"] }, "https://other.ionosphere.test/"),
    ).toThrow("ACCOUNT");
    expect(() => webRedirectConfig({ web: ["admin.localhost"] }, TARGET)).toThrow("ADMIN");
  });

  test("대상이 웹 이름 자신이면 거부(무한 리다이렉트)", () => {
    expect(() => webRedirectConfig({ web: ["ionosphere.test"] }, "https://ionosphere.test/")).toThrow("자신");
  });

  test("위험한 URL은 여기서도 거부된다", () => {
    expect(() => webRedirectConfig({ web: ["ionosphere.test"] }, "http://account.ionosphere.test/")).toThrow("https:");
  });

  test("IonosphereApp 생성자가 리스너를 띄우기 전에 거부한다", () => {
    expect(
      () =>
        new IonosphereApp({
          hostname: "mx.ionosphere.test",
          dbPath: ":memory:",
          blobRoot: "unused",
          serviceHosts: { web: ["ionosphere.test"] },
        }),
    ).toThrow("IONOSPHERE_WEB_REDIRECT_URL");
    expect(
      () =>
        new IonosphereApp({
          hostname: "mx.ionosphere.test",
          dbPath: ":memory:",
          blobRoot: "unused",
          serviceHosts: { web: ["ionosphere.test"] },
          webRedirectUrl: TARGET,
        }),
    ).toThrow("IONOSPHERE_HTTPS_FRONT_PORT");
  });
});

describe("HttpsFrontServer — 리다이렉트 라우트", () => {
  test("웹 이름은 정확한 Location으로 301, 다른 이름은 프록시, 모르는 이름은 404", async () => {
    let upstreamHits = 0;
    const up = createServer((_q, s) => {
      upstreamHits++;
      s.writeHead(200, { "content-type": "text/plain" });
      s.end("proxied");
    });
    await new Promise<void>((r) => up.listen(0, "127.0.0.1", () => r()));
    const upAddr = up.address();
    const upPort = typeof upAddr === "object" && upAddr !== null ? upAddr.port : 0;

    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test", sans: ["*.ionosphere.test", "ionosphere.test"] });
    const front = new HttpsFrontServer({
      tls: { key: tls.keyPem, cert: tls.certPem },
      routes: [
        { hosts: ["ionosphere.test", "www.ionosphere.test"], redirect: TARGET, exposure: "public" },
        { hosts: ["account.ionosphere.test"], port: upPort, exposure: "public" },
      ],
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      for (const host of ["ionosphere.test", "WWW.ionosphere.test:443"]) {
        const r = await req(port, host, "GET", "//evil.example.com/%0d%0a?q=1");
        expect(r.status).toBe(301);
        // 요청 경로를 섞지 않는다 — `//evil` 권한부 혼동·CRLF 주입 여지가 없다.
        expect(r.headers.location).toBe(TARGET);
        expect(r.headers["content-length"]).toBe(String(Buffer.byteLength(r.body)));
        expect(r.headers["cache-control"]).toBe("public, max-age=3600");
        expect(r.headers["x-content-type-options"]).toBe("nosniff");
      }

      // 메서드와 무관하게 301이고, 본문을 보낸 POST도 뒤로 넘어가지 않는다.
      const post = await req(port, "ionosphere.test", "POST", "/form", "a=1");
      expect(post.status).toBe(301);
      expect(post.headers.location).toBe(TARGET);

      const head = await req(port, "www.ionosphere.test", "HEAD");
      expect(head.status).toBe(301);
      expect(head.headers.location).toBe(TARGET);
      expect(head.body).toBe("");

      expect(upstreamHits).toBe(0);

      const proxied = await req(port, "account.ionosphere.test");
      expect(proxied.status).toBe(200);
      expect(proxied.body).toBe("proxied");
      expect(upstreamHits).toBe(1);

      expect((await req(port, "nosuch.ionosphere.test")).status).toBe(404);
    } finally {
      await front.close();
      await new Promise<void>((r) => up.close(() => r()));
    }
  });
});

describe("IonosphereApp — webTls 실패 뒤 자동 복구", () => {
  test("기동 때 webTls를 못 받아도 라우트는 301이고, watch 갱신이 전용 인증서를 붙인다", async () => {
    let publish: ((material: TlsMaterial) => void) | undefined;
    const failedThenWatch: CertSource = {
      mode: "url",
      async resolve() {
        return null;
      },
      watch(onChange) {
        publish = onChange;
        return () => {
          publish = undefined;
        };
      },
      async status() {
        return { mode: "url", enabled: false, source: "test", error: "처음 확보 실패" };
      },
    };
    const dirs: string[] = [];
    const tmp = (prefix: string): string => {
      const dir = mkdtempSync(join(tmpdir(), prefix));
      dirs.push(dir);
      return dir;
    };
    const app = new IonosphereApp({
      hostname: "mx.ionosphere.test",
      dbPath: ":memory:",
      blobRoot: tmp("ionosphere-web-recovery-blobs-"),
      httpsFrontPort: 0,
      serviceHosts: { web: ["ionosphere.test", "www.ionosphere.test"] },
      webRedirectUrl: TARGET,
      certSource: selfSignedCertSource({ commonName: "mx.ionosphere.test", sans: ["mx.ionosphere.test"], dir: tmp("ionosphere-web-recovery-base-") }),
      certSources: { webTls: failedThenWatch },
      runMtaWorker: false,
      resolver: offlineResolver(),
    });
    try {
      await app.start();
      expect((await req(app.httpsFrontPort, "ionosphere.test")).status).toBe(301);
      // 전용 자료가 없던 순간은 기본 인증서다.
      expect(await peerCn(app.httpsFrontPort, "ionosphere.test")).toBe("mx.ionosphere.test");
      expect(publish).toBeDefined();

      const renewed = generateSelfSigned({ commonName: "ionosphere.test", sans: ["ionosphere.test", "www.ionosphere.test"] });
      publish!({ key: renewed.keyPem, cert: renewed.certPem });
      await waitForPeerCn(app.httpsFrontPort, "ionosphere.test", "ionosphere.test");
      await waitForPeerCn(app.httpsFrontPort, "www.ionosphere.test", "ionosphere.test");
    } finally {
      await app.stop();
      for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    }
  }, E2E_HOOK_TIMEOUT_MS);

  test("웹 설정 없이 띄우면 모르는 웹 이름은 기존대로 404", async () => {
    const root = mkdtempSync(join(tmpdir(), "ionosphere-no-web-"));
    const app = new IonosphereApp({
      hostname: "mx.ionosphere.test",
      dbPath: ":memory:",
      blobRoot: join(root, "blobs"),
      httpsFrontPort: 0,
      jmapPort: 0,
      serviceHosts: { jmap: ["jmap.ionosphere.test"] },
      certSource: selfSignedCertSource({ commonName: "mx.ionosphere.test", sans: ["mx.ionosphere.test"], dir: join(root, "tls") }),
      runMtaWorker: false,
      resolver: offlineResolver(),
    });
    try {
      await app.start();
      expect((await req(app.httpsFrontPort, "nosuch.example.test")).status).toBe(404);
    } finally {
      await app.stop();
      rmSync(root, { recursive: true, force: true });
    }
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("IonosphereApp — webTls 배선", () => {
  let app: IonosphereApp;
  const dirs: string[] = [];
  const tmp = (p: string): string => {
    const d = mkdtempSync(join(tmpdir(), p));
    dirs.push(d);
    return d;
  };

  beforeAll(async () => {
    app = new IonosphereApp({
      hostname: "mx.ionosphere.test",
      dbPath: ":memory:",
      blobRoot: tmp("ionosphere-web-blobs-"),
      smtpPort: 0,
      pop3Port: 0,
      adminPort: 0,
      adminRootToken: "t",
      jmapPort: 0,
      httpsFrontPort: 0,
      serviceHosts: {
        admin: ["admin.ionosphere.test"],
        jmap: ["mx.ionosphere.test"],
        web: ["ionosphere.test", "www.ionosphere.test"],
      },
      webRedirectUrl: TARGET,
      certSource: selfSignedCertSource({ commonName: "mx.ionosphere.test", sans: ["mx.ionosphere.test"], dir: tmp("ionosphere-web-base-") }),
      certSources: {
        adminTls: selfSignedCertSource({ commonName: "admin.ionosphere.test", sans: ["admin.ionosphere.test"], dir: tmp("ionosphere-web-adm-") }),
        webTls: selfSignedCertSource({
          commonName: "ionosphere.test",
          sans: ["ionosphere.test", "www.ionosphere.test"],
          dir: tmp("ionosphere-web-web-"),
        }),
      },
      runMtaWorker: false,
      resolver: offlineResolver(),
    });
    await app.start();
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("웹 이름은 443에서 301 — 프록시가 아니다", async () => {
    const r = await req(app.httpsFrontPort, "www.ionosphere.test");
    expect(r.status).toBe(301);
    expect(r.headers.location).toBe(TARGET);
  });

  test("★webTls 인증서는 웹 이름에만 — admin·기본 자료는 그대로", async () => {
    expect(await peerCn(app.httpsFrontPort, "ionosphere.test")).toBe("ionosphere.test");
    expect(await peerCn(app.httpsFrontPort, "www.ionosphere.test")).toBe("ionosphere.test");
    expect(await peerCn(app.httpsFrontPort, "admin.ionosphere.test")).toBe("admin.ionosphere.test");
    expect(await peerCn(app.httpsFrontPort, "mx.ionosphere.test")).toBe("mx.ionosphere.test");
  });

  test("★webTls 갱신은 웹 라우트 전부를 바꾸고 admin·기본은 건드리지 않는다", async () => {
    const renewed = selfSignedCertSource({
      commonName: "web2.ionosphere.test",
      sans: ["ionosphere.test", "www.ionosphere.test"],
      dir: tmp("ionosphere-web-renew-"),
    });
    const m = await renewed.resolve();
    expect(m).not.toBeNull();
    // 갱신 감시가 부르는 것과 같은 경로.
    await app.reloadTlsFor(m!, app.opts.certSources!.webTls);

    expect(await peerCn(app.httpsFrontPort, "ionosphere.test")).toBe("web2.ionosphere.test");
    expect(await peerCn(app.httpsFrontPort, "www.ionosphere.test")).toBe("web2.ionosphere.test");
    expect(await peerCn(app.httpsFrontPort, "admin.ionosphere.test")).toBe("admin.ionosphere.test");
    expect(await peerCn(app.httpsFrontPort, "mx.ionosphere.test")).toBe("mx.ionosphere.test");
  });

  test("adminTls 갱신은 웹 이름을 건드리지 않는다", async () => {
    const renewed = selfSignedCertSource({
      commonName: "admin2.ionosphere.test",
      sans: ["admin.ionosphere.test"],
      dir: tmp("ionosphere-web-adm-renew-"),
    });
    const m = await renewed.resolve();
    await app.reloadTlsFor(m!, app.opts.certSources!.adminTls);
    expect(await peerCn(app.httpsFrontPort, "admin.ionosphere.test")).toBe("admin2.ionosphere.test");
    expect(await peerCn(app.httpsFrontPort, "ionosphere.test")).toBe("web2.ionosphere.test");
  });
});
