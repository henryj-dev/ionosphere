/**
 * 리스너별 인증서(`certSources`) — 한 인스턴스가 포트마다 **다른 이름**으로 TLS를 제공한다.
 *
 * 왜 필요한가: MX 역할은 25번에서 `mx.example.com`을 제시해야 하고(발신 MTA가 MTA-STS의 `mx:`와
 * 대조) 443에서는 `mta-sts.example.com`을 제시해야 한다(브라우저·발신자가 SNI로 검증).
 * 와일드카드 한 장으로 덮으면 가려지지만, 그때도 **개인키 하나가 모든 이름을 대표**한다.
 *
 * ★검증은 배선이 아니라 **실제 핸드셰이크의 CN**으로 한다. "reloadTls가 호출됐다"는 어떤
 * 인증서를 제시하는지 말해주지 않는다 — 이 파일이 잡으려는 결함이 정확히 그 층에 있다.
 */
import { afterEach, describe, expect, test, SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import * as tls from "node:tls";
import * as net from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSelfSigned, type CertSource, type TlsMaterial } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver } from "./helpers.ts";

const IMAPS = generateSelfSigned({ commonName: "imap.test", sans: ["imap.test"] });
const SMTPS = generateSelfSigned({ commonName: "smtp.test", sans: ["smtp.test"] });
const DEFAULT_CERT = generateSelfSigned({ commonName: "default.test", sans: ["default.test"] });
const RENEWED = generateSelfSigned({ commonName: "renewed.test", sans: ["renewed.test"] });

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(closers.map((c) => c()));
  closers.length = 0;
});

/** TLS로 붙어 제시된 인증서의 CN을 읽는다(핸드셰이크만, 앱 프로토콜 미사용). */
function peerCN(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const c = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false }, () => {
      const raw = c.getPeerCertificate().subject?.CN;
      c.end();
      resolve(Array.isArray(raw) ? (raw[0] ?? "") : (raw ?? ""));
    });
    c.on("error", reject);
  });
}

/** 고정 자료를 주는 소스. watch로 갱신을 임의 발화할 수 있다. */
function fixedSource(initial: TlsMaterial): CertSource & { fire(m: TlsMaterial): void } {
  let onChange: ((m: TlsMaterial) => void) | null = null;
  return {
    mode: "file",
    resolve: async () => initial,
    status: async () => ({ mode: "file" as const, enabled: true, source: "test" }),
    watch(cb) {
      onChange = cb;
      return () => {
        onChange = null;
      };
    },
    fire(m) {
      onChange?.(m);
    },
  };
}

/** resolve()가 던지는 소스 — 전용 소스 확보 실패가 기본으로 폴백하지 않는지 확인용. */
function failingSource(): CertSource {
  return {
    mode: "url",
    resolve: async () => {
      throw new Error("확보 실패(테스트)");
    },
    status: async () => ({ mode: "url" as const, enabled: false, source: "test", error: "확보 실패(테스트)" }),
  };
}

interface Built {
  app: IonosphereApp;
}

async function startApp(opts: Partial<ConstructorParameters<typeof IonosphereApp>[0]>): Promise<Built> {
  const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-perlistener-"));
  const app = new IonosphereApp({
    hostname: "default.test",
    dbPath: ":memory:",
    blobRoot,
    resolver: offlineResolver(),
    runMtaWorker: false,
    runWebhookWorker: false,
    runReaper: false,
    blobGcMode: "off",
    ...opts,
  });
  await app.start();
  closers.push(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  });
  return { app };
}

describe("리스너별 인증서 — 포트마다 다른 이름을 제시한다", () => {
  test("★993과 465가 서로 다른 인증서를 제시한다(실제 핸드셰이크 CN)", async () => {
    const { app } = await startApp({
      imapPort: 0,
      imapsPort: 0,
      smtpsPort: 0,
      certSource: fixedSource({ key: DEFAULT_CERT.keyPem, cert: DEFAULT_CERT.certPem }),
      certSources: {
        imaps: fixedSource({ key: IMAPS.keyPem, cert: IMAPS.certPem }),
        smtps: fixedSource({ key: SMTPS.keyPem, cert: SMTPS.certPem }),
      },
    });
    expect(await peerCN(app.imapsPort)).toBe("imap.test");
    expect(await peerCN(app.smtpsPort)).toBe("smtp.test");
  });

  test("전용 소스가 없는 리스너는 기본 소스를 쓴다(하위호환)", async () => {
    const { app } = await startApp({
      imapPort: 0,
      imapsPort: 0,
      smtpsPort: 0,
      certSource: fixedSource({ key: DEFAULT_CERT.keyPem, cert: DEFAULT_CERT.certPem }),
      certSources: { imaps: fixedSource({ key: IMAPS.keyPem, cert: IMAPS.certPem }) },
    });
    expect(await peerCN(app.imapsPort)).toBe("imap.test"); // 전용
    expect(await peerCN(app.smtpsPort)).toBe("default.test"); // 기본
  });

  test("certSources를 안 주면 전부 기본 소스(기존 동작 그대로)", async () => {
    const { app } = await startApp({
      imapPort: 0,
      imapsPort: 0,
      smtpsPort: 0,
      certSource: fixedSource({ key: DEFAULT_CERT.keyPem, cert: DEFAULT_CERT.certPem }),
    });
    expect(await peerCN(app.imapsPort)).toBe("default.test");
    expect(await peerCN(app.smtpsPort)).toBe("default.test");
  });

  /**
   * ★전용 소스를 줬는데 확보가 **실패한** 리스너는 TLS 없이 남아야 한다 — 기본 인증서로 조용히
   * 폴백하면 운영자가 이름을 나눈 의도를 뒤집고, 그 포트가 엉뚱한 이름의 인증서를 제시한다.
   * (fail closed: 안 켜지는 것이 잘못된 이름을 제시하는 것보다 낫다.)
   */
  test("★전용 소스 확보 실패 → 그 리스너만 TLS 비활성(기본으로 폴백하지 않는다)", async () => {
    const { app } = await startApp({
      imapPort: 0,
      imapsPort: 0,
      smtpsPort: 0,
      certSource: fixedSource({ key: DEFAULT_CERT.keyPem, cert: DEFAULT_CERT.certPem }),
      certSources: { imaps: failingSource() },
    });
    expect(app.imapsPort).toBe(0); // 993은 안 뜬다
    expect(await peerCN(app.smtpsPort)).toBe("default.test"); // 465는 정상
  });
});

describe("갱신 반영 범위 — 소스마다 자기 리스너만", () => {
  /**
   * ★한 소스의 갱신이 **다른 소스를 쓰는 리스너를 덮어쓰면 안 된다.** 덮어쓰면 그 포트가
   * 엉뚱한 이름의 인증서를 제시하고, 증상은 갱신 시점에야 나타나 원인이 갱신이라는 것도
   * 드러나지 않는다.
   */
  test("★imaps 소스 갱신이 smtps 인증서를 바꾸지 않는다", async () => {
    const imapsSrc = fixedSource({ key: IMAPS.keyPem, cert: IMAPS.certPem });
    const { app } = await startApp({
      imapPort: 0,
      imapsPort: 0,
      smtpsPort: 0,
      certSources: {
        imaps: imapsSrc,
        smtps: fixedSource({ key: SMTPS.keyPem, cert: SMTPS.certPem }),
      },
    });
    expect(await peerCN(app.imapsPort)).toBe("imap.test");
    expect(await peerCN(app.smtpsPort)).toBe("smtp.test");

    // 범위 판정 자체를 검증하는 테스트이므로 공개 재적재 경로의 완료를 기다린 뒤 연결한다.
    // watch callback은 void 비동기라 재적재 중간에 TLS 연결하면 평문 리스너 재생성 구간과 경합한다.
    await app.reloadTlsFor({ key: RENEWED.keyPem, cert: RENEWED.certPem }, imapsSrc);
    expect(await peerCN(app.imapsPort)).toBe("renewed.test"); // 갱신 반영
    expect(await peerCN(app.smtpsPort)).toBe("smtp.test"); // ★건드리지 않았다
  });

  test("기본 소스 갱신은 전용 소스를 가진 리스너를 건드리지 않는다", async () => {
    const defaultSrc = fixedSource({ key: DEFAULT_CERT.keyPem, cert: DEFAULT_CERT.certPem });
    const { app } = await startApp({
      imapPort: 0,
      imapsPort: 0,
      smtpsPort: 0,
      certSource: defaultSrc,
      certSources: { imaps: fixedSource({ key: IMAPS.keyPem, cert: IMAPS.certPem }) },
    });
    await app.reloadTlsFor({ key: RENEWED.keyPem, cert: RENEWED.certPem });
    expect(await peerCN(app.smtpsPort)).toBe("renewed.test"); // 기본 소스 리스너는 갱신
    expect(await peerCN(app.imapsPort)).toBe("imap.test"); // 전용 소스 리스너는 그대로
  });

  /**
   * ★회귀: `reloadAllTls`가 리스너를 손으로 나열해서 **143·110이 빠져 있었다.** 두 서버 모두
   * `reloadTls`를 갖고 있는데 호출되지 않아, 갱신 후 그 두 포트만 만료 인증서를 제시했다.
   * 같은 함정을 4190에서 겪고 주석까지 남겼는데 STARTTLS를 143·110에 추가하면서 반복됐다.
   * 이제 `TLS_LISTENER_NAMES`가 정본이고 맵이 그 전부를 요구하므로 누락은 컴파일에서 걸린다 —
   * 이 테스트는 그 배선이 실제로 도달하는지를 본다.
   */
  test("★갱신이 143·110·4190(STARTTLS 리스너)까지 도달한다", async () => {
    const src = fixedSource({ key: DEFAULT_CERT.keyPem, cert: DEFAULT_CERT.certPem });
    const { app } = await startApp({
      imapPort: 0,
      pop3Port: 0,
      manageSievePort: 0,
      smtpPort: 0,
      submissionPort: 0,
      certSource: src,
    });

    const seen = new Set<string>();
    const spy = (name: string, srv: { reloadTls(m: TlsMaterial): Promise<void> } | undefined): void => {
      if (!srv) return;
      const orig = srv.reloadTls.bind(srv);
      srv.reloadTls = async (m: TlsMaterial) => {
        seen.add(name);
        await orig(m);
      };
    };
    expect(app.imap).toBeDefined();
    expect(app.pop3).toBeDefined();
    expect(app.managesieve).toBeDefined();
    spy("imap", app.imap);
    spy("pop3", app.pop3);
    spy("manageSieve", app.managesieve);

    src.fire({ key: RENEWED.keyPem, cert: RENEWED.certPem });
    for (let i = 0; i < 100 && seen.size < 3; i++) await new Promise((r) => setTimeout(r, 10));
    expect([...seen].sort()).toEqual(["imap", "manageSieve", "pop3"]);
  });
});

describe("평문 AUTH 판정 — 리스너별 소스만 준 구성", () => {
  /**
   * 기본 소스 없이 리스너별 소스만 준 배치에서 `tlsConfigured`가 거짓이 되면 **평문 AUTH가
   * 열린다.** TLS를 의도한 것이 분명한데 그 신호를 놓치는 것이라 fail open이다.
   */
  test("★certSources만 있어도 평문 AUTH는 막힌다", async () => {
    const { app } = await startApp({
      imapPort: 0,
      certSources: { imap: fixedSource({ key: IMAPS.keyPem, cert: IMAPS.certPem }) },
    });
    // 143에 붙어 CAPABILITY를 보면 LOGINDISABLED가 광고돼야 한다(평문 AUTH 차단의 표시).
    const caps = await new Promise<string>((resolve, reject) => {
      const c = net.connect(app.imapPort, "127.0.0.1");
      let buf = "";
      c.setEncoding("utf8");
      c.on("data", (d: string) => {
        buf += d;
        if (buf.includes("CAPABILITY") || buf.includes("* OK")) {
          c.write("a1 CAPABILITY\r\n");
        }
        if (buf.includes("a1 OK")) {
          c.end();
          resolve(buf);
        }
      });
      c.on("error", reject);
      setTimeout(() => {
        c.destroy();
        resolve(buf);
      }, SOCKET_DEADLINE_MS);
    });
    expect(caps).toContain("LOGINDISABLED");
  });
});
