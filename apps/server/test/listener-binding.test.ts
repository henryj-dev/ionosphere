/**
 * 리스너 오버라이드가 **실제 바인딩**에 반영되는가, 그리고 **기본값이 바뀌지 않았는가**.
 *
 * 후자가 더 중요하다. 이 기능을 넣었다는 이유로 루프백에 묶여 있던 표면(metrics·TLS 프론트 뒤의
 * admin)이 열리면 그건 기능 추가가 아니라 사고다. 여는 것은 눈에 보이는 선택이어야 한다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { networkInterfaces } from "node:os";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver } from "./helpers.ts";

const E2E_HOOK_TIMEOUT_MS = 25_000;

let running: IonosphereApp | null = null;
let dirs: string[] = [];

afterEach(async () => {
  if (running) await running.stop();
  running = null;
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs = [];
});

async function startApp(extra: Record<string, unknown>): Promise<IonosphereApp> {
  const dir = mkdtempSync(join(tmpdir(), "ionosphere-bind-"));
  dirs.push(dir);
  const app = new IonosphereApp({
    hostname: "test.local",
    dbPath: join(dir, "t.db"),
    blobRoot: join(dir, "blobs"),
    resolver: offlineResolver(),
    runMtaWorker: false,
    ...extra,
  } as never);
  await app.start();
  running = app;
  return app;
}

/** 이 호스트의 비루프백 IPv4 — "전 인터페이스에 열렸는가"를 실제 접속으로 확인한다. */
function externalIpv4(): string | undefined {
  for (const list of Object.values(networkInterfaces())) {
    for (const ni of list ?? []) {
      if (ni.family === "IPv4" && !ni.internal) return ni.address;
    }
  }
  return undefined;
}

function reachable(port: number, host: string): Promise<boolean> {
  return new Promise((res) => {
    const sock = connect({ port, host });
    const done = (v: boolean) => {
      sock.destroy();
      res(v);
    };
    sock.setTimeout(3000, () => done(false));
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
  });
}

describe("기본값 보존", () => {
  /** metrics는 앞단 유무와 무관하게 항상 루프백이었다 — 그 계약이 유지돼야 한다. */
  test("metrics는 지정이 없으면 여전히 루프백에만 열린다", async () => {
    const app = await startApp({ metricsPort: 0 });
    expect(await reachable(app.metricsPort, "127.0.0.1")).toBe(true);
    const ext = externalIpv4();
    if (ext) expect(await reachable(app.metricsPort, ext)).toBe(false);
  }, E2E_HOOK_TIMEOUT_MS);

  test("포트를 안 준 서비스는 여전히 안 뜬다", async () => {
    const app = await startApp({ smtpPort: 0 });
    expect(app.smtpPort).toBeGreaterThan(0);
    expect(app.adminPort).toBe(0);
    expect(app.imapPort).toBe(0);
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("경고 억제", () => {
  /**
   * 바인딩 주소를 명시했으면 기본값 경고("앞단이 없어 …루프백에만 연다")를 띄우면 안 된다.
   * 그 경고는 **기본값 판정**에 딸린 것이라, 운영자가 이미 주소를 골랐는데도 뜨면 노이즈가 되고
   * 진짜 경고를 묻는다. 조기 반환으로 기본값 판정 자체를 건너뛴다.
   */
  test("host를 명시하면 기본값 경고를 내지 않는다", async () => {
    const warns: string[] = [];
    const capture = {
      debug() {},
      info() {},
      warn: (msg: string) => void warns.push(msg),
      error() {},
      child() {
        return capture;
      },
    };
    await startApp({
      adminPort: 0,
      adminRootToken: "t",
      logger: capture,
      listeners: { admin: { enabled: true, host: "127.0.0.1" } },
    });
    expect(warns.filter((w) => w.includes("평문 표면을 루프백에만"))).toHaveLength(0);
  }, E2E_HOOK_TIMEOUT_MS);

  test("host를 안 주면 종전대로 경고가 뜬다 — 억제가 과하지 않은지", async () => {
    const warns: string[] = [];
    const capture = {
      debug() {},
      info() {},
      warn: (msg: string) => void warns.push(msg),
      error() {},
      child() {
        return capture;
      },
    };
    await startApp({ adminPort: 0, adminRootToken: "t", logger: capture });
    expect(warns.filter((w) => w.includes("평문 표면을 루프백에만")).length).toBeGreaterThan(0);
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("오버라이드", () => {
  test("host 지정이 기본값(루프백)을 이긴다", async () => {
    const app = await startApp({ metricsPort: 0, listeners: { metrics: { enabled: true, host: "0.0.0.0" } } });
    expect(await reachable(app.metricsPort, "127.0.0.1")).toBe(true);
    const ext = externalIpv4();
    if (ext) expect(await reachable(app.metricsPort, ext)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  test("off는 포트가 지정돼 있어도 기동을 막는다", async () => {
    const app = await startApp({ metricsPort: 0, smtpPort: 0, listeners: { metrics: { enabled: false } } });
    expect(app.metricsPort).toBe(0); // 안 떴다
    expect(app.smtpPort).toBeGreaterThan(0); // 다른 서비스는 영향 없다
  }, E2E_HOOK_TIMEOUT_MS);

  test("port 오버라이드가 기존 옵션 포트를 이긴다", async () => {
    // 0(자동 할당)을 오버라이드로 줘도 그 값이 쓰여야 한다 — 무시되면 아래가 실패한다
    const app = await startApp({ smtpPort: 0, listeners: { smtp: { enabled: true, host: "127.0.0.1" } } });
    expect(app.smtpPort).toBeGreaterThan(0);
    expect(await reachable(app.smtpPort, "127.0.0.1")).toBe(true);
    const ext = externalIpv4();
    if (ext) expect(await reachable(app.smtpPort, ext)).toBe(false);
  }, E2E_HOOK_TIMEOUT_MS);

  test("한 서비스를 끄는 것이 다른 서비스에 영향을 주지 않는다", async () => {
    const app = await startApp({
      smtpPort: 0,
      pop3Port: 0,
      metricsPort: 0,
      listeners: { pop3: { enabled: false } },
    });
    expect(app.pop3Port).toBe(0);
    expect(app.smtpPort).toBeGreaterThan(0);
    expect(app.metricsPort).toBeGreaterThan(0);
  }, E2E_HOOK_TIMEOUT_MS);
});
