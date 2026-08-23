/**
 * 평문 HTTP 표면의 바인딩 주소.
 *
 * 과거 결함: `listen(port)`에 host를 안 줘서 전부 **0.0.0.0(모든 인터페이스)** 였다.
 * metrics는 주석에 *"⚠ 평문 — 내부망/프록시 뒤 스크레이프 전용, 외부 노출 금지"* 라고
 * 선언해 두고도 코드가 그걸 지키지 않았고(인증이 없어 큐 깊이·계정 정지 수가 그대로 샌다),
 * TLS 프론트를 세운 구성에서도 그 뒤에 있어야 할 평문 upstream이 함께 공개됐다.
 *
 * 지금 계약: 평문 표면의 **기본값은 언제나 루프백**이다. 앞단이 있으면 그 포트는 정의상 내부
 * upstream이고, 앞단이 없을 때 전 인터페이스로 여는 것은 설정 누락이 곧 전면 공개가 되는
 * fail open이었다(감사 L-2). 외부 노출은 `IONOSPHERE_LISTEN_*`로 **명시**해야 한다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { IonosphereApp } from "../src/app.ts";
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
  const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-bind-"));
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

/** 루프백이 아닌 로컬 주소에서 그 포트에 붙을 수 있는가(= 외부 인터페이스에 열려 있는가). */
async function reachableOffLoopback(port: number): Promise<boolean> {
  const { connect } = await import("node:net");
  const { networkInterfaces } = await import("node:os");
  const external = Object.values(networkInterfaces())
    .flat()
    .find((n) => n && n.family === "IPv4" && !n.internal);
  if (!external) return false; // 외부 인터페이스가 없는 환경 — 판정 불가

  return new Promise<boolean>((resolve) => {
    const sock = connect({ host: external.address, port });
    const done = (v: boolean): void => {
      sock.destroy();
      resolve(v);
    };
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
    setTimeout(() => done(false), 1500);
  });
}

describe("평문 표면 바인딩", () => {
  test("metrics는 앞단 유무와 무관하게 루프백에만 열린다", async () => {
    const app = await startApp({ metricsPort: 0 });

    expect(app.metricsPort).toBeGreaterThan(0);
    expect(await reachableOffLoopback(app.metricsPort)).toBe(false);
  }, E2E_HOOK_TIMEOUT_MS);

  test("metricsHost를 명시하면 그 주소를 따른다(원격 스크레이프는 눈에 보이는 선택)", async () => {
    const app = await startApp({ metricsPort: 0, metricsHost: "0.0.0.0" });

    expect(await reachableOffLoopback(app.metricsPort)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  test("443에 admin vhost를 얹어도 평문 admin은 루프백 upstream으로 남는다", async () => {
    // 평문 8080이 외부에 열리면 토큰이 평문으로 흐르고, 스로틀이 신뢰하는 XFF를
    // 그쪽에서 위조할 수 있다. 앞단 유무와 **무관하게** 루프백이어야 한다.
    const app = await startApp({ adminPort: 0, serviceHosts: { admin: ["admin.test.local"] }, imapsTls, adminRootToken: "t" });

    expect(app.adminPort).toBeGreaterThan(0);
    expect(await reachableOffLoopback(app.adminPort)).toBe(false);
  }, E2E_HOOK_TIMEOUT_MS);

  /**
   * ★계약 변경(2026-07-31, 감사 L-2). 예전엔 "앞단이 없으면 종전대로 전 인터페이스"였다.
   * 그건 인증서 설정을 빠뜨렸다는 이유로 평문 관리 API가 전 세계에 열리는 fail open이었고,
   * 라이브가 안전했던 근거도 코드가 아니라 live-activate.sh가 심는 env 한 줄이었다.
   * 이제 판정을 못 하는 쪽이 아니라 **안전한 쪽**으로 간다.
   */
  test("앞단이 없어도 평문 admin은 루프백에만 열린다(fail closed)", async () => {
    const app = await startApp({ adminPort: 0, adminRootToken: "t" });

    expect(app.adminPort).toBeGreaterThan(0); // 기동은 정상
    expect(await reachableOffLoopback(app.adminPort)).toBe(false);
  }, E2E_HOOK_TIMEOUT_MS);

  /** 기본값만 바꿨다 — 전면 공개가 필요한 배포는 종전처럼 명시로 연다. */
  test("IONOSPHERE_LISTEN_* 상당의 명시 host는 그대로 존중된다", async () => {
    const app = await startApp({
      adminPort: 0,
      adminRootToken: "t",
      listeners: { admin: { enabled: true, host: "0.0.0.0" } },
    });

    expect(await reachableOffLoopback(app.adminPort)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  test("jmap·autoconfig도 앞단이 없으면 루프백이다", async () => {
    const app = await startApp({ jmapPort: 0, autoconfigPort: 0 });

    expect(await reachableOffLoopback(app.jmapPort)).toBe(false);
    expect(await reachableOffLoopback(app.autoconfigPort)).toBe(false);
  }, E2E_HOOK_TIMEOUT_MS);
});
