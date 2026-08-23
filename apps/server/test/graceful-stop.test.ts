/**
 * 정상 종료 — 열린 연결이 있어도 `app.stop()`이 끝나야 한다.
 *
 * 실제 사고(2026-07-30, 서버 이관 중 발견): SIGTERM 핸들러는 돌았는데(`shutting down` 로그)
 * `app.stop()`이 끝나지 않아 systemd가 90초 뒤 SIGKILL했다. 지난 6시간 로그에 정상 종료가
 * **1회뿐**이라 이번만의 일이 아니었다 — 배포마다 강제 종료되고 있었다.
 *
 * 원인: 모든 리스너의 close()가 `server.close(cb)` 하나였다. node 의미상 이건 "새 연결만 막고,
 * **기존 연결이 전부 끝나면** 콜백"이다. IMAP IDLE이나 JMAP SSE처럼 오래 붙어 있는 연결이
 * 하나만 있어도 영원히 안 온다. `closeAllConnections()`는 http.Server에만 있고 메일 리스너는
 * net.Server라 양 런타임 모두 쓸 수 없다(실측: bun 1.3.14 · node 24 둘 다 undefined).
 *
 * 강제 종료가 위험한 이유: SQLite가 쓰기 도중 죽고, 배달 중이던 큐 항목의 리스가 정리되지 않는다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver } from "./helpers.ts";

const E2E_HOOK_TIMEOUT_MS = 25_000;
/** stop()이 이 안에 안 끝나면 실패 — systemd 기본(90초)보다 훨씬 빠듯하게 잡는다. */
const STOP_BUDGET_MS = 5_000;

let dirs: string[] = [];
let open: ReturnType<typeof connect>[] = [];

afterEach(() => {
  for (const s of open) s.destroy();
  open = [];
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs = [];
});

async function startApp(extra: Record<string, unknown>): Promise<IonosphereApp> {
  const dir = mkdtempSync(join(tmpdir(), "ionosphere-stop-"));
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
  return app;
}

/**
 * 연결을 열고 **붙잡고 있는다**(아무것도 안 보냄) — IDLE 중인 클라이언트를 흉내낸다.
 *
 * ⚠ `connect` 이벤트만 기다리면 **서버 쪽 세션이 자리잡기 전에** stop()을 불러 버려,
 * 리스너가 "연결 없음"으로 보고 그냥 닫힌다 — 테스트가 헛통과한다(실제로 그렇게 짰다가
 * 6건 중 5건이 버그를 못 잡았다). 메일 프로토콜은 접속 즉시 인사말을 보내므로 **첫 바이트**를
 * 기다리는 것이 정확한 신호다. 인사말이 없는 HTTP 계열은 짧은 여유로 대신한다.
 */
function hold(port: number): Promise<void> {
  return new Promise((res, rej) => {
    const sock = connect({ port, host: "127.0.0.1" });
    open.push(sock);
    const settle = setTimeout(res, 400); // HTTP 계열 — 인사말이 없다
    sock.once("data", () => {
      clearTimeout(settle);
      res();
    });
    sock.once("error", (err) => {
      clearTimeout(settle);
      rej(err);
    });
  });
}

/** stop()이 예산 안에 끝나는가. 초과하면 false(행). */
async function stopsWithin(app: IonosphereApp, ms: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<false>((res) => {
    timer = setTimeout(() => res(false), ms);
  });
  const done = app.stop().then(() => true);
  const result = await Promise.race([done, timeout]);
  if (timer) clearTimeout(timer);
  return result;
}

describe("열린 연결이 있어도 종료된다", () => {
  test("★IMAP 연결을 붙잡고 있어도 stop()이 끝난다", async () => {
    const app = await startApp({ imapPort: 0 });
    await hold(app.imapPort);
    expect(await stopsWithin(app, STOP_BUDGET_MS)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  test("SMTP 연결을 붙잡고 있어도 끝난다", async () => {
    const app = await startApp({ smtpPort: 0 });
    await hold(app.smtpPort);
    expect(await stopsWithin(app, STOP_BUDGET_MS)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  test("POP3 연결을 붙잡고 있어도 끝난다", async () => {
    const app = await startApp({ pop3Port: 0 });
    await hold(app.pop3Port);
    expect(await stopsWithin(app, STOP_BUDGET_MS)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  /** HTTP 계열도 같다 — JMAP SSE는 설계상 계속 열려 있는 연결이다. */
  test("JMAP 연결을 붙잡고 있어도 끝난다", async () => {
    const app = await startApp({ jmapPort: 0 });
    await hold(app.jmapPort);
    expect(await stopsWithin(app, STOP_BUDGET_MS)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  test("관리 API 연결을 붙잡고 있어도 끝난다", async () => {
    const app = await startApp({ adminPort: 0, adminRootToken: "t" });
    await hold(app.adminPort);
    expect(await stopsWithin(app, STOP_BUDGET_MS)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);

  /** 실제 운영과 같은 조합 — 여러 리스너에 동시에 연결이 걸린 상태. */
  test("여러 리스너에 동시에 걸려 있어도 끝난다", async () => {
    const app = await startApp({ smtpPort: 0, imapPort: 0, pop3Port: 0, jmapPort: 0 });
    await Promise.all([hold(app.smtpPort), hold(app.imapPort), hold(app.pop3Port), hold(app.jmapPort)]);
    expect(await stopsWithin(app, STOP_BUDGET_MS)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("연결이 없을 때는 종전대로", () => {
  test("빈 상태에서도 정상 종료한다", async () => {
    const app = await startApp({ smtpPort: 0, imapPort: 0 });
    expect(await stopsWithin(app, STOP_BUDGET_MS)).toBe(true);
  }, E2E_HOOK_TIMEOUT_MS);
});
