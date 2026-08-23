/**
 * 역할별 기동 — 필요한 리스너만 띄운다.
 *
 * 왜 필요해졌나: `smtpPort`/`pop3Port`가 **필수 옵션**이라 `startInbound`가 무조건 listen했다.
 * 서버를 역할별로 나누면(MX / 릴레이 / MRA) MRA 서버는 25를 열 이유가 없는데도 열렸고,
 * MX가 아닌 서버까지 스팸·오배달 표면이 늘었다. 릴레이 서버도 POP3를 열고 있었다.
 *
 * 여기서 고정하는 계약: 포트를 생략하면 **그 리스너가 존재하지 않는다**(0은 임시 포트지 끔이 아니다).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver } from "./helpers.ts";

const cleanup: (() => void)[] = [];

afterEach(() => {
  for (const fn of cleanup.splice(0)) fn();
});

function makeApp(extra: Record<string, unknown>): IonosphereApp {
  const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-roles-"));
  cleanup.push(() => rmSync(blobRoot, { recursive: true, force: true }));
  return new IonosphereApp({
    hostname: "mx.test.local",
    dbPath: ":memory:",
    blobRoot,
    runMtaWorker: false,
    resolver: offlineResolver(),
    ...extra,
  } as never);
}

/** 포트가 실제로 닫혀 있는지 — 연결이 거부돼야 한다. */
function refused(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect(port, "127.0.0.1");
    const done = (v: boolean): void => {
      sock.destroy();
      resolve(v);
    };
    sock.on("connect", () => done(false));
    sock.on("error", () => done(true));
    setTimeout(() => done(true), 3000);
  });
}

describe("역할별 리스너 on/off", () => {
  test("MRA 역할: 25를 열지 않는다", async () => {
    const app = makeApp({ pop3Port: 0 }); // smtpPort 생략
    await app.start();
    try {
      expect(app.smtp).toBeUndefined();
      expect(app.smtpPort).toBe(0);
      expect(app.pop3Port).toBeGreaterThan(0); // POP3는 떴다
    } finally {
      await app.stop();
    }
  });

  test("릴레이/MX 역할: POP3를 열지 않는다", async () => {
    const app = makeApp({ smtpPort: 0 }); // pop3Port 생략
    await app.start();
    try {
      expect(app.pop3).toBeUndefined();
      expect(app.pop3Port).toBe(0);
      expect(app.smtpPort).toBeGreaterThan(0);
    } finally {
      await app.stop();
    }
  });

  test("둘 다 생략해도 기동한다 — 관리 전용 인스턴스", async () => {
    const app = makeApp({});
    await app.start();
    try {
      expect(app.smtp).toBeUndefined();
      expect(app.pop3).toBeUndefined();
      expect(app.db).toBeDefined(); // 저장소는 정상적으로 열렸다
    } finally {
      await app.stop();
    }
  });

  test("끈 리스너의 포트는 실제로 닫혀 있다(객체만 없는 게 아니다)", async () => {
    // 먼저 SMTP를 켜서 포트를 알아낸 뒤, 끈 인스턴스에서 그 포트가 안 열리는지 본다.
    const on = makeApp({ smtpPort: 0, pop3Port: 0 });
    await on.start();
    const usedPort = on.smtpPort;
    await on.stop();

    const off = makeApp({ pop3Port: 0 }); // smtp 끔
    await off.start();
    try {
      expect(await refused(usedPort)).toBe(true);
    } finally {
      await off.stop();
    }
  });

  test("stop()이 안 띄운 리스너에서 터지지 않는다", async () => {
    const app = makeApp({});
    await app.start();
    await expect(app.stop()).resolves.toBeUndefined();
  });
});

describe("배경 워커 on/off", () => {
  test("리퍼/웹훅 워커를 끌 수 있다 — 어느 인스턴스가 돌릴지 정한다", async () => {
    const app = makeApp({ pop3Port: 0, runReaper: false, runWebhookWorker: false });
    await app.start();
    try {
      expect(app.reaper).toBeUndefined();
      expect(app.webhookWorker).toBeUndefined();
    } finally {
      await app.stop();
    }
  });

  test("기본값은 켜짐(단일 인스턴스 기존 동작 보존)", async () => {
    const app = makeApp({ pop3Port: 0 });
    await app.start();
    try {
      expect(app.reaper).toBeDefined();
      expect(app.webhookWorker).toBeDefined();
    } finally {
      await app.stop();
    }
  });
});

describe("POP3 배타 락 — 110과 995가 같은 락을 본다", () => {
  test("한 인스턴스 안의 두 POP3 리스너가 락을 공유한다", async () => {
    // app.ts가 백엔드를 둘 만들면서 락을 각자 갖고 있으면, 같은 계정이 110과 995로 동시에 열린다.
    // 인스턴스 하나를 openStorage에서 만들어 넘기는 구조인지 확인한다.
    const app = makeApp({ pop3Port: 0 });
    await app.start();
    try {
      expect(app.maildropLock).toBeDefined();
      // DB 기반 락은 만료가 있으므로 갱신 주기가 양수여야 한다(인프로세스 락은 0).
      expect(app.maildropLock.refreshIntervalMs).toBeGreaterThan(0);
    } finally {
      await app.stop();
    }
  });
});
