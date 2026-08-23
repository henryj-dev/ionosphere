/**
 * 인증 실패 스로틀 **배선** 검증 (감사 M-4·M-5·M-6).
 *
 * 스로틀 알고리즘 자체는 packages/core 단위테스트가 덮는다. 여기서 지키려는 것은 조립이다:
 *  - 리스너들이 **한 인스턴스**를 나눠 쓰는가(따로 만들면 리스너 수만큼 한도가 곱해진다)
 *  - 자격증명 없는 요청이 실패로 세지 않는가(401 뒤 자격증명을 붙이는 표준 흐름이 잠기던 결함)
 *  - 계정 축이 submission(587) 인증에 실제로 걸려 있는가
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const USER = "you@test.local";
const PASS = "pw-throttle-1";
const ROOT_TOKEN = "root-throttle-token";

let app: IonosphereApp;
let blobRoot: string;
let jmapBase: string;
let adminBase: string;

const basic = (pass: string): string => "Basic " + Buffer.from(`${USER}:${pass}`).toString("base64");

/** 587에 붙어 AUTH PLAIN 응답 한 줄만 받아온다. */
function smtpAuth(port: number, user: string, pass: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect(port, "127.0.0.1");
    sock.setEncoding("utf8");
    let buf = "";
    let stage = 0;
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("timeout"));
    }, 15_000);
    const auth = Buffer.from(`\0${user}\0${pass}`).toString("base64");
    sock.on("data", (c: string) => {
      buf += c;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (stage === 0) {
          stage = 1;
          sock.write("EHLO c\r\n");
        } else if (stage === 1 && line.startsWith("250 ")) {
          stage = 2;
          sock.write(`AUTH PLAIN ${auth}\r\n`);
        } else if (stage === 2) {
          clearTimeout(timer);
          sock.write("QUIT\r\n");
          sock.end();
          resolve(line);
          return;
        }
      }
    });
    sock.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-throttle-wire-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    jmapPort: 0,
    adminPort: 0,
    submissionPort: 0,
    adminRootToken: ROOT_TOKEN,
    runMtaWorker: false,
    resolver: offlineResolver(),
  });
  await app.start();
  await app.createUser(USER, PASS);
  jmapBase = `http://127.0.0.1:${app.jmapPort}`;
  adminBase = `http://127.0.0.1:${app.adminPort}`;
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("JMAP — 자격증명 없는 요청은 실패로 세지 않는다 (M-5)", () => {
  test("Authorization 없는 요청 20번 뒤에도 정상 로그인이 통과한다", async () => {
    for (let i = 0; i < 20; i++) {
      const res = await fetch(`${jmapBase}/jmap/session`);
      // 세지 않으므로 계속 401이어야 한다 — 429가 나오면 NAT 뒤 사용자가 연쇄 차단된다는 뜻이다.
      expect(res.status).toBe(401);
    }
    const ok = await fetch(`${jmapBase}/jmap/session`, { headers: { authorization: basic(PASS) } });
    expect(ok.status).toBe(200);
  });
});

describe("리스너들이 스로틀 인스턴스를 공유한다 (M-4)", () => {
  test("JMAP에서 소진한 한도가 관리 API에도 그대로 적용된다", async () => {
    // 기본 한도는 IP당 10회. 자격증명을 **제시한** 실패라 이번엔 센다.
    for (let i = 0; i < 10; i++) {
      const res = await fetch(`${jmapBase}/jmap/session`, { headers: { authorization: basic("wrong") } });
      expect(res.status).toBe(401);
    }
    const blocked = await fetch(`${jmapBase}/jmap/session`, { headers: { authorization: basic("wrong") } });
    expect(blocked.status).toBe(429);

    // 인스턴스가 갈라져 있으면 여기서 401(관리 API의 새 버킷)이 나온다.
    const admin = await fetch(`${adminBase}/v1/accounts`, { headers: { authorization: "Bearer bogus" } });
    expect(admin.status).toBe(429);
    expect(admin.headers.get("retry-after")).toBeTruthy();

    // 뒷 테스트에 영향이 없도록 정리(성공 인증이 하는 일과 같다).
    app.authThrottle.clear({ ip: "127.0.0.1" });
  });

  /**
   * ★라인 프로토콜(587·993·995·4190)은 예전에 각자 `new AuthFailureThrottle()`을 **필드
   * 초기화로** 들고 있어 주입 자체가 불가능했다. 그래서 M-4 조치 후에도 IP 축은 JMAP·관리 API
   * 둘만 공유하고 라인 프로토콜 4개는 여전히 각자 한도를 가졌다 — "IP당 분당 10회"가
   * 리스너 수만큼 곱해지는 상태가 절반만 닫혀 있었다.
   *
   * 이 테스트는 **HTTP 표면과 라인 프로토콜 사이**의 공유를 고정한다. 위 테스트(JMAP↔관리 API)만
   * 있으면 그 절반이 다시 갈라져도 통과한다.
   */
  test("submission(587)에서 소진한 IP 한도가 JMAP에도 적용된다", async () => {
    app.authThrottle.clear({ ip: "127.0.0.1" });

    // 587에서 IP 축을 소진시킨다(자격증명을 제시한 실패라 카운트된다).
    for (let i = 0; i < 10; i++) {
      expect(await smtpAuth(app.submissionPort, USER, "wrong-password")).toStartWith("535");
    }

    // 인스턴스가 갈라져 있으면 여기서 401(JMAP의 새 버킷)이 나온다.
    const res = await fetch(`${jmapBase}/jmap/session`, { headers: { authorization: basic("wrong") } });
    expect(res.status).toBe(429);

    app.authThrottle.clear({ ip: "127.0.0.1" });
  });
});

describe("submission(587) 계정 축 (M-6)", () => {
  test("계정 축이 소진되면 비밀번호가 맞아도 인증이 실패한다(scrypt를 돌리기 전에 막는다)", async () => {
    // 서로 다른 20개 IP에서 같은 계정을 두드린 상황 — IP 축은 어디에도 걸리지 않는다.
    for (let i = 0; i < 20; i++) app.authThrottle.recordFailure({ ip: `2001:db8:${i}::1`, account: USER });

    expect(await smtpAuth(app.submissionPort, USER, PASS)).toStartWith("535");

    app.authThrottle.clear({ account: USER });
    expect(await smtpAuth(app.submissionPort, USER, PASS)).toStartWith("235");
  });
});
