/**
 * Phase 2 조립 e2e: 관리 API 도메인 검증 → 발송 게이트(미검증 553 → 검증 후 허용).
 * 실 DNS 미접촉 — 가변 주입 리졸버(검증 토큰을 런타임에 주입).
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { E2E_HOOK_TIMEOUT_MS } from "./helpers.ts";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DnsNotFoundError, type DnsResolver } from "@ionosphere/mail-auth";
import { createCredential } from "@ionosphere/store";
import { IonosphereApp } from "../src/app.ts";

const txtMap: Record<string, string[]> = { "ionosphere.test": ["v=spf1 mx -all"] };
const mxMap: Record<string, { exchange: string; preference: number }[]> = {
  "ionosphere.test": [{ exchange: "mx.ionosphere.test", preference: 10 }],
};
function mutableResolver(): DnsResolver {
  const nf = (): never => {
    throw new DnsNotFoundError("none");
  };
  return {
    txt: async (n) => txtMap[n.toLowerCase()] ?? nf(),
    mx: async (n) => mxMap[n.toLowerCase()] ?? nf(),
    a: async () => nf(),
    aaaa: async () => nf(),
    ptr: async () => nf(),
  };
}

/**
 * 최소 SMTP submission — AUTH PLAIN → MAIL → RCPT → DATA → 메시지 → `.`.
 * 발송 게이트는 배달(enqueue) 시점에 걸리므로 최종 DATA 후 응답 코드를 반환한다.
 */
function submitFull(port: number, user: string, pass: string, from: string, to: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const authB64 = Buffer.from(`\0${user}\0${pass}`, "utf8").toString("base64");
    const msg = `From: ${from}\r\nTo: ${to}\r\nSubject: gate test\r\n\r\nbody\r\n.\r\n`;
    const steps = [`EHLO t\r\n`, `AUTH PLAIN ${authB64}\r\n`, `MAIL FROM:<${from}>\r\n`, `RCPT TO:<${to}>\r\n`, `DATA\r\n`, msg];
    let stage = -1;
    let buf = "";
    const t = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 4000);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (line.startsWith("250-")) continue; // EHLO 멀티라인 계속
        if (stage === steps.length - 1) {
          // 마지막 스텝(메시지+`.`) 응답 = 최종 배달 코드
          clearTimeout(t);
          s.write("QUIT\r\n"); s.end();
          resolve(line);
          return;
        }
        stage++;
        s.write(steps[stage]!);
      }
    });
    s.on("error", reject);
  });
}

describe("Phase 2 조립: 관리 API 검증 → 발송 게이트", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  const base = () => `http://127.0.0.1:${app.adminPort}`;
  const ROOT = "root-token-test";
  let auth: Record<string, string>;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-p2-"));
    app = new IonosphereApp({
      hostname: "mx.ionosphere.test",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      submissionPort: 0,
      adminPort: 0,
      adminRootToken: ROOT,
      resolver: mutableResolver(),
    });
    await app.start();
    // 테넌트 + api key
    const t = (await (await fetch(`${base()}/v1/tenants`, {
      method: "POST", headers: { authorization: `Bearer ${ROOT}`, "content-type": "application/json" },
      body: JSON.stringify({ name: "acme" }),
    })).json()) as { tenantId: string };
    const k = (await (await fetch(`${base()}/v1/api-keys`, {
      method: "POST", headers: { authorization: `Bearer ${ROOT}`, "content-type": "application/json" },
      body: JSON.stringify({ tenantId: t.tenantId, scopes: "admin" }),
    })).json()) as { key: string };
    auth = { authorization: `Bearer ${k.key}`, "content-type": "application/json" };
    // 발신 계정 — 이 테스트의 주제는 **발송 게이트**라 도메인이 아직 미검증인 상태를 만들어야 한다.
    // REST 계정 생성은 검증된 소유 도메인을 요구하므로(주소 선점 차단) 스토어에 직접 만든다.
    // CLI(add-account)로 만든 계정이 갖는 상태와 같다.
    const { accountId } = await app.store.createAccount({ tenantId: t.tenantId, email: "boss@ionosphere.test" });
    await createCredential(app.db, { accountId, password: "pw12345" });
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("미검증 도메인 → 발송 게이트 553", async () => {
    const code = await submitFull(app.submissionPort, "boss@ionosphere.test", "pw12345", "boss@ionosphere.test", "ext@other.test");
    expect(code).toStartWith("553");
  });

  test("도메인 생성 → 검증 실패(토큰 불일치) → 토큰 주입 후 검증 성공 → 발송 허용", async () => {
    // 생성
    const dom = (await (await fetch(`${base()}/v1/domains`, {
      method: "POST", headers: auth, body: JSON.stringify({ name: "ionosphere.test" }),
    })).json()) as { domainId: string; verifyToken: string };
    expect(dom.domainId).toBeTruthy();
    expect(dom.verifyToken).toBeTruthy();

    // 토큰 없이 검증 → 실패
    const vf = (await (await fetch(`${base()}/v1/domains/${dom.domainId}/verify`, { method: "POST", headers: auth })).json()) as { status: string };
    expect(vf.status).not.toBe("active");

    // DNS에 토큰 게시(리졸버 맵 갱신) → 검증 성공
    txtMap["_ionosphere-verify.ionosphere.test"] = [dom.verifyToken];
    const vp = (await (await fetch(`${base()}/v1/domains/${dom.domainId}/verify`, { method: "POST", headers: auth })).json()) as { status: string };
    expect(vp.status).toBe("active");

    // 이제 발송 게이트 통과 → MAIL FROM 250
    const code = await submitFull(app.submissionPort, "boss@ionosphere.test", "pw12345", "boss@ionosphere.test", "ext@other.test");
    expect(code).toStartWith("250");
  });

  test("알리아스: sales@ → boss 계정으로 배달", async () => {
    // boss 계정 id 조회
    const accts = (await (await fetch(`${base()}/v1/accounts`, { headers: auth })).json()) as {
      email: string;
    }[];
    expect(accts.some((a) => a.email === "boss@ionosphere.test")).toBe(true);
    const list = (await (await fetch(`${base()}/v1/accounts`, { headers: auth })).json()) as unknown[];
    expect(list.length).toBeGreaterThan(0);
    // accountId는 목록에 없으므로 알리아스 생성은 이메일 기반이 아닌 targetAccountId 필요 →
    // DB에서 직접 조회 (테스트 편의)
    const { rows } = await app.db.query({ sql: "SELECT id FROM accounts WHERE email = ?", params: ["boss@ionosphere.test"] });
    const bossId = String(rows[0]!.id);

    // 알리아스 sales@ionosphere.test → boss
    const al = await fetch(`${base()}/v1/aliases`, {
      method: "POST", headers: auth,
      body: JSON.stringify({ address: "sales@ionosphere.test", targetAccountId: bossId }),
    });
    expect(al.status).toBe(200);

    // relay(:25)로 sales@ 앞 수신
    const relayCode = await relaySend(app.smtpPort, "outsider@other.test", "sales@ionosphere.test");
    expect(relayCode).toStartWith("250");

    // boss 메일함에 도착 확인 (POP3)
    const count = await pop3Count(app.pop3Port, "boss@ionosphere.test", "pw12345");
    expect(count).toBeGreaterThan(0);

    // subaddress도 동작: sales+urgent@ → 같은 계정 (별도 검증은 라우팅 로직 신뢰)
    const relayCode2 = await relaySend(app.smtpPort, "outsider@other.test", "unknown-nobody@ionosphere.test");
    expect(relayCode2).toStartWith("550"); // 알리아스도 계정도 없음 → 거부
  });

  test("정지 계정(status=0) → AUTH 535 차단 (abuse 자동 정지)", async () => {
    await app.db.batch([{ sql: "UPDATE accounts SET status = 0 WHERE email = ?", params: ["boss@ionosphere.test"] }]);
    // 정지 계정은 authenticate(WHERE status=1)에서 막혀 AUTH 자체가 실패
    const code = await authOnly(app.submissionPort, "boss@ionosphere.test", "pw12345");
    expect(code).toStartWith("535");
    await app.db.batch([{ sql: "UPDATE accounts SET status = 1 WHERE email = ?", params: ["boss@ionosphere.test"] }]);
  });
});

/** EHLO → AUTH PLAIN → AUTH 응답 코드만 반환하고 종료. */
function authOnly(port: number, user: string, pass: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const authB64 = Buffer.from(`\0${user}\0${pass}`, "utf8").toString("base64");
    const steps = [`EHLO t\r\n`, `AUTH PLAIN ${authB64}\r\n`];
    let stage = -1;
    let buf = "";
    const t = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 4000);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (line.startsWith("250-")) continue;
        if (stage === steps.length - 1) {
          clearTimeout(t); s.write("QUIT\r\n"); s.destroy();
          resolve(line);
          return;
        }
        stage++;
        s.write(steps[stage]!);
      }
    });
    s.on("error", reject);
  });
}

/** relay(무인증) 수신: MAIL/RCPT/DATA → 최종 코드. */
function relaySend(port: number, from: string, to: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const msg = `From: ${from}\r\nTo: ${to}\r\nSubject: alias test\r\n\r\nhi\r\n.\r\n`;
    const steps = [`EHLO t\r\n`, `MAIL FROM:<${from}>\r\n`, `RCPT TO:<${to}>\r\n`, `DATA\r\n`, msg];
    let stage = -1;
    let buf = "";
    const t = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 4000);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (line.startsWith("250-")) continue;
        // RCPT 거부(550)면 그 시점에 최종 반환
        if (line.startsWith("550")) { clearTimeout(t); s.write("QUIT\r\n"); s.end(); resolve(line); return; }
        if (stage === steps.length - 1) { clearTimeout(t); s.write("QUIT\r\n"); s.end(); resolve(line); return; }
        stage++;
        s.write(steps[stage]!);
      }
    });
    s.on("error", reject);
  });
}

/** POP3 STAT 메시지 수 반환. */
function pop3Count(port: number, user: string, pass: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const steps = [`USER ${user}\r\n`, `PASS ${pass}\r\n`, `STAT\r\n`];
    let stage = -1;
    let buf = "";
    const t = setTimeout(() => { s.destroy(); reject(new Error("timeout")); }, 4000);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (stage === steps.length - 1) {
          // STAT 응답: "+OK N size"
          clearTimeout(t); s.write("QUIT\r\n"); s.end();
          const m = line.match(/^\+OK (\d+)/);
          resolve(m ? Number(m[1]) : 0);
          return;
        }
        stage++;
        s.write(steps[stage]!);
      }
    });
    s.on("error", reject);
  });
}
