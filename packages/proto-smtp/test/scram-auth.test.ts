/**
 * SMTP AUTH SCRAM-SHA-256 — 엔진 배선 검증.
 *
 * 여기서 고정하는 계약:
 *  ① 백엔드가 SCRAM을 못 하면 **광고하지 않는다**(끝낼 수 없는 교환을 시작하지 않는다)
 *  ② 성공 경로: client-first → server-first → client-final → **server-final(334)** → 235
 *     ★server-final을 334로 따로 보내는 것이 요점이다 — 클라이언트가 **서버를 검증**한다
 *  ③ 없는 계정도 교환이 끝까지 진행된다(열거 방어)
 *  ④ 증명이 틀리면 535
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { deriveScramKeys, type ScramStoredKeys } from "@ionosphere/core";
import { SmtpEngine, type SmtpAction } from "../src/engine.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const b64 = (s: string): string => Buffer.from(s).toString("base64");

function texts(actions: SmtpAction[]): string {
  return actions.filter((a) => a.kind === "reply").map((a) => (a as { text: string }).text).join("");
}
function kinds(actions: SmtpAction[]): string[] {
  return actions.map((a) => a.kind);
}

function newEngine(scramOffered: boolean): SmtpEngine {
  return new SmtpEngine({
    hostname: "mx.test",
    maxSizeBytes: 1_000_000,
    tlsAvailable: false,
    profile: "submission",
    authOffered: true,
    allowInsecureAuth: true, // 테스트는 평문 — TLS 게이트는 별도 테스트가 덮는다
    scramOffered,
    scramDecoySecret: randomBytes(32),
  });
}

/** EHLO까지 진행하고 응답을 돌려준다. */
function greet(e: SmtpEngine): string {
  e.greeting();
  return texts(e.feed(enc("EHLO client\r\n")));
}

/** 클라이언트 쪽 proof 계산. */
function proofFor(password: string, salt: Buffer, iterations: number, authMessage: string): string {
  const salted = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const sig = createHmac("sha256", storedKey).update(authMessage).digest();
  const p = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) p[i] = clientKey[i]! ^ sig[i]!;
  return p.toString("base64");
}

describe("SMTP AUTH SCRAM-SHA-256 — 광고", () => {
  test("★백엔드가 SCRAM을 못 하면 광고하지 않는다", () => {
    expect(greet(newEngine(false))).not.toContain("SCRAM-SHA-256");
  });

  test("광고할 때는 SCRAM이 **앞에** 온다 — 클라이언트가 순서를 선호도로 읽는다", () => {
    const ehlo = greet(newEngine(true));
    expect(ehlo).toContain("SCRAM-SHA-256");
    const line = ehlo.split("\r\n").find((l) => l.includes("AUTH ")) ?? "";
    expect(line.indexOf("SCRAM-SHA-256")).toBeLessThan(line.indexOf("PLAIN"));
  });

  test("광고하지 않으면 시도해도 504 — 못 끝낼 교환을 시작하지 않는다", () => {
    const e = newEngine(false);
    greet(e);
    expect(texts(e.feed(enc("AUTH SCRAM-SHA-256\r\n")))).toContain("504");
  });
});

describe("SMTP AUTH SCRAM-SHA-256 — 교환", () => {
  test("★성공: client-final 뒤 334 server-final이 오고, 빈 응답에 235로 닫는다", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    greet(e);

    // client-first
    const clientNonce = "abcdefgh1234";
    const a1 = e.feed(enc(`AUTH SCRAM-SHA-256 ${b64(`n,,n=user,r=${clientNonce}`)}\r\n`));
    expect(kinds(a1)).toContain("scramKeys");

    // 어댑터가 키를 돌려준다
    const a2 = e.scramKeysResult(keys as ScramStoredKeys);
    const serverFirst = Buffer.from(texts(a2).replace(/^334 /, "").trim(), "base64").toString();
    expect(serverFirst).toMatch(/^r=.+,s=.+,i=4096$/);

    const fullNonce = /r=([^,]+)/.exec(serverFirst)![1]!;
    const salt = Buffer.from(/s=([^,]+)/.exec(serverFirst)![1]!, "base64");
    const withoutProof = `c=biws,r=${fullNonce}`;
    const authMessage = `n=user,r=${clientNonce},${serverFirst},${withoutProof}`;
    const p = proofFor("pencil", salt, 4096, authMessage);

    // client-final → 334 server-final (235가 아니다!)
    const a3 = e.feed(enc(`${b64(`${withoutProof},p=${p}`)}\r\n`));
    const t3 = texts(a3);
    expect(t3.startsWith("334 ")).toBe(true);
    const serverFinal = Buffer.from(t3.replace(/^334 /, "").trim(), "base64").toString();
    // ★클라이언트는 이 값으로 서버를 검증한다. 235만 보내면 그 기회가 없다.
    expect(serverFinal.startsWith("v=")).toBe(true);

    // 클라이언트의 빈 응답 → authVerified 액션
    const a4 = e.feed(enc("\r\n"));
    expect(kinds(a4)).toContain("authVerified");

    // 어댑터가 승인 → 235
    expect(texts(e.authResult(true))).toContain("235");
  });

  test("★증명이 틀리면 535 (server-final을 주지 않는다)", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    greet(e);
    e.feed(enc(`AUTH SCRAM-SHA-256 ${b64("n,,n=user,r=nonce1234")}\r\n`));
    const a2 = e.scramKeysResult(keys as ScramStoredKeys);
    const serverFirst = Buffer.from(texts(a2).replace(/^334 /, "").trim(), "base64").toString();
    const fullNonce = /r=([^,]+)/.exec(serverFirst)![1]!;
    const bogus = Buffer.alloc(32, 9).toString("base64");
    const a = e.feed(enc(`${b64(`c=biws,r=${fullNonce},p=${bogus}`)}\r\n`));
    const t = texts(a);
    expect(t).toContain("535");
    expect(t).not.toContain("334");
    /**
     * ★거절 응답만으로는 부족하다 — **어댑터가 볼 액션**이 나와야 한다.
     * 예전엔 여기서 reply만 나왔고, 어댑터의 스로틀·감사는 `authVerified` 케이스 안에 있어서
     * 실행되지 않았다. 결과는 SCRAM으로 무제한 대입이 **무기록**으로 가능한 상태였다.
     */
    expect(kinds(a)).toContain("authFailed");
    const failed = a.find((x) => x.kind === "authFailed") as { user?: string; mechanism: string };
    expect(failed.user).toBe("user");
    expect(failed.mechanism).toBe("SCRAM-SHA-256");
  });

  test("★없는 계정도 server-first를 받는다 — 열거 방어", () => {
    const e = newEngine(true);
    greet(e);
    e.feed(enc(`AUTH SCRAM-SHA-256 ${b64("n,,n=ghost@x.test,r=nonce1234")}\r\n`));
    // 어댑터가 "없다"고 null을 줘도 교환은 계속된다.
    const t = texts(e.scramKeysResult(null));
    expect(t.startsWith("334 ")).toBe(true);
    const serverFirst = Buffer.from(t.replace(/^334 /, "").trim(), "base64").toString();
    expect(serverFirst).toMatch(/^r=.+,s=.+,i=\d+$/);
  });

  test("초기 응답 없이 시작하면 빈 334로 client-first를 기다린다", () => {
    const e = newEngine(true);
    greet(e);
    expect(texts(e.feed(enc("AUTH SCRAM-SHA-256\r\n")))).toContain("334");
    const a = e.feed(enc(`${b64("n,,n=user,r=nonce1234")}\r\n`));
    expect(kinds(a)).toContain("scramKeys");
  });

  test("깨진 base64·client-first는 거절한다", () => {
    const e = newEngine(true);
    greet(e);
    expect(texts(e.feed(enc("AUTH SCRAM-SHA-256 !!!notbase64!!!\r\n")))).toMatch(/50[15]/);

    const e2 = newEngine(true);
    greet(e2);
    expect(texts(e2.feed(enc(`AUTH SCRAM-SHA-256 ${b64("garbage")}\r\n`)))).toContain("535");
  });

  test("AUTH 취소(*)는 교환을 끝낸다", () => {
    const e = newEngine(true);
    greet(e);
    e.feed(enc("AUTH SCRAM-SHA-256\r\n"));
    expect(texts(e.feed(enc("*\r\n")))).toContain("501");
  });
});
