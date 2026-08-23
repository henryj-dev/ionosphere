/** SMTP AUTH XOAUTH2 / OAUTHBEARER — 토큰을 pass로 흘려 auth 액션 emit. */
import { describe, expect, test } from "@ionosphere/testkit";
import { SmtpEngine, type SmtpAction } from "../src/engine.ts";

const A = String.fromCharCode(1); // SASL 0x01 구분자 (소스에 제어문자 미포함)

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
function text(actions: SmtpAction[]): string {
  return actions
    .filter((a): a is Extract<SmtpAction, { kind: "reply" }> => a.kind === "reply")
    .map((a) => a.text)
    .join("");
}
function b64(s: string): string {
  return Buffer.from(s).toString("base64");
}
function engine(): SmtpEngine {
  const e = new SmtpEngine({ hostname: "mx.example.test", maxSizeBytes: 1_000_000, tlsAvailable: false, authOffered: true, allowInsecureAuth: true });
  e.greeting();
  e.feed(bytes("EHLO client.test\r\n"));
  return e;
}
function authOf(actions: SmtpAction[]) {
  return actions.find((a): a is Extract<SmtpAction, { kind: "auth" }> => a.kind === "auth");
}

const xoauth2 = (user: string, token: string) => b64(`user=${user}${A}auth=Bearer ${token}${A}${A}`);
const oauthbearer = (user: string, token: string) => b64(`n,a=${user},${A}auth=Bearer ${token}${A}${A}`);

describe("SMTP AUTH XOAUTH2/OAUTHBEARER", () => {
  test("EHLO가 XOAUTH2/OAUTHBEARER 광고", () => {
    const e = new SmtpEngine({ hostname: "mx.example.test", maxSizeBytes: 1_000_000, tlsAvailable: false, authOffered: true, allowInsecureAuth: true });
    e.greeting();
    expect(text(e.feed(bytes("EHLO c\r\n")))).toContain("AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER");
  });

  test("XOAUTH2 초기응답 → auth 액션(토큰=pass) → 235", () => {
    const e = engine();
    expect(authOf(e.feed(bytes(`AUTH XOAUTH2 ${xoauth2("alice@x.test", "tok-1")}\r\n`)))).toEqual({
      kind: "auth",
      user: "alice@x.test",
      pass: "tok-1",
    });
    expect(text(e.authResult(true))).toBe("235 2.7.0 Authentication successful\r\n");
  });

  test("OAUTHBEARER 빈 챌린지 continuation → 데이터 라인 → auth 액션", () => {
    const e = engine();
    expect(text(e.feed(bytes("AUTH OAUTHBEARER\r\n")))).toBe("334 \r\n");
    expect(authOf(e.feed(bytes(`${oauthbearer("bob@x.test", "tok-2")}\r\n`)))).toEqual({
      kind: "auth",
      user: "bob@x.test",
      pass: "tok-2",
    });
  });

  test("형식 오류(Bearer 없음) → 501", () => {
    const e = engine();
    expect(text(e.feed(bytes(`AUTH XOAUTH2 ${b64(`user=x${A}${A}`)}\r\n`)))).toStartWith("501");
  });
});
