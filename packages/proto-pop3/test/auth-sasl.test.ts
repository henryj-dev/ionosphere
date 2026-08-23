/** POP3 SASL AUTH (RFC 5034) — PLAIN/XOAUTH2/OAUTHBEARER. 토큰은 pass로 흘러 authenticate가 검증. */
import { describe, expect, test } from "@ionosphere/testkit";
import { Pop3Engine, type Pop3Action } from "../src/engine.ts";

// 이 파일은 **프로토콜 흐름**을 검사한다(TLS 정책이 아니라). RFC 8314 게이트가 기본 차단이라
// 평문 엔진으로는 인증 단계에 들어갈 수 없으므로 allowInsecureAuth로 명시 완화한다.
// TLS 정책 자체는 apps/server/test/pop3-secure.test.ts가 검증한다.

const enc = new TextEncoder();
const A = String.fromCharCode(1); // SASL 0x01
const NUL = String.fromCharCode(0);

function engine(): Pop3Engine {
  const e = new Pop3Engine({ hostname: "pop.test", allowInsecureAuth: true });
  e.greeting();
  return e;
}
function feed(e: Pop3Engine, line: string): Pop3Action[] {
  return e.feed(enc.encode(`${line}\r\n`));
}
function replies(a: Pop3Action[]): string[] {
  return a.filter((x): x is { kind: "reply"; text: string } => x.kind === "reply").map((x) => x.text);
}
function authOf(a: Pop3Action[]) {
  return a.find((x): x is Extract<Pop3Action, { kind: "auth" }> => x.kind === "auth");
}
const b64 = (s: string) => Buffer.from(s).toString("base64");
const xoauth2 = (u: string, t: string) => b64(`user=${u}${A}auth=Bearer ${t}${A}${A}`);
const oauthbearer = (u: string, t: string) => b64(`n,a=${u},${A}auth=Bearer ${t}${A}${A}`);

describe("POP3 SASL AUTH", () => {
  test("CAPA가 SASL 메커니즘 광고", () => {
    expect(replies(feed(engine(), "CAPA"))[0]).toContain("SASL PLAIN XOAUTH2 OAUTHBEARER");
  });

  test("AUTH(인자 없음) → 메커니즘 목록", () => {
    const out = replies(feed(engine(), "AUTH"))[0]!;
    expect(out).toContain("XOAUTH2");
    expect(out).toContain("OAUTHBEARER");
    expect(out).toContain("PLAIN");
  });

  test("XOAUTH2 초기응답 → auth 액션(토큰=pass) → 성공 시 openMaildrop", () => {
    const e = engine();
    expect(authOf(feed(e, `AUTH XOAUTH2 ${xoauth2("bob@x.test", "tok-1")}`))).toEqual({ kind: "auth", user: "bob@x.test", pass: "tok-1" });
    expect(e.authResult({ accountId: "acc" })).toEqual([{ kind: "openMaildrop" }]);
  });

  test("OAUTHBEARER continuation('+ ' 후 데이터 라인)", () => {
    const e = engine();
    expect(replies(feed(e, "AUTH OAUTHBEARER"))).toEqual(["+ "]);
    expect(authOf(feed(e, oauthbearer("carol@x.test", "tok-2")))).toEqual({ kind: "auth", user: "carol@x.test", pass: "tok-2" });
  });

  test("PLAIN 초기응답", () => {
    const e = engine();
    expect(authOf(feed(e, `AUTH PLAIN ${b64(`${NUL}alice${NUL}pw`)}`))).toEqual({ kind: "auth", user: "alice", pass: "pw" });
  });

  test("잘못된 토큰 → 백엔드 거부(authResult null → -ERR)", () => {
    const e = engine();
    feed(e, `AUTH XOAUTH2 ${xoauth2("bob@x.test", "bad")}`);
    expect(replies(e.authResult(null))[0]).toContain("-ERR [AUTH]");
  });

  test("미지원 메커니즘 / 형식 오류 / 취소", () => {
    expect(replies(feed(engine(), "AUTH SCRAM-SHA-256"))[0]).toContain("unsupported");
    const e2 = engine();
    expect(replies(feed(e2, `AUTH XOAUTH2 ${b64(`user=x${A}${A}`)}`))[0]).toContain("-ERR [AUTH]"); // Bearer 없음
    const e3 = engine();
    feed(e3, "AUTH XOAUTH2");
    expect(replies(feed(e3, "*"))[0]).toContain("cancelled");
  });
});
