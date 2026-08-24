/**
 * SCRAM 재개 시 버퍼 처리 회귀.
 *
 * 엔진의 `xxxResult()` 넷 중 `scramKeysResult()`만 `pump()`와 `guardErrors()`를 거치지
 * 않았다. `awaiting="scramKeys"`(백엔드 키 조회 대기) 동안 도착한 바이트는 버퍼에 쌓이는데,
 * 재개 시점에 아무도 그것을 꺼내지 않았다.
 *
 * ★영향 범위를 정확히 적어 둔다: AUTH 진행 중 다음 줄은 **SASL 데이터**이므로 임의 명령을
 * 파이프라인할 수는 없다(그건 base64로 해석되는 게 맞다). 실제로 이 창에 올 수 있는 것은
 * **SASL 취소(`*`, RFC 4954 §4)** 다 — 클라이언트가 AUTH를 보낸 직후 마음을 바꿔 취소를
 * 붙여 보내면, 그 줄이 버퍼에 남아 501이 나가지 않고 클라이언트는 유휴 타임아웃(5분)까지
 * 기다린다.
 *
 * 두 번째 결과가 더 넓다: `guardErrors()`를 건너뛰므로 이 경로의 4xx/5xx가
 * `MAX_SMTP_ERRORS_PER_SESSION`에 세어지지 않았다. 그 함수 주석이 "공개 메서드는 **전부**
 * 반환 직전에 이 함수를 통과한다 … 새는 갈래 하나가 곧 무제한 오라클"이라고 못 박은 계약이다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { SmtpEngine } from "@ionosphere/proto-smtp";

const CRLF = "\r\n";
const CLIENT_FIRST = Buffer.from("n,,n=user,r=abcdefgh").toString("base64");

function greeted(): SmtpEngine {
  const e = new SmtpEngine({
    hostname: "h.test",
    maxSizeBytes: 1000,
    tlsAvailable: false,
    authOffered: true,
    allowInsecureAuth: true,
    scramOffered: true,
  });
  e.greeting();
  e.feed(Buffer.from(`EHLO x${CRLF}`));
  return e;
}

function replies(actions: readonly { kind: string }[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}

describe("scramKeysResult 재개", () => {
  test("키 조회 대기 중 도착한 SASL 취소를 재개 시점에 처리한다", () => {
    const e = greeted();
    // AUTH와 취소를 한 세그먼트로 — 취소는 키 조회를 기다리는 동안 버퍼에 쌓인다.
    e.feed(Buffer.from(`AUTH SCRAM-SHA-256 ${CLIENT_FIRST}${CRLF}*${CRLF}`));
    const out = replies(e.scramKeysResult(null));
    expect(out.some((t) => t.startsWith("334 "))).toBe(true); // server-first
    expect(out.some((t) => t.startsWith("501 5.7.0"))).toBe(true); // 취소 응답 — 예전엔 안 나갔다
  });

  test("취소 뒤에는 평범한 명령이 다시 동작한다(세션이 살아 있다)", () => {
    const e = greeted();
    e.feed(Buffer.from(`AUTH SCRAM-SHA-256 ${CLIENT_FIRST}${CRLF}*${CRLF}`));
    e.scramKeysResult(null);
    expect(replies(e.feed(Buffer.from(`NOOP${CRLF}`)))).toEqual(["250 2.0.0 OK\r\n"]);
  });

  test("키가 없어도(계정 없음) 교환은 계속된다 — 열거 방어", () => {
    const e = greeted();
    e.feed(Buffer.from(`AUTH SCRAM-SHA-256 ${CLIENT_FIRST}${CRLF}`));
    const out = replies(e.scramKeysResult(null));
    // 가짜 salt로 정상 형태의 server-first가 나가야 한다(즉시 535가 아니다).
    expect(out.some((t) => t.startsWith("334 "))).toBe(true);
    expect(out.some((t) => t.startsWith("535"))).toBe(false);
  });

  /**
   * 오류 상한이 이 경로를 통과하는가 — `guardErrors()`를 거치지 않으면 상한을 넘겨도
   * 세션이 살아남는다. 재개 경로가 곧 무제한 오라클이 되는 자리다.
   */
  test("재개 경로도 세션 오류 상한을 통과한다", () => {
    const e = greeted();
    // 알 수 없는 명령으로 상한(20) 직전까지 오류를 쌓는다.
    for (let i = 0; i < 20; i++) e.feed(Buffer.from(`BOGUS${CRLF}`));
    e.feed(Buffer.from(`AUTH SCRAM-SHA-256 ${CLIENT_FIRST}${CRLF}*${CRLF}`));
    const out = replies(e.scramKeysResult(null));
    expect(out.some((t) => t.startsWith("421"))).toBe(true);
  });
});
