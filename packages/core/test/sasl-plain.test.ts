/**
 * SASL PLAIN 정본 파서 — 4개 프로토콜(SMTP/IMAP/POP3/ManageSieve)이 공유하는 단일 구현.
 *
 * 통합 전엔 엔진마다 규칙이 달랐다:
 *  - SMTP  : 엄격 base64 + 바이트 indexOf (정확)
 *  - IMAP  : 재인코딩 왕복 + 문자열 indexOf
 *  - POP3  : 재인코딩 왕복 + split 후 length!==3  → 비밀번호에 NUL 있으면 **실패**
 *  - ManageSieve: base64 검증 **없음** + split      → 불량 base64를 조용히 절단 수용
 * 그 결과 같은 비밀번호가 IMAP에선 되고 POP3에선 안 되는 상태였다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { decodeSaslBase64, decodeSaslPlain, parseSaslPlain } from "@ionosphere/core";

const NUL = String.fromCharCode(0);
const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

describe("parseSaslPlain (RFC 4616)", () => {
  test("authzid NUL authcid NUL passwd", () => {
    const creds = decodeSaslPlain(b64(`${NUL}alice@x.test${NUL}s3cret`));
    expect(creds).toEqual({ user: "alice@x.test", pass: "s3cret" });
  });

  test("authzid가 있어도 무시하고 authcid를 쓴다", () => {
    const creds = decodeSaslPlain(b64(`admin${NUL}alice@x.test${NUL}pw`));
    expect(creds?.user).toBe("alice@x.test");
  });

  test("★비밀번호에 NUL이 포함돼도 통과한다(두 번째 NUL 이후 전부가 비밀번호)", () => {
    // split 기반 구현(POP3/ManageSieve 옛 코드)은 여기서 parts.length가 4가 되어 거부했다.
    const creds = decodeSaslPlain(b64(`${NUL}bob@x.test${NUL}pa${NUL}ss`));
    expect(creds).toEqual({ user: "bob@x.test", pass: `pa${NUL}ss` });
  });

  test("빈 비밀번호는 허용(계정 정책이 아니라 파싱 계약)", () => {
    expect(decodeSaslPlain(b64(`${NUL}u@x.test${NUL}`))).toEqual({ user: "u@x.test", pass: "" });
  });

  test("authcid가 비면 null", () => {
    expect(decodeSaslPlain(b64(`${NUL}${NUL}pw`))).toBeNull();
  });

  test("NUL이 부족하면 null", () => {
    expect(decodeSaslPlain(b64("noseparator"))).toBeNull();
    expect(decodeSaslPlain(b64(`only${NUL}one`))).toBeNull();
  });

  test("UTF-8 멀티바이트 비밀번호가 깨지지 않는다", () => {
    const creds = decodeSaslPlain(b64(`${NUL}한글@x.test${NUL}비밀번호🔐`));
    expect(creds).toEqual({ user: "한글@x.test", pass: "비밀번호🔐" });
  });
});

describe("decodeSaslBase64 (엄격 검증)", () => {
  test("정상 base64", () => {
    expect(decodeSaslBase64(b64("hi"))).toEqual(new Uint8Array([0x68, 0x69]));
  });

  test("★불량 base64는 조용히 절단하지 않고 null (ManageSieve 옛 구현의 구멍)", () => {
    expect(decodeSaslBase64("!!!!")).toBeNull();
    expect(decodeSaslBase64("abc")).toBeNull(); // 길이 4의 배수 아님
    expect(decodeSaslBase64("a=bc")).toBeNull(); // 잘못된 패딩 위치
  });

  test("빈 문자열은 빈 바이트열(초기 응답 없음)", () => {
    expect(decodeSaslBase64("")).toEqual(new Uint8Array([]));
  });

  test("parseSaslPlain은 바이트를 직접 받는다(디코딩과 분리)", () => {
    const bytes = decodeSaslBase64(b64(`${NUL}u@x.test${NUL}pw`));
    expect(bytes).not.toBeNull();
    expect(parseSaslPlain(bytes!)).toEqual({ user: "u@x.test", pass: "pw" });
  });
});
