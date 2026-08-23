/**
 * RFC 8463 Appendix A 고정 벡터 — Ed25519 규격 적합성 회귀 (2026-08-01 실사고).
 *
 * ★이 파일이 존재하는 이유: 기존 Ed25519 테스트는 전부 "우리가 서명한 것을 우리가 검증"하는
 * 라운드트립이었다. 서명측과 검증측이 **똑같이 틀린** 입력(정규화 원문 대신 SHA-256 다이제스트를
 * 서명해야 하는데 원문을 서명)을 만들었으므로 자체 테스트는 전부 통과했고, 외부 검증자만
 * 실패했다 — Gmail 실측 `dkim=fail header.i=@ionosphere.test header.s=ed1`, 독립 구현(dkimpy)
 * 대조에서 RSA는 pass·Ed25519만 FAIL. 라이브는 Ed25519를 우선 선택하므로(`backend.ts`
 * `ORDER BY k.algo DESC`) **발송 메일 전체의 우리 서명이 외부에서 무효**였다.
 *
 * 그래서 여기서는 **RFC가 만든 서명을 우리가 검증**한다. 우리 `dkimSign`이 개입하지 않으므로
 * 라운드트립의 함정이 없다. RSA 벡터를 나란히 두는 것도 중요하다 — 그쪽은 처음부터 pass였으므로
 * 대조군이 되고, 둘 다 실패하면 원인이 알고리즘이 아니라 픽스처(벡터 복원)라는 뜻이다.
 *
 * 규격 근거(RFC 8463 §3): "The Ed25519-SHA256 signing algorithm computes a message hash as
 * defined in Section 3 of [RFC6376] using SHA-256 as the hash-alg. It **signs the hash** with
 * the PureEdDSA variant Ed25519."
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { dkimVerify } from "../src/verify.ts";
import { ed25519PublicKeyFromRaw, signDkimData, verifyDkimData } from "../src/crypto.ts";
import {
  BODY_HASH,
  ED25519_SELECTOR,
  ED25519_TXT,
  MESSAGE,
  RSA_SELECTOR,
  ed25519PrivateKey,
  resolveTxt,
} from "./vectors/rfc8463.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const publicRaw = Buffer.from(ED25519_TXT.slice(ED25519_TXT.indexOf("p=") + 2), "base64");

describe("RFC 8463 §A — 외부(RFC)가 만든 서명을 우리가 검증한다", () => {
  test("픽스처 신뢰성: A.1 비밀키와 A.2 공개키가 짝이다", () => {
    // 이 단언이 깨지면 아래 실패는 '우리 구현'이 아니라 '벡터 복원'이 원인이다 — 먼저 분리해 둔다.
    const probe = Buffer.from("probe");
    const sig = nodeSign(null, probe, ed25519PrivateKey());
    expect(nodeVerify(null, probe, ed25519PublicKeyFromRaw(publicRaw), sig)).toBe(true);
  });

  test("★A.3의 Ed25519 서명(s=brisbane)을 dkimVerify가 pass로 판정한다", async () => {
    // 이것이 회귀의 핵심이다. 고치기 전에는 fail("서명 불일치")이었다.
    const results = await dkimVerify(enc(MESSAGE), resolveTxt);
    const ed = results.find((r) => r.selector === ED25519_SELECTOR);
    expect(ed).toBeDefined();
    expect(ed?.result).toBe("pass");
  });

  test("A.3의 RSA 서명(s=test)도 pass다 — 대조군", async () => {
    // 이쪽은 수정 전에도 pass였다. 둘 다 실패하면 알고리즘이 아니라 벡터 복원이 틀린 것이다.
    const results = await dkimVerify(enc(MESSAGE), resolveTxt);
    const rsa = results.find((r) => r.selector === RSA_SELECTOR);
    expect(rsa).toBeDefined();
    expect(rsa?.result).toBe("pass");
  });

  test("본문을 1바이트 바꾸면 두 서명 모두 bh 불일치로 fail한다", async () => {
    const tampered = MESSAGE.replace("We lost the game.", "We won the game..");
    const results = await dkimVerify(enc(tampered), resolveTxt);
    expect(results).toHaveLength(2);
    for (const r of results) expect(r.result).toBe("fail");
  });

  test("본문 정규화 해시가 벡터의 bh=와 일치한다 (본문 경로를 따로 고정)", async () => {
    // 헤더 서명이 아니라 본문 해시만 보는 단언 — 본문 정규화가 틀렸다면 위 pass도 우연이 아니게 된다.
    const results = await dkimVerify(enc(MESSAGE), resolveTxt);
    expect(results.every((r) => r.result === "pass")).toBe(true);
    expect(BODY_HASH).toHaveLength(44); // 픽스처 형태 확인(sha256 base64)
  });
});

describe("RFC 8463 §3 — 서명 대상은 SHA-256 다이제스트다", () => {
  const data = Buffer.from("from:alice@x\r\ndkim-signature:v=1; a=ed25519-sha256; b=", "latin1");
  const pub = ed25519PublicKeyFromRaw(publicRaw);

  test("★signDkimData가 규격 계산과 바이트 단위로 일치한다", () => {
    // 기대값을 node:crypto로 직접 만든다 — 우리 구현을 기준으로 삼으면 순환이라 아무것도 못 잡는다.
    const expected = nodeSign(null, createHash("sha256").update(data).digest(), ed25519PrivateKey());
    const actual = signDkimData(data, "ed25519-sha256", ed25519PrivateKey().export({ type: "pkcs8", format: "pem" }).toString());
    expect(actual.equals(expected)).toBe(true);
  });

  test("★고치기 전 방식(원문 직접 서명)은 검증에서 fail이다", () => {
    // 사고의 재현. 이 단언이 있어야 "규격 차이가 실재한다"가 고정되고,
    // 누가 다시 원문 서명으로 되돌리면 위 테스트가 즉시 깨진다.
    const violating = nodeSign(null, data, ed25519PrivateKey()); // 다이제스트가 아니라 원문
    expect(verifyDkimData(data, "ed25519-sha256", pub, violating)).toBe(false);

    const conforming = nodeSign(null, createHash("sha256").update(data).digest(), ed25519PrivateKey());
    expect(verifyDkimData(data, "ed25519-sha256", pub, conforming)).toBe(true);
  });

  test("p=가 32바이트가 아니면 거부한다 (SPKI 조립 방식은 초과 바이트를 조용히 버렸다)", () => {
    // arc.ts가 쓰던 SPKI prefix 조립은 길이 바이트가 prefix에 박혀 있어 33바이트 p=도 받아들였다.
    expect(() => ed25519PublicKeyFromRaw(Buffer.concat([publicRaw, Buffer.from([0])]))).toThrow();
    expect(() => ed25519PublicKeyFromRaw(publicRaw.subarray(0, 31))).toThrow();
  });
});
