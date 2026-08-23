/**
 * RFC 8463 Appendix A 고정 테스트 벡터. IETF Trust 라이선스는 RFC 코드 컴포넌트 인용을 허용한다.
 *
 * ★왜 벡터를 리포에 박아 두는가(2026-08-01 실사고): 이 패키지의 Ed25519 테스트는 전부
 * "우리가 서명한 것을 우리가 검증"하는 라운드트립이었다. 서명측과 검증측이 **똑같이 틀린**
 * 입력을 만들었으므로 자체 테스트는 늘 통과했고 외부 검증자만 실패했다 — 라이브 발송 메일
 * 전체가 Gmail에서 `dkim=fail header.s=ed1`이었다. **라운드트립은 이 종류의 규격 위반을
 * 구조적으로 잡을 수 없다.** 외부가 만든 서명이 반드시 필요하다.
 *
 * `*.test.ts`가 아니므로 `bun test`가 이 파일을 테스트로 실행하지 않는다.
 */
import { createPrivateKey, type KeyObject } from "node:crypto";

/** §A.1 Ed25519 비밀키 — RFC 8032 §7.1 Test1의 **RAW 32바이트 시드**(PKCS#8이 아니다). */
export const ED25519_SEED_B64 = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";

/** §A.2 Ed25519 공개키 DNS TXT. `p=`는 RAW 32바이트 base64(SPKI DER 아님 — RFC 8463 §3). */
export const ED25519_TXT = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

/** §A.2 RSA 공개키 DNS TXT — 대조군. 이쪽은 처음부터 정상이었다. */
export const RSA_TXT =
  "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08" +
  "a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM" +
  "KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB";

/**
 * §A.3 서명된 메시지 — 두 DKIM-Signature(Ed25519 + RSA)가 붙은 원문.
 *
 * ★줄 배열로 두는 이유: DKIM은 바이트 단위로 민감하다. 접힌 헤더의 연속 줄은 **선행 SP 한 칸**이며
 * (RFC 본문의 3칸 들여쓰기를 제거한 결과), 에디터가 탭으로 바꾸면 relaxed에서는 같아도 simple
 * 경로에서 달라진다. 한 줄 문자열로 적으면 그 공백이 조용히 훼손되므로 배열 + join으로 고정한다.
 */
const MESSAGE_LINES: readonly string[] = [
  "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;",
  " d=football.example.com; i=@football.example.com;",
  " q=dns/txt; s=brisbane; t=1528637909; h=from : to :",
  " subject : date : message-id : from : subject : date;",
  " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;",
  " b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus",
  " Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==",
  "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;",
  " d=football.example.com; i=@football.example.com;",
  " q=dns/txt; s=test; t=1528637909; h=from : to : subject :",
  " date : message-id : from : subject : date;",
  " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;",
  " b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3",
  " DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz",
  " dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=",
  "From: Joe SixPack <joe@football.example.com>",
  "To: Suzie Q <suzie@shopping.example.net>",
  "Subject: Is dinner ready?",
  "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)",
  "Message-ID: <20030712040037.46341.5F8J@football.example.com>",
  "",
  "Hi.",
  "",
  "We lost the game.  Are you hungry yet?",
  "",
  "Joe.",
  "",
];

/** §A.3 원문(CRLF 결합). 마지막 빈 줄이 본문 종료 CRLF를 만든다. */
export const MESSAGE = MESSAGE_LINES.join("\r\n");

/** §A.3 두 서명이 공유하는 본문 해시 — 본문 정규화 경로를 따로 고정하는 데 쓴다. */
export const BODY_HASH = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=";

/** §A.3의 셀렉터. Ed25519는 brisbane, RSA는 test. */
export const ED25519_SELECTOR = "brisbane";
export const RSA_SELECTOR = "test";
export const DOMAIN = "football.example.com";

/**
 * §A.1의 RAW 시드를 node가 받는 KeyObject로 만든다.
 *
 * node는 PKCS#8 또는 JWK만 받고 RAW 시드는 직접 못 받는다. JWK 경로는 `x`(공개키)도 요구하므로
 * §A.2의 공개키를 함께 넣는다 — 둘이 짝이 아니면 임포트가 아니라 **서명 검증**에서 틀어지므로,
 * 테스트가 그 짝 맞음을 먼저 단언한다(픽스처 신뢰성 검사).
 */
export function ed25519PrivateKey(): KeyObject {
  const seed = Buffer.from(ED25519_SEED_B64, "base64");
  const pub = Buffer.from(ED25519_TXT.slice(ED25519_TXT.indexOf("p=") + 2), "base64");
  return createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d: seed.toString("base64url"), x: pub.toString("base64url") },
    format: "jwk",
  });
}

/** 셀렉터별 TXT 레코드를 돌려주는 resolveTxt — `dkimVerify`에 주입한다. */
export function resolveTxt(name: string): Promise<string[]> {
  if (name === `${ED25519_SELECTOR}._domainkey.${DOMAIN}`) return Promise.resolve([ED25519_TXT]);
  if (name === `${RSA_SELECTOR}._domainkey.${DOMAIN}`) return Promise.resolve([RSA_TXT]);
  return Promise.reject(new Error(`unexpected TXT lookup: ${name}`));
}
