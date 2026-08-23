/**
 * 봉투 주소 안전성 — SMTP **명령 줄에 그대로 실리는 값**이라 별도 검증이 필요하다.
 *
 * 왜 필요한가: 수신 엔진은 CRLF로만 줄을 자르므로 `MAIL FROM:<a\nb@c>` 처럼 **단일 LF**가
 * 주소 안에 그대로 남는다(정규식 `<([^>]*)>`는 LF를 걸러내지 않는다). 그 값이 큐를 거쳐
 * `MAIL FROM:<...>` / `RCPT TO:<...>`로 나가면, bare-LF를 줄 종료로 받아들이는 상대 MTA·
 * 스마트호스트에서 **임의 SMTP 명령이 주입된다**(추가 RCPT 등 — 우리 쪽 수신자 회계·
 * suppression·과금을 우회한다).
 *
 * 수신 방향은 DATA 종료를 CRLF로만 인정해 스무글링을 막아 두었는데, 발신 방향에만 같은
 * 엄격함이 없었다. 그래서 여기서 대칭을 맞춘다.
 *
 * 적재 시점과 전송 시점 **양쪽**에서 쓴다 — 이 수정 이전에 이미 DB에 들어간 값이 있을 수 있어
 * 적재 검증만으로는 부족하다.
 */

/**
 * 주소에 있으면 안 되는 문자.
 *  - CR/LF: 명령 줄 주입의 본체
 *  - NUL: 일부 파서가 문자열을 절단해 검증을 우회하게 만든다
 *  - `<` `>`: 우리가 감싸는 꺾쇠와 충돌해 파라미터 경계를 흔든다
 *  - 공백: `MAIL FROM:<a b>`는 뒤가 ESMTP 파라미터로 읽힐 수 있다
 */
const UNSAFE_ENVELOPE_CHARS = /[\r\n\u0000<> ]/;

/** 봉투 주소로 안전한가. 빈 문자열(null sender `<>`)은 허용된다. */
export function isSafeEnvelopeAddress(address: string): boolean {
  return !UNSAFE_ENVELOPE_CHARS.test(address);
}

/** 안전하지 않은 첫 주소를 돌려준다(없으면 null). 진단 메시지에 쓸 값을 같이 준다. */
export function findUnsafeAddress(addresses: readonly string[]): string | null {
  for (const a of addresses) {
    if (!isSafeEnvelopeAddress(a)) return a;
  }
  return null;
}
