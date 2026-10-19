/**
 * SASLprep (RFC 4013) — 비밀번호를 해시하거나 SCRAM 키를 만들기 전에 거치는 정규화.
 *
 * 왜 NFC가 아니라 SASLprep인가(2026-10-18 회원 공통 수치 결정 2, ionosphere 제품 예외): SCRAM-SHA-256(RFC 5802 §2.2,
 * RFC 7677)은 클라이언트가 SASLprep으로 정규화한 비밀번호로 증명을 만든다. 서버가 다른 정규화로 키를 만들면
 * 비ASCII 비밀번호의 SCRAM이 깨진다. 다른 서비스들은 NFC를 쓰고, ionosphere만 이 규칙을 쓴다.
 *
 * 단계(RFC 4013 §2): ① 매핑(ASCII가 아닌 공백 → U+0020, "보통 지우는 문자"(RFC 3454 B.1) → 삭제) ② NFKC
 * ③ 금지 문자(C.1.2·C.2.1·C.2.2·C.3~C.9) 검사 ④ 양방향 문자 규칙(RFC 3454 §6) ⑤ 저장용이면 미할당 코드포인트 금지.
 *
 * ⚠ 근사 두 가지(의존성 0 원칙 때문에 Unicode 3.2 표 전체를 싣지 않는다):
 *  - 미할당 판정(⑤)은 RFC 3454 A.1(Unicode 3.2) 대신 지금 엔진의 `\p{Cn}`을 쓴다. 3.2 뒤에 할당된 문자는 허용된다.
 *  - 양방향 규칙의 "L 문자"(D.2)는 표 대신 `\p{L}` 가운데 RandAL(D.1)이 아닌 것으로 본다. D.1은 RFC 표 그대로다.
 *  ASCII 비밀번호는 어느 근사에도 걸리지 않는다(①~⑤ 모두 그대로 통과).
 *
 * 실패(금지 문자·양방향 위반)는 `null`이다. 호출자는 새 비밀번호면 거절하고, 로그인 입력이면 원문으로 검증한다.
 */

/** RFC 3454 C.1.2 — ASCII가 아닌 공백. SASLprep은 이것을 U+0020으로 바꾼다. */
const NON_ASCII_SPACE = new RegExp("[\\u00A0\\u1680\\u2000-\\u200B\\u202F\\u205F\\u3000]", "gu");

/** RFC 3454 B.1 — 보통 지우는 문자(제어 성격의 결합·이형 선택자 등). U+200B는 위 공백 매핑이 먼저 가져간다. */
const MAPPED_TO_NOTHING = new RegExp("[\\u00AD\\u034F\\u1806\\u180B-\\u180D\\u200C\\u200D\\u2060\\uFE00-\\uFE0F\\uFEFF]", "gu");

/**
 * 금지 문자 — RFC 3454 C.1.2(매핑 뒤엔 남지 않지만 NFKC가 다시 만들 수 있어 함께 본다), C.2.1·C.2.2(제어), C.3(사용자 정의),
 * C.4(비문자), C.5(대리 코드), C.6(평문에 부적절), C.7(정규 표기에 부적절), C.8(표시 속성 변경·사용 중단), C.9(태그).
 */
const PROHIBITED = new RegExp(
  [
    "[\\u00A0\\u1680\\u2000-\\u200B\\u202F\\u205F\\u3000]", // C.1.2
    "[\\u0000-\\u001F\\u007F]", // C.2.1
    "[\\u0080-\\u009F\\u06DD\\u070F\\u180E\\u200C\\u200D\\u2028\\u2029\\u2060-\\u2063\\u206A-\\u206F\\uFEFF\\uFFF9-\\uFFFC\\u{1D173}-\\u{1D17A}]", // C.2.2
    "[\\uE000-\\uF8FF\\u{F0000}-\\u{FFFFD}\\u{100000}-\\u{10FFFD}]", // C.3
    "[\\uFDD0-\\uFDEF\\uFFFE\\uFFFF\\u{1FFFE}\\u{1FFFF}\\u{2FFFE}\\u{2FFFF}\\u{3FFFE}\\u{3FFFF}\\u{4FFFE}\\u{4FFFF}\\u{5FFFE}\\u{5FFFF}\\u{6FFFE}\\u{6FFFF}\\u{7FFFE}\\u{7FFFF}\\u{8FFFE}\\u{8FFFF}\\u{9FFFE}\\u{9FFFF}\\u{AFFFE}\\u{AFFFF}\\u{BFFFE}\\u{BFFFF}\\u{CFFFE}\\u{CFFFF}\\u{DFFFE}\\u{DFFFF}\\u{EFFFE}\\u{EFFFF}\\u{FFFFE}\\u{FFFFF}\\u{10FFFE}\\u{10FFFF}]", // C.4
    "[\\uD800-\\uDFFF]", // C.5 — u 플래그에서 짝이 맞는 대리쌍은 코드포인트 하나라 걸리지 않고, 홀로 남은 대리 코드만 걸린다
    "[\\uFFF9-\\uFFFD]", // C.6
    "[\\u2FF0-\\u2FFB]", // C.7
    "[\\u0340\\u0341\\u200E\\u200F\\u202A-\\u202E\\u206A-\\u206F]", // C.8
    "[\\u{E0001}\\u{E0020}-\\u{E007F}]", // C.9
  ].join("|"),
  "u",
);

/** RFC 3454 D.1 — 오른쪽에서 왼쪽으로 쓰는 문자(R·AL). 표 그대로다. */
const RAND_AL =
  new RegExp("[\\u05BE\\u05C0\\u05C3\\u05D0-\\u05EA\\u05F0-\\u05F4\\u061B\\u061F\\u0621-\\u063A\\u0640-\\u064A\\u066D-\\u066F\\u0671-\\u06D5\\u06DD\\u06E5\\u06E6\\u06FA-\\u06FE\\u0700-\\u070D\\u0710\\u0712-\\u072C\\u0780-\\u07A5\\u07B1\\u200F\\uFB1D\\uFB1F-\\uFB28\\uFB2A-\\uFB36\\uFB38-\\uFB3C\\uFB3E\\uFB40\\uFB41\\uFB43\\uFB44\\uFB46-\\uFBB1\\uFBD3-\\uFD3D\\uFD50-\\uFD8F\\uFD92-\\uFDC7\\uFDF0-\\uFDFC\\uFE70-\\uFE74\\uFE76-\\uFEFC]", "u");

/** 근사 L(D.2): 글자(\p{L}) 가운데 RandAL이 아닌 것. */
const LETTER = /\p{L}/u;

const UNASSIGNED = /\p{Cn}/u;

export type SaslprepMode =
  /** 저장할 값(새 비밀번호) — 미할당 코드포인트도 금지한다(RFC 3454 §7). */
  | "stored"
  /** 질의 값(로그인 입력) — 미할당 코드포인트를 허용한다. */
  | "query";

/** SASLprep 결과 — 금지 문자나 양방향 규칙 위반이면 null. */
export function saslprep(input: string, mode: SaslprepMode): string | null {
  // ASCII 인쇄 가능 문자만이면 모든 단계를 그대로 통과한다 — 대부분의 비밀번호가 여기서 끝난다.
  if (/^[\x20-\x7E]*$/.test(input)) return input;
  const mapped = input.replace(NON_ASCII_SPACE, " ").replace(MAPPED_TO_NOTHING, "");
  const normalized = mapped.normalize("NFKC");
  if (PROHIBITED.test(normalized)) return null;
  if (mode === "stored" && UNASSIGNED.test(normalized)) return null;
  if (!bidiOk(normalized)) return null;
  return normalized;
}

/** RFC 3454 §6 — RandAL이 하나라도 있으면 L이 없어야 하고, 첫 글자와 끝 글자가 RandAL이어야 한다. */
function bidiOk(s: string): boolean {
  const chars = Array.from(s);
  if (!chars.some((c) => RAND_AL.test(c))) return true;
  if (chars.some((c) => LETTER.test(c) && !RAND_AL.test(c))) return false;
  return RAND_AL.test(chars[0]!) && RAND_AL.test(chars[chars.length - 1]!);
}
