/**
 * 사람이 고르는 비밀번호의 규칙 — 회원 공통 수치(2026-10-18 결정 1)의 정본.
 *
 * - 최소 8자. 영소문자·영대문자·숫자·그 밖의 문자(공백·한글 포함 영숫자가 아닌 모든 문자) 4종 가운데 3종 이상.
 * - 최대 길이 제한은 두지 않는다. 해시 부담 공격은 로그인·변경 요청 본문 상한(`MAX_LOGIN_BODY_BYTES`, 64 KiB)이 막는다.
 * - 판정 전에 SASLprep으로 정규화한다(ionosphere 제품 예외 — `saslprep.ts`). 길이는 정규화 뒤 코드포인트 수다.
 * - 유출·흔한 비밀번호 차단, 정기 변경 강제는 넣지 않는다(같은 결정).
 *
 * 서버가 만드는 무작위 비밀(앱 비밀번호·토큰)에는 쓰지 않는다 — 엔트로피가 규칙보다 크다.
 * 기존 비밀번호는 막지 않는다. 새로 정하거나 바꿀 때만 본다.
 */
import { saslprep } from "./saslprep.ts";

export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MIN_CLASSES = 3;

/** 거절 사유 — 화면·API가 같은 말을 하도록 코드로 둔다. */
export type PasswordPolicyViolation = "too_short" | "too_few_classes" | "invalid_characters";

export type PasswordPolicyResult = { ok: true } | { ok: false; reason: PasswordPolicyViolation; message: string };

const MESSAGES: Readonly<Record<PasswordPolicyViolation, string>> = {
  too_short: `비밀번호는 ${PASSWORD_MIN_LENGTH}자 이상이어야 합니다`,
  too_few_classes: `비밀번호에 영소문자·영대문자·숫자·특수문자 가운데 ${PASSWORD_MIN_CLASSES}종류 이상을 섞어야 합니다`,
  invalid_characters: "비밀번호에 쓸 수 없는 문자(제어 문자 등)가 들어 있습니다",
};

export function checkPasswordPolicy(password: string): PasswordPolicyResult {
  const normalized = saslprep(password, "stored");
  if (normalized === null) return fail("invalid_characters");
  const chars = Array.from(normalized);
  if (chars.length < PASSWORD_MIN_LENGTH) return fail("too_short");
  let lower = false;
  let upper = false;
  let digit = false;
  let other = false;
  for (const c of chars) {
    if (c >= "a" && c <= "z") lower = true;
    else if (c >= "A" && c <= "Z") upper = true;
    else if (c >= "0" && c <= "9") digit = true;
    else other = true;
  }
  const classes = Number(lower) + Number(upper) + Number(digit) + Number(other);
  return classes >= PASSWORD_MIN_CLASSES ? { ok: true } : fail("too_few_classes");
}

function fail(reason: PasswordPolicyViolation): PasswordPolicyResult {
  return { ok: false, reason, message: MESSAGES[reason] };
}
