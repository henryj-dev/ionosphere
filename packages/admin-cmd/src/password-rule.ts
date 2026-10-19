/**
 * 사람이 정하는 비밀번호에 공통 규칙을 건다 — 계정·관리자 비밀번호를 만들거나 바꾸는 명령이 모두 이것을 부른다.
 * 규칙의 정본은 core `checkPasswordPolicy`다(회원 공통 수치 2026-10-18 결정 1). 기존 비밀번호는 막지 않는다.
 */
import { checkPasswordPolicy } from "@ionosphere/core";
import { CommandError } from "./types.ts";

export function requirePasswordPolicy(password: string): void {
  const r = checkPasswordPolicy(password);
  if (!r.ok) throw new CommandError("invalid", r.message);
}
