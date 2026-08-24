/**
 * LIST 패턴 매칭 + 메일함 이름 유틸 (RFC 9051 §6.3.9).
 * 와일드카드: `*` = 구분자 포함 전부, `%` = 구분자 제외.
 * 계층 구분자는 프로젝트 전역 `/` 고정(UTF-8 네이티브 이름 — SCHEMA §5-1).
 *
 * ★매칭 자체는 `@ionosphere/core`(glob.ts)가 소유한다. 예전엔 여기서 패턴을 정규식으로
 * 바꿨는데(`*` → `.*`) 인접한 `.*`가 지수 백트래킹을 일으켜, 인증된 사용자가 `LIST` 한 줄로
 * 프로세스 전체를 세울 수 있었다(실측 120초 초과). Sieve `:matches`에 **같은 결함이 복제**돼
 * 있었던 것이 정본을 core로 올린 이유다 — 근거는 glob.ts 머리 주석에 있다.
 */
import { compileGlob, imapListSyntax } from "@ionosphere/core";

export const HIERARCHY_DELIMITER = "/";

/** 이 프로토콜의 와일드카드 문법 — 구분자가 고정이라 모듈 로드 시 한 번만 만든다. */
const LIST_SYNTAX = imapListSyntax(HIERARCHY_DELIMITER);

/** INBOX는 대소문자 무관(RFC) — 선두 세그먼트만 정규화. */
export function normalizeMailboxName(name: string): string {
  const segs = name.split(HIERARCHY_DELIMITER);
  if (segs[0] && segs[0].toUpperCase() === "INBOX") segs[0] = "INBOX";
  return segs.join(HIERARCHY_DELIMITER);
}

/** LIST reference + pattern 결합 — 단순 연접(RFC 3501 해석의 실용 부분집합). */
export function joinListPattern(ref: string, pattern: string): string {
  if (ref.length === 0) return pattern;
  if (ref.endsWith(HIERARCHY_DELIMITER)) return ref + pattern;
  return ref + HIERARCHY_DELIMITER + pattern;
}

/**
 * 패턴을 재사용 가능한 매처로 컴파일한다.
 *
 * ★호출부가 **메일함마다** 매칭하므로(engine.ts cmdList) 패턴 파싱은 한 번만 해야 한다.
 * 예전엔 메일함 하나당 `new RegExp()`을 다시 만들었다.
 */
export function compileListPattern(pattern: string): (name: string) => boolean {
  return compileGlob(pattern, LIST_SYNTAX);
}

/**
 * 단건 매칭. 여러 이름에 같은 패턴을 대려면 `compileListPattern`을 쓸 것.
 *
 * ★대소문자를 **구분한다**. 예전엔 정규식에 `i` 플래그를 달아 `LIST "" "work"`가 `Work`·`WORK`를
 * 전부 매치했다 — RFC 9051에서 대소문자 무관인 것은 `INBOX` **하나뿐**이고, 그 처리는
 * `normalizeMailboxName()`이 선두 세그먼트에서 이미 한다. 관용이 필요한 자리가 아니었다.
 */
export function matchesListPattern(pattern: string, name: string): boolean {
  return compileGlob(pattern, LIST_SYNTAX)(name);
}

/** 응답용 메일함 이름 인코딩 — 공백/특수문자 안전하게 항상 quoted로. */
export function quoteMailboxName(name: string): string {
  return `"${name.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

/** role → SPECIAL-USE 속성(RFC 6154). */
const ROLE_ATTRS: Record<string, string> = {
  sent: "\\Sent",
  trash: "\\Trash",
  junk: "\\Junk",
  drafts: "\\Drafts",
  archive: "\\Archive",
};

export function roleToAttribute(role: string | null): string | null {
  if (!role) return null;
  return ROLE_ATTRS[role.toLowerCase()] ?? null;
}
