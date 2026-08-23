/**
 * LIST 패턴 매칭 + 메일함 이름 유틸 (RFC 9051 §6.3.9).
 * 와일드카드: `*` = 구분자 포함 전부, `%` = 구분자 제외.
 * 계층 구분자는 프로젝트 전역 `/` 고정(UTF-8 네이티브 이름 — SCHEMA §5-1).
 */

export const HIERARCHY_DELIMITER = "/";

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

/** 패턴을 정규식으로 — `*`/`%` 외 문자는 이스케이프. */
export function listPatternToRegExp(pattern: string): RegExp {
  let out = "^";
  for (const ch of pattern) {
    if (ch === "*") out += ".*";
    else if (ch === "%") out += `[^${HIERARCHY_DELIMITER}]*`;
    else out += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(out + "$", "i"); // INBOX 대소문자 무관을 포괄하는 관용 비교
}

export function matchesListPattern(pattern: string, name: string): boolean {
  return listPatternToRegExp(pattern).test(name);
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
