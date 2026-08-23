/**
 * 실용적 addr-spec 파서: display-name <local@domain>, bare 주소, 콤마 목록, 그룹(name: a, b;).
 * 손상된 항목은 조용히 건너뛴다 — 절대 throw하지 않는다.
 */
import type { ParsedAddress } from "./types.ts";

/** 따옴표/괄호 밖에서의 최상위 콤마·콜론(그룹 시작)을 인지하며 항목 단위로 분리. */
function splitAddressEntries(input: string): string[] {
  const entries: string[] = [];
  let inQuotes = false;
  let angleDepth = 0;
  let inGroup = false;
  let current = "";

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    if (inQuotes) {
      current += ch;
      if (ch === '"' && input[i - 1] !== "\\") inQuotes = false;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      current += ch;
      continue;
    }
    if (ch === "<") {
      angleDepth++;
      current += ch;
      continue;
    }
    if (ch === ">") {
      if (angleDepth > 0) angleDepth--;
      current += ch;
      continue;
    }
    if (ch === ":" && angleDepth === 0 && !inGroup) {
      inGroup = true;
      current += ch;
      continue;
    }
    if (ch === ";" && inGroup) {
      inGroup = false;
      current += ch;
      entries.push(current);
      current = "";
      continue;
    }
    if (ch === "," && angleDepth === 0 && !inGroup) {
      entries.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim().length > 0) entries.push(current);
  return entries.map((e) => e.trim()).filter((e) => e.length > 0);
}

/** 따옴표/꺾쇠 밖의 최상위 ':' 위치 (그룹 판별용). 없으면 -1. */
function findTopLevelColon(s: string): number {
  let inQuotes = false;
  let angleDepth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (inQuotes) {
      if (ch === '"' && s[i - 1] !== "\\") inQuotes = false;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      continue;
    }
    if (ch === "<") angleDepth++;
    else if (ch === ">") {
      if (angleDepth > 0) angleDepth--;
    } else if (ch === ":" && angleDepth === 0) return i;
  }
  return -1;
}

/** 따옴표 밖의 괄호 코멘트 `(...)` 제거 (단일 레벨, 중첩 미지원 — 실사용상 충분). */
function stripComments(s: string): string {
  let out = "";
  let inQuotes = false;
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (!inQuotes && ch === '"') {
      inQuotes = true;
      out += ch;
      continue;
    }
    if (inQuotes) {
      out += ch;
      if (ch === '"' && s[i - 1] !== "\\") inQuotes = false;
      continue;
    }
    if (ch === "(") {
      depth++;
      continue;
    }
    if (ch === ")") {
      if (depth > 0) depth--;
      continue;
    }
    if (depth > 0) continue;
    out += ch;
  }
  return out;
}

function extractDisplayName(namePart: string): string | null {
  let s = namePart.trim();
  if (!s) return null;
  const qm = s.match(/^"(.*)"$/);
  if (qm) s = qm[1]!.replace(/\\(.)/g, "$1");
  s = s.trim();
  return s.length > 0 ? s : null;
}

/** addr-spec 정규화: localpart·domain 모두 소문자 (SCHEMA.md §2 정규화 규약). 손상 시 null. */
function normalizeEmail(addr: string): string | null {
  const s = addr.trim();
  if (!s) return null;
  const at = s.lastIndexOf("@");
  if (at <= 0 || at === s.length - 1) return null; // '@' 없음/맨앞/맨뒤 — 잘못된 형식
  const local = s.slice(0, at);
  const domain = s.slice(at + 1);
  if (/[\s<>,;:"]/.test(local) || /[\s<>,;:"]/.test(domain)) return null; // 구분자 포함 — 손상
  return `${local.toLowerCase()}@${domain.toLowerCase()}`;
}

function parseSingleMailbox(raw: string): ParsedAddress | null {
  const entry = stripComments(raw).trim();
  if (!entry) return null;

  const angleMatch = entry.match(/^(.*)<([^<>]*)>\s*$/);
  if (angleMatch) {
    const email = normalizeEmail(angleMatch[2]!);
    if (!email) return null;
    return { name: extractDisplayName(angleMatch[1]!), email };
  }

  const email = normalizeEmail(entry);
  if (!email) return null;
  return { name: null, email };
}

function parseSingleOrGroup(entry: string): ParsedAddress[] {
  const colonIdx = findTopLevelColon(entry);
  if (colonIdx === -1) {
    const a = parseSingleMailbox(entry);
    return a ? [a] : [];
  }
  // 그룹: "GroupName: member1, member2;" — 그룹명 자체는 주소가 아니므로 버리고 멤버만 추출.
  let inner = entry.slice(colonIdx + 1).trim();
  if (inner.endsWith(";")) inner = inner.slice(0, -1);
  if (!inner.trim()) return []; // 빈 그룹 (예: "Undisclosed-recipients:;")
  const out: ParsedAddress[] = [];
  for (const member of inner.split(",")) {
    const a = parseSingleMailbox(member.trim());
    if (a) out.push(a);
  }
  return out;
}

/** 주소 목록 헤더(From/To/Cc/Bcc/Reply-To/Sender) 파싱. 손상 항목은 건너뜀, 절대 throw 없음. */
export function parseAddressList(raw: string | null): ParsedAddress[] {
  if (!raw) return [];
  const out: ParsedAddress[] = [];
  for (const entry of splitAddressEntries(raw)) {
    out.push(...parseSingleOrGroup(entry));
  }
  return out;
}
