/**
 * IMAP sequence-set (RFC 9051 §9: seq-number / seq-range / sequence-set).
 * `*`는 "메일함의 최대 값"(SELECT 시점 EXISTS 또는 최대 UID) — 매칭 시점에 주입한다.
 * `12:5`처럼 역순 범위도 유효(정규화), `4:*`는 max<4여도 {max}를 포함(RFC 명시: 4:* == *:4).
 */

export interface SeqRange {
  from: number | "*";
  to: number | "*";
}

/** 파싱 실패 시 null — 엔진이 BAD로 응답. */
export function parseSequenceSet(input: string): SeqRange[] | null {
  if (input.length === 0) return null;
  const ranges: SeqRange[] = [];
  for (const part of input.split(",")) {
    const colon = part.indexOf(":");
    if (colon === -1) {
      const n = parseSeqNumber(part);
      if (n === null) return null;
      ranges.push({ from: n, to: n });
    } else {
      const from = parseSeqNumber(part.slice(0, colon));
      const to = parseSeqNumber(part.slice(colon + 1));
      if (from === null || to === null) return null;
      ranges.push({ from, to });
    }
  }
  return ranges;
}

/** seq-number: nz-number 또는 `*`. */
function parseSeqNumber(s: string): number | "*" | null {
  if (s === "*") return "*";
  if (!/^[1-9]\d*$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}

function resolve(v: number | "*", max: number): number {
  return v === "*" ? max : v;
}

/** value가 집합에 속하는가. max는 `*`의 해석 값(EXISTS 또는 최대 UID). */
export function matchSequenceSet(ranges: readonly SeqRange[], value: number, max: number): boolean {
  for (const r of ranges) {
    let lo = resolve(r.from, max);
    let hi = resolve(r.to, max);
    if (lo > hi) [lo, hi] = [hi, lo];
    if (value >= lo && value <= hi) return true;
  }
  return false;
}

/** UID 목록 → 압축 uid-set 문자열("3:5,9") — COPYUID/APPENDUID 응답 코드용. */
export function formatUidSet(uids: readonly number[]): string {
  const sorted = [...new Set(uids)].sort((a, b) => a - b);
  const parts: string[] = [];
  let i = 0;
  while (i < sorted.length) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1] === sorted[j]! + 1) j++;
    parts.push(i === j ? String(sorted[i]) : `${sorted[i]}:${sorted[j]}`);
    i = j + 1;
  }
  return parts.join(",");
}

/**
 * 집합을 [lo, hi] 정규화 구간 목록으로 — 스토어 질의(UID 범위 WHERE 절) 생성용.
 * 겹치는 구간은 병합, 오름차순 정렬. max=0(빈 메일함)에서 `*` 포함 구간은 제외된다.
 */
export function normalizeRanges(ranges: readonly SeqRange[], max: number): Array<[number, number]> {
  const resolved: Array<[number, number]> = [];
  for (const r of ranges) {
    let lo = resolve(r.from, max);
    let hi = resolve(r.to, max);
    if (lo > hi) [lo, hi] = [hi, lo];
    if (hi < 1 || max < 1 && (r.from === "*" || r.to === "*")) continue;
    resolved.push([Math.max(1, lo), hi]);
  }
  resolved.sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const [lo, hi] of resolved) {
    const last = merged[merged.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else merged.push([lo, hi]);
  }
  return merged;
}
