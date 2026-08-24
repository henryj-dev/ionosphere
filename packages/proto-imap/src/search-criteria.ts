/**
 * SEARCH 크라이테리어 — 파싱 + 평가 (RFC 9051 §6.4.4의 실용 부분집합).
 *
 * 평가 데이터는 엔진이 fetchMessages로 받아온 메시지(flags/size/internalDate/raw)로 충당한다.
 * \Recent은 rev2 시맨틱상 미지원: RECENT/NEW는 공집합, OLD는 전체와 동치.
 *
 * ## ★`search_index`를 선필터로 쓰지 않는다 (2026-08-24 결정)
 *
 * 예전 주석은 "인덱스 최적화(스토어 위임)는 후속"이라고 적었는데, 실제로 해 보면 **할 수
 * 없는 일**이다. 두 검색의 의미가 다르다:
 *
 *  · IMAP `SEARCH BODY "x"`는 **부분 문자열**이다(RFC 9051 §6.4.4). `BODY "oo"`는 `foo`를
 *    매치해야 한다 — 아래 `full.includes(needle)`이 그 규정이다.
 *  · `search_index`는 **단어/바이그램 토큰**이다(`store/tokenize.ts`). `oo`를 질의하면 토큰
 *    `oo`를 찾는데 `foo`는 토큰 `foo`로 저장돼 있어 매치되지 않는다.
 *
 * 색인을 선필터로 쓰면 **거짓 음성**이 생긴다 — 매치돼야 할 메일이 검색에서 사라진다.
 * 선필터는 거짓 음성이 없을 때만 건전한데 그 조건이 성립하지 않으므로, 이건 성능 최적화가
 * 아니라 **정확성 회귀**다. 메모리 폭발은 엔진의 배치화가 이미 막았고(engine.ts의 SEARCH
 * 배치 주석), 남는 것은 CPU·I/O 비용뿐이라 그 값을 치르기로 했다.
 *
 * JMAP은 영향이 없다 — RFC 8621의 `text`/`body` 필터는 **구현체 정의**라 토큰 의미가
 * 허용되고, 그래서 JMAP만 색인을 쓴다. 두 표면이 다른 것은 규격이 다르기 때문이지
 * 갈라진 것이 아니다.
 *
 * 이 결정은 `search-substring.test.ts`가 지킨다 — 부분 문자열 매치가 깨지면 실패한다.
 */
import { parseMessage } from "@ionosphere/mime";
import type { ImapValue } from "./parser.ts";
import { valueText } from "./parser.ts";
import { matchSequenceSet, parseSequenceSet, type SeqRange } from "./sequence-set.ts";

export type SearchKey =
  | { kind: "all" }
  | { kind: "none" } // RECENT/NEW — 항상 거짓
  | { kind: "flag"; flag: string; negate: boolean }
  | { kind: "larger"; n: number }
  | { kind: "smaller"; n: number }
  | { kind: "uid"; ranges: SeqRange[] }
  | { kind: "seq"; ranges: SeqRange[] }
  | { kind: "internal-date"; op: "before" | "on" | "since"; ms: number }
  | { kind: "sent-date"; op: "before" | "on" | "since"; ms: number }
  /** SAVEDBEFORE/SAVEDON/SAVEDSINCE (RFC 8514) — 이 메일함에 들어온 시각 기준. */
  | { kind: "save-date"; op: "before" | "on" | "since"; ms: number }
  | { kind: "header"; field: string; value: string }
  | { kind: "text"; value: string; includeHeaders: boolean }
  | { kind: "modseq"; n: number } // CONDSTORE (RFC 7162)
  | { kind: "not"; key: SearchKey }
  | { kind: "or"; a: SearchKey; b: SearchKey }
  | { kind: "and"; keys: SearchKey[] };

export interface SearchMessage {
  seq: number;
  uid: number;
  flags: readonly string[];
  size: number;
  internalDateMs: number;
  /**
   * SAVEDATE(RFC 8514) 기준 시각. 없으면 `internalDateMs`로 떨어진다 —
   * §3이 "저장 시각을 모르면 SAVEDATE 키는 매칭하지 않는다"고 하지만, 우리는 항상 알기
   * 때문에(`message_mailbox.savedate`) 그 갈래가 필요 없다.
   */
  saveDateMs?: number | undefined;
  /** CONDSTORE MODSEQ 크라이테리어용 — 미지정 시 0. */
  modseq?: number | undefined;
  raw?: Uint8Array | undefined;
}

export type SearchParseResult = { ok: true; key: SearchKey } | { ok: false; badCharset: boolean };

const FLAG_KEYS: Record<string, string> = {
  ANSWERED: "\\Answered",
  DELETED: "\\Deleted",
  DRAFT: "\\Draft",
  FLAGGED: "\\Flagged",
  SEEN: "\\Seen",
};
const HEADER_SHORTCUTS = new Set(["FROM", "TO", "CC", "BCC", "SUBJECT"]);
const MONTH_INDEX: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** search date: "5-Jul-2026" → UTC 자정 epoch ms. 실패 시 null. */
export function parseSearchDate(s: string): number | null {
  const m = /^"?(\d{1,2})-([A-Za-z]{3})-(\d{4})"?$/.exec(s);
  if (!m) return null;
  const month = MONTH_INDEX[(m[2] ?? "").toLowerCase()];
  if (month === undefined) return null;
  return Date.UTC(Number(m[3]), month, Number(m[1]));
}

class TokenStream {
  private readonly values: readonly ImapValue[];
  private idx = 0;

  constructor(values: readonly ImapValue[]) {
    this.values = values;
  }

  next(): ImapValue | null {
    return this.values[this.idx++] ?? null;
  }

  peekText(): string | null {
    const v = this.values[this.idx];
    return v ? valueText(v) : null;
  }

  atEnd(): boolean {
    return this.idx >= this.values.length;
  }
}

/** SEARCH 인자 전체 파싱 — 선두 CHARSET 처리 포함. */
export function parseSearchProgram(values: readonly ImapValue[]): SearchParseResult {
  const stream = new TokenStream(values);
  if (stream.peekText()?.toUpperCase() === "CHARSET") {
    stream.next();
    const cs = stream.next();
    const name = cs ? valueText(cs)?.toUpperCase() : null;
    if (name !== "UTF-8" && name !== "US-ASCII") return { ok: false, badCharset: true };
  }
  const keys: SearchKey[] = [];
  while (!stream.atEnd()) {
    const key = parseKey(stream);
    if (!key) return { ok: false, badCharset: false };
    keys.push(key);
  }
  if (keys.length === 0) return { ok: false, badCharset: false };
  return { ok: true, key: keys.length === 1 ? keys[0]! : { kind: "and", keys } };
}

function parseKey(stream: TokenStream): SearchKey | null {
  const v = stream.next();
  if (!v) return null;

  // 괄호 그룹 — 내부는 암묵 AND
  if (v.kind === "list") {
    const inner = parseSearchProgram(v.items);
    return inner.ok ? inner.key : null;
  }

  const text = valueText(v);
  if (text === null) return null;
  const upper = text.toUpperCase();

  const flag = FLAG_KEYS[upper.replace(/^UN/, "")];
  if (flag && upper.startsWith("UN")) return { kind: "flag", flag, negate: true };
  if (FLAG_KEYS[upper]) return { kind: "flag", flag: FLAG_KEYS[upper]!, negate: false };

  switch (upper) {
    case "ALL":
      return { kind: "all" };
    case "RECENT":
    case "NEW":
      return { kind: "none" }; // \Recent 미지원(rev2)
    case "OLD":
      return { kind: "all" };
    case "KEYWORD":
    case "UNKEYWORD": {
      const kw = argText(stream);
      if (kw === null) return null;
      return { kind: "flag", flag: kw, negate: upper === "UNKEYWORD" };
    }
    case "LARGER":
    case "SMALLER": {
      const n = argNumber(stream);
      if (n === null) return null;
      return upper === "LARGER" ? { kind: "larger", n } : { kind: "smaller", n };
    }
    case "UID": {
      const set = argText(stream);
      const ranges = set !== null ? parseSequenceSet(set) : null;
      return ranges ? { kind: "uid", ranges } : null;
    }
    case "BEFORE":
    case "ON":
    case "SINCE":
    case "SENTBEFORE":
    case "SENTON":
    case "SENTSINCE":
    case "SAVEDBEFORE":
    case "SAVEDON":
    case "SAVEDSINCE": {
      const d = argText(stream);
      const ms = d !== null ? parseSearchDate(d) : null;
      if (ms === null) return null;
      const op = upper.replace("SENT", "").replace("SAVED", "").toLowerCase() as "before" | "on" | "since";
      if (upper.startsWith("SENT")) return { kind: "sent-date", op, ms };
      if (upper.startsWith("SAVED")) return { kind: "save-date", op, ms };
      return { kind: "internal-date", op, ms };
    }
    case "HEADER": {
      const field = argText(stream);
      const value = argText(stream);
      if (field === null || value === null) return null;
      return { kind: "header", field: field.toUpperCase(), value };
    }
    case "BODY":
    case "TEXT": {
      const value = argText(stream);
      if (value === null) return null;
      return { kind: "text", value, includeHeaders: upper === "TEXT" };
    }
    case "MODSEQ": {
      // RFC 7162: MODSEQ [<entry-name> <entry-type>] n — 선택 인자(quoted entry)는 건너뜀
      let t = argText(stream);
      if (t !== null && !/^\d+$/.test(t)) {
        // entry-name(quoted) entry-type(atom) 스킵 후 숫자
        argText(stream);
        t = argText(stream);
      }
      if (t === null || !/^\d+$/.test(t)) return null;
      return { kind: "modseq", n: Number(t) };
    }
    case "NOT": {
      const key = parseKey(stream);
      return key ? { kind: "not", key } : null;
    }
    case "OR": {
      const a = parseKey(stream);
      const b = parseKey(stream);
      return a && b ? { kind: "or", a, b } : null;
    }
    default:
      if (HEADER_SHORTCUTS.has(upper)) {
        const value = argText(stream);
        if (value === null) return null;
        return { kind: "header", field: upper, value };
      }
      // 마지막 해석: sequence-set
      {
        const ranges = parseSequenceSet(text);
        return ranges ? { kind: "seq", ranges } : null;
      }
  }
}

function argText(stream: TokenStream): string | null {
  const v = stream.next();
  return v ? valueText(v) : null;
}

function argNumber(stream: TokenStream): number | null {
  const t = argText(stream);
  if (t === null || !/^\d+$/.test(t)) return null;
  return Number(t);
}

/** raw가 필요한 키(sent-date/header/text) 포함 여부 — fetch needRaw 판단용. */
export function searchNeedsRaw(key: SearchKey): boolean {
  switch (key.kind) {
    case "sent-date":
    case "header":
    case "text":
      return true;
    case "not":
      return searchNeedsRaw(key.key);
    case "or":
      return searchNeedsRaw(key.a) || searchNeedsRaw(key.b);
    case "and":
      return key.keys.some(searchNeedsRaw);
    default:
      return false;
  }
}

/** UTC 달력일 비교용 일 번호. */
function dayNum(ms: number): number {
  return Math.floor(ms / 86_400_000);
}

function dateMatch(op: "before" | "on" | "since", targetMs: number, valueMs: number): boolean {
  const t = dayNum(targetMs);
  const v = dayNum(valueMs);
  if (op === "before") return v < t;
  if (op === "on") return v === t;
  return v >= t;
}

export function evaluateSearch(key: SearchKey, msg: SearchMessage, maxSeq: number, maxUid: number): boolean {
  switch (key.kind) {
    case "all":
      return true;
    case "none":
      return false;
    case "flag": {
      const has = msg.flags.some((f) => f.toUpperCase() === key.flag.toUpperCase());
      return key.negate ? !has : has;
    }
    case "larger":
      return msg.size > key.n;
    case "smaller":
      return msg.size < key.n;
    case "uid":
      return matchSequenceSet(key.ranges, msg.uid, maxUid);
    case "seq":
      return matchSequenceSet(key.ranges, msg.seq, maxSeq);
    case "internal-date":
      return dateMatch(key.op, key.ms, msg.internalDateMs);
    case "save-date":
      // 저장 시각을 모르면 도착 시각으로 — 우리는 항상 알지만 타입이 선택이라 방어한다.
      return dateMatch(key.op, key.ms, msg.saveDateMs ?? msg.internalDateMs);
    case "sent-date": {
      if (!msg.raw) return false;
      const sentAt = parseMessage(msg.raw).sentAt;
      return sentAt !== null && dateMatch(key.op, key.ms, sentAt);
    }
    case "header": {
      if (!msg.raw) return false;
      const headers = parseMessage(msg.raw).headers;
      const vals = headers.get(key.field.toLowerCase()) ?? [];
      if (key.value.length === 0) return vals.length > 0; // 빈 값 = 헤더 존재 검사(RFC)
      const needle = key.value.toLowerCase();
      return vals.some((h) => h.toLowerCase().includes(needle));
    }
    case "text": {
      if (!msg.raw) return false;
      const full = Buffer.from(msg.raw).toString("utf8").toLowerCase();
      const needle = key.value.toLowerCase();
      if (key.includeHeaders) return full.includes(needle);
      const sep = full.search(/\r?\n\r?\n/);
      return (sep === -1 ? "" : full.slice(sep)).includes(needle);
    }
    case "modseq":
      return (msg.modseq ?? 0) >= key.n;
    case "not":
      return !evaluateSearch(key.key, msg, maxSeq, maxUid);
    case "or":
      return evaluateSearch(key.a, msg, maxSeq, maxUid) || evaluateSearch(key.b, msg, maxSeq, maxUid);
    case "and":
      return key.keys.every((k) => evaluateSearch(k, msg, maxSeq, maxUid));
  }
}
