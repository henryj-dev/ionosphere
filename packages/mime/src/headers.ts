/**
 * RFC 5322 헤더 파싱: CRLF/bare-LF 관용, 폴딩 라인 언폴딩, RFC 2047 encoded-word 디코딩.
 * 손상된 줄은 조용히 건너뛴다 — SMTP DATA로 들어오는 임의 입력에 강건해야 함 (throw 금지).
 */
import { decodeBytesWithCharset, decodeEncodedWords } from "./encoding.ts";

export interface ContentTypeInfo {
  type: string;
  subtype: string;
  params: Record<string, string>;
}

export interface ContentDispositionInfo {
  type: string;
  filename: string | null;
}

/** 빈 줄(헤더/본문 경계)에서 문자열을 둘로 분리. 못 찾으면 전체를 헤더로, 본문은 빈 문자열. */
export function splitHeaderBody(str: string): { headerText: string; bodyText: string } {
  const seps = ["\r\n\r\n", "\n\n", "\r\r"];
  let sepIndex = -1;
  let sepLen = 0;
  for (const sep of seps) {
    const idx = str.indexOf(sep);
    if (idx !== -1 && (sepIndex === -1 || idx < sepIndex)) {
      sepIndex = idx;
      sepLen = sep.length;
    }
  }
  if (sepIndex === -1) return { headerText: str, bodyText: "" };
  return { headerText: str.slice(0, sepIndex), bodyText: str.slice(sepIndex + sepLen) };
}

// RFC 5322 field-name: 콜론을 제외한 인쇄 가능 US-ASCII (%d33-57 / %d59-126).
const FIELD_NAME_RE = /^[!-9;-~]+$/;

/**
 * 헤더 레코드 하나 = 필드 하나(접힌 줄 포함).
 *
 * `raw`와 `unfolded`를 **둘 다** 내는 이유: 파싱은 언폴딩된 논리 줄을 원하고,
 * 헤더를 지우거나 다시 쓰는 쪽(`stripForgedAuthResults` 등)은 **원본 바이트**를 원한다.
 * 한쪽만 내면 소비자가 자기 정규식으로 다시 자르게 되고, 그러면 파서와 검사기가
 * 같은 입력을 다르게 읽는다 — 위조 A-R strip 우회(감사 M-13)가 정확히 그 사고였다.
 */
export interface HeaderRecord {
  /** 원본 바이트 그대로(끝의 개행 포함). 순서대로 이으면 입력 헤더 블록이 그대로 복원된다. */
  raw: string;
  /** 언폴딩된 논리 줄 — 개행만 제거하고 선행 공백은 유지한다(RFC 5322 §2.2.3). */
  unfolded: string;
  /** 소문자 필드명. 콜론이 없거나 field-name 문법이 아니면 null(손상된 줄). */
  name: string | null;
}

/**
 * 필드명 추출 — 콜론 앞을 **trim한 뒤** 소문자화한다.
 *
 * trim이 핵심이다: `Authentication-Results : x`처럼 콜론 앞에 공백을 넣는 형태를
 * 파서는 정규 필드로 받아들이므로, 헤더를 지우는 쪽도 **같은 관용**을 적용해야 한다.
 */
function headerFieldName(unfolded: string): string | null {
  const colonIdx = unfolded.indexOf(":");
  if (colonIdx <= 0) return null; // 콜론 없음/빈 이름 — 손상된 줄
  const name = unfolded.slice(0, colonIdx).trim().toLowerCase();
  return FIELD_NAME_RE.test(name) ? name : null;
}

/**
 * 헤더 블록 → 레코드 목록. 접힌 줄(공백류로 시작)은 앞 레코드에 이어 붙인다.
 *
 * 줄 종결자를 직접 훑는 이유는 `split()`이 그것을 버리기 때문이다 — CRLF·bare LF·bare CR가
 * 섞인 원문을 바이트 단위로 되돌릴 수 있어야 지우는 쪽이 나머지를 변형하지 않는다.
 */
export function splitHeaderRecords(headerText: string): HeaderRecord[] {
  const parts: { raw: string; unfolded: string }[] = [];
  let i = 0;
  while (i < headerText.length) {
    let end = i;
    while (end < headerText.length && headerText[end] !== "\r" && headerText[end] !== "\n") end++;
    const content = headerText.slice(i, end);
    const eol =
      end >= headerText.length ? "" : headerText[end] === "\r" && headerText[end + 1] === "\n" ? "\r\n" : headerText[end]!;
    i = end + eol.length;

    const last = parts[parts.length - 1];
    if (last && (content.startsWith(" ") || content.startsWith("\t"))) {
      last.raw += content + eol;
      last.unfolded += content;
      continue;
    }
    parts.push({ raw: content + eol, unfolded: content });
  }
  return parts.map((p) => ({ ...p, name: headerFieldName(p.unfolded) }));
}

/** 헤더 텍스트 → 소문자 필드명 → 값 목록(발생 순). 폴딩 라인은 언폴딩, encoded-word는 디코딩. */
export function parseHeaders(headerText: string): Map<string, string[]> {
  const headers = new Map<string, string[]>();
  if (!headerText) return headers;

  for (const record of splitHeaderRecords(headerText)) {
    if (record.name === null) continue;
    const value = decodeEncodedWords(record.unfolded.slice(record.unfolded.indexOf(":") + 1).trim());
    const list = headers.get(record.name);
    if (list) list.push(value);
    else headers.set(record.name, [value]);
  }
  return headers;
}

export function firstHeader(headers: Map<string, string[]>, name: string): string | null {
  const list = headers.get(name);
  return list && list.length > 0 ? list[0]! : null;
}

/** `;`로 구분된 헤더 파라미터를 큰따옴표 인지하며 분리 (Content-Type/Disposition 공용). */
function splitTopLevelSemicolon(s: string): string[] {
  const out: string[] = [];
  let inQuotes = false;
  let current = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (inQuotes) {
      current += ch;
      if (ch === '"' && s[i - 1] !== "\\") inQuotes = false;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      current += ch;
      continue;
    }
    if (ch === ";") {
      out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

function splitHeaderParams(raw: string): { mainValue: string; params: Record<string, string> } {
  const parts = splitTopLevelSemicolon(raw);
  const mainValue = (parts[0] ?? "").trim();
  const params: Record<string, string> = {};
  const continuations = new Map<string, Map<number, { value: string; encoded: boolean }>>();
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i]!.trim();
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    let key = p.slice(0, eq).trim().toLowerCase();
    const ext = key.match(/^([^*]+)\*(\d+)?(\*)?$/);
    let val = p.slice(eq + 1).trim();
    const qm = val.match(/^"([^"]*)"/);
    if (qm) val = qm[1]!;
    else val = val.replace(/^"|"$/g, "");
    if (ext) {
      const base = ext[1]!;
      const index = Number(ext[2] ?? 0);
      const list = continuations.get(base) ?? new Map();
      list.set(index, { value: val, encoded: ext[3] === "*" });
      continuations.set(base, list);
    } else if (!(key in params)) params[key] = val;
  }
  for (const [key, pieces] of continuations) {
    let joined = "";
    let extended = false;
    for (let i = 0; pieces.has(i); i++) {
      const piece = pieces.get(i)!;
      joined += piece.value;
      extended ||= piece.encoded;
    }
    if (!joined) continue;
    if (extended) {
      const m = joined.match(/^([^']*)'[^']*'(.*)$/);
      const charset = m?.[1];
      const encoded = m?.[2] ?? joined;
      try {
        const bytes = new Uint8Array(encoded.replace(/%([0-9a-f]{2})/gi, (_, h: string) => String.fromCharCode(Number.parseInt(h, 16))).split("").map((c) => c.charCodeAt(0)));
        joined = decodeBytesWithCharset(bytes, charset);
      } catch { /* 잘못된 RFC 2231 값은 원문을 보존한다. */ }
    }
    if (!(key in params)) params[key] = joined;
  }
  return { mainValue, params };
}

export function parseContentType(raw: string | null): ContentTypeInfo {
  if (!raw) return { type: "text", subtype: "plain", params: {} };
  const { mainValue, params } = splitHeaderParams(raw);
  const slash = mainValue.indexOf("/");
  if (slash === -1) return { type: "text", subtype: "plain", params }; // 손상 — RFC 2045 기본값
  const type = mainValue.slice(0, slash).trim().toLowerCase();
  const subtype = mainValue.slice(slash + 1).trim().toLowerCase();
  if (!type || !subtype) return { type: "text", subtype: "plain", params };
  return { type, subtype, params };
}

export function parseContentDisposition(raw: string | null): ContentDispositionInfo | null {
  if (!raw) return null;
  const { mainValue, params } = splitHeaderParams(raw);
  return { type: mainValue.trim().toLowerCase(), filename: params.filename ?? null };
}
