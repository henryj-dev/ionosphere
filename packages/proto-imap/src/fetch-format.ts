/**
 * FETCH 데이터 항목 포매터 — ENVELOPE / BODY(STRUCTURE) / BODY[섹션] 추출 / INTERNALDATE.
 *
 * 모든 포매터는 "와이어 문자열"(latin1: 1문자=1바이트)을 반환한다. 리터럴은
 * `{n}\r\n<bytes-as-latin1>` 형태로 임베드되고, 어댑터/엔진이 마지막에
 * `Buffer.from(wire, "latin1")`로 바이트화한다 — 텍스트/바이너리 혼합 응답의 단일 표현.
 *
 * 실용 편차(주석 필수 규약):
 * - ENVELOPE의 문자열 값은 mime 파서의 decoded 값 기준(원문 encoded-word 재현 안 함).
 *   비ASCII는 UTF-8 리터럴로 방출 — 모던 클라이언트 호환에 문제 없음.
 * - BODY[1.1](비multipart 파트 하위 경로) 등 병적 경로는 관용 해석.
 */
import { parseMessage, parseStructure, type MimePartInfo, type ParsedAddress } from "@ionosphere/mime";

// ── 와이어 문자열 유틸 ─────────────────────────────────────────────────────────

function bytesToWire(bytes: Uint8Array): string {
  let out = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return out;
}

export function wireToBytes(wire: string): Uint8Array {
  const out = new Uint8Array(wire.length);
  for (let i = 0; i < wire.length; i++) out[i] = wire.charCodeAt(i) & 0xff;
  return out;
}

/** 리터럴 임베드 — `{n}\r\n` + 바이트(latin1 표현). */
export function literalWire(bytes: Uint8Array): string {
  return `{${bytes.length}}\r\n${bytesToWire(bytes)}`;
}

const QUOTED_SAFE = /^[\x20-\x7e]*$/;

/** nstring: null→NIL, 안전 ASCII→quoted, 그 외→UTF-8 리터럴. */
export function nstring(value: string | null): string {
  if (value === null) return "NIL";
  if (QUOTED_SAFE.test(value) && !value.includes('"') && !value.includes("\\")) return `"${value}"`;
  if (QUOTED_SAFE.test(value)) return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
  return literalWire(new TextEncoder().encode(value));
}

// ── INTERNALDATE ──────────────────────────────────────────────────────────────

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** date-time 파싱(APPEND) — " 1-Jan-2026 12:34:56 +0900" 관용 포함. 실패 시 null. */
export function parseImapDateTime(s: string): number | null {
  const m = /^\s*(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(s);
  if (!m) return null;
  const month = MONTHS.findIndex((x) => x.toLowerCase() === (m[2] ?? "").toLowerCase());
  if (month === -1) return null;
  const base = Date.UTC(Number(m[3]), month, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
  const offsetMin = Number(m[8]) * 60 + Number(m[9]);
  return base - (m[7] === "+" ? 1 : -1) * offsetMin * 60_000;
}

/** date-time (RFC 3501): "01-Jan-2026 12:34:56 +0000" — UTC 고정 방출. */
export function formatInternalDate(epochMs: number): string {
  const d = new Date(epochMs);
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${pad(d.getUTCDate())}-${MONTHS[d.getUTCMonth()]}-${d.getUTCFullYear()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}

// ── ENVELOPE ──────────────────────────────────────────────────────────────────

function addr(a: ParsedAddress): string {
  const at = a.email.lastIndexOf("@");
  const mailbox = at === -1 ? a.email : a.email.slice(0, at);
  const host = at === -1 ? null : a.email.slice(at + 1);
  return `(${nstring(a.name)} NIL ${nstring(mailbox)} ${nstring(host)})`;
}

function addrList(list: readonly ParsedAddress[]): string {
  if (list.length === 0) return "NIL";
  return `(${list.map(addr).join("")})`;
}

function firstRaw(headers: Map<string, string[]>, name: string): string | null {
  const v = headers.get(name);
  return v && v.length > 0 ? (v[0] ?? null) : null;
}

/** ENVELOPE (RFC 9051 §7.5.2) — sender/reply-to는 부재 시 from으로 폴백(RFC 규정). */
export function formatEnvelope(raw: Uint8Array): string {
  const m = parseMessage(raw);
  const date = firstRaw(m.headers, "date");
  const subject = m.subject;
  const from = addrList(m.from);
  const sender = m.sender.length > 0 ? addrList(m.sender) : from;
  const replyTo = m.replyTo.length > 0 ? addrList(m.replyTo) : from;
  const to = addrList(m.to);
  const cc = addrList(m.cc);
  const bcc = addrList(m.bcc);
  const inReplyTo = firstRaw(m.headers, "in-reply-to");
  const messageId = m.messageId !== null ? `<${m.messageId}>` : null;
  return `(${nstring(date)} ${nstring(subject)} ${from} ${sender} ${replyTo} ${to} ${cc} ${bcc} ${nstring(inReplyTo)} ${nstring(messageId)})`;
}

// ── BODY / BODYSTRUCTURE ──────────────────────────────────────────────────────

function paramsList(params: Record<string, string>): string {
  const entries = Object.entries(params);
  if (entries.length === 0) return "NIL";
  return `(${entries.map(([k, v]) => `${nstring(k)} ${nstring(v)}`).join(" ")})`;
}

function dispositionStr(part: MimePartInfo): string {
  if (!part.disposition) return "NIL";
  return `(${nstring(part.disposition.type)} ${paramsList(part.disposition.params)})`;
}

function bodyPart(part: MimePartInfo, ext: boolean, raw: Uint8Array): string {
  if (part.type === "multipart") {
    const children = part.children.length > 0 ? part.children.map((c) => bodyPart(c, ext, raw)).join("") : "(NIL NIL NIL NIL NIL 0 0)";
    const base = `(${children} ${nstring(part.subtype.toUpperCase())}`;
    if (!ext) return `${base})`;
    return `${base} ${paramsList(part.params)} ${dispositionStr(part)} NIL NIL)`;
  }

  const common = `${nstring(part.type.toUpperCase())} ${nstring(part.subtype.toUpperCase())} ${paramsList(part.params)} ${nstring(part.contentId)} ${nstring(part.description)} ${nstring(part.encoding.toUpperCase())} ${part.size}`;

  let typed = common;
  if (part.type === "message" && part.subtype === "rfc822" && part.children[0]) {
    const inner = part.children[0];
    const innerRaw = raw.subarray(part.bodyStart, part.end);
    typed += ` ${formatEnvelope(innerRaw)} ${bodyPart(inner, ext, raw)} ${part.lines}`;
  } else if (part.type === "text") {
    typed += ` ${part.lines}`;
  }
  if (!ext) return `(${typed})`;
  // 확장: body-fld-md5 dispo lang loc
  return `(${typed} NIL ${dispositionStr(part)} NIL NIL)`;
}

/** BODY(ext=false) / BODYSTRUCTURE(ext=true). */
export function formatBodyStructure(raw: Uint8Array, ext: boolean): string {
  return bodyPart(parseStructure(raw), ext, raw);
}

// ── BODY[섹션] 추출 ────────────────────────────────────────────────────────────

export interface SectionSpec {
  /** 파트 경로(1-기반). 빈 배열 = 메시지 전체 기준. */
  path: number[];
  sub: "HEADER" | "HEADER.FIELDS" | "HEADER.FIELDS.NOT" | "TEXT" | "MIME" | null;
  /** HEADER.FIELDS(.NOT)의 필드명(대문자 정규화). */
  fields: string[];
}

/** 경로 한 스텝 — 메시지 노드의 콘텐츠 기준(message/rfc822는 내포 메시지로 투과). */
function stepPart(node: MimePartInfo, n: number): MimePartInfo | null {
  const content = node.type === "message" && node.subtype === "rfc822" && node.children[0] ? node.children[0] : node;
  if (content.type === "multipart") return content.children[n - 1] ?? null;
  return n === 1 ? content : null; // BODY[1] == 비multipart 메시지의 본문(RFC)
}

function resolvePath(root: MimePartInfo, path: readonly number[]): MimePartInfo | null {
  let node: MimePartInfo | null = root;
  for (const n of path) {
    if (!node) return null;
    node = stepPart(node, n);
  }
  return node;
}

/** 헤더 바이트에서 필드 필터링(폴딩 연속행 유지) — HEADER.FIELDS(.NOT). */
function filterHeaderFields(headerBytes: Uint8Array, fields: readonly string[], negate: boolean): Uint8Array {
  const text = bytesToWire(headerBytes);
  const lines = text.split(/\r?\n/);
  const wanted = new Set(fields.map((f) => f.toUpperCase()));
  const out: string[] = [];
  let keeping = false;
  for (const line of lines) {
    if (line.length === 0) continue;
    if (line[0] === " " || line[0] === "\t") {
      if (keeping) out.push(line);
      continue;
    }
    const colon = line.indexOf(":");
    const name = colon === -1 ? "" : line.slice(0, colon).trim().toUpperCase();
    keeping = colon !== -1 && (negate ? !wanted.has(name) : wanted.has(name));
    if (keeping) out.push(line);
  }
  const joined = out.length > 0 ? out.join("\r\n") + "\r\n\r\n" : "\r\n";
  return wireToBytes(joined);
}

/**
 * 섹션 바이트 추출 — 존재하지 않는 파트는 null(FETCH 응답에서 NIL).
 * HEADER/TEXT는 대상이 메시지(루트 또는 내포 message/rfc822)일 때의 시맨틱.
 */
export function extractSection(raw: Uint8Array, spec: SectionSpec): Uint8Array | null {
  const root = parseStructure(raw);
  const target = resolvePath(root, spec.path);
  if (!target) return null;

  // 메시지 시맨틱 대상: 루트이거나 message/rfc822 파트면 내포 메시지
  const asMessage = (node: MimePartInfo): MimePartInfo | null => {
    if (node === root) return root;
    if (node.type === "message" && node.subtype === "rfc822") return node.children[0] ?? null;
    return null;
  };

  switch (spec.sub) {
    case null:
      // 빈 경로 = 메시지 전체, 파트 경로 = 파트 본문
      if (spec.path.length === 0) return raw;
      return raw.subarray(target.bodyStart, target.end);
    case "HEADER": {
      const m = spec.path.length === 0 ? root : asMessage(target);
      if (!m) return null;
      return raw.subarray(m.start, m.bodyStart);
    }
    case "TEXT": {
      const m = spec.path.length === 0 ? root : asMessage(target);
      if (!m) return null;
      return raw.subarray(m.bodyStart, m.end);
    }
    case "MIME":
      if (spec.path.length === 0) return null; // MIME은 파트 전용(RFC)
      return raw.subarray(target.start, target.bodyStart);
    case "HEADER.FIELDS":
    case "HEADER.FIELDS.NOT": {
      const m = spec.path.length === 0 ? root : asMessage(target);
      if (!m) return null;
      return filterHeaderFields(raw.subarray(m.start, m.bodyStart), spec.fields, spec.sub === "HEADER.FIELDS.NOT");
    }
  }
}
