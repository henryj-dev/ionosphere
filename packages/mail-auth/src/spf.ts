/**
 * RFC 7208 SPF(Sender Policy Framework) 검증. 순수 함수 — DNS 조회는 주입받은 DnsResolver로만
 * 수행한다 (dns.ts 참고, node:dns 직접 import 없음).
 *
 * 두 가지 예산(budget)을 전 재귀 호출에 걸쳐 공유한다(§4.6.4):
 * - lookups: include/a/mx/ptr/exists 메커니즘 + redirect 모디파이어가 매 평가 시 +1. 10 초과 → permerror.
 * - voidLookups: 그 예산에 포함된 DNS 질의가 "빈 응답 또는 NXDOMAIN"으로 끝날 때 +1. 2 초과 → permerror.
 *
 * 구현 시 해석한 RFC 모호점(§7 참고 — report에도 기재):
 * - mx/a/ptr 메커니즘 자신의 DNS 질의(1회)만 10-lookup 예산에 계상하고, 그 결과로 얻은 각
 *   대상 호스트명에 대한 후속 A/AAAA 조회는 별도로 계상하지 않는다(다수 구현체의 관행과 동일).
 *   단, MX/PTR 대상은 방어적으로 최대 10개까지만 처리한다(PTR은 §5.5에 명시된 한도, MX는 유사 관행 적용).
 * - exp= 모디파이어의 매크로 구문 오류나 설명 텍스트 조회 실패는 전체 결과를 permerror로 만들지
 *   않고 explanation을 생략한다 — exp는 부가 정보이므로 관대하게 처리(운영상 안전한 선택).
 * - %{p} 매크로(PTR 검증) 계산 중 오류는 "unknown"으로 대체하고 조용히 진행한다(§7.1의 discouraged 권고와
 *   일관되게, 실패해도 전체 평가를 막지 않는다). 이 매크로가 유발하는 PTR/A/AAAA 조회는 10-lookup
 *   예산에 포함시키지 않는다(5개 카운트 대상 메커니즘에 속하지 않으므로).
 */
import { DnsNotFoundError, DnsTemporaryError, type DnsMxRecord, type DnsResolver } from "./dns.ts";

export type SpfResultValue = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror";

export interface SpfInput {
  ip: string;
  helo: string;
  /** MAIL FROM 주소. 널 리턴패스(바운스)는 빈 문자열 — 이 경우 HELO identity를 사용한다. */
  mailFrom: string;
}

export interface SpfResult {
  result: SpfResultValue;
  domain: string;
  explanation?: string;
}

// ---------------------------------------------------------------------------
// IP 파싱/매칭
// ---------------------------------------------------------------------------

interface ParsedIp {
  version: 4 | 6;
  bytes: Buffer; // v4=4바이트, v6=16바이트
}

function parseHextet(s: string): number | null {
  if (!/^[0-9a-fA-F]{1,4}$/.test(s)) return null;
  return parseInt(s, 16);
}

function parseIpv4(s: string): ParsedIp | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const bytes = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i]!;
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    bytes[i] = n;
  }
  return { version: 4, bytes };
}

function parseIpv6(s: string): ParsedIp | null {
  if (!s.includes(":")) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;

  if (halves.length === 1) {
    const groups = halves[0]!.split(":");
    if (groups.length !== 8) return null;
    const bytes = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
      const v = parseHextet(groups[i]!);
      if (v === null) return null;
      bytes.writeUInt16BE(v, i * 2);
    }
    return { version: 6, bytes };
  }

  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  const bytes = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const v = parseHextet(groups[i]!);
    if (v === null) return null;
    bytes.writeUInt16BE(v, i * 2);
  }
  return { version: 6, bytes };
}

/** IPv4·IPv6·IPv4-매핑 IPv6(::ffff:a.b.c.d, 이 경우 IPv4로 취급)를 파싱한다. */
function parseIp(raw: string): ParsedIp | null {
  const s = raw.trim();
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(s);
  const candidate = mapped ? mapped[1]! : s;
  if (candidate.includes(".") && !candidate.includes(":")) return parseIpv4(candidate);
  if (candidate.includes(":")) return parseIpv6(candidate);
  return null;
}

function presentIp(ip: ParsedIp): string {
  if (ip.version === 4) return Array.from(ip.bytes).join(".");
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(ip.bytes.readUInt16BE(i).toString(16));
  return groups.join(":");
}

/** %{i} 매크로의 IPv6 폼: 32개 니블을 점으로 이어붙인 역순 조회 스타일 표기(RFC 7208 §7.3). */
function nibbleForm(ip: ParsedIp): string {
  const nibbles: string[] = [];
  for (const byte of ip.bytes) {
    nibbles.push(((byte >> 4) & 0xf).toString(16));
    nibbles.push((byte & 0xf).toString(16));
  }
  return nibbles.join(".");
}

function ipInCidr(ip: ParsedIp, network: ParsedIp, prefixLen: number): boolean {
  if (ip.version !== network.version) return false;
  const totalBits = ip.version === 4 ? 32 : 128;
  if (prefixLen < 0 || prefixLen > totalBits) return false;
  const fullBytes = Math.floor(prefixLen / 8);
  const remBits = prefixLen % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (ip.bytes[i] !== network.bytes[i]) return false;
  }
  if (remBits > 0) {
    const mask = (0xff << (8 - remBits)) & 0xff;
    if (((ip.bytes[fullBytes] ?? 0) & mask) !== ((network.bytes[fullBytes] ?? 0) & mask)) return false;
  }
  return true;
}

/**
 * CIDR 목록 매처 — "이 접속 IP가 우리가 지정한 대역에 드는가"를 판정한다.
 *
 * ★왜 SPF 패키지가 소유하는가: IP 파싱(IPv4·IPv6·`::ffff:` 매핑)과 프리픽스 비교는 `ip4:`/`ip6:`
 * 메커니즘 때문에 이미 여기 있다. 신뢰 대역 판정을 위해 밖에서 다시 구현하면 파서가 둘로
 * 갈라지는데, **갈라진 쪽이 보안 판정을 한다**. 예를 들어 `::ffff:10.0.82.134`(node 소켓이
 * 흔히 내주는 형태)를 한쪽만 IPv4로 접어 주면, 같은 호스트가 한 검사에선 신뢰 대역이고
 * 다른 검사에선 아니게 된다. 파서는 하나여야 한다.
 *
 * 프리픽스를 안 적은 항목은 단일 주소(/32·/128)로 본다.
 */
export interface CidrMatcher {
  matches(ip: string): boolean;
  /** 등록된 대역 수 — 0이면 아무도 신뢰하지 않는다(기본값). */
  readonly size: number;
}

/**
 * 설정 문자열 목록을 매처로 만든다. **잘못된 항목은 조용히 버리지 않고 throw한다.**
 *
 * 신뢰 목록에서 "못 읽은 항목을 무시"는 안전한 쪽으로 실패하는 것처럼 보이지만 운영에서는
 * 반대다 — 오타 하나로 목록이 비어도 서버는 정상 기동하고, 운영자는 예외가 걸린 줄 안다.
 * 부팅 때 죽는 편이 낫다(기동 실패는 즉시 보이고, 켜지 않은 상태와 구분된다).
 */
export function parseCidrList(entries: readonly string[]): CidrMatcher {
  const nets: { net: ParsedIp; prefix: number }[] = [];
  for (const raw of entries) {
    const entry = raw.trim();
    if (!entry) continue;
    const slash = entry.lastIndexOf("/");
    const addrPart = slash >= 0 ? entry.slice(0, slash) : entry;
    const prefixPart = slash >= 0 ? entry.slice(slash + 1) : null;
    const net = parseIp(addrPart);
    if (!net) throw new Error(`잘못된 CIDR 주소: ${entry}`);
    const totalBits = net.version === 4 ? 32 : 128;
    let prefix = totalBits;
    if (prefixPart !== null) {
      if (!/^\d{1,3}$/.test(prefixPart)) throw new Error(`잘못된 CIDR 프리픽스: ${entry}`);
      prefix = Number(prefixPart);
      if (prefix > totalBits) throw new Error(`CIDR 프리픽스가 주소 계열보다 크다: ${entry}`);
    }
    nets.push({ net, prefix });
  }
  return {
    size: nets.length,
    matches(ip: string): boolean {
      // 목록이 비면 항상 false — "설정 안 함"이 "전부 신뢰"로 뒤집히지 않게 한다.
      if (nets.length === 0) return false;
      const parsed = parseIp(ip);
      if (!parsed) return false; // 파싱 못 한 주소는 신뢰하지 않는다(fail closed)
      return nets.some((n) => ipInCidr(parsed, n.net, n.prefix));
    },
  };
}

function isValidDomain(d: string): boolean {
  if (!d || d.length > 253) return false;
  const labels = d.split(".");
  // '_'는 엄밀한 RFC 1035 preferred-name-syntax는 아니지만 _spf/_dmarc/_domainkey 등
  // 이메일 생태계 관례상 흔히 쓰이므로 허용한다.
  return labels.every((label) => label.length > 0 && label.length <= 63 && /^[A-Za-z0-9_-]+$/.test(label));
}

// ---------------------------------------------------------------------------
// 평가 컨텍스트/에러
// ---------------------------------------------------------------------------

class SpfEvalError extends Error {
  kind: "permerror" | "temperror";
  constructor(kind: "permerror" | "temperror", message: string) {
    super(message);
    this.kind = kind;
    this.name = "SpfEvalError";
  }
}

function describeErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

interface EvalCtx {
  resolver: DnsResolver;
  lookups: number;
  voidLookups: number;
  /**
   * `%{p}` 매크로 결과 캐시 — **평가 1회당 한 번만 계산한다**(RFC 7208 §7.3의 "p"는
   * 클라이언트 IP의 함수이므로 재귀 레벨과 무관하게 같은 값이다).
   *
   * ★왜 `MacroCtx`가 아니라 여기인가(2026-07-31 실측): 예전엔 캐시가 `MacroCtx`에 있었는데
   * `evaluateRecord`가 `{ ...mb, currentDomain }`로 **객체를 복사**해서 레코드마다 리셋됐다.
   * 그래서 `exp=%{p}`를 단계마다 둔 include 체인 10단계가 PTR 10회 + A 100회를 냈다 —
   * 예산 10회 정책에 **실제 130회**다(같은 PTR 이름을 10번 다시 물었다). 캐시가 재귀 전체를
   * 살아 있어야 그 곱셈이 사라진다.
   */
  pMacroValue?: string;
  clientIp: ParsedIp;
  pendingExplanation?: string;
}

function countLookup(ctx: EvalCtx): void {
  ctx.lookups++;
  if (ctx.lookups > 10) throw new SpfEvalError("permerror", "DNS 조회 횟수 한도(10) 초과");
}

function countVoidLookup(ctx: EvalCtx): void {
  ctx.voidLookups++;
  if (ctx.voidLookups > 2) throw new SpfEvalError("permerror", "void lookup 한도(2) 초과");
}

interface MacroCtx {
  senderFull: string; // s
  senderLocal: string; // l
  senderDomain: string; // o
  helo: string; // h
  clientIp: ParsedIp; // i/c/v
  currentDomain: string; // d — 재귀 레벨마다 달라짐
  resolver: DnsResolver;
  /** 예산·캐시를 공유하는 평가 컨텍스트 — `%{p}`가 예산을 계상하고 캐시를 재사용하려면 필요하다. */
  ctx: EvalCtx;
}

// ---------------------------------------------------------------------------
// DNS 헬퍼(예산 계상 포함)
// ---------------------------------------------------------------------------

async function fetchSpfRecord(domain: string, ctx: EvalCtx, countVoidIfEmpty: boolean): Promise<string | null> {
  let txts: string[];
  try {
    txts = await ctx.resolver.txt(domain);
  } catch (err) {
    if (err instanceof DnsNotFoundError) {
      if (countVoidIfEmpty) countVoidLookup(ctx);
      return null;
    }
    if (err instanceof DnsTemporaryError) {
      throw new SpfEvalError("temperror", `TXT(${domain}) 조회 실패: ${describeErr(err)}`);
    }
    throw new SpfEvalError("temperror", `TXT(${domain}) 조회 실패: ${describeErr(err)}`);
  }
  if (txts.length === 0) {
    if (countVoidIfEmpty) countVoidLookup(ctx);
    return null;
  }
  const spfRecords = txts.filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (spfRecords.length === 0) return null; // TXT는 있지만 v=spf1 아님 — 없는 것과 동일 취급
  if (spfRecords.length > 1) throw new SpfEvalError("permerror", `${domain}: v=spf1 레코드가 2개 이상`);
  return spfRecords[0]!;
}

async function lookupAddrs(domain: string, version: 4 | 6, ctx: EvalCtx, countVoid: boolean): Promise<ParsedIp[]> {
  let raw: string[];
  try {
    raw = version === 4 ? await ctx.resolver.a(domain) : await ctx.resolver.aaaa(domain);
  } catch (err) {
    if (err instanceof DnsNotFoundError) {
      if (countVoid) countVoidLookup(ctx);
      return [];
    }
    throw new SpfEvalError("temperror", `${version === 4 ? "A" : "AAAA"}(${domain}) 조회 실패: ${describeErr(err)}`);
  }
  if (raw.length === 0 && countVoid) countVoidLookup(ctx);
  const out: ParsedIp[] = [];
  for (const s of raw) {
    const p = parseIp(s);
    if (p) out.push(p);
  }
  return out;
}

async function safeMx(domain: string, ctx: EvalCtx): Promise<DnsMxRecord[]> {
  try {
    const recs = await ctx.resolver.mx(domain);
    if (recs.length === 0) countVoidLookup(ctx);
    return recs;
  } catch (err) {
    if (err instanceof DnsNotFoundError) {
      countVoidLookup(ctx);
      return [];
    }
    throw new SpfEvalError("temperror", `MX(${domain}) 조회 실패: ${describeErr(err)}`);
  }
}

async function safePtr(ip: ParsedIp, ctx: EvalCtx): Promise<string[]> {
  const ipStr = presentIp(ip);
  try {
    const recs = await ctx.resolver.ptr(ipStr);
    if (recs.length === 0) countVoidLookup(ctx);
    return recs;
  } catch (err) {
    if (err instanceof DnsNotFoundError) {
      countVoidLookup(ctx);
      return [];
    }
    throw new SpfEvalError("temperror", `PTR(${ipStr}) 조회 실패: ${describeErr(err)}`);
  }
}

/**
 * `%{p}` 매크로: PTR로 얻은 후보 이름 중 정방향(A/AAAA)이 클라이언트 IP로 재확인되는 첫 이름.
 * 실패 시 "unknown".
 *
 * ★조회를 **예산에 계상한다**(2026-07-31). 예전엔 이 함수의 PTR·A 질의가 `countLookup`을
 * 거치지 않아 RFC 7208 §4.6.4의 10회 예산 **밖**이었다. 후보 이름 상한이 10이라 한 번의
 * `%{p}` 확장만으로 최대 11회(PTR 1 + A 10)가 예산 없이 나갔고, 캐시가 레코드마다 리셋되던
 * 버그와 겹쳐 **예산 10회 정책에서 실제 130회**가 관측됐다. 조회 대상 이름을 발신자가 정하므로
 * (PTR 응답이 곧 A 질의 대상) 우리 리졸버가 제3자를 향한 증폭기가 되는 형태다.
 *
 * 예산을 넘기면 `countLookup`이 던지고, 그 예외는 아래 catch가 "unknown"으로 흡수한다 —
 * `%{p}` 실패가 전체 평가를 막지 않는다는 기존 동작(§7.1 discouraged 권고)은 그대로다.
 */
async function resolvePMacro(mctx: MacroCtx): Promise<string> {
  try {
    countLookup(mctx.ctx);
    const names = await mctx.resolver.ptr(presentIp(mctx.clientIp));
    for (const name of names.slice(0, 10)) {
      countLookup(mctx.ctx);
      const raw = mctx.clientIp.version === 4 ? await mctx.resolver.a(name) : await mctx.resolver.aaaa(name);
      for (const s of raw) {
        const p = parseIp(s);
        if (p && p.bytes.equals(mctx.clientIp.bytes)) return name.replace(/\.$/, "");
      }
    }
  } catch {
    // p 매크로는 실패해도 전체 평가를 막지 않는다 — "unknown"으로 대체
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// 매크로 확장(RFC 7208 §7)
// ---------------------------------------------------------------------------

function splitByDelims(value: string, delims: string): string[] {
  const set = new Set(delims.split(""));
  const parts: string[] = [];
  let cur = "";
  for (const ch of value) {
    if (set.has(ch)) {
      parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts;
}

async function macroValueAsync(letter: string, mctx: MacroCtx, forExp: boolean): Promise<string | null> {
  switch (letter) {
    case "s":
      return mctx.senderFull;
    case "l":
      return mctx.senderLocal;
    case "o":
      return mctx.senderDomain;
    case "d":
      return mctx.currentDomain;
    case "i":
      return mctx.clientIp.version === 4 ? presentIp(mctx.clientIp) : nibbleForm(mctx.clientIp);
    case "h":
      return mctx.helo;
    case "v":
      return mctx.clientIp.version === 4 ? "in-addr" : "ip6";
    case "p":
      // 캐시는 평가 전체가 공유한다(EvalCtx.pMacroValue 주석 — 레코드마다 리셋되던 사고).
      if (mctx.ctx.pMacroValue === undefined) mctx.ctx.pMacroValue = await resolvePMacro(mctx);
      return mctx.ctx.pMacroValue;
    case "c":
      return forExp ? presentIp(mctx.clientIp) : null; // c/r/t는 exp 텍스트 전용(§7.3)
    case "r":
      return forExp ? "unknown" : null;
    case "t":
      return forExp ? String(Math.floor(Date.now() / 1000)) : null;
    default:
      return null;
  }
}

const MACRO_RE = /^([slodiphcrtvSLODIPHCRTV])(\d*)(r?)([.\-+,/_=]*)$/;

async function expandMacros(template: string, mctx: MacroCtx, forExp: boolean): Promise<string | null> {
  let out = "";
  let i = 0;
  while (i < template.length) {
    const ch = template[i]!;
    if (ch !== "%") {
      out += ch;
      i++;
      continue;
    }
    const next = template[i + 1];
    if (next === "%") {
      out += "%";
      i += 2;
      continue;
    }
    if (next === "_") {
      out += " ";
      i += 2;
      continue;
    }
    if (next === "-") {
      out += "%20";
      i += 2;
      continue;
    }
    if (next !== "{") return null;
    const close = template.indexOf("}", i + 2);
    if (close === -1) return null;
    const inner = template.slice(i + 2, close);
    const m = MACRO_RE.exec(inner);
    if (!m) return null;
    const letter = m[1]!.toLowerCase();
    const digitsStr = m[2]!;
    const reversed = m[3] === "r";
    const delims = m[4]! || ".";
    const value = await macroValueAsync(letter, mctx, forExp);
    if (value === null) return null;
    let parts = splitByDelims(value, delims);
    if (reversed) parts = parts.reverse();
    if (digitsStr) {
      const n = Number(digitsStr);
      if (n > 0 && n < parts.length) parts = parts.slice(parts.length - n);
    }
    out += parts.join(".");
    i = close + 1;
  }
  return out;
}

function expandDomainSpec(spec: string, mctx: MacroCtx): Promise<string> {
  return expandMacros(spec, mctx, false).then((expanded) => {
    if (expanded === null) throw new SpfEvalError("permerror", `매크로 확장 실패: ${spec}`);
    const domain = expanded.replace(/\.$/, "");
    if (!isValidDomain(domain)) throw new SpfEvalError("permerror", `잘못된 도메인(매크로 확장 후): ${domain}`);
    return domain;
  });
}

async function tryFetchExplanation(expSpec: string, ctx: EvalCtx, mctx: MacroCtx): Promise<void> {
  try {
    const domain = await expandDomainSpec(expSpec, mctx);
    const txts = await ctx.resolver.txt(domain);
    if (txts.length === 0) return;
    const expanded = await expandMacros(txts[0]!, mctx, true);
    if (expanded !== null) ctx.pendingExplanation = expanded;
  } catch {
    // exp는 부가 정보 — 실패해도 전체 fail 결과에는 영향 없음
  }
}

// ---------------------------------------------------------------------------
// 메커니즘 파싱/평가
// ---------------------------------------------------------------------------

type Qualifier = "+" | "-" | "~" | "?";

interface Mechanism {
  qualifier: Qualifier;
  type: "all" | "ip4" | "ip6" | "a" | "mx" | "ptr" | "include" | "exists";
  arg: string | null;
  cidr4: number | null;
  cidr6: number | null;
}

function isMechanismTerm(term: string): boolean {
  const t = term.replace(/^[+\-~?]/, "");
  return (
    /^all$/i.test(t) ||
    /^(include|exists):/i.test(t) ||
    /^a(:|\/|$)/i.test(t) ||
    /^mx(:|\/|$)/i.test(t) ||
    /^ptr(:|$)/i.test(t) ||
    /^ip4:/i.test(t) ||
    /^ip6:/i.test(t)
  );
}

function parseMechanism(term: string): Mechanism | null {
  const qm = /^([+\-~?])?(.*)$/.exec(term)!;
  const qualifier = (qm[1] as Qualifier | undefined) ?? "+";
  const rest = qm[2]!;

  if (/^all$/i.test(rest)) return { qualifier, type: "all", arg: null, cidr4: null, cidr6: null };

  let m = /^ip4:([^/]+)(?:\/(\d{1,2}))?$/i.exec(rest);
  if (m) return { qualifier, type: "ip4", arg: m[1]!, cidr4: m[2] ? Number(m[2]) : 32, cidr6: null };

  m = /^ip6:([^/]+)(?:\/(\d{1,3}))?$/i.exec(rest);
  if (m) return { qualifier, type: "ip6", arg: m[1]!, cidr4: null, cidr6: m[2] ? Number(m[2]) : 128 };

  m = /^a(?::([^/]*))?(?:\/(\d{1,2}))?(?:\/\/(\d{1,3}))?$/i.exec(rest);
  if (m) return { qualifier, type: "a", arg: m[1] || null, cidr4: m[2] ? Number(m[2]) : 32, cidr6: m[3] ? Number(m[3]) : 128 };

  m = /^mx(?::([^/]*))?(?:\/(\d{1,2}))?(?:\/\/(\d{1,3}))?$/i.exec(rest);
  if (m) return { qualifier, type: "mx", arg: m[1] || null, cidr4: m[2] ? Number(m[2]) : 32, cidr6: m[3] ? Number(m[3]) : 128 };

  m = /^ptr(?::(.+))?$/i.exec(rest);
  if (m) return { qualifier, type: "ptr", arg: m[1] || null, cidr4: null, cidr6: null };

  m = /^include:(.+)$/i.exec(rest);
  if (m) return { qualifier, type: "include", arg: m[1]!, cidr4: null, cidr6: null };

  m = /^exists:(.+)$/i.exec(rest);
  if (m) return { qualifier, type: "exists", arg: m[1]!, cidr4: null, cidr6: null };

  return null;
}

function qualifierToResult(q: Qualifier): "pass" | "fail" | "softfail" | "neutral" {
  if (q === "+") return "pass";
  if (q === "-") return "fail";
  if (q === "~") return "softfail";
  return "neutral";
}

async function evalMechanism(mech: Mechanism, ctx: EvalCtx, mctx: MacroCtx): Promise<boolean> {
  switch (mech.type) {
    case "all":
      return true;

    case "ip4": {
      const net = parseIp(mech.arg!);
      if (!net || net.version !== 4) throw new SpfEvalError("permerror", `잘못된 ip4 네트워크: ${mech.arg}`);
      if (mech.cidr4! < 0 || mech.cidr4! > 32) throw new SpfEvalError("permerror", `잘못된 ip4 prefix: /${mech.cidr4}`);
      return ctx.clientIp.version === 4 && ipInCidr(ctx.clientIp, net, mech.cidr4!);
    }

    case "ip6": {
      const net = parseIp(mech.arg!);
      if (!net || net.version !== 6) throw new SpfEvalError("permerror", `잘못된 ip6 네트워크: ${mech.arg}`);
      if (mech.cidr6! < 0 || mech.cidr6! > 128) throw new SpfEvalError("permerror", `잘못된 ip6 prefix: /${mech.cidr6}`);
      return ctx.clientIp.version === 6 && ipInCidr(ctx.clientIp, net, mech.cidr6!);
    }

    case "a": {
      countLookup(ctx);
      const domain = mech.arg ? await expandDomainSpec(mech.arg, mctx) : mctx.currentDomain;
      const addrs = await lookupAddrs(domain, ctx.clientIp.version, ctx, true);
      const prefix = ctx.clientIp.version === 4 ? mech.cidr4! : mech.cidr6!;
      return addrs.some((a) => ipInCidr(ctx.clientIp, a, prefix));
    }

    case "mx": {
      countLookup(ctx);
      const domain = mech.arg ? await expandDomainSpec(mech.arg, mctx) : mctx.currentDomain;
      const mxRecords = (await safeMx(domain, ctx)).slice(0, 10);
      const prefix = ctx.clientIp.version === 4 ? mech.cidr4! : mech.cidr6!;
      for (const mx of mxRecords) {
        const addrs = await lookupAddrs(mx.exchange, ctx.clientIp.version, ctx, false);
        if (addrs.some((a) => ipInCidr(ctx.clientIp, a, prefix))) return true;
      }
      return false;
    }

    case "ptr": {
      countLookup(ctx);
      const domain = mech.arg ? await expandDomainSpec(mech.arg, mctx) : mctx.currentDomain;
      const names = (await safePtr(ctx.clientIp, ctx)).slice(0, 10);
      for (const name of names) {
        const addrs = await lookupAddrs(name, ctx.clientIp.version, ctx, false);
        const confirmed = addrs.some((a) => a.bytes.equals(ctx.clientIp.bytes));
        if (!confirmed) continue;
        const lname = name.toLowerCase().replace(/\.$/, "");
        const ldomain = domain.toLowerCase().replace(/\.$/, "");
        if (lname === ldomain || lname.endsWith("." + ldomain)) return true;
      }
      return false;
    }

    case "exists": {
      countLookup(ctx);
      const domain = await expandDomainSpec(mech.arg!, mctx);
      const addrs = await lookupAddrs(domain, 4, ctx, true);
      return addrs.length > 0;
    }

    case "include": {
      countLookup(ctx);
      const domain = await expandDomainSpec(mech.arg!, mctx);
      const sub = await checkHostInner(domain, ctx, mctx, false);
      return sub === "pass";
    }
  }
}

// ---------------------------------------------------------------------------
// 레코드 평가 / 재귀
// ---------------------------------------------------------------------------

async function evaluateRecord(record: string, currentDomain: string, ctx: EvalCtx, mb: MacroCtx): Promise<SpfResultValue> {
  const mctx: MacroCtx = { ...mb, currentDomain };
  const body = record.trim().slice(6).trim(); // "v=spf1" 6글자 제거
  const terms = body.length === 0 ? [] : body.split(/\s+/);

  const mechanisms: Mechanism[] = [];
  let redirectSpec: string | null = null;
  let expSpec: string | null = null;
  let sawRedirect = false;
  let sawExp = false;

  // 1단계: 전체 레코드 구문 검증 + 모디파이어 수집 (RFC 7208 §4.6: 레코드 어디든 구문 오류가
  // 있으면 앞쪽 메커니즘이 먼저 매치되더라도 즉시 permerror).
  for (const term of terms) {
    if (isMechanismTerm(term)) {
      const mech = parseMechanism(term);
      if (!mech) throw new SpfEvalError("permerror", `잘못된 메커니즘 구문: ${term}`);
      mechanisms.push(mech);
      continue;
    }
    const modMatch = /^([A-Za-z][A-Za-z0-9_.\-]*)=(.+)$/.exec(term);
    if (!modMatch) throw new SpfEvalError("permerror", `알 수 없는 항목: ${term}`);
    const name = modMatch[1]!.toLowerCase();
    const value = modMatch[2]!;
    if (name === "redirect") {
      if (sawRedirect) throw new SpfEvalError("permerror", "redirect 모디파이어 중복");
      sawRedirect = true;
      redirectSpec = value;
    } else if (name === "exp") {
      if (sawExp) throw new SpfEvalError("permerror", "exp 모디파이어 중복");
      sawExp = true;
      expSpec = value;
    }
    // 그 외 알 수 없는 모디파이어는 RFC 7208 §6에 따라 무시
  }

  // 2단계: 메커니즘을 등장 순서대로 평가, 첫 매치에서 확정.
  for (const mech of mechanisms) {
    const matched = await evalMechanism(mech, ctx, mctx);
    if (matched) {
      const outcome = qualifierToResult(mech.qualifier);
      if (outcome === "fail" && expSpec) await tryFetchExplanation(expSpec, ctx, mctx);
      return outcome;
    }
  }

  if (redirectSpec) {
    countLookup(ctx);
    const domain = await expandDomainSpec(redirectSpec, mctx);
    return checkHostInner(domain, ctx, mctx, false);
  }

  return "neutral"; // 매치 없음 + redirect 없음 → 암묵적 ?all (RFC 7208 §4.7)
}

/**
 * isTop=true: 최초(원래) 도메인 평가 — SPF 레코드가 없으면 "none".
 * isTop=false: include/redirect로 진입한 재귀 평가 — 레코드가 없으면 permerror.
 */
async function checkHostInner(domain: string, ctx: EvalCtx, mb: MacroCtx, isTop: boolean): Promise<SpfResultValue> {
  if (!isValidDomain(domain)) {
    if (isTop) return "none";
    throw new SpfEvalError("permerror", `잘못된 도메인: ${domain}`);
  }
  const record = await fetchSpfRecord(domain, ctx, !isTop);
  if (record === null) {
    if (isTop) return "none";
    throw new SpfEvalError("permerror", `${domain}: SPF 레코드 없음`);
  }
  return evaluateRecord(record, domain, ctx, mb);
}

// ---------------------------------------------------------------------------
// 공개 API
// ---------------------------------------------------------------------------

export async function checkSpf(input: SpfInput, resolver: DnsResolver): Promise<SpfResult> {
  const clientIp = parseIp(input.ip);
  if (!clientIp) {
    return { result: "permerror", domain: input.mailFrom || input.helo, explanation: `잘못된 IP 주소: ${input.ip}` };
  }

  let senderFull: string;
  let senderLocal: string;
  let senderDomain: string;
  if (input.mailFrom && input.mailFrom.includes("@")) {
    const at = input.mailFrom.lastIndexOf("@");
    senderLocal = input.mailFrom.slice(0, at) || "postmaster";
    senderDomain = input.mailFrom.slice(at + 1);
    senderFull = input.mailFrom;
  } else {
    // RFC 7208 §2.4: MAIL FROM이 널 리턴패스(빈 문자열)이거나 '@' 없이 손상됐으면 HELO identity 사용.
    senderLocal = "postmaster";
    senderDomain = input.helo;
    senderFull = `postmaster@${input.helo}`;
  }

  if (!senderDomain || !isValidDomain(senderDomain)) {
    return { result: "none", domain: senderDomain || "" };
  }

  const ctx: EvalCtx = { resolver, lookups: 0, voidLookups: 0, clientIp };
  const mb: MacroCtx = {
    senderFull,
    senderLocal,
    senderDomain,
    helo: input.helo,
    clientIp,
    currentDomain: senderDomain,
    resolver,
    ctx,
  };

  try {
    const result = await checkHostInner(senderDomain, ctx, mb, true);
    return result === "fail" && ctx.pendingExplanation !== undefined
      ? { result, domain: senderDomain, explanation: ctx.pendingExplanation }
      : { result, domain: senderDomain };
  } catch (err) {
    if (err instanceof SpfEvalError) {
      return { result: err.kind, domain: senderDomain, explanation: err.message };
    }
    return { result: "temperror", domain: senderDomain, explanation: describeErr(err) };
  }
}
