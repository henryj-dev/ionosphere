/**
 * ARC — Authenticated Received Chain (RFC 8617). 포워딩 홉을 거쳐도 인증 결과를
 * 체인으로 보존한다(우리 포워딩과 보완). DKIM 프리미티브(canon.ts) 재사용.
 *
 * 각 홉은 ARC 세트 3개를 추가한다:
 *  - ARC-Authentication-Results (AAR): 이 홉의 Authentication-Results 스냅샷
 *  - ARC-Message-Signature (AMS): 메시지(헤더 h= + 본문 bh=)에 대한 DKIM류 서명
 *  - ARC-Seal (AS): 지금까지의 모든 ARC 헤더에 대한 서명 + 체인 상태(cv)
 *
 * cv(chain validation): 최초 홉은 none, 이후 홉은 수신 체인 검증 결과(pass/fail).
 */
import { createHash, type KeyObject } from "node:crypto";
import { dkimPublicKey, signDkimData, verifyDkimData } from "./crypto.ts";
import {
  canonBody,
  canonHeaderField,
  groupHeaderFields,
  normalizeLineEndings,
  parseHeaderFields,
  resolveHeaderSequence,
  splitMessage,
  type HeaderField,
} from "./canon.ts";
import type { DkimAlgorithm } from "./sign.ts";
import type { DnsResolver } from "./dns.ts";

const AMS_SIGNED_HEADERS = [
  "from",
  "to",
  "cc",
  "subject",
  "date",
  "message-id",
  "reply-to",
  "in-reply-to",
  "references",
  "mime-version",
  "content-type",
  "content-transfer-encoding",
];

const FOLD_WIDTH = 78;

/** b= 값만 78컬럼으로 접어 이어붙인다(sign.ts와 동일 규칙). */
function foldTail(headLength: number, tail: string): string {
  let out = "";
  let col = headLength;
  let cursor = 0;
  while (cursor < tail.length) {
    const room = Math.max(FOLD_WIDTH - col, 1);
    out += tail.slice(cursor, cursor + room);
    cursor += room;
    if (cursor < tail.length) {
      out += "\r\n\t";
      col = 1;
    }
  }
  return out;
}

/** 서명 프리미티브는 crypto.ts가 소유한다 — 예전에는 여기에 복제돼 있어 RFC 8463 위반이 두 벌이었다. */
function signData(data: Buffer, algorithm: DkimAlgorithm, privateKey: string): string {
  return signDkimData(data, algorithm, privateKey).toString("base64");
}

/** relaxed 정규화 후 b= 태그 값을 비운다(검증 재구성용). 단일 라인 전제(relaxed unfold). */
function blankB(canonLine: string): string {
  return canonLine.replace(/\bb=[^;\r\n]*/, "b=");
}

export interface ArcSet {
  instance: number;
  aar?: HeaderField;
  ams?: HeaderField;
  seal?: HeaderField;
}

/** 헤더에서 i= 태그 값을 추출. */
function instanceOf(field: HeaderField): number | null {
  const colon = field.raw.indexOf(":");
  const value = field.raw.slice(colon + 1);
  const m = value.match(/(?:^|;)\s*i=\s*(\d+)/);
  return m ? Number(m[1]) : null;
}

/** 메시지의 ARC 헤더를 인스턴스별 세트로 파싱(오름차순). */
export function parseArcChain(raw: Uint8Array): ArcSet[] {
  const bin = normalizeLineEndings(Buffer.from(raw).toString("latin1"));
  const { headerBlock } = splitMessage(bin);
  const fields = parseHeaderFields(headerBlock);
  const sets = new Map<number, ArcSet>();
  const get = (i: number): ArcSet => {
    let s = sets.get(i);
    if (!s) {
      s = { instance: i };
      sets.set(i, s);
    }
    return s;
  };
  for (const f of fields) {
    const name = f.name.trim().toLowerCase();
    if (name !== "arc-authentication-results" && name !== "arc-message-signature" && name !== "arc-seal") continue;
    const i = instanceOf(f);
    if (i === null || i < 1) continue;
    const set = get(i);
    if (name === "arc-authentication-results") set.aar = f;
    else if (name === "arc-message-signature") set.ams = f;
    else set.seal = f;
  }
  return [...sets.values()].sort((a, b) => a.instance - b.instance);
}

export interface ArcSealOptions {
  domain: string;
  selector: string;
  privateKey: string;
  algorithm: DkimAlgorithm;
  /** 이 홉의 Authentication-Results 값(authserv-id 포함, 전체). 예: "mx.ex; spf=pass ...; dkim=pass". */
  authResults: string;
  /** 수신 체인 검증 결과. 최초 홉(체인 없음)은 자동으로 none. */
  cv?: "none" | "pass" | "fail";
  timestamp?: number;
  /** AMS h= 대상(기본 표준 헤더 중 존재하는 것). ARC 헤더는 포함 금지. */
  signedHeaders?: string[];
}

/**
 * 다음 인스턴스의 ARC 세트 3개(AAR/AMS/AS)를 생성해 prepend용 문자열로 반환한다.
 * (트레일링 CRLF 없음 — 호출자가 `arcSeal(...) + "\r\n" + raw`로 붙인다)
 */
export function arcSeal(raw: Uint8Array, opts: ArcSealOptions): string {
  const chain = parseArcChain(raw);
  const i = (chain.length > 0 ? Math.max(...chain.map((s) => s.instance)) : 0) + 1;
  const cv = chain.length === 0 ? "none" : (opts.cv ?? "none");
  const t = opts.timestamp ?? Math.floor(Date.now() / 1000);

  // ── AAR ── (authResults는 authserv-id를 이미 포함)
  const aarText = `ARC-Authentication-Results: i=${i}; ${opts.authResults}`;
  const aarField: HeaderField = { name: "ARC-Authentication-Results", raw: aarText };

  // ── AMS (DKIM류 서명, 헤더명만 다름 + i= 추가) ──
  const bin = normalizeLineEndings(Buffer.from(raw).toString("latin1"));
  const { headerBlock, body } = splitMessage(bin);
  const groups = groupHeaderFields(parseHeaderFields(headerBlock));
  const candidates = (opts.signedHeaders ?? AMS_SIGNED_HEADERS)
    .map((n) => n.toLowerCase())
    .filter((n) => n !== "from" && groups.has(n));
  const hNames = groups.has("from") ? ["from", "from", ...candidates] : [...candidates];
  const resolved = resolveHeaderSequence(groups, hNames);
  const headerHashInput = resolved.map((f) => (f ? canonHeaderField(f, "relaxed") : "")).join("");
  const bh = createHash("sha256").update(Buffer.from(canonBody(body, "relaxed"), "latin1")).digest("base64");
  const amsTags = [
    `i=${i}`,
    `a=${opts.algorithm}`,
    `c=relaxed/relaxed`,
    `d=${opts.domain}`,
    `s=${opts.selector}`,
    `t=${t}`,
    `h=${hNames.join(":")}`,
    `bh=${bh}`,
    "b=",
  ];
  const amsUnsigned = `ARC-Message-Signature: ${amsTags.join("; ")}`;
  const amsSelfCanon = canonHeaderField({ name: "ARC-Message-Signature", raw: amsUnsigned }, "relaxed").replace(/\r\n$/, "");
  const amsSig = signData(Buffer.from(headerHashInput + amsSelfCanon, "latin1"), opts.algorithm, opts.privateKey);
  const amsText = amsUnsigned + foldTail(amsUnsigned.length, amsSig);
  const amsField: HeaderField = { name: "ARC-Message-Signature", raw: amsText };

  // ── AS (체인 전체 ARC 헤더에 대한 서명) ──
  const sealUnsigned = `ARC-Seal: i=${i}; a=${opts.algorithm}; t=${t}; cv=${cv}; d=${opts.domain}; s=${opts.selector}; b=`;
  const sealInput = buildSealInput(chain, aarField, amsField, { name: "ARC-Seal", raw: sealUnsigned });
  const sealSig = signData(Buffer.from(sealInput, "latin1"), opts.algorithm, opts.privateKey);
  const sealText = sealUnsigned + foldTail(sealUnsigned.length, sealSig);

  // prepend 순서: 관례상 위에서부터 ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results
  return [sealText, amsText, aarText].join("\r\n");
}

/**
 * ARC-Seal 서명 입력 구성 — 인스턴스 오름차순으로 각 세트의 AAR·AMS·AS를 relaxed 정규화해
 * 이어붙이고, 마지막(현재) AS는 b= 비운 뒤 트레일링 CRLF를 제거한다(RFC 8617 §5.1.1).
 */
function buildSealInput(priorChain: ArcSet[], newAar: HeaderField, newAms: HeaderField, newSeal: HeaderField): string {
  let out = "";
  for (const set of priorChain) {
    if (set.aar) out += canonHeaderField(set.aar, "relaxed");
    if (set.ams) out += canonHeaderField(set.ams, "relaxed");
    if (set.seal) out += canonHeaderField(set.seal, "relaxed");
  }
  out += canonHeaderField(newAar, "relaxed");
  out += canonHeaderField(newAms, "relaxed");
  // 현재 AS: b= 비우고 트레일링 CRLF 제거
  out += blankB(canonHeaderField(newSeal, "relaxed")).replace(/\r\n$/, "");
  return out;
}

/**
 * TXT p= 태그에서 공개키를 만든다. 알고리즘은 AMS/AS의 a=로 판단.
 *
 * Ed25519 임포트는 crypto.ts가 소유한다 — 예전에는 여기서 SPKI prefix(`302a30…`)를 붙이고
 * verify.ts는 JWK로 감싸, **같은 일을 두 방식으로** 하고 있었다(한쪽만 고치면 갈라진다).
 */
function publicKeyFromTxt(txtRecords: string[], algorithm: DkimAlgorithm): KeyObject | null {
  const joined = txtRecords.length > 1 ? txtRecords.join("") : (txtRecords[0] ?? "");

  /**
   * `k=`(키 타입)와 `a=`(서명 알고리즘)의 일치를 확인한다 — RFC 6376 §3.6.1의 `k=` 태그.
   *
   * ★왜 필요한가: 이 검사가 `verify.ts`(DKIM)에는 있고 **여기(ARC)에는 없었다**(2026-08-01
   * 크립토 정본화 중 발견). 그래서 ARC는 `a=ed25519-sha256`인데 `k=rsa` 레코드로도 키 임포트를
   * 시도했다. 임포트가 실패하면 `공개키 없음`으로 수렴해 안전한 쪽이지만, **실패 이유가
   * "타입 불일치"가 아니라 "키 없음"으로 보고돼 진단이 어긋난다** — 운영자는 DNS 레코드가
   * 없다고 읽는데 실제로는 잘못된 타입으로 게시한 것이다.
   *
   * 같은 검사가 두 곳에 있어야 하는 이유: DKIM과 ARC는 서명 대상·헤더가 달라 검증 함수를
   * 공유하지 않는다. 공유하는 것은 크립토 프리미티브(`crypto.ts`)뿐이고, `k=`는 TXT 파싱
   * 단계의 판정이라 그 계층에 속하지 않는다.
   *
   * `k=`가 아예 없으면 통과시킨다 — RFC 6376 §3.6.1이 기본값을 `rsa`로 정하지만, 생략된
   * 레코드를 거부하면 정상 발신자를 막는다. 명시된 값이 어긋날 때만 거부한다(fail closed의 범위).
   */
  const kMatch = joined.match(/(?:^|;)\s*k=\s*([A-Za-z0-9-]+)/);
  if (kMatch?.[1]) {
    const expected = algorithm === "ed25519-sha256" ? "ed25519" : "rsa";
    if (kMatch[1].toLowerCase() !== expected) return null;
  }

  const pMatch = joined.match(/(?:^|;)\s*p=\s*([A-Za-z0-9+/=\s]*)/);
  if (!pMatch || !pMatch[1]) return null;
  const p = pMatch[1].replace(/\s+/g, "");
  if (!p) return null;
  const imported = dkimPublicKey(Buffer.from(p, "base64"), algorithm);
  return imported.ok ? imported.key : null;
}

/** 헤더 필드에서 태그 맵 파싱(값 원본 유지). */
function parseTags(field: HeaderField): Map<string, string> {
  const colon = field.raw.indexOf(":");
  const value = field.raw.slice(colon + 1).replace(/\r\n/g, "");
  const map = new Map<string, string>();
  for (const part of value.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    map.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
  }
  return map;
}

export interface ArcVerifyResult {
  /** 체인 검증 상태 — RFC 8617 §4. none=체인 없음. */
  cv: "none" | "pass" | "fail";
  instances: number;
  reason?: string;
}

/**
 * ARC 체인 검증 → cv. 체인이 없으면 cv=none. 최신 AMS(메시지 서명)와 모든 AS(체인)를
 * 검증해 전부 통과하면 pass, 아니면 fail. 공개키는 resolveTxt로 조회(DKIM과 동일).
 */
/**
 * ARC 체인 길이 상한. 우리가 정한 값이 아니라 RFC 8617이 정한 값이다 —
 * §4.2.1 "Instance tag values can range from 1-50 (inclusive)",
 * §5.2 step 1 "The maximum number of ARC Sets that can be attached to a message is 50.
 * If more than the maximum number exist, the Chain Validation Status is 'fail', and the
 * algorithm stops here." 즉 초과 시 fail로 즉시 중단하는 것이 규격 그대로의 동작이라,
 * 정상 체인을 자를 여지가 없다(50을 넘은 체인은 정의상 유효하지 않다).
 *
 * 성능 측면에서도 여기서 끊어야 한다: 체인 검증은 O(N²)다. k번째 봉인(AS)의 서명 입력이
 * 1..k 세트 전체를 다시 정규화해 이어붙이기 때문이고, 거기에 세트마다 DNS 조회 1회와
 * 서명 검증 1회가 더 붙는다. 검증에 들어가기 **전에** 자르는 이유다.
 */
const MAX_ARC_SETS = 50;

export async function arcVerify(raw: Uint8Array, resolver: Pick<DnsResolver, "txt">): Promise<ArcVerifyResult> {
  const chain = parseArcChain(raw);
  if (chain.length === 0) return { cv: "none", instances: 0 };
  if (chain.length > MAX_ARC_SETS) {
    return { cv: "fail", instances: chain.length, reason: `ARC 세트 ${chain.length}개 — 상한(${MAX_ARC_SETS}) 초과` };
  }

  // 인스턴스 연속성 검사(1..N)
  for (let k = 0; k < chain.length; k++) {
    const set = chain[k]!;
    if (set.instance !== k + 1 || !set.aar || !set.ams || !set.seal) {
      return { cv: "fail", instances: chain.length, reason: `불완전/불연속 인스턴스 ${set.instance}` };
    }
  }
  const N = chain.length;

  // 1) 최신 AMS(i=N)로 메시지 서명 검증
  const amsOk = await verifyAms(raw, chain[N - 1]!.ams!, resolver);
  if (!amsOk.ok) return { cv: "fail", instances: N, reason: `AMS(i=${N}) 실패: ${amsOk.reason}` };

  // 2) 각 인스턴스의 AS(체인 서명) 검증
  for (let k = 1; k <= N; k++) {
    const asOk = await verifySeal(chain.slice(0, k), resolver);
    if (!asOk.ok) return { cv: "fail", instances: N, reason: `AS(i=${k}) 실패: ${asOk.reason}` };
  }
  return { cv: "pass", instances: N };
}

async function verifyAms(
  raw: Uint8Array,
  ams: HeaderField,
  resolver: Pick<DnsResolver, "txt">,
): Promise<{ ok: boolean; reason?: string }> {
  const tags = parseTags(ams);
  const d = tags.get("d");
  const s = tags.get("s");
  const a = tags.get("a") as DkimAlgorithm | undefined;
  const bh = tags.get("bh");
  const b = tags.get("b");
  const h = tags.get("h");
  if (!d || !s || !a || !bh || !b || !h) return { ok: false, reason: "AMS 태그 누락" };

  const bin = normalizeLineEndings(Buffer.from(raw).toString("latin1"));
  const { headerBlock, body } = splitMessage(bin);
  const groups = groupHeaderFields(parseHeaderFields(headerBlock));
  const actualBh = createHash("sha256").update(Buffer.from(canonBody(body, "relaxed"), "latin1")).digest("base64");
  if (actualBh !== bh) return { ok: false, reason: "bh 불일치" };

  const hNames = h.split(":").map((n) => n.trim().toLowerCase());
  const resolved = resolveHeaderSequence(groups, hNames);
  const headerHashInput = resolved.map((f) => (f ? canonHeaderField(f, "relaxed") : "")).join("");
  const amsBlank = blankB(canonHeaderField(ams, "relaxed")).replace(/\r\n$/, "");
  const dataToVerify = Buffer.from(headerHashInput + amsBlank, "latin1");

  return verifySig(dataToVerify, b, d, s, a, resolver);
}

async function verifySeal(
  chainUpToK: ArcSet[],
  resolver: Pick<DnsResolver, "txt">,
): Promise<{ ok: boolean; reason?: string }> {
  const current = chainUpToK[chainUpToK.length - 1]!;
  const seal = current.seal!;
  const tags = parseTags(seal);
  const d = tags.get("d");
  const s = tags.get("s");
  const a = tags.get("a") as DkimAlgorithm | undefined;
  const b = tags.get("b");
  if (!d || !s || !a || !b) return { ok: false, reason: "AS 태그 누락" };

  // 서명 입력: 1..k-1 세트 전체 + k의 AAR·AMS + k의 AS(b= 비움, 트레일링 CRLF 제거)
  let out = "";
  for (const set of chainUpToK.slice(0, -1)) {
    if (set.aar) out += canonHeaderField(set.aar, "relaxed");
    if (set.ams) out += canonHeaderField(set.ams, "relaxed");
    if (set.seal) out += canonHeaderField(set.seal, "relaxed");
  }
  out += canonHeaderField(current.aar!, "relaxed");
  out += canonHeaderField(current.ams!, "relaxed");
  out += blankB(canonHeaderField(seal, "relaxed")).replace(/\r\n$/, "");

  return verifySig(Buffer.from(out, "latin1"), b, d, s, a, resolver);
}

async function verifySig(
  data: Buffer,
  b: string,
  domain: string,
  selector: string,
  algorithm: DkimAlgorithm,
  resolver: Pick<DnsResolver, "txt">,
): Promise<{ ok: boolean; reason?: string }> {
  let txt: string[];
  try {
    txt = await resolver.txt(`${selector}._domainkey.${domain}`);
  } catch (err) {
    return { ok: false, reason: `DNS 실패: ${err instanceof Error ? err.message : String(err)}` };
  }
  const key = publicKeyFromTxt(txt, algorithm);
  if (!key) return { ok: false, reason: "공개키 없음" };
  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(b.replace(/\s+/g, ""), "base64");
  } catch {
    return { ok: false, reason: "b= 디코딩 실패" };
  }
  const ok = verifyDkimData(data, algorithm, key, sigBytes);
  return ok ? { ok: true } : { ok: false, reason: "서명 불일치" };
}
