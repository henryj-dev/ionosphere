/**
 * RFC 6376 DKIM 서명 검증 + RFC 8301(rsa-sha1 거부) + RFC 8463(Ed25519).
 * 순수 패키지 — DNS 조회는 주입받은 resolveTxt로만 수행한다 (node:dns 직접 import 없음).
 */
import { createHash } from "node:crypto";
import { dkimPublicKey, verifyDkimData, type DkimAlgorithm } from "./crypto.ts";
import {
  canonBody,
  canonHeaderField,
  groupHeaderFields,
  normalizeLineEndings,
  parseHeaderFields,
  resolveHeaderSequence,
  splitMessage,
  type DkimCanonMode,
  type HeaderField,
} from "./canon.ts";

export type DkimVerifyOutcome = "pass" | "fail" | "permerror" | "temperror";

export interface DkimVerifyResult {
  domain: string;
  selector: string;
  result: DkimVerifyOutcome;
  error?: string;
  /** DNS 키 레코드의 t=y(testing) 플래그. 레코드까지 도달했다면 pass/fail 여부와 무관하게 표시. */
  testing?: boolean;
  /**
   * 서명의 `a=` 알고리즘. **판정을 알고리즘별로 집계할 수 있어야 한다.**
   *
   * ★왜 추가했나(2026-08-01): Ed25519 서명 구현이 RFC 8463 §3을 위반해 우리가 **규격을 지키는
   * 외부 발신자를 전부 `dkim=fail`로 판정해 왔다**(§4-7). 그런데 그 규모를 소급해서 셀 수가
   * 없었다 — 결과에 알고리즘이 없어 "ed25519 서명이 몇 건 fail이었나"를 로그에서 답할 방법이
   * 없었기 때문이다. 같은 종류의 결함이 다시 생기면 이번엔 집계로 드러나야 한다.
   *
   * `a=`를 읽기 전에 실패하는 경로(헤더 파싱 실패 등)에서는 없다 — 그래서 선택 필드다.
   */
  algorithm?: DkimAlgorithm;
}

interface ParsedTag {
  tag: string;
  value: string; // FWS 제거된 시맨틱 값
  rawStart: number; // 원본 text 내 값 구간(오프셋) — b= 블랭킹용
  rawEnd: number;
}

/**
 * RFC 6376 §3.2 tag-value-list 파싱: `tag=value; tag=value...`.
 * 값 내부 FWS(공백/CRLF)는 의미가 없어(§3.2) 전부 제거해 시맨틱 값을 만들되,
 * b= 태그를 원문에서 "지우기" 위해 각 태그 값의 원본 오프셋(rawStart/rawEnd)도 함께 기록한다.
 */
function parseTagList(text: string): ParsedTag[] | null {
  const tags: ParsedTag[] = [];
  let offset = 0;
  const segments = text.split(";");
  for (const segment of segments) {
    const segStart = offset;
    offset += segment.length + 1; // split이 삼킨 ';' 1글자 보정
    if (segment.trim() === "") continue;
    const eqIdx = segment.indexOf("=");
    if (eqIdx === -1) return null; // tag=value 형태가 아님 — 파싱 불가
    const tag = segment.slice(0, eqIdx).trim().toLowerCase();
    if (!tag) return null;
    const rawStart = segStart + eqIdx + 1;
    const rawEnd = segStart + segment.length;
    const value = segment.slice(eqIdx + 1).replace(/[ \t\r\n]+/g, "");
    tags.push({ tag, value, rawStart, rawEnd });
  }
  return tags;
}

function findTag(tags: ParsedTag[], name: string): string | null {
  for (const t of tags) if (t.tag === name) return t.value; // 중복 시 첫 값 채택
  return null;
}

function makeResult(
  domain: string,
  selector: string,
  outcome: DkimVerifyOutcome,
  error?: string,
  testing?: boolean,
): DkimVerifyResult {
  return {
    domain,
    selector,
    result: outcome,
    ...(error !== undefined ? { error } : {}),
    ...(testing !== undefined ? { testing } : {}),
  };
}

function sha256(bin: string): Buffer {
  return createHash("sha256").update(Buffer.from(bin, "latin1")).digest();
}

/**
 * 한 메시지에서 검증할 DKIM-Signature 헤더 수 상한.
 *
 * ★왜 필요한가(실측). 예전에는 상한이 없어 서명 하나당 DNS TXT 조회 1회가 나갔고, 조회 대상
 * 도메인은 전부 **서명자가 d=로 지정**한다. 헤더로 채운 인바운드 메시지 한 통이:
 *   1MB → 서명 7,445개 → 공격자 지정 도메인 7,445곳에 DNS 질의 (7.2초)
 *   4MB → 서명 29,616개 → 29,616회 (60.8초)
 * 즉 **미인증 발신자 한 명이 우리 리졸버를 임의 네임서버를 향한 질의 대포로 쓸 수 있었다**
 * (RFC 6376 §6.1은 검증자가 서명 수를 제한해도 된다고 명시한다). 실제 메일의 서명은 1~3개고
 * 포워더·메일링리스트가 몇 개 더 붙이는 정도라 10이면 정상 트래픽에 여유롭다.
 *
 * 상한을 넘긴 서명은 **버린다**. 이는 fail closed다 — DKIM 결과는 오직 pass를 "추가"할 뿐이라,
 * 버려서 얻을 수 있는 최악은 DMARC가 SPF로 떨어지는 것(더 엄격한 쪽)이지 통과가 아니다.
 */
const MAX_DKIM_SIGNATURES = 10;

async function verifyOne(
  field: HeaderField,
  groups: Map<string, HeaderField[]>,
  bodyHash: (mode: DkimCanonMode) => Buffer,
  resolveTxt: (name: string) => Promise<string[]>,
): Promise<DkimVerifyResult> {
  const colonIdx = field.raw.indexOf(":");
  const valueText = field.raw.slice(colonIdx + 1);
  const tags = parseTagList(valueText);
  if (!tags) return makeResult("", "", "permerror", "malformed DKIM-Signature 헤더");

  const domain = findTag(tags, "d") ?? "";
  const selector = findTag(tags, "s") ?? "";

  const v = findTag(tags, "v");
  if (v !== null && v !== "1") return makeResult(domain, selector, "permerror", `지원하지 않는 v=${v}`);

  const a = findTag(tags, "a");
  const bh = findTag(tags, "bh");
  const b = findTag(tags, "b");
  const h = findTag(tags, "h");
  if (!a || !bh || !b || !h || !domain || !selector) {
    return makeResult(domain, selector, "permerror", "필수 태그(a/b/bh/d/h/s) 누락");
  }
  if (a === "rsa-sha1") {
    return makeResult(domain, selector, "permerror", "rsa-sha1은 RFC 8301에 의해 거부됨");
  }
  if (a !== "rsa-sha256" && a !== "ed25519-sha256") {
    return makeResult(domain, selector, "permerror", `지원하지 않는 알고리즘 a=${a}`);
  }

  const hNames = h
    .split(":")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (!hNames.includes("from")) {
    return makeResult(domain, selector, "permerror", "h=에 from이 없음");
  }

  const c = findTag(tags, "c") ?? "simple/simple";
  const [headerCanonRaw, bodyCanonRaw] = c.split("/");
  const headerCanon = headerCanonRaw ?? "simple";
  const bodyCanon = bodyCanonRaw ?? "simple"; // c=에 body 알고리즘 생략 시 기본값은 simple (RFC 6376 §3.5)
  if (headerCanon !== "relaxed" && headerCanon !== "simple") {
    return makeResult(domain, selector, "permerror", `알 수 없는 헤더 정규화 c=${c}`);
  }
  if (bodyCanon !== "relaxed" && bodyCanon !== "simple") {
    return makeResult(domain, selector, "permerror", `알 수 없는 본문 정규화 c=${c}`);
  }

  const x = findTag(tags, "x");
  if (x !== null) {
    const exp = Number(x);
    if (Number.isFinite(exp) && exp * 1000 < Date.now()) {
      return makeResult(domain, selector, "fail", "서명 만료(x=)");
    }
  }

  let bhBytes: Buffer;
  let sigBytes: Buffer;
  try {
    bhBytes = Buffer.from(bh, "base64");
    sigBytes = Buffer.from(b, "base64");
    if (bhBytes.length !== 32) throw new Error("bh 길이 이상");
  } catch {
    return makeResult(domain, selector, "permerror", "bh= 또는 b= base64 디코딩 실패");
  }

  if (!bodyHash(bodyCanon).equals(bhBytes)) {
    return makeResult(domain, selector, "fail", "본문 해시(bh=) 불일치");
  }

  const resolved = resolveHeaderSequence(groups, hNames);
  const headerHashInput = resolved.map((f) => (f ? canonHeaderField(f, headerCanon) : "")).join("");

  // RFC 6376 §3.7: 해시 재구성 시 b= 태그의 "값"은 빈 문자열로 취급 — 태그 값의 원본 구간을
  // 그대로 잘라내(FWS/접힘까지 포함) 나머지(다른 태그·그 접힘)는 원문 그대로 보존한다.
  const bTag = tags.find((t) => t.tag === "b");
  const blankedValue = bTag ? valueText.slice(0, bTag.rawStart) + valueText.slice(bTag.rawEnd) : valueText;
  const dkimField: HeaderField = { name: field.name, raw: field.raw.slice(0, colonIdx) + ":" + blankedValue };
  const dkimFieldCanon = canonHeaderField(dkimField, headerCanon).replace(/\r\n$/, "");

  const dataToVerify = Buffer.from(headerHashInput + dkimFieldCanon, "latin1");

  let txtRecords: string[];
  try {
    txtRecords = await resolveTxt(`${selector}._domainkey.${domain}`);
  } catch (err) {
    return makeResult(domain, selector, "temperror", `DNS 조회 실패: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!txtRecords || txtRecords.length === 0) {
    return makeResult(domain, selector, "permerror", "DKIM 키 레코드를 찾을 수 없음");
  }

  // RFC 6376 §3.6.2.2: 키 레코드의 character-string들은 연접한다. RSA-2048 키는 항상
  // 255바이트를 넘어 분할되고, node의 resolveTxt는 이를 여러 레코드로 쪼개 반환하기도 한다
  // → 여러 개면 "연접본"을 우선 후보로, 이후 개별 레코드를 시도(진짜 복수 키 레코드 대비).
  // pass/fail은 유효 키로 판정된 것이므로 즉시 반환, permerror/temperror만 다음 후보로.
  const candidates = txtRecords.length > 1 ? [txtRecords.join(""), ...txtRecords] : [txtRecords[0]!];
  let last: DkimVerifyResult | null = null;
  for (const candidate of candidates) {
    last = tryKeyRecord(candidate, domain, selector, a, dataToVerify, sigBytes);
    if (last.result === "pass" || last.result === "fail") return last;
  }
  return last ?? makeResult(domain, selector, "permerror", "키 레코드 형식 오류");
}

/** 단일 키 레코드 문자열로 검증 시도 (RFC 6376 §3.6.2 키 파싱 + 크립토). */
function tryKeyRecord(
  record: string,
  domain: string,
  selector: string,
  a: string,
  dataToVerify: Buffer,
  sigBytes: Buffer,
): DkimVerifyResult {
  const keyTags = parseTagList(record);
  if (!keyTags) return makeResult(domain, selector, "permerror", "키 레코드 형식 오류");

  const kv = findTag(keyTags, "v");
  if (kv !== null && kv !== "DKIM1") {
    return makeResult(domain, selector, "permerror", `지원하지 않는 키 레코드 버전 v=${kv}`);
  }
  const p = findTag(keyTags, "p");
  if (p === null) return makeResult(domain, selector, "permerror", "키 레코드에 p= 없음");
  if (p === "") return makeResult(domain, selector, "permerror", "폐기된 키(p= 비어있음)");

  const kh = findTag(keyTags, "h");
  if (kh !== null && !kh.split(":").map((s) => s.trim().toLowerCase()).includes("sha256")) {
    return makeResult(domain, selector, "permerror", "키 레코드가 sha256 해시를 허용하지 않음");
  }

  const testing = (findTag(keyTags, "t") ?? "")
    .split(":")
    .map((s) => s.trim().toLowerCase())
    .includes("y");

  const k = findTag(keyTags, "k") ?? "rsa";
  const expectedK = a === "ed25519-sha256" ? "ed25519" : "rsa";
  if (k !== expectedK) {
    return makeResult(domain, selector, "permerror", `키 타입 불일치: a=${a} vs k=${k}`, testing);
  }

  let pubKeyBytes: Buffer;
  try {
    pubKeyBytes = Buffer.from(p, "base64");
  } catch {
    return makeResult(domain, selector, "permerror", "p= base64 디코딩 실패", testing);
  }

  try {
    // 와이어 포맷 차이(RSA=SPKI DER / Ed25519=RAW 32바이트)와 RFC 8301 비트수 검사는
    // crypto.ts가 소유한다 — arc.ts가 같은 일을 다른 방식으로 하고 있어 갈라졌었다.
    const algorithm = k === "rsa" ? "rsa-sha256" : "ed25519-sha256";
    const imported = dkimPublicKey(pubKeyBytes, algorithm);
    if (!imported.ok) return makeResult(domain, selector, "permerror", imported.reason, testing);
    const ok = verifyDkimData(dataToVerify, algorithm, imported.key, sigBytes);
    return makeResult(domain, selector, ok ? "pass" : "fail", ok ? undefined : "서명 불일치", testing);
  } catch (err) {
    return makeResult(
      domain,
      selector,
      "permerror",
      `키 파싱/검증 오류: ${err instanceof Error ? err.message : String(err)}`,
      testing,
    );
  }
}

/** DKIM-Signature 헤더별로 하나씩, 메시지에 등장하는 순서(top-to-bottom)대로 결과를 반환. */
export async function dkimVerify(
  raw: Uint8Array,
  resolveTxt: (name: string) => Promise<string[]>,
): Promise<DkimVerifyResult[]> {
  const bin = Buffer.from(raw).toString("latin1");
  const { headerBlock, body } = splitMessage(normalizeLineEndings(bin));
  const fields = parseHeaderFields(headerBlock);
  const sigFields = fields.filter((f) => f.name.trim().toLowerCase() === "dkim-signature");

  // 서명마다 다시 만들면 서명 수 N에 대해 O(N²)이 된다 — 헤더 그룹핑은 서명과 무관하므로 한 번만.
  const groups = groupHeaderFields(fields);

  // 본문 해시는 (본문, 정규화 모드)에만 의존하고 모드는 relaxed/simple 둘뿐이다. 서명마다
  // 다시 계산하면 25MB 본문 × 서명 수만큼 해싱하게 되므로 모드별로 한 번만 계산해 재사용한다.
  const hashCache = new Map<DkimCanonMode, Buffer>();
  const bodyHash = (mode: DkimCanonMode): Buffer => {
    let h = hashCache.get(mode);
    if (!h) {
      h = sha256(canonBody(body, mode));
      hashCache.set(mode, h);
    }
    return h;
  };

  const results: DkimVerifyResult[] = [];
  for (const field of sigFields.slice(0, MAX_DKIM_SIGNATURES)) {
    const result = await verifyOne(field, groups, bodyHash, resolveTxt);
    /**
     * 알고리즘을 여기서 붙이는 이유: `verifyOne`은 실패 경로가 23곳이고 각각 `makeResult`로
     * 즉시 반환한다. 그 전부에 인자를 하나 더 넘기면 변경이 넓어지는데, `a=`는 서명 헤더에서
     * 바로 읽을 수 있으므로 **호출 경계에서 한 번** 붙이는 편이 얇다.
     * 지원하지 않는 값(`rsa-sha1` 등)은 담지 않는다 — 타입이 두 알고리즘만 표현한다.
     */
    const a = findTag(parseTagList(field.raw.slice(field.raw.indexOf(":") + 1)) ?? [], "a");
    results.push(a === "rsa-sha256" || a === "ed25519-sha256" ? { ...result, algorithm: a } : result);
  }
  // 조용히 버리지 않는다 — Authentication-Results에 남아야 운영자가 폭주를 관측할 수 있다.
  if (sigFields.length > MAX_DKIM_SIGNATURES) {
    results.push(
      makeResult("", "", "permerror", `DKIM 서명 ${sigFields.length}개 — 상한(${MAX_DKIM_SIGNATURES}) 초과분은 검증하지 않음`),
    );
  }
  return results;
}
