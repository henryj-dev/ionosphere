/**
 * DNSSEC 검증 (RFC 4033-4035, 6605, 8080) — **DANE의 전제**.
 *
 * 왜 이것부터인가: RFC 7672는 TLSA 조회가 DNSSEC로 검증될 것을 요구한다. 검증 없이
 * TLSA를 믿으면 DNS를 속일 수 있는 공격자가 TLSA도 지우거나 바꿀 수 있어 **보안 이득이
 * 정확히 0**이다. 검증기 없이 "DANE 지원"을 적는 것은 없는 보안을 주장하는 것이다.
 *
 * ★**모든 실패는 "검증 안 됨"으로 수렴한다.** 파싱 오류·미지원 알고리즘·키 없음·서명
 * 불일치·시각 벗어남이 전부 같은 결과다. 검증기의 버그가 **거짓 보안**이 되는 것이 이
 * 코드의 최악이라, 확신이 없으면 언제나 "검증되지 않았다"로 간다 —
 * 그러면 호출부는 DANE를 적용하지 않고 기존 동작(기회적 TLS)으로 남는다.
 *
 * ⚠ **부재 증명(NSEC/NSEC3)은 구현하지 않았다.** 그래서 "TLSA가 없다"를 **안전하게 증명하지
 * 못한다** — 공격자가 TLSA 응답을 지우면 우리는 DANE 없이 진행한다. 그건 지금과 같은 상태라
 * 새로 나빠지는 것은 없지만, RFC 7672가 요구하는 다운그레이드 방어는 아니다. 켤 때 이 한계를
 * 알고 켜야 한다.
 */
import { createHash, createPublicKey, createVerify, verify as verifyOneShot } from "node:crypto";
import { RRType, type DnsRecord, type RData } from "./wire.ts";

/** 지원 알고리즘 — 실사용되는 셋만. 나머지는 "검증 안 됨"이다(추측하지 않는다). */
export const DNSSEC_ALGO = {
  RSASHA256: 8,
  ECDSAP256SHA256: 13,
  ED25519: 15,
} as const;

/** DS digest 타입 — SHA-256(2)만 받는다. SHA-1(1)은 이미 안전하지 않다. */
const DS_DIGEST_SHA256 = 2;

export type ValidationResult =
  /** 서명이 트러스트 앵커까지 이어졌다. */
  | { status: "secure" }
  /** 검증할 수 없었다(서명 없음·미지원 알고리즘·체인 끊김). DANE를 적용하지 않는다. */
  | { status: "insecure"; reason: string }
  /** 서명이 **있는데 틀렸다**. 응답을 버려야 한다 — 조작 신호다. */
  | { status: "bogus"; reason: string };

/** 이름을 정규 형식으로 — 소문자 + 루트는 빈 라벨(RFC 4034 §6.2). */
function canonicalNameBytes(name: string): Uint8Array {
  const out: number[] = [];
  const trimmed = name.replace(/\.$/, "").toLowerCase();
  if (trimmed.length > 0) {
    for (const label of trimmed.split(".")) {
      const bytes = new TextEncoder().encode(label);
      if (bytes.length > 63) throw new Error("label too long");
      out.push(bytes.length, ...bytes);
    }
  }
  out.push(0);
  return new Uint8Array(out);
}

function u16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}
function u32(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

/**
 * RDATA를 정규 형식으로 직렬화한다(RFC 4034 §6.2).
 *
 * ★이름이 든 타입은 **압축을 풀고 소문자로** 써야 한다. 응답에 실린 원본 바이트를 그대로
 * 쓰면 압축 포인터가 섞여 서명이 맞지 않는다 — 여기서 재조립하는 이유가 그것이다.
 * 반대로 이름이 없는 타입(A·AAAA·TLSA 등)은 원본을 그대로 쓴다.
 */
function canonicalRdata(rr: DnsRecord): Uint8Array | null {
  const d: RData = rr.rdata;
  switch (d.kind) {
    case "A":
    case "AAAA":
      return d.kind === "A" ? ipv4Bytes(d.address) : ipv6Bytes(d.address);
    case "NS":
    case "CNAME":
    case "PTR":
      return canonicalNameBytes(d.target);
    case "MX":
      return new Uint8Array([...u16(d.preference), ...canonicalNameBytes(d.exchange)]);
    case "TXT": {
      const out: number[] = [];
      for (const c of d.chunks) {
        const b = new TextEncoder().encode(c);
        out.push(b.length, ...b);
      }
      return new Uint8Array(out);
    }
    case "DS":
      return new Uint8Array([...u16(d.keyTag), d.algorithm, d.digestType, ...d.digest]);
    case "DNSKEY":
      return new Uint8Array([...u16(d.flags), d.protocol, d.algorithm, ...d.publicKey]);
    case "TLSA":
      return new Uint8Array([d.usage, d.selector, d.matchingType, ...d.data]);
    default:
      // 모르는 타입은 정규화할 수 없다 — 추측해서 검증하느니 "검증 안 됨"이 낫다.
      return null;
  }
}

function ipv4Bytes(a: string): Uint8Array {
  return new Uint8Array(a.split(".").map((x) => Number(x) & 0xff));
}
function ipv6Bytes(a: string): Uint8Array {
  // 축약(::)을 편 뒤 8그룹으로.
  const [head, tail] = a.split("::");
  const h = head ? head.split(":").filter(Boolean) : [];
  const t = tail ? tail.split(":").filter(Boolean) : [];
  const mid = new Array(Math.max(0, 8 - h.length - t.length)).fill("0");
  const groups = [...h, ...mid, ...t].map((g) => parseInt(g || "0", 16));
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    out[i * 2] = (g >> 8) & 0xff;
    out[i * 2 + 1] = g & 0xff;
  });
  return out;
}

/** RRset 정렬 — RDATA의 바이트 사전순(RFC 4034 §6.3). */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * 서명 대상 바이트를 만든다: `RRSIG_RDATA(서명 제외) | RR(1) | RR(2) | ...`
 * 각 RR은 `이름 | 타입 | 클래스 | 원본TTL | RDLENGTH | RDATA`(RFC 4035 §5.3.2).
 *
 * ★TTL은 응답의 값이 아니라 **RRSIG의 originalTtl**을 쓴다. 캐시를 거치면 TTL이 줄어드는데,
 * 그걸 쓰면 같은 응답이 경로에 따라 다르게 검증된다.
 */
function signedData(rrsig: Extract<RData, { kind: "RRSIG" }>, rrs: readonly DnsRecord[]): Uint8Array | null {
  const owner = canonicalNameBytes(rrs[0]!.name);
  const rows: Uint8Array[] = [];
  for (const rr of rrs) {
    const rdata = canonicalRdata(rr);
    if (rdata === null) return null;
    rows.push(
      new Uint8Array([
        ...owner,
        ...u16(rr.type),
        ...u16(rr.class),
        ...u32(rrsig.originalTtl),
        ...u16(rdata.length),
        ...rdata,
      ]),
    );
  }
  rows.sort((a, b) => compareBytes(a, b));
  const total = rrsig.rdataPrefix.length + rows.reduce((n, r) => n + r.length, 0);
  const out = new Uint8Array(total);
  out.set(rrsig.rdataPrefix, 0);
  let off = rrsig.rdataPrefix.length;
  for (const r of rows) {
    out.set(r, off);
    off += r.length;
  }
  return out;
}

/** DNSKEY RDATA → node 공개키. 지원하지 않는 형식이면 null(검증 안 됨으로 수렴). */
function publicKeyOf(algorithm: number, key: Uint8Array): ReturnType<typeof createPublicKey> | null {
  try {
    if (algorithm === DNSSEC_ALGO.ED25519) {
      if (key.length !== 32) return null;
      // SPKI 래핑: Ed25519 OID + BIT STRING
      const spki = new Uint8Array([
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...key,
      ]);
      return createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
    }
    if (algorithm === DNSSEC_ALGO.ECDSAP256SHA256) {
      if (key.length !== 64) return null;
      // 비압축 점(0x04) + X||Y → SPKI(prime256v1)
      const spki = new Uint8Array([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, ...key,
      ]);
      return createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
    }
    if (algorithm === DNSSEC_ALGO.RSASHA256) {
      // RFC 3110: exponent 길이(1 또는 3바이트) | exponent | modulus
      let i = 0;
      let expLen = key[0] ?? 0;
      i = 1;
      if (expLen === 0) {
        expLen = ((key[1] ?? 0) << 8) | (key[2] ?? 0);
        i = 3;
      }
      if (expLen === 0 || i + expLen >= key.length) return null;
      const exp = key.subarray(i, i + expLen);
      const mod = key.subarray(i + expLen);
      return createPublicKey({ key: rsaSpki(mod, exp), format: "der", type: "spki" });
    }
  } catch {
    return null;
  }
  return null;
}

/** DER 정수(선행 0 처리 포함). */
function derInt(b: Uint8Array): number[] {
  let s = 0;
  while (s < b.length - 1 && b[s] === 0) s++;
  const body = (b[s]! & 0x80) !== 0 ? [0, ...b.subarray(s)] : [...b.subarray(s)];
  return [0x02, ...derLen(body.length), ...body];
}
function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}
function rsaSpki(mod: Uint8Array, exp: Uint8Array): Buffer {
  const seq = [...derInt(mod), ...derInt(exp)];
  const rsaKey = [0x30, ...derLen(seq.length), ...seq];
  const bitStr = [0x03, ...derLen(rsaKey.length + 1), 0x00, ...rsaKey];
  const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const outer = [...algId, ...bitStr];
  return Buffer.from([0x30, ...derLen(outer.length), ...outer]);
}

/** ECDSA 원시 서명(R||S) → DER. node는 DER 또는 ieee-p1363을 받는다. */
function verifySignature(algorithm: number, key: ReturnType<typeof createPublicKey>, data: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (algorithm === DNSSEC_ALGO.ED25519) {
      return verifyOneShot(null, Buffer.from(data), key, Buffer.from(sig));
    }
    if (algorithm === DNSSEC_ALGO.ECDSAP256SHA256) {
      if (sig.length !== 64) return false;
      return verifyOneShot("sha256", Buffer.from(data), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(sig));
    }
    if (algorithm === DNSSEC_ALGO.RSASHA256) {
      const v = createVerify("sha256");
      v.update(Buffer.from(data));
      v.end();
      return v.verify(key, Buffer.from(sig));
    }
  } catch {
    return false;
  }
  return false;
}

/** DNSKEY의 key tag (RFC 4034 부록 B). */
export function keyTag(d: Extract<RData, { kind: "DNSKEY" }>): number {
  const rdata = new Uint8Array([...u16(d.flags), d.protocol, d.algorithm, ...d.publicKey]);
  let acc = 0;
  for (let i = 0; i < rdata.length; i++) {
    acc += i & 1 ? rdata[i]! : rdata[i]! << 8;
  }
  acc += (acc >> 16) & 0xffff;
  return acc & 0xffff;
}

/**
 * RRset을 주어진 DNSKEY들로 검증한다.
 *
 * ★서명 유효기간을 반드시 본다(RFC 4035 §5.3.1). 만료된 서명을 받아들이면 **재생 공격**이
 * 성립한다 — 옛 응답을 붙잡아 두었다가 나중에 먹인다.
 */
export function verifyRrset(
  rrs: readonly DnsRecord[],
  rrsigs: readonly DnsRecord[],
  keys: readonly DnsRecord[],
  now: number,
): ValidationResult {
  if (rrs.length === 0) return { status: "insecure", reason: "빈 RRset" };
  if (rrsigs.length === 0) return { status: "insecure", reason: "RRSIG 없음" };

  const dnskeys = keys.map((k) => k.rdata).filter((d): d is Extract<RData, { kind: "DNSKEY" }> => d.kind === "DNSKEY");
  if (dnskeys.length === 0) return { status: "insecure", reason: "DNSKEY 없음" };

  let sawSupported = false;
  for (const sigRr of rrsigs) {
    const sig = sigRr.rdata;
    if (sig.kind !== "RRSIG") continue;
    if (sig.typeCovered !== rrs[0]!.type) continue;
    const nowSec = Math.floor(now / 1000);
    // 유효기간 밖이면 그 서명은 쓰지 않는다(다른 서명이 있을 수 있으므로 계속 본다).
    if (nowSec < sig.inception || nowSec > sig.expiration) continue;

    const data = signedData(sig, rrs);
    if (data === null) continue;

    for (const k of dnskeys) {
      if (k.algorithm !== sig.algorithm) continue;
      if (keyTag(k) !== sig.keyTag) continue;
      const pub = publicKeyOf(k.algorithm, k.publicKey);
      if (!pub) continue; // 미지원 알고리즘 — "검증 안 됨"이지 실패가 아니다
      sawSupported = true;
      if (verifySignature(k.algorithm, pub, data, sig.signature)) return { status: "secure" };
    }
  }
  /**
   * ★여기까지 왔다는 것은 "쓸 수 있는 키로 검증을 시도했는데 전부 실패"이거나
   * "시도조차 못 했다"는 뜻이다. 앞의 것은 **조작 신호(bogus)**이고 뒤의 것은 단지
   * 검증 불가(insecure)다 — 둘을 뭉개면 조작을 못 알아본다.
   */
  return sawSupported
    ? { status: "bogus", reason: "서명 검증 실패" }
    : { status: "insecure", reason: "쓸 수 있는 키·알고리즘 없음" };
}

/**
 * DS가 DNSKEY를 가리키는지 확인한다(RFC 4034 §5.1.4).
 * digest = SHA-256(정규 이름 | DNSKEY RDATA).
 */
export function dsMatchesKey(ds: Extract<RData, { kind: "DS" }>, ownerName: string, key: Extract<RData, { kind: "DNSKEY" }>): boolean {
  if (ds.digestType !== DS_DIGEST_SHA256) return false; // SHA-1은 받지 않는다
  if (ds.algorithm !== key.algorithm) return false;
  if (ds.keyTag !== keyTag(key)) return false;
  const rdata = new Uint8Array([...u16(key.flags), key.protocol, key.algorithm, ...key.publicKey]);
  const digest = createHash("sha256").update(Buffer.from(canonicalNameBytes(ownerName))).update(Buffer.from(rdata)).digest();
  if (digest.length !== ds.digest.length) return false;
  // 길이가 같을 때만 비교한다 — 타이밍은 공개값이라 중요하지 않지만 형태는 맞춰 둔다.
  return compareBytes(new Uint8Array(digest), ds.digest) === 0;
}

export { RRType };
