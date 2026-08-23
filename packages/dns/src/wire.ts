/**
 * DNS 와이어 포맷 인코더/디코더 (RFC 1035 §4). 소켓 I/O가 전혀 없는 **순수 모듈** —
 * 바이트열 in/out만 다루므로 단위테스트로 결정적으로 검증한다(리졸버 로직 테스트도
 * 여기서 만든 응답을 mock transport에 태워 재사용).
 *
 * 지원 레코드: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT. 그 외는 UNKNOWN(원시 바이트 보존).
 * 이름 압축(0xC0 포인터)은 **디코드에서만** 처리한다(실서버 응답 대응) — 인코드는 항상
 * 완전 이름을 쓴다(질의는 압축 불필요). TXT는 여러 character-string 조각을 이어붙인다.
 */

/** 레코드 타입 번호 (erasableSyntaxOnly: enum 금지 → const 객체). */
export const RRType = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  DS: 43,
  RRSIG: 46,
  DNSKEY: 48,
  TLSA: 52,
} as const;

export type RRTypeName = keyof typeof RRType;

/** 클래스 — 인터넷(IN)만 사용. */
export const RRClass = { IN: 1 } as const;

/** 응답 코드 (RFC 1035 §4.1.1). */
export const RCode = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
} as const;

/** 레코드 RDATA — 타입별 파싱 결과(kind로 판별). */
export type RData =
  | { kind: "A"; address: string }
  | { kind: "AAAA"; address: string }
  | { kind: "NS"; target: string }
  | { kind: "CNAME"; target: string }
  | { kind: "PTR"; target: string }
  | { kind: "MX"; preference: number; exchange: string }
  | { kind: "TXT"; text: string; chunks: string[] }
  | {
      kind: "SOA";
      mname: string;
      rname: string;
      serial: number;
      refresh: number;
      retry: number;
      expire: number;
      minimum: number;
    }
  /** DNSSEC 위임 서명자(RFC 4034 §5) — 부모 존이 자식 DNSKEY를 가리키는 해시. */
  | { kind: "DS"; keyTag: number; algorithm: number; digestType: number; digest: Uint8Array }
  /** DNSSEC 공개키(RFC 4034 §2). */
  | { kind: "DNSKEY"; flags: number; protocol: number; algorithm: number; publicKey: Uint8Array }
  /**
   * DNSSEC 서명(RFC 4034 §3). `signedData`를 만들려면 RDATA의 **서명 제외 앞부분**이
   * 그대로 필요해서 `rdataPrefix`를 함께 보관한다 — 재조립하면 바이트가 미묘하게 달라진다.
   */
  | {
      kind: "RRSIG";
      typeCovered: number;
      algorithm: number;
      labels: number;
      originalTtl: number;
      expiration: number;
      inception: number;
      keyTag: number;
      signerName: string;
      signature: Uint8Array;
      rdataPrefix: Uint8Array;
    }
  /** DANE 인증서 연관(RFC 6698). */
  | { kind: "TLSA"; usage: number; selector: number; matchingType: number; data: Uint8Array }
  | { kind: "UNKNOWN"; type: number; data: Uint8Array };

export interface DnsQuestion {
  name: string;
  type: number;
  class: number;
}

export interface DnsRecord {
  name: string;
  type: number;
  class: number;
  ttl: number;
  rdata: RData;
}

export interface DnsHeader {
  id: number;
  qr: boolean;
  opcode: number;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  rcode: number;
}

export interface DnsMessage {
  header: DnsHeader;
  questions: DnsQuestion[];
  answers: DnsRecord[];
  authorities: DnsRecord[];
  additionals: DnsRecord[];
}

/** 와이어 포맷이 깨졌을 때(범위 초과 등). 리졸버는 이를 일시 오류로 취급. */
export class DnsWireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnsWireError";
  }
}

// ─────────────────────────── 인코딩 ───────────────────────────

/** 가변 길이 바이트 버퍼 라이터. */
class ByteWriter {
  private buf: number[] = [];

  u8(n: number): void {
    this.buf.push(n & 0xff);
  }

  u16(n: number): void {
    this.buf.push((n >> 8) & 0xff, n & 0xff);
  }

  u32(n: number): void {
    this.buf.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }

  bytes(b: Uint8Array): void {
    for (const x of b) this.buf.push(x & 0xff);
  }

  /** 도메인 이름을 라벨 시퀀스로 인코딩(압축 안 함). 루트("" 또는 ".")는 0바이트. */
  name(n: string): void {
    const trimmed = n.replace(/\.$/, "");
    if (trimmed === "") {
      this.u8(0);
      return;
    }
    for (const label of trimmed.split(".")) {
      const bytes = encodeAscii(label);
      if (bytes.length === 0) throw new DnsWireError(`빈 라벨: ${n}`);
      if (bytes.length > 63) throw new DnsWireError(`라벨 길이 초과(>63): ${label}`);
      this.u8(bytes.length);
      this.bytes(bytes);
    }
    this.u8(0);
  }

  toUint8(): Uint8Array {
    return Uint8Array.from(this.buf);
  }

  get length(): number {
    return this.buf.length;
  }
}

function encodeAscii(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** "1.2.3.4" → 4바이트. */
function parseIpv4(s: string): Uint8Array {
  const parts = s.split(".");
  if (parts.length !== 4) throw new DnsWireError(`잘못된 IPv4: ${s}`);
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new DnsWireError(`잘못된 IPv4: ${s}`);
    out[i] = n;
  }
  return out;
}

/** "2001:db8::1" → 16바이트(`::` 압축 해제). */
function parseIpv6(s: string): Uint8Array {
  const halves = s.split("::");
  if (halves.length > 2) throw new DnsWireError(`잘못된 IPv6: ${s}`);
  const toGroups = (part: string): string[] => (part === "" ? [] : part.split(":"));
  const head = toGroups(halves[0]!);
  const tail = halves.length === 2 ? toGroups(halves[1]!) : [];

  let groups: string[];
  if (halves.length === 1) {
    if (head.length !== 8) throw new DnsWireError(`잘못된 IPv6: ${s}`);
    groups = head;
  } else {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) throw new DnsWireError(`잘못된 IPv6: ${s}`);
    groups = [...head, ...new Array<string>(missing).fill("0"), ...tail];
  }
  if (groups.length !== 8) throw new DnsWireError(`잘못된 IPv6: ${s}`);

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const v = parseInt(groups[i]!, 16);
    if (Number.isNaN(v) || v < 0 || v > 0xffff) throw new DnsWireError(`잘못된 IPv6: ${s}`);
    out[i * 2] = (v >> 8) & 0xff;
    out[i * 2 + 1] = v & 0xff;
  }
  return out;
}

function encodeRdata(w: ByteWriter, r: DnsRecord): void {
  const rd = r.rdata;
  switch (rd.kind) {
    case "A": {
      const b = parseIpv4(rd.address);
      w.u16(b.length);
      w.bytes(b);
      return;
    }
    case "AAAA": {
      const b = parseIpv6(rd.address);
      w.u16(b.length);
      w.bytes(b);
      return;
    }
    case "NS":
    case "CNAME":
    case "PTR": {
      // 길이 프리픽스를 나중에 채우기 위해 임시 라이터 사용(압축 없음).
      const inner = new ByteWriter();
      inner.name(rd.target);
      const bytes = inner.toUint8();
      w.u16(bytes.length);
      w.bytes(bytes);
      return;
    }
    case "MX": {
      const inner = new ByteWriter();
      inner.u16(rd.preference);
      inner.name(rd.exchange);
      const bytes = inner.toUint8();
      w.u16(bytes.length);
      w.bytes(bytes);
      return;
    }
    case "TXT": {
      const inner = new ByteWriter();
      for (const chunk of rd.chunks) {
        const b = encodeAscii(chunk);
        if (b.length > 255) throw new DnsWireError("TXT 조각 길이 초과(>255)");
        inner.u8(b.length);
        inner.bytes(b);
      }
      const bytes = inner.toUint8();
      w.u16(bytes.length);
      w.bytes(bytes);
      return;
    }
    case "SOA": {
      const inner = new ByteWriter();
      inner.name(rd.mname);
      inner.name(rd.rname);
      inner.u32(rd.serial);
      inner.u32(rd.refresh);
      inner.u32(rd.retry);
      inner.u32(rd.expire);
      inner.u32(rd.minimum);
      const bytes = inner.toUint8();
      w.u16(bytes.length);
      w.bytes(bytes);
      return;
    }
    case "UNKNOWN": {
      w.u16(rd.data.length);
      w.bytes(rd.data);
      return;
    }
  }
}

function encodeRecord(w: ByteWriter, r: DnsRecord): void {
  w.name(r.name);
  w.u16(r.type);
  w.u16(r.class);
  w.u32(r.ttl);
  encodeRdata(w, r);
}

/** 전체 DNS 메시지 인코딩(질의/응답 공용 — 테스트가 응답 생성에 재사용). */
export function encodeMessage(msg: DnsMessage): Uint8Array {
  const w = new ByteWriter();
  const h = msg.header;
  w.u16(h.id);
  let flags = 0;
  if (h.qr) flags |= 0x8000;
  flags |= (h.opcode & 0x0f) << 11;
  if (h.aa) flags |= 0x0400;
  if (h.tc) flags |= 0x0200;
  if (h.rd) flags |= 0x0100;
  if (h.ra) flags |= 0x0080;
  flags |= h.rcode & 0x0f;
  w.u16(flags);
  w.u16(msg.questions.length);
  w.u16(msg.answers.length);
  w.u16(msg.authorities.length);
  w.u16(msg.additionals.length);

  for (const q of msg.questions) {
    w.name(q.name);
    w.u16(q.type);
    w.u16(q.class);
  }
  for (const r of msg.answers) encodeRecord(w, r);
  for (const r of msg.authorities) encodeRecord(w, r);
  for (const r of msg.additionals) encodeRecord(w, r);
  return w.toUint8();
}

/**
 * EDNS0 OPT 의사 레코드가 광고하는 UDP 페이로드 크기.
 *
 * DNSSEC 응답은 RRSIG·DNSKEY 때문에 512옥텟을 쉽게 넘는다. 이 값을 올리지 않으면 서버가
 * TC를 세워 매 질의가 TCP로 떨어진다 — 동작은 하지만 느리다. 4096은 관행적 값이다.
 */
const EDNS_UDP_SIZE = 4096;

/**
 * 단일 질의 패킷 조립(RD 지정 — iterative는 0, 업스트림 재귀는 1).
 *
 * `dnssecOk`면 EDNS0 OPT를 붙이고 DO 비트를 세운다. ★DO 없이는 서버가 **RRSIG를 보내지
 * 않는다** — 서명이 없으니 검증기는 전부 "insecure"로 결론내고 DANE가 조용히 꺼진다.
 * OPT는 RData 유니온에 넣지 않고 바이트로 덧붙인다: 의사 레코드라 rdata 의미가 없고,
 * 인코더/디코더 유니온에 들이면 모든 사용처가 다뤄야 하는 변형이 하나 늘 뿐이다.
 */
export function encodeQuery(id: number, name: string, type: number, rd: boolean, dnssecOk = false): Uint8Array {
  const base = encodeMessage({
    header: { id, qr: false, opcode: 0, aa: false, tc: false, rd, ra: false, rcode: RCode.NOERROR },
    questions: [{ name, type, class: RRClass.IN }],
    answers: [],
    authorities: [],
    additionals: [],
  });
  if (!dnssecOk) return base;

  // OPT RR: 이름=루트(0x00), 타입=41, class=UDP 크기, TTL 상위비트=DO, RDLENGTH=0.
  const opt = new Uint8Array([
    0x00,
    ...u16be(41),
    ...u16be(EDNS_UDP_SIZE),
    0x00, // 확장 RCODE
    0x00, // EDNS 버전
    0x80, // DO=1
    0x00,
    ...u16be(0), // RDLENGTH
  ]);
  const out = new Uint8Array(base.length + opt.length);
  out.set(base, 0);
  out.set(opt, base.length);
  // ARCOUNT(헤더 오프셋 10-11) +1 — 안 올리면 파서가 OPT를 못 보고 서버가 FORMERR를 준다.
  const arcount = (((out[10] ?? 0) << 8) | (out[11] ?? 0)) + 1;
  out[10] = (arcount >> 8) & 0xff;
  out[11] = arcount & 0xff;
  return out;
}

function u16be(n: number): [number, number] {
  return [(n >> 8) & 0xff, n & 0xff];
}

// ─────────────────────────── 디코딩 ───────────────────────────

/**
 * 이름 하나를 읽으며 허용할 최대 단계 수(라벨 + 압축 점프).
 * RFC 1035의 이름 길이 상한 255옥텟 / 라벨당 최소 2옥텟이라 정상 이름은 128을 넘지 않는다.
 */
const MAX_NAME_STEPS = 128;

/** 전체 버퍼를 붙들고 절대 오프셋으로 읽는 리더(이름 압축 포인터 대응). */
class ByteReader {
  private view: Uint8Array;
  offset: number;

  constructor(view: Uint8Array) {
    this.view = view;
    this.offset = 0;
  }

  private ensure(n: number): void {
    if (this.offset + n > this.view.length) throw new DnsWireError("버퍼 범위 초과");
  }

  u8(): number {
    this.ensure(1);
    return this.view[this.offset++]!;
  }

  u16(): number {
    this.ensure(2);
    const v = (this.view[this.offset]! << 8) | this.view[this.offset + 1]!;
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.ensure(4);
    const v =
      (this.view[this.offset]! * 0x1000000 +
        ((this.view[this.offset + 1]! << 16) | (this.view[this.offset + 2]! << 8) | this.view[this.offset + 3]!)) >>>
      0;
    this.offset += 4;
    return v;
  }

  /**
   * 이미 읽은 구간의 **원본 바이트**를 그대로 돌려준다(offset 이동 없음).
   * RRSIG 검증 입력은 재조립하면 미묘하게 달라지므로 원본이 필요하다.
   */
  rangeBytes(from: number, to: number): Uint8Array {
    return this.view.subarray(from, to);
  }

  bytes(n: number): Uint8Array {
    this.ensure(n);
    const out = this.view.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  /**
   * 이름 읽기(압축 포인터 지원). this.offset은 최초 포인터 직후로만 전진한다
   * (점프 이후 바이트는 소비하지 않음 — RFC 1035 §4.1.4).
   */
  name(): string {
    const labels: string[] = [];
    let pos = this.offset;
    let jumped = false;
    let next = this.offset;
    /**
     * 압축 포인터 점프 횟수 상한.
     *
     * 예전 가드는 `guard > this.view.length`라 이름 하나당 O(n)까지 허용했다. 64KB TCP 응답을
     * 이름으로 가득 채우면 전체가 O(n²)(수십억 연산)이 되어 **악성 권한 서버 하나가 리졸버의
     * CPU를 태울 수 있다.** 정상 이름은 라벨이 128개를 넘지 않는다(RFC 1035의 이름 길이 255옥텟,
     * 라벨당 최소 2옥텟) — 그 상한이면 압축 체인도 함께 묶인다.
     */
    let guard = 0;
    for (;;) {
      if (guard++ > MAX_NAME_STEPS) throw new DnsWireError("이름 압축 루프");
      if (pos >= this.view.length) throw new DnsWireError("이름 범위 초과");
      const len = this.view[pos]!;
      if (len === 0) {
        if (!jumped) next = pos + 1;
        break;
      }
      if ((len & 0xc0) === 0xc0) {
        if (pos + 1 >= this.view.length) throw new DnsWireError("압축 포인터 범위 초과");
        const ptr = ((len & 0x3f) << 8) | this.view[pos + 1]!;
        if (!jumped) next = pos + 2;
        jumped = true;
        pos = ptr;
        continue;
      }
      if ((len & 0xc0) !== 0) throw new DnsWireError("알 수 없는 라벨 타입");
      pos += 1;
      if (pos + len > this.view.length) throw new DnsWireError("라벨 범위 초과");
      labels.push(decodeAscii(this.view.subarray(pos, pos + len)));
      pos += len;
    }
    this.offset = next;
    return labels.join(".");
  }
}

function decodeAscii(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** 4바이트 → "1.2.3.4". */
function formatIpv4(b: Uint8Array): string {
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}

/** 16바이트 → 압축된 IPv6 표기(RFC 5952: 최장 0연속 → "::"). */
function formatIpv6(b: Uint8Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((b[i]! << 8) | b[i + 1]!) >>> 0);

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return groups.map((x) => x.toString(16)).join(":");
  const head = groups.slice(0, bestStart).map((x) => x.toString(16)).join(":");
  const tail = groups.slice(bestStart + bestLen).map((x) => x.toString(16)).join(":");
  return `${head}::${tail}`;
}

function decodeRdata(r: ByteReader, type: number, rdlength: number): RData {
  const end = r.offset + rdlength;
  switch (type) {
    case RRType.DS: {
      if (rdlength < 5) throw new DnsWireError("DS RDATA 길이 오류");
      const keyTag = r.u16();
      const algorithm = r.u8();
      const digestType = r.u8();
      const digest = r.bytes(end - r.offset);
      return { kind: "DS", keyTag, algorithm, digestType, digest };
    }
    case RRType.DNSKEY: {
      if (rdlength < 5) throw new DnsWireError("DNSKEY RDATA 길이 오류");
      const flags = r.u16();
      const protocol = r.u8();
      const algorithm = r.u8();
      const publicKey = r.bytes(end - r.offset);
      return { kind: "DNSKEY", flags, protocol, algorithm, publicKey };
    }
    case RRType.RRSIG: {
      if (rdlength < 18) throw new DnsWireError("RRSIG RDATA 길이 오류");
      const start = r.offset;
      const typeCovered = r.u16();
      const algorithm = r.u8();
      const labels = r.u8();
      const originalTtl = r.u32();
      const expiration = r.u32();
      const inception = r.u32();
      const keyTag = r.u16();
      /**
       * ★서명자 이름은 **압축을 쓰지 않는다**(RFC 4034 §3.1.7). 그래서 여기서 읽은
       * 바이트 길이가 곧 원본 길이이고, `rdataPrefix`를 그 지점까지로 자를 수 있다.
       */
      const signerName = r.name();
      const prefixEnd = r.offset;
      const signature = r.bytes(end - r.offset);
      return {
        kind: "RRSIG",
        typeCovered,
        algorithm,
        labels,
        originalTtl,
        expiration,
        inception,
        keyTag,
        signerName,
        signature,
        // 검증 입력은 "RRSIG RDATA에서 서명을 뺀 앞부분"이다 — 원본 바이트를 그대로 쓴다.
        rdataPrefix: r.rangeBytes(start, prefixEnd),
      };
    }
    case RRType.TLSA: {
      if (rdlength < 4) throw new DnsWireError("TLSA RDATA 길이 오류");
      const usage = r.u8();
      const selector = r.u8();
      const matchingType = r.u8();
      const data = r.bytes(end - r.offset);
      return { kind: "TLSA", usage, selector, matchingType, data };
    }
    case RRType.A: {
      const b = r.bytes(rdlength);
      if (b.length !== 4) throw new DnsWireError("A RDATA 길이 오류");
      return { kind: "A", address: formatIpv4(b) };
    }
    case RRType.AAAA: {
      const b = r.bytes(rdlength);
      if (b.length !== 16) throw new DnsWireError("AAAA RDATA 길이 오류");
      return { kind: "AAAA", address: formatIpv6(b) };
    }
    case RRType.NS: {
      const target = r.name();
      r.offset = end;
      return { kind: "NS", target };
    }
    case RRType.CNAME: {
      const target = r.name();
      r.offset = end;
      return { kind: "CNAME", target };
    }
    case RRType.PTR: {
      const target = r.name();
      r.offset = end;
      return { kind: "PTR", target };
    }
    case RRType.MX: {
      const preference = r.u16();
      const exchange = r.name();
      r.offset = end;
      return { kind: "MX", preference, exchange };
    }
    case RRType.TXT: {
      const chunks: string[] = [];
      while (r.offset < end) {
        const len = r.u8();
        chunks.push(decodeAscii(r.bytes(len)));
      }
      r.offset = end;
      return { kind: "TXT", text: chunks.join(""), chunks };
    }
    case RRType.SOA: {
      const mname = r.name();
      const rname = r.name();
      const serial = r.u32();
      const refresh = r.u32();
      const retry = r.u32();
      const expire = r.u32();
      const minimum = r.u32();
      r.offset = end;
      return { kind: "SOA", mname, rname, serial, refresh, retry, expire, minimum };
    }
    default: {
      const data = r.bytes(rdlength).slice();
      return { kind: "UNKNOWN", type, data };
    }
  }
}

function decodeRecord(r: ByteReader): DnsRecord {
  const name = r.name();
  const type = r.u16();
  const cls = r.u16();
  const ttl = r.u32();
  const rdlength = r.u16();
  const rdata = decodeRdata(r, type, rdlength);
  return { name, type, class: cls, ttl, rdata };
}

/** 전체 DNS 메시지 디코딩. 깨진 입력은 DnsWireError. */
export function decodeMessage(buf: Uint8Array): DnsMessage {
  const r = new ByteReader(buf);
  const id = r.u16();
  const flags = r.u16();
  const header: DnsHeader = {
    id,
    qr: (flags & 0x8000) !== 0,
    opcode: (flags >> 11) & 0x0f,
    aa: (flags & 0x0400) !== 0,
    tc: (flags & 0x0200) !== 0,
    rd: (flags & 0x0100) !== 0,
    ra: (flags & 0x0080) !== 0,
    rcode: flags & 0x0f,
  };
  const qd = r.u16();
  const an = r.u16();
  const ns = r.u16();
  const ar = r.u16();

  const questions: DnsQuestion[] = [];
  for (let i = 0; i < qd; i++) {
    const name = r.name();
    const type = r.u16();
    const cls = r.u16();
    questions.push({ name, type, class: cls });
  }
  const answers: DnsRecord[] = [];
  for (let i = 0; i < an; i++) answers.push(decodeRecord(r));
  const authorities: DnsRecord[] = [];
  for (let i = 0; i < ns; i++) authorities.push(decodeRecord(r));
  const additionals: DnsRecord[] = [];
  for (let i = 0; i < ar; i++) additionals.push(decodeRecord(r));

  return { header, questions, answers, authorities, additionals };
}

/** IP 문자열 → PTR 조회 이름(in-addr.arpa / ip6.arpa). 파싱 불가 시 null. */
export function ptrQueryName(ip: string): string | null {
  if (ip.includes(":")) {
    let bytes: Uint8Array;
    try {
      bytes = parseIpv6(ip);
    } catch {
      return null;
    }
    // 주소 순서대로 상위 니블→하위 니블을 쌓은 뒤 전체를 뒤집으면
    // (마지막 바이트의 하위 니블부터) ip6.arpa 순서가 된다.
    const nibbles: string[] = [];
    for (const byte of bytes) {
      nibbles.push((byte >> 4).toString(16), (byte & 0x0f).toString(16));
    }
    return `${nibbles.reverse().join(".")}.ip6.arpa`;
  }
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
  }
  return `${parts.reverse().join(".")}.in-addr.arpa`;
}
