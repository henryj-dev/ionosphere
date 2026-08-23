/**
 * 최소 DER(ASN.1) 인코더 — 셀프사인 X.509 + ACME CSR 생성용(zero-dep). 인코딩 전용.
 * 각 노드는 Uint8Array(완성 TLV)로 표현하고 합성한다.
 */

const enc = new TextEncoder();

function encodeLen(len: number): Uint8Array {
  if (len < 0x80) return Uint8Array.of(len);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

/** tag + length + content. */
export function tlv(tag: number, content: Uint8Array): Uint8Array {
  const len = encodeLen(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

function concat(items: Uint8Array[]): Uint8Array {
  const total = items.reduce((n, x) => n + x.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const x of items) {
    out.set(x, off);
    off += x.length;
  }
  return out;
}

export function seq(...items: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(items));
}
export function set(...items: Uint8Array[]): Uint8Array {
  return tlv(0x31, concat(items));
}

/**
 * INTEGER — 양수 바이트열. number 또는 바이트열.
 *
 * DER은 **최소 길이 인코딩**을 요구한다(X.690 §8.3.2): 부호 비트에 필요한 경우가 아니면
 * 선행 0x00을 두면 안 된다. 예전엔 선행 0을 제거하지 않아, 난수에서 첫 바이트가 0x00으로
 * 나오면(직렬번호·ECDSA 서명값 등) **엄격한 파서가 거부하는 인증서가 만들어졌다** —
 * 실측 0.25%(1/256 기대치와 일치). 간헐적이라 "가끔 인증서가 안 먹는다"로만 보인다.
 */
export function int(value: number | Uint8Array): Uint8Array {
  let bytes: Uint8Array;
  if (typeof value === "number") {
    if (value === 0) return tlv(0x02, Uint8Array.of(0));
    const arr: number[] = [];
    let n = value;
    while (n > 0) {
      arr.unshift(n & 0xff);
      n = Math.floor(n / 256);
    }
    bytes = Uint8Array.from(arr);
  } else {
    bytes = value.length === 0 ? Uint8Array.of(0) : value;
  }
  // 선행 0x00 제거 — 단 다음 바이트의 최상위 비트가 서 있으면 그 0x00은 부호용이라 남긴다.
  let i = 0;
  while (i + 1 < bytes.length && bytes[i] === 0 && (bytes[i + 1]! & 0x80) === 0) i++;
  if (i > 0) bytes = bytes.subarray(i);
  if (bytes[0]! & 0x80) bytes = Uint8Array.of(0, ...bytes); // 양수 보장
  return tlv(0x02, bytes);
}

export function oid(dotted: string): Uint8Array {
  const parts = dotted.split(".").map(Number);
  const first = 40 * parts[0]! + parts[1]!;
  const body: number[] = [first];
  for (const p of parts.slice(2)) {
    const stack: number[] = [];
    let n = p;
    stack.unshift(n & 0x7f);
    n >>= 7;
    while (n > 0) {
      stack.unshift((n & 0x7f) | 0x80);
      n >>= 7;
    }
    body.push(...stack);
  }
  return tlv(0x06, Uint8Array.from(body));
}

export function bitString(content: Uint8Array, unusedBits = 0): Uint8Array {
  return tlv(0x03, Uint8Array.of(unusedBits, ...content));
}
export function octetString(content: Uint8Array): Uint8Array {
  return tlv(0x04, content);
}
export function boolean(v: boolean): Uint8Array {
  return tlv(0x01, Uint8Array.of(v ? 0xff : 0x00));
}
export function nullValue(): Uint8Array {
  return tlv(0x05, new Uint8Array(0));
}
export function utf8String(s: string): Uint8Array {
  return tlv(0x0c, enc.encode(s));
}
export function printableString(s: string): Uint8Array {
  return tlv(0x13, enc.encode(s));
}
export function ia5String(s: string): Uint8Array {
  return tlv(0x16, enc.encode(s));
}

/** UTCTime "YYMMDDHHMMSSZ"(2050 미만) / GeneralizedTime(이상). */
export function time(date: Date): Uint8Array {
  const y = date.getUTCFullYear();
  const p2 = (n: number) => String(n).padStart(2, "0");
  const body = `${p2(date.getUTCMonth() + 1)}${p2(date.getUTCDate())}${p2(date.getUTCHours())}${p2(date.getUTCMinutes())}${p2(date.getUTCSeconds())}Z`;
  if (y < 2050) return tlv(0x17, enc.encode(`${p2(y % 100)}${body}`));
  return tlv(0x18, enc.encode(`${y}${body}`));
}

/** context-specific 태그 [n]. constructed=true면 0xA0|n, false면 0x80|n. */
export function context(tagNum: number, constructed: boolean, content: Uint8Array): Uint8Array {
  return tlv((constructed ? 0xa0 : 0x80) | tagNum, content);
}

/** 이미 DER로 인코딩된 바이트를 그대로 노드로 취급(예: node의 SPKI export). */
export function raw(bytes: Uint8Array): Uint8Array {
  return bytes;
}

/** DER → PEM(라벨). */
export function toPem(der: Uint8Array, label: string): string {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
