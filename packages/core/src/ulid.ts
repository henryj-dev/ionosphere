/**
 * ULID — 앱 생성 객체 id (SCHEMA.md §2).
 * 48bit epoch-ms + 80bit 난수, Crockford base32, 26자.
 * 같은 ms 내에서는 난수부를 +1 증가시켜 단조성 보장 (InnoDB 클러스터 인덱스에
 * append-mostly 삽입이 되도록 — 리뷰 L2).
 */

const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

let lastTime = -1;
const lastRandom = new Uint8Array(10);

function encodeTime(time: number): string {
  let s = "";
  let t = time;
  for (let i = 0; i < 10; i++) {
    s = ENCODING[t % 32] + s;
    t = Math.floor(t / 32);
  }
  return s;
}

function encodeRandom(bytes: Uint8Array): string {
  // 80bit = 16 chars × 5bit. 비트 스트림으로 처리.
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ENCODING[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  // 80 % 5 === 0 이므로 잔여 비트 없음
  return out;
}

function incrementRandom(bytes: Uint8Array): void {
  for (let i = bytes.length - 1; i >= 0; i--) {
    const b = bytes[i]!;
    if (b < 0xff) {
      bytes[i] = b + 1;
      return;
    }
    bytes[i] = 0;
  }
  // 80bit 오버플로 — 같은 ms에 2^80회 생성은 실질 불가능
  throw new Error("ulid: random overflow within one millisecond");
}

export function ulid(now: number = Date.now()): string {
  if (now === lastTime) {
    incrementRandom(lastRandom);
  } else {
    lastTime = now;
    crypto.getRandomValues(lastRandom);
  }
  return encodeTime(now) + encodeRandom(lastRandom);
}

export function isUlid(value: string): boolean {
  if (value.length !== 26) return false;
  for (const ch of value) {
    if (!ENCODING.includes(ch)) return false;
  }
  return true;
}
