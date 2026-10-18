/**
 * TOTP (RFC 6238) — 관리 콘솔 MFA의 자체 검증기. 순수 계산이고 I/O가 없다.
 *
 * 왜 자체 구현인가: 의존성은 node 빌트인만 허용한다. HOTP(RFC 4226)는 HMAC 한 번과 자르기뿐이라
 * 외부 라이브러리를 들일 이유가 없다.
 *
 * 파라미터는 인증 앱들이 기본으로 맞추는 값으로 **고정한다**(SHA-1·30초·6자리). 바꿀 수 있게 열어 두면
 * 앱마다 무시하는 파라미터가 달라 "등록은 됐는데 코드가 안 맞는" 계정이 생긴다.
 *
 * ★재사용 방지는 호출자 몫이 아니라 **반환값의 계약**이다: `verifyTotp`는 맞은 스텝 번호를 돌려주고,
 * 저장소는 그 스텝이 마지막으로 쓴 스텝보다 클 때만 받아들인다. 같은 코드를 30초 안에 두 번 쓰는
 * 재전송(어깨너머 관찰·피싱 프록시)을 막는다.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
/** 시계 오차 허용 — 앞뒤 한 스텝(±30초). 넓힐수록 대입 성공 확률이 그만큼 커진다. */
export const TOTP_SKEW_STEPS = 1;
/** RFC 4226 §4 권장 최소 128비트, 권장 160비트. */
const SECRET_BYTES = 20;

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32(패딩 없음) — 인증 앱이 받는 형식. Crockford(ulid)와 다른 알파벳이다. */
export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(buffer << (5 - bits)) & 31];
  return out;
}

/** 공백·소문자·패딩을 허용한다(사람이 옮겨 적는 값이라). 모르는 문자는 null. */
export function base32Decode(text: string): Uint8Array | null {
  const clean = text.replace(/[\s=]/g, "").toUpperCase();
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const v = BASE32.indexOf(ch);
    if (v < 0) return null;
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/** 새 TOTP 비밀 — base32 문자열. 평문은 등록 화면에 한 번만 보여 주고 저장은 봉인해서 한다. */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(SECRET_BYTES));
}

/** 이 시각(ms)의 스텝 번호. */
export function totpStep(nowMs: number): number {
  return Math.floor(nowMs / 1000 / TOTP_PERIOD_SECONDS);
}

/** HOTP(RFC 4226 §5.3) — 한 스텝의 코드. `digits`는 테스트 벡터(8자리) 확인용으로만 연다. */
export function hotp(secret: Uint8Array, counter: number, digits: number = TOTP_DIGITS): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/**
 * 코드 검증 — 맞으면 그 **스텝 번호**, 아니면 null.
 *
 * `lastStep` 이하의 스텝은 맞아도 거절한다(재사용 방지). 허용 창 안의 스텝을 **전부** 계산해 비교한다 —
 * 맞는 스텝에서 바로 끝내면 비교 횟수로 어느 스텝이 맞았는지가 응답 시간에 실린다.
 */
export function verifyTotp(secretBase32: string, code: string, nowMs: number, lastStep: number | null): number | null {
  const secret = base32Decode(secretBase32);
  if (secret === null || secret.length === 0) return null;
  const given = code.replace(/\s/g, "");
  if (!/^\d+$/.test(given) || given.length !== TOTP_DIGITS) return null;
  const current = totpStep(nowMs);
  let matched: number | null = null;
  for (let delta = -TOTP_SKEW_STEPS; delta <= TOTP_SKEW_STEPS; delta++) {
    const step = current + delta;
    const expected = Buffer.from(hotp(secret, step));
    if (timingSafeEqual(expected, Buffer.from(given)) && (lastStep === null || step > lastStep)) matched = step;
  }
  return matched;
}

/** 인증 앱 등록용 otpauth URI(Key Uri Format). issuer·label은 사람이 앱에서 알아볼 이름이다. */
export function totpUri(secretBase32: string, issuer: string, label: string): string {
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: "SHA1", digits: String(TOTP_DIGITS), period: String(TOTP_PERIOD_SECONDS) });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?${params.toString()}`;
}
