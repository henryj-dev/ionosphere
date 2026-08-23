/**
 * SRS(Sender Rewriting Scheme) — 포워딩 시 envelope MAIL FROM를 재작성해 다음 홉의
 * SPF를 통과시킨다(RFC 저자 Levine의 SRS 명세, guerrilla/postsrsd 호환 구조).
 *
 * 우리 포워더 도메인만이 자신이 만든 SRS0/SRS1 주소를 되돌리므로(바운스 반송처가 우리),
 * 크로스벤더 호환보다 자기 일관성이 핵심이다 — 해시/타임스탬프 인코딩은 내부 대칭이면 충분.
 *
 * SRS0=<hash>=<tt>=<도메인>=<로컬>@<포워더>              최초 재작성
 * SRS1=<hash>=<tt>=<원포워더>=<srs0 잔여>@<새포워더>      이미 SRS0인 발신자의 재포워딩(체인)
 *
 * 서명 범위는 **포워더 도메인(`@` 오른쪽)을 포함**한다. 예전엔 로컬파트만 서명해서
 * 같은 토큰을 임의 도메인 뒤에 붙여도 통과했고, 그게 오픈 릴레이(감사 C-1)의 뿌리 중 하나였다.
 * 도메인은 wire에 중복해 싣지 않는다 — 주소 자체에서 복원되므로 서명 데이터에만 넣는다.
 *
 * 순수 함수 — node:crypto만 사용(의존성 제로 원칙). HTTP/DB 무관.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

/** base32 알파벳(RFC 4648) — 타임스탬프와 해시 인코딩용. */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TS_PRECISION_DAYS = 1024; // 2^10 — tt 2글자(2×5비트)로 표현 가능한 일수 주기
const MS_PER_DAY = 86_400_000;
/**
 * 해시 12글자 = 60비트.
 *
 * 예전엔 base64 4글자(24비트)였는데 `hashEquals`가 비교 전 양쪽을 소문자화해서 알파벳이
 * 64→38종으로 접혔고 실질 2²¹까지 붕괴했다(감사 H-3). `RCPT TO`가 250/550으로 답하는
 * 무제한 검증 오라클이라 미인증 원격이 무차별 대입으로 유효 SRS 주소를 만들어낼 수 있었다.
 *
 * 인코딩을 base64가 아니라 **base32로 바꾼 이유**가 이 수정의 핵심이다 —
 * 우리 수신 파이프라인이 배달 직전 수신자 주소를 통째로 소문자화한다
 * (`backend.ts` runInboundPipeline: `env.rcptTo.map((r) => r.toLowerCase())`).
 * 즉 `srsReverse`가 보는 주소는 **항상 소문자**다. 그래서 "대소문자 접기를 없앤다"는
 * 단순 수정은 실제 바운스를 전부 깨뜨린다(단위 테스트는 주소를 직접 넘기므로 못 잡는다).
 * base32는 알파벳에 대소문자 쌍이 없어 대문자 정규화가 엔트로피를 **한 비트도** 잃지 않는다.
 */
const HASH_LEN = 12;

export interface SrsOptions {
  /** HMAC 비밀키(운영자 주입, 회전 시 과거 SRS 주소는 만료). */
  secret: string;
  /** 되돌리기 허용 최대 나이(일). 기본 21. */
  maxAgeDays?: number;
  /** 테스트용 현재시각(ms) 주입. 기본 Date.now(). */
  now?: number;
}

const DEFAULT_MAX_AGE_DAYS = 21;

/**
 * base32 문자열을 대문자로 정규화 — 알파벳 밖 문자가 하나라도 있으면 null.
 *
 * `String.prototype.toUpperCase()`를 쓰지 않는 이유: 유니코드에는 대문자화하면 길이가
 * 늘어나는 문자가 있어('ﬀ' → "FF") 길이 검사를 통과한 입력이 비교 단계에서 늘어난다.
 * ASCII 범위만 손으로 접어 그런 입력을 애초에 거절한다.
 */
function normalizeB32(s: string): string | null {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 97 && c <= 122) c -= 32; // a-z → A-Z
    const isAlpha = c >= 65 && c <= 90; // A-Z
    const isDigit = c >= 50 && c <= 55; // 2-7
    if (!isAlpha && !isDigit) return null;
    out += String.fromCharCode(c);
  }
  return out;
}

/** 바이트열 앞에서부터 5비트씩 끊어 base32 len글자로. */
function base32Encode(bytes: Buffer, len: number): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    // acc는 매 바이트마다 하위 bits(<5)비트만 남기므로 13비트를 넘지 않는다(<<가 안전).
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >>> bits) & 31]!;
      if (out.length === len) return out;
    }
    acc &= (1 << bits) - 1;
  }
  return out;
}

/** 타임스탬프(오늘 일수 mod 1024)를 base32 2글자로. */
function encodeTimestamp(nowMs: number): string {
  const days = Math.floor(nowMs / MS_PER_DAY) % TS_PRECISION_DAYS;
  return B32[(days >> 5) & 31]! + B32[days & 31]!;
}

/** base32 2글자 → 오늘 기준 나이(일). 잘못된 문자는 null. */
function timestampAgeDays(tt: string, nowMs: number): number | null {
  if (tt.length !== 2) return null;
  const norm = normalizeB32(tt);
  if (norm === null) return null;
  const hi = B32.indexOf(norm[0]!);
  const lo = B32.indexOf(norm[1]!);
  if (hi < 0 || lo < 0) return null;
  const stamped = (hi << 5) | lo; // 0..1023
  const today = Math.floor(nowMs / MS_PER_DAY) % TS_PRECISION_DAYS;
  // stamped ≤ today면 same-cycle, 아니면 이전 주기로 감김
  let age = today - stamped;
  if (age < 0) age += TS_PRECISION_DAYS;
  return age;
}

/** tt 하나에 대한 만료 판정 — 형식 오류와 만료를 구분해 reason에 그대로 실어 보낸다. */
function checkAge(tt: string, nowMs: number, maxAgeDays: number): "ok" | "expired" | "bad-format" {
  const age = timestampAgeDays(tt, nowMs);
  if (age === null) return "bad-format";
  return age > maxAgeDays ? "expired" : "ok";
}

/**
 * HMAC-SHA256(secret, data)의 base32 앞 HASH_LEN글자.
 * data를 소문자화하므로 페이로드(도메인·로컬파트)의 대소문자 변형은 서명에 영향이 없다.
 * SHA-1이었던 것을 SHA-256으로 올렸다 — 잘라 쓰는 용도라 실익은 작지만 SHA-1 의존을 남길 이유가 없다.
 */
function computeHash(secret: string, data: string): string {
  return base32Encode(createHmac("sha256", secret).update(data.toLowerCase()).digest(), HASH_LEN);
}

/**
 * 상수시간 비교. base32는 대소문자 쌍이 없으므로 대문자 정규화 후 비교해도 공간이 접히지 않는다
 * (소문자화된 주소가 들어오는 이유는 HASH_LEN 주석 참고).
 * 알파벳 밖 문자·길이 불일치는 비교 전에 거절하는데, 이건 공격자 자신의 입력에 대한 정보라
 * 비밀에 대한 타이밍 정보를 흘리지 않는다.
 */
function hashEquals(expected: string, actual: string): boolean {
  if (actual.length !== expected.length) return false;
  const norm = normalizeB32(actual);
  if (norm === null) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(norm);
  return a.length === b.length && timingSafeEqual(a, b);
}

function splitAddress(addr: string): { local: string; domain: string } | null {
  const at = addr.lastIndexOf("@");
  if (at <= 0 || at === addr.length - 1) return null;
  return { local: addr.slice(0, at), domain: addr.slice(at + 1) };
}

/**
 * 포워딩 발신자 재작성 — origSender를 forwarderDomain 소속 SRS 주소로.
 * origSender가 이미 우리/타 포워더의 SRS0면 SRS1로 체인, SRS1이면 재서명.
 */
export function srsForward(origSender: string, forwarderDomain: string, opts: SrsOptions): string {
  const nowMs = opts.now ?? Date.now();
  const parsed = splitAddress(origSender);
  if (!parsed) throw new Error(`잘못된 발신자 주소: ${origSender}`);
  const { local, domain } = parsed;

  // 이미 SRS1= : 잔여부(=hash 뒤)만 유지하고 재서명.
  // **tt를 새로 찍지 않는다** — 체인을 계속 돌리는 것만으로 시계를 리셋해 무기한 연장하는
  // 우회를 막는다(감사 H-7). 만료는 최초 발급 시점 기준으로 흐른다.
  if (/^SRS1=/i.test(local)) {
    const rest = local.slice(local.indexOf("=", 5) + 1); // 첫 hash 필드 제거 → "tt=srsdomain=guts"
    const hash = computeHash(opts.secret, `${forwarderDomain}=${rest}`);
    return `SRS1=${hash}=${rest}@${forwarderDomain}`;
  }
  // SRS0= : SRS1로 승격(원 포워더 도메인 보존).
  // 새 tt를 찍지만 원 SRS0의 tt가 guts 안에 그대로 남아 reverse에서 **함께** 검사되므로
  // 만료된 SRS0이 승격으로 되살아나지는 않는다.
  if (/^SRS0=/i.test(local)) {
    const guts = local.slice(5); // "hash=tt=domain=orig"
    const payload = `${encodeTimestamp(nowMs)}=${domain}=${guts}`; // srs0가 있던 도메인 + 원 SRS0 잔여
    const hash = computeHash(opts.secret, `${forwarderDomain}=${payload}`);
    return `SRS1=${hash}=${payload}@${forwarderDomain}`;
  }
  // 최초 재작성 → SRS0
  const payload = `${encodeTimestamp(nowMs)}=${domain}=${local}`;
  const hash = computeHash(opts.secret, `${forwarderDomain}=${payload}`);
  return `SRS0=${hash}=${payload}@${forwarderDomain}`;
}

export type SrsReverseResult =
  | { ok: true; address: string }
  | { ok: false; reason: "not-srs" | "bad-format" | "bad-hash" | "expired" };

/**
 * SRS 주소 되돌리기(바운스 반송처 → 원 발신자).
 * SRS0 → 원 발신자(local@domain). SRS1 → 원 포워더의 SRS0 주소(그 홉이 다시 되돌림).
 */
export function srsReverse(srsAddress: string, opts: SrsOptions): SrsReverseResult {
  const parsed = splitAddress(srsAddress);
  if (!parsed) return { ok: false, reason: "bad-format" };
  const { local, domain: forwarderDomain } = parsed;
  const maxAge = opts.maxAgeDays ?? DEFAULT_MAX_AGE_DAYS;
  const nowMs = opts.now ?? Date.now();

  if (/^SRS0=/i.test(local)) {
    // SRS0=hash=tt=domain=local
    const parts = local.slice(5).split("=");
    if (parts.length < 4) return { ok: false, reason: "bad-format" };
    const [hash, tt, origDomain, ...localRest] = parts;
    const origLocal = localRest.join("="); // 로컬파트에 '='가 있었던 경우 복원
    const payload = `${tt}=${origDomain}=${origLocal}`;
    if (!hashEquals(computeHash(opts.secret, `${forwarderDomain}=${payload}`), hash!)) {
      return { ok: false, reason: "bad-hash" };
    }
    const age = checkAge(tt!, nowMs, maxAge);
    if (age !== "ok") return { ok: false, reason: age };
    return { ok: true, address: `${origLocal}@${origDomain}` };
  }

  if (/^SRS1=/i.test(local)) {
    // SRS1=hash=tt=srsdomain=guts → SRS0=guts@srsdomain
    const rest = local.slice(5);
    const eq = rest.indexOf("=");
    if (eq < 0) return { ok: false, reason: "bad-format" };
    const hash = rest.slice(0, eq);
    const payload = rest.slice(eq + 1); // "tt=srsdomain=guts"
    if (!hashEquals(computeHash(opts.secret, `${forwarderDomain}=${payload}`), hash)) {
      return { ok: false, reason: "bad-hash" };
    }
    const fields = payload.split("=");
    if (fields.length < 3) return { ok: false, reason: "bad-format" };
    const [tt, srsDomain, ...gutsRest] = fields;
    const guts = gutsRest.join("=");
    const outerAge = checkAge(tt!, nowMs, maxAge);
    if (outerAge !== "ok") return { ok: false, reason: outerAge };
    /**
     * 감싸고 있는 SRS0의 나이도 검사한다 — 승격이 시계를 리셋하는 우회를 막는다.
     * 안쪽 해시는 원 포워더의 secret으로 서명돼 있어 우리가 검증할 수 없지만 tt는 읽을 수 있다.
     * tt가 우리 형식이 아니면 만료를 판단할 수 없으므로 **거절**한다(fail closed) —
     * 이 잔여부는 SRS1을 만들 때 봉투발신자로 들어온 공격자 제어 문자열이기도 하다.
     */
    const gutsFields = guts.split("=");
    if (gutsFields.length < 4) return { ok: false, reason: "bad-format" };
    const innerAge = checkAge(gutsFields[1]!, nowMs, maxAge);
    if (innerAge !== "ok") return { ok: false, reason: innerAge };
    return { ok: true, address: `SRS0=${guts}@${srsDomain}` };
  }

  return { ok: false, reason: "not-srs" };
}

/** 주소가 SRS0/SRS1 로컬파트인지(대소문자 무시). */
export function isSrsAddress(addr: string): boolean {
  const parsed = splitAddress(addr);
  return parsed !== null && /^SRS[01]=/i.test(parsed.local);
}
