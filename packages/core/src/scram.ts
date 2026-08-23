/**
 * SCRAM-SHA-256 서버측 (RFC 5802 + RFC 7677) — **순수 함수 + 명시적 상태**. I/O 없음.
 *
 * 왜 필요한가: PLAIN·LOGIN은 비밀번호를 그대로 서버에 넘긴다. TLS가 그 구간을 가려 주지만,
 * **서버는 매 로그인마다 평문 비밀번호를 손에 쥔다.** SCRAM은 그러지 않는다 — 서버가 가진
 * 것으로 클라이언트를 검증하되, 그 값으로 **클라이언트를 흉내 낼 수는 없다**(StoredKey는
 * ClientKey의 해시라 역산되지 않는다). 서버 침해 시 피해 범위가 다르다.
 *
 * ★대신 감수하는 것이 있다: SCRAM은 PBKDF2를 쓰고 이 저장소의 비밀번호 해시는 scrypt다.
 * PBKDF2는 메모리 하드가 아니라 오프라인 대입에 더 약하다. 그래서 **scrypt를 버리지 않고**
 * SCRAM 키를 함께 둔다(auth.ts) — PLAIN 검증은 계속 scrypt가 하고, SCRAM 교환에만 이 키를 쓴다.
 * 반복 횟수를 RFC 최소치(4096)보다 훨씬 높게 잡는 것도 그 보정이다.
 *
 * ⚠ **SASLprep(RFC 4013)을 완전히 구현하지 않는다.** 정규화를 NFKC로 근사한다 —
 * 비ASCII 비밀번호에서 클라이언트와 정규화가 갈리면 인증이 실패할 수 있다. 외부 의존성
 * 없이 전체 SASLprep(stringprep 테이블)을 넣는 비용이 그 위험보다 크다고 보고 명시해 둔다.
 */
import { createHash, createHmac, pbkdf2 as pbkdf2Cb, randomBytes, timingSafeEqual } from "node:crypto";

/** RFC 7677 최소치는 4096이지만, PBKDF2의 약한 오프라인 내성을 반복 횟수로 보정한다. */
export const SCRAM_DEFAULT_ITERATIONS = 100_000;
const SALT_BYTES = 16;
const KEY_LEN = 32; // SHA-256

export interface ScramKeys {
  salt: Buffer;
  iterations: number;
  /** `H(HMAC(SaltedPassword, "Client Key"))` — 검증에만 쓰인다(역산 불가). */
  storedKey: Buffer;
  /** `HMAC(SaltedPassword, "Server Key")` — 서버가 자기를 증명하는 데 쓴다. */
  serverKey: Buffer;
}

function pbkdf2(password: string, salt: Buffer, iterations: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // ★비동기 pbkdf2를 쓴다. 동기판은 이벤트 루프를 통째로 막는다 — scrypt에서 이미 겪은
    //   문제와 같은 부류다(auth.ts scryptAsync 주석). 한 프로세스에 전 프로토콜이 올라가 있다.
    pbkdf2Cb(password, salt, iterations, KEY_LEN, "sha256", (err, key) => (err ? reject(err) : resolve(key)));
  });
}

const hmac = (key: Buffer, data: string | Buffer): Buffer => createHmac("sha256", key).update(data).digest();
const sha256 = (data: Buffer): Buffer => createHash("sha256").update(data).digest();

/** SASLprep 근사 — NFKC. 위 ⚠ 참조. */
export function normalizePassword(password: string): string {
  return password.normalize("NFKC");
}

/** 비밀번호 → 저장할 키들. 평문은 여기서만 만지고 밖으로 나가지 않는다. */
export async function deriveScramKeys(
  password: string,
  opts: { salt?: Buffer; iterations?: number } = {},
): Promise<ScramKeys> {
  const salt = opts.salt ?? randomBytes(SALT_BYTES);
  const iterations = opts.iterations ?? SCRAM_DEFAULT_ITERATIONS;
  const saltedPassword = await pbkdf2(normalizePassword(password), salt, iterations);
  const clientKey = hmac(saltedPassword, "Client Key");
  return { salt, iterations, storedKey: sha256(clientKey), serverKey: hmac(saltedPassword, "Server Key") };
}

/** 클라이언트 first 메시지 파싱 결과. */
export interface ClientFirst {
  /** GS2 헤더(`n,,` 등) — 채널 바인딩 판정과 client-final의 `c=` 대조에 쓴다. */
  gs2Header: string;
  /** `n=...,r=...` — AuthMessage 계산에 **원문 그대로** 필요하다. */
  bare: string;
  username: string;
  clientNonce: string;
}

/** `=2C`·`=3D` 언이스케이프(RFC 5802 §5.1 saslname). */
function unescapeName(v: string): string | null {
  // 이스케이프 대상이 아닌 `=`가 남아 있으면 잘못된 입력이다 — 조용히 통과시키지 않는다.
  if (/=(?!2C|3D)/.test(v)) return null;
  return v.replace(/=2C/g, ",").replace(/=3D/g, "=");
}

export function parseClientFirst(message: string): ClientFirst | null {
  // gs2-header = gs2-cbind-flag "," [ authzid ] ","
  const m = message.match(/^(([ny]|p=[^,]+),[^,]*,)(.*)$/s);
  if (!m) return null;
  const gs2Header = m[1] ?? "";
  const bare = m[3] ?? "";
  /**
   * ★채널 바인딩(`p=`)을 요구하는 클라이언트는 **거절한다.** 우리는 tls-unique/exporter를
   * 제공하지 않으므로, 지원하는 척하고 진행하면 클라이언트가 기대한 보호가 없는 채로
   * 성공한다 — 없는 보안을 있다고 말하는 셈이다.
   */
  if (gs2Header.startsWith("p=")) return null;

  const attrs = new Map<string, string>();
  for (const part of bare.split(",")) {
    const eq = part.indexOf("=");
    if (eq <= 0) return null;
    // 첫 `=`만 구분자다. 값 안의 `=`(이스케이프·base64 패딩)는 그대로 둔다.
    if (!attrs.has(part.slice(0, eq))) attrs.set(part.slice(0, eq), part.slice(eq + 1));
  }
  const rawUser = attrs.get("n");
  const clientNonce = attrs.get("r");
  if (rawUser === undefined || !clientNonce) return null;
  const username = unescapeName(rawUser);
  if (username === null) return null;
  // nonce는 printable ASCII에서 `,`를 뺀 것(RFC 5802 §5.1). 아니면 뒤의 메시지 파싱이 갈린다.
  if (!/^[\x21-\x2b\x2d-\x7e]+$/.test(clientNonce)) return null;
  return { gs2Header, bare, username, clientNonce };
}

/** 서버 nonce — 클라이언트 nonce에 이어 붙는다. */
export function serverNonce(): string {
  return randomBytes(18).toString("base64");
}

export function buildServerFirst(input: { clientNonce: string; serverNonce: string; salt: Buffer; iterations: number }): string {
  return `r=${input.clientNonce}${input.serverNonce},s=${input.salt.toString("base64")},i=${input.iterations}`;
}

export interface ClientFinalVerdict {
  ok: boolean;
  /** 성공 시 서버가 보낼 마지막 메시지(`v=...`). 실패면 undefined. */
  serverFinal?: string;
  /** 실패 사유(로그용). 클라이언트에게는 구분해서 알려주지 않는다. */
  reason?: string;
}

/**
 * client-final 검증 + server-final 생성.
 *
 * ★실패 사유를 클라이언트에게 구분해 주지 않는다. "nonce가 틀렸다"와 "증명이 틀렸다"를
 * 나눠 알려주면 사용자 존재 여부·상태가 새어 나간다 — 인증 실패는 하나의 답이어야 한다.
 */
export function verifyClientFinal(input: {
  clientFirstBare: string;
  serverFirst: string;
  clientFinal: string;
  expectedNonce: string;
  gs2Header: string;
  storedKey: Buffer;
  serverKey: Buffer;
}): ClientFinalVerdict {
  const proofIdx = input.clientFinal.lastIndexOf(",p=");
  if (proofIdx < 0) return { ok: false, reason: "no-proof" };
  const withoutProof = input.clientFinal.slice(0, proofIdx);
  const proofB64 = input.clientFinal.slice(proofIdx + 3);

  const attrs = new Map<string, string>();
  for (const part of withoutProof.split(",")) {
    const eq = part.indexOf("=");
    if (eq <= 0) return { ok: false, reason: "malformed" };
    if (!attrs.has(part.slice(0, eq))) attrs.set(part.slice(0, eq), part.slice(eq + 1));
  }

  // ★`c=`는 gs2 헤더의 base64여야 한다. 다르면 **다운그레이드 시도**다 — 클라이언트가 채널
  //   바인딩을 요구했는데 중간자가 지운 경우가 여기서 잡힌다(RFC 5802 §6).
  if (attrs.get("c") !== Buffer.from(input.gs2Header).toString("base64")) {
    return { ok: false, reason: "channel-binding-mismatch" };
  }
  if (attrs.get("r") !== input.expectedNonce) return { ok: false, reason: "nonce-mismatch" };

  let proof: Buffer;
  try {
    proof = Buffer.from(proofB64, "base64");
  } catch {
    return { ok: false, reason: "malformed-proof" };
  }
  if (proof.length !== KEY_LEN) return { ok: false, reason: "malformed-proof" };

  const authMessage = `${input.clientFirstBare},${input.serverFirst},${withoutProof}`;
  const clientSignature = hmac(input.storedKey, authMessage);
  // ClientKey = ClientProof XOR ClientSignature
  const clientKey = Buffer.alloc(KEY_LEN);
  for (let i = 0; i < KEY_LEN; i++) clientKey[i] = (proof[i] ?? 0) ^ (clientSignature[i] ?? 0);

  // ★timingSafeEqual — 해시 비교라 실용적 위험은 낮지만, 비교 방식이 곳마다 다르면
  //   "여기는 왜 다르지"를 나중에 판단해야 한다. 인증 경로의 비교는 하나로 통일한다.
  if (!timingSafeEqual(sha256(clientKey), input.storedKey)) return { ok: false, reason: "bad-proof" };

  const serverSignature = hmac(input.serverKey, authMessage);
  return { ok: true, serverFinal: `v=${serverSignature.toString("base64")}` };
}
