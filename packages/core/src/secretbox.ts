/**
 * 대칭 봉인 (AES-256-GCM) — DKIM 개인키 등 DB 보관 비밀의 저장 시 암호화 (SCHEMA §9-2).
 * 마스터키는 패스프레이즈 문자열 → scrypt 유도. 포맷은 자기서술:
 *   "enc$v1$<saltB64>$<ivB64>$<tagB64>$<dataB64>"  (암호화)
 *   "plain$<원문>"                                  (마스터키 미설정 — 호출자가 경고 책임)
 */
import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb, scryptSync } from "node:crypto";

const KDF = { N: 16384, r: 8, p: 1 } as const;

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, KDF);
}

/**
 * 비동기 키 유도 — libuv 스레드풀에서 돈다.
 *
 * ★왜 필요한가: `scryptSync`는 실측 **85.7ms** 동안 이벤트 루프를 통째로 막는다. 이 저장소는
 * 같은 위험을 이미 두 곳에 적어 뒀지만(`store/auth.ts` scryptAsync · `core/scram.ts` pbkdf2)
 * 그 교훈이 봉인 해제 경로로는 전파되지 않았다. 전 프로토콜이 단일 프로세스라 그동안
 * 25·587·993·995가 함께 멈춘다.
 */
function deriveKeyAsync(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(passphrase, salt, 32, KDF, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/**
 * 봉인 결과. `sealed:false`면 마스터키 미설정으로 **평문 저장**이라는 뜻 —
 * 반환 타입으로 드러내 호출자가 모르고 지나칠 수 없게 한다(과거엔 string만 돌려줘서
 * REST 경로가 경고 없이 평문 DKIM 키를 저장했다).
 */
export interface SealResult {
  /** true면 AES-256-GCM 봉인됨, false면 평문(`plain$` 접두). */
  sealed: boolean;
  /** DB/파일에 저장할 자기서술 문자열. */
  value: string;
}

export function seal(plaintext: string, passphrase: string | undefined): SealResult {
  if (!passphrase) return { sealed: false, value: `plain$${plaintext}` };
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(passphrase, salt), iv);
  const data = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    sealed: true,
    value: [
      "enc$v1",
      salt.toString("base64"),
      iv.toString("base64"),
      tag.toString("base64"),
      data.toString("base64"),
    ].join("$"),
  };
}

/** 봉인 문자열을 뜯는다 — 형식 검증은 동기·비동기가 공유해야 갈라지지 않는다. */
function parseSealed(
  sealed: string,
  passphrase: string | undefined,
): { plain: string } | { salt: Buffer; iv: Buffer; tag: Buffer; data: Buffer; passphrase: string } {
  if (sealed.startsWith("plain$")) return { plain: sealed.slice("plain$".length) };
  const parts = sealed.split("$");
  if (parts.length !== 6 || parts[0] !== "enc" || parts[1] !== "v1") {
    throw new Error("secretbox: unknown format");
  }
  if (!passphrase) throw new Error("secretbox: master key required to open encrypted secret");
  return {
    salt: Buffer.from(parts[2]!, "base64"),
    iv: Buffer.from(parts[3]!, "base64"),
    tag: Buffer.from(parts[4]!, "base64"),
    data: Buffer.from(parts[5]!, "base64"),
    passphrase,
  };
}

function decrypt(key: Buffer, iv: Buffer, tag: Buffer, data: Buffer): string {
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

/**
 * 잘못된 키/손상 데이터는 throw — 비밀 복호 실패를 조용히 넘기지 않는다.
 *
 * ⚠ **이벤트 루프를 85ms 막는다**(scryptSync). 부팅·CLI처럼 한 번 도는 경로에서만 쓸 것.
 * 요청·메시지마다 도는 경로에서는 `openAsync()`를 쓴다.
 */
export function open(sealed: string, passphrase: string | undefined): string {
  const p = parseSealed(sealed, passphrase);
  if ("plain" in p) return p.plain;
  return decrypt(deriveKey(p.passphrase, p.salt), p.iv, p.tag, p.data);
}

/**
 * `open()`의 비동기판 — 키 유도가 libuv 스레드풀에서 돈다. 판정·오류는 동기판과 같다.
 *
 * 배달·서명처럼 **메시지마다 도는 경로**는 이쪽을 쓴다. DKIM 서명이 통당 두 번(RSA+Ed25519)
 * 동기 `open()`을 부르던 것이 통당 172ms 정지였다.
 */
export async function openAsync(sealed: string, passphrase: string | undefined): Promise<string> {
  const p = parseSealed(sealed, passphrase);
  if ("plain" in p) return p.plain;
  return decrypt(await deriveKeyAsync(p.passphrase, p.salt), p.iv, p.tag, p.data);
}
