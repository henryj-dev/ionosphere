/**
 * 대칭 봉인 (AES-256-GCM) — DKIM 개인키 등 DB 보관 비밀의 저장 시 암호화 (SCHEMA §9-2).
 * 마스터키는 패스프레이즈 문자열 → scrypt 유도. 포맷은 자기서술:
 *   "enc$v1$<saltB64>$<ivB64>$<tagB64>$<dataB64>"  (암호화)
 *   "plain$<원문>"                                  (마스터키 미설정 — 호출자가 경고 책임)
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
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

/** 잘못된 키/손상 데이터는 throw — 비밀 복호 실패를 조용히 넘기지 않는다. */
export function open(sealed: string, passphrase: string | undefined): string {
  if (sealed.startsWith("plain$")) return sealed.slice("plain$".length);
  const parts = sealed.split("$");
  if (parts.length !== 6 || parts[0] !== "enc" || parts[1] !== "v1") {
    throw new Error("secretbox: unknown format");
  }
  if (!passphrase) throw new Error("secretbox: master key required to open encrypted secret");
  const salt = Buffer.from(parts[2]!, "base64");
  const iv = Buffer.from(parts[3]!, "base64");
  const tag = Buffer.from(parts[4]!, "base64");
  const data = Buffer.from(parts[5]!, "base64");
  const decipher = createDecipheriv("aes-256-gcm", deriveKey(passphrase, salt), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}
