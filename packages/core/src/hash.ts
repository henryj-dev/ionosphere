/**
 * sha256 해시 헬퍼 (SCHEMA.md §2): 블롭 id는 hex 64자 그대로,
 * 내부 매칭용(msgid_hash·ref_hash·key_hash)은 hex 32자로 절단(128bit, 충돌 무시 가능).
 */
import { createHash } from "node:crypto";

export function sha256hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function sha256hex32(data: string | Uint8Array): string {
  return sha256hex(data).slice(0, 32);
}
