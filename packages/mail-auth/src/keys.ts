/**
 * DKIM 키 페어 생성 (RSA-2048 / Ed25519) + DNS TXT 레코드 문자열 조립.
 * RSA 공개키는 SPKI DER(RFC 6376 관례), Ed25519 공개키는 RAW 32바이트(RFC 8463 §3 — SPKI 아님).
 */
import { generateKeyPairSync } from "node:crypto";
import type { DkimAlgorithm } from "./sign.ts";

export interface DkimKeyPair {
  privateKeyPem: string; // PKCS#8 PEM
  publicKeyBase64: string; // RSA: SPKI DER base64 / Ed25519: RAW 32바이트 base64
  dnsRecord: string; // "v=DKIM1; k=...; p=..." — selector._domainkey.domain에 게시할 TXT 값
}

export function generateDkimKeyPair(algo: DkimAlgorithm): DkimKeyPair {
  if (algo === "rsa-sha256") {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicKeyDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
    const publicKeyBase64 = publicKeyDer.toString("base64");
    return {
      privateKeyPem,
      publicKeyBase64,
      dnsRecord: `v=DKIM1; k=rsa; p=${publicKeyBase64}`,
    };
  }

  // ed25519: Node의 KeyObject.export({format:"jwk"})로 RAW 32바이트 x 좌표를 꺼낸다.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const publicKeyBase64 = Buffer.from(jwk.x, "base64url").toString("base64");
  return {
    privateKeyPem,
    publicKeyBase64,
    dnsRecord: `v=DKIM1; k=ed25519; p=${publicKeyBase64}`,
  };
}
