/**
 * ACME용 최소 JOSE — ES256(P-256) JWS 서명, EC JWK, RFC 7638 thumbprint. zero-dep(node:crypto).
 * ACME(RFC 8555)는 flattened JWS로 요청에 서명한다: {protected, payload, signature}.
 */
import { createHash, createPrivateKey, createSign, generateKeyPairSync, type KeyObject } from "node:crypto";

export function b64url(data: Uint8Array | string): string {
  return Buffer.from(typeof data === "string" ? Buffer.from(data) : data).toString("base64url");
}

export interface EcJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d?: string;
}

/** ES256 계정 키 생성 → PKCS#8 PEM. */
export function generateAccountKey(): string {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

/** PEM 개인키 → 공개 JWK(d 제외). node의 JWK export 사용. */
export function publicJwk(privateKeyPem: string): EcJwk {
  const key: KeyObject = createPrivateKey(privateKeyPem);
  const jwk = key.export({ format: "jwk" }) as unknown as EcJwk & { d?: string };
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

/** RFC 7638 JWK thumbprint — 정렬 키 {crv,kty,x,y}의 sha256 base64url. */
export function jwkThumbprint(jwk: EcJwk): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64url(createHash("sha256").update(canonical).digest());
}

/** DER ECDSA 서명(SEQ{INTEGER r,INTEGER s}) → raw R||S(각 32바이트) — JWS ES256 형식. */
function derToRawEcdsa(der: Uint8Array): Uint8Array {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error("ECDSA DER: SEQUENCE 아님");
  if (der[i]! & 0x80) i += (der[i]! & 0x7f) + 1;
  else i += 1; // 길이 바이트 스킵
  const readInt = (): Uint8Array => {
    if (der[i++] !== 0x02) throw new Error("ECDSA DER: INTEGER 아님");
    let len = der[i++]!;
    let v = der.slice(i, i + len);
    i += len;
    while (v.length > 0 && v[0] === 0x00) v = v.slice(1); // 선행 0 제거
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length); // 좌측 0 패딩
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

/** ES256 서명(raw R||S) — signingInput 문자열에 서명. */
export function signES256(privateKeyPem: string, signingInput: string): string {
  const der = createSign("SHA256").update(signingInput).sign(privateKeyPem);
  return b64url(derToRawEcdsa(new Uint8Array(der)));
}

export interface JwsHeader {
  alg: "ES256";
  nonce: string;
  url: string;
  kid?: string;
  jwk?: EcJwk;
}

/** flattened JWS 생성. payload=null → POST-as-GET(빈 페이로드). */
export function makeJws(privateKeyPem: string, header: JwsHeader, payload: unknown | null): string {
  const protectedB64 = b64url(JSON.stringify(header));
  const payloadB64 = payload === null ? "" : b64url(JSON.stringify(payload));
  const signature = signES256(privateKeyPem, `${protectedB64}.${payloadB64}`);
  return JSON.stringify({ protected: protectedB64, payload: payloadB64, signature });
}
