/**
 * SASL OAuth 메커니즘 파서 — XOAUTH2(Google 사실표준) + OAUTHBEARER(RFC 7628). 순수 함수.
 * base64 디코딩된 페이로드 문자열에서 (user, token)을 추출한다. 토큰 검증은 호출자 몫
 * (ionosphere는 kind=2 자체발급 토큰을 credentials로 검증 — @ionosphere/store authenticate).
 *
 * XOAUTH2:   "user=<user>^Aauth=Bearer <token>^A^A"                     (^A = 0x01)
 * OAUTHBEARER: "n,a=<user>,^A[host=..^A][port=..^A]auth=Bearer <token>^A^A"  (GS2 헤더 + kvpair)
 */

const CTRL_A = "\u0001";

export interface SaslOAuthCreds {
  user: string;
  token: string;
}

/** "auth=Bearer <token>" 필드에서 토큰 추출(대소문자 무시 Bearer). */
function extractBearer(fields: string[]): string | null {
  for (const f of fields) {
    const m = f.match(/^auth=Bearer[ ]+(.+)$/i);
    if (m) return m[1]!.trim();
  }
  return null;
}

function parseXoauth2(decoded: string): SaslOAuthCreds | null {
  const fields = decoded.split(CTRL_A);
  let user: string | null = null;
  for (const f of fields) {
    if (f.startsWith("user=")) user = f.slice("user=".length);
  }
  const token = extractBearer(fields);
  if (!user || user.length === 0 || !token) return null;
  return { user, token };
}

function parseOauthbearer(decoded: string): SaslOAuthCreds | null {
  const fields = decoded.split(CTRL_A);
  // 첫 필드는 GS2 헤더: "n,a=<user>," 또는 "n,," (authzid 없음)
  const gs2 = fields[0] ?? "";
  let user: string | null = null;
  const aMatch = gs2.match(/(?:^|,)a=([^,]*)/);
  if (aMatch && aMatch[1]) user = decodeGs2(aMatch[1]);
  const token = extractBearer(fields.slice(1));
  if (!user || user.length === 0 || !token) return null;
  return { user, token };
}

/** GS2 saslname 디코딩: =2C→',' =3D→'='. */
function decodeGs2(s: string): string {
  return s.replace(/=2C/gi, ",").replace(/=3D/gi, "=");
}

/** 메커니즘별 파싱. 지원하지 않는 메커니즘/형식 오류는 null. */
export function parseSaslOAuth(mechanism: string, decoded: string): SaslOAuthCreds | null {
  const m = mechanism.toUpperCase();
  if (m === "XOAUTH2") return parseXoauth2(decoded);
  if (m === "OAUTHBEARER") return parseOauthbearer(decoded);
  return null;
}

/** OAuth SASL 메커니즘인지(대소문자 무시). */
export function isOAuthMechanism(mechanism: string): boolean {
  const m = mechanism.toUpperCase();
  return m === "XOAUTH2" || m === "OAUTHBEARER";
}

/**
 * SASL 응답 라인용 **엄격** base64 정규식 — mime의 관대한 디코더와 달리 형식 오류는 거부한다.
 * (ManageSieve는 검증이 아예 없어 불량 base64를 조용히 절단 수용했다.)
 */
const STRICT_BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** AUTH 연속행 base64 디코딩 — 형식이 틀리면 null. 프로토콜별 에러 응답은 호출자 몫. */
export function decodeSaslBase64(s: string): Uint8Array | null {
  if (!STRICT_BASE64_RE.test(s)) return null;
  try {
    return new Uint8Array(Buffer.from(s, "base64"));
  } catch {
    return null;
  }
}

/**
 * SASL PLAIN 페이로드 파싱 (RFC 4616 §2): `authzid NUL authcid NUL passwd`.
 * authzid는 무시한다. **비밀번호는 두 번째 NUL 이후 전부** — split(NUL) 후 길이를 3으로
 * 강제하면 NUL이 포함된 비밀번호가 거부된다(IMAP/SMTP는 통과, POP3/ManageSieve는 실패하던
 * 원인). 바이트 단위로 다뤄 UTF-8 경계도 안전하게 처리한다.
 */
export function parseSaslPlain(bytes: Uint8Array): { user: string; pass: string } | null {
  const idx1 = bytes.indexOf(0);
  if (idx1 === -1) return null;
  const idx2 = bytes.indexOf(0, idx1 + 1);
  if (idx2 === -1) return null;
  const decoder = new TextDecoder();
  const user = decoder.decode(bytes.subarray(idx1 + 1, idx2));
  const pass = decoder.decode(bytes.subarray(idx2 + 1));
  if (user.length === 0) return null;
  return { user, pass };
}

/** base64 문자열 → PLAIN 자격증명. 디코딩·파싱 어느 쪽이 실패해도 null. */
export function decodeSaslPlain(b64: string): { user: string; pass: string } | null {
  const bytes = decodeSaslBase64(b64);
  return bytes === null ? null : parseSaslPlain(bytes);
}
