/**
 * ResultReference JSON 포인터 해석 (RFC 8620 §3.7 + RFC 6901).
 *
 * 백레퍼런스: 인자 값이 `{ "#name": { resultOf, name, path } }` 형태면, 앞선 메서드 응답에서
 * path(JSON 포인터)로 값을 뽑아 치환한다. JMAP 확장: `*`는 배열의 각 원소를 순회해
 * 나머지 경로를 적용하고 결과를 평탄화(RFC 8620 §3.7).
 */

import { hasOwnKey } from "./safe-key.ts";

export interface ResultReference {
  resultOf: string;
  name: string;
  path: string;
}

/**
 * 값이 ResultReference 형태({resultOf, name, path})인지 검증 (RFC 8620 §3.7).
 * 백레퍼런스는 인자 "키"에 `#` 접두가 붙고 그 값이 이 형태다 — `#` 판별은 엔진이 키에서 한다.
 */
export function asResultReference(value: unknown): ResultReference | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const r = value as Record<string, unknown>;
  if (typeof r.resultOf !== "string" || typeof r.name !== "string" || typeof r.path !== "string") return null;
  return { resultOf: r.resultOf, name: r.name, path: r.path };
}

/** 포인터 참조 토큰 디코드 (~1→/, ~0→~). */
function decodeToken(token: string): string {
  return token.replace(/~1/g, "/").replace(/~0/g, "~");
}

/**
 * JSON 포인터 평가 (RFC 6901 + JMAP `*` 확장).
 * 못 찾으면 undefined(호출자가 invalidResultReference로 처리).
 */
export function evalPointer(root: unknown, path: string): unknown {
  if (path === "" || path === "/") return root;
  if (!path.startsWith("/")) return undefined;
  const tokens = path.slice(1).split("/").map(decodeToken);
  return walk(root, tokens);
}

function walk(value: unknown, tokens: readonly string[]): unknown {
  if (tokens.length === 0) return value;
  const [token, ...rest] = tokens;
  if (token === "*") {
    // 배열 순회 후 나머지 경로 적용 + 평탄화(한 단계) — RFC 8620 §3.7
    if (!Array.isArray(value)) return undefined;
    const out: unknown[] = [];
    for (const item of value) {
      const r = walk(item, rest);
      if (r === undefined) continue;
      if (Array.isArray(r)) out.push(...r);
      else out.push(r);
    }
    return out;
  }
  if (Array.isArray(value)) {
    const idx = Number(token);
    if (!Number.isInteger(idx) || idx < 0 || idx >= value.length) return undefined;
    return walk(value[idx], rest ?? []);
  }
  if (typeof value === "object" && value !== null) {
    // ★`token in value`가 아니라 소유 키만 본다. `in`은 프로토타입 체인을 보므로 클라이언트가
    //   path에 `/__proto__`나 `/constructor`를 넣으면 앞선 응답에 없는 값(Object.prototype,
    //   생성자 함수)이 그대로 다음 메서드의 인자로 흘러들어간다(RFC 6901은 소유 멤버만 뜻한다).
    if (!hasOwnKey(value, token!)) return undefined;
    return walk((value as Record<string, unknown>)[token!], rest);
  }
  return undefined;
}
