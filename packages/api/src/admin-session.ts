/**
 * 관리 콘솔 사람 세션의 HTTP 쪽 규칙 — 쿠키·Origin·CSRF·step-up (회원 정책 E1).
 *
 * 저장(세션 행·TOTP)은 `@ionosphere/store`의 admin-auth가 하고, 여기는 "HTTP에서 그것을 어떻게
 * 싣고 확인하는가"만 둔다. 서버(server.ts)가 이 함수들을 한 관문에서 부른다.
 */
import type { IncomingMessage } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { sha256hex } from "@ionosphere/core";

/**
 * 세션 쿠키 이름. `__Host-` 접두사는 브라우저가 **Secure·Path=/·Domain 없음**을 강제하게 한다 —
 * 같은 상위 도메인의 다른 서브도메인이 이 쿠키를 덮어쓰는(쿠키 토싱) 길을 막는다.
 */
export const ADMIN_SESSION_COOKIE = "__Host-ionosphere_admin";
/** 메일 계정 셀프서비스 세션 쿠키(E2). 이름이 다르면 같은 브라우저에서 두 세션이 서로를 덮지 않는다. */
export const ACCOUNT_SESSION_COOKIE = "__Host-ionosphere_account";

/** CSRF 토큰을 실어 보내는 헤더. 브라우저는 다른 오리진의 요청에 커스텀 헤더를 붙일 수 없다(CORS 사전 요청). */
export const CSRF_HEADER = "x-csrf-token";

/**
 * 민감 작업(destructive 명령) 전에 요구하는 최근 MFA 창. ⚠ **임시** 값이다 — 공통 회원정책 수치가
 * 확정되지 않았다(2026-10-18). 설정(`AdminApiDeps.stepUpMs`)으로 덮을 수 있다.
 */
export const PROVISIONAL_STEP_UP_MS = 10 * 60 * 1000;

/** 쿠키 헤더에서 이름 하나를 꺼낸다. 같은 이름이 여럿이면 **거절**한다(어느 것이 진짜인지 추측하지 않는다). */
export function readCookie(req: IncomingMessage, name: string): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  const found: string[] = [];
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) found.push(part.slice(eq + 1).trim());
  }
  return found.length === 1 ? found[0]! : null;
}

/** 로그인 응답의 Set-Cookie. 수명은 쿠키가 아니라 서버 세션 행이 정한다(세션 쿠키 — 브라우저를 닫으면 사라진다). */
export function sessionCookie(token: string, name: string = ADMIN_SESSION_COOKIE): string {
  return `${name}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

export function clearedSessionCookie(name: string = ADMIN_SESSION_COOKIE): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/**
 * 상태를 바꾸는 쿠키 요청의 출처 확인. SameSite=Strict가 1차 방어지만 브라우저 구현과 설정에
 * 기대는 것이라, 서버가 직접 한 번 더 본다.
 *
 * - `Origin`이 **반드시** 있어야 한다. 현대 브라우저는 POST에 항상 싣는다 — 없으면 브라우저 밖이거나
 *   이상한 경로라 쿠키 인증을 쓸 이유가 없다(자동화는 Bearer API 키를 쓴다).
 * - `expectedOrigin`이 설정돼 있으면 정확히 같아야 한다. 없으면 Origin의 host가 요청 Host와 같아야 한다.
 * - `Sec-Fetch-Site`가 있으면 same-origin이어야 한다.
 */
export function originAllowed(req: IncomingMessage, expectedOrigin: string | undefined): boolean {
  const origin = req.headers.origin;
  if (typeof origin !== "string" || origin === "" || origin === "null") return false;
  const site = req.headers["sec-fetch-site"];
  if (typeof site === "string" && site !== "same-origin") return false;
  if (expectedOrigin !== undefined) return origin === expectedOrigin;
  let host: string;
  try {
    host = new URL(origin).host;
  } catch {
    return false;
  }
  return typeof req.headers.host === "string" && host === req.headers.host;
}

/** CSRF 토큰이 세션에 묶인 해시와 같은가 — 상수시간 비교(둘 다 sha256hex라 길이가 같다). */
export function csrfMatches(req: IncomingMessage, csrfHash: string): boolean {
  const given = req.headers[CSRF_HEADER];
  if (typeof given !== "string" || given === "") return false;
  // 저장값이 오염돼 길이가 다르면 timingSafeEqual이 throw한다 — 거절로 수렴시킨다.
  if (!/^[0-9a-f]{64}$/.test(csrfHash)) return false;
  return timingSafeEqual(Buffer.from(sha256hex(given), "hex"), Buffer.from(csrfHash, "hex"));
}
