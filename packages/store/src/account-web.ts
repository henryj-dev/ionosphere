/**
 * 메일 계정 셀프서비스의 첫 번째 요소와 세션 해석 (2026-10-18 회원 정책 E2).
 *
 * 두 번째 요소(TOTP·등록 코드·복구 코드)와 세션 생성·철회는 `web-mfa.ts`의 `ACCOUNT_REALM`이 정본이다.
 * 여기는 메일 계정에만 있는 두 가지만 둔다: 어떤 비밀번호로 웹에 들어올 수 있는가, 세션이 지금 어느 계정인가.
 */
import { randomBytes } from "node:crypto";
import { sha256hex } from "@ionosphere/core";
import { ACCOUNT_STATUS, CREDENTIAL_KIND, type DbDriver } from "@ionosphere/db";
import { hashSecret, verifySecret } from "./auth.ts";
import { ACCOUNT_REALM, touchWebSession, type WebSessionPolicy } from "./web-mfa.ts";

export interface SelfServiceAccount {
  accountId: string;
  tenantId: string;
  email: string;
  /** 확정된 TOTP가 있는가. 없으면 민감 작업(비밀번호 변경·앱 비밀번호 발급·철회)을 할 수 없다(결정 D3). */
  mfaEnrolled: boolean;
}

let dummyHash: Promise<string> | null = null;

/**
 * 셀프서비스 로그인의 첫 번째 요소 — **기본 비밀번호(kind=0)만** 받는다.
 *
 * ★앱 비밀번호·OAuth 토큰·디렉터리 bind는 받지 않는다. 앱 비밀번호는 "메일 클라이언트 하나에만 준 자격증명"이라는 뜻이고,
 * 클라이언트에 저장돼 새기 쉽다. 그것으로 웹에 들어와 다른 앱 비밀번호를 발급하거나 비밀번호를 바꿀 수 있으면,
 * 클라이언트 하나가 털릴 때 계정 전체가 넘어간다.
 *
 * 없음·정지·틀림은 전부 같은 null(계정 열거 방지). 없는 계정에도 같은 비용(scrypt)을 태운다.
 */
export async function verifyAccountPrimaryPassword(db: DbDriver, email: string, password: string): Promise<SelfServiceAccount | null> {
  const { rows } = await db.query({
    sql: `SELECT a.id, a.tenant_id, a.email, c.secret, m.totp_secret
            FROM accounts a
            JOIN credentials c ON c.account_id = a.id AND c.kind = ?
            LEFT JOIN account_mfa m ON m.account_id = a.id
           WHERE a.email = ? AND a.status = ?`,
    params: [CREDENTIAL_KIND.password, email.trim().toLowerCase(), ACCOUNT_STATUS.active],
  });
  if (rows.length === 0) {
    dummyHash ??= hashSecret(randomBytes(32).toString("hex"));
    await verifySecret(password, await dummyHash);
    return null;
  }
  for (const r of rows) {
    if (await verifySecret(password, String(r.secret))) {
      return { accountId: String(r.id), tenantId: String(r.tenant_id), email: String(r.email), mfaEnrolled: r.totp_secret != null };
    }
  }
  return null;
}

export interface ResolvedAccountSession {
  sessionId: string;
  account: SelfServiceAccount;
  mfaAt: number | null;
  csrfHash: string;
}

/**
 * 쿠키 토큰 → 살아 있는 세션 + **지금의** 계정 상태. 아니면 null.
 * 매 보호 요청마다 부른다(캐시 없음) — 계정 정지·삭제·로그아웃이 다음 요청부터 반영된다.
 */
export async function resolveAccountSession(db: DbDriver, token: string, policy: WebSessionPolicy, nowMs: number = Date.now()): Promise<ResolvedAccountSession | null> {
  if (token === "") return null;
  const sessionId = sha256hex(token);
  const { rows } = await db.query({
    sql: `SELECT s.created_at, s.last_seen_at, s.mfa_at, s.csrf_hash, a.id, a.tenant_id, a.email, m.totp_secret
            FROM account_sessions s
            JOIN accounts a ON a.id = s.account_id
            LEFT JOIN account_mfa m ON m.account_id = a.id
           WHERE s.id = ? AND s.revoked_at IS NULL AND a.status = ?`,
    params: [sessionId, ACCOUNT_STATUS.active],
  });
  const row = rows[0];
  if (!row) return null;
  if (!(await touchWebSession(db, ACCOUNT_REALM, sessionId, Number(row.created_at), Number(row.last_seen_at), policy, nowMs))) return null;
  const mfaEnrolled = row.totp_secret != null;
  return {
    sessionId,
    account: { accountId: String(row.id), tenantId: String(row.tenant_id), email: String(row.email), mfaEnrolled },
    // 등록되지 않았으면 MFA 시각이 있을 수 없다(초기화 직후 남은 값도 무효로 본다).
    mfaAt: mfaEnrolled && row.mfa_at != null ? Number(row.mfa_at) : null,
    csrfHash: String(row.csrf_hash),
  };
}
