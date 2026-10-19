/**
 * 관리 콘솔 사람 주체 — 비밀번호·TOTP·서버측 세션 (마이그레이션 025, 회원 정책 E1).
 *
 * 메일 계정 인증(`auth.ts`)과 테이블도 함수도 나눈다(결정 D1). 같은 것은 해시 함수(scrypt)뿐이다.
 * TOTP·등록 코드·복구 코드·세션의 규칙은 `web-mfa.ts`가 정본이고, 여기는 관리자 영역(`ADMIN_REALM`)으로 고정한 얇은 이름이다.
 *
 * 실패 표현: 조회·검증은 `| null`/`false`, 저장 실패(DB 오류)는 throw. 한 파일 안에서 섞지 않는다.
 * 이름에 드러나지 않는 부수효과는 없다 — 세션을 함께 끊는 함수는 이름에 `AndRevokeSessions`가 붙는다.
 */
import { randomBytes } from "node:crypto";
import { sha256hex, ulid } from "@ionosphere/core";
import { ADMIN_STATUS, BatchConflictError, isAdminRole, type AdminRole, type DbDriver } from "@ionosphere/db";
import { hashSecret, matchSecret, verifySecret } from "./auth.ts";
import {
  ADMIN_REALM,
  beginTotpEnrollment,
  confirmTotpEnrollment,
  createWebSession,
  csrfTokenForRealm,
  issueEnrollCode,
  markWebSessionMfa,
  PROVISIONAL_WEB_SESSION_POLICY,
  redeemRecoveryCode,
  remainingRecoveryCodes,
  resetTotpAndRevokeSessions,
  revokeWebSession,
  revokeWebSessions,
  touchWebSession,
  verifySecondFactorTotp,
  type WebSessionPolicy,
} from "./web-mfa.ts";

// 두 번째 요소·세션의 정본은 web-mfa.ts다(관리자·셀프서비스 공용). 여기는 관리자 영역으로 고정한 이름만 둔다.
export { burnTotpCost, PROVISIONAL_ENROLL_CODE_TTL_MS, PROVISIONAL_RECOVERY_CODES, PROVISIONAL_TOTP_LOCK } from "./web-mfa.ts";

export interface AdminUser {
  id: string;
  /** null = 운영자(전 테넌트). 값이 있으면 그 테넌트에만 작용한다. */
  tenantId: string | null;
  username: string;
  displayName: string | null;
  role: AdminRole;
  /** 확정된 TOTP가 있는가. 없으면 보호 요청을 받을 수 없다(MFA 1차 필수). */
  mfaEnrolled: boolean;
}

function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

function rowToUser(r: Record<string, unknown>): AdminUser | null {
  const role = Number(r.role);
  // DB → 타입 경계에서 좁힌다. 모르는 역할은 권한 0이 아니라 "사용자 없음"으로 닫는다.
  if (!isAdminRole(role)) return null;
  return {
    id: String(r.id),
    tenantId: r.tenant_id == null ? null : String(r.tenant_id),
    username: String(r.username),
    displayName: r.display_name == null ? null : String(r.display_name),
    role,
    mfaEnrolled: r.totp_secret != null,
  };
}

const USER_COLUMNS = "id, tenant_id, username, display_name, role, totp_secret";

/**
 * 관리자 생성 — 만들어지면 id, 사용자명이 이미 있으면 null.
 *
 * 비밀번호는 선택이다. 없으면 로컬 로그인이 불가능한 주체가 된다(E3 OIDC 연결 전용).
 * 유일성은 사전 조회가 아니라 UNIQUE 인덱스가 판정한다 — 동시 생성의 패자는 BatchConflictError다.
 */
export async function createAdminUser(
  db: DbDriver,
  input: { username: string; role: AdminRole; tenantId?: string; displayName?: string; password?: string },
): Promise<string | null> {
  const id = ulid();
  const now = Date.now();
  const passwordHash = input.password ? await hashSecret(input.password) : null;
  try {
    await db.batch([
      {
        sql: `INSERT INTO admin_users (id, tenant_id, username, display_name, role, status, password_hash, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        params: [id, input.tenantId ?? null, normalizeUsername(input.username), input.displayName ?? null, input.role, ADMIN_STATUS.active, passwordHash, now, now],
      },
    ]);
  } catch (err) {
    if (err instanceof BatchConflictError) return null;
    throw err;
  }
  return id;
}

export async function getAdminUser(db: DbDriver, id: string): Promise<AdminUser | null> {
  const { rows } = await db.query({ sql: `SELECT ${USER_COLUMNS} FROM admin_users WHERE id = ? AND status = ?`, params: [id, ADMIN_STATUS.active] });
  return rows[0] ? rowToUser(rows[0]) : null;
}

/** 계정이 없을 때 태울 더미 해시 — 응답 시간으로 사용자명 존재가 새지 않게(auth.ts와 같은 규율). */
let dummyAdminHash: Promise<string> | null = null;

/**
 * 사용자명 + 비밀번호 검증 → 활성 관리자 또는 null.
 * 없음·정지·비밀번호 없음(OIDC 전용)·틀림은 **전부 같은 null**이다(계정 열거 방지).
 */
export async function verifyAdminPassword(db: DbDriver, username: string, password: string): Promise<AdminUser | null> {
  const { rows } = await db.query({
    sql: `SELECT ${USER_COLUMNS}, password_hash FROM admin_users WHERE username = ? AND status = ?`,
    params: [normalizeUsername(username), ADMIN_STATUS.active],
  });
  const row = rows[0];
  const hash = row?.password_hash;
  if (!row || typeof hash !== "string") {
    dummyAdminHash ??= hashSecret(randomBytes(32).toString("hex"));
    await verifySecret(password, await dummyAdminHash);
    return null;
  }
  const match = await matchSecret(password, hash);
  if (!match) return null;
  if (match.rehash) {
    // 정규화 전 원문으로 맞았다 — 새 규칙(SASLprep)으로 다시 저장한다. 베스트에포트, 조건부 UPDATE.
    void (async () => {
      try {
        const next = await hashSecret(password);
        await db.batch([{ sql: "UPDATE admin_users SET password_hash = ? WHERE id = ? AND password_hash = ?", params: [next, String(row.id), hash] }]);
      } catch {
        /* 다음 로그인에 다시 시도한다 */
      }
    })();
  }
  return rowToUser(row);
}

/**
 * 비밀번호 교체 + 그 관리자의 **모든 세션 철회**. 비밀번호를 바꾸는 이유의 대부분이 "새었을지 모른다"라서,
 * 옛 비밀번호로 열린 세션을 살려 두면 교체가 아무것도 막지 못한다. 없는 관리자면 false.
 */
export async function setAdminPasswordAndRevokeSessions(db: DbDriver, id: string, password: string): Promise<boolean> {
  const hash = await hashSecret(password);
  const now = Date.now();
  const r = await db.batch([
    { sql: "UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?", params: [hash, now, id] },
    { sql: "UPDATE admin_sessions SET revoked_at = ? WHERE admin_user_id = ? AND revoked_at IS NULL", params: [now, id] },
  ]);
  return (r[0]?.changes ?? 0) > 0;
}

// ── 두 번째 요소(관리자 영역) ─────────────────────────────────────────────

export const issueAdminEnrollCode = (db: DbDriver, id: string, nowMs?: number): Promise<string | null> =>
  issueEnrollCode(db, ADMIN_REALM, id, nowMs);
export const beginAdminTotpEnrollment = (db: DbDriver, id: string, enrollCode: string, masterKey: string | undefined, nowMs?: number): Promise<string | null> =>
  beginTotpEnrollment(db, ADMIN_REALM, id, enrollCode, masterKey, nowMs);
export const confirmAdminTotpEnrollment = (db: DbDriver, id: string, code: string, masterKey: string | undefined, nowMs?: number): Promise<string[] | null> =>
  confirmTotpEnrollment(db, ADMIN_REALM, id, code, masterKey, nowMs);
export const verifyAdminTotp = (db: DbDriver, id: string, code: string, masterKey: string | undefined, nowMs?: number): Promise<boolean> =>
  verifySecondFactorTotp(db, ADMIN_REALM, id, code, masterKey, nowMs);
export const resetAdminTotpAndRevokeSessions = (db: DbDriver, id: string, nowMs?: number): Promise<string | null> =>
  resetTotpAndRevokeSessions(db, ADMIN_REALM, id, nowMs);
export const redeemAdminRecoveryCode = (db: DbDriver, id: string, code: string, nowMs?: number): Promise<{ enrollCode: string } | null> =>
  redeemRecoveryCode(db, ADMIN_REALM, id, code, nowMs);
export const remainingAdminRecoveryCodes = (db: DbDriver, id: string): Promise<number> => remainingRecoveryCodes(db, ADMIN_REALM, id);

// ── 세션(관리자 영역) ────────────────────────────────────────────────────

export type AdminSessionPolicy = WebSessionPolicy;
export const PROVISIONAL_ADMIN_SESSION_POLICY: AdminSessionPolicy = PROVISIONAL_WEB_SESSION_POLICY;

/** 세션 토큰 → CSRF 토큰(관리자 영역 라벨). 정의는 `web-mfa.ts` `csrfTokenForRealm`. */
export function csrfTokenFor(sessionToken: string): string {
  return csrfTokenForRealm(ADMIN_REALM, sessionToken);
}

export const createAdminSession = (db: DbDriver, adminUserId: string, mfaAt: number | null, nowMs?: number): Promise<{ sessionId: string; token: string; csrfToken: string }> =>
  createWebSession(db, ADMIN_REALM, adminUserId, mfaAt, nowMs);
export const markAdminSessionMfa = (db: DbDriver, sessionId: string, nowMs?: number): Promise<void> => markWebSessionMfa(db, ADMIN_REALM, sessionId, nowMs);
export const revokeAdminSession = (db: DbDriver, sessionId: string, nowMs?: number): Promise<void> => revokeWebSession(db, ADMIN_REALM, sessionId, nowMs);
export const revokeAdminSessions = (db: DbDriver, adminUserId: string, nowMs?: number): Promise<number> => revokeWebSessions(db, ADMIN_REALM, adminUserId, nowMs);

export interface ResolvedAdminSession {
  sessionId: string;
  user: AdminUser;
  /** 이 세션에서 마지막으로 MFA를 통과한 시각 — step-up 판정에 쓴다. */
  mfaAt: number | null;
  csrfHash: string;
}

/**
 * 쿠키 토큰 → 살아 있는 세션 + **지금의** 관리자 상태·역할. 아니면 null.
 *
 * ★매 보호 요청마다 부른다. 캐시하지 않는다 — 로그아웃·정지·역할 하향이 "다음 보호 요청부터"
 * 반영되는 것(공통 기준 3)이 이 조회 하나에 달려 있다. 조회가 throw하면 호출자는 거부한다(fail closed).
 */
export async function resolveAdminSession(
  db: DbDriver,
  token: string,
  policy: AdminSessionPolicy,
  nowMs: number = Date.now(),
): Promise<ResolvedAdminSession | null> {
  if (token === "") return null;
  const sessionId = sha256hex(token);
  const { rows } = await db.query({
    sql: `SELECT s.created_at, s.last_seen_at, s.mfa_at, s.csrf_hash, u.id, u.tenant_id, u.username, u.display_name, u.role, u.totp_secret
            FROM admin_sessions s JOIN admin_users u ON u.id = s.admin_user_id
           WHERE s.id = ? AND s.revoked_at IS NULL AND u.status = ?`,
    params: [sessionId, ADMIN_STATUS.active],
  });
  const row = rows[0];
  if (!row) return null;
  const user = rowToUser(row);
  if (!user) return null;
  if (!(await touchWebSession(db, ADMIN_REALM, sessionId, Number(row.created_at), Number(row.last_seen_at), policy, nowMs))) return null;
  return { sessionId, user, mfaAt: row.mfa_at == null ? null : Number(row.mfa_at), csrfHash: String(row.csrf_hash) };
}
