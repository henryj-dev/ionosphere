/**
 * 관리 콘솔 사람 주체 — 비밀번호·TOTP·서버측 세션 (마이그레이션 025, 회원 정책 E1).
 *
 * 메일 계정 인증(`auth.ts`)과 테이블도 함수도 나눈다(결정 D1). 같은 것은 해시 함수(scrypt)뿐이다.
 *
 * 실패 표현: 조회·검증은 `| null`/`false`, 저장 실패(DB 오류)는 throw. 한 파일 안에서 섞지 않는다.
 * 이름에 드러나지 않는 부수효과는 없다 — 세션을 함께 끊는 함수는 이름에 `AndRevokeSessions`가 붙는다.
 */
import { createHmac, randomBytes } from "node:crypto";
import { base32Decode, generateTotpSecret, openAsync, seal, sha256hex, ulid, verifyTotp } from "@ionosphere/core";
import { ADMIN_STATUS, BatchConflictError, isAdminRole, type AdminRole, type DbDriver } from "@ionosphere/db";
import { hashSecret, verifySecret } from "./auth.ts";

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
  return (await verifySecret(password, hash)) ? rowToUser(row) : null;
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

// ── TOTP ───────────────────────────────────────────────────────────────

/**
 * ★마스터 키가 없으면 TOTP를 다루지 않는다(fail closed). secretbox는 키가 없으면 평문으로 저장하는데
 * (DKIM 키는 그 대가로 경고만 낸다), TOTP 비밀이 평문이면 DB 사본 하나로 MFA가 통째로 무력해진다.
 */
function requireMasterKey(masterKey: string | undefined): string {
  if (!masterKey) throw new Error("IONOSPHERE_MASTER_KEY가 없어 TOTP 비밀을 봉인할 수 없다");
  return masterKey;
}

/**
 * TOTP 등록 시작 — 새 비밀을 **대기 칸**에 봉인해 두고 평문(base32)을 돌려준다. 확정 전에는 로그인에 쓰이지 않는다.
 * 앱에 옮겨 적다 틀리면 그 계정은 영영 MFA를 통과하지 못하므로, 코드 하나를 맞혀야 확정된다.
 */
export async function beginAdminTotpEnrollment(db: DbDriver, id: string, masterKey: string | undefined): Promise<string | null> {
  const key = requireMasterKey(masterKey);
  const secret = generateTotpSecret();
  const r = await db.batch([
    { sql: "UPDATE admin_users SET totp_pending_secret = ?, updated_at = ? WHERE id = ? AND status = ?", params: [seal(secret, key).value, Date.now(), id, ADMIN_STATUS.active] },
  ]);
  return (r[0]?.changes ?? 0) > 0 ? secret : null;
}

/** 등록 확정 — 대기 비밀로 만든 코드가 맞으면 확정 칸으로 옮긴다. 이미 확정된 비밀은 이 경로로 덮지 않는다. */
export async function confirmAdminTotpEnrollment(db: DbDriver, id: string, code: string, masterKey: string | undefined, nowMs: number = Date.now()): Promise<boolean> {
  const key = requireMasterKey(masterKey);
  const { rows } = await db.query({
    sql: "SELECT totp_pending_secret FROM admin_users WHERE id = ? AND status = ? AND totp_secret IS NULL",
    params: [id, ADMIN_STATUS.active],
  });
  const pending = rows[0]?.totp_pending_secret;
  if (typeof pending !== "string") return false;
  if (!(await claimTotpAttempt(db, id, nowMs))) return false;
  const step = verifyTotp(await openAsync(pending, key), code, nowMs, null);
  if (step === null) return false;
  const r = await db.batch([
    {
      // 조건부 — 확인과 쓰기 사이에 다른 요청이 확정했거나 대기 비밀을 바꿨으면 쓰지 않는다.
      sql: `UPDATE admin_users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL, totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL, updated_at = ?
            WHERE id = ? AND totp_secret IS NULL AND totp_pending_secret = ?`,
      params: [step, nowMs, id, pending],
    },
  ]);
  return (r[0]?.changes ?? 0) > 0;
}

/**
 * TOTP 연속 실패 잠금. 계정 축 스로틀(분당 20회)만으로는 6자리 대입이 며칠이면 끝난다
 * (하루 2.9만 회 × 3/10⁶). 그래서 **연속 실패**를 계정에 쌓고, 문턱을 넘으면 실패할 때마다 잠금을 배로 늘린다.
 * 이 경로에 닿으려면 비밀번호가 맞아야 하므로, 비밀번호를 모르는 사람이 남의 계정을 잠그지는 못한다.
 * ⚠ 수치는 **임시**다 — 공통 회원정책 수치가 확정되지 않았다(2026-10-18).
 */
export const PROVISIONAL_TOTP_LOCK = {
  /** 이만큼 연속으로 틀리면 잠그기 시작한다. */
  freeFailures: 5,
  /** 첫 잠금 길이. 실패가 하나 늘 때마다 두 배. */
  baseLockMs: 60_000,
  /** 잠금 상한. */
  maxLockMs: 24 * 60 * 60 * 1000,
} as const;

function lockUntilAfter(failures: number, nowMs: number): number | null {
  const over = failures - PROVISIONAL_TOTP_LOCK.freeFailures;
  if (over < 0) return null;
  return nowMs + Math.min(PROVISIONAL_TOTP_LOCK.baseLockMs * 2 ** Math.min(over, 30), PROVISIONAL_TOTP_LOCK.maxLockMs);
}

/**
 * TOTP 시도 슬롯을 **계산하기 전에** 원자적으로 차지한다 — 차지했으면 true.
 *
 * ★실패를 나중에 기록하면(읽고 +1 해서 쓰기) 추측 N개를 동시에 보낼 때 모두가 "아직 안 잠김"을 읽고 통과하고,
 * 실패 수는 1만 는다(2026-10-18 보안 재검토). 그래서 순서를 뒤집는다: 시도마다 **먼저** 실패 수를 DB 안에서 +1 하고
 * (성공하면 0으로 되돌린다), 차지 조건을 그 UPDATE의 WHERE에 넣는다. 행 갱신은 DB가 직렬화하므로
 * 문턱 전에는 최대 `freeFailures`개, 잠금이 풀린 뒤에는 한 개만 차지한다.
 *
 * 잠금 해제 직후의 차지는 `totp_locked_until`을 비우고, 곧바로 아래에서 새 잠금을 건다 — 그 사이에 온 요청은
 * "실패 수가 문턱 이상인데 잠금 시각이 없다"는 조건에 걸려 차지하지 못한다.
 */
async function claimTotpAttempt(db: DbDriver, id: string, nowMs: number): Promise<boolean> {
  const r = await db.batch([
    {
      sql: `UPDATE admin_users SET totp_failures = totp_failures + 1, totp_locked_until = NULL
             WHERE id = ? AND (totp_failures < ? OR (totp_locked_until IS NOT NULL AND totp_locked_until <= ?))`,
      params: [id, PROVISIONAL_TOTP_LOCK.freeFailures, nowMs],
    },
  ]);
  if ((r[0]?.changes ?? 0) === 0) return false;
  const { rows } = await db.query({ sql: "SELECT totp_failures FROM admin_users WHERE id = ?", params: [id] });
  const until = lockUntilAfter(Number(rows[0]?.totp_failures ?? 0), nowMs);
  // 문턱에 닿은 시도는 결과를 보기 전에 잠금을 건다. 이 시도가 맞으면 성공 경로가 풀어 준다.
  if (until !== null) await db.batch([{ sql: "UPDATE admin_users SET totp_locked_until = ? WHERE id = ?", params: [until, id] }]);
  return true;
}

/**
 * 로그인 응답 시간 평탄화. 비밀번호가 맞고 TOTP가 들어왔을 때만 봉인 해제(scrypt)가 돌면, 응답 시간만으로
 * "비밀번호는 맞았다"가 샌다 — 응답 본문을 같게 만든 의미가 사라진다. 그 경로가 아닐 때 이걸 불러 같은 비용을 태운다.
 */
let dummySealed: string | null = null;
export async function burnTotpCost(masterKey: string | undefined): Promise<void> {
  if (!masterKey) return;
  dummySealed ??= seal(generateTotpSecret(), masterKey).value;
  await openAsync(dummySealed, masterKey);
}

/**
 * MFA 검증 — 맞고 아직 안 쓴 스텝이면 true, 그 스텝을 소비한다.
 *
 * ★소비를 조건부 UPDATE로 한다. 같은 코드를 동시에 두 요청이 내면 둘 다 계산상 맞지만,
 * `totp_last_step < ?`를 이기는 쪽은 하나뿐이다 — 읽고 쓰는 사이의 재사용 창을 DB가 닫는다.
 */
export async function verifyAdminTotp(db: DbDriver, id: string, code: string, masterKey: string | undefined, nowMs: number = Date.now()): Promise<boolean> {
  const key = requireMasterKey(masterKey);
  const { rows } = await db.query({
    sql: "SELECT totp_secret, totp_last_step FROM admin_users WHERE id = ? AND status = ?",
    params: [id, ADMIN_STATUS.active],
  });
  const row = rows[0];
  if (typeof row?.totp_secret !== "string") return false;
  // 슬롯을 못 차지하면(잠김) 코드를 계산하지도 않는다 — 맞는 코드도 거절한다. 비용은 같게 태운다.
  if (!(await claimTotpAttempt(db, id, nowMs))) {
    await burnTotpCost(key);
    return false;
  }
  const last = row.totp_last_step == null ? null : Number(row.totp_last_step);
  const secret = await openAsync(row.totp_secret, key);
  const step = base32Decode(secret) === null ? null : verifyTotp(secret, code, nowMs, last);
  // 실패는 이미 차지할 때 셌다 — 여기서 더 기록하지 않는다.
  if (step === null) return false;
  const r = await db.batch([
    {
      sql: "UPDATE admin_users SET totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
      params: [step, id, step],
    },
  ]);
  return (r[0]?.changes ?? 0) > 0;
}

/** MFA 초기화(분실 복구 — 비상 경로·owner 명령 전용) + 세션 철회. 초기화 뒤에는 재등록 전까지 보호 요청이 막힌다. */
export async function resetAdminTotpAndRevokeSessions(db: DbDriver, id: string): Promise<boolean> {
  const now = Date.now();
  const r = await db.batch([
    { sql: "UPDATE admin_users SET totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = NULL, totp_failures = 0, totp_locked_until = NULL, updated_at = ? WHERE id = ?", params: [now, id] },
    { sql: "UPDATE admin_sessions SET revoked_at = ? WHERE admin_user_id = ? AND revoked_at IS NULL", params: [now, id] },
  ]);
  return (r[0]?.changes ?? 0) > 0;
}

// ── 세션 ───────────────────────────────────────────────────────────────

/**
 * 세션 수명 정책. ⚠ 기본값은 **임시**다 — 6개 서비스 공통 회원정책의 수치가 아직 확정되지 않았다
 * (2026-10-18). 공통안이 오면 그 값으로 바꾼다. 호출자가 설정으로 덮을 수 있다.
 */
export interface AdminSessionPolicy {
  /** 마지막 보호 요청 뒤 이만큼 지나면 만료. */
  idleMs: number;
  /** 로그인 뒤 이만큼 지나면 활동과 무관하게 만료. */
  absoluteMs: number;
}
export const PROVISIONAL_ADMIN_SESSION_POLICY: AdminSessionPolicy = {
  idleMs: 30 * 60 * 1000,
  absoluteMs: 12 * 60 * 60 * 1000,
};

/** `last_seen_at` 갱신 간격 — 요청마다 쓰면 읽기 전용 화면도 쓰기 부하가 된다. idle 판정 오차는 이만큼이다. */
const LAST_SEEN_WRITE_INTERVAL_MS = 60_000;

function newToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * 세션 토큰 → CSRF 토큰. **유도한다**(따로 뽑지 않는다).
 *
 * ★따로 뽑아 화면 저장소에 두면 새 탭에는 토큰이 없어 쓰기가 전부 막힌다. 유도하면 서버가 쿠키만 보고 언제든
 * 다시 만들어 줄 수 있다(`GET /admin/session`). 쿠키는 HttpOnly라 스크립트가 읽지 못하고, 그 응답은 같은
 * 오리진만 읽을 수 있으므로(CORS 미허용) 다른 사이트가 이 값을 얻을 길이 없다.
 */
export function csrfTokenFor(sessionToken: string): string {
  return createHmac("sha256", sessionToken).update("ionosphere-admin-csrf").digest("base64url");
}

/**
 * 세션 생성 — 쿠키에 넣을 토큰과 CSRF 토큰을 **한 번만** 돌려준다. 둘 다 해시로만 저장한다.
 * `mfaAt`: 이 로그인에서 MFA를 통과했으면 그 시각. 미등록 관리자는 null로 열리고 등록 화면만 쓸 수 있다.
 */
export async function createAdminSession(
  db: DbDriver,
  adminUserId: string,
  mfaAt: number | null,
  nowMs: number = Date.now(),
): Promise<{ sessionId: string; token: string; csrfToken: string }> {
  const token = newToken();
  const csrfToken = csrfTokenFor(token);
  const sessionId = sha256hex(token);
  await db.batch([
    {
      sql: "INSERT INTO admin_sessions (id, admin_user_id, csrf_hash, created_at, last_seen_at, mfa_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
      params: [sessionId, adminUserId, sha256hex(csrfToken), nowMs, nowMs, mfaAt],
    },
  ]);
  return { sessionId, token, csrfToken };
}

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
  const createdAt = Number(row.created_at);
  const lastSeen = Number(row.last_seen_at);
  if (nowMs - createdAt > policy.absoluteMs || nowMs - lastSeen > policy.idleMs) return null;
  const user = rowToUser(row);
  if (!user) return null;
  if (nowMs - lastSeen >= LAST_SEEN_WRITE_INTERVAL_MS) {
    await db.batch([{ sql: "UPDATE admin_sessions SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL", params: [nowMs, sessionId] }]);
  }
  return { sessionId, user, mfaAt: row.mfa_at == null ? null : Number(row.mfa_at), csrfHash: String(row.csrf_hash) };
}

/** 이 세션에서 방금 MFA를 통과했다(로그인 뒤 step-up·등록 확정). */
export async function markAdminSessionMfa(db: DbDriver, sessionId: string, nowMs: number = Date.now()): Promise<void> {
  await db.batch([{ sql: "UPDATE admin_sessions SET mfa_at = ? WHERE id = ? AND revoked_at IS NULL", params: [nowMs, sessionId] }]);
}

/** 로그아웃 — 이 세션 하나. */
export async function revokeAdminSession(db: DbDriver, sessionId: string, nowMs: number = Date.now()): Promise<void> {
  await db.batch([{ sql: "UPDATE admin_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", params: [nowMs, sessionId] }]);
}

/** 그 관리자의 세션 전부 — "모든 기기 로그아웃"·정지 대응. 끊은 수를 돌려준다. */
export async function revokeAdminSessions(db: DbDriver, adminUserId: string, nowMs: number = Date.now()): Promise<number> {
  const r = await db.batch([{ sql: "UPDATE admin_sessions SET revoked_at = ? WHERE admin_user_id = ? AND revoked_at IS NULL", params: [nowMs, adminUserId] }]);
  return r[0]?.changes ?? 0;
}
