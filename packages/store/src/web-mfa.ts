/**
 * 웹 로그인의 두 번째 요소와 서버측 세션 — **영역(realm)별 공용 정본**(회원 정책 E1·E2).
 *
 * 관리 콘솔 관리자(`admin_users`)와 셀프서비스 메일 사용자(`account_mfa`)가 같은 규칙을 쓴다:
 * TOTP(봉인 저장·재사용 방지), 일회용 등록 코드, 복구 코드, 연속 실패 잠금, 서버 세션·CSRF 유도.
 *
 * ★왜 한 곳인가: 같은 보안 로직을 두 벌 두면 한쪽만 고친다 — 이 저장소의 반복 사고다. E1을 보안 검토하며 고친
 * 동시성·타이밍 결함(시도 슬롯 원자 차지, 확정에 이긴 쪽만 복구 코드 기록 등)이 E2에 그대로 오도록 함수를 공유한다.
 *
 * SQL에 끼우는 테이블·컬럼 이름은 **아래 두 상수에서만** 온다(사용자 입력이 아니다).
 * 실패 표현: 검증은 `| null`/`false`, DB 오류는 throw.
 */
import { createHmac, randomBytes } from "node:crypto";
import { base32Decode, base32Encode, generateTotpSecret, openAsync, seal, sha256hex, verifyTotp } from "@ionosphere/core";
import { ACCOUNT_STATUS, ADMIN_STATUS, type DbDriver } from "@ionosphere/db";

export interface MfaRealm {
  readonly name: "admin" | "account";
  /** TOTP·잠금·등록 코드 칸을 가진 테이블과 그 주체 키. */
  readonly mfaTable: "admin_users" | "account_mfa";
  readonly mfaKey: "id" | "account_id";
  /** 주체가 지금 활성인가 — mfaTable 행에 거는 조건(파라미터 없음). 정지된 주체는 두 번째 요소도 통과하지 못한다. */
  readonly activeWhere: string;
  readonly sessionTable: "admin_sessions" | "account_sessions";
  readonly sessionKey: "admin_user_id" | "account_id";
  readonly recoveryTable: "admin_recovery_codes" | "account_recovery_codes";
  readonly recoveryKey: "admin_user_id" | "account_id";
  /** CSRF 유도 라벨 — 영역마다 달라야 한쪽 세션의 토큰이 다른 쪽 화면에서 통하지 않는다. */
  readonly csrfLabel: string;
  /** MFA 행이 주체와 따로 있는가(있으면 첫 쓰기 전에 행을 만든다). */
  readonly separateMfaRow: boolean;
}

export const ADMIN_REALM: MfaRealm = {
  name: "admin",
  mfaTable: "admin_users",
  mfaKey: "id",
  activeWhere: `status = ${ADMIN_STATUS.active}`,
  sessionTable: "admin_sessions",
  sessionKey: "admin_user_id",
  recoveryTable: "admin_recovery_codes",
  recoveryKey: "admin_user_id",
  csrfLabel: "ionosphere-admin-csrf",
  separateMfaRow: false,
};

export const ACCOUNT_REALM: MfaRealm = {
  name: "account",
  mfaTable: "account_mfa",
  mfaKey: "account_id",
  activeWhere: `account_id IN (SELECT id FROM accounts WHERE status = ${ACCOUNT_STATUS.active})`,
  sessionTable: "account_sessions",
  sessionKey: "account_id",
  recoveryTable: "account_recovery_codes",
  recoveryKey: "account_id",
  csrfLabel: "ionosphere-account-csrf",
  separateMfaRow: true,
};

// ── 공통 상수(⚠ 전부 임시 — 6개 서비스 공통 회원정책 수치 미확정, 2026-10-18) ──────────────

/** 일회용 등록 코드 유효 기간. */
export const PROVISIONAL_ENROLL_CODE_TTL_MS = 24 * 60 * 60 * 1000;
/** 복구 코드 — 한 번에 발급하는 개수와 길이. 10자 base32 ≈ 50비트. */
export const PROVISIONAL_RECOVERY_CODES = { count: 10, length: 10 } as const;
/** TOTP·복구 코드 연속 실패 잠금. */
export const PROVISIONAL_TOTP_LOCK = {
  /** 이만큼 연속으로 틀리면 잠그기 시작한다. */
  freeFailures: 5,
  /** 첫 잠금 길이. 실패가 하나 늘 때마다 두 배. */
  baseLockMs: 60_000,
  /** 잠금 상한. */
  maxLockMs: 24 * 60 * 60 * 1000,
} as const;

/** 세션 수명 정책. 호출자가 설정으로 덮을 수 있다. */
export interface WebSessionPolicy {
  /** 마지막 보호 요청 뒤 이만큼 지나면 만료. */
  idleMs: number;
  /** 로그인 뒤 이만큼 지나면 활동과 무관하게 만료. */
  absoluteMs: number;
}
export const PROVISIONAL_WEB_SESSION_POLICY: WebSessionPolicy = {
  idleMs: 30 * 60 * 1000,
  absoluteMs: 12 * 60 * 60 * 1000,
};

/** `last_seen_at` 갱신 간격 — 요청마다 쓰면 읽기 전용 화면도 쓰기 부하가 된다. idle 판정 오차는 이만큼이다. */
export const LAST_SEEN_WRITE_INTERVAL_MS = 60_000;

// ── 마스터 키·코드 생성 ─────────────────────────────────────────────────

/**
 * ★마스터 키가 없으면 TOTP를 다루지 않는다(fail closed). secretbox는 키가 없으면 평문으로 저장하는데
 * (DKIM 키는 그 대가로 경고만 낸다), TOTP 비밀이 평문이면 DB 사본 하나로 MFA가 통째로 무력해진다.
 */
function requireMasterKey(masterKey: string | undefined): string {
  if (!masterKey) throw new Error("IONOSPHERE_MASTER_KEY가 없어 TOTP 비밀을 봉인할 수 없다");
  return masterKey;
}

/**
 * 일회용 등록 코드 — 16 소문자(4-4-4-4), 편향 없는 rejection sampling, 약 75비트.
 *
 * 앱 비밀번호와 모양은 같지만 **생성기를 공유하지 않는다.** 사람이 고르는 비밀번호가 아니라 서버가 뽑는 고엔트로피
 * 1회용 값이라 sha256 저장이 맞다(api_keys와 같은 규율). 비밀번호 생성기를 빌려 쓰면 그 값이 "비밀번호"로 분류돼
 * 느린 해시가 필요한 것처럼 보이고(CodeQL js/insufficient-password-hash), 두 용도의 요구가 갈릴 때 함께 묶인다.
 */
function generateOneTimeCode(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const limit = 256 - (256 % alphabet.length);
  const chars: string[] = [];
  while (chars.length < 16) {
    for (const b of randomBytes(32)) {
      if (b >= limit) continue;
      chars.push(alphabet[b % alphabet.length]!);
      if (chars.length === 16) break;
    }
  }
  return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join("")).join("-");
}

function normalizeOneTimeCode(code: string): string {
  return code.replace(/[\s-]/g, "").toLowerCase();
}

function generateRecoveryCode(): string {
  const raw = base32Encode(randomBytes(8)).toLowerCase().slice(0, PROVISIONAL_RECOVERY_CODES.length);
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

/** MFA 행이 주체와 따로 있는 영역이면 행을 만든다(이미 있으면 그대로). 다이얼렉트 분기는 `insertIgnore`가 봉인한다. */
async function ensureMfaRow(db: DbDriver, realm: MfaRealm, id: string, nowMs: number): Promise<void> {
  if (!realm.separateMfaRow) return;
  await db.batch([{ sql: db.insertIgnore(realm.mfaTable, [realm.mfaKey, "totp_failures", "updated_at"]), params: [id, 0, nowMs] }]);
}

// ── 등록 코드·TOTP 등록 ─────────────────────────────────────────────────

/**
 * 일회용 등록 코드 발급(2026-10-18 사용자 결정). 첫 TOTP 등록(새 주체·MFA 초기화·복구 코드 사용 뒤)에 필요하다.
 *
 * ★비밀번호만으로 등록할 수 있으면 비밀번호를 아는 사람이 본인보다 먼저 MFA를 차지한다 — 그 뒤로는 그 사람이
 * 계정의 주인이 된다. 등록 코드는 발급하는 쪽(관리자·호스트 CLI)이 한 번만 보고 본인에게 **따로** 전달한다.
 * 해시로만 저장하고, 등록이 확정되면 지운다. 이전 코드는 무효가 된다. 주체가 없으면 null.
 */
export async function issueEnrollCode(db: DbDriver, realm: MfaRealm, id: string, nowMs: number = Date.now()): Promise<string | null> {
  await ensureMfaRow(db, realm, id, nowMs);
  const code = generateOneTimeCode();
  const r = await db.batch([
    {
      sql: `UPDATE ${realm.mfaTable} SET enroll_code_hash = ?, enroll_code_expires_at = ?, updated_at = ? WHERE ${realm.mfaKey} = ?`,
      params: [sha256hex(normalizeOneTimeCode(code)), nowMs + PROVISIONAL_ENROLL_CODE_TTL_MS, nowMs, id],
    },
  ]);
  return (r[0]?.changes ?? 0) > 0 ? code : null;
}

/**
 * TOTP 등록 시작 — 등록 코드가 맞을 때만 새 비밀을 **대기 칸**에 봉인하고 평문(base32)을 돌려준다.
 * 확정 전에는 로그인에 쓰이지 않는다. 앱에 옮겨 적다 틀리면 영영 통과하지 못하므로, 코드 하나를 맞혀야 확정된다.
 * 등록 코드 확인은 UPDATE의 조건이다(조회 뒤 쓰기가 아니다). 틀림·만료·이미 등록됨·비활성은 전부 null.
 */
export async function beginTotpEnrollment(
  db: DbDriver,
  realm: MfaRealm,
  id: string,
  enrollCode: string,
  masterKey: string | undefined,
  nowMs: number = Date.now(),
): Promise<string | null> {
  const key = requireMasterKey(masterKey);
  if (normalizeOneTimeCode(enrollCode) === "") return null;
  const secret = generateTotpSecret();
  const r = await db.batch([
    {
      sql: `UPDATE ${realm.mfaTable} SET totp_pending_secret = ?, updated_at = ?
             WHERE ${realm.mfaKey} = ? AND ${realm.activeWhere} AND totp_secret IS NULL AND enroll_code_hash = ? AND enroll_code_expires_at > ?`,
      params: [seal(secret, key).value, nowMs, id, sha256hex(normalizeOneTimeCode(enrollCode)), nowMs],
    },
  ]);
  return (r[0]?.changes ?? 0) > 0 ? secret : null;
}

/**
 * 등록 확정 — 대기 비밀로 만든 코드가 맞으면 확정 칸으로 옮기고, 등록 코드를 지우고, **복구 코드를 새로 발급**한다.
 * 성공하면 평문 복구 코드 목록(한 번만 보인다), 실패하면 null. 이미 확정된 비밀은 이 경로로 덮지 않는다.
 */
export async function confirmTotpEnrollment(
  db: DbDriver,
  realm: MfaRealm,
  id: string,
  code: string,
  masterKey: string | undefined,
  nowMs: number = Date.now(),
): Promise<string[] | null> {
  const key = requireMasterKey(masterKey);
  const { rows } = await db.query({
    sql: `SELECT totp_pending_secret FROM ${realm.mfaTable} WHERE ${realm.mfaKey} = ? AND ${realm.activeWhere} AND totp_secret IS NULL`,
    params: [id],
  });
  const pending = rows[0]?.totp_pending_secret;
  if (typeof pending !== "string") return null;
  if (!(await claimSecondFactorAttempt(db, realm, id, nowMs))) return null;
  const step = verifyTotp(await openAsync(pending, key), code, nowMs, null);
  if (step === null) return null;
  const r = await db.batch([
    {
      // 조건부 — 확인과 쓰기 사이에 다른 요청이 확정했거나 대기 비밀을 바꿨으면 쓰지 않는다.
      sql: `UPDATE ${realm.mfaTable} SET totp_secret = totp_pending_secret, totp_pending_secret = NULL, totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL,
                   enroll_code_hash = NULL, enroll_code_expires_at = NULL, updated_at = ?
             WHERE ${realm.mfaKey} = ? AND totp_secret IS NULL AND totp_pending_secret = ?`,
      params: [step, nowMs, id, pending],
    },
  ]);
  if ((r[0]?.changes ?? 0) === 0) return null;
  /**
   * 복구 코드는 확정에 **이긴 뒤에만** 쓴다. 같은 배치에 넣으면 동시 확정에서 진 요청도 복구 코드를 덮어써,
   * 이긴 요청이 사용자에게 보여 준 코드가 무효가 된다. 옛 코드는 지운다 — 새 장치로 등록했으면 예전에 인쇄해 둔
   * 코드는 더 이상 이 계정의 것이 아니다.
   */
  const recovery = Array.from({ length: PROVISIONAL_RECOVERY_CODES.count }, generateRecoveryCode);
  await db.batch([
    { sql: `DELETE FROM ${realm.recoveryTable} WHERE ${realm.recoveryKey} = ?`, params: [id] },
    ...recovery.map((c) => ({
      sql: `INSERT INTO ${realm.recoveryTable} (${realm.recoveryKey}, code_hash, created_at, used_at) VALUES (?, ?, ?, NULL)`,
      params: [id, sha256hex(normalizeOneTimeCode(c)), nowMs],
    })),
  ]);
  return recovery;
}

// ── 시도 잠금 ───────────────────────────────────────────────────────────

function lockUntilAfter(failures: number, nowMs: number): number | null {
  const over = failures - PROVISIONAL_TOTP_LOCK.freeFailures;
  if (over < 0) return null;
  return nowMs + Math.min(PROVISIONAL_TOTP_LOCK.baseLockMs * 2 ** Math.min(over, 30), PROVISIONAL_TOTP_LOCK.maxLockMs);
}

/**
 * 두 번째 요소(TOTP·복구 코드) 시도 슬롯을 **계산하기 전에** 원자적으로 차지한다 — 차지했으면 true.
 *
 * 계정 축 스로틀(분당 20회)만으로는 6자리 대입이 며칠이면 끝난다(하루 2.9만 회 × 3/10⁶). 그래서 연속 실패를
 * 주체에 쌓고, 문턱을 넘으면 실패할 때마다 잠금을 배로 늘린다. 이 경로에 닿으려면 비밀번호가 맞아야 하므로,
 * 비밀번호를 모르는 사람이 남의 계정을 잠그지는 못한다.
 *
 * ★실패를 나중에 기록하면(읽고 +1 해서 쓰기) 추측 N개를 동시에 보낼 때 모두가 "아직 안 잠김"을 읽고 통과하고,
 * 실패 수는 1만 는다(2026-10-18 보안 재검토). 그래서 순서를 뒤집는다: 시도마다 **먼저** 실패 수를 DB 안에서 +1 하고
 * (성공하면 0으로 되돌린다), 차지 조건을 그 UPDATE의 WHERE에 넣는다. 행 갱신은 DB가 직렬화하므로
 * 문턱 전에는 최대 `freeFailures`개, 잠금이 풀린 뒤에는 한 개만 차지한다.
 *
 * 잠금 해제 직후의 차지는 `totp_locked_until`을 비우고, 곧바로 아래에서 새 잠금을 건다 — 그 사이에 온 요청은
 * "실패 수가 문턱 이상인데 잠금 시각이 없다"는 조건에 걸려 차지하지 못한다.
 */
async function claimSecondFactorAttempt(db: DbDriver, realm: MfaRealm, id: string, nowMs: number): Promise<boolean> {
  const r = await db.batch([
    {
      sql: `UPDATE ${realm.mfaTable} SET totp_failures = totp_failures + 1, totp_locked_until = NULL
             WHERE ${realm.mfaKey} = ? AND (totp_failures < ? OR (totp_locked_until IS NOT NULL AND totp_locked_until <= ?))`,
      params: [id, PROVISIONAL_TOTP_LOCK.freeFailures, nowMs],
    },
  ]);
  if ((r[0]?.changes ?? 0) === 0) return false;
  const { rows } = await db.query({ sql: `SELECT totp_failures FROM ${realm.mfaTable} WHERE ${realm.mfaKey} = ?`, params: [id] });
  const until = lockUntilAfter(Number(rows[0]?.totp_failures ?? 0), nowMs);
  // 문턱에 닿은 시도는 결과를 보기 전에 잠금을 건다. 이 시도가 맞으면 성공 경로가 풀어 준다.
  if (until !== null) await db.batch([{ sql: `UPDATE ${realm.mfaTable} SET totp_locked_until = ? WHERE ${realm.mfaKey} = ?`, params: [until, id] }]);
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

// ── 검증·초기화·복구 ────────────────────────────────────────────────────

/** 확정된 TOTP가 있는가. */
export async function mfaEnrolled(db: DbDriver, realm: MfaRealm, id: string): Promise<boolean> {
  const { rows } = await db.query({ sql: `SELECT totp_secret FROM ${realm.mfaTable} WHERE ${realm.mfaKey} = ?`, params: [id] });
  return rows[0]?.totp_secret != null;
}

/**
 * MFA 검증 — 맞고 아직 안 쓴 스텝이면 true, 그 스텝을 소비한다.
 *
 * ★소비를 조건부 UPDATE로 한다. 같은 코드를 동시에 두 요청이 내면 둘 다 계산상 맞지만,
 * `totp_last_step < ?`를 이기는 쪽은 하나뿐이다 — 읽고 쓰는 사이의 재사용 창을 DB가 닫는다.
 */
export async function verifySecondFactorTotp(
  db: DbDriver,
  realm: MfaRealm,
  id: string,
  code: string,
  masterKey: string | undefined,
  nowMs: number = Date.now(),
): Promise<boolean> {
  const key = requireMasterKey(masterKey);
  const { rows } = await db.query({
    sql: `SELECT totp_secret, totp_last_step FROM ${realm.mfaTable} WHERE ${realm.mfaKey} = ? AND ${realm.activeWhere}`,
    params: [id],
  });
  const row = rows[0];
  if (typeof row?.totp_secret !== "string") return false;
  // 슬롯을 못 차지하면(잠김) 코드를 계산하지도 않는다 — 맞는 코드도 거절한다. 비용은 같게 태운다.
  if (!(await claimSecondFactorAttempt(db, realm, id, nowMs))) {
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
      sql: `UPDATE ${realm.mfaTable} SET totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL
             WHERE ${realm.mfaKey} = ? AND (totp_last_step IS NULL OR totp_last_step < ?)`,
      params: [step, id, step],
    },
  ]);
  return (r[0]?.changes ?? 0) > 0;
}

/**
 * MFA 초기화(분실 복구의 보조 경로 — 관리자 명령·호스트 CLI 전용) + 세션 철회 + 복구 코드 폐기 + **새 등록 코드 발급**.
 * 돌려준 등록 코드는 부른 쪽이 한 번만 보고 본인에게 따로 전달한다. 주체가 없으면 null.
 * 초기화 뒤에는 재등록 전까지 보호 요청이 막힌다.
 */
export async function resetTotpAndRevokeSessions(db: DbDriver, realm: MfaRealm, id: string, nowMs: number = Date.now()): Promise<string | null> {
  await ensureMfaRow(db, realm, id, nowMs);
  const code = generateOneTimeCode();
  const r = await db.batch([
    {
      sql: `UPDATE ${realm.mfaTable} SET totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = NULL, totp_failures = 0, totp_locked_until = NULL,
                   enroll_code_hash = ?, enroll_code_expires_at = ?, updated_at = ? WHERE ${realm.mfaKey} = ?`,
      params: [sha256hex(normalizeOneTimeCode(code)), nowMs + PROVISIONAL_ENROLL_CODE_TTL_MS, nowMs, id],
    },
    { sql: `UPDATE ${realm.sessionTable} SET revoked_at = ? WHERE ${realm.sessionKey} = ? AND revoked_at IS NULL`, params: [nowMs, id] },
    { sql: `DELETE FROM ${realm.recoveryTable} WHERE ${realm.recoveryKey} = ?`, params: [id] },
  ]);
  return (r[0]?.changes ?? 0) > 0 ? code : null;
}

/**
 * 복구 코드로 들어오기 — 인증 앱을 잃은 본인이 스스로 되찾는 경로(2026-10-18 사용자 결정).
 *
 * 맞으면: 그 코드를 소비하고, TOTP를 지우고, **다른 세션을 전부 끊고**, 새 등록 코드를 돌려준다. 호출자는 그 등록 코드로
 * 이 세션에서 곧바로 새 장치를 등록하게 한다. 복구 코드는 "MFA를 통과했다"가 아니라 "다시 등록할 자격"이다 —
 * 그래서 등록을 마치기 전에는 보호 요청이 열리지 않는다.
 *
 * 시도는 TOTP와 **같은 실패 카운터·잠금**을 쓴다(둘 다 두 번째 요소 추측이다). 틀림·잠김·쓴 코드는 전부 null.
 */
export async function redeemRecoveryCode(db: DbDriver, realm: MfaRealm, id: string, code: string, nowMs: number = Date.now()): Promise<{ enrollCode: string } | null> {
  const normalized = normalizeOneTimeCode(code);
  if (normalized === "") return null;
  if (!(await claimSecondFactorAttempt(db, realm, id, nowMs))) return null;
  const used = await db.batch([
    {
      sql: `UPDATE ${realm.recoveryTable} SET used_at = ? WHERE ${realm.recoveryKey} = ? AND code_hash = ? AND used_at IS NULL`,
      params: [nowMs, id, sha256hex(normalized)],
    },
  ]);
  if ((used[0]?.changes ?? 0) === 0) return null;
  const enrollCode = generateOneTimeCode();
  await db.batch([
    {
      sql: `UPDATE ${realm.mfaTable} SET totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = NULL, totp_failures = 0, totp_locked_until = NULL,
                   enroll_code_hash = ?, enroll_code_expires_at = ?, updated_at = ? WHERE ${realm.mfaKey} = ?`,
      params: [sha256hex(normalizeOneTimeCode(enrollCode)), nowMs + PROVISIONAL_ENROLL_CODE_TTL_MS, nowMs, id],
    },
    { sql: `UPDATE ${realm.sessionTable} SET revoked_at = ? WHERE ${realm.sessionKey} = ? AND revoked_at IS NULL`, params: [nowMs, id] },
  ]);
  return { enrollCode };
}

/** 남은(안 쓴) 복구 코드 수 — 화면이 "얼마 안 남았다"를 알릴 수 있게. */
export async function remainingRecoveryCodes(db: DbDriver, realm: MfaRealm, id: string): Promise<number> {
  const { rows } = await db.query({ sql: `SELECT COUNT(*) AS n FROM ${realm.recoveryTable} WHERE ${realm.recoveryKey} = ? AND used_at IS NULL`, params: [id] });
  return Number(rows[0]?.n ?? 0);
}

// ── 세션 ───────────────────────────────────────────────────────────────

function newToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * 세션 토큰 → CSRF 토큰. **유도한다**(따로 뽑지 않는다).
 *
 * ★따로 뽑아 화면 저장소에 두면 새 탭에는 토큰이 없어 쓰기가 전부 막힌다. 유도하면 서버가 쿠키만 보고 언제든
 * 다시 만들어 줄 수 있다(세션 조회 응답). 쿠키는 HttpOnly라 스크립트가 읽지 못하고, 그 응답은 같은
 * 오리진만 읽을 수 있으므로(CORS 미허용) 다른 사이트가 이 값을 얻을 길이 없다. 라벨이 영역마다 다르다.
 */
export function csrfTokenForRealm(realm: MfaRealm, sessionToken: string): string {
  return createHmac("sha256", sessionToken).update(realm.csrfLabel).digest("base64url");
}

/**
 * 세션 생성 — 쿠키에 넣을 토큰과 CSRF 토큰을 **한 번만** 돌려준다. 둘 다 해시로만 저장한다.
 * `mfaAt`: 이 로그인에서 MFA를 통과했으면 그 시각. 미등록 주체는 null로 열리고 등록 화면만 쓸 수 있다.
 */
export async function createWebSession(
  db: DbDriver,
  realm: MfaRealm,
  principalId: string,
  mfaAt: number | null,
  nowMs: number = Date.now(),
): Promise<{ sessionId: string; token: string; csrfToken: string }> {
  const token = newToken();
  const csrfToken = csrfTokenForRealm(realm, token);
  const sessionId = sha256hex(token);
  await db.batch([
    {
      sql: `INSERT INTO ${realm.sessionTable} (id, ${realm.sessionKey}, csrf_hash, created_at, last_seen_at, mfa_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)`,
      params: [sessionId, principalId, sha256hex(csrfToken), nowMs, nowMs, mfaAt],
    },
  ]);
  return { sessionId, token, csrfToken };
}

/** 세션 행의 수명 판정 + `last_seen_at` 갱신. 주체 조회(JOIN)는 영역별 해석기가 한다. 살아 있으면 true. */
export async function touchWebSession(
  db: DbDriver,
  realm: MfaRealm,
  sessionId: string,
  createdAt: number,
  lastSeen: number,
  policy: WebSessionPolicy,
  nowMs: number,
): Promise<boolean> {
  if (nowMs - createdAt > policy.absoluteMs || nowMs - lastSeen > policy.idleMs) return false;
  if (nowMs - lastSeen >= LAST_SEEN_WRITE_INTERVAL_MS) {
    await db.batch([{ sql: `UPDATE ${realm.sessionTable} SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL`, params: [nowMs, sessionId] }]);
  }
  return true;
}

/** 이 세션에서 방금 MFA를 통과했다(로그인 뒤 step-up·등록 확정). */
export async function markWebSessionMfa(db: DbDriver, realm: MfaRealm, sessionId: string, nowMs: number = Date.now()): Promise<void> {
  await db.batch([{ sql: `UPDATE ${realm.sessionTable} SET mfa_at = ? WHERE id = ? AND revoked_at IS NULL`, params: [nowMs, sessionId] }]);
}

/** 로그아웃 — 이 세션 하나. */
export async function revokeWebSession(db: DbDriver, realm: MfaRealm, sessionId: string, nowMs: number = Date.now()): Promise<void> {
  await db.batch([{ sql: `UPDATE ${realm.sessionTable} SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, params: [nowMs, sessionId] }]);
}

/** 그 주체의 세션 전부 — "모든 기기 로그아웃"·정지 대응. 끊은 수를 돌려준다. */
export async function revokeWebSessions(db: DbDriver, realm: MfaRealm, principalId: string, nowMs: number = Date.now()): Promise<number> {
  const r = await db.batch([{ sql: `UPDATE ${realm.sessionTable} SET revoked_at = ? WHERE ${realm.sessionKey} = ? AND revoked_at IS NULL`, params: [nowMs, principalId] }]);
  return r[0]?.changes ?? 0;
}
