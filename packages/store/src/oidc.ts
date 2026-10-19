/**
 * 외부 OIDC 로그인의 저장 — 인가 요청 상태(1회용)와 외부 신원 → 주체 연결 (회원 정책 E3).
 *
 * ★연결은 **sub로만** 찾는다. 이메일·이름 클레임으로 계정을 찾거나 만들지 않는다(자동 연결·JIT 금지 — 공통 기준 1).
 */
import { sha256hex, ulid } from "@ionosphere/core";
import { ACCOUNT_STATUS, ADMIN_STATUS, BatchConflictError, type DbDriver } from "@ionosphere/db";

export type OidcRealm = "admin" | "account";

/** 인가 요청 상태 수명 — 사람이 IdP에서 로그인하는 동안. 길면 훔친 state를 쓸 창이 넓어진다. */
export const OIDC_STATE_TTL_MS = 10 * 60 * 1000;

/** 메일 계정 쪽 `directory_identities.provider` 값 — LDAP provider 이름과 섞이지 않게 접두를 붙인다(D5). */
export function accountOidcProvider(providerId: string): string {
  return `oidc:${providerId}`;
}

/**
 * 진행 중인 인가 요청 수 상한. 시작 요청은 무인증이라 반복하면 행이 쌓인다 — 넘치면 새 시작을 거절한다(false).
 * 정상 로그인은 몇 분 안에 끝나 이 수에 닿지 않는다.
 */
export const MAX_PENDING_OIDC_STATES = 2000;

export async function saveOidcLoginState(
  db: DbDriver,
  input: { state: string; provider: string; realm: OidcRealm; nonce: string; codeVerifier: string },
  nowMs: number = Date.now(),
): Promise<boolean> {
  const { rows } = await db.query({ sql: "SELECT COUNT(*) AS n FROM oidc_login_states WHERE expires_at > ?", params: [nowMs] });
  if (Number(rows[0]?.n ?? 0) >= MAX_PENDING_OIDC_STATES) return false;
  await db.batch([
    // 만료된 것은 저장할 때 같이 쓸어낸다 — 별도 스위퍼를 두지 않아도 테이블이 자라지 않는다.
    { sql: "DELETE FROM oidc_login_states WHERE expires_at <= ?", params: [nowMs] },
    {
      sql: "INSERT INTO oidc_login_states (state_hash, provider, realm, nonce, code_verifier, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      params: [sha256hex(input.state), input.provider, input.realm, input.nonce, input.codeVerifier, nowMs, nowMs + OIDC_STATE_TTL_MS],
    },
  ]);
  return true;
}

/**
 * state를 **소비한다** — 맞고 안 만료됐고 영역이 같으면 저장된 nonce·verifier, 아니면 null. 두 번째 사용은 null이다
 * (DELETE의 changes로 판정 — 같은 state로 동시에 두 콜백이 와도 하나만 이긴다).
 */
export async function takeOidcLoginState(
  db: DbDriver,
  state: string,
  realm: OidcRealm,
  nowMs: number = Date.now(),
): Promise<{ provider: string; nonce: string; codeVerifier: string } | null> {
  const hash = sha256hex(state);
  const { rows } = await db.query({ sql: "SELECT provider, realm, nonce, code_verifier, expires_at FROM oidc_login_states WHERE state_hash = ?", params: [hash] });
  const row = rows[0];
  if (!row) return null;
  const r = await db.batch([{ sql: "DELETE FROM oidc_login_states WHERE state_hash = ?", params: [hash] }]);
  if ((r[0]?.changes ?? 0) === 0) return null;
  if (String(row.realm) !== realm || Number(row.expires_at) <= nowMs) return null;
  return { provider: String(row.provider), nonce: String(row.nonce), codeVerifier: String(row.code_verifier) };
}

// ── 관리자 영역 ───────────────────────────────────────────────────────

/** (공급자, sub) → 활성 관리자 id. 연결이 없거나 정지면 null. */
export async function adminByIdentity(db: DbDriver, provider: string, subject: string): Promise<string | null> {
  const { rows } = await db.query({
    sql: `SELECT u.id FROM admin_identities i JOIN admin_users u ON u.id = i.admin_user_id
           WHERE i.provider = ? AND i.subject = ? AND u.status = ?`,
    params: [provider, subject, ADMIN_STATUS.active],
  });
  return rows[0] ? String(rows[0].id) : null;
}

// ── 연결 식별자 묘비(마이그레이션 029) ─────────────────────────────────────

type TombstoneRealm = "admin" | "account";

/**
 * 이 sub가 예전에 **다른 주체**에 연결됐다가 끊겼는가. 그렇다면 다시 연결하지 않는다(회원 공통 수치 결정 9 — IdP가 sub를
 * 재활용하거나 운영자가 실수하면 예전 사람의 IdP 로그인이 새 주체로 들어온다). 원래 주인에게 다시 잇는 것은 허용한다.
 */
async function retiredForOther(db: DbDriver, realm: TombstoneRealm, provider: string, subject: string, ownerId: string): Promise<boolean> {
  const { rows } = await db.query({
    sql: "SELECT owner_id FROM identity_tombstones WHERE realm = ? AND provider = ? AND subject = ?",
    params: [realm, provider, subject],
  });
  return rows.length > 0 && String(rows[0]!.owner_id) !== ownerId;
}

/** 연결을 끊는 배치에 함께 넣는 묘비 — 이미 있으면(같은 sub를 예전에 끊었다) 첫 기록을 남긴다. */
function tombstoneStatement(db: DbDriver, realm: TombstoneRealm, provider: string, subject: string, ownerId: string, now: number): { sql: string; params: unknown[] } {
  return { sql: db.insertIgnore("identity_tombstones", ["realm", "provider", "subject", "owner_id", "retired_at"]), params: [realm, provider, subject, ownerId, now] };
}

/**
 * 연결 — 그 sub가 이미 다른 관리자에, 또는 그 관리자가 이 공급자의 다른 sub에 연결돼 있으면 "conflict".
 * 예전에 다른 관리자에 연결됐다가 끊긴 sub면 "retired"(묘비).
 */
export async function linkAdminIdentity(db: DbDriver, provider: string, subject: string, adminUserId: string): Promise<"ok" | "conflict" | "retired"> {
  if (await retiredForOther(db, "admin", provider, subject, adminUserId)) return "retired";
  try {
    await db.batch([
      { sql: "INSERT INTO admin_identities (provider, subject, admin_user_id, created_at) VALUES (?, ?, ?, ?)", params: [provider, subject, adminUserId, Date.now()] },
    ]);
    return "ok";
  } catch (err) {
    if (err instanceof BatchConflictError) return "conflict";
    throw err;
  }
}

/** 연결 해제 — 행을 지우고 같은 배치에서 묘비를 남긴다(다른 관리자에 다시 연결하지 못하게). */
export async function unlinkAdminIdentity(db: DbDriver, provider: string, adminUserId: string): Promise<boolean> {
  const { rows } = await db.query({ sql: "SELECT subject FROM admin_identities WHERE provider = ? AND admin_user_id = ?", params: [provider, adminUserId] });
  if (rows.length === 0) return false;
  const subject = String(rows[0]!.subject);
  const r = await db.batch([
    tombstoneStatement(db, "admin", provider, subject, adminUserId, Date.now()),
    { sql: "DELETE FROM admin_identities WHERE provider = ? AND admin_user_id = ? AND subject = ?", params: [provider, adminUserId, subject] },
  ]);
  return (r[1]?.changes ?? 0) > 0;
}

export async function listAdminIdentities(db: DbDriver): Promise<{ provider: string; subject: string; adminUserId: string; createdAt: number }[]> {
  const { rows } = await db.query({ sql: "SELECT provider, subject, admin_user_id, created_at FROM admin_identities ORDER BY created_at" });
  return rows.map((r) => ({ provider: String(r.provider), subject: String(r.subject), adminUserId: String(r.admin_user_id), createdAt: Number(r.created_at) }));
}

// ── 메일 계정 영역(D5: directory_identities 재사용) ─────────────────────────

/** (테넌트, 공급자, sub) → 활성 메일 계정 id. 연결이 없거나 계정이 활성이 아니면 null. */
export async function accountByOidcIdentity(db: DbDriver, tenantId: string, providerId: string, subject: string): Promise<string | null> {
  const { rows } = await db.query({
    sql: `SELECT a.id FROM directory_identities d JOIN accounts a ON a.id = d.account_id
           WHERE d.tenant_id = ? AND d.provider = ? AND d.external_key = ? AND d.status = 1 AND a.status = ? AND a.tenant_id = ?`,
    params: [tenantId, accountOidcProvider(providerId), subject, ACCOUNT_STATUS.active, tenantId],
  });
  return rows[0] ? String(rows[0].id) : null;
}

/**
 * 메일 계정 연결 — `directory_identities`에 OIDC 신원 행을 만든다. 같은 테넌트의 활성 계정이어야 한다.
 * 그 sub가 이미 있거나(다른 계정이든 같은 계정이든), 그 계정이 이 공급자의 다른 sub에 연결돼 있으면 "conflict"
 * (024의 UNIQUE가 최종 판정).
 */
export async function linkAccountOidcIdentity(db: DbDriver, tenantId: string, providerId: string, subject: string, accountId: string): Promise<"ok" | "conflict" | "no_account" | "retired"> {
  const { rows } = await db.query({ sql: "SELECT id FROM accounts WHERE id = ? AND tenant_id = ? AND status = ?", params: [accountId, tenantId, ACCOUNT_STATUS.active] });
  if (rows.length === 0) return "no_account";
  // 예전에 다른 계정에 연결됐다가 끊긴 sub면 다시 쓰지 않는다(묘비, 마이그레이션 029).
  if (await retiredForOther(db, "account", accountOidcProvider(providerId), subject, accountId)) return "retired";
  try {
    await db.batch([
      {
        sql: `INSERT INTO directory_identities (id, tenant_id, provider, external_key, account_id, login_names, email, display_name, last_seen_at, status)
              VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, 1)`,
        params: [ulid(), tenantId, accountOidcProvider(providerId), subject, accountId, "[]", Date.now()],
      },
    ]);
    return "ok";
  } catch (err) {
    if (err instanceof BatchConflictError) return "conflict";
    throw err;
  }
}

/** 연결 해제 — 행을 지우고 같은 배치에서 묘비를 남긴다(다른 계정에 다시 연결하지 못하게). 연결된 계정이 없던 행은 묘비가 필요 없다. */
export async function unlinkAccountOidcIdentity(db: DbDriver, tenantId: string, providerId: string, subject: string): Promise<boolean> {
  const provider = accountOidcProvider(providerId);
  const { rows } = await db.query({
    sql: "SELECT account_id FROM directory_identities WHERE tenant_id = ? AND provider = ? AND external_key = ?",
    params: [tenantId, provider, subject],
  });
  if (rows.length === 0) return false;
  const owner = rows[0]!.account_id;
  const del = { sql: "DELETE FROM directory_identities WHERE tenant_id = ? AND provider = ? AND external_key = ?", params: [tenantId, provider, subject] };
  const r = await db.batch(owner == null ? [del] : [tombstoneStatement(db, "account", provider, subject, String(owner), Date.now()), del]);
  return (r[r.length - 1]?.changes ?? 0) > 0;
}
