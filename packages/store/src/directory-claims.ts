/**
 * 디렉터리(LDAP/AD) 연결의 최초 주인 기록 — SSO sub와 같은 규칙을 디렉터리 외부 키에도 건다(2026-10-19 사용자 결정).
 *
 * 왜: 계정 드레인(SCHEMA §7-7)이 탈퇴한 계정의 `directory_identities` 행을 지운다. 그러면 다음 동기화가 같은 외부 키를
 * "연결 없음"으로 다시 만들고, 운영자가 그 키를 **다른 계정**에 이을 수 있었다. 해제(`directory-identity-unlink`)도 같다.
 * 예전 사람의 디렉터리 로그인이 새 계정으로 들어오는 길이다. 그래서 처음 연결할 때 주인을 `identity_claims`에 남기고
 * 지우지 않는다(마이그레이션 029의 표를 그대로 쓴다, realm="directory").
 *
 * 연결은 한 원자 배치다: 기록을 INSERT IGNORE하고(최초 주인이 이긴다), `directory_identities` UPDATE에 「주인이 나」
 * 조건을 붙인다. 같은 계정이 같은 공급자의 두 키를 동시에 claim해 UNIQUE 충돌이 나도 claim까지 함께 롤백된다.
 *
 * 이 변경 전에 이미 있던 연결은 기록이 없다. 해제 명령은 행을 지우는 같은 배치에서, 계정 드레인은 데이터 삭제 전에
 * 청크로 그 주인을 먼저 기록한다. 그래서 옮겨 적는 마이그레이션이 필요 없다(방언마다 문자열 연결·해시가 달라 SQL로는 같은 키를 못 만든다).
 *
 * 키 모양: `provider` 열에 `<테넌트 id>:<공급자>`(26+1+32 ≤ 64자), `subject` 열에 외부 키의 SHA-256.
 * 원문 키는 512자이고 DN처럼 개인정보를 담을 수 있어 묘비에는 SHA-256만 남긴다. 이는 가명화라 후보 DN을
 * 아는 사람의 대조까지 막지는 않는다. 서버 비밀 HMAC은 키 회전 때 묘비를 무효화하므로 쓰지 않는다.
 */
import { sha256hex, ulid } from "@ionosphere/core";
import { BatchConflictError, type DbDriver, type Statement } from "@ionosphere/db";
import { directoryMembershipSource } from "./directory-sync.ts";

export const DIRECTORY_CLAIM_REALM = "directory";

function directoryClaimKey(tenantId: string, provider: string, externalKey: string): { provider: string; subject: string } {
  return { provider: `${tenantId}:${provider}`, subject: `sha256:${sha256hex(externalKey)}` };
}

/** 주인 기록 — 이미 있으면 그대로 둔다(최초 주인이 이긴다). 해제·계정 드레인도 이 문장을 삭제 앞에 둔다. */
export function directoryClaimStatement(
  db: DbDriver,
  tenantId: string,
  provider: string,
  externalKey: string,
  ownerId: string,
  now: number,
): Statement {
  const k = directoryClaimKey(tenantId, provider, externalKey);
  return {
    sql: db.insertIgnore("identity_claims", ["realm", "provider", "subject", "owner_id", "claimed_at"]),
    params: [DIRECTORY_CLAIM_REALM, k.provider, k.subject, ownerId, now],
  };
}

export type DirectoryLinkResult = "ok" | "conflict" | "retired";

export interface DirectoryLinkInput {
  tenantId: string;
  provider: string;
  externalKey: string;
  accountId: string;
  displayName: string | null;
  now?: number;
}

const DIRECTORY_LINK_RETRY_LIMIT = 5;

/**
 * 외부 키를 계정에 연결하고 최초 주인을 남긴다.
 *
 * `retired`: 이 키가 예전에 다른 계정에 연결됐었다(현재 행이 끊겨 있어도 묘비가 막음).
 * `conflict`: 지금 다른 계정에 연결돼 있거나, 이 계정이 같은 공급자의 다른 키에 연결돼 있다.
 *
 * MySQL은 서로 다른 identity 행을 같은 계정에 동시에 연결하면 두 트랜잭션이 계정 유니크 인덱스를
 * 반대 순서로 기다려 교착될 수 있다. DB가 한쪽을 되돌린 뒤 **전체 판정부터** 다시 해야 한다 — 실패한
 * batch만 그대로 재전송하면 그사이 이긴 연결·claim을 보지 못한다. PG의 deadlock/serialization과
 * SQLite busy도 같은 규칙으로 처리한다.
 */
export async function linkDirectoryIdentityWithClaim(db: DbDriver, input: DirectoryLinkInput): Promise<DirectoryLinkResult> {
  let lastError: unknown;
  for (let attempt = 0; attempt < DIRECTORY_LINK_RETRY_LIMIT; attempt++) {
    try {
      return await linkDirectoryIdentityAttempt(db, input);
    } catch (error) {
      if (!isRetryableTransactionError(error)) throw error;
      lastError = error;
      if (attempt < DIRECTORY_LINK_RETRY_LIMIT - 1) {
        await new Promise((resolve) => setTimeout(resolve, 5 * (attempt + 1) + Math.floor(Math.random() * 10)));
      }
    }
  }
  throw lastError;
}

function isRetryableTransactionError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  // node:sqlite는 code="ERR_SQLITE_ERROR", errcode=5로 busy를 표현한다.
  if ("errcode" in error && Number((error as { errcode: unknown }).errcode) === 5) return true;
  if (!("code" in error)) return false;
  const code = String((error as { code: unknown }).code);
  return code === "ER_LOCK_DEADLOCK" || code === "ER_LOCK_WAIT_TIMEOUT" || code === "40P01" || code === "40001";
}

async function linkDirectoryIdentityAttempt(db: DbDriver, input: DirectoryLinkInput): Promise<DirectoryLinkResult> {
  if (input.provider.startsWith("oidc:")) throw new Error("OIDC identity는 OIDC 연결 함수로 다뤄야 합니다");
  const now = input.now ?? Date.now();
  const k = directoryClaimKey(input.tenantId, input.provider, input.externalKey);
  const state = async (): Promise<{ accountId: string | null; ownerId: string | null }> => {
    const { rows } = await db.query({
      sql: `SELECT d.account_id, c.owner_id
              FROM directory_identities d LEFT JOIN identity_claims c
                ON c.realm = ? AND c.provider = ? AND c.subject = ?
             WHERE d.tenant_id = ? AND d.provider = ? AND d.external_key = ?`,
      params: [DIRECTORY_CLAIM_REALM, k.provider, k.subject, input.tenantId, input.provider, input.externalKey],
    });
    return {
      accountId: rows[0]?.account_id == null ? null : String(rows[0].account_id),
      ownerId: rows[0]?.owner_id == null ? null : String(rows[0].owner_id),
    };
  };

  const before = await state();
  if (before.accountId !== null && before.accountId !== input.accountId) return "conflict";
  if (before.ownerId !== null && before.ownerId !== input.accountId) return "retired";

  try {
    const statements: Statement[] = [
      {
        sql: `UPDATE directory_identities SET account_id = ?
               WHERE tenant_id = ? AND provider = ? AND external_key = ? AND status = 1
                 AND (account_id IS NULL OR account_id = ?)
                 AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND tenant_id = ? AND status = 1)
                 AND NOT EXISTS (SELECT 1 FROM identity_claims
                                  WHERE realm = ? AND provider = ? AND subject = ? AND owner_id <> ?)`,
        params: [
          input.accountId,
          input.tenantId,
          input.provider,
          input.externalKey,
          input.accountId,
          input.accountId,
          input.tenantId,
          DIRECTORY_CLAIM_REALM,
          k.provider,
          k.subject,
          input.accountId,
        ],
      },
    ];
    if (before.ownerId === null) {
      /**
       * 연결 UPDATE가 실제 승인된 경우에만 claim한다. 삭제가 사전 조회와 배치 사이에 시작되면 UPDATE도 SELECT도
       * 0행이라 묘비가 생기지 않는다. 동시 최초 연결은 identity 행 잠금 뒤 한쪽만 account_id를 얻고, 진 쪽의
       * INSERT SELECT는 0행이다. 같은 계정의 두 키가 UNIQUE 충돌하면 이 INSERT까지 한 배치로 롤백된다.
       */
      statements.push({
        sql: `INSERT INTO identity_claims (realm, provider, subject, owner_id, claimed_at)
              SELECT ?, ?, ?, ?, ? FROM directory_identities d JOIN accounts a ON a.id = d.account_id
               WHERE d.tenant_id = ? AND d.provider = ? AND d.external_key = ? AND d.account_id = ? AND d.status = 1
                 AND a.tenant_id = ? AND a.status = 1`,
        params: [
          DIRECTORY_CLAIM_REALM,
          k.provider,
          k.subject,
          input.accountId,
          now,
          input.tenantId,
          input.provider,
          input.externalKey,
          input.accountId,
          input.tenantId,
        ],
      });
    }
    /**
     * identity principal은 외부 주체 자체라 account_id를 갖지 않는다. 연결이 승인된 경우에만 만들고 갱신한다.
     * 연결·묘비·principal·권한 버전을 한 배치에 둬 중간 실패가 반쪽 상태를 남기지 않는다.
     */
    const linked = `EXISTS (SELECT 1 FROM directory_identities d JOIN identity_claims c
                              ON c.realm = ? AND c.provider = ? AND c.subject = ? AND c.owner_id = d.account_id
                            WHERE d.tenant_id = ? AND d.provider = ? AND d.external_key = ? AND d.account_id = ? AND d.status = 1)`;
    const principalColumns = ["id", "tenant_id", "kind", "provider", "external_key", "display_name", "created_at"] as const;
    const marker = `VALUES (${principalColumns.map(() => "?").join(", ")})`;
    const principalInsert = db.insertIgnore("principals", principalColumns);
    if (!principalInsert.includes(marker)) throw new Error("directory principal INSERT 변환 실패");
    statements.push({
      // FROM 한 행을 명시한다 — 오래된 MariaDB도 FROM 없는 SELECT … WHERE에 기대지 않게.
      sql: principalInsert.replace(marker, `SELECT ?, ?, 0, ?, ?, ?, ? FROM (SELECT 1) AS one WHERE ${linked}`),
      params: [
        ulid(), input.tenantId, input.provider, input.externalKey, input.displayName, now,
        DIRECTORY_CLAIM_REALM, k.provider, k.subject, input.tenantId, input.provider, input.externalKey, input.accountId,
      ],
    });
    statements.push({
      sql: `UPDATE principals SET display_name = ?
             WHERE tenant_id = ? AND kind = 0 AND provider = ? AND external_key = ? AND ${linked}`,
      params: [
        input.displayName, input.tenantId, input.provider, input.externalKey,
        DIRECTORY_CLAIM_REALM, k.provider, k.subject, input.tenantId, input.provider, input.externalKey, input.accountId,
      ],
    });
    statements.push({
      sql: `UPDATE accounts SET permissions_version = permissions_version + 1
             WHERE id = ? AND tenant_id = ? AND ${linked}`,
      params: [
        input.accountId, input.tenantId,
        DIRECTORY_CLAIM_REALM, k.provider, k.subject, input.tenantId, input.provider, input.externalKey, input.accountId,
      ],
    });
    await db.batch(statements);
  } catch (error) {
    if (!(error instanceof BatchConflictError)) throw error;
    // 같은 계정의 같은 요청이 동시에 성공해 claim UNIQUE만 경합했으면 이미 원하는 상태다.
  }

  const after = await state();
  if (after.accountId !== null && after.accountId !== input.accountId) return "conflict";
  if (after.ownerId !== null && after.ownerId !== input.accountId) return "retired";
  if (after.accountId !== input.accountId || after.ownerId !== input.accountId) return "conflict";
  return "ok";
}

/**
 * 연결 해제 — 기존 연결을 처음 보는 경우도, 행을 끊는 **같은 배치 안에서** 최초 주인을 기록한다.
 * claim은 지우지 않으므로 원래 계정만 다시 연결할 수 있다.
 */
export async function unlinkDirectoryIdentityWithClaim(
  db: DbDriver,
  input: { tenantId: string; provider: string; externalKey: string; now?: number },
): Promise<"ok" | "notFound"> {
  if (input.provider.startsWith("oidc:")) throw new Error("OIDC identity는 OIDC 연결 함수로 다뤄야 합니다");
  const { rows } = await db.query({
    sql: "SELECT account_id FROM directory_identities WHERE tenant_id = ? AND provider = ? AND external_key = ?",
    params: [input.tenantId, input.provider, input.externalKey],
  });
  const accountId = rows[0]?.account_id == null ? null : String(rows[0].account_id);
  if (!accountId) return "notFound";
  await db.batch([
    directoryClaimStatement(db, input.tenantId, input.provider, input.externalKey, accountId, input.now ?? Date.now()),
    { sql: "DELETE FROM account_memberships WHERE account_id = ? AND source = ?", params: [accountId, directoryMembershipSource(input.provider)] },
    // 기능 전 sync가 identity principal에 account_id를 넣었을 수 있다. 해제 뒤 외부 주체 ACL이 계정에 남지 않게 걷는다.
    {
      sql: "UPDATE principals SET account_id = NULL WHERE tenant_id = ? AND kind = 0 AND provider = ? AND external_key = ? AND account_id = ?",
      params: [input.tenantId, input.provider, input.externalKey, accountId],
    },
    {
      sql: "UPDATE directory_identities SET account_id = NULL WHERE tenant_id = ? AND provider = ? AND external_key = ? AND account_id = ?",
      params: [input.tenantId, input.provider, input.externalKey, accountId],
    },
    { sql: "UPDATE accounts SET permissions_version = permissions_version + 1 WHERE id = ? AND tenant_id = ?", params: [accountId, input.tenantId] },
  ]);
  return "ok";
}
