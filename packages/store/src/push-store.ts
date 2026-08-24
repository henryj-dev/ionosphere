/**
 * JMAP `PushSubscription` 저장 (RFC 8620 §7.2).
 *
 * ★`verification_code`는 **읽어 나가지 않는다.** `/get`이 그 값을 돌려주면 아무나 구독을
 * 조회해 코드를 알아내고 확인 절차를 우회한다 — 그 절차의 목적이 "이 엔드포인트가 정말
 * 구독자의 것인가"이므로, 코드는 **엔드포인트로만** 전달돼야 의미가 있다.
 * 그래서 조회 함수는 코드를 빼고 돌려주고, 대조는 여기 안에서만 한다.
 */
import { ulid } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";

export interface PushSubscriptionRow {
  id: string;
  deviceClientId: string;
  url: string;
  keys: { p256dh: string; auth: string } | null;
  /** 확인 전이면 null — 이 값이 없으면 `StateChange`를 보내지 않는다(§7.2.2). */
  verifiedAt: number | null;
  expires: number;
  /** 관심 타입. null이면 전부(§7.2.1). */
  types: string[] | null;
}

export interface PushSubscriptionInput {
  deviceClientId: string;
  url: string;
  keys: { p256dh: string; auth: string } | null;
  expires: number;
  types: string[] | null;
}

function mapRow(r: Record<string, unknown>): PushSubscriptionRow {
  const p256dh = r.keys_p256dh == null ? null : String(r.keys_p256dh);
  const auth = r.keys_auth == null ? null : String(r.keys_auth);
  return {
    id: String(r.id),
    deviceClientId: String(r.device_client_id),
    url: String(r.url),
    keys: p256dh !== null && auth !== null ? { p256dh, auth } : null,
    verifiedAt: r.verified_at == null ? null : Number(r.verified_at),
    expires: Number(r.expires),
    types: r.types == null ? null : (JSON.parse(String(r.types)) as string[]),
  };
}

/** 이 사용자의 구독들. **만료된 것은 빼고** 돌려준다 — 만료는 곧 없는 것이다(§7.2.1). */
export async function listPushSubscriptions(db: DbDriver, subjectId: string, now: number = Date.now()): Promise<PushSubscriptionRow[]> {
  const { rows } = await db.query({
    sql: `SELECT id, device_client_id, url, keys_p256dh, keys_auth, verified_at, expires, types
            FROM push_subscriptions WHERE subject_id = ? AND expires > ? ORDER BY created_at`,
    params: [subjectId, now],
  });
  return rows.map(mapRow);
}

/**
 * 만들거나 **대체한다**(`deviceClientId`가 같으면).
 *
 * ★같은 기기가 다시 등록하면 새 구독이 아니라 교체다(§7.2.1의 유일성). 아니면 앱을 다시
 * 깔 때마다 죽은 구독이 쌓이고 우리는 그 전부에 POST를 계속한다.
 *
 * ★확인 코드는 **여기서 만든다.** 클라이언트가 준 값을 쓰면 확인 절차가 무의미해진다 —
 * 자기가 아는 코드를 되돌려주는 것은 아무것도 증명하지 못한다.
 */
export async function upsertPushSubscription(
  db: DbDriver,
  subjectId: string,
  input: PushSubscriptionInput,
  now: number = Date.now(),
): Promise<{ id: string; verificationCode: string }> {
  const verificationCode = ulid();
  const id = ulid();
  await db.batch([
    { sql: "DELETE FROM push_subscriptions WHERE subject_id = ? AND device_client_id = ?", params: [subjectId, input.deviceClientId] },
    {
      sql: `INSERT INTO push_subscriptions
              (id, subject_id, device_client_id, url, keys_p256dh, keys_auth, verification_code, verified_at, expires, types, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`,
      params: [
        id,
        subjectId,
        input.deviceClientId,
        input.url,
        input.keys?.p256dh ?? null,
        input.keys?.auth ?? null,
        verificationCode,
        input.expires,
        input.types === null ? null : JSON.stringify(input.types),
        now,
      ],
    },
  ]);
  return { id, verificationCode };
}

/**
 * 확인 코드를 대조해 맞으면 검증 상태로 바꾼다 (§7.2.2).
 *
 * ★대조를 **여기 안에서** 한다. 코드를 밖으로 내보내 호출자가 비교하게 하면 그 값이
 * 로그·응답에 실릴 길이 생기고, 그러면 확인 절차가 형식만 남는다.
 */
export async function verifyPushSubscription(
  db: DbDriver,
  subjectId: string,
  id: string,
  code: string,
  now: number = Date.now(),
): Promise<boolean> {
  const [res] = await db.batch([
    {
      sql: "UPDATE push_subscriptions SET verified_at = ? WHERE id = ? AND subject_id = ? AND verification_code = ?",
      params: [now, id, subjectId, code],
    },
  ]);
  return (res?.changes ?? 0) === 1;
}

/** 만료 연장·타입 변경. 계정 스코프를 WHERE에 둔다 — id는 클라이언트가 주는 값이다. */
export async function updatePushSubscription(
  db: DbDriver,
  subjectId: string,
  id: string,
  patch: { expires?: number; types?: string[] | null },
): Promise<boolean> {
  const sets: string[] = [];
  const params: unknown[] = [];
  if (patch.expires !== undefined) {
    sets.push("expires = ?");
    params.push(patch.expires);
  }
  if (patch.types !== undefined) {
    sets.push("types = ?");
    params.push(patch.types === null ? null : JSON.stringify(patch.types));
  }
  if (sets.length === 0) return true;
  const [res] = await db.batch([
    { sql: `UPDATE push_subscriptions SET ${sets.join(", ")} WHERE id = ? AND subject_id = ?`, params: [...params, id, subjectId] },
  ]);
  return (res?.changes ?? 0) === 1;
}

export async function deletePushSubscription(db: DbDriver, subjectId: string, id: string): Promise<boolean> {
  const [res] = await db.batch([
    { sql: "DELETE FROM push_subscriptions WHERE id = ? AND subject_id = ?", params: [id, subjectId] },
  ]);
  return (res?.changes ?? 0) > 0;
}

/**
 * 푸시를 보낼 대상 — **검증됐고 만료되지 않은** 것만.
 *
 * ★두 조건이 다 필수다. 검증 없이 보내면 우리가 임의 URL로 POST하는 도구가 되고,
 * 만료를 안 보면 죽은 엔드포인트로 영원히 보낸다.
 */
export async function pushTargets(db: DbDriver, subjectId: string, now: number = Date.now()): Promise<PushSubscriptionRow[]> {
  const { rows } = await db.query({
    sql: `SELECT id, device_client_id, url, keys_p256dh, keys_auth, verified_at, expires, types
            FROM push_subscriptions WHERE subject_id = ? AND verified_at IS NOT NULL AND expires > ?`,
    params: [subjectId, now],
  });
  return rows.map(mapRow);
}

/**
 * 푸시를 받을 사람들 — **검증되고 살아 있는** 구독을 가진 주체만.
 *
 * ★푸시 감시자가 이 목록만 폴링한다. 전체 계정을 돌면 구독하지 않은 계정까지 주기 조회를
 * 하게 되고, 그건 이 기능을 안 쓰는 사람이 내는 비용이다.
 */
export async function pushSubjects(db: DbDriver, now: number = Date.now()): Promise<string[]> {
  const { rows } = await db.query({
    sql: "SELECT DISTINCT subject_id FROM push_subscriptions WHERE verified_at IS NOT NULL AND expires > ?",
    params: [now],
  });
  return rows.map((r) => String(r.subject_id));
}

/** 만료된 구독 정리 — 보존 스윕이 부른다. */
export async function purgeExpiredPushSubscriptions(db: DbDriver, now: number = Date.now()): Promise<number> {
  const [res] = await db.batch([{ sql: "DELETE FROM push_subscriptions WHERE expires <= ?", params: [now] }]);
  return res?.changes ?? 0;
}
