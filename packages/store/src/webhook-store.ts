/**
 * 수신 웹훅 엔드포인트·배달 큐 (Phase 4).
 *
 * 적재만 담당한다 — 실제 POST·재시도는 @ionosphere/webhook의 WebhookWorker.
 */
import { open, seal, ulid } from "@ionosphere/core";
import type { Statement } from "@ionosphere/db";
import { StoreError } from "./errors.ts";
import type { StoreInternals } from "./internals.ts";

/**
 * `webhook_endpoints.secret` / `webhook_deliveries.secret` 컬럼 폭 — 마이그레이션 002의
 * `VARCHAR(128)`이고 **스키마는 동결**이다(`docs/SCHEMA.md` v2.1).
 *
 * ★봉인은 값을 늘린다. secretbox 포맷은 고정 오버헤드 74자(`enc$v1$` + salt/iv/tag base64)
 * 위에 본문 base64(`4*ceil(n/3)`)가 얹히므로, 128자에 들어가는 평문은 **39바이트까지**다.
 * sqlite는 VARCHAR 폭을 무시하지만 postgres/mysql은 초과분을 에러 또는 절단으로 처리하고,
 * **절단된 봉인문은 두 번 다시 열리지 않는다**(GCM 태그 검증 실패 = 배달 영구 불가).
 * 그래서 저장 전에 실제 문자열 길이를 재서 거부한다 — 조용히 깨진 값을 심는 것보다
 * 등록을 실패시키는 쪽이 안전하다(fail closed).
 */
const MAX_SECRET_COLUMN_CHARS = 128;

/** 봉인 후에도 컬럼에 들어가는 평문 최대 바이트(위 계산의 결과값 — 에러 메시지에 쓴다). */
const MAX_SEALABLE_SECRET_BYTES = 39;

/**
 * 엔드포인트 시크릿 복호 — 저장 포맷 3가지를 모두 받는다.
 *
 * - `enc$v1$...` : secretbox 봉인 (masterKey 필요)
 * - `plain$...`  : 마스터키 미설정 배포의 평문 (core `open()`이 접두사를 떼준다)
 * - 그 외        : **봉인 도입 이전에 저장된 날평문** — `open()`은 이걸 "unknown format"으로
 *                  던지므로 여기서 먼저 걸러 그대로 돌려준다. 이 갈래가 없으면 기존 배포가
 *                  마이그레이션 없이는 웹훅을 못 보낸다(값이 이미 DB에 있고 우리는 스키마를
 *                  동결했으므로 백필 마이그레이션이라는 수단 자체가 없다).
 *                  빈 문자열(`NOT NULL DEFAULT ''`)도 이 갈래로 떨어져 "서명 없음"이 된다.
 */
function openEndpointSecret(stored: string, masterKey: string | undefined): string {
  if (stored.startsWith("enc$") || stored.startsWith("plain$")) return open(stored, masterKey);
  return stored;
}

/**
 * 웹훅 엔드포인트 등록. 시크릿은 정본 저장소라 **저장 시 봉인**한다(secretbox) —
 * DKIM 개인키·스마트호스트 비밀번호와 같은 규율이다. 마스터키가 없으면 `plain$` 평문이고,
 * 그 조건은 부팅 게이트(`apps/server/src/main.ts` `assertSecretsAtRest`)가 이미 막는다.
 */
export async function addWebhookEndpoint(s: StoreInternals, accountId: string, url: string, secret: string): Promise<string> {
  const id = ulid();
  const stored = seal(secret, s.masterKey).value;
  if (stored.length > MAX_SECRET_COLUMN_CHARS) {
    throw new StoreError(
      `웹훅 시크릿이 너무 깁니다 — 봉인 결과 ${stored.length}자가 컬럼 폭 ${MAX_SECRET_COLUMN_CHARS}자를 넘습니다` +
        ` (봉인 오버헤드 때문에 평문 ${MAX_SEALABLE_SECRET_BYTES}바이트까지만 저장 가능)`,
    );
  }
  await s.db.batch([
    { sql: "INSERT INTO webhook_endpoints (id, account_id, url, secret, active, created_at) VALUES (?, ?, ?, ?, 1, ?)", params: [id, accountId, url, stored, Date.now()] },
  ]);
  return id;
}

export async function listWebhookEndpoints(s: StoreInternals, accountId: string): Promise<{ id: string; url: string; active: boolean }[]> {
  const { rows } = await s.db.query({ sql: "SELECT id, url, active FROM webhook_endpoints WHERE account_id = ? ORDER BY created_at", params: [accountId] });
  return rows.map((r) => ({ id: String(r.id), url: String(r.url), active: Number(r.active) === 1 }));
}

export async function deleteWebhookEndpoint(s: StoreInternals, accountId: string, id: string): Promise<void> {
  await s.db.batch([{ sql: "DELETE FROM webhook_endpoints WHERE id = ? AND account_id = ?", params: [id, accountId] }]);
}

/**
 * 수신 메일에 대해 계정의 활성 웹훅 엔드포인트마다 배달을 적재(재시도 큐). URL/시크릿/
 * 페이로드를 적재 시점 스냅샷 → 이후 엔드포인트 변경·삭제와 무관하게 배달 일관. 적재 건수 반환.
 *
 * ★시크릿 사본의 수명은 여기가 아니라 WebhookWorker가 관리한다(감사 §8-10): 배달이 종료
 * 상태(done/failed)에 닿는 순간 워커가 `secret = ''`으로 비우고, 보존 기간이 지난 종료 행은
 * `sweepRetention()`이 지운다. 적재 측이 사본을 남기는 건 재시도 구간에서 서명하기 위함이지,
 * 영구 보관하려는 게 아니다.
 *
 * ★사본은 **복호된 평문**으로 넣는다. 정본만 봉인하고 사본은 그대로 두는 이유: 워커가 서명하는
 * 값은 평문이어야 하고(HMAC 키), 사본까지 봉인하면 워커가 매 배달마다 마스터키를 들고 복호해야
 * 한다 — 실패 지점만 늘고 수명이 이미 닫혀 있어(위 문단) 얻는 것이 없다. 감사 §9-10의 판정이다.
 */
export async function enqueueWebhookDeliveries(s: StoreInternals, accountId: string, payload: string): Promise<number> {
  const { rows } = await s.db.query({ sql: "SELECT id, url, secret FROM webhook_endpoints WHERE account_id = ? AND active = 1", params: [accountId] });
  if (rows.length === 0) return 0;
  const now = Date.now();
  const stmts: Statement[] = rows.map((r) => ({
    sql: `INSERT INTO webhook_deliveries (id, account_id, endpoint_id, url, secret, payload, status, attempts, next_attempt, lease_until, last_error, created_at)
          VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, NULL, NULL, ?)`,
    params: [ulid(), accountId, String(r.id), String(r.url), openEndpointSecret(String(r.secret), s.masterKey), payload, now, now],
  }));
  await s.db.batch(stmts);
  return rows.length;
}
