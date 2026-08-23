/**
 * 테넌트 사용량 미터링(SaaS 과금) — 계정 수·저장 용량·기간 내 발송/바운스 집계.
 *
 * 과금 집계가 메일 스토어 본문에 섞여 있으면 "스토리지 변경"과 "요금제 변경"이 같은 파일에서
 * 충돌한다. 큐 상태 인코딩은 @ionosphere/db(MTA_QUEUE_STATUS)가 소유하므로 여기서는 참조만 한다.
 */
import { MTA_QUEUE_STATUS, PENDING_QUEUE_STATUSES } from "@ionosphere/db";
import type { StoreInternals } from "./internals.ts";
import type { TenantUsage } from "./types.ts";

export async function tenantUsage(s: StoreInternals, tenantId: string, opts: { windowMs?: number; now?: number } = {}): Promise<TenantUsage> {
  const now = opts.now ?? Date.now();
  const sinceMs = now - (opts.windowMs ?? 30 * 24 * 60 * 60 * 1000);
  const { rows: aRows } = await s.db.query({
    sql: `SELECT COUNT(*) AS accounts,
                 COALESCE(SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END), 0) AS active,
                 COALESCE(SUM(message_count), 0) AS messages,
                 COALESCE(SUM(used_bytes), 0) AS used_bytes,
                 COALESCE(SUM(quota_bytes), 0) AS quota_bytes
          FROM accounts WHERE tenant_id = ?`,
    params: [tenantId],
  });
  const a = aRows[0] ?? {};
  const { rows: qRows } = await s.db.query({
    sql: "SELECT status, COUNT(*) AS c FROM mta_queue WHERE tenant_id = ? AND created_at >= ? GROUP BY status",
    params: [tenantId, sinceMs],
  });
  const byStatus = new Map(qRows.map((r) => [Number(r.status), Number(r.c)]));
  // 상수는 @ionosphere/db 소유 — status 인코딩이 바뀌면 여기 집계도 함께 따라간다(청구서 오류 방지).
  const delivered = byStatus.get(MTA_QUEUE_STATUS.done) ?? 0;
  const bounced = byStatus.get(MTA_QUEUE_STATUS.bounced) ?? 0;
  const pending = PENDING_QUEUE_STATUSES.reduce<number>((sum, s) => sum + (byStatus.get(s) ?? 0), 0);
  return {
    tenantId,
    accounts: Number(a.accounts ?? 0),
    activeAccounts: Number(a.active ?? 0),
    messages: Number(a.messages ?? 0),
    storageBytes: Number(a.used_bytes ?? 0),
    quotaBytes: Number(a.quota_bytes ?? 0),
    window: { sinceMs, delivered, bounced, pending },
  };
}

// ── SetKeywords (§7-2) ──────────────────────────────────────────────
