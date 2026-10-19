import type { Migration } from "../migrate.ts";

/**
 * 계정 삭제 시작 시각 — 계정 드레인의 마감(24시간) 판정용 (2026-10-19 P8 결정).
 *
 * 탈퇴를 "즉시 비노출 + 비동기 드레인"으로 처리하려면 드레인이 **언제 시작됐는지**를 알아야
 * 「24시간 안에 끝났나」를 잴 수 있다. `status=2`만으로는 그 시각이 없다.
 *
 * 이미 `status=2`인 계정은 시작 시각을 모르므로 `created_at`으로 채운다 — 실제보다 **이르게**
 * 잡혀 곧바로 마감 초과로 보인다. 늦게 잡혀 경보가 안 울리는 쪽보다 낫다(fail closed).
 */
export const m030AccountDeletingSince: Migration = {
  version: 30,
  name: "account deleting_since",
  statements: [
    "ALTER TABLE accounts ADD COLUMN deleting_since BIGINT",
    "UPDATE accounts SET deleting_since = created_at WHERE status = 2 AND deleting_since IS NULL",
    "CREATE INDEX IF NOT EXISTS ix_accounts_status ON accounts(status, deleting_since)",
  ],
};
