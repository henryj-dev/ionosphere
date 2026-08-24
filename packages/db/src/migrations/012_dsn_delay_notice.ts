import type { Migration } from "../migrate.ts";

/**
 * 012 — 지연 통보를 보냈는지 기록하는 `mta_queue.delay_notified_at`.
 *
 * RFC 5321 §4.5.4.1은 메시지를 몇 시간 안에 배달하지 못하면 **발신자에게 알리라**고 한다
 * (관행은 4시간). 그러려면 "이미 알렸는가"를 알아야 하고, 그건 추론할 수 없는 사실이다.
 *
 * ★왜 `attempts`로 대신하지 않는가: 백오프에 ±20% 지터가 있어(`worker.ts backoffMs`)
 * 시도 횟수와 경과 시간이 일대일로 대응하지 않는다. 시도 N회를 "4시간 지남"으로 읽으면
 * 어떤 메시지는 두 번 알리고 어떤 메시지는 못 알린다 — **중복 통보가 특히 나쁘다**.
 * 사용자는 아직 배달될 수 있는 메일에 대해 실패처럼 보이는 알림을 반복해서 받는다.
 *
 * NULL = 아직 안 보냄. 컬럼 추가뿐이라 기존 행은 자연히 NULL이 되고, 그 값이 곧
 * "예전 큐 행에는 통보한 적 없다"라는 사실과 일치한다.
 */
export const m012DsnDelayNotice: Migration = {
  version: 12,
  name: "dsn-delay-notice",
  statements: [`ALTER TABLE mta_queue ADD COLUMN delay_notified_at BIGINT`],
};
