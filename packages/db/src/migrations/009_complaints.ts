import type { Migration } from "../migrate.ts";

/**
 * 009 — mta_queue에 신고 시각 추가(FBL/ARF 소비).
 *
 * 왜 필요한가: PLAN.md §8 통제 ④는 "**신고율** / 바운스율 임계 → 자동 정지"인데, 코드에는
 * 바운스율뿐이었다(`mta/abuse.ts`). `docs/AUP.md`도 신고율을 "로드맵"으로 적어 두고 있었다.
 * 이용약관이 약속한 통제가 코드에 없으면 그 문서는 지킬 수 없는 것을 약속하는 셈이다.
 *
 * ── 왜 새 테이블이 아니라 컬럼인가 ──
 * 신고는 "이 발송이 신고당했다"는 **발송 한 건의 속성**이다. 별도 테이블로 빼면 발송률
 * 계산에서 매번 조인해야 하는데, `checkAccountAbuse`는 이미 `mta_queue`를 창(window)으로
 * 집계한다 — 같은 질의 한 줄에 얹는 것이 자연스럽고 빠르다.
 *
 * ── 왜 status 값을 늘리지 않는가 ──
 * `status`를 `complained`로 덮으면 **배달됐다는 사실이 사라진다**. 신고는 배달 이후에
 * 도착하므로 둘 다 참이어야 하고, 분모(발송 수)가 무너지면 신고율 자체가 틀린다.
 * 별도 컬럼이면 `status`는 그대로 두고 신고만 표시한다.
 *
 * ALTER를 쓰는 근거는 008과 같다(추가뿐이고, 실패 모드가 rebuild보다 안전하다 —
 * docs/DECISIONS-pending.md §1의 실측).
 */
export const m009Complaints: Migration = {
  version: 9,
  name: "complaints",
  statements: [
    `ALTER TABLE mta_queue ADD COLUMN complained_at BIGINT`,
    /**
     * 상관관계 키 — 발송 시 메시지에 실어 보내는 식별자. ARF 리포트가 원문을 동봉하므로
     * 그 헤더에서 이 값을 되찾아 어느 발송인지 짚는다.
     *
     * ★`verp_token`을 쓰지 않는 이유: 그건 봉투 재작성(VERP)이 붙어야 쓸 수 있는데
     * `enqueue.ts`가 그 작업을 의도적으로 미뤄 뒀다. 헤더 식별자는 봉투를 건드리지 않고
     * 지금 성립한다 — 없는 전제를 기다리지 않는다.
     */
    `CREATE INDEX IF NOT EXISTS ix_queue_complained ON mta_queue(account_id, complained_at)`,
  ],
};
