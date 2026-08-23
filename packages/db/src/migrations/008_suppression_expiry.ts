import type { Migration } from "../migrate.ts";

/**
 * 008 — suppressions에 만료 시각 추가.
 *
 * 왜 필요한가: `reason=exhausted(1)`은 "상대가 영구 거절했다"가 아니라 **"우리가 며칠간 못
 * 보내서 포기했다"**이다. 우리 쪽 DNS·네트워크 장애로도 발생하는데, 지금은 hardBounce와
 * 똑같이 **영구 차단**으로 남는다. 장애가 복구돼도 그때 큐에 있던 정상 수신자들이 영영
 * 막힌 채로 있고, 운영자가 목록을 보고 하나씩 지워 주지 않으면 풀리지 않는다.
 *
 * NULL = 만료 없음(hardBounce). 값이 있으면 그 시각 이후로는 차단이 아니다.
 * 행을 지우지 않고 남기는 이유: **왜 한 번 막혔는지가 운영 정보**다. 자동으로 지워 버리면
 * 반복해서 exhausted에 걸리는 주소를 알아볼 수 없다.
 *
 * ── 왜 rebuild가 아니라 ALTER인가 ──
 * 003·006은 재빌드 패턴(CREATE 신규 → INSERT SELECT → DROP → RENAME)을 썼지만, 그건 컬럼을
 * **지우거나 바꿔야** 했기 때문이다(SQLite에 이식 가능한 DROP COLUMN이 없다). 여기는 추가뿐이라
 * 그 이유가 해당하지 않는다. 실패 모드가 다르다는 것도 실측으로 확인했다
 * (docs/DECISIONS-pending.md §1):
 *
 *   ALTER  최악 = "마이그레이션이 멈추고 사람이 문장 하나 건너뛴다" (데이터는 그대로)
 *   rebuild 최악 = DROP↔RENAME 사이에서 죽으면 **차단 목록 소실** (백업에서 복원)
 *
 * 재개 안전성은 드라이버가 준다: PostgreSQL은 ADD COLUMN IF NOT EXISTS로 바꿔 실행하고,
 * SQLite·MySQL·D1은 "이미 있음" 오류를 멱등 no-op으로 흡수한다(packages/db/src/ddl.ts).
 * MySQL이 CREATE INDEX IF NOT EXISTS를 흡수하던 장치(idempotentIndex)를 넓힌 것이라
 * 새 개념을 만들지 않았다.
 */
export const m008SuppressionExpiry: Migration = {
  version: 8,
  name: "suppression-expiry",
  statements: [
    `ALTER TABLE suppressions ADD COLUMN expires_at BIGINT`,
    // 만료분 정리(운영 스윕)용 — 없으면 전수 스캔이다. 기존 PK는 (tenant_id, email)이라 못 쓴다.
    `CREATE INDEX IF NOT EXISTS ix_suppressions_expires ON suppressions(expires_at)`,
  ],
};
