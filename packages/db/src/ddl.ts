/**
 * 방언 공통 DDL 판별 — **드라이버들이 같은 기준으로 봐야 하는 것**만 둔다.
 *
 * 각 방언의 "이미 존재함" 오류를 흡수하려면 먼저 "이 문장이 흡수 대상인가"를 판정해야 하는데,
 * 그 정규식이 드라이버마다 복제되면 한쪽만 고쳐져 조용히 갈라진다(이 저장소가 반복해 겪은 종류).
 * 판정은 여기, 흡수는 방언을 아는 각 드라이버가 소유한다.
 */

/**
 * `ALTER TABLE … ADD COLUMN …` 인가.
 *
 * 왜 필요한가: 컬럼 추가는 SQLite·MySQL에 `IF NOT EXISTS`가 없다(PostgreSQL만 지원).
 * 마이그레이션 러너는 문장 단위 멱등을 전제로 실패 지점부터 재개하는데(D1은 트랜잭셔널 DDL이
 * 없어 특히), 재개할 때 이미 추가된 컬럼에서 멈춰 버리면 사람이 손으로 문장을 건너뛰어야 한다.
 * `CREATE INDEX IF NOT EXISTS`를 MySQL에서 흡수하던 것(idempotentIndex)과 같은 장치를 넓힌 것이다.
 */
export function isAddColumn(sql: string): boolean {
  return /^\s*ALTER\s+TABLE\s+\S+\s+ADD\s+COLUMN\s+/i.test(sql);
}
