/**
 * 인증 실패 카운터의 DB 구현 — `core`의 `SharedThrottleStore` 계약 (마이그레이션 028).
 *
 * 서버 여러 대가 같은 테이블을 보므로 한도가 인스턴스 수만큼 곱해지지 않는다(2026-10-18 회원 공통 수치 결정 3).
 * 규칙(몇 회부터 얼마나 막는가)은 core가 정한다. 여기는 원자적으로 세고 읽기만 한다.
 */
import type { SharedThrottleStore, ThrottleCounter } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";
import { queryInChunks } from "./chunk.ts";

const TABLE = "auth_failures";
/** 한 번에 읽는 버킷 수 상한 — 호출자는 축 두 개(IP·계정)만 넘긴다. 그 이상은 계약 위반이다. */
const MAX_READ_BUCKETS = 8;

export class DbAuthFailureStore implements SharedThrottleStore {
  private readonly db: DbDriver;

  constructor(db: DbDriver) {
    this.db = db;
  }

  async read(buckets: readonly string[]): Promise<Map<string, ThrottleCounter>> {
    const out = new Map<string, ThrottleCounter>();
    if (buckets.length === 0) return out;
    if (buckets.length > MAX_READ_BUCKETS) throw new Error(`auth_failures 읽기 버킷이 너무 많다: ${buckets.length}`);
    const rows = await queryInChunks(this.db, buckets, (ph) => `SELECT bucket, fails, last_fail_at FROM ${TABLE} WHERE bucket IN (${ph})`);
    for (const r of rows) out.set(String(r.bucket), { fails: Number(r.fails), lastFailAt: Number(r.last_fail_at) });
    return out;
  }

  /**
   * 행이 없으면 만들고, 있으면 하나 더한다.
   *
   * 순서: UPDATE 먼저 → 0행이면(버킷이 처음이다) INSERT IGNORE로 1회짜리 행 → 그것도 0행이면(동시에 다른 서버가
   * 만들었다) UPDATE를 한 번 더. 흔한 경우(행이 이미 있다)가 문장 하나로 끝난다.
   *
   * ★문장마다 **따로 커밋한다**(SCHEMA의 "한 논리 연산 = 한 배치"의 예외). 한 트랜잭션으로 묶으면 MySQL에서
   * 같은 새 버킷을 동시에 세는 서버들이 INSERT의 공유 잠금과 UPDATE의 배타 잠금을 서로 기다려 교착에 빠진다
   * (2026-10-18 로컬 MySQL 8에서 20개 동시 실패로 재현, ER_LOCK_DEADLOCK). 나눠도 잃는 것이 없다:
   * UPDATE는 자기 행을 읽어 더하므로 원자적이고, INSERT IGNORE가 진 쪽은 마지막 UPDATE로 이긴 행에 더한다.
   * 초기화 판정은 `<=`다 — core `blockedUntil`이 "마지막 실패 뒤 정확히 초기화 시간"을 이미 풀린 것으로 보는 것과 맞춘다.
   */
  async recordFailure(bucket: string, now: number, resetBefore: number): Promise<void> {
    const update = {
      sql: `UPDATE ${TABLE} SET fails = CASE WHEN last_fail_at <= ? THEN 1 ELSE fails + 1 END, last_fail_at = ? WHERE bucket = ?`,
      params: [resetBefore, now, bucket],
    };
    if ((await this.db.batch([update]))[0]!.changes > 0) return;
    const inserted = await this.db.batch([{ sql: this.db.insertIgnore(TABLE, ["bucket", "fails", "last_fail_at"]), params: [bucket, 1, now] }]);
    if (inserted[0]!.changes > 0) return;
    await this.db.batch([update]);
  }

  async clear(buckets: readonly string[]): Promise<void> {
    if (buckets.length === 0) return;
    await this.db.batch([{ sql: `DELETE FROM ${TABLE} WHERE bucket IN (${buckets.map(() => "?").join(", ")})`, params: buckets }]);
  }

  async sweep(before: number): Promise<void> {
    await this.db.batch([{ sql: `DELETE FROM ${TABLE} WHERE last_fail_at < ?`, params: [before] }]);
  }
}
