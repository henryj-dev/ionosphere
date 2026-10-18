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
   * ★두 문장을 **따로 커밋한다**(SCHEMA의 "한 논리 연산 = 한 배치"의 예외). 한 트랜잭션으로 묶으면 MySQL에서
   * 같은 새 버킷을 동시에 세는 서버들이 INSERT의 공유 잠금과 UPDATE의 배타 잠금을 서로 기다려 교착에 빠진다
   * (2026-10-18 로컬 MySQL 8에서 20개 동시 실패로 재현, ER_LOCK_DEADLOCK). 나눠도 잃는 것이 없다:
   * 미리 만든 빈 행(0회)은 판정에 쓰이지 않고, 더하기는 UPDATE 한 문장이 자기 행을 읽어 더하므로 원자적이다.
   * 빈 행의 시각을 0이 아니라 `now`로 넣는 이유: 두 문장 사이에 `sweep`이 돌면 시각 0인 행은 지워져 이번 실패를 잃는다.
   * `now`면 sweep 대상이 아니고, CASE도 초기화로 보지 않아 0 + 1 = 1이 된다.
   */
  async recordFailure(bucket: string, now: number, resetBefore: number): Promise<void> {
    await this.db.batch([{ sql: this.db.insertIgnore(TABLE, ["bucket", "fails", "last_fail_at"]), params: [bucket, 0, now] }]);
    await this.db.batch([
      {
        sql: `UPDATE ${TABLE} SET fails = CASE WHEN last_fail_at < ? THEN 1 ELSE fails + 1 END, last_fail_at = ? WHERE bucket = ?`,
        params: [resetBefore, now, bucket],
      },
    ]);
  }

  async clear(buckets: readonly string[]): Promise<void> {
    if (buckets.length === 0) return;
    await this.db.batch([{ sql: `DELETE FROM ${TABLE} WHERE bucket IN (${buckets.map(() => "?").join(", ")})`, params: buckets }]);
  }

  async sweep(before: number): Promise<void> {
    await this.db.batch([{ sql: `DELETE FROM ${TABLE} WHERE last_fail_at < ?`, params: [before] }]);
  }
}
