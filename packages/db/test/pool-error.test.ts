/**
 * 풀 오류로 프로세스가 죽지 않아야 한다.
 *
 * 과거 결함: node-postgres는 **유휴 클라이언트**에서 오류가 나면 Pool에 'error'를 emit하는데,
 * 리스너가 없으면 unhandled error가 되어 **프로세스가 죽는다**. DB 재시작·네트워크 순단 한 번에
 * 올인원 서버(SMTP·IMAP·POP3·JMAP 전부)가 통째로 내려간다.
 *
 * 실제 DB 서버 없이 검증 가능하다 — pg/mysql2 풀은 생성 시점에 연결하지 않으므로
 * 풀 객체를 꺼내 직접 'error'를 발화시켜 보면 된다. 리스너가 없으면 EventEmitter가 throw한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import type { EventEmitter } from "node:events";
import { openMysql, openPostgres } from "@ionosphere/db";

/** 드라이버 내부의 풀(EventEmitter) — TS `private`는 런타임 은닉이 아니라 접근 가능하다. */
function poolOf(driver: unknown): EventEmitter {
  return (driver as { pool: EventEmitter }).pool;
}

describe("커넥션 풀 오류 처리", () => {
  test("postgres: 유휴 클라이언트 오류가 unhandled로 새지 않는다", async () => {
    const db = await openPostgres("postgres://user:pw@127.0.0.1:1/nonexistent");
    try {
      const pool = poolOf(db);
      expect(pool.listenerCount("error")).toBeGreaterThan(0);
      // 리스너가 없으면 이 emit 자체가 throw한다(EventEmitter의 'error' 특례).
      expect(() => pool.emit("error", new Error("simulated idle client error"))).not.toThrow();
    } finally {
      await db.close();
    }
  });

  test("mysql: 풀 오류가 unhandled로 새지 않는다", async () => {
    const db = await openMysql("mysql://user:pw@127.0.0.1:1/nonexistent");
    try {
      const pool = poolOf(db);
      expect(pool.listenerCount("error")).toBeGreaterThan(0);
      expect(() => pool.emit("error", new Error("simulated pool error"))).not.toThrow();
    } finally {
      await db.close();
    }
  });
});
