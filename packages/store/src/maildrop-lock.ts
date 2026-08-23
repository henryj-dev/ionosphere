/**
 * DB 기반 maildrop 배타 잠금 — MRA를 2대 이상 띄울 때 RFC 1939 §3의 배타 접근을 지키는 구현.
 * 계약은 `@ionosphere/core`의 MaildropLock, 테이블은 마이그레이션 005(maildrop_locks).
 *
 * ── 원자성 근거 (greylist.ts·migrate.ts와 같은 규율) ──
 * 획득은 **두 갈래 모두 단일 문장 check-and-set**이라 프로세스 간에도 원자적이다.
 *  ① 락 행이 없으면 INSERT(승인 신호 = changes 1). PK 충돌은 네 방언 모두에서 원자적이므로,
 *     동시에 들어온 두 MRA 중 정확히 하나만 1을 받는다. 방언 분기를 피하려고 예외 대신
 *     insertIgnore(SCHEMA.md §1-5의 유일한 승인 탈출구)를 쓴다.
 *  ② 행이 있으면 **만료된 경우에만** 뺏는 가드된 UPDATE(`WHERE expires_at <= ?`).
 *     조건 검사와 쓰기가 한 문장 안에 있으므로 "만료를 읽고 → 뺏는" 사이에 끼어들 틈이 없다.
 *     SELECT로 만료를 먼저 확인하는 구현이었다면 두 MRA가 같은 만료 락을 동시에 뺏는다.
 * 해제·갱신은 `AND owner = ?` 가드가 붙은 단일 문장이라, 이미 뺏긴 락에는 0행이 되어 무해하다.
 *
 * ── TTL을 왜 유휴 타임아웃의 2배로 잡는가 ──
 * TTL의 목적은 오직 "크래시한 MRA가 계정을 영원히 잠그는 것"을 막는 것이다. 반대 방향의 실수,
 * 즉 **살아 있는 세션의 락을 뺏는 것**은 배타성 자체가 깨지는 일이라 훨씬 나쁘다(A가 지운
 * 메시지를 B가 RETR → "message vanished"). POP3 어댑터는 유휴 POP3_IDLE_TIMEOUT_MS(10분)에
 * 연결을 끊으므로 살아 있는 세션은 10분마다 최소 한 번은 활동한다. TTL을 그 2배로 두면
 * 갱신이 한 번 실패하거나(일시적 DB 오류) 긴 RETR이 끼어도 여유가 남는다.
 * 대가는 크래시 후 최대 TTL 동안 그 계정의 POP3 로그인이 [IN-USE]를 받는 것 — 메일 유실보다
 * 압도적으로 가볍고, 클라이언트는 다음 폴링에서 정상 동작한다.
 *
 * ── 갱신(refresh)이 필요한 이유 ──
 * 세션은 유휴가 아니어도 오래 살 수 있다(느린 회선에서 큰 메일 RETR, STAT/LIST/NOOP 반복).
 * 특히 STAT/LIST/UIDL은 엔진이 세션 캐시로 답하므로 **백엔드를 전혀 호출하지 않는다** —
 * "백엔드 호출 때마다 연장"만으로는 TTL을 넘길 수 있다. 그래서 호출자가 refreshIntervalMs
 * 주기로 refresh를 돌려 리스를 살려 두고, false(=이미 뺏김)를 받으면 사실을 알 수 있게 한다.
 */
import { POP3_IDLE_TIMEOUT_MS, type MaildropLock } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";

const LOCK_TABLE = "maildrop_locks";
const LOCK_COLUMNS = ["account_id", "owner", "expires_at"] as const;

/** 크래시 복구용 TTL — 유휴 타임아웃의 2배(위 주석의 비대칭 위험 논거). */
const DEFAULT_TTL_MS = POP3_IDLE_TIMEOUT_MS * 2;

/** 갱신 주기 = TTL/3 — 연장이 연속 2회 실패해도 만료 전에 한 번 더 기회가 있다. */
const REFRESH_DIVISOR = 3;

export interface DbMaildropLockOptions {
  /** 리스 수명(ms). 기본 POP3_IDLE_TIMEOUT_MS × 2. 유휴 타임아웃보다 짧게 주지 말 것. */
  ttlMs?: number;
}

export class DbMaildropLock implements MaildropLock {
  private readonly db: DbDriver;
  private readonly ttlMs: number;
  readonly refreshIntervalMs: number;

  constructor(db: DbDriver, opts?: DbMaildropLockOptions) {
    this.db = db;
    this.ttlMs = opts?.ttlMs ?? DEFAULT_TTL_MS;
    this.refreshIntervalMs = Math.max(1, Math.floor(this.ttlMs / REFRESH_DIVISOR));
  }

  async acquire(accountId: string, owner: string, now: number = Date.now()): Promise<boolean> {
    const expiresAt = now + this.ttlMs;

    // ① 빈 자리 잡기 — PK 충돌이면 changes 0(패배). 예외 대신 insertIgnore를 쓰는 건
    //    방언 분기를 봉인하기 위함이다.
    const [inserted] = await this.db.batch([
      { sql: this.db.insertIgnore(LOCK_TABLE, LOCK_COLUMNS), params: [accountId, owner, expiresAt] },
    ]);
    if (inserted?.changes === 1) return true;

    // ② 이미 누가 잡고 있다 — 만료된 락만 탈취. 살아 있는 락은 여기서 0행이 되어 실패한다.
    const [stolen] = await this.db.batch([
      {
        sql: `UPDATE ${LOCK_TABLE} SET owner = ?, expires_at = ? WHERE account_id = ? AND expires_at <= ?`,
        params: [owner, expiresAt, accountId, now],
      },
    ]);
    return (stolen?.changes ?? 0) === 1;
  }

  async refresh(accountId: string, owner: string, now: number = Date.now()): Promise<boolean> {
    // owner 가드가 곧 "아직 내 락인가"의 판정이다 — 뺏겼다면 owner가 바뀌어 0행이 된다.
    // 만료 여부는 굳이 보지 않는다: 아직 아무도 안 뺏었고 이 세션이 살아 있다면 연장이 맞다.
    const [res] = await this.db.batch([
      {
        sql: `UPDATE ${LOCK_TABLE} SET expires_at = ? WHERE account_id = ? AND owner = ?`,
        params: [now + this.ttlMs, accountId, owner],
      },
    ]);
    return (res?.changes ?? 0) === 1;
  }

  /**
   * 만료된 지 오래된 락 행을 지운다 — 크래시·계정 폐기로 남은 행의 누수 방지.
   *
   * 왜 필요한가: `acquire`가 만료 락을 **덮어쓰므로** 다시 로그인하는 계정의 행은 누수가 아니다.
   * 문제는 **다시 로그인하지 않는 계정**(폐기·이전)의 행으로, 아무도 건드리지 않아 영원히 남는다.
   * 계정당 1행이라 폭주하진 않지만, 정리 주체가 없는 테이블은 시간이 지나면 아무도 그 내용을
   * 신뢰하지 않게 된다.
   *
   * `graceMs`만큼 더 지난 것만 지운다 — 방금 만료된 락은 곧 재사용될 가능성이 높고,
   * 지워도 `acquire`의 ①번 갈래가 다시 만들 뿐이라 서두를 이유가 없다.
   * 반환값은 지운 행 수(관측용).
   */
  async sweepExpired(now: number = Date.now(), graceMs: number = this.ttlMs): Promise<number> {
    const [res] = await this.db.batch([
      { sql: `DELETE FROM ${LOCK_TABLE} WHERE expires_at <= ?`, params: [now - graceMs] },
    ]);
    return res?.changes ?? 0;
  }

  async release(accountId: string, owner: string): Promise<void> {
    // 자기 락만 삭제 — 락을 못 잡았거나 이미 뺏긴 세션이 남의 락을 푸는 사고를 막는다.
    await this.db.batch([
      { sql: `DELETE FROM ${LOCK_TABLE} WHERE account_id = ? AND owner = ?`, params: [accountId, owner] },
    ]);
  }
}
