/**
 * 보존창 스윕 — 무한히 자라던 테이블들을 주기적으로 잘라낸다.
 *
 * ★왜 필요한가(2026-08-23 검수): 주석이 "주기 스위퍼가 수렴시킨다"고 약속한 대상들이
 * **하나도 구현돼 있지 않았다.** 전부 append-only로 자랐다:
 *
 *   change_log   무한 증가. `accounts.changelog_floor`는 계정 생성 시 0으로 쓰고
 *                **한 번도 전진하지 않았다**(그 필드를 읽는 쪽은 있는데 쓰는 쪽이 없었다)
 *   expunged     메일함이 통째로 리핑될 때만 삭제
 *   thread_refs  `expungeAttempt` 주석이 "자체 보존창 GC(§5-3, 기본 180일)로 수거"라
 *                적어 뒀는데 그 GC가 없었다
 *   mta_queue    done/bounced 행이 영구 잔존
 *
 * ★이 파일이 다루는 것과 다루지 않는 것: 여기 있는 것은 **시간이 지나면 쓸모가 없어지는
 * 기록**이다. 메시지 본문·색인처럼 "지워야 하는 것"은 파기 경로가 즉시 지운다(§7-4) —
 * 그건 보존 정책이 아니라 삭제 계약이라 지연 처리 대상이 아니다.
 */
import type { DbDriver, Statement } from "@ionosphere/db";
import { MTA_QUEUE_STATUS } from "@ionosphere/db";

export interface RetentionOptions {
  /**
   * `change_log` 보존 기간.
   *
   * 이 값이 곧 **클라이언트가 오프라인으로 버틸 수 있는 시간**이다. 보존창 밖의 state를 들고
   * 돌아온 클라이언트는 `cannotCalculate`를 받고 전체 재동기화를 한다(그 갈래는 이미
   * 구현돼 있다 — `jmap-store.ts`가 `changelog_floor`를 읽는다). 30일이면 휴가를 다녀와도
   * 델타 동기화가 유지되고, 그보다 긴 부재는 전체 재동기화가 합리적이다.
   */
  changeLogRetentionMs?: number;
  /**
   * `thread_refs` 보존 기간 — 기본 180일.
   *
   * `expungeAttempt`의 §7-4 편차 주석이 약속한 값을 그대로 쓴다. 스레딩은 "이 참조를 가진
   * 옛 메일이 있었나"를 보는 것이라 오래될수록 값이 떨어지고, 6개월 지난 스레드에 답장이
   * 붙는 일은 드물다.
   */
  threadRefRetentionMs?: number;
  /**
   * 종료된 `mta_queue` 행(done·bounced) 보존 기간.
   *
   * ⚠ **가장 긴 레이트리밋 윈도우보다 길어야 한다.** 이 테이블이 곧 발송 카운터라
   * (`enqueue.ts`가 `COUNT(*) … created_at > ?`로 센다) 보존창이 짧으면 카운트가
   * 과소평가돼 한도가 뚫린다. `enqueue.ts:305`가 이 트레이드오프를 이미 주석으로 적어 뒀다.
   * 기본 7일은 perDay(24h)와 abuse 창(24h)보다 충분히 길고, 운영자가 최근 발송 이력을
   * 조회하기에도 넉넉하다.
   */
  queueRetentionMs?: number;
  /** 테스트 결정성용 시각 주입. */
  now?: number;
}

export interface RetentionResult {
  changeLog: number;
  /** 만료된 vacation 중복 억제 기록. */
  vacationSent: number;
  threadRefs: number;
  queue: number;
  /** `changelog_floor`를 전진시킨 계정 수. */
  floorsAdvanced: number;
}

const DAY = 24 * 60 * 60 * 1000;
const DEFAULT_CHANGE_LOG_MS = 30 * DAY;
const DEFAULT_THREAD_REF_MS = 180 * DAY;
const DEFAULT_QUEUE_MS = 7 * DAY;

/**
 * 한 사이클. 실패는 던진다 — 호출자(워커)가 로그로 남기고 다음 주기에 다시 시도한다.
 *
 * ⚠ **`expunged`는 일부러 손대지 않는다.** QRESYNC(RFC 7162)의 `VANISHED`가 그 테이블에서
 * 나오는데, IMAP에는 `changelog_floor` 같은 **하한을 알릴 장치가 없다**. 지우면 오래
 * 떠나 있던 클라이언트가 "삭제된 적 없다"는 답을 받고 유령 메시지를 영영 들고 있게 된다 —
 * 조용히 틀린 답이라 사용자가 알아차릴 방법도 없다. 디스크를 아끼려고 클라이언트 데이터를
 * 어긋나게 둘 수는 없다. 안전하게 자르려면 메일함별 "이 modseq 아래는 답할 수 없다" 표시가
 * 스키마에 필요하고(그리고 그 아래를 요청한 세션은 UIDVALIDITY를 올려 전체 재동기화로
 * 밀어야 한다), 그건 별도 작업이다.
 *
 * ⚠ 행 수 상한은 두지 않았다 — `DELETE … LIMIT`은 방언마다 다르고(SQLite는 빌드 옵션에
 * 달렸다) 이 저장소는 다이얼렉트 분기를 봉인한다. 대신 컷오프가 자연히 유계로 만든다:
 * 첫 스윕만 누적분을 지우고 이후에는 한 주기 분량만 남는다. **이미 커진 DB의 첫 스윕은
 * 길 수 있으므로** 도입 시에는 한산한 시간에 한 번 돌리고 켜는 편이 낫다.
 *
 * ★순서가 중요하다: `change_log`를 지우기 **전에** `changelog_floor`를 올린다. 반대면
 * "행은 없는데 floor는 낮은" 창이 생기고, 그 사이 `/changes`가 **조용히 불완전한 델타**를
 * 돌려준다 — 클라이언트는 그것이 전부인 줄 안다. floor를 먼저 올리면 최악이
 * `cannotCalculate`(전체 재동기화)라 안전한 쪽으로 틀린다.
 */
export async function runRetention(db: DbDriver, opts: RetentionOptions = {}): Promise<RetentionResult> {
  const now = opts.now ?? Date.now();
  const changeLogCutoff = now - (opts.changeLogRetentionMs ?? DEFAULT_CHANGE_LOG_MS);
  const threadRefCutoff = now - (opts.threadRefRetentionMs ?? DEFAULT_THREAD_REF_MS);
  const queueCutoff = now - (opts.queueRetentionMs ?? DEFAULT_QUEUE_MS);

  /**
   * 1) 계정마다 "보존창 밖 최대 modseq"를 구해 floor를 그 값으로 올린다.
   *    그 modseq 이하의 change_log는 이제 없는 것으로 계약된다.
   */
  const { rows: floorRows } = await db.query({
    sql: `SELECT account_id, MAX(modseq) AS max_modseq
            FROM change_log WHERE created_at < ? GROUP BY account_id`,
    params: [changeLogCutoff],
  });
  const floorStmts: Statement[] = floorRows.map((r) => ({
    // 단조 증가 가드 — 동시에 다른 스윕이 더 올려 뒀다면 되돌리지 않는다.
    sql: "UPDATE accounts SET changelog_floor = ? WHERE id = ? AND changelog_floor < ?",
    params: [Number(r.max_modseq), String(r.account_id), Number(r.max_modseq)],
  }));
  if (floorStmts.length > 0) await db.batch(floorStmts);

  /** 2) floor를 올린 뒤에야 행을 지운다(위 순서 주석). */
  const deletes: Statement[] = [
    { sql: `DELETE FROM change_log WHERE created_at < ?`, params: [changeLogCutoff] },
    { sql: `DELETE FROM thread_refs WHERE created_at < ?`, params: [threadRefCutoff] },
    {
      // 재시도 중인 행은 절대 건드리지 않는다 — 종료된 것만 정리 대상이다.
      sql: `DELETE FROM mta_queue WHERE status IN (${MTA_QUEUE_STATUS.done}, ${MTA_QUEUE_STATUS.bounced}) AND created_at < ?`,
      params: [queueCutoff],
    },
    // vacation 억제 기록은 **자체 만료 시각**을 들고 있다(`:days`가 스크립트마다 다르다).
    { sql: `DELETE FROM vacation_sent WHERE expires_at <= ?`, params: [now] },
  ];
  const res = await db.batch(deletes);

  return {
    floorsAdvanced: floorStmts.length,
    changeLog: res[0]?.changes ?? 0,
    threadRefs: res[1]?.changes ?? 0,
    queue: res[2]?.changes ?? 0,
    vacationSent: res[3]?.changes ?? 0,
  };
}
