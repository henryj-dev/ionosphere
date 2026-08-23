/**
 * 스토어 내부 컬럼 인코딩과 공용 헬퍼 — **store 패키지 안에서만** 쓰인다.
 *
 * 패키지 경계를 넘는 인코딩(message_addresses.kind, mta_queue.status)은 스키마를 소유한
 * @ionosphere/db의 columns.ts가 갖는다. 여기 있는 값들은 store 밖에서 참조되지 않으므로
 * store-local로 둔다 — 소유자를 한 곳으로 모으되 불필요하게 공개하지는 않는다.
 */

export const ENTITY = { Email: 0, Mailbox: 1, Thread: 2, EmailSubmission: 3, SieveScript: 4 } as const;
export const CHANGE_KIND = { created: 0, updated: 1, destroyed: 2 } as const;
// REF_KIND(blob_refs.ref_kind)는 store 밖(@ionosphere/mta 큐 적재, JMAP 업로드)에서도 참조를
// 만들어야 해서 스키마 소유 패키지인 @ionosphere/db로 올렸다. 여기서 다시 export하지 않는다 —
// 소유자는 하나여야 한다.
export const SEARCH_FIELD = { subject: 0, body: 1, from: 2, to: 3 } as const;
export const CHANGE_LOG_SQL =
  "INSERT INTO change_log (account_id, modseq, entity, object_id, kind, created_at) VALUES (?, ?, ?, ?, ?, ?)";

/** 행 목록을 키별로 묶는다(다중 조회 결과 조립용). */
export function groupBy<T, V>(rows: readonly Record<string, unknown>[], key: (r: Record<string, unknown>) => string, value: (r: Record<string, unknown>) => V): Map<string, V[]> {
  const out = new Map<string, V[]>();
  for (const r of rows) {
    const k = key(r);
    const arr = out.get(k);
    if (arr) arr.push(value(r));
    else out.set(k, [value(r)]);
  }
  return out;
}
