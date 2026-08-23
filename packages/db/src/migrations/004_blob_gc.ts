import type { Migration } from "../migrate.ts";

/**
 * 004 — 블롭 GC 준비: 큐 블롭 원장 백필 + GC 스캔 인덱스.
 *
 * 왜 백필이 필요한가: 지금까지 `blobs`/`blob_refs` 행을 만든 곳은 `appendMessage` 하나뿐이었다.
 * 포워딩·SRS 바운스·SMTP 제출·JMAP 제출이 만든 아웃바운드 블롭은 **파일만 있고 DB에 흔적이
 * 없는 상태**로 쌓였다. 이 상태로 GC를 켜면 두 갈래 다 나쁘다 —
 *   · 원장 기반 GC: 안 보이니 영원히 안 지워진다(누수 그대로).
 *   · 파일 스캔 기반 GC: 지금 발송 대기 중인 본문을 지운다(메일 유실).
 * 그래서 기존 큐 행에 대해 원장(blobs) + 참조(blob_refs, ref_kind=1 queue)를 만들어 준다.
 * 이후로는 enqueueMessage가 적재와 같은 배치에서 직접 만든다.
 *
 * size_bytes를 0으로 두는 이유: 마이그레이션은 파일시스템을 볼 수 없어 실제 크기를 알 수 없다.
 * 이 컬럼은 정보성이며 과금(accounts.used_bytes)·쿼터와 무관해서 0으로 둬도 회계가 틀어지지 않는다.
 * 새로 적재되는 행부터는 정확한 값이 들어간다.
 *
 * 주의: `blobs`에 이미 행이 있는 블롭(= 메시지 블롭을 재사용한 JMAP 제출)은 INSERT가 PK 충돌로
 * 무시되어야 하므로 `WHERE NOT EXISTS`로 걸러 넣는다(방언별 INSERT IGNORE 문법 차이 회피).
 */
export const m004BlobGc: Migration = {
  version: 4,
  name: "blob_gc",
  statements: [
    // 기존 큐 블롭의 원장 행 — 상태는 live(0), 세대는 0(지금까지 라이터가 항상 0에 썼다)
    `INSERT INTO blobs (id, size_bytes, backend, status, generation, created_at)
       SELECT q.blob_id, 0, 0, 0, 0, MIN(q.created_at)
         FROM mta_queue q
        WHERE NOT EXISTS (SELECT 1 FROM blobs b WHERE b.id = q.blob_id)
        GROUP BY q.blob_id`,
    // 큐 참조 — account_id는 NOT NULL이라 시스템 발송(NULL)은 빈 문자열 센티널로(columns.ts SYSTEM_ACCOUNT_REF)
    `INSERT INTO blob_refs (blob_id, account_id, ref_kind, ref_id, created_at)
       SELECT q.blob_id, COALESCE(q.account_id, ''), 1, q.id, q.created_at
         FROM mta_queue q
        WHERE NOT EXISTS (
                SELECT 1 FROM blob_refs r
                 WHERE r.blob_id = q.blob_id AND r.ref_kind = 1 AND r.ref_id = q.id
              )`,
    // GC 1단계는 "참조 0인 live 블롭", 2단계는 "유예 지난 doomed 블롭"을 훑는다 — 둘 다 status 선행
    `CREATE INDEX IF NOT EXISTS ix_blobs_status ON blobs(status, doomed_at)`,
  ],
};
