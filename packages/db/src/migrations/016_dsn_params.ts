import type { Migration } from "../migrate.ts";

/**
 * 016 — DSN 확장 파라미터(RFC 3461)를 큐에 싣는다.
 *
 * ★`NOTIFY`가 **가장 중요하다.** 발신자가 `NOTIFY=NEVER`라고 말했으면 실패해도 바운스를
 * 보내면 안 된다 — 그걸 무시하면 메일링리스트가 자기 실패 알림을 되받아 폭풍이 된다
 * (리스트 소프트웨어가 `NOTIFY=NEVER`를 쓰는 이유가 정확히 그것이다). 지금까지는 파라미터를
 * **문법으로만 받고 버려서**, 우리는 사실상 그 요청을 무시하고 있었다.
 *
 * 컬럼 선택:
 *  · `dsn_notify` — 쉼표 목록(`NEVER` 또는 `SUCCESS,FAILURE,DELAY`) 원문. 정수로 인코딩하지
 *    않는 이유: 조합이라 비트가 필요한데, 이 값을 쓰는 곳이 한 군데뿐이라 인코딩 소유
 *    규약(`columns.ts`)을 늘릴 만큼의 값이 없다. 파싱은 워커가 한 번 한다.
 *  · `dsn_orcpt` — 원 수신자 주소(RFC 3461 §4.2). 메일링리스트가 여러 번 재작성해도
 *    **발신자가 처음 쓴 주소**를 바운스에 실어야 사람이 알아본다.
 *  · `dsn_envid` — 발신자가 붙인 봉투 id(§4.3). 바운스를 자기 발송 기록과 맞추는 열쇠다.
 *  · `dsn_ret` — `FULL`이면 원문 전체, `HDRS`면 헤더만 바운스에 싣는다(§4.3).
 *
 * 전부 NULL 허용이다 — 파라미터를 안 쓴 발송이 대다수이고, NULL이 곧 기본 동작이다.
 */
export const m016DsnParams: Migration = {
  version: 16,
  name: "dsn_params",
  statements: [
    `ALTER TABLE mta_queue ADD COLUMN dsn_notify VARCHAR(64)`,
    `ALTER TABLE mta_queue ADD COLUMN dsn_orcpt VARCHAR(320)`,
    `ALTER TABLE mta_queue ADD COLUMN dsn_envid VARCHAR(128)`,
    `ALTER TABLE mta_queue ADD COLUMN dsn_ret VARCHAR(8)`,
  ],
};
