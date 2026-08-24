import type { Migration } from "../migrate.ts";

/**
 * 017 — 대외 리포트 집계 테이블 (DMARC 집계 리포트 RFC 7489 §7.2, TLS-RPT RFC 8460).
 *
 * ★두 리포트 모두 **받기만 하고 내지는 않던** 것이다. 그건 역싸방향 상호운용을 반쪽만
 * 하는 상태다 — 우리는 남의 리포트로 우리 정렬을 고치면서, 우리에게 보내는 쪽에는 같은
 * 근거를 주지 않는다. MTA-STS를 **강제하면서** TLS-RPT를 안 내는 것은 특히 어긋난다
 * (상대는 우리 쪽 강제로 실패하는데 그 사실을 알 방법이 없다).
 *
 * ## 왜 원본이 아니라 **집계 행**인가
 *
 * 리포트는 (기간, 소스 IP, 판정, 정렬)별 **개수**다. 메시지마다 한 행을 남기면 하루 수백만
 * 행이 되고 리포트를 만들 때 그걸 다시 그룹핑해야 한다. 처음부터 그 조합을 PK로 두고
 * 카운터만 올리면 행 수가 **실제 조합 수**로 묶인다 — 정상 도메인이면 하루 수십~수백 행이다.
 *
 * ★`count` 증가는 `insertIgnore` + `UPDATE`가 아니라 **UPDATE 먼저, 없으면 INSERT**다.
 * 다이얼렉트 봉인 규약상 upsert 문법을 쓸 수 없어서다(`insertIgnore`가 유일한 탈출구).
 *
 * `day`는 UTC 자정 epoch ms다. 리포트 기간이 하루 단위(§7.2의 관례)라 그 경계로 미리 묶는다.
 */
export const m017Reporting: Migration = {
  version: 17,
  name: "reporting",
  statements: [
    /**
     * DMARC 집계 행 — RFC 7489 §7.2의 `<record>` 하나에 대응한다.
     *
     * 정책 도메인(`policy_domain`)이 리포트의 단위다: 그 도메인의 DMARC 레코드에 적힌
     * `rua`로 보낸다. `header_from`을 따로 두는 이유는 하위 도메인이 조직 도메인 정책을
     * 물려받을 때 둘이 다르기 때문이다.
     */
    `CREATE TABLE IF NOT EXISTS dmarc_report_rows (
      day            BIGINT NOT NULL,
      policy_domain  VARCHAR(255) NOT NULL,
      header_from    VARCHAR(255) NOT NULL,
      source_ip      VARCHAR(45) NOT NULL,
      disposition    VARCHAR(16) NOT NULL,
      dkim_aligned   SMALLINT NOT NULL,
      spf_aligned    SMALLINT NOT NULL,
      dkim_result    VARCHAR(16) NOT NULL,
      spf_result     VARCHAR(16) NOT NULL,
      dkim_domain    VARCHAR(255),
      spf_domain     VARCHAR(255),
      count          BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (day, policy_domain, header_from, source_ip, disposition, dkim_aligned, spf_aligned, dkim_result, spf_result)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_dmarc_rows_day ON dmarc_report_rows(day, policy_domain)`,

    /**
     * TLS-RPT 집계 행 — RFC 8460 §4.4의 `policies[].failure-details` / 성공 카운트.
     *
     * ★**발송 쪽** 결과를 센다. 우리가 상대 MX로 보낼 때 MTA-STS/DANE 정책이 어떻게
     * 적용됐는지가 상대에게 유용한 정보다(그들의 정책 설정이 우리 발송을 막고 있는지).
     */
    `CREATE TABLE IF NOT EXISTS tlsrpt_report_rows (
      day            BIGINT NOT NULL,
      policy_domain  VARCHAR(255) NOT NULL,
      policy_type    VARCHAR(16) NOT NULL,
      receiving_mx   VARCHAR(255) NOT NULL,
      result_type    VARCHAR(48) NOT NULL,
      count          BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (day, policy_domain, policy_type, receiving_mx, result_type)
    )`,
    `CREATE INDEX IF NOT EXISTS ix_tlsrpt_rows_day ON tlsrpt_report_rows(day, policy_domain)`,

    /**
     * 보낸 리포트 기록 — **중복 발송을 막는 유일한 근거**다.
     *
     * ★없으면 리포트 작업이 하루에 두 번 돌거나 재기동으로 다시 돌 때마다 같은 기간의
     * 리포트가 또 나간다. 받는 쪽은 그걸 중복으로 세어 통계가 부풀고, 우리는 스팸처럼 보인다.
     */
    `CREATE TABLE IF NOT EXISTS report_sends (
      kind           VARCHAR(16) NOT NULL,
      day            BIGINT NOT NULL,
      policy_domain  VARCHAR(255) NOT NULL,
      report_id      VARCHAR(128) NOT NULL,
      sent_at        BIGINT NOT NULL,
      PRIMARY KEY (kind, day, policy_domain)
    )`,
  ],
};
