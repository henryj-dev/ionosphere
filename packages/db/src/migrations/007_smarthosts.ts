import type { Migration } from "../migrate.ts";

/**
 * 007 — 테넌트/발신 도메인별 스마트호스트(아웃바운드 릴레이).
 *
 * 왜 필요한가: 릴레이 설정이 지금까지 프로세스 env(IONOSPHERE_SMARTHOST*) 하나뿐이라
 * **서버 전체가 같은 릴레이를 쓴다**. 멀티테넌트에서 이건 두 가지로 깨진다.
 *  · 테넌트 A의 메일이 테넌트 B의 릴레이 계정으로 나간다 — 제공자 쪽 발송 한도·평판·청구가
 *    엉키고, 릴레이 자격증명 하나가 새면 전 테넌트의 발신 권한이 함께 샌다.
 *  · 제공자마다 "이 계정으로 보낼 수 있는 발신 도메인"이 정해져 있다(Cloudflare Email Service가
 *    그렇다). 도메인별로 릴레이를 못 고르면 온보딩되지 않은 도메인이 550으로 튕긴다.
 *
 * 해석 순서는 좁은 것부터다: 발신 도메인 → 테넌트 기본 → 전역 env → MX 직송.
 * 그래서 `domain`은 **발신자(envelope-from)의 도메인**이지 수신 도메인이 아니다.
 *
 * 스키마 결정:
 *  · PK (tenant_id, domain) — "한 범위에 릴레이 하나"를 DB가 강제한다. 애플리케이션이
 *    ORDER BY로 승자를 고르게 두면 중복 행이 들어간 순간 어느 쪽이 이길지 조회 계획에 달린다.
 *    `domain = ''`(SMARTHOST_TENANT_DEFAULT)이 테넌트 기본 — NULL을 쓰지 않는 이유는
 *    columns.ts의 센티널 주석 참고.
 *  · secret — **평문으로 두지 않는다**. DKIM 개인키와 같은 `seal()`(AES-256-GCM,
 *    IONOSPHERE_MASTER_KEY)로 봉인해 넣는다. 릴레이 자격증명은 탈취되면 그 즉시 임의 발신
 *    권한이므로 DB 덤프·백업에 그대로 실려서는 안 된다.
 *  · max_rcpts — 세션당 RCPT TO 상한. 제공자가 정하는 값이라 릴레이별로 다르다
 *    (Cloudflare Email Service는 50). 넘겨서 보내면 초과분이 거절되는데, 우리 큐는
 *    (수신 도메인, 발신자, 블롭)으로 묶어 한 연결에 몰아 보내므로 대량 발송에서 실제로 닿는다.
 *    NULL이면 상한 없음.
 *
 * D1(비트랜잭셔널 DDL) 재개 안전: 문장이 IF NOT EXISTS뿐이라 멱등.
 */
export const m007Smarthosts: Migration = {
  version: 7,
  name: "smarthosts",
  statements: [
    `CREATE TABLE IF NOT EXISTS smarthosts (
      tenant_id  VARCHAR(26)  NOT NULL,
      domain     VARCHAR(255) NOT NULL,
      host       VARCHAR(255) NOT NULL,
      port       INTEGER      NOT NULL,
      tls_mode   SMALLINT     NOT NULL,
      username   VARCHAR(255),
      secret     TEXT,
      max_rcpts  INTEGER,
      created_at BIGINT       NOT NULL,
      PRIMARY KEY (tenant_id, domain)
    )`,
  ],
};
