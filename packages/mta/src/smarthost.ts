/**
 * 스마트호스트(아웃바운드 릴레이) — 해석 인터페이스와 DB 인코딩 코덱.
 *
 * 워커는 "이 메일을 어디로 릴레이하나"를 스스로 알지 않는다. 해석은 주입된
 * `SmarthostResolver`가 하고(구현은 apps/server가 DB를 보고 만든다), 워커는 결과만 쓴다.
 * DkimHook과 같은 모양이다 — 순수 엔진 쪽에 DB 조회·복호화를 들이지 않기 위해서다.
 */
import { SMARTHOST_TLS, type SmarthostTls } from "@ionosphere/db";
import type { SmtpAuth, TlsMode } from "./smtp-client.ts";

/**
 * 스마트호스트(릴레이) 설정 — 지정 시 MX 조회를 생략하고 이 호스트로 릴레이한다
 * (STATUS §9: 아웃바운드 25 차단 환경의 실발송 경로).
 */
export interface SmarthostOptions {
  host: string;
  /** 기본 587. 465는 tls:"implicit"과 함께. */
  port?: number;
  /** SASL 자격증명 — 릴레이 제공자 계정. */
  auth?: SmtpAuth;
  /** 기본 "required" — 자격증명을 평문으로 보내지 않도록 STARTTLS 강제. */
  tls?: TlsMode;
  /**
   * 한 SMTP 세션에 실을 RCPT TO 최대 개수. 제공자가 정하는 값이다
   * (Cloudflare Email Service = 50). 미지정이면 상한 없음.
   *
   * 우리 큐는 (수신 도메인, 발신자, 블롭)이 같은 항목을 한 연결에 몰아 보내므로,
   * 상한을 모르면 대량 발송에서 초과분이 통째로 거절된다.
   */
  maxRcptsPerSession?: number;
}

/**
 * 테넌트/발신 도메인 → 릴레이 해석기.
 *
 * `null`은 "이 범위에 설정된 릴레이가 없다"는 뜻이고, 그때 워커는 전역 설정(env) 또는
 * MX 직송으로 내려간다. **찾지 못한 것과 조회에 실패한 것은 다르다** — 실패는 던져야 한다.
 * 실패를 null로 뭉개면 릴레이를 쓰라고 설정해 둔 테넌트의 메일이 조용히 MX 직송으로
 * 새 나가고(제공자 밖 발송·평판 사고), 인증 없이 나가게 된다.
 */
export interface SmarthostResolver {
  resolve(tenantId: string, senderDomain: string): Promise<SmarthostOptions | null>;
}

/**
 * `TlsMode`(문자열) → `smarthosts.tls_mode`(정수).
 *
 * `Record<TlsMode, …>`인 것이 핵심이다 — TlsMode에 값이 하나 늘면 **여기서 컴파일 에러가 난다.**
 * 저장할 수 없는 모드가 조용히 생기는 것을 막는다.
 */
export const SMARTHOST_TLS_CODE: Record<TlsMode, SmarthostTls> = {
  required: SMARTHOST_TLS.required,
  opportunistic: SMARTHOST_TLS.opportunistic,
  implicit: SMARTHOST_TLS.implicit,
  never: SMARTHOST_TLS.never,
};

/**
 * `smarthosts.tls_mode`(정수) → `TlsMode`(문자열).
 *
 * 반대 방향으로 `Record<SmarthostTls, …>`라, db 쪽 인코딩에 값이 늘면 여기서 컴파일 에러가 난다.
 * 두 Record가 마주 보고 있어 한쪽만 고치는 것이 불가능하다.
 */
export const SMARTHOST_TLS_MODE: Record<SmarthostTls, TlsMode> = {
  [SMARTHOST_TLS.required]: "required",
  [SMARTHOST_TLS.opportunistic]: "opportunistic",
  [SMARTHOST_TLS.implicit]: "implicit",
  [SMARTHOST_TLS.never]: "never",
};
