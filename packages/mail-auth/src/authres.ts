/**
 * RFC 8601 Authentication-Results 헤더 값 조립 + message_auth(SCHEMA §9-3) SMALLINT 코드 매핑.
 * 순수 함수, DNS 없음.
 *
 * buildAuthenticationResults는 필드명("Authentication-Results:") 없이 헤더 **값**만 반환한다 —
 * 조립기(assembler)가 `"Authentication-Results: " + buildAuthenticationResults(...)`로 붙인다.
 * (RFC 8601 §2.2: authserv-id는 발신 MTA가 스스로 부여하는 신뢰 경계 식별자이므로, 착신 시
 * 반드시 자기 authserv-id를 사칭한 기존 헤더를 제거한 뒤 이 값으로 새로 붙여야 한다 — 이는
 * 조립기의 책임이며 이 함수의 범위 밖이다.)
 */
import type { DkimVerifyOutcome, DkimVerifyResult } from "./verify.ts";
import type { SpfResultValue } from "./spf.ts";
import type { DmarcResult } from "./dmarc.ts";

export interface AuthResultsSpfInput {
  result: SpfResultValue;
  domain: string;
  /** 어떤 SMTP identity로 SPF를 평가했는지 — smtp.mailfrom= 또는 smtp.helo= 프로퍼티 선택에 사용. 기본 mailfrom. */
  identity?: "mailfrom" | "helo";
}

export interface AuthResultsDmarcInput {
  result: DmarcResult["result"];
  fromDomain: string;
}

export interface AuthResultsInput {
  spf?: AuthResultsSpfInput;
  /** DKIM 서명별 결과. 빈 배열이면 "서명 없음"으로 dkim=none을 명시한다. undefined면 DKIM 자체를 검사 안 함(절 생략). */
  dkim?: DkimVerifyResult[];
  dmarc?: AuthResultsDmarcInput;
}

function spfClause(spf: AuthResultsSpfInput): string {
  const idKey = spf.identity === "helo" ? "smtp.helo" : "smtp.mailfrom";
  return `spf=${spf.result} ${idKey}=${spf.domain}`;
}

function dkimClause(d: DkimVerifyResult): string {
  const parts = [`dkim=${d.result}`];
  if (d.domain) parts.push(`header.d=${d.domain}`);
  if (d.selector) parts.push(`header.s=${d.selector}`);
  /**
   * `header.a=`(서명 알고리즘) — RFC 8601 §2.7.1의 `header.a` ptype.
   *
   * ★왜 넣는가(2026-08-01): Ed25519 구현이 RFC 8463 §3을 위반해 규격을 지키는 외부 발신자를
   * 전부 `dkim=fail`로 판정해 왔는데(§4-7), **그 규모를 소급해서 셀 수 없었다** — 우리가 남긴
   * 판정 기록에 알고리즘이 없어 "ed25519 서명이 몇 건 fail이었나"에 답할 방법이 없었다.
   * 같은 종류의 결함이 다시 생기면 이번엔 헤더 집계로 드러난다.
   *
   * Gmail도 같은 정보를 담는다(`dkim=neutral (no key) header.i=… header.s=ed1`처럼 셀렉터로
   * 유추 가능한 형태였지만, 셀렉터 이름은 운영자가 정하는 값이라 알고리즘의 근거가 못 된다).
   */
  if (d.algorithm) parts.push(`header.a=${d.algorithm}`);
  return parts.join(" ");
}

function dmarcClause(dmarc: AuthResultsDmarcInput): string {
  return `dmarc=${dmarc.result} header.from=${dmarc.fromDomain}`;
}

/** RFC 8601 Authentication-Results 헤더 "값"(필드명 제외)을 조립한다. */
export function buildAuthenticationResults(authservId: string, input: AuthResultsInput): string {
  const clauses: string[] = [];
  if (input.spf) clauses.push(spfClause(input.spf));
  if (input.dkim && input.dkim.length > 0) {
    for (const d of input.dkim) clauses.push(dkimClause(d));
  } else if (input.dkim) {
    clauses.push("dkim=none");
  }
  if (input.dmarc) clauses.push(dmarcClause(input.dmarc));

  return clauses.length > 0 ? `${authservId}; ${clauses.join("; ")}` : `${authservId}; none`;
}

// ---------------------------------------------------------------------------
// message_auth(SCHEMA §9-3) 저장용 SMALLINT 매핑
// 0 none / 1 pass / 2 fail / 3 softfail / 4 neutral / 5 temperror / 6 permerror
// ---------------------------------------------------------------------------

export type AuthStorageCode = 0 | 1 | 2 | 3 | 4 | 5 | 6;

const SPF_CODE: Record<SpfResultValue, AuthStorageCode> = {
  none: 0,
  pass: 1,
  fail: 2,
  softfail: 3,
  neutral: 4,
  temperror: 5,
  permerror: 6,
};

// DKIM은 softfail/neutral 개념이 없다 — "서명 없음"은 별도로 "none"(0)을 입력받는다.
const DKIM_CODE: Record<DkimVerifyOutcome, AuthStorageCode> = {
  pass: 1,
  fail: 2,
  temperror: 5,
  permerror: 6,
};

// DMARC도 softfail/neutral 개념이 없다.
const DMARC_CODE: Record<DmarcResult["result"], AuthStorageCode> = {
  none: 0,
  pass: 1,
  fail: 2,
  temperror: 5,
  permerror: 6,
};

export interface StorageCodes {
  /**
   * `null`은 **검사하지 않았다**는 뜻이다 — `0`(none: 레코드가 없더라)과 다르다.
   *
   * 신뢰 릴레이 예외처럼 SPF를 아예 돌리지 않는 경로가 생기면서 필요해졌다. 둘을 뭉개면
   * "SPF를 게시하지 않은 발신자"와 "우리가 검사를 건너뛴 홉"이 집계에서 구별되지 않고,
   * message_auth로 인증 실태를 세는 순간 그 차이가 그대로 오답이 된다.
   * (`message_auth.spf`는 SCHEMA §9-3에서 NULL 허용 컬럼이다.)
   */
  spf: AuthStorageCode | null;
  dkim: AuthStorageCode;
  dmarc: AuthStorageCode;
}

export function mapToStorageCodes(
  spf: SpfResultValue | null,
  dkim: DkimVerifyOutcome | "none",
  dmarc: DmarcResult["result"],
): StorageCodes {
  return {
    spf: spf === null ? null : SPF_CODE[spf],
    dkim: dkim === "none" ? 0 : DKIM_CODE[dkim],
    dmarc: DMARC_CODE[dmarc],
  };
}
