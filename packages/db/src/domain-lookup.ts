/**
 * `domains` 라우팅 판정의 정본 — 원시 `SELECT ... FROM domains`를 라우팅 경로에 두지 않는다.
 *
 * ★왜 승격했나(감사 5차 H-4): 같은 판정을 세 곳이 각자 원시 SQL로 하다가 **두 곳이 `status`를
 * 빠뜨렸다**. `domains.name`에는 UNIQUE 제약이 없고(001_init: 평범한 인덱스), 전역 유일성은
 * `domain_name_claims.name PRIMARY KEY`가 **status=1인 행 하나만** 보장한다. 즉 아무 테넌트나
 * `gmail.com` status=0 행을 만들 수 있다. 그 행이 라우팅 판정에 섞이면
 *   - 워커의 `isLocalDomain`이 true가 되어 **전 테넌트의 gmail 발송이 스마트호스트 밖으로** 나가고
 *   - `localOnly` 게이트가 미검증 행으로 통과해 **내부 전용 배포에서 외부로 샌다**.
 *
 * 그래서 판정을 두 축으로 쪼갠다. 한 축만 쓰면 반드시 한쪽이 깨진다:
 *   `verified`     — 전역에서 검증된 도메인(status=1). **타 테넌트의 미검증 행에 오염되지 않는다.**
 *   `ownedByTenant`— 그 테넌트 자신이 소유한 행(검증 여부 무관).
 *
 * 미검증이어도 **자기 테넌트 것이면** 로컬로 취급해야 하는 이유는 워커
 * `isLocalDomain` 주석에 있다: 미검증 도메인을 "외부"로 보내면 릴레이가 MX를 조회해 결국
 * 우리에게 오고, 수신 라우팅이 거절해도 그 거절을 **우리가 못 본다**(제공자가 대신 받는다).
 * 로컬로 취급해 직접 보내야 같은 거절을 동기 응답으로 받아 hardBounce로 기록할 수 있다.
 * 이 이점은 유지하면서 **타 테넌트에게는 새지 않게** 하는 것이 두 축으로 나눈 목적이다.
 */
import type { DbDriver } from "./types.ts";

/** 검증된 도메인의 `domains.status` 값. 미검증은 0(§4 도메인 소유권 검증). */
const DOMAIN_STATUS_VERIFIED = 1;

export interface DomainRouting {
  /** 전역에서 검증된(status=1) 도메인인가. 이 축만 신뢰 경계를 넘어도 안전하다. */
  verified: boolean;
  /** 조회한 테넌트가 소유한 행이 있는가(검증 여부 무관). tenantId 미지정 시 항상 false. */
  ownedByTenant: boolean;
}

/**
 * 도메인 한 개의 라우팅 축 두 개를 **한 번의 조회**로 얻는다.
 *
 * 왜 한 번인가: 배달 경로(워커)에서 도메인마다 도는 조회라 왕복을 늘리면 큐 처리량이 떨어진다.
 * `tenantId`가 없으면 `ownedByTenant`는 묻지 않는다(파라미터 개수를 다이얼렉트 간 일정하게
 * 유지하려고 빈 문자열을 쓴다 — 빈 tenant_id를 가진 행은 존재하지 않는다).
 */
export async function lookupDomainRouting(
  db: DbDriver,
  name: string,
  tenantId?: string,
): Promise<DomainRouting> {
  const domain = name.trim().toLowerCase();
  if (!domain) return { verified: false, ownedByTenant: false };
  const { rows } = await db.query({
    sql: `SELECT status, tenant_id FROM domains WHERE name = ?`,
    params: [domain],
  });
  let verified = false;
  let ownedByTenant = false;
  for (const row of rows) {
    if (Number(row.status) === DOMAIN_STATUS_VERIFIED) verified = true;
    if (tenantId !== undefined && tenantId !== "" && String(row.tenant_id) === tenantId) ownedByTenant = true;
  }
  return { verified, ownedByTenant };
}

/**
 * 이 도메인으로 **우리가 직접 배달해도 되는가**(= 로컬 취급).
 *
 * 검증된 도메인이거나, 조회 테넌트 자신의 도메인이면 참. 타 테넌트가 만든 미검증 행은
 * 참이 되지 않는다 — 그것이 H-4가 뚫린 자리다.
 */
export async function isLocallyRoutableDomain(
  db: DbDriver,
  name: string,
  tenantId?: string,
): Promise<boolean> {
  const r = await lookupDomainRouting(db, name, tenantId);
  return r.verified || r.ownedByTenant;
}

/**
 * **이 테넌트가 이 도메인으로 발송할 자격이 있는가**(아웃바운드 게이트, PLAN.md §8 ②).
 *
 * 위 두 함수와 조건이 다르다 — 발송은 "검증됐고 **내 것**"을 동시에 요구한다. 남의 검증된
 * 도메인으로 보내는 것은 사칭이고, 내 미검증 도메인으로 보내는 것은 SPF·DKIM이 없어 어차피
 * 거절당한다. 이름을 따로 둔 이유가 그것이다 — 셋을 한 함수의 플래그로 합치면 호출부가
 * 어느 판정을 원하는지 읽히지 않는다.
 */
export async function canSendFromDomain(db: DbDriver, name: string, tenantId: string): Promise<boolean> {
  const domain = name.trim().toLowerCase();
  if (!domain || !tenantId) return false;
  const { rows } = await db.query({
    sql: `SELECT 1 AS x FROM domains WHERE tenant_id = ? AND name = ? AND status = ?`,
    params: [tenantId, domain, DOMAIN_STATUS_VERIFIED],
  });
  return rows.length > 0;
}
