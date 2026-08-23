/**
 * DANE TLSA 조회 — `@ionosphere/dns`의 DNSSEC 검증 리졸버를 MTA 워커 계약에 물린다.
 *
 * 이 파일이 조립층에 있는 이유: `@ionosphere/mta`는 DNS 구현을 몰라야 하고(순수 발송 로직),
 * `@ionosphere/dns`는 MTA 계약을 몰라야 한다. 둘을 아는 것은 조립층뿐이다.
 *
 * ★`secure`가 아니면 TLSA를 쓰지 않는다. 검증되지 않은 TLSA를 받아들이면 DNS를 속인
 * 공격자가 **우리가 그의 인증서를 고정하게** 만들 수 있다 — DANE가 막으려는 그 공격이다.
 */
import { ValidatingResolver, RRType, type RData, type ValidatedAnswer } from "@ionosphere/dns";
import { tlsaQueryName, type TlsaRecord } from "@ionosphere/mail-auth";
import type { TlsaLookup } from "@ionosphere/mta";
import type { Logger } from "@ionosphere/core";

/**
 * 검증 리졸버에서 **우리가 쓰는 부분만** 요구한다 — 테스트가 클래스를 통째로 흉내내지 않도록.
 */
export interface TlsaValidator {
  validated(name: string, qtype: number): Promise<ValidatedAnswer>;
}

export interface TlsaLookupOptions {
  resolver?: TlsaValidator;
  logger?: Logger;
  /** 조회 결과 캐시 TTL(ms). 기본 5분. */
  cacheTtlMs?: number;
}

/** 기본 캐시 TTL — 큐가 한 도메인에 여러 통을 보낼 때 루트부터 다시 걷지 않게 한다. */
const DEFAULT_CACHE_TTL_MS = 5 * 60_000;

export function createTlsaLookup(opts: TlsaLookupOptions = {}): (mxHost: string, port: number) => Promise<TlsaLookup> {
  const resolver = opts.resolver ?? new ValidatingResolver();
  const ttl = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  /**
   * 캐시는 **판정 전체**를 담는다(none/bogus 포함). 실패만 캐시하지 않으면 문제 있는 도메인에
   * 대해 매 통마다 루트부터 재귀 질의가 나간다.
   */
  const cache = new Map<string, { value: TlsaLookup; expiresAt: number }>();

  return async (mxHost, port) => {
    const key = `${mxHost}:${port}`;
    const now = Date.now();
    const hit = cache.get(key);
    if (hit && hit.expiresAt > now) return hit.value;

    const answer = await resolver.validated(tlsaQueryName(mxHost, port), RRType.TLSA);
    let value: TlsaLookup;
    if (answer.status === "bogus") {
      value = { kind: "bogus", reason: answer.reason };
    } else if (answer.status === "insecure") {
      // 서명이 없는 존이거나 조회가 실패했다 — DANE 이전 동작으로 간다.
      value = { kind: "none" };
    } else {
      const records: TlsaRecord[] = [];
      for (const r of answer.records) {
        const rd: RData = r.rdata;
        if (rd.kind !== "TLSA") continue;
        records.push({ usage: rd.usage, selector: rd.selector, matchingType: rd.matchingType, data: rd.data });
      }
      value = records.length > 0 ? { kind: "tlsa", set: { records, dnssecValidated: true } } : { kind: "none" };
      if (records.length > 0) {
        opts.logger?.info("dane tlsa", { mx: mxHost, port, records: records.length });
      }
    }

    cache.set(key, { value, expiresAt: now + ttl });
    return value;
  };
}
