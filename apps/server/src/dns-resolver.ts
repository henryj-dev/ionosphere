/**
 * node:dns 기반 DnsResolver 구현 — mail-auth의 검증 함수들과 api의 도메인 검증에 주입.
 * NXDOMAIN/빈결과 → DnsNotFoundError, SERVFAIL/타임아웃 → DnsTemporaryError로 정규화
 * (mail-auth의 temperror/permerror 판정이 이 구분에 의존).
 *
 * 주의: node:dns 스텁 리졸버는 OS 리졸버(/etc/resolv.conf)를 씀. DNSBL 신뢰 조회용
 * 자체 재귀 리졸버는 Phase 3 — SPF/DKIM/DMARC는 퍼블릭 리졸버로도 무방(차단 대상 아님).
 */
import { Resolver } from "node:dns/promises";
import { DnsNotFoundError, DnsTemporaryError, type DnsResolver } from "@ionosphere/mail-auth";

// node:dns 에러코드 → 우리 구분
const NOT_FOUND = new Set(["ENOTFOUND", "ENODATA", "NXDOMAIN"]);

function mapError(err: unknown): never {
  const code = (err as { code?: string }).code;
  if (code && NOT_FOUND.has(code)) throw new DnsNotFoundError(String(code));
  throw new DnsTemporaryError(code ?? String(err));
}

export class NodeDnsResolver implements DnsResolver {
  private readonly r: Resolver;

  constructor(servers?: string[]) {
    this.r = new Resolver();
    if (servers && servers.length > 0) this.r.setServers(servers);
  }

  async txt(name: string): Promise<string[]> {
    try {
      const records = await this.r.resolveTxt(name);
      // 각 레코드는 문자열 조각 배열 — RFC상 이어붙임
      const joined = records.map((chunks) => chunks.join(""));
      if (joined.length === 0) throw new DnsNotFoundError("empty TXT");
      return joined;
    } catch (err) {
      if (err instanceof DnsNotFoundError) throw err;
      mapError(err);
    }
  }

  async mx(name: string): Promise<{ exchange: string; preference: number }[]> {
    try {
      const records = await this.r.resolveMx(name);
      if (records.length === 0) throw new DnsNotFoundError("empty MX");
      return records.map((m) => ({ exchange: m.exchange, preference: m.priority }));
    } catch (err) {
      if (err instanceof DnsNotFoundError) throw err;
      mapError(err);
    }
  }

  async a(name: string): Promise<string[]> {
    try {
      const records = await this.r.resolve4(name);
      if (records.length === 0) throw new DnsNotFoundError("empty A");
      return records;
    } catch (err) {
      if (err instanceof DnsNotFoundError) throw err;
      mapError(err);
    }
  }

  async aaaa(name: string): Promise<string[]> {
    try {
      const records = await this.r.resolve6(name);
      if (records.length === 0) throw new DnsNotFoundError("empty AAAA");
      return records;
    } catch (err) {
      if (err instanceof DnsNotFoundError) throw err;
      mapError(err);
    }
  }

  async ptr(ip: string): Promise<string[]> {
    try {
      const records = await this.r.reverse(ip);
      if (records.length === 0) throw new DnsNotFoundError("empty PTR");
      return records;
    } catch (err) {
      if (err instanceof DnsNotFoundError) throw err;
      mapError(err);
    }
  }
}
