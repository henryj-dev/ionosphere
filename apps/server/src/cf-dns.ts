/**
 * Cloudflare DNS-01 provider — ACME 챌린지용 _acme-challenge TXT 레코드 생성/삭제.
 * @ionosphere/tls의 DnsProvider 훅 구현(fetch 기반, 의존성 제로). 존 ID는 미지정 시 fqdn의
 * 등록가능 도메인으로 조회한다. 토큰은 Zone.DNS:Edit 권한 필요.
 */
import type { DnsProvider } from "@ionosphere/tls";

export interface CloudflareDnsOptions {
  apiToken: string;
  /** 미지정 시 fqdn 접미사 매칭으로 존 자동 조회. */
  zoneId?: string;
  baseUrl?: string;
  fetch?: typeof fetch;
}

export type DnsProviderFactory = (opts: CloudflareDnsOptions) => DnsProvider;
const DNS_PROVIDER_FACTORIES: Readonly<Record<string, DnsProviderFactory>> = { cloudflare: cloudflareDnsProvider };

/** ACME 조립부가 특정 구현을 직접 참조하지 않도록 공급자 선택을 한 곳에 봉인한다. */
export function dnsProviderFromConfig(name: string, opts: CloudflareDnsOptions): DnsProvider {
  const factory = DNS_PROVIDER_FACTORIES[name.trim().toLowerCase()];
  if (!factory) throw new Error(`지원하지 않는 DNS provider: ${name}`);
  return factory(opts);
}

const DEFAULT_BASE = "https://api.cloudflare.com/client/v4";

export function cloudflareDnsProvider(opts: CloudflareDnsOptions): DnsProvider {
  const base = opts.baseUrl ?? DEFAULT_BASE;
  const f = opts.fetch ?? fetch;
  const H = { Authorization: `Bearer ${opts.apiToken}`, "Content-Type": "application/json" };
  const zoneCache = new Map<string, string>();

  async function cf(path: string, init?: RequestInit): Promise<{ result: unknown }> {
    const res = await f(`${base}${path}`, { headers: H, ...init });
    if (!res.ok) throw new Error(`CF ${path}: HTTP ${res.status}`);
    const j = (await res.json()) as { success: boolean; result: unknown; errors?: unknown };
    if (!j.success) throw new Error(`CF ${path}: ${JSON.stringify(j.errors)}`);
    return j;
  }

  /** fqdn(_acme-challenge.mx.ionosphere.test)의 담당 존 ID — 이름 접미사가 가장 긴 존. */
  async function zoneFor(fqdn: string): Promise<string> {
    if (opts.zoneId) return opts.zoneId;
    const cached = [...zoneCache.entries()].find(([name]) => fqdn === name || fqdn.endsWith(`.${name}`));
    if (cached) return cached[1];
    const candidate = fqdn.split(".").map((_, i, a) => a.slice(i).join(".")).filter(Boolean);
    const zones: { id: string; name: string }[] = [];
    for (const name of candidate) {
      const { result } = (await cf(`/zones?name=${encodeURIComponent(name)}&per_page=50`)) as { result: { id: string; name: string }[] };
      zones.push(...result);
    }
    let best: { id: string; name: string } | null = null;
    for (const z of zones) {
      if ((fqdn === z.name || fqdn.endsWith(`.${z.name}`)) && (!best || z.name.length > best.name.length)) best = z;
    }
    if (!best) throw new Error(`CF: ${fqdn} 담당 존을 찾을 수 없음`);
    zoneCache.set(best.name, best.id);
    return best.id;
  }

  return {
    async setTxt(fqdn, value) {
      const zone = await zoneFor(fqdn);
      await cf(`/zones/${zone}/dns_records`, { method: "POST", body: JSON.stringify({ type: "TXT", name: fqdn, content: value, ttl: 60 }) });
    },
    async removeTxt(fqdn, value) {
      const zone = await zoneFor(fqdn);
      const records: { id: string; content: string }[] = [];
      for (let page = 1;; page++) {
        const { result } = (await cf(`/zones/${zone}/dns_records?type=TXT&name=${encodeURIComponent(fqdn)}&page=${page}&per_page=100`)) as { result: { id: string; content: string }[] };
        records.push(...result);
        if (result.length < 100) break;
      }
      for (const rec of records) {
        if (rec.content === value || `"${value}"` === rec.content) {
          await cf(`/zones/${zone}/dns_records/${rec.id}`, { method: "DELETE" });
        }
      }
    },
  };
}
