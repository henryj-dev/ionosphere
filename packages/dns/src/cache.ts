/**
 * TTL 준수 DNS 캐시 + 네거티브 캐시(RFC 2308). 순수 로직만 — 시계(clock)를 주입해
 * 만료를 결정적으로 테스트한다. 소켓/네트워크 없음.
 *
 * - 포지티브: 레코드들의 최소 TTL만큼 유효(0이면 캐시 안 함).
 * - 네거티브: NXDOMAIN/NODATA를 권한 SOA의 minimum TTL만큼 캐시(없으면 기본값).
 * 키는 `${type}:${소문자 이름}` — 대소문자 비구분(RFC 4343).
 */
import type { DnsRecord } from "./wire.ts";

export interface DnsCacheEntry {
  /** 네거티브면 빈 배열. */
  records: DnsRecord[];
  negative: boolean;
  /** clock() 기준 만료 시각(ms). */
  expiresAt: number;
}

export interface DnsCacheOptions {
  /** ms 단위 현재 시각. 기본 Date.now. */
  clock?: () => number;
  /** 최대 엔트리 수(초과 시 가장 먼저 넣은 것부터 축출). 기본 4096. */
  maxEntries?: number;
  /** TTL 상한(초). 과도한 TTL 방지. 기본 86400(1일). */
  maxTtlSec?: number;
  /** 네거티브 기본 TTL(초) — SOA minimum 없을 때. 기본 300. */
  defaultNegativeTtlSec?: number;
}

function keyOf(name: string, type: number): string {
  return `${type}:${name.toLowerCase().replace(/\.$/, "")}`;
}

export class DnsCache {
  private readonly map = new Map<string, DnsCacheEntry>();
  private readonly clock: () => number;
  private readonly maxEntries: number;
  private readonly maxTtlSec: number;
  private readonly defaultNegativeTtlSec: number;

  constructor(opts?: DnsCacheOptions) {
    this.clock = opts?.clock ?? Date.now;
    this.maxEntries = opts?.maxEntries ?? 4096;
    this.maxTtlSec = opts?.maxTtlSec ?? 86400;
    this.defaultNegativeTtlSec = opts?.defaultNegativeTtlSec ?? 300;
  }

  /** 유효한 엔트리 반환. 만료됐거나 없으면 undefined(만료분은 제거). */
  get(name: string, type: number): DnsCacheEntry | undefined {
    const key = keyOf(name, type);
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (this.clock() >= entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    return entry;
  }

  /** 포지티브 캐시. 레코드 최소 TTL 사용. TTL 0이면 저장 안 함. */
  setPositive(name: string, type: number, records: DnsRecord[]): void {
    if (records.length === 0) return;
    let minTtl = Infinity;
    for (const r of records) minTtl = Math.min(minTtl, r.ttl);
    if (!Number.isFinite(minTtl) || minTtl <= 0) return;
    const ttl = Math.min(minTtl, this.maxTtlSec);
    this.store(keyOf(name, type), { records, negative: false, expiresAt: this.clock() + ttl * 1000 });
  }

  /** 네거티브 캐시. soaMinimumSec 지정 시 그 값, 아니면 기본 네거티브 TTL. */
  setNegative(name: string, type: number, soaMinimumSec?: number): void {
    const base = soaMinimumSec !== undefined && soaMinimumSec > 0 ? soaMinimumSec : this.defaultNegativeTtlSec;
    const ttl = Math.min(base, this.maxTtlSec);
    this.store(keyOf(name, type), { records: [], negative: true, expiresAt: this.clock() + ttl * 1000 });
  }

  private store(key: string, entry: DnsCacheEntry): void {
    // 이미 있으면 갱신 순서를 위해 삭제 후 재삽입(Map은 삽입 순서 보존 → FIFO 축출).
    this.map.delete(key);
    this.map.set(key, entry);
    if (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
  }

  /** 현재 엔트리 수(테스트/진단용). */
  get size(): number {
    return this.map.size;
  }

  clear(): void {
    this.map.clear();
  }
}
