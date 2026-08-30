export const LISTING_CACHE_LIMITS = { maxResults: 2_000, minTtlMs: 5_000, maxTtlMs: 30_000, maxEntries: 256 } as const;

export interface ListingCacheKeyParts {
  principalId: string;
  mailboxId: string;
  mailboxModseq: number;
  aclVersion: number;
  permissionsVersion: number;
  query: unknown;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
}

/** Query 전체와 권한 세대를 포함한 key. display-only 정렬과 offset도 query에 반드시 넣는다. */
export function listingCacheKey(parts: ListingCacheKeyParts): string {
  return canonical({ principalId: parts.principalId, mailboxId: parts.mailboxId, mailboxModseq: parts.mailboxModseq, aclVersion: parts.aclVersion, permissionsVersion: parts.permissionsVersion, query: parts.query });
}

export interface ListingCacheOptions { maxEntries?: number; ttlMs?: number; now?: () => number; }

interface Entry<T> { value: readonly T[]; expiresAt: number; }

/** 프로세스 로컬 bounded LRU. 프로세스 종료 시 유실되며 DB가 정본이다. */
export class ListingCache<T> {
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly entries = new Map<string, Entry<T>>();

  constructor(options: ListingCacheOptions = {}) {
    this.maxEntries = options.maxEntries ?? LISTING_CACHE_LIMITS.maxEntries;
    this.ttlMs = options.ttlMs ?? 10_000;
    this.now = options.now ?? Date.now;
    if (!Number.isInteger(this.maxEntries) || this.maxEntries < 1) throw new Error("listing cache maxEntries는 양의 정수");
    if (!Number.isInteger(this.ttlMs) || this.ttlMs < LISTING_CACHE_LIMITS.minTtlMs || this.ttlMs > LISTING_CACHE_LIMITS.maxTtlMs) throw new Error("listing cache TTL은 5~30초");
  }

  get(key: string): readonly T[] | null {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) { this.entries.delete(key); return null; }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: string, values: readonly T[]): readonly T[] {
    const bounded = values.slice(0, LISTING_CACHE_LIMITS.maxResults);
    this.entries.delete(key);
    this.entries.set(key, { value: bounded, expiresAt: this.now() + this.ttlMs });
    while (this.entries.size > this.maxEntries) this.entries.delete(this.entries.keys().next().value!);
    return bounded;
  }

  delete(key: string): void { this.entries.delete(key); }
  clear(): void { this.entries.clear(); }
  get size(): number { return this.entries.size; }
}

export async function getOrLoadListing<T>(cache: ListingCache<T>, key: string, loader: () => Promise<readonly T[]>): Promise<readonly T[]> {
  const cached = cache.get(key);
  if (cached) return cached;
  return cache.set(key, await loader());
}
