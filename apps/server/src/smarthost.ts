/**
 * DB 기반 스마트호스트 해석기 + 제공자 프리셋.
 *
 * `StoreDkimHook`과 같은 모양이다 — 순수 워커에 DB 조회·복호화를 들이지 않고,
 * 조립층인 apps/server가 그 둘을 아는 구현을 만들어 주입한다.
 */
import { open } from "@ionosphere/core";
import { isSmarthostTls, SMARTHOST_TENANT_DEFAULT, type DbDriver } from "@ionosphere/db";
import { SMARTHOST_TLS_MODE, type SmarthostOptions, type SmarthostResolver } from "@ionosphere/mta";

/**
 * 제공자 프리셋 — 접속 파라미터를 사람이 매번 옮겨 적지 않게 한다.
 *
 * 릴레이 접속 정보는 틀리면 조용히 실패하지 않고 **평문 노출이나 전량 거절**로 이어진다.
 * 특히 포트와 TLS 모드는 짝이다(465는 implicit, 587은 STARTTLS) — 한쪽만 맞으면 연결이
 * 성립하지 않거나, 최악의 경우 자격증명이 평문으로 나간다. 그래서 짝으로 묶어 둔다.
 */
export interface SmarthostPreset {
  host: string;
  port: number;
  tls: NonNullable<SmarthostOptions["tls"]>;
  /** 제공자가 고정한 SASL 사용자명(있으면). Cloudflare는 리터럴 `api_token`. */
  username?: string;
  maxRcptsPerSession?: number;
  /** 비밀번호로 무엇을 넣어야 하는지 — CLI 사용법 출력에 쓴다. */
  secretHint: string;
}

/**
 * Cloudflare Email Service SMTP.
 * https://developers.cloudflare.com/email-service/api/send-emails/smtp/
 *
 * 문서가 못 박은 것들이라 그대로 옮긴다:
 *  · 465 **implicit TLS 전용** — 587/평문/STARTTLS는 지원하지 않는다.
 *  · 사용자명은 계정 이메일이 아니라 **리터럴 문자열 `api_token`**이다.
 *  · 비밀번호는 "Email Sending: Edit" 권한의 API 토큰. 그 토큰을 가진 사람은 해당 계정에
 *    온보딩된 **모든 도메인**으로 발송할 수 있다 — 문서가 직접 경고하는 부분이라, 우리도
 *    DB에 봉인해 넣고(seal) 저장소·로그에는 절대 남기지 않는다.
 *  · 세션당 RCPT TO 50개 상한.
 */
export const CLOUDFLARE_EMAIL_PRESET: SmarthostPreset = {
  host: "smtp.mx.cloudflare.net",
  port: 465,
  tls: "implicit",
  username: "api_token",
  maxRcptsPerSession: 50,
  secretHint: '"Email Sending: Edit" 권한을 가진 Cloudflare API 토큰',
};

export const SMARTHOST_PRESETS: Readonly<Record<string, SmarthostPreset>> = {
  cloudflare: CLOUDFLARE_EMAIL_PRESET,
};

/** 캐시 수명 — 릴레이 설정은 거의 안 바뀌지만, 자격증명 교체가 재기동을 요구하면 안 된다. */
const DEFAULT_TTL_MS = 60_000;
/** 캐시 상한 — 테넌트 수는 무제한이라 축출이 없으면 계속 자란다(MTA-STS 캐시와 같은 이유). */
const MAX_CACHE_ENTRIES = 1024;

interface CacheEntry {
  value: SmarthostOptions | null;
  expiresAt: number;
}

export interface StoreSmarthostResolverOptions {
  ttlMs?: number;
}

export class StoreSmarthostResolver implements SmarthostResolver {
  private readonly db: DbDriver;
  private readonly masterKey: string | undefined;
  private readonly ttlMs: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(db: DbDriver, masterKey: string | undefined, opts?: StoreSmarthostResolverOptions) {
    this.db = db;
    this.masterKey = masterKey;
    this.ttlMs = opts?.ttlMs ?? DEFAULT_TTL_MS;
  }

  async resolve(tenantId: string, senderDomain: string): Promise<SmarthostOptions | null> {
    const domain = senderDomain.toLowerCase();
    const key = `${tenantId}\u0000${domain}`;
    const now = Date.now();
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > now) return cached.value;

    /**
     * 두 범위를 한 번에 가져와 **코드에서** 고른다. `ORDER BY domain DESC LIMIT 1`로도
     * 되지만(빈 문자열이 항상 뒤로 밀리므로), 그건 센티널의 정렬 순서에 정확성을 맡기는 것이다.
     * 콜레이션이 바뀌면 조용히 테넌트 기본이 도메인 지정을 이긴다.
     */
    const { rows } = await this.db.query({
      sql: `SELECT domain, host, port, tls_mode, username, secret, max_rcpts
            FROM smarthosts WHERE tenant_id = ? AND domain IN (?, ?)`,
      params: [tenantId, domain, SMARTHOST_TENANT_DEFAULT],
    });
    const row = rows.find((r) => String(r.domain) === domain) ?? rows.find((r) => String(r.domain) === SMARTHOST_TENANT_DEFAULT);

    const value = row ? this.toOptions(row) : null;
    if (this.cache.size >= MAX_CACHE_ENTRIES) {
      // 만료분을 먼저 쓸고, 그래도 넘치면 가장 먼저 넣은 것부터 버린다(Map은 삽입 순서 보존).
      for (const [k, v] of this.cache) if (v.expiresAt <= now) this.cache.delete(k);
      while (this.cache.size >= MAX_CACHE_ENTRIES) {
        const oldest = this.cache.keys().next();
        if (oldest.done) break;
        this.cache.delete(oldest.value);
      }
    }
    this.cache.set(key, { value, expiresAt: now + this.ttlMs });
    return value;
  }

  /** 설정 변경 직후 반영이 필요할 때(관리 API·CLI가 같은 프로세스일 때). */
  invalidate(): void {
    this.cache.clear();
  }

  private toOptions(row: Record<string, unknown>): SmarthostOptions {
    const tlsCode = Number(row.tls_mode);
    /**
     * DB 값이 인코딩 밖이면 **던진다**. 워커는 이 예외를 지연으로 처리한다(폴백하지 않는다).
     * 알 수 없는 값을 기본값으로 뭉개면, tls_mode가 깨졌을 때 자격증명이 평문으로 나갈 수 있다.
     */
    if (!isSmarthostTls(tlsCode)) throw new Error(`알 수 없는 smarthosts.tls_mode: ${tlsCode}`);
    const username = row.username == null ? "" : String(row.username);
    const sealed = row.secret == null ? "" : String(row.secret);
    const maxRcpts = row.max_rcpts == null ? undefined : Number(row.max_rcpts);
    return {
      host: String(row.host),
      port: Number(row.port),
      tls: SMARTHOST_TLS_MODE[tlsCode],
      ...(username ? { auth: { user: username, pass: open(sealed, this.masterKey) } } : {}),
      ...(maxRcpts ? { maxRcptsPerSession: maxRcpts } : {}),
    };
  }
}
