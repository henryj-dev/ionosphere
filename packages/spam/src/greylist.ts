/**
 * Greylisting (PROTOCOLS.md §7.1): 초면 (IP, MAIL FROM, RCPT TO) 트리플에 임시거부(4xx) →
 * 정상 MTA는 재시도, 스팸봇은 대부분 재시도하지 않고 사라짐. SPF-pass 발신자는 면제하는 게
 * 요즘 관행(§7.1) — 이미 발신 도메인이 IP를 인증했으므로 greylisting의 봇 필터링 효과가
 * 중복이고, 지연만 유발한다.
 *
 * ── dedup_tracking 스키마 위에서 first_seen을 인코딩하는 방법 (SCHEMA.md §9-2) ──
 * dedup_tracking에는 (account_id, scope, key_hash, expires_at)만 있고 별도 first_seen
 * 컬럼이 없다. 이 모듈은 옵션 (b)로 유도한다: **최초 삽입 시 expires_at = now + expireMs로
 * 쓴다.** 그러면 언제든 first_seen = expires_at - expireMs로 역산할 수 있다(초기 삽입 시점의
 * expires_at은 오직 first_seen + expireMs로만 결정되므로 역산이 정확하다).
 *
 * 흐름:
 * 1. INSERT OR IGNORE(scope=2, account_id='' 전역 센티널 — SCHEMA.md §9-2 주석) 시도.
 *    영향행수==1 → 이 트리플의 첫 목격 → defer(retryAfterMs=delayMs).
 * 2. 영향행수==0(행이 이미 있음) → 읽어서 expires_at을 확인.
 *    - now > expires_at (만료됨, GC 전에 재방문) → 처음 본 것처럼 다시 취급: 행을 리셋
 *      (expires_at = now + expireMs)하고 defer(retryAfterMs=delayMs).
 *    - firstSeen = expires_at - expireMs 역산. now >= firstSeen + delayMs → accept.
 *      accept 시 expires_at을 now + expireMs로 "리프레시"해 이 트리플이 앞으로 expireMs
 *      동안 통과하도록 유지한다(문서화된 트레이드오프: 이 리프레시는 역산되는 first_seen도
 *      함께 앞으로 당기므로, 리프레시 직후 delayMs 이내에 같은 트리플이 다시 들어오면
 *      한 번 더 defer될 수 있다 — 단일 컬럼 인코딩이라는 제약 안에서 수용 가능한 부작용).
 *    - 아직 delayMs 안 지남 → defer(retryAfterMs = 남은 시간 = firstSeen + delayMs - now).
 *
 * 원자성: greylist는 계정별이 아니라 전역 스코프(account_id='')이므로 계정-modseq 클레임
 * 배치 규율이 적용되지 않는다. INSERT OR IGNORE + 읽기의 2단계 패턴으로 충분(SCHEMA.md §1-5
 * 승인 메커니즘). 동시에 두 요청이 같은 트리플을 처음 볼 때의 경합: 승자만 INSERT를 얻고
 * 패자는 방금 삽입된(아직 delayMs 안 지난) 행을 읽어 defer를 받는다 — "둘 다 defer"는
 * 허용되는 결과다(레이스에서 accept가 새는 것보다 안전한 쪽으로 치우침).
 *
 * GC: 만료된 행의 정리는 별도 백그라운드 잡(SCHEMA.md §9-4 background_jobs)의 몫 — 이 모듈은
 * expires_at을 정확히 쓰는 것까지만 책임진다.
 */
import { sha256hex32 } from "@ionosphere/core";
import type { DbDriver } from "@ionosphere/db";

/** dedup_tracking.scope — greylist (SCHEMA.md §9-2). */
const SCOPE_GREYLIST = 2;

/** greylist는 계정 스코프가 아닌 전역 스코프 — SCHEMA.md §9-2 주석의 센티널 값. */
const GLOBAL_ACCOUNT_SENTINEL = "";

/** 재시도 지연 기본값 — 60초(관행적 greylisting 지연). */
const DEFAULT_DELAY_MS = 60_000;

/** 트리플 기록 보존 기본값 — 36시간(그 안에 재시도 없으면 만료, 다시 최초 목격으로 취급). */
const DEFAULT_EXPIRE_MS = 36 * 60 * 60 * 1000;

export interface GreylistInput {
  ip: string;
  mailFrom: string;
  rcpt: string;
  /** true면 SPF 검증을 이미 통과한 발신자 — greylist 면제(§7.1 "모던 관행"). */
  spfPass?: boolean;
}

export interface GreylistOptions {
  /** 최초 목격 후 재시도까지 요구하는 지연(ms). 기본 60_000. */
  delayMs?: number;
  /** 트리플 레코드 보존 기간(ms). 기본 36시간. */
  expireMs?: number;
  /** 테스트 결정성용 시각 주입. 생략 시 Date.now(). */
  now?: number;
}

export type GreylistResult = { action: "accept" } | { action: "defer"; retryAfterMs: number };

/** 주소 정규화 — 트리플 키 계산 전 대소문자/공백 차이를 흡수. */
function normalizeAddress(addr: string): string {
  return addr.trim().toLowerCase();
}

function tripleKeyHash(ip: string, mailFrom: string, rcpt: string): string {
  const normFrom = normalizeAddress(mailFrom);
  const normRcpt = normalizeAddress(rcpt);
  return sha256hex32(`${ip}|${normFrom}|${normRcpt}`);
}

export async function checkGreylist(
  db: DbDriver,
  input: GreylistInput,
  opts?: GreylistOptions,
): Promise<GreylistResult> {
  if (input.spfPass) {
    // SPF-pass 발신자는 트리플을 기록조차 하지 않고 바로 통과(§7.1).
    return { action: "accept" };
  }

  const delayMs = opts?.delayMs ?? DEFAULT_DELAY_MS;
  const expireMs = opts?.expireMs ?? DEFAULT_EXPIRE_MS;
  const now = opts?.now ?? Date.now();
  const keyHash = tripleKeyHash(input.ip, input.mailFrom, input.rcpt);

  const insertSql = db.insertIgnore("dedup_tracking", ["account_id", "scope", "key_hash", "expires_at"]);
  const [insertResult] = await db.batch([
    { sql: insertSql, params: [GLOBAL_ACCOUNT_SENTINEL, SCOPE_GREYLIST, keyHash, now + expireMs] },
  ]);

  if (insertResult?.changes === 1) {
    // 최초 목격 — first_seen = now (expires_at = now + expireMs로 인코딩됨).
    return { action: "defer", retryAfterMs: delayMs };
  }

  // 이미 행이 존재 — 읽어서 상태 판정.
  const { rows } = await db.query({
    sql: "SELECT expires_at FROM dedup_tracking WHERE account_id = ? AND scope = ? AND key_hash = ?",
    params: [GLOBAL_ACCOUNT_SENTINEL, SCOPE_GREYLIST, keyHash],
  });
  const row = rows[0];
  if (!row) {
    // 극히 드문 레이스(읽기 직전 GC가 행을 지움) — 처음 본 것처럼 안전하게 재시도 요구.
    return { action: "defer", retryAfterMs: delayMs };
  }

  const expiresAt = Number(row.expires_at);

  if (now > expiresAt) {
    // 만료된 트리플 — 처음 본 것처럼 리셋.
    await db.batch([
      {
        sql: "UPDATE dedup_tracking SET expires_at = ? WHERE account_id = ? AND scope = ? AND key_hash = ?",
        params: [now + expireMs, GLOBAL_ACCOUNT_SENTINEL, SCOPE_GREYLIST, keyHash],
      },
    ]);
    return { action: "defer", retryAfterMs: delayMs };
  }

  const firstSeen = expiresAt - expireMs;
  const elapsed = now - firstSeen;

  if (elapsed >= delayMs) {
    // 지연 통과 — 수락하고 만료를 리프레시(향후 expireMs 동안 재통과 없이 즉시 accept).
    await db.batch([
      {
        sql: "UPDATE dedup_tracking SET expires_at = ? WHERE account_id = ? AND scope = ? AND key_hash = ?",
        params: [now + expireMs, GLOBAL_ACCOUNT_SENTINEL, SCOPE_GREYLIST, keyHash],
      },
    ]);
    return { action: "accept" };
  }

  return { action: "defer", retryAfterMs: firstSeen + delayMs - now };
}
