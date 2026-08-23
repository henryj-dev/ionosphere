/**
 * DANE for SMTP (RFC 7672) — TLSA 레코드로 상대 MX의 인증서를 고정한다.
 *
 * 순수 함수만 둔다: "이 인증서가 이 TLSA 집합에 맞는가". DNS 조회와 소켓은 호출부 몫이다.
 *
 * ★**DNSSEC로 검증된 TLSA만 받는다.** 검증되지 않은 TLSA는 없는 것과 같다 —
 * DNS를 속일 수 있는 공격자가 TLSA를 심으면 우리가 그의 인증서를 고정하게 된다.
 * 그래서 이 모듈은 `secure` 판정을 받은 레코드만 입력으로 받도록 설계했고,
 * 호출부가 그 판정을 건너뛸 수 없게 타입으로 요구한다(`DaneTlsaSet.dnssecValidated`).
 *
 * ★**사용 가능한 TLSA가 하나도 없으면 "적용 안 함"이다.** 알 수 없는 usage·selector·
 * matching type만 있는 경우가 여기 해당한다(RFC 7672 §2.2 — 이해 못 하는 레코드는 무시).
 * "전부 무시했더니 남은 게 없다"를 "검증 통과"로 읽으면 고정이 조용히 사라진다.
 */
import { createHash } from "node:crypto";

/** TLSA 인증서 사용법(RFC 6698 §2.1.1). SMTP는 DANE-TA(2)·DANE-EE(3)만 쓴다(RFC 7672 §3.1). */
export const TLSA_USAGE = { PKIX_TA: 0, PKIX_EE: 1, DANE_TA: 2, DANE_EE: 3 } as const;
/** 무엇을 해시할 것인가 — 인증서 전체(0) 또는 공개키(1). */
export const TLSA_SELECTOR = { FULL_CERT: 0, SPKI: 1 } as const;
/** 어떻게 대조할 것인가 — 원본(0)·SHA-256(1)·SHA-512(2). */
export const TLSA_MATCHING = { EXACT: 0, SHA256: 1, SHA512: 2 } as const;

export interface TlsaRecord {
  usage: number;
  selector: number;
  matchingType: number;
  data: Uint8Array;
}

export interface DaneTlsaSet {
  records: readonly TlsaRecord[];
  /**
   * ★DNSSEC로 검증됐는가. **false면 이 집합을 쓰지 않는다.**
   * 필드로 강제하는 이유: 호출부가 검증을 건너뛰고 TLSA를 넘기는 실수를 타입이 막지는
   * 못하지만, 최소한 **의식적으로 false를 적어야** 하게 만든다.
   */
  dnssecValidated: boolean;
}

export type DaneResult =
  /** TLSA와 맞았다 — 인증서가 고정됐다. */
  | { status: "match"; usage: number }
  /** DANE를 적용하지 않는다(TLSA 없음·DNSSEC 미검증·이해 가능한 레코드 없음). */
  | { status: "not-applicable"; reason: string }
  /** TLSA가 있는데 **맞지 않는다**. 배달을 중단해야 한다 — 중간자 신호다. */
  | { status: "mismatch"; reason: string };

/**
 * 이 레코드를 우리가 **이해하는가**(RFC 7672 §2.2 — 이해 못 하는 레코드는 무시).
 *
 * `checkDane`의 "쓸 수 있는 레코드가 있었나" 판정과 호출부의 "DANE를 적용할 상대인가" 판정이
 * **같은 정의**를 봐야 한다. 두 곳에 따로 쓰면 한쪽만 고쳐져 "TLS는 강제해놓고 대조는 안 하는"
 * 상태가 생긴다.
 */
function isUnderstood(rec: TlsaRecord): boolean {
  if (rec.usage !== TLSA_USAGE.DANE_TA && rec.usage !== TLSA_USAGE.DANE_EE) return false;
  if (rec.selector !== TLSA_SELECTOR.FULL_CERT && rec.selector !== TLSA_SELECTOR.SPKI) return false;
  return (
    rec.matchingType === TLSA_MATCHING.EXACT ||
    rec.matchingType === TLSA_MATCHING.SHA256 ||
    rec.matchingType === TLSA_MATCHING.SHA512
  );
}

/**
 * 이 상대에게 DANE를 적용해야 하는가 — **연결 전에** 답이 필요하다.
 *
 * ★참이면 TLS는 **필수**가 된다(RFC 7672 §2.2). 쓸 수 있는 TLSA가 있는데 평문으로 보내면
 * 상대가 애써 게시한 고정을 우리가 무시하는 것이고, 다운그레이드 공격에 그대로 노출된다.
 */
export function hasUsableTlsa(tlsa: DaneTlsaSet): boolean {
  return tlsa.dnssecValidated && tlsa.records.some(isUnderstood);
}

/** 인증서 하나에서 대조 대상 바이트를 뽑는다. */
function selectorBytes(cert: { raw: Uint8Array; spki: Uint8Array }, selector: number): Uint8Array | null {
  if (selector === TLSA_SELECTOR.FULL_CERT) return cert.raw;
  if (selector === TLSA_SELECTOR.SPKI) return cert.spki;
  return null; // 모르는 selector — 이해 못 하는 레코드는 무시한다(RFC 7672 §2.2)
}

function matchBytes(input: Uint8Array, matchingType: number): Uint8Array | null {
  if (matchingType === TLSA_MATCHING.EXACT) return input;
  if (matchingType === TLSA_MATCHING.SHA256) return new Uint8Array(createHash("sha256").update(input).digest());
  if (matchingType === TLSA_MATCHING.SHA512) return new Uint8Array(createHash("sha512").update(input).digest());
  return null;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * 제시된 인증서 체인이 TLSA 집합과 맞는지 본다.
 *
 * @param chain 상대가 제시한 체인. `[0]`이 말단(EE) 인증서다.
 *
 * ★DANE-EE(3)는 **말단만** 본다. 체인 전체에서 찾으면 중간 CA와 맞는 것을 EE로 착각해
 * 아무 인증서나 통과시킬 수 있다.
 * ★DANE-TA(2)는 체인 **어디든** 맞으면 된다 — 그게 "이 CA를 신뢰하라"는 뜻이다.
 */
export function checkDane(chain: readonly { raw: Uint8Array; spki: Uint8Array }[], tlsa: DaneTlsaSet): DaneResult {
  if (!tlsa.dnssecValidated) {
    return { status: "not-applicable", reason: "TLSA가 DNSSEC로 검증되지 않았다" };
  }
  if (tlsa.records.length === 0) return { status: "not-applicable", reason: "TLSA 없음" };
  if (chain.length === 0) return { status: "mismatch", reason: "인증서 체인이 비었다" };

  let usable = 0;
  for (const rec of tlsa.records) {
    /**
     * ★SMTP에서 PKIX-TA(0)·PKIX-EE(1)는 **쓰지 않는다**(RFC 7672 §3.1). 그 두 usage는
     * 공개 CA 신뢰를 전제하는데 SMTP MX에는 그 전제가 없다. 무시하는 것이 규격이다.
     */
    if (!isUnderstood(rec)) continue;
    usable += 1;

    const candidates = rec.usage === TLSA_USAGE.DANE_EE ? chain.slice(0, 1) : chain;

    for (const cert of candidates) {
      const sel = selectorBytes(cert, rec.selector);
      if (sel === null) continue;
      const got = matchBytes(sel, rec.matchingType);
      if (got === null) continue;
      if (bytesEqual(got, rec.data)) return { status: "match", usage: rec.usage };
    }
  }

  /**
   * ★"쓸 수 있는 레코드가 하나도 없었다"와 "있었는데 전부 안 맞았다"를 가른다.
   * 앞은 적용 대상이 아니고(무시가 규격), 뒤는 **중간자 신호**다. 뭉개면 공격이
   * "설정이 이상하네"로 보인다.
   */
  return usable === 0
    ? { status: "not-applicable", reason: "이해할 수 있는 TLSA 레코드 없음" }
    : { status: "mismatch", reason: "TLSA와 맞는 인증서가 없다" };
}

/** TLSA 조회 이름 — `_<port>._tcp.<mx호스트>`(RFC 7672 §3). */
export function tlsaQueryName(mxHost: string, port: number): string {
  return `_${port}._tcp.${mxHost.replace(/\.$/, "")}`;
}
