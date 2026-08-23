/**
 * 스팸 점수 엔진 — 여러 신호를 **가중 합산**해 하나의 조치로 바꾼다.
 *
 * 예전에는 DNSBL과 greylist가 각자 즉시 거부/지연을 결정했다. 그러면 신호 하나가 곧
 * 판정이라 **조합이 불가능**하다: "DNSBL 약한 등재 + 인증 실패 + 표시이름 위장"은 셋 다
 * 단독으로는 거부 사유가 못 되는데 합치면 명백하다. 반대로 강한 신호 하나로 거부하면
 * 오탐 한 번이 곧 메일 유실이다.
 *
 * ★조치가 **세 갈래**인 것이 이 엔진의 요점이다.
 *  - `accept` : 그대로 배달
 *  - `junk`   : 배달하되 Junk로 — **메일을 잃지 않으면서** 사용자를 보호한다
 *  - `reject` : SMTP 단계에서 거부. 발신자가 즉시 안다(조용히 버리는 것보다 정직하다)
 * 중간 갈래가 없으면 모든 판정이 "받는다/버린다"가 되고, 그때 임계값을 어디에 두든
 * 한쪽 실패가 크게 난다. 확신이 낮은 구간을 junk로 흘리는 것이 그 완충이다.
 *
 * ⚠ **조용한 폐기(silent drop)는 제공하지 않는다.** 발신자도 수신자도 모르는 유실은
 * 메일 시스템이 할 수 있는 가장 나쁜 실패다.
 */
import type { DnsblResult } from "./dnsbl.ts";
import type { RuleHit } from "./rules.ts";

export const SPAM_ACTION = { accept: "accept", junk: "junk", reject: "reject" } as const;
export type SpamAction = (typeof SPAM_ACTION)[keyof typeof SPAM_ACTION];

/** 인증 결과 요약 — `runInboundAuth`의 summary와 같은 어휘(pass/fail/none/...). */
export interface AuthSummary {
  spf?: string;
  dkim?: string;
  dmarc?: string;
}

export interface SpamSignals {
  dnsbl?: DnsblResult;
  auth?: AuthSummary;
  rules?: readonly RuleHit[];
  /**
   * 내용 기반 분류기의 스팸 확률(0..1). **선택이다.**
   *
   * ⚠ PLAN.md §3은 Bayes를 점수 엔진의 축으로 적었지만, §8 머리는 "운영자는 사용자 메일
   * 내용을 열람하지 않는다"를 원칙으로 선언한다. 본문 토큰을 학습·조회하는 분류기는 그
   * 원칙과 정면으로 부딪힌다. 그래서 여기서는 **자리만 두고 구현을 넣지 않는다** —
   * 켤지 말지는 제품 결정이지 서버가 조용히 정할 일이 아니다.
   */
  bayesSpamProbability?: number;
}

export interface SpamScoreOptions {
  /** DMARC fail 가중치(기본 3.0). SPF·DKIM 개별 fail보다 무겁다 — 정렬까지 깨진 것이다. */
  dmarcFailWeight?: number;
  /** SPF fail 가중치(기본 1.5). softfail은 절반으로 센다. */
  spfFailWeight?: number;
  /** DKIM fail 가중치(기본 1.0). 포워딩으로 깨지는 일이 흔해 낮다. */
  dkimFailWeight?: number;
  /** Bayes 확률에 곱할 상한 가중치(기본 3.0). p=1이면 이 값이 그대로 더해진다. */
  bayesWeight?: number;
  /** 이 점수 이상이면 Junk 배달(기본 5.0). */
  junkThreshold?: number;
  /** 이 점수 이상이면 거부(기본 10.0). */
  rejectThreshold?: number;
}

export interface SpamScore {
  score: number;
  action: SpamAction;
  /** 어떤 신호가 얼마를 더했는지 — 운영자가 임계값을 조정할 근거. 본문은 담기지 않는다. */
  reasons: { signal: string; weight: number; detail?: string }[];
}

const DEFAULTS = {
  dmarcFailWeight: 3.0,
  spfFailWeight: 1.5,
  dkimFailWeight: 1.0,
  bayesWeight: 3.0,
  junkThreshold: 5.0,
  rejectThreshold: 10.0,
} as const;

export function scoreSpam(signals: SpamSignals, opts: SpamScoreOptions = {}): SpamScore {
  const o = { ...DEFAULTS, ...opts };
  const reasons: SpamScore["reasons"] = [];
  let score = 0;

  const add = (signal: string, weight: number, detail?: string): void => {
    if (weight === 0) return;
    score += weight;
    reasons.push({ signal, weight, ...(detail ? { detail } : {}) });
  };

  /**
   * DNSBL — 존별 가중치는 이미 `checkDnsbl`이 합산했다. **화이트리스트 존은 음수**라
   * 여기서 점수를 낮춘다(DnsblZone.weight 주석). 그래서 `listed`가 아니라 `score`를 본다.
   */
  if (signals.dnsbl && signals.dnsbl.score !== 0) {
    add("dnsbl", signals.dnsbl.score, signals.dnsbl.hits.map((h) => h.zone).join(",") || undefined);
  }

  const auth = signals.auth;
  if (auth) {
    // ★`fail`만 센다. `none`(레코드 없음)·`temperror`를 스팸 신호로 쓰면 SPF를 게시하지 않은
    //   정상 도메인과 우리 DNS 일시 장애가 전부 스팸으로 기운다.
    if (auth.dmarc === "fail") add("dmarc-fail", o.dmarcFailWeight);
    if (auth.spf === "fail") add("spf-fail", o.spfFailWeight);
    else if (auth.spf === "softfail") add("spf-softfail", o.spfFailWeight / 2);
    if (auth.dkim === "fail") add("dkim-fail", o.dkimFailWeight);
    // 정렬된 DMARC pass는 **점수를 낮춘다** — 도메인이 자기 메일임을 증명한 것이다.
    if (auth.dmarc === "pass") add("dmarc-pass", -2.0);
  }

  for (const hit of signals.rules ?? []) add(`rule:${hit.rule}`, hit.weight, hit.detail);

  const p = signals.bayesSpamProbability;
  if (typeof p === "number" && Number.isFinite(p)) {
    const clamped = Math.min(1, Math.max(0, p));
    // 0.5를 중립으로 두고 ±로 편다 — p=0.5(모르겠다)가 점수를 움직이면 안 된다.
    add("bayes", (clamped - 0.5) * 2 * o.bayesWeight, clamped.toFixed(2));
  }

  /**
   * ★임계 비교를 `>=`로 한다. `>`면 "임계값 = 10"으로 설정한 운영자가 정확히 10점인
   * 메일을 통과시키는데, 그건 설정한 사람의 기대와 다르다.
   */
  const action: SpamAction =
    score >= o.rejectThreshold ? SPAM_ACTION.reject : score >= o.junkThreshold ? SPAM_ACTION.junk : SPAM_ACTION.accept;

  return { score: Math.round(score * 100) / 100, action, reasons };
}
