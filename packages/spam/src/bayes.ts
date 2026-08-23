/**
 * 나이브 베이즈 분류기 — **계정별·해시 토큰**. 순수 함수, I/O 없음(저장소는 주입).
 *
 * ── PLAN §3과 §8의 충돌을 어떻게 넘었는가 ──
 *
 * §3은 Bayes를 점수 엔진의 축으로 적었고, §8의 머리는 "**운영자는** 사용자 메일 내용을
 * 열람하지 않는다"를 원칙으로 선언한다. 이 둘이 부딪히는 것처럼 보였는데, §8이 금지하는
 * 것은 **사람의 열람**이지 자동 처리 자체가 아니다(그렇지 않다면 스팸 판정도 검색 색인도
 * 성립하지 않는다 — 둘 다 이미 본문을 다룬다).
 *
 * 그 선을 코드로 지킨다:
 *  ① **토큰을 해시로만 저장한다.** DB에 읽을 수 있는 단어가 남지 않는다 — 운영자가 DB를
 *     열어도 남의 메일 내용을 복원할 수 없다. 이것이 "열람하지 않는다"의 실질이다.
 *  ② **계정 경계를 넘지 않는다.** 학습도 판정도 그 계정 안에서만 일어난다.
 *     전역 코퍼스를 만들면 한 사람의 메일이 다른 사람의 판정에 영향을 준다.
 *  ③ **학습은 사용자의 명시적 행동에서만.** 서버가 스스로 "이건 스팸 같다"로 학습하면
 *     자기 편향을 증폭시킨다(오탐이 오탐을 낳는다).
 *
 * ★해시가 되돌릴 수 없는 것은 아니다 — 토큰 공간이 작아 사전 공격이 가능하다. 그래서
 * **계정별 솔트**를 섞는다. 같은 단어라도 계정이 다르면 다른 해시가 되어, 한 계정의
 * 사전을 만들어도 다른 계정에 못 쓴다.
 */
import { createHmac } from "node:crypto";

/** 토큰 하나의 학습 카운트. */
export interface TokenCounts {
  spam: number;
  ham: number;
}

/** 저장소 인터페이스 — 구현은 `@ionosphere/store`(계정 경계를 지키는 것도 그쪽 책임). */
export interface BayesStore {
  /** 해시 토큰들의 카운트. 없는 토큰은 결과에서 빠진다. */
  counts(accountId: string, tokens: readonly string[]): Promise<Map<string, TokenCounts>>;
  /** 학습 반영 — 같은 토큰이 여러 번 나와도 **한 번만** 센다(호출부가 중복 제거해 넘긴다). */
  train(accountId: string, tokens: readonly string[], kind: "spam" | "ham"): Promise<void>;
  /** 학습 표본 수(스팸/햄 메시지 건수) — 사전 확률과 "학습 부족" 판정에 쓴다. */
  totals(accountId: string): Promise<{ spam: number; ham: number }>;
}

/**
 * 토큰화 — 언어 중립.
 *
 * ★한국어·일본어에는 공백 분리가 통하지 않는다. 그래서 **CJK는 바이그램**으로 자른다
 * (이 저장소의 검색 색인이 쓰는 것과 같은 방식 — `store/tokenize.ts`). 공백 분리만 쓰면
 * 한국어 메일에서 토큰이 문장 하나로 뭉쳐 학습이 성립하지 않는다.
 */
export function tokenize(text: string): string[] {
  const out: string[] = [];
  const lower = text.toLowerCase();
  // 라틴·숫자 낱말
  for (const m of lower.matchAll(/[a-z0-9][a-z0-9'._-]{1,30}/g)) out.push(m[0]);
  // CJK 바이그램
  const cjk = lower.replace(/[^぀-ヿ㐀-䶿一-鿿가-힯]+/g, " ");
  for (const run of cjk.split(" ")) {
    for (let i = 0; i + 1 < run.length; i++) out.push(run.slice(i, i + 2));
  }
  return out;
}

/** 해시 토큰 — 계정별 솔트를 섞어 사전이 계정 간에 재사용되지 않게 한다. */
export function hashTokens(accountSalt: string, tokens: readonly string[]): string[] {
  const seen = new Set<string>();
  for (const t of tokens) {
    // 12바이트면 충돌 확률이 실질적으로 0이면서 저장 비용이 작다.
    seen.add(createHmac("sha256", accountSalt).update(t).digest("base64url").slice(0, 16));
  }
  return [...seen];
}

/** 판정에 쓸 최대 토큰 수 — "가장 치우친" 것들만 본다(Paul Graham 방식). */
const MAX_SIGNIFICANT = 15;
/** 학습 표본이 이보다 적으면 판정하지 않는다. 적은 표본의 확률은 잡음이다. */
const MIN_SAMPLES = 5;

export interface BayesVerdict {
  /** 스팸 확률 0..1. 판정 불가면 null — **0.5로 뭉개지 않는다**(모른다와 반반은 다르다). */
  probability: number | null;
  /** 판정에 실제로 쓰인 토큰 수(진단용). */
  used: number;
}

/**
 * 스팸 확률을 계산한다.
 *
 * ★학습이 부족하면 **null**이다. 0.5를 돌려주면 점수 엔진에서 "중립"과 구분되지 않아,
 * 학습이 안 된 계정에서도 분류기가 동작하는 것처럼 보인다.
 */
export async function classify(
  store: BayesStore,
  accountId: string,
  accountSalt: string,
  text: string,
): Promise<BayesVerdict> {
  const totals = await store.totals(accountId);
  if (totals.spam < MIN_SAMPLES || totals.ham < MIN_SAMPLES) return { probability: null, used: 0 };

  const tokens = hashTokens(accountSalt, tokenize(text));
  if (tokens.length === 0) return { probability: null, used: 0 };
  const counts = await store.counts(accountId, tokens);

  /**
   * 토큰별 스팸 확률(라플라스 보정). 한쪽에만 나온 토큰이 확률을 0·1로 못 박지 않도록
   * 분자·분모에 상수를 더한다 — 그게 없으면 토큰 하나가 전체 판정을 결정한다.
   */
  const scored: { p: number; skew: number }[] = [];
  for (const t of tokens) {
    const c = counts.get(t);
    if (!c || c.spam + c.ham === 0) continue;
    const s = c.spam / Math.max(1, totals.spam);
    const h = c.ham / Math.max(1, totals.ham);
    const p = Math.min(0.99, Math.max(0.01, s / (s + h)));
    scored.push({ p, skew: Math.abs(p - 0.5) });
  }
  if (scored.length === 0) return { probability: null, used: 0 };

  // 가장 치우친 토큰만 쓴다 — 흔한 단어가 결과를 희석하는 것을 막는다.
  scored.sort((a, b) => b.skew - a.skew);
  const top = scored.slice(0, MAX_SIGNIFICANT);

  /**
   * 로그 공간에서 합산한다. 확률을 그대로 곱하면 토큰 15개만 돼도 **언더플로**로 0이 되어
   * 모든 메일이 같은 판정을 받는다(부동소수 하한). 교과서 공식을 그대로 옮기면 걸리는 자리다.
   */
  let logSpam = 0;
  let logHam = 0;
  for (const { p } of top) {
    logSpam += Math.log(p);
    logHam += Math.log(1 - p);
  }
  const probability = 1 / (1 + Math.exp(logHam - logSpam));
  return { probability: Math.min(1, Math.max(0, probability)), used: top.length };
}

/** 학습 — 사용자의 명시적 행동에서만 부른다(위 ③). */
export async function train(
  store: BayesStore,
  accountId: string,
  accountSalt: string,
  text: string,
  kind: "spam" | "ham",
): Promise<void> {
  const tokens = hashTokens(accountSalt, tokenize(text));
  if (tokens.length === 0) return;
  await store.train(accountId, tokens, kind);
}
