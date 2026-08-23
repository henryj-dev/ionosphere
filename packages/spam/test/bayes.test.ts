/**
 * 나이브 베이즈 분류기.
 *
 * 여기서 고정하는 것:
 *  ① **학습 부족은 `null`** — 0.5로 뭉개면 점수 엔진에서 "중립"과 구분되지 않아,
 *     학습 안 된 계정에서도 분류기가 도는 것처럼 보인다
 *  ② **언더플로 없음** — 확률을 그대로 곱하면 토큰 몇 개만으로 0이 되어 모든 메일이
 *     같은 판정을 받는다(교과서 공식을 그대로 옮기면 걸리는 자리)
 *  ③ **계정 경계·해시** — 같은 단어라도 계정이 다르면 다른 토큰이 된다
 *  ④ **CJK 토큰화** — 공백 분리만 쓰면 한국어 메일에서 학습이 성립하지 않는다
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { classify, hashTokens, tokenize, train, type BayesStore, type TokenCounts } from "../src/bayes.ts";

/** 메모리 저장소 — 계약만 만족하면 되므로 DB 없이 검증한다. */
function memStore(): BayesStore & { dump: () => Map<string, TokenCounts> } {
  const tokens = new Map<string, Map<string, TokenCounts>>();
  const totals = new Map<string, { spam: number; ham: number }>();
  return {
    dump: () => tokens.get("acct") ?? new Map(),
    async counts(accountId, want) {
      const t = tokens.get(accountId) ?? new Map<string, TokenCounts>();
      const out = new Map<string, TokenCounts>();
      for (const k of want) {
        const c = t.get(k);
        if (c) out.set(k, c);
      }
      return out;
    },
    async train(accountId, toks, kind) {
      const t = tokens.get(accountId) ?? new Map<string, TokenCounts>();
      for (const k of toks) {
        const c = t.get(k) ?? { spam: 0, ham: 0 };
        if (kind === "spam") c.spam += 1;
        else c.ham += 1;
        t.set(k, c);
      }
      tokens.set(accountId, t);
      const tot = totals.get(accountId) ?? { spam: 0, ham: 0 };
      if (kind === "spam") tot.spam += 1;
      else tot.ham += 1;
      totals.set(accountId, tot);
    },
    async totals(accountId) {
      return totals.get(accountId) ?? { spam: 0, ham: 0 };
    },
  };
}

const SALT = "acct-salt";

describe("tokenize", () => {
  test("라틴 낱말을 뽑는다", () => {
    expect(tokenize("Buy CHEAP pills now")).toContain("cheap");
    expect(tokenize("Buy CHEAP pills now")).toContain("pills");
  });

  test("★한국어는 바이그램으로 자른다 — 공백 분리만으로는 학습이 성립하지 않는다", () => {
    const t = tokenize("무료 대출 상담");
    expect(t).toContain("무료");
    expect(t).toContain("대출");
    // 문장 하나가 통째로 토큰이 되면 안 된다.
    expect(t.every((x) => x.length <= 31)).toBe(true);
  });

  test("빈 입력은 빈 배열", () => {
    expect(tokenize("")).toEqual([]);
  });
});

describe("hashTokens", () => {
  test("★계정 솔트가 다르면 같은 단어도 다른 토큰이 된다 — 사전이 계정 간에 재사용되지 않는다", () => {
    const a = hashTokens("salt-a", ["viagra"]);
    const b = hashTokens("salt-b", ["viagra"]);
    expect(a[0]).not.toBe(b[0]);
  });

  test("같은 솔트·같은 단어면 결정적, 중복은 한 번만", () => {
    expect(hashTokens(SALT, ["x", "x", "y"])).toHaveLength(2);
    expect(hashTokens(SALT, ["x"])[0]).toBe(hashTokens(SALT, ["x"])[0]);
  });

  test("★해시라 원문이 남지 않는다 — DB를 열어도 단어를 못 읽는다", () => {
    const [h] = hashTokens(SALT, ["confidential-word"]);
    expect(h).not.toContain("confidential");
    expect(h!.length).toBe(16);
  });
});

describe("classify", () => {
  test("★학습이 부족하면 null — 0.5가 아니다", async () => {
    const s = memStore();
    expect((await classify(s, "acct", SALT, "anything")).probability).toBeNull();
    // 표본 하한(각 5)에 못 미치면 계속 null이다.
    for (let i = 0; i < 4; i++) await train(s, "acct", SALT, "spam text", "spam");
    for (let i = 0; i < 4; i++) await train(s, "acct", SALT, "ham text", "ham");
    expect((await classify(s, "acct", SALT, "spam text")).probability).toBeNull();
  });

  test("★학습 뒤에는 스팸/햄을 가른다", async () => {
    const s = memStore();
    for (let i = 0; i < 10; i++) await train(s, "acct", SALT, "무료 대출 상담 지금 신청 viagra cheap", "spam");
    for (let i = 0; i < 10; i++) await train(s, "acct", SALT, "회의 일정 공유드립니다 meeting agenda", "ham");

    const spam = await classify(s, "acct", SALT, "무료 대출 지금 viagra");
    const ham = await classify(s, "acct", SALT, "회의 일정 meeting");
    expect(spam.probability).not.toBeNull();
    expect(ham.probability).not.toBeNull();
    expect(spam.probability!).toBeGreaterThan(0.5);
    expect(ham.probability!).toBeLessThan(0.5);
  });

  test("★토큰이 많아도 언더플로로 0이 되지 않는다", async () => {
    const s = memStore();
    // 서로 다른 토큰을 잔뜩 학습시켜 곱셈이 길어지게 한다.
    const long = Array.from({ length: 200 }, (_, i) => `w${i}`).join(" ");
    for (let i = 0; i < 10; i++) await train(s, "acct", SALT, long, "spam");
    for (let i = 0; i < 10; i++) await train(s, "acct", SALT, "다른 내용 completely different", "ham");

    const r = await classify(s, "acct", SALT, long);
    expect(r.probability).not.toBeNull();
    // 확률을 그대로 곱하면 여기서 0(또는 NaN)이 나온다. 로그 공간이라 유한하다.
    expect(Number.isFinite(r.probability!)).toBe(true);
    expect(r.probability!).toBeGreaterThan(0);
  });

  test("학습에 없는 내용은 판정하지 않는다(null)", async () => {
    const s = memStore();
    for (let i = 0; i < 10; i++) await train(s, "acct", SALT, "aaa bbb", "spam");
    for (let i = 0; i < 10; i++) await train(s, "acct", SALT, "ccc ddd", "ham");
    expect((await classify(s, "acct", SALT, "zzzz yyyy")).probability).toBeNull();
  });

  test("★다른 계정의 학습이 새어 들어오지 않는다", async () => {
    const s = memStore();
    for (let i = 0; i < 10; i++) await train(s, "other", SALT, "무료 대출 viagra", "spam");
    for (let i = 0; i < 10; i++) await train(s, "other", SALT, "회의 일정", "ham");
    // acct는 아무것도 배우지 않았다.
    expect((await classify(s, "acct", SALT, "무료 대출 viagra")).probability).toBeNull();
  });
});
