/**
 * 점수 엔진 + 휴리스틱 룰.
 *
 * 여기서 고정하는 것은 "스팸을 잘 잡는가"가 아니라 **"정상 메일을 잃지 않는가"**다.
 * 스팸 판정의 실패는 대칭이 아니다 — 스팸 한 통을 받는 것보다 정상 메일 한 통을 잃는 것이
 * 훨씬 나쁘다. 그래서 오탐 쪽 계약을 먼저 못박는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { parseMessage } from "@ionosphere/mime";
import { evaluateRules } from "../src/rules.ts";
import { scoreSpam, SPAM_ACTION } from "../src/score.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/** 흠 없는 정상 메일. */
const GOOD = enc(
  [
    "From: Alice <alice@example.com>",
    "To: bob@mx.test",
    "Subject: 안녕하세요",
    "Date: Mon, 07 Aug 2026 10:00:00 +0900",
    "Message-ID: <abc123@example.com>",
    "",
    "본문",
  ].join("\r\n"),
);

describe("evaluateRules — 헤더·봉투만 본다", () => {
  test("★정상 메일은 룰에 하나도 걸리지 않는다", () => {
    const hits = evaluateRules({
      parsed: parseMessage(GOOD),
      mailFrom: "alice@example.com",
      heloName: "mail.example.com",
    });
    expect(hits).toEqual([]);
  });

  test("Message-ID·Date가 없으면 잡는다", () => {
    const raw = enc("From: a@b.com\r\nTo: c@d.com\r\n\r\nbody");
    const rules = evaluateRules({ parsed: parseMessage(raw), mailFrom: "a@b.com" }).map((h) => h.rule);
    expect(rules).toContain("no-message-id");
    expect(rules).toContain("no-date");
  });

  test("★표시 이름에 다른 도메인 주소를 숨긴 것을 잡는다", () => {
    const raw = enc(
      [
        'From: "security@bank.example" <attacker@evil.example>',
        "To: v@mx.test",
        "Date: Mon, 07 Aug 2026 10:00:00 +0900",
        "Message-ID: <x@evil.example>",
        "",
        "body",
      ].join("\r\n"),
    );
    const hits = evaluateRules({ parsed: parseMessage(raw), mailFrom: "attacker@evil.example" });
    expect(hits.map((h) => h.rule)).toContain("display-name-address-mismatch");
  });

  test("★자기 주소를 표시 이름에 쓰는 정상 메일은 잡지 않는다 (오탐 방지)", () => {
    const raw = enc(
      [
        'From: "alice@example.com" <alice@example.com>',
        "To: b@mx.test",
        "Date: Mon, 07 Aug 2026 10:00:00 +0900",
        "Message-ID: <y@example.com>",
        "",
        "body",
      ].join("\r\n"),
    );
    const hits = evaluateRules({ parsed: parseMessage(raw), mailFrom: "alice@example.com" });
    expect(hits.map((h) => h.rule)).not.toContain("display-name-address-mismatch");
  });

  test("★양방향 제어문자로 주소를 위장한 From을 잡는다", () => {
    // U+202E = RIGHT-TO-LEFT OVERRIDE. **escape로만** 넣는다 — 눈에 안 보이는 문자가
    // 소스에 박히면 diff·grep이 깨지고, 그 자체가 Trojan Source 수법이다(CLAUDE.md).
    const raw = enc(
      [
        "From: =?utf-8?q?=E2=80=AEevil?= <a@evil.example>",
        "To: b@mx.test",
        "Date: Mon, 07 Aug 2026 10:00:00 +0900",
        "Message-ID: <z@evil.example>",
        "",
        "body",
      ].join("\r\n"),
    );
    const hits = evaluateRules({ parsed: parseMessage(raw), mailFrom: "a@evil.example" });
    expect(hits.map((h) => h.rule)).toContain("from-bidi-override");
  });

  test("★규격을 무시한 raw 8비트 UTF-8 bidi도 잡는다 — 안 지키는 쪽이 빠져나가면 안 된다", () => {
    // 헤더 비ASCII는 encoded-word로 와야 하고 그건 파서가 디코딩한다. 규격을 무시하고 8비트를
    // 그대로 싣는 발신자가 실제로 많은데, 그때는 U+202E가 UTF-8 3바이트로 보인다(실측).
    const rawBytes = new Uint8Array([
      ...enc("From: "),
      0xe2, 0x80, 0xae, // U+202E를 UTF-8 바이트로 직접
      ...enc("evil <a@evil.example>\r\nTo: b@mx.test\r\nDate: Mon, 07 Aug 2026 10:00:00 +0900\r\nMessage-ID: <r@e.example>\r\n\r\nbody"),
    ]);
    const hits = evaluateRules({ parsed: parseMessage(rawBytes), mailFrom: "a@evil.example" });
    expect(hits.map((h) => h.rule)).toContain("from-bidi-override");
  });

  test("메일링리스트(List-Id 있음)는 수신자 헤더 룰에서 면제된다", () => {
    const raw = enc(
      [
        "From: list@example.com",
        "List-Id: <dev.example.com>",
        "Date: Mon, 07 Aug 2026 10:00:00 +0900",
        "Message-ID: <l@example.com>",
        "",
        "body",
      ].join("\r\n"),
    );
    const hits = evaluateRules({ parsed: parseMessage(raw), mailFrom: "bounce@example.com" });
    expect(hits.map((h) => h.rule)).not.toContain("no-recipient-header");
  });
});

describe("scoreSpam — 조합해서 판정한다", () => {
  test("신호가 없으면 accept, 점수 0", () => {
    const r = scoreSpam({});
    expect(r.score).toBe(0);
    expect(r.action).toBe(SPAM_ACTION.accept);
  });

  test("★단독으로는 거부에 못 미치는 신호들이 합쳐지면 거부가 된다", () => {
    // 이게 점수 엔진의 존재 이유다 — 예전엔 신호 하나가 곧 판정이라 조합이 불가능했다.
    const r = scoreSpam({
      dnsbl: { listed: true, score: 3, hits: [{ zone: "bl.test", codes: ["2"], weight: 3 }] },
      auth: { dmarc: "fail", spf: "fail" },
      rules: [{ rule: "display-name-address-mismatch", weight: 3 }],
    });
    expect(r.score).toBeGreaterThanOrEqual(10);
    expect(r.action).toBe(SPAM_ACTION.reject);
  });

  test("★중간 구간은 junk — 메일을 잃지 않으면서 사용자를 보호한다", () => {
    // DMARC fail(3.0) + 표시이름 위장(3.0) = 6.0 — 의심스럽지만 확신은 아니다.
    // 거부하면 오탐 시 메일이 사라지고, 통과시키면 사용자가 그대로 본다. 그 사이가 junk다.
    const r = scoreSpam({
      auth: { dmarc: "fail" },
      rules: [{ rule: "display-name-address-mismatch", weight: 3 }],
    });
    expect(r.score).toBe(6);
    expect(r.action).toBe(SPAM_ACTION.junk);
  });

  test("★DMARC pass는 점수를 낮춘다 — 도메인이 자기 메일임을 증명했다", () => {
    const withPass = scoreSpam({ auth: { dmarc: "pass" }, rules: [{ rule: "no-date", weight: 1 }] });
    const without = scoreSpam({ rules: [{ rule: "no-date", weight: 1 }] });
    expect(withPass.score).toBeLessThan(without.score);
    expect(withPass.action).toBe(SPAM_ACTION.accept);
  });

  test("★인증 `none`·`temperror`는 스팸 신호가 아니다 (오탐 방지)", () => {
    // SPF를 게시하지 않은 정상 도메인과 우리 DNS 일시 장애가 스팸으로 기울면 안 된다.
    expect(scoreSpam({ auth: { spf: "none", dkim: "none", dmarc: "none" } }).score).toBe(0);
    expect(scoreSpam({ auth: { spf: "temperror", dmarc: "temperror" } }).score).toBe(0);
  });

  test("DNSWL(음수 가중치)은 점수를 낮춘다", () => {
    const r = scoreSpam({
      dnsbl: { listed: true, score: -2, hits: [{ zone: "wl.test", codes: ["1"], weight: -2 }] },
      rules: [{ rule: "no-date", weight: 1 }],
    });
    expect(r.score).toBeLessThan(0);
    expect(r.action).toBe(SPAM_ACTION.accept);
  });

  test("bayes 0.5(모르겠다)는 점수를 움직이지 않는다", () => {
    expect(scoreSpam({ bayesSpamProbability: 0.5 }).score).toBe(0);
    expect(scoreSpam({ bayesSpamProbability: 1 }).score).toBeGreaterThan(0);
    expect(scoreSpam({ bayesSpamProbability: 0 }).score).toBeLessThan(0);
  });

  test("임계값은 `>=` — 정확히 임계값이면 그 조치다", () => {
    expect(scoreSpam({ rules: [{ rule: "x", weight: 5 }] }, { junkThreshold: 5 }).action).toBe(SPAM_ACTION.junk);
    expect(scoreSpam({ rules: [{ rule: "x", weight: 10 }] }, { rejectThreshold: 10 }).action).toBe(SPAM_ACTION.reject);
  });

  test("reasons에 신호별 기여가 남는다 (임계값 조정 근거)", () => {
    const r = scoreSpam({ auth: { spf: "fail" }, rules: [{ rule: "no-date", weight: 1, detail: "d" }] });
    expect(r.reasons.map((x) => x.signal)).toEqual(["spf-fail", "rule:no-date"]);
    expect(r.reasons[1]?.detail).toBe("d");
  });
});
