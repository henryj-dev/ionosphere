/**
 * Sieve `body`(RFC 5173) · `relational`(RFC 5231) · `date`(RFC 5260) · `spamtest`(RFC 5235).
 *
 * 네 확장이 한 파일에 있는 이유: `relational`이 나머지 셋의 **쓰임새를 만든다**.
 * `spamtest`는 `:value "ge" "5"` 없이는 거의 쓸모가 없고(§2가 그렇게 적는다), `date`도
 * "이 시각 이후"를 표현하려면 관계 연산자가 필요하다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { runSieve, SieveError, type SieveEnv } from "../src/interpret.ts";
import { datePartOf, parseHeaderDate, parseZoneOffset } from "../src/date-parts.ts";

function env(over: Partial<SieveEnv> = {}): SieveEnv {
  return {
    headers: new Map([
      ["from", ["alice@example.com"]],
      ["to", ["bob@test.local"]],
      ["subject", ["hello"]],
    ]),
    envelopeFrom: "alice@example.com",
    envelopeTo: ["bob@test.local"],
    size: 1000,
    ...over,
  };
}

/** 스크립트를 돌려 fileinto 대상을 본다 — 참/거짓을 눈에 보이게 하는 가장 짧은 방법. */
function hit(script: string, e: SieveEnv): boolean {
  return runSieve(script, e).fileinto.includes("HIT");
}

describe("body (RFC 5173)", () => {
  const withBody = (text: string): SieveEnv => env({ bodyText: text });

  test(":text가 기본이고 :contains로 부분 문자열", () => {
    expect(hit('require ["body","fileinto"]; if body :contains "needle" { fileinto "HIT"; }', withBody("a needle b"))).toBe(true);
    expect(hit('require ["body","fileinto"]; if body :contains "nope" { fileinto "HIT"; }', withBody("a needle b"))).toBe(false);
  });

  test(":matches 글롭", () => {
    expect(hit('require ["body","fileinto"]; if body :matches "*needle*" { fileinto "HIT"; }', withBody("a needle b"))).toBe(true);
  });

  /** ★`:raw`는 디코드 전 원문이라 `:text`와 **다른 값**을 본다. */
  test(":raw는 원문을 본다", () => {
    const e = env({ bodyText: "decoded", bodyRaw: "encoded-blob" });
    expect(hit('require ["body","fileinto"]; if body :raw :contains "encoded" { fileinto "HIT"; }', e)).toBe(true);
    expect(hit('require ["body","fileinto"]; if body :contains "encoded" { fileinto "HIT"; }', e)).toBe(false);
  });

  test(":content는 지정한 타입의 파트만 본다", () => {
    const e = env({
      bodyParts: [
        { contentType: "text/plain", text: "plain words" },
        { contentType: "text/html", text: "<b>html words</b>" },
      ],
    });
    expect(hit('require ["body","fileinto"]; if body :content "text/html" :contains "html words" { fileinto "HIT"; }', e)).toBe(true);
    expect(hit('require ["body","fileinto"]; if body :content "text/plain" :contains "html words" { fileinto "HIT"; }', e)).toBe(false);
    // 접두사 매칭 — "text"는 둘 다 잡는다
    expect(hit('require ["body","fileinto"]; if body :content "text" :contains "html words" { fileinto "HIT"; }', e)).toBe(true);
  });

  /**
   * ★파트를 하나로 이어 붙이면 **파트 경계를 넘는 우연한 매칭**이 생긴다.
   * 아래는 "plainhtml"이 어느 파트에도 없는데 이어 붙이면 생기는 형태다.
   */
  test(":content는 파트를 이어 붙이지 않는다", () => {
    const e = env({ bodyParts: [{ contentType: "text/plain", text: "plain" }, { contentType: "text/html", text: "html" }] });
    expect(hit('require ["body","fileinto"]; if body :content "text" :contains "plainhtml" { fileinto "HIT"; }', e)).toBe(false);
  });

  test("본문이 없으면 매칭되지 않는다", () => {
    expect(hit('require ["body","fileinto"]; if body :contains "x" { fileinto "HIT"; }', env())).toBe(false);
  });

  test("키가 없으면 SieveError", () => {
    expect(() => runSieve('require ["body"]; if body :contains { keep; }', env())).toThrow();
  });
});

describe("relational (RFC 5231)", () => {
  /**
   * ★`:count`는 **값의 개수**를 센다 — 값 하나하나가 아니라(§5).
   * 인자 순서는 RFC 5228의 `header <header-names> <key-list>` 그대로다:
   * `:count "ge"`는 매치 종류이고 그 뒤가 헤더 이름, 마지막이 비교할 개수다.
   */
  test(":count는 헤더 개수를 센다", () => {
    const e = env({ headers: new Map([["received", ["a", "b", "c"]]]) });
    expect(hit('require ["relational","comparator-i;ascii-numeric","fileinto"]; if header :count "ge" "received" "3" { fileinto "HIT"; }', e)).toBe(true);
    expect(hit('require ["relational","comparator-i;ascii-numeric","fileinto"]; if header :count "gt" "received" "3" { fileinto "HIT"; }', e)).toBe(false);
  });

  test("없는 헤더의 :count는 0이다", () => {
    expect(hit('require ["relational","comparator-i;ascii-numeric","fileinto"]; if header :count "eq" "x-nope" "0" { fileinto "HIT"; }', env())).toBe(true);
  });

  test(":value는 값을 비교한다", () => {
    const e = env({ headers: new Map([["x-priority", ["3"]]]) });
    const s = (rel: string, n: string) =>
      `require ["relational","comparator-i;ascii-numeric","fileinto"]; if header :value "${rel}" :comparator "i;ascii-numeric" "x-priority" "${n}" { fileinto "HIT"; }`;
    expect(hit(s("ge", "3"), e)).toBe(true);
    expect(hit(s("lt", "3"), e)).toBe(false);
    expect(hit(s("le", "5"), e)).toBe(true);
    expect(hit(s("ne", "9"), e)).toBe(true);
  });

  /**
   * ★`i;ascii-numeric`에서 **숫자가 아닌 값은 무한대**다(RFC 4790 §9.1.1).
   * 0으로 떨어뜨리면 헤더가 이상한 메일이 `:value "lt"`에 걸려 엉뚱하게 분류된다.
   */
  test("숫자가 아닌 값은 무한대로 친다", () => {
    const e = env({ headers: new Map([["x-priority", ["urgent"]]]) });
    const s = (rel: string, n: string) =>
      `require ["relational","comparator-i;ascii-numeric","fileinto"]; if header :value "${rel}" :comparator "i;ascii-numeric" "x-priority" "${n}" { fileinto "HIT"; }`;
    expect(hit(s("lt", "5"), e)).toBe(false);
    expect(hit(s("gt", "5"), e)).toBe(true);
  });

  test("문자열 비교가 기본이다", () => {
    const e = env({ headers: new Map([["subject", ["banana"]]]) });
    expect(hit('require ["relational","fileinto"]; if header :value "gt" "subject" "apple" { fileinto "HIT"; }', e)).toBe(true);
  });

  test("모르는 관계 연산자는 SieveError", () => {
    expect(() => runSieve('require ["relational"]; if header :value "nope" "subject" "x" { keep; }', env())).toThrow(SieveError);
  });
});

describe("date-parts 단위", () => {
  const T = Date.UTC(2026, 7, 24, 15, 4, 5); // 2026-08-24T15:04:05Z (월요일)

  test("조각들이 고정 폭 문자열이다", () => {
    expect(datePartOf(T, 0, "year")).toBe("2026");
    expect(datePartOf(T, 0, "month")).toBe("08");
    expect(datePartOf(T, 0, "day")).toBe("24");
    expect(datePartOf(T, 0, "date")).toBe("2026-08-24");
    expect(datePartOf(T, 0, "hour")).toBe("15");
    expect(datePartOf(T, 0, "minute")).toBe("04");
    expect(datePartOf(T, 0, "second")).toBe("05");
    expect(datePartOf(T, 0, "time")).toBe("15:04:05");
    expect(datePartOf(T, 0, "zone")).toBe("+0000");
    expect(datePartOf(T, 0, "weekday")).toBe("1"); // 월요일
  });

  /** ★고정 폭이 아니면 `"9" < "10"`이 거짓이 되어 문자열 비교가 뒤집힌다. */
  test("한 자리 값도 0을 채운다", () => {
    expect(datePartOf(Date.UTC(2026, 0, 2, 3, 4, 5), 0, "month")).toBe("01");
    expect(datePartOf(Date.UTC(2026, 0, 2, 3, 4, 5), 0, "hour")).toBe("03");
  });

  test("오프셋이 벽시계를 옮긴다", () => {
    expect(datePartOf(T, 9 * 60, "hour")).toBe("00"); // +0900이면 다음 날 00시
    expect(datePartOf(T, 9 * 60, "day")).toBe("25");
    expect(datePartOf(T, 9 * 60, "zone")).toBe("+0900");
  });

  test("iso8601 / std11", () => {
    expect(datePartOf(T, 0, "iso8601")).toBe("2026-08-24T15:04:05Z");
    expect(datePartOf(T, 0, "std11")).toBe("Mon, 24 Aug 2026 15:04:05 +0000");
  });

  test("julian은 Modified Julian Day", () => {
    expect(datePartOf(Date.UTC(1970, 0, 1), 0, "julian")).toBe("40587");
  });

  test("parseZoneOffset", () => {
    expect(parseZoneOffset("+0900")).toBe(540);
    expect(parseZoneOffset("-0500")).toBe(-300);
    expect(parseZoneOffset("nonsense")).toBe(null);
  });

  test("parseHeaderDate는 오프셋을 따로 돌려준다", () => {
    const r = parseHeaderDate("Mon, 24 Aug 2026 15:04:05 +0900")!;
    expect(r.offsetMinutes).toBe(540);
    expect(new Date(r.ms).toISOString()).toBe("2026-08-24T06:04:05.000Z");
    expect(parseHeaderDate("어제")).toBe(null);
  });
});

describe("date / currentdate (RFC 5260)", () => {
  const DATE_HDR = "Mon, 24 Aug 2026 15:04:05 +0900";
  const e = (): SieveEnv => env({ headers: new Map([["date", [DATE_HDR]]]), now: Date.UTC(2026, 7, 24, 15, 4, 5) });

  test("헤더의 date-part를 비교한다", () => {
    expect(hit('require ["date","fileinto"]; if date "date" "year" "2026" { fileinto "HIT"; }', e())).toBe(true);
    expect(hit('require ["date","fileinto"]; if date "date" "year" "2020" { fileinto "HIT"; }', e())).toBe(false);
  });

  /** ★`:originalzone`은 **메일에 적힌 시간대**로 조각을 낸다(§3) — UTC로 환산하면 안 된다. */
  test(":originalzone과 기본(UTC)이 다른 값을 낸다", () => {
    expect(hit('require ["date","fileinto"]; if date :originalzone "date" "hour" "15" { fileinto "HIT"; }', e())).toBe(true);
    expect(hit('require ["date","fileinto"]; if date "date" "hour" "06" { fileinto "HIT"; }', e())).toBe(true);
  });

  test(":zone으로 시간대를 지정한다", () => {
    expect(hit('require ["date","fileinto"]; if date :zone "+0900" "date" "hour" "15" { fileinto "HIT"; }', e())).toBe(true);
  });

  /** 헤더가 없거나 못 읽으면 **거짓**이다 — 지어낸 시각으로 분류하면 안 된다. */
  test("Date 헤더가 없으면 거짓", () => {
    expect(hit('require ["date","fileinto"]; if date "date" "year" "2026" { fileinto "HIT"; }', env())).toBe(false);
    expect(hit('require ["date","fileinto"]; if date "date" "year" "2026" { fileinto "HIT"; }', env({ headers: new Map([["date", ["어제"]]]) }))).toBe(false);
  });

  test("currentdate는 주입된 now를 본다", () => {
    expect(hit('require ["date","fileinto"]; if currentdate "year" "2026" { fileinto "HIT"; }', e())).toBe(true);
    expect(hit('require ["date","fileinto"]; if currentdate "date" "2026-08-24" { fileinto "HIT"; }', e())).toBe(true);
  });

  /** relational과 함께 쓰는 것이 실제 쓰임새다 — "업무 시간 이후" 같은 규칙. */
  test("relational과 함께 — 시각 범위", () => {
    const script =
      'require ["date","relational","comparator-i;ascii-numeric","fileinto"];' +
      ' if currentdate :value "ge" :comparator "i;ascii-numeric" "hour" "12" { fileinto "HIT"; }';
    expect(hit(script, e())).toBe(true);
  });

  test("모르는 date-part는 SieveError", () => {
    expect(() => runSieve('require ["date"]; if currentdate "nonsense" "x" { keep; }', e())).toThrow(SieveError);
  });

  test("잘못된 :zone은 SieveError", () => {
    expect(() => runSieve('require ["date"]; if currentdate :zone "nonsense" "year" "2026" { keep; }', e())).toThrow(SieveError);
  });
});

describe("spamtest (RFC 5235)", () => {
  const s = (rel: string, n: string) =>
    `require ["spamtest","relational","comparator-i;ascii-numeric","fileinto"]; if spamtest :value "${rel}" "${n}" { fileinto "HIT"; }`;

  /** ★`"0"`은 **검사 안 함**이고 `"1"`이 "확실히 스팸 아님"이다 — 섞으면 미검사가 통과한다. */
  test("검사하지 않았으면 0이다", () => {
    expect(hit(s("eq", "0"), env())).toBe(true);
    expect(hit(s("ge", "1"), env())).toBe(false);
  });

  test("점수를 비교한다", () => {
    expect(hit(s("ge", "5"), env({ spamScore: 6 }))).toBe(true);
    expect(hit(s("ge", "7"), env({ spamScore: 6 }))).toBe(false);
    expect(hit(s("eq", "1"), env({ spamScore: 1 }))).toBe(true);
  });

  /** ★비교자를 안 줘도 숫자로 본다 — 문자열이면 `"10" < "5"`가 참이 되어 뜻이 뒤집힌다. */
  test("비교자 없이도 숫자로 비교한다", () => {
    expect(hit('require ["spamtest","relational","fileinto"]; if spamtest :value "gt" "5" { fileinto "HIT"; }', env({ spamScore: 10 }))).toBe(true);
  });

  test(":percent는 0~100 눈금", () => {
    const p = (rel: string, n: string) =>
      `require ["spamtest","relational","comparator-i;ascii-numeric","fileinto"]; if spamtest :percent :value "${rel}" "${n}" { fileinto "HIT"; }`;
    expect(hit(p("eq", "0"), env({ spamScore: 1 }))).toBe(true); // 1 → 0%
    expect(hit(p("eq", "100"), env({ spamScore: 10 }))).toBe(true); // 10 → 100%
  });

  test("값이 없으면 SieveError", () => {
    expect(() => runSieve('require ["spamtest","relational"]; if spamtest :value "ge" { keep; }', env())).toThrow();
  });
});
