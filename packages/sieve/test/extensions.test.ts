/**
 * Sieve 확장 — `mailbox`(RFC 5490) · `subaddress`(RFC 5233).
 *
 * 두 확장이 고치는 것은 **조용한 실패**다. 없는 메일함에 `fileinto`하면 지금까지 메일이
 * INBOX로 샜고(사용자 눈에는 "규칙이 동작하지 않는다"), `bob+lists@`로 온 메일을 태그로
 * 가르려면 `:matches` 글롭을 손으로 짜야 했다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { runSieve, type SieveEnv } from "../src/interpret.ts";

function env(over: Partial<SieveEnv> = {}): SieveEnv {
  return {
    headers: new Map([
      ["from", ["Alice <alice@example.com>"]],
      ["to", ["bob@test.local"]],
    ]),
    envelopeFrom: "alice@example.com",
    envelopeTo: ["bob@test.local"],
    size: 1000,
    ...over,
  };
}

describe("mailbox 확장 (RFC 5490)", () => {
  test("fileinto :create는 생성 요청을 남긴다", () => {
    const r = runSieve('require ["fileinto", "mailbox"]; fileinto :create "Lists/Dev";', env());
    expect(r.fileinto).toEqual(["Lists/Dev"]);
    expect(r.fileintoCreate).toEqual(["Lists/Dev"]);
  });

  /** §3.2 — `:create`가 **있을 때만** 만든다. 오타 하나로 메일함이 생기지 않게 하는 장치다. */
  test(":create 없는 fileinto는 생성 요청이 아니다", () => {
    const r = runSieve('require "fileinto"; fileinto "Lists/Dev";', env());
    expect(r.fileinto).toEqual(["Lists/Dev"]);
    expect(r.fileintoCreate).toEqual([]);
  });

  test(":create와 :copy는 함께 쓸 수 있다", () => {
    const r = runSieve('require ["fileinto","mailbox","copy"]; fileinto :create :copy "Archive";', env());
    expect(r.fileintoCreate).toEqual(["Archive"]);
    expect(r.keep).toBe(true); // :copy는 암묵 keep을 유지한다
  });

  test("mailboxexists — 전부 있으면 참", () => {
    const e = env({ mailboxes: ["Work", "Lists/Dev"] });
    expect(runSieve('require ["mailbox","fileinto"]; if mailboxexists "Work" { fileinto "Work"; }', e).fileinto).toEqual(["Work"]);
    expect(runSieve('require ["mailbox","fileinto"]; if mailboxexists "Work" "Lists/Dev" { fileinto "W"; }', e).fileinto).toEqual(["W"]);
  });

  /**
   * ★"하나라도"가 아니라 "전부"다. 스크립트가 보통 `if mailboxexists ... { fileinto ... }`
   * 형태라, 일부만 있는데 참이 되면 없는 곳으로 보내 메일이 INBOX로 샌다.
   */
  test("mailboxexists — 하나라도 없으면 거짓", () => {
    const e = env({ mailboxes: ["Work"] });
    expect(runSieve('require ["mailbox","fileinto"]; if mailboxexists "Work" "Nope" { fileinto "W"; }', e).fileinto).toEqual([]);
  });

  /** 목록을 안 주면 "모른다"인데, 모를 때 있다고 답하는 것보다 없다고 답하는 쪽이 안전하다. */
  test("mailboxes 미주입이면 거짓", () => {
    expect(runSieve('require ["mailbox","fileinto"]; if mailboxexists "Work" { fileinto "W"; }', env()).fileinto).toEqual([]);
  });
});

describe("subaddress 확장 (RFC 5233)", () => {
  const withTo = (to: string): SieveEnv => env({ headers: new Map([["to", [to]]]), envelopeTo: [to] });

  test(":user / :detail 로 localpart를 나눈다", () => {
    const e = withTo("bob+lists@test.local");
    expect(runSieve('require ["subaddress","fileinto"]; if address :user :is "to" "bob" { fileinto "U"; }', e).fileinto).toEqual(["U"]);
    expect(runSieve('require ["subaddress","fileinto"]; if address :detail :is "to" "lists" { fileinto "D"; }', e).fileinto).toEqual(["D"]);
  });

  test("envelope에도 적용된다", () => {
    const e = withTo("bob+dev@test.local");
    expect(runSieve('require ["subaddress","envelope","fileinto"]; if envelope :detail :is "to" "dev" { fileinto "D"; }', e).fileinto).toEqual(["D"]);
  });

  /** 구분자가 없으면 :user는 localpart 전체, :detail은 빈 문자열이다(§4). */
  test("구분자가 없으면 user=localpart, detail=빈 문자열", () => {
    const e = withTo("bob@test.local");
    expect(runSieve('require ["subaddress","fileinto"]; if address :user :is "to" "bob" { fileinto "U"; }', e).fileinto).toEqual(["U"]);
    expect(runSieve('require ["subaddress","fileinto"]; if address :detail :is "to" "" { fileinto "D"; }', e).fileinto).toEqual(["D"]);
  });

  /**
   * ★**첫** 구분자로 자른다. 태그 안에 구분자를 넣는 서비스가 있어서, 마지막 것으로 자르면
   * 그런 주소의 태그가 잘린다.
   */
  test("구분자가 여러 개면 첫 번째로 자른다", () => {
    const e = withTo("bob+a+b@test.local");
    expect(runSieve('require ["subaddress","fileinto"]; if address :detail :is "to" "a+b" { fileinto "D"; }', e).fileinto).toEqual(["D"]);
  });

  test("구분자를 바꿀 수 있다", () => {
    const e = env({ headers: new Map([["to", ["bob-dev@test.local"]]]), subaddressDelimiter: "-" });
    expect(runSieve('require ["subaddress","fileinto"]; if address :detail :is "to" "dev" { fileinto "D"; }', e).fileinto).toEqual(["D"]);
  });

  /** :localpart는 태그를 **떼지 않는다** — 기존 스크립트의 뜻이 바뀌면 안 된다. */
  test(":localpart는 태그를 그대로 둔다", () => {
    const e = withTo("bob+lists@test.local");
    expect(runSieve('require "fileinto"; if address :localpart :is "to" "bob+lists" { fileinto "L"; }', e).fileinto).toEqual(["L"]);
  });
});
