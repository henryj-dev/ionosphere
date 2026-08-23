/**
 * 위조 헤더 제거기와 MIME 파서의 **합의** 검증 (감사 M-13).
 *
 * 이 결함의 정체는 "파서와 검사기가 같은 바이트를 다르게 읽는다"였다. strip은 자체 정규식으로
 * 헤더 블록 경계와 필드명을 판정했고, 파서는 `@ionosphere/mime`으로 판정했다. 둘이 갈라지는
 * 입력을 만들면 위조본이 strip을 통과한 뒤 파서에게는 정규 필드로 보였다.
 *
 * 도달 가능한 소비처가 있다: `backend.ts`가 `headers: parsed.headers`로 파서 결과를 Sieve
 * 실행 환경에 넘기므로, 사용자가
 *   `if header :contains "Authentication-Results" "dkim=pass" { fileinto "Trusted"; }`
 * 같은 규칙을 쓰면 공격자가 메일 하나로 DKIM을 통과한 것처럼 그 규칙을 발동시킬 수 있었다.
 *
 * 그래서 각 케이스는 **두 가지를 함께** 본다: ① 위조 바이트가 사라졌는가,
 * ② strip 결과를 파서에 통과시켰을 때 그 필드가 없는가. ②가 이 파일의 핵심이다 —
 * ①만 보면 다음에 또 다른 파싱 차이가 생겼을 때 놓친다.
 *
 * SMTP를 태우지 않고 함수를 직접 부르는 이유: 우회 3종 중 (b)는 `\n\r\n`이라는 **깨진 줄바꿈**이
 * 필요한데, 전송 계층을 거치면 정규화돼 재현되지 않는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { parseMessage } from "@ionosphere/mime";
import { stripForgedAuthResults, stripForgedReceivedSpf } from "../src/inbound-auth.ts";

const OURS = "mx.test.local";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => Buffer.from(b).toString("latin1");

/** strip 후 파서가 그 필드를 하나도 못 보는지 — strip과 파서의 합의. */
function parsedFields(raw: Uint8Array, name: string): string[] {
  return parseMessage(raw).headers.get(name) ?? [];
}

/** A-R을 지운 뒤 남은 바이트와 파서가 읽은 A-R 목록. */
function stripAr(message: string): { text: string; parsed: string[] } {
  const out = stripForgedAuthResults(enc(message), OURS);
  return { text: dec(out), parsed: parsedFields(out, "authentication-results") };
}

function stripSpf(message: string): { text: string; parsed: string[] } {
  const out = stripForgedReceivedSpf(enc(message), OURS);
  return { text: dec(out), parsed: parsedFields(out, "received-spf") };
}

const TAIL = "From: evil@remote.example\r\nSubject: forged\r\n\r\nBODY\r\n";

describe("Authentication-Results — 파서 차이를 이용한 우회 (M-13)", () => {
  test("(a) 콜론 앞 공백/탭 — 파서는 이름을 trim해서 받으므로 strip도 받아야 한다", () => {
    for (const gap of [" ", "\t", " \t "]) {
      const { text, parsed } = stripAr(`Authentication-Results${gap}: ${OURS}; dkim=pass header.d=bank.example\r\n${TAIL}`);
      expect(text).not.toContain("bank.example");
      expect(parsed).toHaveLength(0);
    }
  });

  test("(b) 헤더/본문 경계 불일치(\\n\\r\\n) — strip이 파서보다 일찍 헤더를 끝내면 안 된다", () => {
    // 자체 정규식 /\r?\n\r?\n/은 `\n\r\n`에 매치돼 11번에서 헤더가 끝났다고 봤지만,
    // splitHeaderBody는 리터럴 3종만 보므로 그 뒤까지 헤더였다 — 위조본이 그 틈에 들어갔다.
    const msg = `Subject: hi\n\r\nAuthentication-Results: ${OURS}; dkim=pass header.d=bank.example\r\n\r\nBODY\r\n`;
    const { text, parsed } = stripAr(msg);
    expect(text).not.toContain("bank.example");
    expect(parsed).toHaveLength(0);
    expect(text).toContain("BODY"); // 본문은 살아 있다
  });

  test("(c) authserv-id 후행 점 — DNS에서 같은 이름이므로 같게 본다", () => {
    const { text, parsed } = stripAr(`Authentication-Results: ${OURS}.; dmarc=pass header.from=bank.example\r\n${TAIL}`);
    expect(text).not.toContain("bank.example");
    expect(parsed).toHaveLength(0);
  });

  test("(a)+(b)+(c) 동시 — 조합해도 새는 곳이 없다", () => {
    const msg = `Subject: hi\n\r\nAuthentication-Results\t: ${OURS}..; dkim=pass header.d=bank.example\r\n\r\nBODY\r\n`;
    const { text, parsed } = stripAr(msg);
    expect(text).not.toContain("bank.example");
    expect(parsed).toHaveLength(0);
  });
});

describe("Authentication-Results — 유지 회귀(이미 되던 것)", () => {
  test("남의 authserv-id는 남는다 — 상류 MTA의 정당한 정보", () => {
    const { text, parsed } = stripAr(`Authentication-Results: upstream.example; spf=pass smtp.mailfrom=ok.example\r\n${TAIL}`);
    expect(text).toContain("upstream.example");
    expect(text).toContain("ok.example");
    expect(parsed).toHaveLength(1);
  });

  test("후행 점 정규화가 남의 id를 우리 것으로 오인하지 않는다", () => {
    const { text } = stripAr(`Authentication-Results: upstream.example.; spf=pass smtp.mailfrom=ok.example\r\n${TAIL}`);
    expect(text).toContain("ok.example");
  });

  test("대소문자·중복·폴딩·bare LF·주석은 여전히 제거된다", () => {
    const forged =
      `authentication-results:   ${OURS.toUpperCase()} ; dmarc=pass header.from=a.example\n` +
      `Authentication-Results: (주석) ${OURS};\r\n\tdmarc=pass header.from=b.example;\r\n\tspf=pass smtp.mailfrom=b.example\r\n` +
      `Authentication-Results: ${OURS}; dmarc=pass header.from=c.example\r\n`;
    const { text, parsed } = stripAr(forged + TAIL);
    for (const d of ["a.example", "b.example", "c.example"]) expect(text).not.toContain(d);
    expect(parsed).toHaveLength(0);
  });

  test("본문에 있는 헤더처럼 생긴 줄은 건드리지 않는다", () => {
    const msg = `Subject: hi\r\n\r\nAuthentication-Results: ${OURS}; dmarc=pass header.from=body.example\r\n`;
    const { text } = stripAr(msg);
    expect(text).toBe(msg);
  });
});

describe("Received-SPF — 같은 우회 3종이 재현되지 않는다", () => {
  const claim = (id: string): string =>
    `pass (${id}: domain of ceo@bank.example designates 1.2.3.4 as permitted sender) receiver=${id}; client-ip=1.2.3.4`;

  test("(a) 콜론 앞 공백/탭", () => {
    const { text, parsed } = stripSpf(`Received-SPF \t: ${claim(OURS)}\r\n${TAIL}`);
    expect(text).not.toContain("bank.example");
    expect(parsed).toHaveLength(0);
  });

  test("(b) 헤더/본문 경계 불일치(\\n\\r\\n)", () => {
    const { text, parsed } = stripSpf(`Subject: hi\n\r\nReceived-SPF: ${claim(OURS)}\r\n\r\nBODY\r\n`);
    expect(text).not.toContain("bank.example");
    expect(parsed).toHaveLength(0);
  });

  test("(c) receiver·주석 호스트의 후행 점", () => {
    const { text, parsed } = stripSpf(`Received-SPF: ${claim(`${OURS}.`)}\r\n${TAIL}`);
    expect(text).not.toContain("bank.example");
    expect(parsed).toHaveLength(0);
  });
});

describe("Received-SPF — 신원을 밝히지 않은 것은 지운다 (fail closed)", () => {
  /**
   * `Received-SPF: pass` 한 줄은 receiver도 주석도 없어 누구 것인지 확인할 방법이 없는데,
   * 헤더를 훑는 사람에게는 우리가 붙인 pass와 구별되지 않는다. 남겨 두는 쪽이 더 위험하다.
   */
  test("★receiver·주석이 없는 Received-SPF: pass는 제거된다", () => {
    const { text, parsed } = stripSpf(`Received-SPF: pass\r\n${TAIL}`);
    expect(text).not.toContain("Received-SPF");
    expect(parsed).toHaveLength(0);
  });

  test("주석이 RFC 예시 형태가 아니어서 호스트를 못 읽는 것도 제거된다", () => {
    const { parsed } = stripSpf(`Received-SPF: pass (domain of x@bank.example designates 1.2.3.4)\r\n${TAIL}`);
    expect(parsed).toHaveLength(0);
  });

  test("신원을 밝힌 상류 MTA의 Received-SPF는 남는다", () => {
    const { text, parsed } = stripSpf(
      `Received-SPF: pass (upstream.example: domain of ok@legit.example designates 5.5.5.5 as permitted sender) receiver=upstream.example\r\n${TAIL}`,
    );
    expect(text).toContain("legit.example");
    expect(parsed).toHaveLength(1);
  });
});
