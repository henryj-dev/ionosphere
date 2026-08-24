/**
 * CHUNKING / BDAT (RFC 3030) + LIMITS (RFC 9422).
 *
 * ★BDAT의 위험은 **세션 동기**다. 바이트를 세어 읽는데 하나라도 어긋나면 그다음 바이트가
 * 명령 줄로 해석된다 — 그러면 데이터가 명령이 되고 명령이 데이터가 되는, 조용히 어긋나는
 * 종류의 사고다. 아래는 그 경계(0바이트 청크·여러 청크·크기 초과·RSET)를 전부 밟는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { SmtpEngine, type SmtpAction } from "../src/engine.ts";

const enc = new TextEncoder();

function makeEngine(): SmtpEngine {
  return new SmtpEngine({ hostname: "mx.test", maxSizeBytes: 1000, tlsAvailable: false });
}

function text(actions: SmtpAction[]): string {
  return actions.map((a) => (a.kind === "reply" ? a.text : "")).join("");
}

/** 배달 액션에 실린 원문 — BDAT가 이어 붙인 결과를 여기서 본다. */
function deliveredRaw(actions: SmtpAction[]): Uint8Array | null {
  const a = actions.find((x) => x.kind === "deliver");
  return a && a.kind === "deliver" ? a.raw : null;
}

/**
 * EHLO → MAIL → RCPT까지 몰아 놓는다.
 *
 * ★RCPT는 백엔드 확인이 필요해 액션을 내고 멈춘다 — `rcptResult`로 재개하지 않으면
 * 엔진이 `rcpt` 상태가 되지 않는다(순수 엔진 + 얇은 어댑터 구조의 결과다).
 */
function ready(e: SmtpEngine): void {
  e.greeting();
  e.feed(enc.encode("EHLO client.test\r\n"));
  e.feed(enc.encode("MAIL FROM:<a@x.test>\r\n"));
  e.feed(enc.encode("RCPT TO:<b@y.test>\r\n"));
  e.rcptResult({ ok: true });
}

describe("LIMITS / CHUNKING 광고", () => {
  test("EHLO가 둘 다 알린다", () => {
    const e = makeEngine();
    e.greeting();
    const t = text(e.feed(enc.encode("EHLO client.test\r\n")));
    expect(t).toContain("CHUNKING");
    expect(t).toContain("LIMITS RCPTMAX=");
  });
});

describe("BDAT", () => {
  /** ★BDAT는 dot-stuffing이 없다 — 보낸 바이트가 **그대로** 배달돼야 한다. */
  test("한 청크의 바이트가 그대로 배달된다", () => {
    const e = makeEngine();
    ready(e);
    const body = "From: a@x.test\r\nSubject: hi\r\n\r\n.dot line\r\n";
    const raw = deliveredRaw(e.feed(enc.encode(`BDAT ${body.length} LAST\r\n${body}`)));
    expect(raw).not.toBe(null);
    expect(new TextDecoder().decode(raw!)).toBe(body); // 선두 dot이 제거되지 않았다
  });

  /** ★여러 청크가 이어 붙어야 한다 — 경계에서 바이트가 새면 본문이 깨진다. */
  test("여러 청크가 이어 붙는다", () => {
    const e = makeEngine();
    ready(e);
    const a = "From: a@x.test\r\n";
    const b = "Subject: hi\r\n\r\nbody\r\n";
    const first = text(e.feed(enc.encode(`BDAT ${a.length}\r\n${a}`)));
    expect(first).toContain("250");
    expect(first).toContain("octets received");
    const raw = deliveredRaw(e.feed(enc.encode(`BDAT ${b.length} LAST\r\n${b}`)));
    expect(new TextDecoder().decode(raw!)).toBe(a + b);
  });

  /** ★청크가 소켓 경계에 걸쳐 나눠 와도 세어 읽어야 한다. */
  test("바이트가 나눠 와도 센다", () => {
    const e = makeEngine();
    ready(e);
    const body = "From: a@x.test\r\n\r\nbody\r\n";
    e.feed(enc.encode(`BDAT ${body.length} LAST\r\n${body.slice(0, 5)}`));
    const raw = deliveredRaw(e.feed(enc.encode(body.slice(5))));
    expect(new TextDecoder().decode(raw!)).toBe(body);
  });

  /** 0바이트 청크는 문법상 유효하다 — 경계 처리가 즉시 돌아야 한다. */
  test("0바이트 LAST 청크", () => {
    const e = makeEngine();
    ready(e);
    const body = "From: a@x.test\r\n\r\nbody\r\n";
    e.feed(enc.encode(`BDAT ${body.length}\r\n${body}`));
    const raw = deliveredRaw(e.feed(enc.encode("BDAT 0 LAST\r\n")));
    expect(new TextDecoder().decode(raw!)).toBe(body);
  });

  /**
   * ★크기 초과는 **읽기 전에** 안다(발신자가 크기를 말하므로) — DATA에서는 못 하던 것이다.
   * 그래도 바이트는 읽어 버려야 세션 동기가 유지된다.
   */
  test("크기를 넘으면 552이고 세션은 살아 있다", () => {
    const e = makeEngine();
    ready(e);
    const big = "x".repeat(2000);
    const out = text(e.feed(enc.encode(`BDAT ${big.length} LAST\r\n${big}`)));
    expect(out).toContain("552");
    // 다음 명령이 정상 처리된다 = 바이트가 명령으로 새지 않았다
    expect(text(e.feed(enc.encode("NOOP\r\n")))).toContain("250");
  });

  test("RCPT 전 BDAT는 503", () => {
    const e = makeEngine();
    e.greeting();
    e.feed(enc.encode("EHLO client.test\r\n"));
    expect(text(e.feed(enc.encode("BDAT 5 LAST\r\nhello")))).toContain("503");
  });

  test("문법 오류는 501", () => {
    const e = makeEngine();
    ready(e);
    expect(text(e.feed(enc.encode("BDAT\r\n")))).toContain("501");
    expect(text(e.feed(enc.encode("BDAT abc LAST\r\n")))).toContain("501");
    expect(text(e.feed(enc.encode("BDAT 5 NONSENSE\r\n")))).toContain("501");
  });

  /**
   * ★RSET이 BDAT 상태를 지워야 한다. 안 지우면 남은 청크 카운터 때문에 다음 명령의
   * 첫 바이트들이 **데이터로 먹힌다** — 세션이 조용히 어긋나는 형태다.
   */
  test("중간 RSET 뒤 세션이 정상이다", () => {
    const e = makeEngine();
    ready(e);
    e.feed(enc.encode("BDAT 100\r\n"));
    e.feed(enc.encode("x".repeat(100)));
    expect(text(e.feed(enc.encode("RSET\r\n")))).toContain("250");
    expect(text(e.feed(enc.encode("NOOP\r\n")))).toContain("250");
  });

  /** DATA는 그대로 살아 있어야 한다 — BDAT가 대체가 아니라 추가다. */
  test("DATA 경로가 그대로 동작한다", () => {
    const e = makeEngine();
    ready(e);
    expect(text(e.feed(enc.encode("DATA\r\n")))).toContain("354");
  });
});

describe("DSN 확장 파라미터 (RFC 3461)", () => {
  const deliverAction = (actions: SmtpAction[]): Extract<SmtpAction, { kind: "deliver" }> | null => {
    const a = actions.find((x) => x.kind === "deliver");
    return a && a.kind === "deliver" ? a : null;
  };

  /** 세션을 몰아 DATA까지 보내고 deliver 액션을 돌려준다. */
  function send(mailParams: string, rcptParams: string): Extract<SmtpAction, { kind: "deliver" }> | null {
    const e = makeEngine();
    e.greeting();
    e.feed(enc.encode("EHLO client.test\r\n"));
    e.feed(enc.encode(`MAIL FROM:<a@x.test>${mailParams}\r\n`));
    e.feed(enc.encode(`RCPT TO:<b@y.test>${rcptParams}\r\n`));
    e.rcptResult({ ok: true });
    e.feed(enc.encode("DATA\r\n"));
    return deliverAction(e.feed(enc.encode("From: a@x.test\r\n\r\nbody\r\n.\r\n")));
  }

  test("EHLO가 DSN을 광고한다", () => {
    const e = makeEngine();
    e.greeting();
    expect(text(e.feed(enc.encode("EHLO client.test\r\n")))).toContain("DSN");
  });

  test("NOTIFY와 ORCPT가 배달 액션까지 간다", () => {
    const d = send("", " NOTIFY=FAILURE,DELAY ORCPT=rfc822;orig@z.test")!;
    expect(d.dsn?.perRcpt?.get("b@y.test")?.notify).toBe("FAILURE,DELAY");
    expect(d.dsn?.perRcpt?.get("b@y.test")?.orcpt).toBe("rfc822;orig@z.test");
  });

  test("RET과 ENVID가 배달 액션까지 간다", () => {
    const d = send(" RET=HDRS ENVID=abc123", "")!;
    expect(d.dsn?.ret).toBe("HDRS");
    expect(d.dsn?.envid).toBe("abc123");
  });

  test("파라미터가 없으면 dsn 자체가 없다", () => {
    expect(send("", "")!.dsn).toBe(undefined);
  });

  /** ★§4.1 — `NEVER`는 단독이어야 한다. 섞여 오면 뜻이 모순이라 거절한다. */
  test("NOTIFY=NEVER를 다른 값과 섞으면 501", () => {
    const e = makeEngine();
    e.greeting();
    e.feed(enc.encode("EHLO client.test\r\n"));
    e.feed(enc.encode("MAIL FROM:<a@x.test>\r\n"));
    expect(text(e.feed(enc.encode("RCPT TO:<b@y.test> NOTIFY=NEVER,FAILURE\r\n")))).toContain("501");
  });

  test("모르는 NOTIFY 값은 501", () => {
    const e = makeEngine();
    e.greeting();
    e.feed(enc.encode("EHLO client.test\r\n"));
    e.feed(enc.encode("MAIL FROM:<a@x.test>\r\n"));
    expect(text(e.feed(enc.encode("RCPT TO:<b@y.test> NOTIFY=MAYBE\r\n")))).toContain("501");
  });

  /**
   * ★`ENVID`/`ORCPT`는 xtext다. 풀어서 헤더에 싣는데, 제어문자를 풀어 넣으면 **줄 주입**이
   * 된다 — 그래서 디코딩 단계에서 거절한다.
   */
  test("제어문자를 인코딩한 xtext는 501", () => {
    const e = makeEngine();
    e.greeting();
    e.feed(enc.encode("EHLO client.test\r\n"));
    expect(text(e.feed(enc.encode("MAIL FROM:<a@x.test> ENVID=a+0Db\r\n")))).toContain("501");
  });

  test("xtext가 풀려서 전달된다", () => {
    const d = send(" ENVID=a+2Bb", "")!; // `+2B` = '+'
    expect(d.dsn?.envid).toBe("a+b");
  });

  test("모르는 RCPT 파라미터는 504", () => {
    const e = makeEngine();
    e.greeting();
    e.feed(enc.encode("EHLO client.test\r\n"));
    e.feed(enc.encode("MAIL FROM:<a@x.test>\r\n"));
    expect(text(e.feed(enc.encode("RCPT TO:<b@y.test> NONSENSE=1\r\n")))).toContain("504");
  });

  /** ★트랜잭션 단위다 — 남기면 다음 메일이 앞 메일의 설정을 물려받는다. */
  test("RSET이 DSN 파라미터를 지운다", () => {
    const e = makeEngine();
    e.greeting();
    e.feed(enc.encode("EHLO client.test\r\n"));
    e.feed(enc.encode("MAIL FROM:<a@x.test> ENVID=first\r\n"));
    e.feed(enc.encode("RSET\r\n"));
    e.feed(enc.encode("MAIL FROM:<a@x.test>\r\n"));
    e.feed(enc.encode("RCPT TO:<b@y.test>\r\n"));
    e.rcptResult({ ok: true });
    e.feed(enc.encode("DATA\r\n"));
    const d = deliverAction(e.feed(enc.encode("From: a@x.test\r\n\r\nbody\r\n.\r\n")));
    expect(d!.dsn).toBe(undefined);
  });
});
