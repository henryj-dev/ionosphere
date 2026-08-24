/**
 * SmtpEngine 단위테스트 — 소켓 없이 스크립트된 바이트 시퀀스로 순수 상태머신 검증.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { SmtpEngine, type SmtpAction } from "../src/engine.ts";

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function text(actions: SmtpAction[]): string {
  return actions
    .filter((a): a is Extract<SmtpAction, { kind: "reply" }> => a.kind === "reply")
    .map((a) => a.text)
    .join("");
}

function makeEngine(overrides: Partial<{ hostname: string; maxSizeBytes: number; tlsAvailable: boolean }> = {}): SmtpEngine {
  return new SmtpEngine({
    hostname: "mx.example.test",
    maxSizeBytes: 1_000_000,
    tlsAvailable: false,
    ...overrides,
  });
}

/** RCPT/DATA 액션이 나오면 즉시 성공 결과를 흘려 트랜잭션을 완결시키는 헬퍼. */
function driveHappyPath(engine: SmtpEngine, actions: SmtpAction[]): { replies: string; delivered: { mailFrom: string; rcptTo: readonly string[]; raw: Uint8Array } | null } {
  let replies = "";
  let delivered: { mailFrom: string; rcptTo: readonly string[]; raw: Uint8Array } | null = null;
  let pending = actions;
  while (pending.length > 0) {
    const next: SmtpAction[] = [];
    for (const a of pending) {
      if (a.kind === "reply") replies += a.text;
      else if (a.kind === "rcpt") next.push(...engine.rcptResult({ ok: true }));
      else if (a.kind === "deliver") {
        delivered = { mailFrom: a.mailFrom, rcptTo: a.rcptTo, raw: a.raw };
        next.push(...engine.deliveryResult({ ok: true, queuedId: "q1" }));
      }
    }
    pending = next;
  }
  return { replies, delivered };
}

describe("greeting/EHLO", () => {
  test("220 배너", () => {
    const engine = makeEngine();
    const t = text(engine.greeting());
    expect(t).toBe("220 mx.example.test ESMTP ready\r\n");
  });

  test("EHLO capability 목록 — SIZE/8BITMIME/PIPELINING/ENHANCEDSTATUSCODES/SMTPUTF8, STARTTLS 없음", () => {
    const engine = makeEngine({ tlsAvailable: false });
    engine.greeting();
    const t = text(engine.feed(bytes("EHLO client.test\r\n")));
    const lines = t.split("\r\n").filter((l) => l.length > 0);
    expect(lines[0]).toBe("250-mx.example.test Hello client.test");
    expect(lines).toContain("250-SIZE 1000000");
    expect(lines).toContain("250-8BITMIME");
    expect(lines).toContain("250-PIPELINING");
    expect(lines).toContain("250-ENHANCEDSTATUSCODES");
    expect(lines).toContain("250-SMTPUTF8");
    // LIMITS(RFC 9422) — 이미 강제하는 값을 말로 알린다. CHUNKING(RFC 3030)은 BDAT다.
    expect(lines.some((l) => l.startsWith("250-LIMITS RCPTMAX="))).toBe(true);
    // 마지막 줄만 대시가 없다 — 확장이 늘 때 그 자리가 바뀌므로 이름이 아니라 형식을 본다.
    expect(lines[lines.length - 1]!.startsWith("250 ")).toBe(true);
    expect(t).toContain("CHUNKING");
    expect(t).not.toContain("STARTTLS");
  });

  test("EHLO — tlsAvailable=true면 STARTTLS 광고", () => {
    const engine = makeEngine({ tlsAvailable: true });
    engine.greeting();
    const t = text(engine.feed(bytes("EHLO client.test\r\n")));
    expect(t).toContain("STARTTLS");
  });

  test("HELO — 단일행, capability 없음", () => {
    const engine = makeEngine();
    engine.greeting();
    const t = text(engine.feed(bytes("HELO client.test\r\n")));
    expect(t).toBe("250 mx.example.test Hello client.test\r\n");
  });
});

describe("happy path 전체 트랜잭션", () => {
  test("MAIL→RCPT→DATA→dot-stuffed content→250, 백엔드에 정확한 raw 전달", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO client.test\r\n"));

    let actions = engine.feed(bytes("MAIL FROM:<alice@example.test>\r\n"));
    expect(text(actions)).toBe("250 2.1.0 OK\r\n");

    actions = engine.feed(bytes("RCPT TO:<bob@example.test>\r\n"));
    expect(actions).toHaveLength(1);
    expect(actions[0]).toEqual({ kind: "rcpt", address: "bob@example.test" });
    actions = engine.rcptResult({ ok: true });
    expect(text(actions)).toBe("250 2.1.5 bob@example.test OK\r\n");

    actions = engine.feed(bytes("DATA\r\n"));
    expect(text(actions)).toBe("354 Start mail input; end with <CRLF>.<CRLF>\r\n");

    const body = "Subject: hi\r\n\r\n..leading dot line\r\nplain line\r\n.\r\n"; // ".." → "."  , 마지막 "." 는 종료자
    actions = engine.feed(bytes(body));
    const deliverAction = actions.find((a): a is Extract<SmtpAction, { kind: "deliver" }> => a.kind === "deliver");
    expect(deliverAction).toBeDefined();
    expect(deliverAction!.mailFrom).toBe("alice@example.test");
    expect(deliverAction!.rcptTo).toEqual(["bob@example.test"]);
    const rawText = new TextDecoder().decode(deliverAction!.raw);
    expect(rawText).toBe("Subject: hi\r\n\r\n.leading dot line\r\nplain line\r\n");

    actions = engine.deliveryResult({ ok: true, queuedId: "abc123" });
    expect(text(actions)).toBe("250 2.6.0 queued as abc123\r\n");
  });

  test("dot-stuffing: 본문 중간의 외로운 '.' 라인은 종료자로만 취급되지 않고 스터핑 라인만 unstuff", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    let actions = engine.feed(bytes("RCPT TO:<c@d.test>\r\n"));
    actions = engine.rcptResult({ ok: true });
    engine.feed(bytes("DATA\r\n"));

    // ".." 라인은 unstuff되어 "." 콘텐츠 라인이 되고, 진짜 종료자는 별도의 순수 "." 라인
    const body = "line1\r\n..\r\nline3\r\n.\r\n";
    actions = engine.feed(bytes(body));
    const deliverAction = actions.find((a): a is Extract<SmtpAction, { kind: "deliver" }> => a.kind === "deliver")!;
    expect(new TextDecoder().decode(deliverAction.raw)).toBe("line1\r\n.\r\nline3\r\n");
  });

  test("<> null sender 허용", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    const actions = engine.feed(bytes("MAIL FROM:<>\r\n"));
    expect(text(actions)).toBe("250 2.1.0 OK\r\n");
  });

  test("다중 RCPT", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));

    let actions = engine.feed(bytes("RCPT TO:<r1@b.test>\r\n"));
    actions = engine.rcptResult({ ok: true });
    expect(text(actions)).toContain("r1@b.test OK");

    actions = engine.feed(bytes("RCPT TO:<r2@b.test>\r\n"));
    actions = engine.rcptResult({ ok: true });
    expect(text(actions)).toContain("r2@b.test OK");

    engine.feed(bytes("DATA\r\n"));
    actions = engine.feed(bytes("hello\r\n.\r\n"));
    const deliverAction = actions.find((a): a is Extract<SmtpAction, { kind: "deliver" }> => a.kind === "deliver")!;
    expect(deliverAction.rcptTo).toEqual(["r1@b.test", "r2@b.test"]);
  });

  test("8비트 바이트(0x80-0xFF)가 DATA 본문에서 그대로 보존됨", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test> BODY=8BITMIME\r\n"));
    let actions = engine.feed(bytes("RCPT TO:<r@b.test>\r\n"));
    actions = engine.rcptResult({ ok: true });
    engine.feed(bytes("DATA\r\n"));

    const highBytes = new Uint8Array(Array.from({ length: 128 }, (_, i) => 0x80 + i));
    const dataCmd = new Uint8Array([...bytes("X-Bin: "), ...highBytes, ...bytes("\r\n.\r\n")]);
    actions = engine.feed(dataCmd);
    const deliverAction = actions.find((a): a is Extract<SmtpAction, { kind: "deliver" }> => a.kind === "deliver")!;
    const raw = deliverAction.raw;
    // "X-Bin: " (7바이트) 다음에 128개의 하이바이트, 그다음 "\r\n"
    for (let i = 0; i < 128; i++) {
      expect(raw[7 + i]).toBe(0x80 + i);
    }
  });
});

describe("상태머신 순서 위반", () => {
  test("EHLO 전 MAIL → 503", () => {
    const engine = makeEngine();
    engine.greeting();
    const actions = engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    expect(text(actions)).toStartWith("503 ");
  });

  test("MAIL 전 RCPT → 503", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    const actions = engine.feed(bytes("RCPT TO:<a@b.test>\r\n"));
    expect(text(actions)).toStartWith("503 ");
  });

  test("RCPT 전 DATA → 503", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    const actions = engine.feed(bytes("DATA\r\n"));
    expect(text(actions)).toStartWith("503 ");
  });
});

describe("구문 오류 501", () => {
  test("MAIL FROM 괄호 없음 → 501", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    const actions = engine.feed(bytes("MAIL FROM:a@b.test\r\n"));
    expect(text(actions)).toStartWith("501 ");
  });

  test("RCPT TO 빈 주소 → 501", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    const actions = engine.feed(bytes("RCPT TO:<>\r\n"));
    expect(text(actions)).toStartWith("501 ");
  });
});

describe("SIZE 파라미터", () => {
  test("SIZE=maxSizeBytes 초과 → 552, 트랜잭션 시작 안 됨", () => {
    const engine = makeEngine({ maxSizeBytes: 100 });
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    const actions = engine.feed(bytes("MAIL FROM:<a@b.test> SIZE=200\r\n"));
    expect(text(actions)).toStartWith("552 ");
  });

  test("DATA 누적 바이트가 maxSizeBytes 초과 → 552, 배달 없음", () => {
    const engine = makeEngine({ maxSizeBytes: 20 });
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    let actions = engine.feed(bytes("RCPT TO:<r@b.test>\r\n"));
    actions = engine.rcptResult({ ok: true });
    engine.feed(bytes("DATA\r\n"));

    actions = engine.feed(bytes("this line is definitely longer than twenty bytes\r\n.\r\n"));
    const deliverAction = actions.find((a) => a.kind === "deliver");
    expect(deliverAction).toBeUndefined();
    expect(text(actions)).toStartWith("552 ");
  });
});

describe("RSET", () => {
  test("트랜잭션 중 RSET → 250, 이후 MAIL부터 다시 시작 가능", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    let actions = engine.feed(bytes("RCPT TO:<r@b.test>\r\n"));
    engine.rcptResult({ ok: true });

    actions = engine.feed(bytes("RSET\r\n"));
    expect(text(actions)).toStartWith("250 ");

    // RSET 이후 RCPT는 다시 503 (MAIL부터 다시 필요)
    actions = engine.feed(bytes("RCPT TO:<r@b.test>\r\n"));
    expect(text(actions)).toStartWith("503 ");
  });
});

describe("파이프라이닝", () => {
  test("한 번의 feed 호출에 MAIL+RCPT+DATA가 실려도 순서대로 처리", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));

    const pipelined = "MAIL FROM:<a@b.test>\r\nRCPT TO:<r@b.test>\r\nDATA\r\n";
    const actions = engine.feed(bytes(pipelined));

    // MAIL 250 응답 + RCPT 백엔드 확인 액션까지는 동기로 나옴; DATA는 RCPT 결과 이후에나 처리 가능하므로 아직 없음
    const replyTexts = actions.filter((a): a is Extract<SmtpAction, { kind: "reply" }> => a.kind === "reply").map((a) => a.text);
    expect(replyTexts[0]).toBe("250 2.1.0 OK\r\n");
    const rcptAction = actions.find((a) => a.kind === "rcpt");
    expect(rcptAction).toBeDefined();

    // RCPT 결과를 흘리면 버퍼에 쌓여있던 DATA\r\n이 이어서 처리됨(250 RCPT OK 다음에 354)
    const after = engine.rcptResult({ ok: true });
    expect(text(after)).toBe("250 2.1.5 r@b.test OK\r\n354 Start mail input; end with <CRLF>.<CRLF>\r\n");
  });
});

describe("RCPT 거부", () => {
  test("백엔드가 rcptResult(ok:false)로 거부하면 지정된 코드로 응답, rcptTo에 추가 안 됨", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    engine.feed(bytes("RCPT TO:<nouser@b.test>\r\n"));
    const actions = engine.rcptResult({ ok: false, code: 550, enhanced: "5.1.1", message: "User unknown" });
    expect(text(actions)).toBe("550 5.1.1 User unknown\r\n");
  });
});

describe("VRFY/EXPN/HELP/NOOP", () => {
  test("VRFY → 항상 252", () => {
    const engine = makeEngine();
    engine.greeting();
    const actions = engine.feed(bytes("VRFY someone\r\n"));
    expect(text(actions)).toStartWith("252 ");
  });

  test("EXPN → 502", () => {
    const engine = makeEngine();
    engine.greeting();
    const actions = engine.feed(bytes("EXPN list\r\n"));
    expect(text(actions)).toStartWith("502 ");
  });

  test("HELP → 214", () => {
    const engine = makeEngine();
    engine.greeting();
    const actions = engine.feed(bytes("HELP\r\n"));
    expect(text(actions)).toStartWith("214 ");
  });

  test("NOOP → 250", () => {
    const engine = makeEngine();
    engine.greeting();
    const actions = engine.feed(bytes("NOOP\r\n"));
    expect(text(actions)).toBe("250 2.0.0 OK\r\n");
  });
});

describe("QUIT", () => {
  test("221 응답 + close 액션", () => {
    const engine = makeEngine();
    engine.greeting();
    const actions = engine.feed(bytes("QUIT\r\n"));
    expect(text(actions)).toStartWith("221 ");
    expect(actions.some((a) => a.kind === "close")).toBe(true);
  });
});

describe("STARTTLS", () => {
  test("tlsAvailable=false면 502", () => {
    const engine = makeEngine({ tlsAvailable: false });
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    const actions = engine.feed(bytes("STARTTLS\r\n"));
    expect(text(actions)).toStartWith("502 ");
  });

  test("tlsAvailable=true — 220 + startTls 액션, 이후 EHLO에서 STARTTLS 미광고 & 재EHLO 요구", () => {
    const engine = makeEngine({ tlsAvailable: true });
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    const actions = engine.feed(bytes("STARTTLS\r\n"));
    expect(text(actions)).toBe("220 2.0.0 Ready to start TLS\r\n");
    expect(actions.some((a) => a.kind === "startTls")).toBe(true);

    engine.tlsUpgraded();
    // 업그레이드 후 MAIL은 EHLO 없이 불가 (state가 init으로 리셋됨)
    const mailActions = engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    expect(text(mailActions)).toStartWith("503 ");

    const ehloActions = engine.feed(bytes("EHLO c\r\n"));
    expect(text(ehloActions)).not.toContain("STARTTLS");
  });

  test("이미 TLS인 상태에서 STARTTLS 재시도 → 503", () => {
    const engine = makeEngine({ tlsAvailable: true });
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));
    engine.feed(bytes("STARTTLS\r\n"));
    engine.tlsUpgraded();
    engine.feed(bytes("EHLO c\r\n"));
    const actions = engine.feed(bytes("STARTTLS\r\n"));
    expect(text(actions)).toStartWith("503 ");
  });
});

describe("전체 happy-path 헬퍼로 여러 메시지 연속 처리", () => {
  test("driveHappyPath로 두 번째 메시지도 정상 처리(트랜잭션 리셋 확인)", () => {
    const engine = makeEngine();
    engine.greeting();
    engine.feed(bytes("EHLO c\r\n"));

    engine.feed(bytes("MAIL FROM:<a@b.test>\r\n"));
    let actions = engine.feed(bytes("RCPT TO:<r@b.test>\r\n"));
    actions = engine.feed(bytes("DATA\r\n")); // 아직 RCPT 결과 안 옴 — 버퍼링됨
    const rcptOutActions = engine.rcptResult({ ok: true });
    const result1 = driveHappyPath(engine, rcptOutActions);
    expect(result1.delivered).toBeNull(); // 이미 DATA 커맨드까지만 처리(354), 컨텐츠는 아직
    expect(result1.replies).toContain("354 ");

    const dataActions = engine.feed(bytes("first message\r\n.\r\n"));
    const r1 = driveHappyPath(engine, dataActions);
    expect(new TextDecoder().decode(r1.delivered!.raw)).toBe("first message\r\n");

    // 두 번째 메시지 — 트랜잭션이 깨끗이 리셋되어 있어야 함
    engine.feed(bytes("MAIL FROM:<x@y.test>\r\n"));
    const r2rcpt = engine.feed(bytes("RCPT TO:<z@y.test>\r\n"));
    const r2after = driveHappyPath(engine, r2rcpt);
    expect(r2after.replies).toContain("2.1.5");
    engine.feed(bytes("DATA\r\n"));
    const r2data = engine.feed(bytes("second message\r\n.\r\n"));
    const r2 = driveHappyPath(engine, r2data);
    expect(r2.delivered!.mailFrom).toBe("x@y.test");
    expect(r2.delivered!.rcptTo).toEqual(["z@y.test"]);
  });
});
