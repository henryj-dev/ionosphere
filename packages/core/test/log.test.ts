import { describe, expect, test } from "@ionosphere/testkit";
import { createLogger, noopLogger } from "@ionosphere/core";

describe("logger", () => {
  test("json 포맷: 한 줄 JSON + 바인딩 필드 병합", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "info", format: "json", sink: (l) => lines.push(l) });
    const child = log.child({ component: "smtp", conn: 7 });
    child.info("delivered", { rcpt: "a@b.c", size: 120 });
    child.debug("숨겨져야 함");
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.level).toBe("info");
    expect(parsed.msg).toBe("delivered");
    expect(parsed.component).toBe("smtp");
    expect(parsed.conn).toBe(7);
    expect(parsed.rcpt).toBe("a@b.c");
    expect(typeof parsed.ts).toBe("string");
  });

  test("pretty 포맷: 레벨/컴포넌트/필드 렌더링", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "debug", format: "pretty", sink: (l) => lines.push(l) });
    log.child({ component: "pop3" }).warn("auth failed", { user: "x@y.z" });
    expect(lines[0]).toMatch(/WARN {2}\[pop3\] auth failed user=x@y\.z\n$/);
  });

  test("레벨 필터링 + noop", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "error", format: "json", sink: (l) => lines.push(l) });
    log.info("no");
    log.warn("no");
    log.error("yes");
    expect(lines).toHaveLength(1);
    noopLogger.error("아무 일 없음"); // throw 안 하면 됨
  });
});

/**
 * 민감 필드 마스킹 — 로깅은 되돌릴 수 없다. 호출자 규율만으로는 "옵션 객체를 통째로
 * 넘기는 한 줄"을 막지 못하므로 로거 안에서 키 이름으로 지운다.
 */
describe("logger 마스킹", () => {
  function capture(fn: (log: ReturnType<typeof createLogger>) => void): Record<string, unknown> {
    const lines: string[] = [];
    fn(createLogger({ level: "debug", format: "json", sink: (l) => lines.push(l) }));
    return JSON.parse(lines[0]!) as Record<string, unknown>;
  }

  test("민감 키는 값이 지워지고 정상 필드는 그대로다", () => {
    const parsed = capture((log) =>
      log.info("smarthost", {
        host: "smtp.relay.test",
        user: "postmaster",
        password: "hunter2",
        apiToken: "cf-abc",
        clientSecret: "s3cr3t",
        credentials: "x",
        authorization: "Bearer y",
        masterKey: "mk",
      }),
    );
    expect(parsed.host).toBe("smtp.relay.test");
    expect(parsed.user).toBe("postmaster");
    for (const k of ["password", "apiToken", "clientSecret", "credentials", "authorization", "masterKey"]) {
      expect(parsed[k]).toBe("<redacted>");
    }
  });

  test("대소문자를 가리지 않는다", () => {
    const parsed = capture((log) => log.info("x", { PASSWORD: "a", Api_Token: "b", DKIM_KEY: "c" }));
    expect(parsed.PASSWORD).toBe("<redacted>");
    expect(parsed.Api_Token).toBe("<redacted>");
    expect(parsed.DKIM_KEY).toBe("<redacted>");
  });

  /** 실제 위협 형태 — 비밀은 보통 한 겹 감싼 옵션 객체 안에 있다. */
  test("중첩 객체·배열 안까지 내려간다", () => {
    const parsed = capture((log) =>
      log.info("boot", {
        opts: { smarthost: { host: "relay.test", password: "hunter2" }, tlsName: "mx.test" },
        endpoints: [{ url: "https://a.test/hook", secret: "whsec" }],
      }),
    );
    const opts = parsed.opts as { smarthost: Record<string, unknown>; tlsName: string };
    expect(opts.smarthost.host).toBe("relay.test");
    expect(opts.smarthost.password).toBe("<redacted>");
    expect(opts.tlsName).toBe("mx.test");
    const endpoints = parsed.endpoints as Record<string, unknown>[];
    expect(endpoints[0]!.url).toBe("https://a.test/hook");
    expect(endpoints[0]!.secret).toBe("<redacted>");
  });

  /** 오탐 회귀 — 이 이름들이 지워지면 운영 로그가 못 쓰게 된다. */
  test("정상 운영 필드는 살아남는다", () => {
    const parsed = capture((log) =>
      log.child({ component: "mta" }).info("delivered", {
        selector: "s1",
        domain: "example.test",
        rcpt: "a@b.test",
        accountId: "acc",
        mailboxId: "mb",
        attempts: 2,
        srs: true,
        submitter: "u@b.test",
      }),
    );
    expect(parsed.component).toBe("mta");
    expect(parsed.selector).toBe("s1");
    expect(parsed.domain).toBe("example.test");
    expect(parsed.rcpt).toBe("a@b.test");
    expect(parsed.accountId).toBe("acc");
    expect(parsed.mailboxId).toBe("mb");
    expect(parsed.attempts).toBe(2);
    expect(parsed.srs).toBe(true);
    expect(parsed.submitter).toBe("u@b.test");
  });

  test("child로 바인딩한 필드도 마스킹된다", () => {
    const parsed = capture((log) => log.child({ component: "webhook", secret: "whsec" }).warn("retry"));
    expect(parsed.component).toBe("webhook");
    expect(parsed.secret).toBe("<redacted>");
  });

  test("pretty 포맷도 같은 판정을 쓴다", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "info", format: "pretty", sink: (l) => lines.push(l) });
    log.info("auth", { user: "u@b.test", password: "hunter2" });
    expect(lines[0]).toContain("user=u@b.test");
    expect(lines[0]).toContain("password=<redacted>");
    expect(lines[0]).not.toContain("hunter2");
  });

  /** 재귀가 생겼으므로 순환 참조가 무한 루프가 되지 않는지 확인한다(로깅이 프로세스를 멈추면 안 된다). */
  test("순환 참조는 표식으로 끊는다", () => {
    const cyclic: Record<string, unknown> = { name: "a" };
    cyclic.self = cyclic;
    const parsed = capture((log) => log.info("cycle", { cyclic }));
    const got = parsed.cyclic as Record<string, unknown>;
    expect(got.name).toBe("a");
    expect(got.self).toBe("<circular>");
  });
});
