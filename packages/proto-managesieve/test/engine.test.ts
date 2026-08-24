/** ManageSieveEngine — 명령 대화·SASL·리터럴 스크립트·CRUD 액션 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { ManageSieveEngine, type ManageSieveAction } from "../src/engine.ts";
import { SUPPORTED_EXTENSION_LIST } from "@ionosphere/sieve";

const enc = new TextEncoder();
function engine(): ManageSieveEngine {
  return new ManageSieveEngine({ hostname: "sieve.test", allowInsecureAuth: true });
}
function feed(e: ManageSieveEngine, s: string): ManageSieveAction[] {
  return e.feed(enc.encode(s));
}
function texts(actions: ManageSieveAction[]): string[] {
  return actions.filter((a): a is { kind: "reply"; text: string } => a.kind === "reply").map((a) => a.text);
}
function plainB64(user: string, pass: string): string {
  return Buffer.from(`\u0000${user}\u0000${pass}`, "utf8").toString("base64");
}
/** 인증 완료 엔진. */
function authed(): ManageSieveEngine {
  const e = engine();
  feed(e, `AUTHENTICATE "PLAIN" "${plainB64("u", "p")}"\r\n`);
  e.authResult({ accountId: "acc" });
  return e;
}

describe("인사말·CAPABILITY", () => {
  test("greeting에 IMPLEMENTATION/SIEVE/SASL + OK", () => {
    const g = texts(engine().greeting());
    expect(g.some((l) => l.includes("IMPLEMENTATION"))).toBe(true);
    /**
     * ★능력줄이 **평가기가 실제로 받는 목록**과 같아야 한다. 예전엔 여기 손으로 적은 사본이
     * 있었고, `vacation`을 평가기에 추가했을 때 사본이 안 따라와 "받기는 하는데 광고하지 않는"
     * 상태가 됐다. 능력줄로 기능을 판단하는 클라이언트에겐 없는 것과 같다.
     */
    const sieveLine = g.find((l) => l.includes('"SIEVE"'));
    expect(sieveLine).toBeTruthy();
    for (const ext of SUPPORTED_EXTENSION_LIST) expect(sieveLine!.includes(ext)).toBe(true);
    expect(g.some((l) => l.includes('"SASL" "PLAIN"'))).toBe(true);
    expect(g.at(-1)).toStartWith("OK");
  });

  test("CAPABILITY 재조회", () => {
    const out = texts(feed(engine(), "CAPABILITY\r\n"));
    expect(out.at(-1)).toBe("OK");
  });

  /**
   * 제공하지 않는 것을 광고하면 클라이언트는 그것을 시도하고 실패한 뒤 자격증명을 의심한다
   * (POP3 cmdCapa가 경계하는 안티패턴). tlsAvailable=false면 STARTTLS는 어느 회선에도 안 실린다.
   */
  test("tlsAvailable 없으면 STARTTLS를 광고하지 않는다", () => {
    for (const allowInsecureAuth of [true, false]) {
      const e = new ManageSieveEngine({ hostname: "sieve.test", allowInsecureAuth });
      expect(texts(e.greeting()).some((l) => l.includes("STARTTLS"))).toBe(false);
      expect(texts(feed(e, "CAPABILITY\r\n")).some((l) => l.includes("STARTTLS"))).toBe(false);
    }
  });

  /**
   * ★L-5의 **성질**을 고정한다: 광고와 수락은 절대 어긋나지 않는다.
   *
   * L-5의 원래 결함은 "광고했는데 NO로 거절"이었고, 그 뒤 광고만 지웠더니 인증 경로가
   * 사라졌다. 어느 쪽으로도 되돌아가지 않게, 모든 구성 조합에서 두 값이 같은지 확인한다.
   */
  test("STARTTLS 광고 여부 == 수락 여부 (모든 구성 조합)", () => {
    for (const tlsAvailable of [true, false]) {
      for (const allowInsecureAuth of [true, false]) {
        for (const secure of [true, false]) {
          const e = new ManageSieveEngine({ hostname: "sieve.test", tlsAvailable, allowInsecureAuth, secure });
          const advertised = texts(e.greeting()).some((l) => l.includes("STARTTLS"));
          const accepted = feed(e, "STARTTLS\r\n").some((a) => a.kind === "startTls");
          expect(advertised).toBe(accepted);
          // 이미 TLS면 광고하지 않는다(RFC 5804 §1.7) — 조합의 기대값도 고정해 둔다.
          expect(advertised).toBe(tlsAvailable && !secure);
        }
      }
    }
  });

  test("평문 회선은 빈 SASL만 알린다", () => {
    const e = new ManageSieveEngine({ hostname: "sieve.test", allowInsecureAuth: false });
    expect(texts(e.greeting())).toContain('"SASL" ""');
  });
});

/**
 * STARTTLS (RFC 5804 §2.2) — 감사 L-5의 해법. 라이브 인증 경로가 여기 하나에 달려 있다.
 * 평문 AUTH는 fail closed로 막혀 있으므로, 이 경로가 죽으면 Sieve 관리가 불가능해진다.
 */
describe("STARTTLS", () => {
  /** 라이브 4190과 같은 구성: 평문 AUTH 차단 + STARTTLS 제공. */
  function live(): ManageSieveEngine {
    return new ManageSieveEngine({ hostname: "sieve.test", allowInsecureAuth: false, tlsAvailable: true });
  }

  test("평문 회선: STARTTLS 광고 + 빈 SASL — 인증은 막고 갈 길은 알려준다", () => {
    const g = texts(live().greeting());
    expect(g).toContain('"STARTTLS"');
    expect(g).toContain('"SASL" ""');
  });

  test("STARTTLS → OK + startTls 액션", () => {
    const out = feed(live(), "STARTTLS\r\n");
    expect(texts(out)[0]).toStartWith("OK");
    expect(out.at(-1)).toEqual({ kind: "startTls" });
  });

  test("업그레이드 후 능력 목록을 다시 보내며 SASL PLAIN이 열린다 (§2.2 재조회)", () => {
    const e = live();
    feed(e, "STARTTLS\r\n");
    const after = texts(e.tlsUpgraded());
    expect(after).toContain('"SASL" "PLAIN"');
    // 이미 TLS이므로 STARTTLS는 더 광고하지 않는다.
    expect(after.some((l) => l.includes("STARTTLS"))).toBe(false);
    expect(after.at(-1)).toStartWith("OK");
  });

  test("업그레이드 후 AUTHENTICATE PLAIN이 실제로 수락된다 — L-5 인증 경로", () => {
    const e = live();
    // 평문 구간에서는 거절돼야 한다(fail closed 유지).
    expect(texts(feed(e, `AUTHENTICATE "PLAIN" "${plainB64("u", "p")}"\r\n`))[0]).toContain("TLS required");
    feed(e, "STARTTLS\r\n");
    e.tlsUpgraded();
    expect(feed(e, `AUTHENTICATE "PLAIN" "${plainB64("u", "p")}"\r\n`)).toEqual([{ kind: "auth", user: "u", pass: "p" }]);
    expect(texts(e.authResult({ accountId: "acc" }))[0]).toStartWith("OK");
    // 인증이 살아났으므로 스크립트 관리 명령이 통한다(끝까지 확인).
    expect(feed(e, "LISTSCRIPTS\r\n")).toEqual([{ kind: "listScripts" }]);
  });

  test("이미 TLS면 STARTTLS는 NO — 광고하지 않은 것을 수락하지도 않는다", () => {
    const e = live();
    feed(e, "STARTTLS\r\n");
    e.tlsUpgraded();
    const out = feed(e, "STARTTLS\r\n");
    expect(texts(out)[0]).toStartWith("NO");
    expect(out.some((a) => a.kind === "startTls")).toBe(false);
  });

  /**
   * 고전적 STARTTLS 명령 주입(CVE-2011-0411 계열): 공격자가 `STARTTLS`와 **같은 세그먼트**에
   * 평문 명령을 덧붙이면, 서버가 그 바이트를 버리지 않을 경우 업그레이드 후에 **TLS 세션의
   * 명령인 것처럼** 실행된다. proto-smtp에 같은 회귀 테스트가 있다(starttls.test.ts I-1).
   */
  test("STARTTLS와 같은 세그먼트로 온 평문 명령은 업그레이드 후에도 실행되지 않는다", () => {
    const e = live();
    const injected = feed(e, `STARTTLS\r\nAUTHENTICATE "PLAIN" "${plainB64("attacker", "pw")}"\r\nLISTSCRIPTS\r\n`);
    // 업그레이드 전: OK와 startTls뿐. 주입분은 응답조차 나오면 안 된다.
    expect(injected.map((a) => a.kind)).toEqual(["reply", "startTls"]);

    // 업그레이드 후: 주입분이 살아 있었다면 auth/listScripts 액션이 여기서 튀어나온다.
    const after = e.tlsUpgraded();
    expect(after.some((a) => a.kind === "auth" || a.kind === "listScripts")).toBe(false);
    expect(JSON.stringify(after)).not.toContain("attacker");

    // 업그레이드 직후 정상 명령은 그대로 동작한다(방어가 기능을 막지 않는지).
    expect(feed(e, `AUTHENTICATE "PLAIN" "${plainB64("u", "p")}"\r\n`)).toEqual([{ kind: "auth", user: "u", pass: "p" }]);
  });

  /**
   * ★위 테스트만으로는 방어가 고정되지 않는다(뮤테이션으로 확인 — 실측 LEAK=true).
   *
   * 완결된 라인은 `feed`의 `awaitingTls` break가 막지만, **마지막 CRLF가 없는 미완결 라인**은
   * 리더 **내부 버퍼**에 남는다. 업그레이드 후 공격자가 CRLF만 이어 붙이면 그 명령이 완결되어
   * TLS 세션의 명령으로 실행된다. 그래서 `tlsUpgraded()`가 리더를 새로 만든다.
   * 이 케이스가 없으면 그 한 줄을 지워도 테스트가 통과한다.
   */
  test("미완결 평문 라인도 업그레이드로 폐기된다 — 리더 버퍼 잔여분", () => {
    const e = live();
    // 마지막 CRLF 없음 → 리더 버퍼에 남는다
    feed(e, `STARTTLS\r\nAUTHENTICATE "PLAIN" "${plainB64("attacker", "pw")}"`);
    e.tlsUpgraded();
    // 남아 있었다면 CRLF 하나로 완결되어 attacker 인증이 튀어나온다.
    const out = feed(e, "\r\n");
    expect(out.some((a) => a.kind === "auth")).toBe(false);
    expect(JSON.stringify(out)).not.toContain("attacker");
  });

  test("업그레이드 대기 중 도착한 바이트는 폐기된다(응답 없음)", () => {
    const e = live();
    feed(e, "STARTTLS\r\n");
    expect(feed(e, "NOOP\r\n")).toEqual([]);
  });

  /**
   * 백엔드 왕복 중에 파이프라인된 STARTTLS는 **큐에서** 꺼내진다 — `feed`의 가드를 지나온
   * 경로다. 그 뒤에 붙은 평문 명령이 drain에서 계속 실행되면 주입 방어에 구멍이 난다
   * (뮤테이션으로 확인: 큐를 비우지 않으면 주입 명령이 실제로 실행됐다).
   */
  test("백엔드 대기 중 큐에 쌓인 STARTTLS 뒤의 평문 명령은 실행되지 않는다", () => {
    const e = new ManageSieveEngine({ hostname: "sieve.test", allowInsecureAuth: true, tlsAvailable: true });
    feed(e, `AUTHENTICATE "PLAIN" "${plainB64("u", "p")}"\r\n`);
    e.authResult({ accountId: "acc" });
    // LISTSCRIPTS로 pending을 만든 뒤 같은 세그먼트에 STARTTLS + 주입 명령
    feed(e, `LISTSCRIPTS\r\nSTARTTLS\r\nDELETESCRIPT "victim"\r\n`);
    const out = e.listResult([]); // 여기서 drain이 큐를 처리한다
    expect(out.some((a) => a.kind === "startTls")).toBe(true);
    expect(out.some((a) => a.kind === "deleteScript")).toBe(false);
    expect(JSON.stringify(out)).not.toContain("victim");
    // 업그레이드 후에도 되살아나지 않는다.
    expect(JSON.stringify(e.tlsUpgraded())).not.toContain("victim");
  });

  test("평문에서 인증했더라도 업그레이드가 인증 상태를 폐기한다", () => {
    // allowInsecureAuth=true + tlsAvailable=true (dev 구성) — 평문 인증 후 업그레이드.
    const e = new ManageSieveEngine({ hostname: "sieve.test", allowInsecureAuth: true, tlsAvailable: true });
    feed(e, `AUTHENTICATE "PLAIN" "${plainB64("u", "p")}"\r\n`);
    e.authResult({ accountId: "acc" });
    feed(e, "STARTTLS\r\n");
    e.tlsUpgraded();
    // RFC 5804 §2.2: 업그레이드는 협상 상태를 버린다 — 다시 인증해야 한다.
    expect(texts(feed(e, "LISTSCRIPTS\r\n"))[0]).toContain("Authenticate first");
  });
});

describe("AUTHENTICATE PLAIN", () => {
  test("initial-response 동봉 → auth 액션 → OK", () => {
    const e = engine();
    const out = feed(e, `AUTHENTICATE "PLAIN" "${plainB64("bob", "pw")}"\r\n`);
    expect(out).toEqual([{ kind: "auth", user: "bob", pass: "pw" }]);
    expect(texts(e.authResult({ accountId: "x" }))[0]).toStartWith("OK");
  });

  test("continuation(챌린지 후 응답 라인)", () => {
    const e = engine();
    expect(texts(feed(e, 'AUTHENTICATE "PLAIN"\r\n'))).toEqual(['""']);
    const out = feed(e, `${plainB64("bob", "pw")}\r\n`);
    expect(out).toEqual([{ kind: "auth", user: "bob", pass: "pw" }]);
  });

  test("실패 → NO, 인증 전 명령 거부", () => {
    const e = engine();
    feed(e, `AUTHENTICATE "PLAIN" "${plainB64("u", "bad")}"\r\n`);
    expect(texts(e.authResult(null))[0]).toStartWith("NO");
    expect(texts(feed(e, "LISTSCRIPTS\r\n"))[0]).toContain("Authenticate first");
  });
});

describe("스크립트 CRUD 액션", () => {
  test("PUTSCRIPT — 리터럴 스크립트 본문 파싱", () => {
    const e = authed();
    const script = 'require "fileinto";\r\n';
    const out = feed(e, `PUTSCRIPT "main" {${script.length}+}\r\n${script}\r\n`);
    expect(out).toEqual([{ kind: "putScript", name: "main", content: script }]);
    expect(texts(e.opResult({ ok: true }))).toEqual(["OK"]);
  });

  test("PUTSCRIPT 검증 실패 → NO(사유)", () => {
    const e = authed();
    feed(e, `PUTSCRIPT "bad" {3+}\r\nxxx\r\n`);
    expect(texts(e.opResult({ ok: false, message: "syntax error at 1" }))[0]).toBe('NO "syntax error at 1"');
  });

  test("LISTSCRIPTS — ACTIVE 표시", () => {
    const e = authed();
    feed(e, "LISTSCRIPTS\r\n");
    const out = texts(e.listResult([{ name: "main", active: true }, { name: "old", active: false }]));
    expect(out).toEqual(['"main" ACTIVE', '"old"', "OK"]);
  });

  test("GETSCRIPT — 리터럴 응답", () => {
    const e = authed();
    feed(e, `GETSCRIPT "main"\r\n`);
    const actions = e.getResult({ ok: true, content: "keep;\r\n" });
    const bytesAction = actions.find((a) => a.kind === "replyBytes") as { kind: "replyBytes"; bytes: Uint8Array };
    const text = new TextDecoder().decode(bytesAction.bytes);
    // RFC 5804 §2.9: 리터럴 옥텟(keep;\r\n=7) 뒤 CRLF로 데이터 종료, 그다음 OK 라인
    expect(text).toBe("{7}\r\nkeep;\r\n\r\nOK\r\n");
  });

  test("GETSCRIPT 없음 → NO", () => {
    const e = authed();
    feed(e, `GETSCRIPT "nope"\r\n`);
    expect(texts(e.getResult({ ok: false }))[0]).toStartWith("NO");
  });

  test("SETACTIVE / DELETESCRIPT / RENAMESCRIPT 액션", () => {
    const e = authed();
    expect(feed(e, `SETACTIVE "main"\r\n`)).toEqual([{ kind: "setActive", name: "main" }]);
    e.opResult({ ok: true });
    expect(feed(e, `SETACTIVE ""\r\n`)).toEqual([{ kind: "setActive", name: "" }]); // 전체 비활성
    e.opResult({ ok: true });
    expect(feed(e, `DELETESCRIPT "old"\r\n`)).toEqual([{ kind: "deleteScript", name: "old" }]);
    e.opResult({ ok: true });
    expect(feed(e, `RENAMESCRIPT "a" "b"\r\n`)).toEqual([{ kind: "renameScript", from: "a", to: "b" }]);
    e.opResult({ ok: true });
  });

  test("DELETESCRIPT 활성 → NO(사유 코드)", () => {
    const e = authed();
    feed(e, `DELETESCRIPT "main"\r\n`);
    expect(texts(e.opResult({ ok: false, code: "ACTIVE", message: "cannot delete active script" }))[0]).toBe('NO (ACTIVE) "cannot delete active script"');
  });

  test("HAVESPACE — 상한 이내 OK, 초과 NO", () => {
    const e = authed();
    expect(texts(feed(e, `HAVESPACE "x" 100\r\n`))[0]).toBe("OK");
    expect(texts(feed(e, `HAVESPACE "x" 99999999\r\n`))[0]).toStartWith("NO");
  });
});

describe("NOOP·LOGOUT·파이프라이닝", () => {
  test("LOGOUT → BYE/OK + close", () => {
    const e = authed();
    const out = feed(e, "LOGOUT\r\n");
    expect(texts(out)[0]).toStartWith("OK");
    expect(out.at(-1)).toEqual({ kind: "close" });
  });

  test("백엔드 대기 중 도착 명령 버퍼링 후 순서 처리", () => {
    const e = authed();
    const first = feed(e, "LISTSCRIPTS\r\nNOOP\r\n");
    expect(first).toEqual([{ kind: "listScripts" }]); // NOOP은 대기
    const out = texts(e.listResult([]));
    expect(out).toEqual(["OK", 'OK "NOOP completed"']);
  });
});
