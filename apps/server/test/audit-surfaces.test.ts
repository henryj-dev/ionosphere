/**
 * 접근 감사 로그 — **표면별 배선** 검증.
 *
 * 왜 조립층에서 테스트하는가: 이벤트 타입(`core/audit.ts`)·파일 싱크·이관 워커는 각자 단위
 * 테스트가 있다. 여기서 잡으려는 결함은 그것들이 **실제 세션에서 연결되어 있는가**다 —
 * 옵션 하나가 빠져도 타입은 통과하고, 리스너는 `noopAuditSink`로 조용히 굳는다.
 * 그게 이 저장소의 반복 사고라(과거 JMAP만 레이트리밋을 우회, 143·110이 TLS 재적재에서 누락),
 * 표면마다 실소켓/실HTTP 세션을 열어 이벤트가 나오는지 본다.
 *
 * 특히 고정하는 갈래(예전에 로그가 **한 줄도 없던** 자리들):
 *  ① 스로틀 차단 — 백엔드를 부르지 않고 조기 반환하던 갈래. 공격 활동이 가장 잘 드러나는 곳
 *  ② JMAP 인증 캐시 히트 — `authenticate()`에 훅을 걸면 30초간의 요청이 전부 누락된다
 *  ③ ManageSieve·관리 REST — 표면 자체가 무기록이었다
 *  ④ 감사 로그에 메일 본문/스크립트 본문이 실리지 않는지(실리면 감사 로그가 메일 사본이 된다)
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AUDIT_OUTCOME, AUDIT_SURFACE, auditDayUtc, type AuditEvent } from "@ionosphere/core";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver, smtpDeliver } from "./helpers.ts";

const PASS = "audit-surface-pw";
const USER = "you@test.local";
const ROOT = "root-token-for-audit-test";

let app: IonosphereApp;
let blobRoot: string;
let auditDir: string;
/**
 * 지금까지 **파일에 실제로 쓰인** 이벤트.
 *
 * ★훅을 가로채지 않고 파일을 읽는 이유: 여기서 확인할 것은 "표면이 `record()`를 불렀는가"가
 * 아니라 **기록이 실제로 남았는가**다. 직렬화(`formatAuditLine`)까지 통과해야 감사 로그가
 * 되므로, 중간을 훔쳐보면 파일에는 없는데 테스트만 통과하는 구멍이 생긴다.
 */
let events: AuditLine[] = [];

/**
 * **파일에 적힌 형태**의 이벤트. `AuditEvent`와 한 군데가 다르다: `ts`가 epoch 정수가 아니라
 * ISO 문자열이다(`formatAuditLine`). 사람이 `mc cat`으로 읽는 파일이라 그렇게 굳혔고,
 * 그 차이를 타입으로 드러내 두지 않으면 이 테스트가 메모리 형태를 검사하는 것처럼 읽힌다.
 */
type AuditLine = Omit<AuditEvent, "ts"> & { ts: string };

/**
 * 버퍼를 강제로 내리고 파일 전체를 다시 읽는다.
 *
 * flush 간격을 60초로 둔 것과 짝이다 — 주기를 기다리면 테스트가 느려지고 타이밍 플레이크가
 * 생기므로, 검사 직전에 명시적으로 내린다(`flush()`는 공개 계약이다).
 */
async function refresh(): Promise<void> {
  await app.auditSink!.flush();
  const day = auditDayUtc(Date.now());
  const lines: AuditLine[] = [];
  // 자정을 넘겨 두 날짜 파일이 생길 수 있다 — 어제 것까지 읽는다(경계에서 이벤트를 놓치지 않게).
  for (const d of [auditDayUtc(Date.now() - 24 * 60 * 60 * 1000), day]) {
    const path = join(auditDir, `audit-${d}.jsonl`);
    if (!existsSync(path)) continue;
    for (const line of readFileSync(path, "utf8").split("\n")) {
      if (line.trim() !== "") lines.push(JSON.parse(line) as AuditLine);
    }
  }
  events = lines;
}

const openClients: Socket[] = [];

/** 줄 단위 클라이언트 — imap-e2e.test.ts와 같은 패턴(부분 세그먼트·응답 붙음 처리). */
function lineClient(port: number): {
  send: (s: string) => void;
  read: (until?: (l: string) => boolean) => Promise<string[]>;
  close: () => void;
} {
  const socket = connect(port, "127.0.0.1");
  openClients.push(socket);
  let buffer = "";
  const lines: string[] = [];
  const waiters: { until: (l: string) => boolean; resolve: (ls: string[]) => void }[] = [];
  const tryResolve = (): void => {
    while (waiters.length > 0) {
      const w = waiters[0]!;
      const i = lines.findIndex((l) => w.until(l));
      if (i < 0) return;
      waiters.shift();
      w.resolve(lines.splice(0, i + 1));
    }
  };
  socket.on("data", (chunk) => {
    buffer += chunk.toString("latin1");
    let idx: number;
    while ((idx = buffer.indexOf("\r\n")) >= 0) {
      lines.push(buffer.slice(0, idx));
      buffer = buffer.slice(idx + 2);
    }
    tryResolve();
  });
  return {
    send: (s) => socket.write(s),
    read: (until = () => true) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("read timeout")), 4000);
        waiters.push({
          until,
          resolve: (ls) => {
            clearTimeout(timer);
            resolve(ls);
          },
        });
        tryResolve();
      }),
    close: () => socket.destroy(),
  };
}

/** 특정 표면의 이벤트만. */
function bySurface(surface: string): AuditLine[] {
  return events.filter((e) => e.surface === surface);
}

/** 표면+action 조합 하나를 집어온다(없으면 undefined — 호출부가 expect로 드러낸다). */
function find(surface: string, action: string): AuditLine | undefined {
  return events.find((e) => e.surface === surface && e.action === action);
}

/** SASL PLAIN — 구분자는 NUL. 소스에 리터럴 제어문자를 두지 않는다(CLAUDE.md 규약). */
const NUL = String.fromCharCode(0);
function plainB64(user: string, pass: string): string {
  return Buffer.from(`${NUL}${user}${NUL}${pass}`, "utf8").toString("base64");
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-audit-surf-"));
  auditDir = mkdtempSync(join(tmpdir(), "ionosphere-audit-dir-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    // 여섯 표면을 한 프로세스에 모두 띄운다 — 하나라도 배선이 빠지면 그 describe가 실패한다.
    smtpPort: 0,
    pop3Port: 0,
    imapPort: 0,
    submissionPort: 0,
    manageSievePort: 0,
    jmapPort: 0,
    lmtpPort: 0,
    adminPort: 0,
    adminRootToken: ROOT,
    // flush 주기는 길게 두고 검사 직전에 `refresh()`가 강제로 내린다(주기 대기 = 플레이크).
    audit: { dir: auditDir, flushIntervalMs: 60_000, shipIntervalMs: 60_000 },
    resolver: offlineResolver(),
  });
  await app.start();
  await app.createUser(USER, PASS);
  // 배선이 끊겼으면 여기서 즉시 드러난다 — 아래 테스트가 "이벤트 0건"으로 헤매지 않게.
  if (!app.auditSink) throw new Error("auditSink가 없다 — audit 옵션 배선이 끊겼다");
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  for (const c of openClients) c.destroy();
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
  rmSync(auditDir, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("접근 감사 — IMAP(143)", () => {
  test("인증 성공에 IP·사용자·credKind가 남고, 명령도 기록된다", async () => {
    const c = lineClient(app.imapPort);
    await c.read((l) => l.startsWith("* OK"));
    c.send(`a1 LOGIN ${USER} ${PASS}\r\n`);
    await c.read((l) => l.startsWith("a1 "));
    c.send("a2 SELECT INBOX\r\n");
    await c.read((l) => l.startsWith("a2 "));
    c.close();

    await refresh();
    const auth = find(AUDIT_SURFACE.imap, "auth");
    expect(auth?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(auth?.user).toBe(USER);
    // ★이 작업의 원래 목적. 예전에는 로그에 IP가 아예 없어서 인증 실패의 출처를 짚을 수 없었다.
    expect(auth?.ip).toBe("127.0.0.1");
    expect(auth?.accountId).toBeTruthy();
    // 기본 비밀번호로 로그인했으므로 credKind가 그것을 가리켜야 한다.
    expect(auth?.credKind).toBe("password");

    const select = find(AUDIT_SURFACE.imap, "selectMailbox");
    expect(select?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(select?.detail?.mailbox).toBe("INBOX");
    expect(select?.accountId).toBe(auth?.accountId);
  });

  test("인증 실패는 fail로, 사용자명은 남고 비밀번호는 어디에도 없다", async () => {
    const c = lineClient(app.imapPort);
    await c.read((l) => l.startsWith("* OK"));
    c.send(`b1 LOGIN ${USER} totally-wrong-secret\r\n`);
    await c.read((l) => l.startsWith("b1 "));
    c.close();

    await refresh();
    const fails = bySurface(AUDIT_SURFACE.imap).filter((e) => e.action === "auth" && e.outcome === AUDIT_OUTCOME.fail);
    expect(fails.length).toBeGreaterThan(0);
    expect(fails.at(-1)!.user).toBe(USER);
    /**
     * ★비밀번호가 감사 로그에 새지 않는지 **전체 이벤트를 훑어** 확인한다.
     * `auth-throttle.ts`와 같은 규율: 감사 계층은 비밀번호를 애초에 받지 않는 것으로 안전을
     * 확보한다. 표준 로거의 `SENSITIVE_KEY_PARTS` 마스킹을 경유하지 않으므로(경유하면 credKind가
     * `<redacted>`가 된다) 이 검사가 그 방어의 대체물이다.
     */
    expect(JSON.stringify(events)).not.toContain("totally-wrong-secret");
    expect(JSON.stringify(events)).not.toContain(PASS);
  });

  test("APPEND는 메일 본문을 남기지 않고 크기만 남긴다", async () => {
    const body = "Subject: audit-secret-subject\r\n\r\nthis-body-must-not-be-logged\r\n";
    const c = lineClient(app.imapPort);
    await c.read((l) => l.startsWith("* OK"));
    c.send(`c1 LOGIN ${USER} ${PASS}\r\n`);
    await c.read((l) => l.startsWith("c1 "));
    c.send(`c2 APPEND INBOX {${Buffer.byteLength(body)}}\r\n`);
    await c.read((l) => l.startsWith("+"));
    c.send(body + "\r\n");
    await c.read((l) => l.startsWith("c2 "));
    c.close();

    await refresh();
    const append = find(AUDIT_SURFACE.imap, "appendMessage");
    expect(append?.detail?.mailbox).toBe("INBOX");
    expect(append?.detail?.bytes).toBe(Buffer.byteLength(body));
    /**
     * ★본문이 실리면 감사 로그가 **메일 사본**이 되고, 보존기간·접근권한 설계가 전부 어긋난다
     * (그 파일은 오브젝트 스토리지로도 올라간다). `auditDetailOf`가 허용 목록인 이유가 이것이다.
     */
    expect(JSON.stringify(events)).not.toContain("this-body-must-not-be-logged");
  });

  /**
   * ★**SCRAM 증명 실패**가 기록되는지 — 예전에 이 갈래가 **무기록이었다**.
   *
   * SCRAM 검증은 순수 계산이라 백엔드 왕복이 없다. 그래서 실패가 `auth`도 `authVerified`도
   * 거치지 않고 거절 응답만 내고 끝났고, 어댑터의 `recordFailure`·`record`가 실행되지 않았다.
   * 라이브 IMAP 993이 SCRAM을 광고하므로 **무제한 대입이 로그 한 줄 없이** 가능한 상태였다.
   *
   * 여기서 proof를 계산하지 않는 이유: 실패만 만들면 되므로 아무 바이트나 보내면 된다.
   * (성공 경로는 `scram-e2e.test.ts`가 실제 계산으로 덮는다.)
   */
  test("★SCRAM 증명 실패도 기록된다 — 예전엔 이 갈래가 로그 한 줄도 남기지 않았다", async () => {
    const before = bySurface(AUDIT_SURFACE.imap).filter(
      (e) => e.action === "auth" && e.outcome === AUDIT_OUTCOME.fail,
    ).length;

    const cn = "auditscramnonce";
    const c = lineClient(app.imapPort);
    await c.read((l) => l.startsWith("* OK"));
    // client-first(SASL-IR) — 존재하는 계정으로, 증명만 틀리게 한다.
    c.send(`s1 AUTHENTICATE SCRAM-SHA-256 ${Buffer.from(`n,,n=${USER},r=${cn}`).toString("base64")}\r\n`);
    const first = await c.read((l) => l.startsWith("+ "));
    const serverFirst = Buffer.from(first.at(-1)!.slice(2), "base64").toString();
    const full = /r=([^,]+)/.exec(serverFirst)![1]!;
    // 어떤 비밀번호로도 맞을 수 없는 proof.
    const bogus = Buffer.alloc(32, 11).toString("base64");
    c.send(`${Buffer.from(`c=biws,r=${full},p=${bogus}`).toString("base64")}\r\n`);
    await c.read((l) => l.startsWith("s1 "));
    c.close();

    await refresh();
    const fails = bySurface(AUDIT_SURFACE.imap).filter(
      (e) => e.action === "auth" && e.outcome === AUDIT_OUTCOME.fail,
    );
    expect(fails.length).toBe(before + 1);
    const last = fails.at(-1)!;
    expect(last.user).toBe(USER);
    expect(last.ip).toBe("127.0.0.1");
    // 메커니즘이 남아야 한다 — SCRAM 대입과 평문 대입은 대응이 다르다.
    expect(last.detail?.mechanism).toBe("SCRAM-SHA-256");
  });
});

describe("접근 감사 — POP3(110)", () => {
  test("인증과 maildrop 열기·RETR이 기록되고 본문은 남지 않는다", async () => {
    // 먼저 메일 한 통을 넣어 RETR 대상을 만든다.
    await smtpDeliver({
      port: app.smtpPort,
      from: "sender@example.test",
      to: USER,
      data: "Subject: pop3-audit\r\n\r\npop3-body-must-not-be-logged\r\n",
    });

    const c = lineClient(app.pop3Port);
    await c.read((l) => l.startsWith("+OK"));
    c.send(`USER ${USER}\r\n`);
    await c.read();
    c.send(`PASS ${PASS}\r\n`);
    await c.read();
    c.send("RETR 1\r\n");
    await c.read((l) => l === ".");
    c.send("QUIT\r\n");
    await c.read();
    c.close();

    await refresh();
    const auth = find(AUDIT_SURFACE.pop3, "auth");
    expect(auth?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(auth?.ip).toBe("127.0.0.1");
    expect(auth?.credKind).toBe("password");

    const open = find(AUDIT_SURFACE.pop3, "openMaildrop");
    expect(open?.outcome).toBe(AUDIT_OUTCOME.ok);
    // 앞선 IMAP APPEND 테스트가 INBOX에 한 통을 넣어 뒀으므로 여기서는 여러 통이 보인다 —
    // 정확한 수를 박으면 위 테스트를 손댈 때 이 테스트가 무관하게 깨진다.
    expect(open?.detail?.messages).toBeGreaterThanOrEqual(1);

    const retr = find(AUDIT_SURFACE.pop3, "retrieve");
    expect(retr?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(retr?.detail?.bytes).toBeGreaterThan(0);
    expect(retr?.detail?.uidl).toBeTruthy();
    expect(JSON.stringify(events)).not.toContain("pop3-body-must-not-be-logged");
  });
});

describe("접근 감사 — ManageSieve(4190)", () => {
  test("인증·PUTSCRIPT·SETACTIVE가 기록되고 스크립트 본문은 남지 않는다", async () => {
    // ★이 표면은 예전에 **인증 로그가 아예 없었다**. 4190은 사용자 필터를 바꾸는 자리라
    //   `setActive` 한 줄이 그 순간부터 모든 수신 메일의 행방을 바꾼다.
    const script = 'require ["fileinto"];\r\nif header :contains "Subject" "audit" { fileinto "Junk"; }\r\n';
    const c = lineClient(app.manageSievePort);
    await c.read((l) => l.startsWith("OK"));
    c.send(`AUTHENTICATE "PLAIN" "${plainB64(USER, PASS)}"\r\n`);
    await c.read((l) => /^(OK|NO)\b/.test(l));
    c.send(`PUTSCRIPT "filter" {${Buffer.byteLength(script)}+}\r\n${script}\r\n`);
    await c.read((l) => /^(OK|NO)\b/.test(l));
    c.send('SETACTIVE "filter"\r\n');
    await c.read((l) => /^(OK|NO)\b/.test(l));
    c.close();

    await refresh();
    const auth = find(AUDIT_SURFACE.managesieve, "auth");
    expect(auth?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(auth?.user).toBe(USER);
    expect(auth?.ip).toBe("127.0.0.1");

    const put = find(AUDIT_SURFACE.managesieve, "putScript");
    expect(put?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(put?.detail?.script).toBe("filter");
    expect(put?.detail?.bytes).toBe(Buffer.byteLength(script));

    const active = find(AUDIT_SURFACE.managesieve, "setActive");
    expect(active?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(active?.detail?.script).toBe("filter");

    // 스크립트 본문에는 전달 주소·조건이 들어 있어 남기면 사용자 규칙 사본이 된다.
    expect(JSON.stringify(events)).not.toContain("fileinto");
  });
});

describe("접근 감사 — SMTP", () => {
  test("25번 수신은 인증이 없어도 deliver로 기록된다(수신 표면의 유일한 기록)", async () => {
    await smtpDeliver({
      port: app.smtpPort,
      from: "inbound@example.test",
      to: USER,
      data: "Subject: smtp-audit\r\n\r\nhello\r\n",
    });
    await refresh();
    const deliver = bySurface(AUDIT_SURFACE.smtp).filter((e) => e.action === "deliver");
    expect(deliver.length).toBeGreaterThan(0);
    const last = deliver.at(-1)!;
    expect(last.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(last.detail?.from).toBe("inbound@example.test");
    expect(last.detail?.rcpts).toBe(1);
    expect(last.detail?.bytes).toBeGreaterThan(0);
    // 25번은 인증이 없으므로 user가 없다 — 그 부재 자체가 "미인증 수신"을 뜻한다.
    expect(last.user).toBeUndefined();
  });

  test("submission(587) 인증은 smtp가 아니라 submission 표면으로 기록된다", async () => {
    await smtpDeliver({
      port: app.submissionPort,
      from: USER,
      to: "someone@example.test",
      data: "Subject: submission-audit\r\n\r\nhi\r\n",
      auth: { user: USER, pass: PASS },
    });
    /**
     * ★표면이 갈리는지 확인한다. 두 리스너가 **같은 클래스**(SmtpServer)를 쓰므로 조립층이 손으로
     * 표면을 넘기면 한쪽이 잘못된 값으로 기록되고도 조용히 통과한다 — 그래서 `profile`에서
     * 파생시켰다. 이 테스트가 그 파생을 고정한다.
     */
    await refresh();
    const auth = find(AUDIT_SURFACE.submission, "auth");
    expect(auth?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(auth?.user).toBe(USER);
    expect(auth?.credKind).toBe("password");
    // 25번 표면에는 auth가 없어야 한다(AUTH를 광고하지 않는다).
    expect(bySurface(AUDIT_SURFACE.smtp).some((e) => e.action === "auth")).toBe(false);
  });
});

describe("접근 감사 — LMTP", () => {
  test("배달이 수신자 수·성공 수와 함께 기록된다", async () => {
    const c = lineClient(app.lmtpPort);
    await c.read((l) => l.startsWith("220"));
    c.send("LHLO test\r\n");
    await c.read((l) => /^250 /.test(l));
    c.send(`MAIL FROM:<lmtp@example.test>\r\n`);
    await c.read();
    c.send(`RCPT TO:<${USER}>\r\n`);
    await c.read();
    c.send("DATA\r\n");
    await c.read();
    c.send("Subject: lmtp-audit\r\n\r\nbody\r\n.\r\n");
    await c.read();
    c.close();

    await refresh();
    const deliver = find(AUDIT_SURFACE.lmtp, "deliver");
    // LMTP는 인증이 없으므로 이 한 줄이 표면의 유일한 기록이다.
    expect(deliver?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(deliver?.detail?.rcpts).toBe(1);
    expect(deliver?.detail?.delivered).toBe(1);
  });
});

describe("접근 감사 — JMAP", () => {
  const authHeader = "Basic " + Buffer.from(`${USER}:${PASS}`).toString("base64");

  test("요청마다 기록되고 **캐시 히트도** 기록된다", async () => {
    const base = `http://127.0.0.1:${app.jmapPort}`;
    await fetch(`${base}/jmap/session`, { headers: { authorization: authHeader } });
    await fetch(`${base}/jmap/session`, { headers: { authorization: authHeader } });

    await refresh();
    const ok = bySurface(AUDIT_SURFACE.jmap).filter((e) => e.outcome === AUDIT_OUTCOME.ok && e.action === "GET /jmap/session");
    /**
     * ★두 줄이어야 한다. 훅을 `authenticate()`에 걸면 두 번째 요청이 30초 인증 캐시로
     * 조기 반환하면서 **감사 로그에서 사라진다** — 캐시가 사는 동안 수백 요청이 무기록이 된다.
     * 그래서 `handle()`에 걸었고, 이 테스트가 그 선택을 고정한다.
     */
    expect(ok.length).toBe(2);
    expect(ok[0]!.detail?.cachedAuth).toBe(0);
    expect(ok[1]!.detail?.cachedAuth).toBe(1);
    expect(ok[0]!.user).toBe(USER);
    expect(ok[0]!.ip).toBeTruthy();
  });

  test("자격증명 미제시와 오류를 구분해 남긴다", async () => {
    const base = `http://127.0.0.1:${app.jmapPort}`;
    await fetch(`${base}/jmap/session`); // Authorization 없음
    await fetch(`${base}/jmap/session`, {
      headers: { authorization: "Basic " + Buffer.from(`${USER}:nope-not-the-password`).toString("base64") },
    });

    await refresh();
    const fails = bySurface(AUDIT_SURFACE.jmap).filter((e) => e.outcome === AUDIT_OUTCOME.fail);
    expect(fails.some((e) => e.detail?.presented === 0)).toBe(true);
    /**
     * 미제시(401을 받고 자격증명을 붙이는 표준 브라우저 흐름)를 공격으로 읽으면 CGNAT 뒤의
     * 정상 사용자가 공격자로 보인다 — 스로틀이 이 둘을 구분하는 이유와 같은 구분을 감사에도 남긴다.
     */
    expect(fails.some((e) => e.detail?.presented === 1 && e.user === USER)).toBe(true);
    expect(JSON.stringify(events)).not.toContain("nope-not-the-password");
  });
});

describe("접근 감사 — 관리 REST API", () => {
  test("apiKeyId·tenantId·메서드·경로가 남는다", async () => {
    const base = `http://127.0.0.1:${app.adminPort}`;
    const t = (await (
      await fetch(`${base}/v1/tenants`, {
        method: "POST",
        headers: { authorization: `Bearer ${ROOT}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "audit-tenant" }),
      })
    ).json()) as { tenantId: string };
    const k = (await (
      await fetch(`${base}/v1/api-keys?tenantId=${t.tenantId}`, {
        method: "POST",
        headers: { authorization: `Bearer ${ROOT}`, "content-type": "application/json" },
        body: JSON.stringify({ scopes: "admin" }),
      })
    ).json()) as { key: string };

    await fetch(`${base}/v1/accounts?tenantId=${t.tenantId}`, { headers: { authorization: `Bearer ${k.key}` } });

    // root 토큰 요청은 테넌트가 없고 isRoot=1로 드러난다(cross-tenant 주체).
    await refresh();
    const rootCall = bySurface(AUDIT_SURFACE.api).find((e) => e.action === "POST /v1/tenants");
    expect(rootCall?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(rootCall?.detail?.isRoot).toBe(1);
    expect(rootCall?.tenantId).toBeUndefined();

    // ★api key 주체는 `apiKeyId`가 핵심 값이다 — 키가 여러 개 발급되므로 "어느 키로 했나"에
    //   답할 수 있어야 폐기 결정을 내릴 수 있다.
    const keyCall = bySurface(AUDIT_SURFACE.api).find((e) => e.action === "GET /v1/accounts");
    expect(keyCall?.outcome).toBe(AUDIT_OUTCOME.ok);
    expect(keyCall?.detail?.isRoot).toBe(0);
    expect(keyCall?.detail?.apiKeyId).toBeTruthy();
    expect(keyCall?.tenantId).toBe(t.tenantId);
    expect(keyCall?.detail?.status).toBe(200);

    // 발급된 평문 키가 감사 로그에 실리면 안 된다(로그가 곧 자격증명 사본이 된다).
    expect(JSON.stringify(events)).not.toContain(k.key);
    expect(JSON.stringify(events)).not.toContain(ROOT);
  });

  test("인증 실패는 denied로 남고, 주체 정보는 비어 있다", async () => {
    const base = `http://127.0.0.1:${app.adminPort}`;
    await fetch(`${base}/v1/accounts`, { headers: { authorization: "Bearer wrong-token-value" } });

    await refresh();
    const denied = bySurface(AUDIT_SURFACE.api).filter((e) => e.outcome === AUDIT_OUTCOME.denied);
    expect(denied.length).toBeGreaterThan(0);
    const last = denied.at(-1)!;
    expect(last.detail?.status).toBe(401);
    // 인증 전 거부이므로 주체가 없다 — 그 부재가 곧 "인증을 통과하지 못했다"는 뜻이다.
    expect(last.detail?.apiKeyId).toBeUndefined();
    expect(last.tenantId).toBeUndefined();
    expect(JSON.stringify(events)).not.toContain("wrong-token-value");
  });

  test("/healthz는 기록하지 않는다(초 단위 생존 확인이 다른 줄을 파묻는다)", async () => {
    await refresh();
    const before = bySurface(AUDIT_SURFACE.api).length;
    await fetch(`http://127.0.0.1:${app.adminPort}/healthz`);
    await fetch(`http://127.0.0.1:${app.adminPort}/healthz`);
    await refresh();
    expect(bySurface(AUDIT_SURFACE.api).length).toBe(before);
  });
});

describe("접근 감사 — 공통 계약", () => {
  test("모든 이벤트에 ts·surface·action·outcome·ip가 있다", async () => {
    await refresh();
    expect(events.length).toBeGreaterThan(0);
    for (const e of events) {
      // 파일의 ts는 ISO 문자열이다(AuditLine 주석) — 파싱 가능해야 조회가 시간으로 정렬된다.
      expect(typeof e.ts).toBe("string");
      expect(Number.isNaN(Date.parse(e.ts))).toBe(false);
      expect(typeof e.surface).toBe("string");
      expect(e.surface.length).toBeGreaterThan(0);
      expect(typeof e.action).toBe("string");
      expect(e.action.length).toBeGreaterThan(0);
      // ip는 "unknown"일 수 있지만 빈 문자열이면 안 된다 — 그러면 필드가 있으나 마나다.
      expect(e.ip.length).toBeGreaterThan(0);
    }
  });

  test("여덟 표면이 모두 이벤트를 냈다 — 배선이 빠진 표면이 없다", async () => {
    await refresh();
    /**
     * ★이 테스트가 이 파일의 요점이다. 리스너 조립에서 `audit` 옵션 하나가 빠지면 그 표면은
     * `noopAuditSink`로 굳어 **타입 검사도 통과하고 다른 테스트도 통과한다**. 표면 목록을
     * 명시적으로 세워 두면 새 리스너를 추가하고 배선을 잊었을 때 여기가 실패한다.
     */
    for (const surface of [
      AUDIT_SURFACE.imap,
      AUDIT_SURFACE.pop3,
      AUDIT_SURFACE.managesieve,
      AUDIT_SURFACE.smtp,
      AUDIT_SURFACE.submission,
      AUDIT_SURFACE.lmtp,
      AUDIT_SURFACE.jmap,
      AUDIT_SURFACE.api,
    ]) {
      expect(bySurface(surface).length, `${surface} 표면에서 이벤트가 없다`).toBeGreaterThan(0);
    }
  });
});
