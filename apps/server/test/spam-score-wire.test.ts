/**
 * 스팸 점수 엔진 조립 검증 — 판정이 **실제 수신 경로**에 걸리는지.
 *
 * 판정 계약 자체는 `packages/spam/test/score.test.ts`가 덮는다. 여기서 보는 것은
 * ① 기본은 꺼져 있다(기존 동작 불변)
 * ② reject 임계를 넘으면 SMTP 554
 * ③ ★junk는 **거부가 아니다** — 배달되고 `$Junk` 키워드 + `X-Spam-Status` 헤더가 남는다
 * ④ ★정상 메일은 켜 놔도 그대로 통과한다(오탐이 곧 유실인 자리)
 */
import { afterAll, beforeAll, describe, expect, test, SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DnsNotFoundError, type DnsResolver } from "@ionosphere/mail-auth";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS } from "./helpers.ts";

function offline(): DnsResolver {
  const nf = (): never => {
    throw new DnsNotFoundError("none");
  };
  return { txt: async () => nf(), mx: async () => nf(), a: async () => nf(), aaaa: async () => nf(), ptr: async () => nf() };
}

/** 헤더 줄들을 그대로 실어 보낸다 — 룰이 헤더만 보므로 그게 입력이다. */
function send(port: number, from: string, to: string, headers: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const msg = `${headers.join("\r\n")}\r\n\r\nbody\r\n.\r\n`;
    const steps = [`EHLO t\r\n`, `MAIL FROM:<${from}>\r\n`, `RCPT TO:<${to}>\r\n`, `DATA\r\n`, msg];
    let stage = -1;
    let buf = "";
    const t = setTimeout(() => {
      s.destroy();
      reject(new Error("timeout"));
    }, SOCKET_DEADLINE_MS);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (line.startsWith("250-")) continue;
        if (line.startsWith("4") || line.startsWith("5")) {
          clearTimeout(t);
          s.write("QUIT\r\n");
          s.destroy();
          resolve(line);
          return;
        }
        if (stage === steps.length - 1) {
          clearTimeout(t);
          s.write("QUIT\r\n");
          s.destroy();
          resolve(line);
          return;
        }
        stage++;
        s.write(steps[stage]!);
      }
    });
    s.on("error", reject);
  });
}

const GOOD_HEADERS = [
  "From: Alice <alice@example.com>",
  "To: rcpt@mx.test",
  "Subject: 안녕하세요",
  "Date: Mon, 07 Aug 2026 10:00:00 +0900",
  "Message-ID: <good@example.com>",
];

/** 표시이름 위장(3.0) + Message-ID 없음(1.5) + Date 없음(1.0) + 수신자 헤더 없음(1.0) = 6.5 → junk */
const JUNKY_HEADERS = ['From: "billing@bank.example" <a@evil.example>'];

/** 위 + 봉투 불일치까지 겹쳐 reject 임계(10)를 넘기도록 임계를 낮춘 앱에서 쓴다. */

async function startApp(extra: Record<string, unknown>): Promise<{ app: IonosphereApp; root: string }> {
  const root = mkdtempSync(join(tmpdir(), "ionosphere-spam-"));
  const app = new IonosphereApp({
    hostname: "mx.test",
    dbPath: ":memory:",
    blobRoot: root,
    smtpPort: 0,
    pop3Port: 0,
    resolver: offline(),
    runMtaWorker: false,
    ...extra,
  });
  await app.start();
  await app.createUser("rcpt@mx.test", "pw");
  return { app, root };
}

describe("스팸 점수 조립 — 기본 비활성", () => {
  test("켜지 않으면 의심스러운 헤더도 그대로 받는다", async () => {
    const { app, root } = await startApp({});
    try {
      expect(await send(app.smtpPort, "a@evil.example", "rcpt@mx.test", JUNKY_HEADERS)).toStartWith("250");
    } finally {
      await app.stop();
      rmSync(root, { recursive: true, force: true });
    }
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("스팸 점수 조립 — 켠 상태", () => {
  let app: IonosphereApp;
  let root: string;

  beforeAll(async () => {
    ({ app, root } = await startApp({ spamScore: true }));
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(root, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("★정상 메일은 그대로 통과한다 — 오탐이 곧 유실인 자리", async () => {
    expect(await send(app.smtpPort, "alice@example.com", "rcpt@mx.test", GOOD_HEADERS)).toStartWith("250");
  });

  test("★junk는 거부가 아니다 — 250으로 받는다", async () => {
    // 배달을 막으면 오탐 한 번이 곧 메일 유실이다. junk는 "옮기는 것"이지 "버리는 것"이 아니다.
    expect(await send(app.smtpPort, "a@evil.example", "rcpt@mx.test", JUNKY_HEADERS)).toStartWith("250");
  });

  test("★junk 판정이 $Junk 키워드와 X-Spam-Status 헤더로 남는다", async () => {
    await send(app.smtpPort, "a@evil.example", "rcpt@mx.test", [
      'From: "billing@bank.example" <b@evil.example>',
      "Message-ID: <j2@evil.example>",
    ]);
    const acc = await app.store.getAccountByEmail("rcpt@mx.test");
    const boxes = await app.store.listMailboxes(String(acc!.id));
    const inbox = boxes.find((m) => String(m.role ?? "") === "inbox")!;
    const rows = await app.store.listMessages(String(inbox.id));
    expect(rows.length).toBeGreaterThan(0);

    // 키워드로 표식이 남는가 — 클라이언트가 이걸로 거른다.
    // ★키워드는 **소문자로 저장된다**(SCHEMA §5-3, store.ts `keywordsLower`). 그래서 조회도
    //   소문자로 한다 — `$Junk`로 찾으면 있는데도 못 찾는다.
    const { rows: kwRows } = await app.db.query({
      sql: "SELECT message_id FROM message_keywords WHERE keyword = ?",
      params: ["$junk"],
    });
    const marked = kwRows.map((r) => String(r.message_id));
    expect(marked.length).toBeGreaterThan(0);

    // 헤더에도 남아야 한다 — 메일함 배치만으로는 사용자도 운영자도 "왜"를 모른다.
    const ref = await app.store.getMessageBlob(marked[0]!);
    const raw = new TextDecoder().decode(await app.blobs.get(ref!.blobId, ref!.generation));
    expect(raw).toContain("X-Spam-Status: Yes");
    expect(raw).toContain("display-name-address-mismatch");
  });
});

describe("스팸 점수 조립 — reject 임계", () => {
  test("임계를 넘으면 554로 거부한다", async () => {
    // 기본 임계(10)는 헤더 룰만으로 넘기 어렵다 — 임계를 낮춰 갈래 자체를 구동한다.
    const { app, root } = await startApp({ spamScore: { rejectThreshold: 3 } });
    try {
      const r = await send(app.smtpPort, "a@evil.example", "rcpt@mx.test", JUNKY_HEADERS);
      expect(r).toStartWith("554");
    } finally {
      await app.stop();
      rmSync(root, { recursive: true, force: true });
    }
  }, E2E_HOOK_TIMEOUT_MS);
});
