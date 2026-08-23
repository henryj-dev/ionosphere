/**
 * Phase 3 e2e: 실소켓 IMAP 세션 — SMTP 수신 → IMAP LOGIN/LIST/SELECT/FETCH/
 * STORE/SEARCH/CREATE/APPEND/COPY/EXPUNGE 왕복. 프로토콜 상세는 proto-imap
 * 단위테스트가 커버 — 여기선 백엔드 조립(스토어/블롭/플래그 매핑)을 검증.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const openClients: LineClient[] = [];

/** 줄 단위 스크립트 클라이언트 (e2e.test.ts와 동일 패턴). */
class LineClient {
  private readonly socket: Socket;
  private buffer = "";
  private lines: string[] = [];
  private readonly waiters: { until: (line: string) => boolean; resolve: (lines: string[]) => void }[] = [];

  constructor(port: number) {
    this.socket = connect(port, "127.0.0.1");
    openClients.push(this);
    this.socket.on("data", (chunk) => {
      this.buffer += chunk.toString("latin1");
      let idx: number;
      while ((idx = this.buffer.indexOf("\r\n")) >= 0) {
        this.lines.push(this.buffer.slice(0, idx));
        this.buffer = this.buffer.slice(idx + 2);
      }
      this.tryResolve();
    });
  }

  private tryResolve(): void {
    while (this.waiters.length > 0) {
      const w = this.waiters[0]!;
      const i = this.lines.findIndex((l) => w.until(l));
      if (i < 0) return;
      this.waiters.shift();
      w.resolve(this.lines.splice(0, i + 1));
    }
  }

  read(until: (line: string) => boolean = () => true): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("read timeout")), 4000);
      this.waiters.push({
        until,
        resolve: (lines) => {
          clearTimeout(timer);
          resolve(lines);
        },
      });
      this.tryResolve();
    });
  }

  send(data: string): void {
    this.socket.write(data);
  }

  close(): void {
    this.socket.destroy();
  }
}

const RAW = [
  "From: Alice <alice@remote.example>",
  "To: user@test.local",
  "Subject: imap e2e",
  "Message-ID: <imap-e2e-1@remote.example>",
  "Date: Wed, 23 Jul 2026 12:00:00 +0900",
  "",
  "hello imap world",
].join("\r\n");

describe("e2e: IMAP 세션", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  let imap: LineClient;
  let tagN = 0;

  /** 태그 자동 발급 명령 실행 — tagged 응답까지 수신, 전체 라인 반환. */
  async function cmd(line: string): Promise<string[]> {
    const tag = `t${++tagN}`;
    imap.send(`${tag} ${line}\r\n`);
    return imap.read((l) => l.startsWith(`${tag} `));
  }

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-imap-e2e-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      imapPort: 0,
      resolver: offlineResolver(),
    });
    await app.start();
    await app.createUser("user@test.local", "pw-imap-1");

    // SMTP로 메시지 1건 배달
    const smtp = new LineClient(app.smtpPort);
    await smtp.read();
    smtp.send("EHLO client.example\r\n");
    await smtp.read((l) => l.startsWith("250 "));
    smtp.send("MAIL FROM:<alice@remote.example>\r\n");
    await smtp.read();
    smtp.send("RCPT TO:<user@test.local>\r\n");
    await smtp.read();
    smtp.send("DATA\r\n");
    await smtp.read((l) => l.startsWith("354"));
    smtp.send(RAW + "\r\n.\r\n");
    await smtp.read((l) => l.startsWith("250 "));
    smtp.send("QUIT\r\n");
    await smtp.read();
    smtp.close();

    imap = new LineClient(app.imapPort);
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    for (const c of openClients) c.close();
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("인사말 + LOGIN", async () => {
    const greeting = await imap.read();
    expect(greeting[0]).toStartWith("* OK [CAPABILITY IMAP4rev1");
    const out = await cmd('LOGIN user@test.local "pw-imap-1"');
    expect(out[out.length - 1]).toContain("OK [CAPABILITY");
  });

  test("LIST/STATUS — INBOX 노출 + 카운터", async () => {
    const list = await cmd('LIST "" "*"');
    expect(list.some((l) => l.includes('"INBOX"'))).toBe(true);
    const status = await cmd("STATUS INBOX (MESSAGES UNSEEN UIDNEXT)");
    expect(status[0]).toContain("MESSAGES 1");
    expect(status[0]).toContain("UNSEEN 1");
  });

  test("SELECT — EXISTS/UIDVALIDITY/UNSEEN", async () => {
    const out = await cmd("SELECT INBOX");
    expect(out).toContain("* 1 EXISTS");
    expect(out.some((l) => l.startsWith("* OK [UIDVALIDITY "))).toBe(true);
    expect(out.some((l) => l.startsWith("* OK [UNSEEN 1]"))).toBe(true);
    expect(out[out.length - 1]).toContain("OK [READ-WRITE]");
  });

  test("FETCH — FLAGS/ENVELOPE/BODY[] 리터럴 + markSeen", async () => {
    const meta = await cmd("FETCH 1 (FLAGS RFC822.SIZE ENVELOPE)");
    const fetchLine = meta.find((l) => l.startsWith("* 1 FETCH"))!;
    expect(fetchLine).toContain("FLAGS ()");
    expect(fetchLine).toContain('"imap e2e"');
    // 저장본은 Received 헤더 부가 등으로 원문보다 큼 — 정확값 대신 형식/하한만
    const sizeMatch = /RFC822\.SIZE (\d+)/.exec(fetchLine);
    expect(Number(sizeMatch?.[1])).toBeGreaterThan(RAW.length);

    const body = await cmd("FETCH 1 (BODY[])");
    expect(body.join("\r\n")).toContain("hello imap world");
    // 비PEEK → \Seen 반영 확인
    const after = await cmd("FETCH 1 (FLAGS)");
    expect(after.find((l) => l.startsWith("* 1 FETCH"))).toContain("\\Seen");
  });

  test("STORE/SEARCH — 플래그 왕복", async () => {
    const stored = await cmd("STORE 1 +FLAGS (\\Flagged $custom)");
    expect(stored.find((l) => l.startsWith("* 1 FETCH"))).toContain("\\Flagged");
    const hits = await cmd("SEARCH FLAGGED");
    expect(hits[0]).toBe("* SEARCH 1");
    const none = await cmd("SEARCH UNSEEN");
    expect(none[0]).toBe("* SEARCH");
    const text = await cmd("SEARCH TEXT imap");
    expect(text[0]).toBe("* SEARCH 1");
  });

  test("CREATE/APPEND/COPY — APPENDUID/COPYUID", async () => {
    expect((await cmd("CREATE Archive/2026"))[0]).toContain("OK CREATE");
    const draft = "From: me@test.local\r\nSubject: draft\r\n\r\ndraft body\r\n";
    const appended = await cmd(`APPEND Archive/2026 (\\Draft) {${draft.length}+}\r\n${draft}`);
    expect(appended[appended.length - 1]).toMatch(/OK \[APPENDUID \d+ 1\]/);

    const copied = await cmd("COPY 1 Archive/2026");
    expect(copied[copied.length - 1]).toMatch(/OK \[COPYUID \d+ \d+ 2\]/);
    const status = await cmd("STATUS Archive/2026 (MESSAGES)");
    expect(status[0]).toContain("MESSAGES 2");
  });

  test("\\Deleted + EXPUNGE + LOGOUT", async () => {
    await cmd("STORE 1 +FLAGS.SILENT (\\Deleted)");
    const out = await cmd("EXPUNGE");
    expect(out).toContain("* 1 EXPUNGE");
    const status = await cmd("STATUS INBOX (MESSAGES)");
    expect(status[0]).toContain("MESSAGES 0");
    // 사본은 Archive/2026에 살아있음 (메시지 공유 모델)
    const arch = await cmd("STATUS Archive/2026 (MESSAGES)");
    expect(arch[0]).toContain("MESSAGES 2");
    const bye = await cmd("LOGOUT");
    expect(bye[0]).toStartWith("* BYE");
  });
});
