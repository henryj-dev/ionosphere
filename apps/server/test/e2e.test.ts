/**
 * Phase 0 완료 기준 e2e (PLAN.md): 실소켓으로 SMTP 수신 → 스토어 → POP3 조회.
 * 프로토콜 상세는 각 패키지 단위테스트가 커버 — 여기선 조립 왕복만 검증.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

/** 열린 클라이언트 추적 — 어서션 실패로 close()를 못 타도 afterAll에서 강제 정리
 *  (소켓이 살아있으면 server.close()가 영원히 대기 → 훅 타임아웃). */
const openClients: LineClient[] = [];

/** 줄 단위 스크립트 클라이언트 — 기대 응답 프리픽스 확인 후 다음 명령 전송. */
class LineClient {
  private readonly socket: Socket;
  private buffer = "";
  private lines: string[] = []; // 미소비 완성 줄 큐
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

  /** read() 등록 전에 도착한 줄도 처리되도록, 등록·수신 양쪽에서 큐를 스캔. */
  private tryResolve(): void {
    while (this.waiters.length > 0) {
      const w = this.waiters[0]!;
      const i = this.lines.findIndex((l) => w.until(l));
      if (i < 0) return;
      this.waiters.shift();
      w.resolve(this.lines.splice(0, i + 1));
    }
  }

  /** until(line)이 참이 되는 줄까지 수신 대기 (멀티라인 응답 대응). */
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

const RAW_MESSAGE = [
  "From: =?UTF-8?B?67O07IWM7J20?= <sender@remote.example>",
  "To: user@test.local",
  "Subject: =?UTF-8?B?7JWI64WVIO2FjOyKpO2KuA==?=",
  "Message-ID: <e2e-1@remote.example>",
  "Date: Wed, 23 Jul 2026 12:00:00 +0900",
  "",
  "첫 줄입니다.",
  ".점으로 시작하는 줄", // dot-stuffing 왕복 검증
  "마지막 줄",
].join("\r\n");

describe("e2e: SMTP 수신 → POP3 조회", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-e2e-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      resolver: offlineResolver(), // 실 DNS 미접촉 — 인증은 전부 none으로 결정적
    });
    await app.start();
    await app.createUser("user@test.local", "pw-e2e-1");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    for (const c of openClients) c.close();
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("SMTP로 보낸 메일이 POP3 RETR로 바이트 정확히 돌아온다", async () => {
    // 1) SMTP 발신
    const smtp = new LineClient(app.smtpPort);
    expect((await smtp.read())[0]).toStartWith("220 ");
    smtp.send("EHLO client.example\r\n");
    const ehlo = await smtp.read((l) => l.startsWith("250 "));
    expect(ehlo.some((l) => l.includes("PIPELINING"))).toBe(true);
    smtp.send("MAIL FROM:<sender@remote.example>\r\n");
    expect((await smtp.read())[0]).toStartWith("250 ");
    smtp.send("RCPT TO:<user@test.local>\r\n");
    expect((await smtp.read())[0]).toStartWith("250 ");
    smtp.send("DATA\r\n");
    expect((await smtp.read())[0]).toStartWith("354 ");
    // dot-stuffing 적용해 전송 (".점으로..." → "..점으로...")
    const stuffed = RAW_MESSAGE.split("\r\n").map((l) => (l.startsWith(".") ? "." + l : l)).join("\r\n");
    smtp.send(stuffed + "\r\n.\r\n");
    expect((await smtp.read())[0]).toStartWith("250 ");
    smtp.send("QUIT\r\n");
    await smtp.read();
    smtp.close();

    // 2) 수신 거부 경로: 없는 사용자
    const smtp2 = new LineClient(app.smtpPort);
    await smtp2.read();
    smtp2.send("EHLO x\r\n");
    await smtp2.read((l) => l.startsWith("250 "));
    smtp2.send("MAIL FROM:<a@b.example>\r\n");
    await smtp2.read();
    smtp2.send("RCPT TO:<ghost@test.local>\r\n");
    expect((await smtp2.read())[0]).toStartWith("550 ");
    smtp2.close();

    // 3) POP3 조회
    const pop3 = new LineClient(app.pop3Port);
    expect((await pop3.read())[0]).toStartWith("+OK");
    pop3.send("USER user@test.local\r\n");
    expect((await pop3.read())[0]).toStartWith("+OK");
    pop3.send("PASS pw-e2e-1\r\n");
    expect((await pop3.read())[0]).toStartWith("+OK");
    pop3.send("STAT\r\n");
    const stat = (await pop3.read())[0]!;
    expect(stat).toMatch(/^\+OK 1 \d+/);
    pop3.send("UIDL\r\n");
    const uidl = await pop3.read((l) => l === ".");
    expect(uidl.length).toBe(3); // +OK, "1 <ulid>", "."
    pop3.send("RETR 1\r\n");
    const retr = await pop3.read((l) => l === ".");
    // 첫 줄 +OK, 마지막 줄 "." 제거 + dot-unstuffing.
    // LineClient는 latin1(바이트 보존)로 수신하므로 UTF-8 원문 비교 전에 재디코딩.
    const bodyLatin1 = retr.slice(1, -1).map((l) => (l.startsWith("..") ? l.slice(1) : l)).join("\r\n");
    const body = Buffer.from(bodyLatin1, "latin1").toString("utf8");
    /**
     * 수신 MTA가 붙이는 헤더 순서:
     *   Received-SPF (RFC 7208 §9.1 — "above the Received: field generated by the SMTP receiver")
     *   Received      (RFC 5321 §4.4 — 이 홉의 trace)
     *   Authentication-Results (RFC 8601)
     */
    expect(body).toStartWith("Received-SPF: ");
    expect(body.indexOf("Received-SPF:")).toBeLessThan(body.indexOf("Received: from "));
    expect(body.indexOf("Received: from ")).toBeLessThan(body.indexOf("Authentication-Results:"));
    // trace는 정확히 하나 — 우리 홉이 한 번만 찍혀야 한다(중복은 루프 카운터를 오염시킨다)
    expect(body.split("\r\n").filter((l) => l.startsWith("Received:"))).toHaveLength(1);
    // 평문 세션이므로 ESMTP(RFC 3848), 수신자 1명이므로 for 절이 있다
    expect(body).toContain("with ESMTP");
    expect(body).toContain("for <user@test.local>");
    expect(body).toContain("Authentication-Results: test.local;");
    expect(body).toContain("spf=none");
    // 우리가 붙인 헤더 뒤 원문은 바이트 그대로 보존돼야 함
    const afterOurHeaders = body.slice(body.indexOf(RAW_MESSAGE.slice(0, 20)));
    expect(afterOurHeaders).toBe(RAW_MESSAGE);
    // 4) DELE + QUIT → 재접속 시 maildrop 비어야 함 (expunge 커밋 검증)
    pop3.send("DELE 1\r\n");
    expect((await pop3.read())[0]).toStartWith("+OK");
    pop3.send("QUIT\r\n");
    expect((await pop3.read())[0]).toStartWith("+OK");
    pop3.close();

    const pop3b = new LineClient(app.pop3Port);
    await pop3b.read();
    pop3b.send("USER user@test.local\r\n");
    await pop3b.read();
    pop3b.send("PASS pw-e2e-1\r\n");
    expect((await pop3b.read())[0]).toStartWith("+OK");
    pop3b.send("STAT\r\n");
    expect((await pop3b.read())[0]).toStartWith("+OK 0 ");
    pop3b.send("QUIT\r\n");
    await pop3b.read();
    pop3b.close();
  });

  test("파싱된 봉투가 스토어에 반영됐다 (제목 디코딩·스레딩·미리보기)", async () => {
    // 이전 테스트에서 expunge됐으므로 새 메일 하나 다시 투입
    const smtp = new LineClient(app.smtpPort);
    await smtp.read();
    smtp.send("EHLO x\r\n");
    await smtp.read((l) => l.startsWith("250 "));
    smtp.send("MAIL FROM:<sender@remote.example>\r\nRCPT TO:<user@test.local>\r\nDATA\r\n"); // 파이프라이닝
    await smtp.read((l) => l.startsWith("354 "));
    smtp.send(RAW_MESSAGE.replace(".점", "점") + "\r\n.\r\n");
    await smtp.read((l) => l.startsWith("250 "));
    smtp.send("QUIT\r\n");
    await smtp.read();
    smtp.close();

    const { rows } = await app.db.query({
      sql: "SELECT subject, preview, thread_id FROM messages ORDER BY created_at DESC LIMIT 1",
    });
    expect(String(rows[0]?.subject)).toBe("안녕 테스트");
    expect(String(rows[0]?.preview)).toContain("첫 줄입니다");
    expect(String(rows[0]?.thread_id)).toHaveLength(26);
  });
});
