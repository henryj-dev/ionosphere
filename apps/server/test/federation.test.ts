/**
 * Phase 1 완료 기준 e2e (로컬 페더레이션 — 인터넷 없이 발송 파이프라인 전체 검증):
 *   인스턴스 A에서 인증 submit(587) → A의 MtaWorker가 MX 조회(주입식→127.0.0.1)로
 *   B의 릴레이(:25)에 배달 → B에서 DKIM 검증 통과 → POP3로 수신 확인.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dkimVerify } from "@ionosphere/mail-auth";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

class LineClient {
  private readonly socket: Socket;
  private buffer = "";
  private lines: string[] = [];
  private readonly waiters: { until: (l: string) => boolean; resolve: (ls: string[]) => void }[] = [];

  constructor(port: number) {
    this.socket = connect(port, "127.0.0.1");
    this.socket.on("data", (chunk) => {
      this.buffer += chunk.toString("latin1");
      let idx: number;
      while ((idx = this.buffer.indexOf("\r\n")) >= 0) {
        this.lines.push(this.buffer.slice(0, idx));
        this.buffer = this.buffer.slice(idx + 2);
      }
      this.drain();
    });
  }
  private drain(): void {
    while (this.waiters.length > 0) {
      const w = this.waiters[0]!;
      const i = this.lines.findIndex((l) => w.until(l));
      if (i < 0) return;
      this.waiters.shift();
      w.resolve(this.lines.splice(0, i + 1));
    }
  }
  read(until: (l: string) => boolean = () => true): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("read timeout")), 4000);
      this.waiters.push({ until, resolve: (ls) => { clearTimeout(t); resolve(ls); } });
      this.drain();
    });
  }
  send(s: string): void { this.socket.write(s); }
  close(): void { this.socket.destroy(); }
}

describe("federation: A submit → B relay → DKIM 검증 → POP3", () => {
  let a: IonosphereApp;
  let b: IonosphereApp;
  let dirs: string[] = [];
  const clients: LineClient[] = [];

  beforeAll(async () => {
    const dirA = mkdtempSync(join(tmpdir(), "ionosphere-fed-a-"));
    const dirB = mkdtempSync(join(tmpdir(), "ionosphere-fed-b-"));
    dirs = [dirA, dirB];

    // B: 수신 인스턴스. bob@b.test 계정. 수신 인증은 오프라인(실 DNS 미접촉) —
    // AR 헤더는 붙되 a.test가 안 풀려 전부 none. DKIM 원본 검증은 아래 수동 리졸버로 별도 확인.
    b = new IonosphereApp({
      hostname: "b.test", dbPath: ":memory:", blobRoot: dirB, smtpPort: 0, pop3Port: 0,
      resolver: offlineResolver(),
    });
    await b.start();
    await b.createUser("bob@b.test", "bobpw");

    // A: 발신 인스턴스. alice@a.test + a.test 도메인(DKIM 키). MX는 전부 B의 :25로.
    a = new IonosphereApp({
      hostname: "a.test", dbPath: ":memory:", blobRoot: dirA, smtpPort: 0, pop3Port: 0,
      submissionPort: 0,
      masterKey: "fed-master",
      outboundPort: b.smtpPort,                       // MTA가 B의 릴레이 포트로
      resolveMx: async () => [{ exchange: "127.0.0.1", priority: 0 }],
      mtaIntervalMs: 100,                             // 테스트: 빠른 tick
    });
    await a.start();
    await a.createUser("alice@a.test", "alicepw");
    await provisionDomain(a, "a.test", "fed-master");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    for (const c of clients) c.close();
    await a.stop();
    await b.stop();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("submit → 배달 → DKIM pass → POP3 수신", async () => {
    // 1) A의 587로 AUTH PLAIN 후 제출
    const sub = new LineClient(a.submissionPort);
    clients.push(sub);
    expect((await sub.read())[0]).toStartWith("220 ");
    sub.send("EHLO alice-client\r\n");
    const ehlo = await sub.read((l) => l.startsWith("250 "));
    expect(ehlo.some((l) => l.includes("AUTH"))).toBe(true);
    // AUTH PLAIN \0alice@a.test\0alicepw
    const authB64 = Buffer.from(`\0alice@a.test\0alicepw`, "utf8").toString("base64");
    sub.send(`AUTH PLAIN ${authB64}\r\n`);
    expect((await sub.read())[0]).toStartWith("235 ");
    sub.send("MAIL FROM:<alice@a.test>\r\n");
    expect((await sub.read())[0]).toStartWith("250 ");
    sub.send("RCPT TO:<bob@b.test>\r\n");
    expect((await sub.read())[0]).toStartWith("250 ");
    sub.send("DATA\r\n");
    expect((await sub.read())[0]).toStartWith("354 ");
    const msg = [
      "From: alice@a.test",
      "To: bob@b.test",
      "Subject: federation test",
      "Message-ID: <fed-1@a.test>",
      "Date: Thu, 23 Jul 2026 10:00:00 +0900",
      "",
      "페더레이션 본문",
    ].join("\r\n");
    sub.send(msg + "\r\n.\r\n");
    expect((await sub.read())[0]).toStartWith("250 ");
    sub.send("QUIT\r\n");
    await sub.read();

    // 2) A의 MTA 워커가 큐를 비우고 B에 배달할 때까지 대기 (tick 간격 대신 폴링)
    let popMsg: string[] | null = null;
    for (let i = 0; i < 40; i++) {
      const pop = new LineClient(b.pop3Port);
      clients.push(pop);
      await pop.read();
      pop.send("USER bob@b.test\r\n"); await pop.read();
      pop.send("PASS bobpw\r\n"); await pop.read();
      pop.send("STAT\r\n");
      const stat = (await pop.read())[0]!;
      if (/^\+OK [1-9]/.test(stat)) {
        pop.send("RETR 1\r\n");
        popMsg = await pop.read((l) => l === ".");
        pop.send("QUIT\r\n"); await pop.read();
        pop.close();
        break;
      }
      pop.send("QUIT\r\n"); await pop.read();
      pop.close();
      await new Promise((r) => setTimeout(r, 100));
    }

    expect(popMsg).not.toBeNull();
    // latin1 = 바이트 보존 문자열. DKIM은 원바이트로 검증해야 하므로 UTF-8 재인코딩 금지.
    const rawLatin1 = popMsg!.slice(1, -1).map((l) => (l.startsWith("..") ? l.slice(1) : l)).join("\r\n");
    const rawBytes = Buffer.from(rawLatin1, "latin1");
    // 3) DKIM-Signature 헤더 존재 + a.test 도메인 (헤더는 ASCII라 latin1 문자열로 검사 무방)
    expect(rawLatin1).toContain("DKIM-Signature:");
    expect(rawLatin1).toContain("d=a.test");
    expect(rawLatin1).toContain("Subject: federation test");

    // 4) DKIM 검증: A의 DNS 레코드를 주입식 리졸버로 제공
    const txt = await dkimTxtRecords(a, "a.test");
    const results = await dkimVerify(
      new Uint8Array(rawBytes),
      async (name) => {
        const rec = txt.get(name);
        if (!rec) throw new Error(`no TXT ${name}`);
        return [rec];
      },
    );
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((r) => r.result === "pass")).toBe(true);
  });
});

/**
 * add-domain CLI와 동일한 도메인+DKIM 프로비저닝을 테스트에서 재현.
 * createUser가 이미 검증된 도메인 행을 만들어 두므로(수신 라우팅이 검증된 소유 도메인만 인정),
 * 있으면 그 행에 DKIM 키만 붙인다 — 새로 만들면 domain_name_claims PK와 충돌한다.
 */
async function provisionDomain(app: IonosphereApp, name: string, masterKey: string): Promise<void> {
  const { ulid, seal } = await import("@ionosphere/core");
  const { generateDkimKeyPair } = await import("@ionosphere/mail-auth");
  const now = Date.now();
  const { rows: dr } = await app.db.query({
    sql: "SELECT id FROM domains WHERE name = ? AND status = 1",
    params: [name],
  });
  const existing = dr[0];
  const domainId = existing ? String(existing.id) : ulid();
  const rsa = generateDkimKeyPair("rsa-sha256");
  const ed = generateDkimKeyPair("ed25519-sha256");
  const stmts: { sql: string; params: unknown[] }[] = [];
  if (!existing) {
    const { rows } = await app.db.query({ sql: "SELECT id FROM tenants LIMIT 1" });
    const tenantId = String(rows[0]!.id);
    stmts.push(
      { sql: `INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?,?,?,1,?,?)`, params: [domainId, tenantId, name, now, now] },
      { sql: `INSERT INTO domain_name_claims (name, domain_id) VALUES (?,?)`, params: [name, domainId] },
    );
  }
  stmts.push(
    { sql: `INSERT INTO dkim_keys (id, domain_id, selector, algo, private_key, key_version, active, created_at) VALUES (?,?,'rsa1',0,?,1,1,?)`, params: [ulid(), domainId, seal(rsa.privateKeyPem, masterKey).value, now] },
    { sql: `INSERT INTO dkim_keys (id, domain_id, selector, algo, private_key, key_version, active, created_at) VALUES (?,?,'ed1',1,?,1,1,?)`, params: [ulid(), domainId, seal(ed.privateKeyPem, masterKey).value, now] },
  );
  await app.db.batch(stmts);
  // 검증용 DNS 레코드 캐시 (selector → record). 실제로는 DNS에 게시.
  dnsCache.set(`rsa1._domainkey.${name}`, rsa.dnsRecord);
  dnsCache.set(`ed1._domainkey.${name}`, ed.dnsRecord);
}

const dnsCache = new Map<string, string>();
async function dkimTxtRecords(_app: IonosphereApp, _domain: string): Promise<Map<string, string>> {
  return dnsCache;
}
