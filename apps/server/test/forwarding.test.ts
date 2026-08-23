/**
 * 포워딩(Phase 5, SRS) — forward_to 알리아스가 SRS 재작성으로 relay 적재되고, SRS 바운스가
 * 원 발신자로 reverse되며, 루프 가드가 동작하는지. MtaWorker는 끄고(runMtaWorker=false)
 * mta_queue 적재 결과만 검증(실제 외부 발송 없음).
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ulid } from "@ionosphere/core";
import { provisionDkimKeys } from "@ionosphere/api";
import { arcVerify, type DnsResolver } from "@ionosphere/mail-auth";
import { srsForward } from "@ionosphere/srs";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const SRS_SECRET = "forwarding-test-secret";

/** 최소 SMTP 송신 — 봉투/헤더 지정. 응답 프리픽스만 확인. */
async function sendOne(port: number, from: string, to: string, data: string): Promise<string> {
  const sock = connect(port, "127.0.0.1");
  let buf = "";
  const pending: ((line: string) => void)[] = [];
  sock.on("data", (c) => {
    buf += c.toString("latin1");
    let i: number;
    while ((i = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 2);
      pending.shift()?.(line);
    }
  });
  const line = () => new Promise<string>((resolve) => pending.push(resolve));
  const send = (s: string) => sock.write(s);
  await line(); // 220
  send("EHLO client.test\r\n");
  // 250 멀티라인 소비
  await new Promise<void>((resolve) => {
    const onLine = (l: string) => (l.startsWith("250 ") ? resolve() : pending.unshift(onLine));
    pending.push(onLine);
  });
  send(`MAIL FROM:<${from}>\r\n`);
  await line();
  send(`RCPT TO:<${to}>\r\n`);
  const rcptResp = await line();
  if (!rcptResp.startsWith("250")) {
    send("QUIT\r\n");
    sock.end();
    return rcptResp;
  }
  send("DATA\r\n");
  await line(); // 354
  send(data.replace(/\r?\n/g, "\r\n") + "\r\n.\r\n");
  const dataResp = await line();
  send("QUIT\r\n");
  sock.end();
  await new Promise<void>((resolve) => sock.on("close", () => resolve()));
  return dataResp;
}

describe("SRS 포워딩", () => {
  let app: IonosphereApp;
  let blobRoot: string;
  let dkimTxt: Record<string, string> = {}; // selector._domainkey.test.local → TXT(ARC 검증용)

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-fwd-"));
    app = new IonosphereApp({
      hostname: "test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      srsSecret: SRS_SECRET,
      runMtaWorker: false, // 큐 적재만 검증, 외부 발송 안 함
      resolver: offlineResolver(),
    });
    await app.start();

    // 테넌트 + 도메인 + forward-only 알리아스 fwd@test.local → ext@remote.test
    const { tenantId } = await app.store.createTenant("t");
    const domainId = ulid();
    const now = Date.now();
    // DKIM 키 프로비저닝(ARC 봉인용) — masterKey 없이 평문 저장
    const dkim = provisionDkimKeys(domainId, "test.local", undefined);
    for (const r of dkim.dnsRecords) {
      if (r.name.includes("_domainkey.")) dkimTxt[r.name] = r.value;
    }
    await app.db.batch([
      { sql: "INSERT INTO domains (id, tenant_id, name, status, claimed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)", params: [domainId, tenantId, "test.local", now, now] },
      { sql: "INSERT INTO addresses (id, tenant_id, domain_id, localpart, forward_to, created_at) VALUES (?, ?, ?, 'fwd', ?, ?)", params: [ulid(), tenantId, domainId, "ext@remote.test", now] },
      ...dkim.statements,
    ]);
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  async function queueRows() {
    const { rows } = await app.db.query({ sql: "SELECT env_from, rcpt FROM mta_queue ORDER BY created_at" });
    return rows.map((r) => ({ envFrom: String(r.env_from), rcpt: String(r.rcpt) }));
  }

  test("forward_to 알리아스 수신 → SRS 재작성된 relay 적재", async () => {
    const resp = await sendOne(app.smtpPort, "sender@remote.example", "fwd@test.local", "Subject: hi\r\n\r\nbody\r\n");
    expect(resp).toStartWith("250");
    const rows = await queueRows();
    const fwd = rows.find((r) => r.rcpt === "ext@remote.test");
    expect(fwd).toBeDefined();
    // envelope from이 SRS0=...@test.local로 재작성됨
    expect(fwd!.envFrom).toMatch(/^SRS0=.+@test\.local$/);
  });

  test("SRS 바운스 반송처 수신 → 원 발신자로 reverse relay (null 발신자 유지)", async () => {
    // 우리가 예전에 만든 SRS 주소로 바운스가 돌아온 상황
    const srsAddr = srsForward("victim@origin.example", "test.local", { secret: SRS_SECRET });
    const before = (await queueRows()).length;
    const resp = await sendOne(app.smtpPort, "", srsAddr, "Subject: bounce\r\n\r\nfailed\r\n"); // MAIL FROM:<>
    expect(resp).toStartWith("250");
    const rows = await queueRows();
    expect(rows.length).toBe(before + 1);
    const relay = rows[rows.length - 1]!;
    expect(relay.rcpt).toBe("victim@origin.example");
    expect(relay.envFrom).toBe(""); // 이중 바운스 방지 — null 발신자 유지
  });

  test("변조된 SRS 주소는 relay 안 함(reverse 실패 → 550/드롭)", async () => {
    const before = (await queueRows()).length;
    const resp = await sendOne(app.smtpPort, "", "SRS0=BADHASH= zz=origin.example=x@test.local".replace(" ", ""), "Subject: x\r\n\r\ny\r\n");
    // verifyRecipient에서 reverse 실패 → 550 거부(RCPT 단계)
    expect(resp).toStartWith("550");
    expect((await queueRows()).length).toBe(before);
  });

  test("포워딩 메시지에 ARC 봉인이 붙고 체인이 cv=pass로 검증됨", async () => {
    await sendOne(app.smtpPort, "sender@remote.example", "fwd@test.local", "Subject: arc\r\n\r\nbody\r\n");
    const { rows } = await app.db.query({
      sql: "SELECT blob_id FROM mta_queue WHERE rcpt = 'ext@remote.test' ORDER BY created_at DESC LIMIT 1",
    });
    const blobId = String(rows[0]!.blob_id);
    const raw = await app.blobs.get(blobId);
    const text = Buffer.from(raw).toString("latin1");
    expect(text).toContain("ARC-Seal:");
    expect(text).toContain("ARC-Message-Signature:");
    expect(text).toContain("ARC-Authentication-Results:");
    // 게시된 DKIM 키로 ARC 체인 검증 → cv=pass
    const resolver: Pick<DnsResolver, "txt"> = {
      txt: async (name: string) => {
        const rec = dkimTxt[name];
        if (!rec) throw new Error(`no txt: ${name}`);
        return [rec];
      },
    };
    const result = await arcVerify(raw, resolver);
    expect(result.cv).toBe("pass");
    expect(result.instances).toBe(1);
  });

  /**
   * 감사 5차 M-15 회귀 — 예전엔 `countForwardHops`가 헤더 **발생 횟수만** 셌다.
   * 이 헤더는 어떤 제거기에도 걸리지 않고 서명도 없었으므로, 미인증 원격 발신자가
   * `X-Ionosphere-Forwarded` 10줄을 손으로 붙여 보내는 것만으로 **피해자의 forward_to
   * 알리아스와 Sieve redirect를 무력화**할 수 있었다(미인증 원격 DoS).
   * 이 테스트는 예전에 "루프 가드가 동작한다"고 단언하던 자리였다 — 공격자가 쓰는 방법과
   * 정확히 같은 방법으로 검증하고 있었던 것이 문제였다.
   */
  test("위조된 X-Ionosphere-Forwarded는 홉으로 세지 않는다 — 포워딩이 살아 있어야 한다", async () => {
    const before = (await queueRows()).length;
    const forged = Array.from({ length: 10 }, () => "X-Ionosphere-Forwarded: test.local").join("\r\n");
    const resp = await sendOne(app.smtpPort, "sender@remote.example", "fwd@test.local", `${forged}\r\nSubject: loop\r\n\r\nbody\r\n`);
    // 봉인이 없는 값은 우리가 만든 것이 아니므로 무시된다 → 정상 포워딩.
    expect(resp).toStartWith("250");
    expect((await queueRows()).length).toBe(before + 1);
  });

  /**
   * 루프 가드 자체는 살아 있어야 한다 — 위조를 무시한다고 해서 방어를 없앤 것이 아니다.
   * 우리가 실제로 붙인 봉인 표식을 릴레이 사본에서 뽑아 10번 붙여 되먹인다.
   */
  test("우리가 봉인한 X-Ionosphere-Forwarded는 홉으로 세어 루프를 끊는다", async () => {
    // 1) 한 번 포워딩시켜 우리 봉인 표식을 얻는다. Message-ID를 고정해야 봉인이 재사용된다.
    const messageId = "<loop-seal@remote.example>";
    await sendOne(
      app.smtpPort,
      "sender@remote.example",
      "fwd@test.local",
      `Message-ID: ${messageId}\r\nSubject: seal\r\n\r\nbody\r\n`,
    );
    const { rows } = await app.db.query({
      sql: "SELECT blob_id FROM mta_queue WHERE rcpt = 'ext@remote.test' ORDER BY created_at DESC LIMIT 1",
    });
    const text = Buffer.from(await app.blobs.get(String(rows[0]!.blob_id))).toString("latin1");
    const marker = /^X-Ionosphere-Forwarded: (.+)$/m.exec(text)?.[1]?.trim();
    expect(marker).toBeDefined();
    expect(marker).toContain("; s="); // 봉인이 실제로 붙어 있다

    // 2) 같은 Message-ID의 메일에 그 표식을 10번 붙여 보낸다 → 루프가드 발동.
    const before = (await queueRows()).length;
    const sealed = Array.from({ length: 10 }, () => `X-Ionosphere-Forwarded: ${marker}`).join("\r\n");
    const resp = await sendOne(
      app.smtpPort,
      "sender@remote.example",
      "fwd@test.local",
      `${sealed}\r\nMessage-ID: ${messageId}\r\nSubject: loop\r\n\r\nbody\r\n`,
    );
    expect(resp).toStartWith("451"); // 배달 처분 0 — 릴레이가 드롭됐다
    expect((await queueRows()).length).toBe(before);
  });

  /**
   * 개명(mailer → ionosphere) 전환 회귀 — 롤링 배포 중에는 구 노드가 붙인
   * `X-Mailer-Forwarded`와 새 이름이 한 메시지에 섞인다. 새 이름만 세면 홉 수가 실제보다
   * 적게 나와 루프가드가 조용히 느슨해진다. 메일 루프는 증폭되는 사고라 세는 쪽으로 틀린다.
   */
  test("★개명 전 이름(X-Mailer-Forwarded)의 봉인 표식도 홉으로 센다", async () => {
    const messageId = "<legacy-seal@remote.example>";
    await sendOne(
      app.smtpPort,
      "sender@remote.example",
      "fwd@test.local",
      `Message-ID: ${messageId}\r\nSubject: seal\r\n\r\nbody\r\n`,
    );
    const { rows } = await app.db.query({
      sql: "SELECT blob_id FROM mta_queue WHERE rcpt = 'ext@remote.test' ORDER BY created_at DESC LIMIT 1",
    });
    const text = Buffer.from(await app.blobs.get(String(rows[0]!.blob_id))).toString("latin1");
    const marker = /^X-Ionosphere-Forwarded: (.+)$/m.exec(text)?.[1]?.trim();
    expect(marker).toBeDefined();

    // 같은 봉인을 **구 헤더 이름으로** 10번 붙인다 — 봉인 HMAC은 헤더 이름을 포함하지 않는다.
    const before = (await queueRows()).length;
    const sealed = Array.from({ length: 10 }, () => `X-Mailer-Forwarded: ${marker}`).join("\r\n");
    const resp = await sendOne(
      app.smtpPort,
      "sender@remote.example",
      "fwd@test.local",
      `${sealed}\r\nMessage-ID: ${messageId}\r\nSubject: loop\r\n\r\nbody\r\n`,
    );
    expect(resp).toStartWith("451");
    expect((await queueRows()).length).toBe(before);
  });

  /**
   * 감사 5차 H-6 회귀 — `relayCopy`가 원본(`env.raw`)을 릴레이해서 우리 홉에서 Received가
   * 증가하지 않았다. 그래서 `MAX_RECEIVED_HOPS`가 수신 저장 경로에만 걸리고 릴레이 경로가
   * 비어 있었다(RFC 5321 §4.4는 Received 추가를 MUST로 요구한다).
   */
  test("릴레이 사본에 우리 Received가 포함된다", async () => {
    await sendOne(app.smtpPort, "sender@remote.example", "fwd@test.local", "Subject: trace\r\n\r\nbody\r\n");
    const { rows } = await app.db.query({
      sql: "SELECT blob_id FROM mta_queue WHERE rcpt = 'ext@remote.test' ORDER BY created_at DESC LIMIT 1",
    });
    const raw = await app.blobs.get(String(rows[0]!.blob_id));
    const text = Buffer.from(raw).toString("latin1");
    // 우리 호스트명이 by 절에 있는 Received가 있어야 한다.
    expect(text).toMatch(/Received:[\s\S]*?by test\.local/);
  });
});
