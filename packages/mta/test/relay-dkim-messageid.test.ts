/**
 * 릴레이 경유 발송에서 DKIM 서명이 살아남는지 — `Message-ID` 재작성 회귀 (2026-07-31 실사고).
 *
 * 사고: Cloudflare Email Service가 중계하면서 `Message-ID`를 자기 것으로 재작성한다. 우리
 * `h=`에 `message-id`가 있어 목적지에서 서명이 **항상 깨졌다.** Google DMARC 리포트가
 * `dkim d=ionosphere.test s=ed1 → fail`로 확인했고, 같은 리포트의 `bh=`가 우리 서명과 릴레이
 * 서명에서 동일해 **본문은 무사하고 헤더 해시만 깨졌다**는 것까지 드러났다.
 *
 * 그때 DMARC가 pass였던 것은 Cloudflare가 우리 도메인으로 붙여 준 `s=cf-bounce` 서명 덕분이다
 * — 즉 우리가 통제하지 않는 서명 하나에만 의존하는 상태였다. 이 테스트는 우리 서명이 그 경로에서
 * 살아남는 것을 고정한다.
 *
 * 이 파일이 검증하는 계약 3개:
 *  ① 릴레이 경유(`smarthost` 설정) → `h=`에 `message-id`가 없다
 *  ② 릴레이가 Message-ID를 바꿔도 우리 서명이 pass다  ← 사고의 직접 재현
 *  ③ 직접 발송(스마트호스트 없음) → `h=`에 `message-id`가 **있다**(기본값 유지)
 * ③이 없으면 "릴레이 제약을 전 경로에 퍼뜨리는" 회귀를 잡지 못한다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpServer, type SmtpBackend } from "@ionosphere/proto-smtp";
import { dkimVerify, generateDkimKeyPair } from "@ionosphere/mail-auth";
import { ulid } from "@ionosphere/core";
import { MtaWorker, type BlobReader, type DkimHook } from "../src/worker.ts";
import { freshDb } from "./helpers.ts";

let activeServers: SmtpServer[] = [];
afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

const SUBMITTED_MSGID = "<original-1785485979876@sender.test>";
const REWRITTEN_MSGID = "<JCQm2EytCvpC9PHZvghqJvtWhBzR12sNWnks@sender.test>";

const RAW_TEXT = [
  "From: alice@sender.test",
  "To: bob@remote.test",
  "Subject: relay dkim",
  "Date: Fri, 31 Jul 2026 08:19:39 GMT",
  `Message-ID: ${SUBMITTED_MSGID}`,
  "MIME-Version: 1.0",
  'Content-Type: text/plain; charset="utf-8"',
  "",
  "body text",
  "",
].join("\r\n");

interface Received {
  raw: Uint8Array;
}

/** AUTH 필수 릴레이(submission 프로파일) — smarthost.test.ts와 같은 구성. */
function relayServer(): { start: () => Promise<number>; received: Received[] } {
  const received: Received[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      received.push({ raw: env.raw });
      return { ok: true };
    },
    authenticate: async (user, pass) => ({ ok: user === "relay-user" && pass === "relay-pass" }),
  };
  const server = new SmtpServer({
    hostname: "smarthost.test",
    maxSizeBytes: 10_000_000,
    profile: "submission",
    allowInsecureAuth: true, // 테스트 전용 — TLS 미설정 서버라 평문 AUTH 허용 필요
    backend,
  });
  activeServers.push(server);
  return { start: () => server.listen(0, "127.0.0.1"), received };
}

/**
 * 직접 발송(MX) 상대 — `profile: "relay"`(기본값)다. 인바운드 MX 수신을 뜻하는 프로파일 이름이
 * `"relay"`이므로 `"mx"`는 없다.
 * ③에서 submission 서버를 재사용했다가 실패했다: 직접 발송 경로는 AUTH를 하지 않으므로
 * AUTH 필수 서버는 메일을 받지 못한다.
 */
function mxServer(): { start: () => Promise<number>; received: Received[] } {
  const received: Received[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      received.push({ raw: env.raw });
      return { ok: true };
    },
  };
  const server = new SmtpServer({ hostname: "mx.test", maxSizeBytes: 10_000_000, profile: "relay", backend });
  activeServers.push(server);
  return { start: () => server.listen(0, "127.0.0.1"), received };
}

function fakeBlobs(blobId: string, raw: Uint8Array): BlobReader {
  return {
    get: async (id) => {
      if (id !== blobId) throw new Error(`unexpected blobId: ${id}`);
      return raw;
    },
  };
}

async function insertQueueRow(db: Awaited<ReturnType<typeof freshDb>>, blobId: string): Promise<string> {
  const id = ulid();
  const now = Date.now();
  await db.batch([
    {
      sql: `INSERT INTO mta_queue (id, tenant_id, account_id, submission_id, blob_id, env_from, verp_token, rcpt, rcpt_domain, status, attempts, next_attempt, lease_until, last_error, created_at)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, 0, 0, ?, NULL, NULL, ?)`,
      params: [id, ulid(), ulid(), blobId, "alice@sender.test", "0".repeat(16), "bob@remote.test", "remote.test", now, now],
    },
  ]);
  return id;
}

/** h= 태그 값을 꺼낸다(콜론 구분 헤더명 목록). */
function signedHeaderNames(raw: Uint8Array): string[] {
  const text = new TextDecoder().decode(raw);
  const m = text.match(/DKIM-Signature:[\s\S]*?\bh=([^;]+);/);
  if (!m || !m[1]) throw new Error("DKIM-Signature의 h= 태그를 찾지 못했다");
  return m[1].replace(/\s+/g, "").split(":").map((s) => s.toLowerCase());
}

describe("릴레이 경유 DKIM — Message-ID 재작성 내성", () => {
  test("① 릴레이 경유면 h=에 message-id가 없다", async () => {
    const db = await freshDb();
    const relay = relayServer();
    const port = await relay.start();
    const raw = new TextEncoder().encode(RAW_TEXT);
    const blobId = "d".repeat(64);
    await insertQueueRow(db, blobId);

    const keyPair = generateDkimKeyPair("ed25519-sha256");
    const dkim: DkimHook = {
      selectorFor: async () => [{ selector: "ed1", privateKey: keyPair.privateKeyPem, algorithm: "ed25519-sha256" }],
    };

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: async () => {
        throw new Error("resolveMx must not be called in smarthost mode");
      },
      dkim,
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port, auth: { user: "relay-user", pass: "relay-pass" }, tls: "never" },
    });

    expect(await worker.tick()).toBe(1);
    expect(relay.received).toHaveLength(1);

    const names = signedHeaderNames(relay.received[0]!.raw);
    expect(names).not.toContain("message-id");
    // 다른 보호 대상은 그대로 서명돼야 한다 — 범위를 과하게 줄이면 그것도 회귀다.
    expect(names).toContain("from");
    expect(names).toContain("subject");
    expect(names).toContain("date");
    expect(names).toContain("to");

    await db.close();
  });

  test("★② 릴레이가 Message-ID를 바꿔도 우리 서명이 pass다 (사고 재현)", async () => {
    const db = await freshDb();
    const relay = relayServer();
    const port = await relay.start();
    const raw = new TextEncoder().encode(RAW_TEXT);
    const blobId = "e".repeat(64);
    await insertQueueRow(db, blobId);

    const keyPair = generateDkimKeyPair("ed25519-sha256");
    const dkim: DkimHook = {
      selectorFor: async () => [{ selector: "ed1", privateKey: keyPair.privateKeyPem, algorithm: "ed25519-sha256" }],
    };

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: async () => {
        throw new Error("resolveMx must not be called in smarthost mode");
      },
      dkim,
      ehloName: "client.test",
      smarthost: { host: "127.0.0.1", port, auth: { user: "relay-user", pass: "relay-pass" }, tls: "never" },
    });

    expect(await worker.tick()).toBe(1);

    // 릴레이가 하는 일을 그대로 적용한다: Message-ID를 자기 것으로 교체.
    const delivered = new TextDecoder().decode(relay.received[0]!.raw);
    expect(delivered).toContain(SUBMITTED_MSGID); // 우리가 보낸 것은 원래 값
    const atDestination = delivered.replace(SUBMITTED_MSGID, REWRITTEN_MSGID);

    const resolveTxt = async (name: string): Promise<string[]> => {
      expect(name).toBe("ed1._domainkey.sender.test");
      return [keyPair.dnsRecord];
    };
    const results = await dkimVerify(new TextEncoder().encode(atDestination), resolveTxt);
    expect(results).toHaveLength(1);
    expect(results[0]?.result).toBe("pass");

    await db.close();
  });

  test("③ 직접 발송은 message-id를 계속 서명한다 (기본값 유지 — 릴레이 제약을 퍼뜨리지 않는다)", async () => {
    const db = await freshDb();
    const mx = mxServer(); // ★submission 서버를 재사용하면 안 된다 — 직접 발송은 AUTH를 하지 않는다
    const port = await mx.start();
    const raw = new TextEncoder().encode(RAW_TEXT);
    const blobId = "f".repeat(64);
    await insertQueueRow(db, blobId);

    const keyPair = generateDkimKeyPair("ed25519-sha256");
    const dkim: DkimHook = {
      selectorFor: async () => [{ selector: "ed1", privateKey: keyPair.privateKeyPem, algorithm: "ed25519-sha256" }],
    };

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: async () => [{ exchange: "127.0.0.1", priority: 10 }],
      dkim,
      ehloName: "client.test",
      port,
    });

    expect(await worker.tick()).toBe(1);
    expect(mx.received).toHaveLength(1);
    expect(signedHeaderNames(mx.received[0]!.raw)).toContain("message-id");

    await db.close();
  });

  test("★④ 키가 여러 개면 서명도 여러 개 붙고 각각 독립적으로 검증된다 (이중 서명)", async () => {
    // 왜: Ed25519 단독 서명이면 그것을 검증하지 않는 수신자에게는 우리 서명이 없는 것과 같다.
    // Gmail 실측 `dkim=neutral (no key) header.s=ed1` — 우리 서명·키·DNS는 전부 정상이었고
    // `fail`이 아니라 `neutral`(검증을 시도하지 않음)인 것이 신호였다.
    const db = await freshDb();
    const mx = mxServer();
    const port = await mx.start();
    const raw = new TextEncoder().encode(RAW_TEXT);
    const blobId = "a".repeat(64);
    await insertQueueRow(db, blobId);

    const ed = generateDkimKeyPair("ed25519-sha256");
    const rsa = generateDkimKeyPair("rsa-sha256");
    const dkim: DkimHook = {
      selectorFor: async () => [
        { selector: "ed1", privateKey: ed.privateKeyPem, algorithm: "ed25519-sha256" },
        { selector: "rsa1", privateKey: rsa.privateKeyPem, algorithm: "rsa-sha256" },
      ],
    };

    const worker = new MtaWorker({
      db,
      blobs: fakeBlobs(blobId, raw),
      resolveMx: async () => [{ exchange: "127.0.0.1", priority: 10 }],
      dkim,
      ehloName: "client.test",
      port,
    });

    expect(await worker.tick()).toBe(1);
    const delivered = mx.received[0]!.raw;
    const text = new TextDecoder().decode(delivered);

    // 서명이 두 개 붙었는가 — 예전 구현(LIMIT 1)은 하나뿐이었다.
    expect((text.match(/^DKIM-Signature:/gm) ?? []).length).toBe(2);
    expect(text).toContain("s=ed1");
    expect(text).toContain("s=rsa1");

    // ★둘 다 **독립적으로** 검증돼야 한다. 서명이 서로의 헤더를 서명 범위에 넣으면
    //   나중에 붙은 것만 통과하고 먼저 붙은 것이 깨진다 — 그 회귀를 여기서 잡는다.
    const results = await dkimVerify(delivered, async (name) => {
      if (name === "ed1._domainkey.sender.test") return [ed.dnsRecord];
      if (name === "rsa1._domainkey.sender.test") return [rsa.dnsRecord];
      throw new Error(`unexpected TXT: ${name}`);
    });
    expect(results).toHaveLength(2);
    for (const r of results) expect(r.result).toBe("pass");

    await db.close();
  });
});
