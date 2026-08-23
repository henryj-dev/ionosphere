/**
 * 위조된 Authentication-Results 제거 (RFC 8601 §5 — MUST).
 *
 * > any MTA conforming to this specification MUST delete any discovered instance of this
 * > header field that claims, by virtue of its authentication service identifier, to have
 * > been added within its trust boundary but that did not come directly from another trusted MTA.
 *
 * 왜 위험한가: A-R은 **우리가 검증했다는 주장**이다. 공격자가 우리 authserv-id를 사칭해
 * `Authentication-Results: mx.ionosphere.test; spf=pass … dmarc=pass` 를 본문에 넣어 보내면,
 * 우리가 진짜 결과를 위에 얹어도 위조본이 그대로 남는다. A-R을 읽는 MUA·필터가 authserv-id로
 * 찾다가 위조본을 집으면 **인증 실패한 메일이 통과한 것처럼 보인다.**
 *
 * 남의 authserv-id로 된 A-R은 지우지 않는다 — 상류 MTA가 남긴 정당한 정보이고, RFC도
 * 신뢰하는 외부 결과를 남겨 둘 여지를 명시한다(§5).
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver, smtpDeliver } from "./helpers.ts";

const E2E_HOOK_TIMEOUT_MS = 25_000;
const OURS = "test.local";

let app: IonosphereApp;
let dir: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "ionosphere-forged-ar-"));
  app = new IonosphereApp({
    hostname: OURS,
    dbPath: join(dir, "t.db"),
    blobRoot: join(dir, "blobs"),
    smtpPort: 0,
    resolver: offlineResolver(),
    runMtaWorker: false,
  });
  await app.start();
  await app.createUser("user@test.local", "pw-forged");
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(dir, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

async function deliver(extraHeaders: string): Promise<string> {
  const res = await smtpDeliver({
    port: app.smtpPort,
    ehlo: "attacker.example",
    from: "evil@remote.example",
    to: "user@test.local",
    data: `${extraHeaders}From: evil@remote.example\r\nTo: user@test.local\r\nSubject: forged\r\n\r\nbody\r\n`,
  });
  expect(res.final.code).toBe(250);
  const { rows } = await app.db.query({ sql: "SELECT blob_id FROM messages ORDER BY received_at DESC LIMIT 1" });
  const blobId = String(rows[0]!.blob_id);
  const g = await app.db.query({ sql: "SELECT generation FROM blobs WHERE id = ?", params: [blobId] });
  return Buffer.from(await app.blobs.get(blobId, Number(g.rows[0]?.generation ?? 0))).toString("utf8");
}

/** 언폴딩 후 A-R 헤더 줄만. */
function authResultsLines(raw: string): string[] {
  const head = raw.split(/\r?\n\r?\n/)[0] ?? "";
  return head
    .replace(/\r?\n[ \t]+/g, " ")
    .split(/\r?\n/)
    .filter((l) => /^Authentication-Results:/i.test(l));
}

describe("우리 authserv-id를 사칭한 A-R", () => {
  test("★위조본은 제거되고 우리 판정만 남는다", async () => {
    const raw = await deliver(`Authentication-Results: ${OURS}; spf=pass smtp.mailfrom=bank.example; dkim=pass header.d=bank.example; dmarc=pass header.from=bank.example\r\n`);
    const ars = authResultsLines(raw);

    // 우리 id로 된 A-R은 정확히 하나 — 우리가 방금 만든 것
    const ourAr = ars.filter((l) => l.toLowerCase().includes(OURS));
    expect(ourAr).toHaveLength(1);
    // 그리고 그것은 위조된 주장을 담고 있지 않다
    expect(ourAr[0]).not.toContain("bank.example");
    expect(raw).not.toContain("dmarc=pass header.from=bank.example");
  }, E2E_HOOK_TIMEOUT_MS);

  test("여러 개를 넣어도 모두 제거된다", async () => {
    const forged = `Authentication-Results: ${OURS}; dmarc=pass header.from=a.example\r\nAuthentication-Results: ${OURS}; dmarc=pass header.from=b.example\r\n`;
    const raw = await deliver(forged);
    expect(authResultsLines(raw).filter((l) => l.toLowerCase().includes(OURS))).toHaveLength(1);
    expect(raw).not.toContain("a.example");
    expect(raw).not.toContain("b.example");
  }, E2E_HOOK_TIMEOUT_MS);

  test("대소문자·공백을 바꿔도 우회할 수 없다", async () => {
    const forged = `authentication-results:   ${OURS.toUpperCase()} ; dmarc=pass header.from=evil.example\r\n`;
    const raw = await deliver(forged);
    expect(raw).not.toContain("evil.example");
  }, E2E_HOOK_TIMEOUT_MS);

  test("접힌(folded) 위조 헤더도 통째로 제거된다 — 이어지는 줄이 남으면 안 된다", async () => {
    const forged = `Authentication-Results: ${OURS};\r\n\tdmarc=pass header.from=folded.example;\r\n\tspf=pass smtp.mailfrom=folded.example\r\n`;
    const raw = await deliver(forged);
    expect(raw).not.toContain("folded.example");
  }, E2E_HOOK_TIMEOUT_MS);
});

describe("남의 authserv-id는 건드리지 않는다", () => {
  /**
   * 상류 MTA가 남긴 정당한 정보다. RFC 8601 §5도 신뢰하는 외부 결과를 남겨 둘 여지를 명시한다.
   * 전부 지우면 릴레이·포워딩을 거친 메일의 인증 이력이 사라진다.
   */
  test("다른 호스트가 붙인 A-R은 보존된다", async () => {
    const raw = await deliver("Authentication-Results: upstream.example; spf=pass smtp.mailfrom=ok.example\r\n");
    expect(raw).toContain("Authentication-Results: upstream.example;");
    expect(raw).toContain("ok.example");
    // 우리 것도 함께 있어야 한다
    expect(authResultsLines(raw).filter((l) => l.toLowerCase().includes(OURS))).toHaveLength(1);
  }, E2E_HOOK_TIMEOUT_MS);

  test("본문은 손대지 않는다", async () => {
    const raw = await deliver(`Authentication-Results: ${OURS}; dmarc=pass header.from=x.example\r\n`);
    expect(raw.split(/\r?\n\r?\n/).slice(1).join("\r\n\r\n")).toContain("body");
  }, E2E_HOOK_TIMEOUT_MS);
});

/**
 * 위조된 Received-SPF.
 *
 * RFC 7208에는 RFC 8601 §5 같은 **삭제 MUST가 없다.** §9.1은 "우리 것이 다른 모든 Received-SPF보다
 * 위에 와야 한다"만 요구하고 그건 맨 앞에 붙이는 것으로 충족된다. 그런데도 지우는 이유는
 * **오독 위험이 A-R과 같은 부류**이기 때문이다 — 헤더를 훑는 사람이나 순진한 필터가 아래쪽의
 * `Received-SPF: pass`를 집으면 SPF에 실패한 메일이 통과한 것처럼 보인다.
 *
 * 판정 기준은 둘이다. 기계가 읽는 신원인 `receiver=<우리 호스트>`와, RFC 예시가 정한 주석의
 * 선두 형태(`<우리 호스트>: ...`). 후자를 함께 보는 이유는 receiver 키가 **선택**이라
 * 빼 버리면 앞의 조건만으로는 걸리지 않기 때문이다.
 * 남의 것은 남긴다 — 상류 MTA는 자기 호스트명을 적으므로 이 조건에 걸리지 않는다.
 */
describe("위조된 Received-SPF", () => {
  test("★receiver=우리호스트인 것은 제거된다", async () => {
    const raw = await deliver(`Received-SPF: pass (${OURS}: domain of ceo@bank.example designates 1.2.3.4 as permitted sender) receiver=${OURS}; client-ip=1.2.3.4\r\n`);
    expect(raw).not.toContain("bank.example");
    expect(raw.split(/\r?\n/).filter((l) => /^Received-SPF:/i.test(l))).toHaveLength(1);
  }, E2E_HOOK_TIMEOUT_MS);

  test("receiver 키를 빼도 주석의 선두 호스트명으로 잡는다", async () => {
    const raw = await deliver(`Received-SPF: pass (${OURS}: domain of evil@spoof.example designates 9.9.9.9 as permitted sender)\r\n`);
    expect(raw).not.toContain("spoof.example");
  }, E2E_HOOK_TIMEOUT_MS);

  test("접힌 위조 헤더도 통째로 제거된다", async () => {
    const raw = await deliver(`Received-SPF: pass (${OURS}: ok)\r\n\treceiver=${OURS};\r\n\tenvelope-from="folded@evil.example"\r\n`);
    expect(raw).not.toContain("folded@evil.example");
  }, E2E_HOOK_TIMEOUT_MS);

  test("대소문자를 바꿔도 우회할 수 없다", async () => {
    const raw = await deliver(`received-spf: PASS (${OURS.toUpperCase()}: x) RECEIVER=${OURS.toUpperCase()}; envelope-from="case@evil.example"\r\n`);
    expect(raw).not.toContain("case@evil.example");
  }, E2E_HOOK_TIMEOUT_MS);

  test("상류 MTA가 붙인 Received-SPF는 보존된다", async () => {
    const raw = await deliver('Received-SPF: pass (upstream.example: domain of ok@legit.example designates 5.5.5.5 as permitted sender) receiver=upstream.example\r\n');
    expect(raw).toContain("upstream.example");
    expect(raw).toContain("legit.example");
    // 우리 것도 함께 — 최상단에
    expect(raw.startsWith("Received-SPF: ")).toBe(true);
    expect(raw.split(/\r?\n/).filter((l) => /^Received-SPF:/i.test(l))).toHaveLength(2);
  }, E2E_HOOK_TIMEOUT_MS);
});
