/**
 * 신뢰 릴레이 예외 — 2026-08-17 라이브 헤더에서 드러난 사고의 회귀 테스트.
 *
 * 실제 모양: `you@ionosphere.test`(로컬 도메인) 앞으로 온 메일을 MSA가 릴레이 없이 우리 MX로
 * 직송하는데, 3대 분리 후 그 홉이 사설망을 타서 MX가 보는 접속 IP가 `10.0.82.134`였다.
 * apex SPF에는 MSA의 **공인** IP만 있고 `-all`이라 판정은 `fail`이고, SPF 레코드 쪽에는 고칠
 * 방법이 없다(사설 대역을 공개 SPF에 적는 것은 외부에 무의미하고 그 대역 전체에 우리 도메인을
 * 위임하는 것이다).
 *
 * 여기서 고정하는 계약은 셋이다:
 *   ① 신뢰 대역에서 온 홉은 SPF를 **평가하지 않는다**(결과를 뒤집는 게 아니다).
 *   ② DKIM·DMARC는 그대로 돈다 — 내부 DKIM 회귀를 우리 손으로 못 보게 되면 안 된다.
 *   ③ 기본값은 "아무도 신뢰 안 함"이라 설정 전 동작이 바뀌지 않는다.
 */
import { afterAll, beforeAll, describe, expect, test, SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import { DnsNotFoundError, dkimSign, generateDkimKeyPair, type DnsResolver } from "@ionosphere/mail-auth";
import { parseMessage } from "@ionosphere/mime";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInboundAuth } from "../src/inbound-auth.ts";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS } from "./helpers.ts";

function fakeResolver(txt: Record<string, string[]>): DnsResolver {
  const get = (name: string): string[] => {
    const v = txt[name.toLowerCase()];
    if (!v) throw new DnsNotFoundError(name);
    return v;
  };
  const nf = (): never => {
    throw new DnsNotFoundError("none");
  };
  return { txt: async (n) => get(n), mx: async () => nf(), a: async () => nf(), aaaa: async () => nf(), ptr: async () => nf() };
}

const enc = (s: string) => new TextEncoder().encode(s);

/** 라이브와 같은 모양: 우리 도메인이 DKIM 서명한 메일이 사설 IP에서 도착한다. */
function liveShape(): { raw: Uint8Array; resolver: DnsResolver } {
  const { privateKeyPem, dnsRecord } = generateDkimKeyPair("rsa-sha256");
  const base = [
    "From: Henry <team_dev@ionosphere.test>",
    "To: you@ionosphere.test",
    "Subject: hi",
    "Message-Id: <live@ionosphere.test>",
    "",
    "body",
  ].join("\r\n");
  const sig = dkimSign(enc(base), {
    domain: "ionosphere.test",
    selector: "rsa1",
    privateKey: privateKeyPem,
    algorithm: "rsa-sha256",
  });
  return {
    raw: enc(sig + "\r\n" + base),
    resolver: fakeResolver({
      // 실측 apex SPF — 공인 IP만 있고 하드페일이다. 사설 홉은 여기 들 수가 없다.
      "ionosphere.test": ["v=spf1 ip4:203.0.113.113 -all"],
      "rsa1._domainkey.ionosphere.test": [dnsRecord],
      "_dmarc.ionosphere.test": ["v=DMARC1; p=quarantine; adkim=s; aspf=r"],
    }),
  };
}

describe("신뢰 릴레이 예외 — 인증 파이프라인", () => {
  test("설정 전(기본): 사설 홉이 spf=fail로 판정된다 — 사고 재현", async () => {
    const { raw, resolver } = liveShape();
    const auth = await runInboundAuth(
      {
        raw,
        parsed: parseMessage(raw),
        clientIp: "10.0.82.134",
        heloName: "smtp.ionosphere.test",
        mailFrom: "team_dev@ionosphere.test",
        authservId: "mx.ionosphere.test",
      },
      resolver,
    );
    expect(auth.summary.spf).toBe("fail");
    expect(auth.codes.spf).toBe(2);
    expect(auth.authResults).toContain("spf=fail");
    // ★DMARC가 통과하는 것은 DKIM 정렬 하나 덕분이다 — SPF는 이미 고정 실패다.
    expect(auth.summary.dmarc).toBe("pass");
  });

  test("신뢰 릴레이: SPF를 평가하지 않는다(뒤집지 않는다)", async () => {
    const { raw, resolver } = liveShape();
    const auth = await runInboundAuth(
      {
        raw,
        parsed: parseMessage(raw),
        clientIp: "10.0.82.134",
        heloName: "smtp.ionosphere.test",
        mailFrom: "team_dev@ionosphere.test",
        authservId: "mx.ionosphere.test",
        trustedRelay: true,
      },
      resolver,
    );
    // A-R에 spf 절이 아예 없다 — `spf=pass`로 위조하지도, `spf=none`으로 뭉개지도 않는다.
    expect(auth.authResults).not.toContain("spf=");
    expect(auth.summary.spf).toBeUndefined();
    // 저장 코드는 null = "검사 안 함". 0(none: 레코드 없음)과 구별돼야 집계가 거짓말을 안 한다.
    expect(auth.codes.spf).toBe(null);
    // 확인하지 않은 판정을 헤더로 주장하지 않는다.
    expect(auth.receivedSpf).toBeUndefined();
  });

  test("신뢰 릴레이라도 DKIM·DMARC는 그대로 돈다", async () => {
    const { raw, resolver } = liveShape();
    const auth = await runInboundAuth(
      {
        raw,
        parsed: parseMessage(raw),
        clientIp: "10.0.82.134",
        heloName: "smtp.ionosphere.test",
        mailFrom: "team_dev@ionosphere.test",
        authservId: "mx.ionosphere.test",
        trustedRelay: true,
      },
      resolver,
    );
    expect(auth.summary.dkim).toBe("pass");
    expect(auth.codes.dkim).toBe(1);
    expect(auth.summary.dmarc).toBe("pass"); // DKIM 정렬만으로 통과 — SPF 증거는 없음
    expect(auth.authResults).toContain("dkim=pass");
  });

  test("서명이 깨지면 신뢰 릴레이여도 dmarc=fail이 보인다", async () => {
    // ★이 프로젝트는 릴레이가 Message-ID를 재작성해 DKIM이 조용히 깨진 적이 있다.
    // 내부 홉이라고 인증을 통째로 끄면 그 회귀를 우리 손으로 볼 수 없게 된다.
    const { raw, resolver } = liveShape();
    const tampered = enc(Buffer.from(raw).toString("latin1").replace("Subject: hi", "Subject: hj"));
    const auth = await runInboundAuth(
      {
        raw: tampered,
        parsed: parseMessage(tampered),
        clientIp: "10.0.82.134",
        heloName: "smtp.ionosphere.test",
        mailFrom: "team_dev@ionosphere.test",
        authservId: "mx.ionosphere.test",
        trustedRelay: true,
      },
      resolver,
    );
    expect(auth.summary.dkim).toBe("fail");
    expect(auth.summary.dmarc).toBe("fail");
  });
});

/**
 * 조립 검증 — 옵션이 실제로 게이트에 닿는가.
 *
 * greylist를 골라 본 이유: 이 예외가 없으면 우리 MSA가 우리 MX에서 451을 맞는다(spfPass가
 * false라 면제가 안 걸린다). 그래서 "첫 대면인데 250"이 곧 예외가 배선됐다는 증거다.
 * (greylist-wire.test.ts의 반대 방향 — 그쪽은 신뢰 목록 없이 451을 확인한다.)
 */
function relaySend(port: number, from: string, to: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const msg = `From: ${from}\r\nTo: ${to}\r\nSubject: tr\r\n\r\nhi\r\n.\r\n`;
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

function offline(): DnsResolver {
  const nf = (): never => {
    throw new DnsNotFoundError("none");
  };
  return { txt: async () => nf(), mx: async () => nf(), a: async () => nf(), aaaa: async () => nf(), ptr: async () => nf() };
}

describe("신뢰 릴레이 예외 — 조립", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-tr-"));
    app = new IonosphereApp({
      hostname: "mx.test",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      resolver: offline(),
      greylist: { delayMs: 3_600_000, expireMs: 3_600_000 }, // 면제가 없으면 반드시 defer된다
      trustedRelays: ["127.0.0.1/32", "::1/128"], // 테스트 하네스의 접속 주소
    });
    await app.start();
    await app.createUser("rcpt@mx.test", "pw");
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("신뢰 대역 접속은 첫 대면에도 greylist에 걸리지 않는다", async () => {
    const r = await relaySend(app.smtpPort, "stranger@ext.test", "rcpt@mx.test");
    expect(r).toStartWith("250");
  });
});

describe("신뢰 릴레이 예외 — 설정 가드", () => {
  test("잘못된 CIDR은 기동에서 드러난다", () => {
    // 조용히 빈 목록이 되면 운영자는 예외가 걸린 줄 알고 계속 fail을 본다.
    expect(
      () =>
        new IonosphereApp({
          hostname: "mx.test",
          dbPath: ":memory:",
          blobRoot: tmpdir(),
          smtpPort: 0,
          pop3Port: 0,
          trustedRelays: ["10.0.82.999/32"],
        }),
    ).toThrow();
  });
});
