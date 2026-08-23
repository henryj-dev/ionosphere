/**
 * TLS 핫리로드 — ImapServer(993)/SmtpServer(465)의 setSecureContext로 무중단 인증서 교체.
 * ⚠ 런타임 제약: node는 무중단 스왑 O, **bun 1.3.14는 setSecureContext/SNICallback 스왑 미지원**
 * (실측 확인). 라이브가 bun이면 갱신 반영엔 프로세스 재시작이 필요(acme reloadcmd). 이 테스트는
 * node에서 실제 스왑을, bun에선 no-op(제약 문서화)을 검증한다.
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import * as tls from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ImapServer } from "@ionosphere/proto-imap";
import { SmtpServer } from "@ionosphere/proto-smtp";
import { generateSelfSigned, type CertSource, type TlsMaterial } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
import { offlineResolver } from "./helpers.ts";

const A = generateSelfSigned({ commonName: "a.test", sans: ["a.test"] });
const B = generateSelfSigned({ commonName: "b.test", sans: ["b.test"] });

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(closers.map((c) => c()));
  closers.length = 0;
});

/** TLS로 붙어 제시된 인증서의 CN을 읽는다(핸드셰이크만, 앱 프로토콜 미사용). */
function peerCN(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const c = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false }, () => {
      // node 타입에서 CN은 string | string[]다(다중 CN 인증서). 첫 값만 본다.
      const rawCn = c.getPeerCertificate().subject?.CN;
      const cn = Array.isArray(rawCn) ? (rawCn[0] ?? "") : (rawCn ?? "");
      c.end();
      resolve(cn);
    });
    c.on("error", reject);
  });
}

const stubImapBackend = {} as unknown as ConstructorParameters<typeof ImapServer>[0]["backend"];
const stubSmtpBackend = { verifyRecipient: async () => ({ ok: true as const }), deliver: async () => ({ ok: true as const }) };

describe("reloadTls 핫리로드 (node=setSecureContext / bun=리스너 재생성 — 양 런타임 동작)", () => {
  test("ImapServer(암시적 TLS 993) 인증서 교체가 실제 반영", async () => {
    const s = new ImapServer({ hostname: "mx.test", backend: stubImapBackend, tls: { key: A.keyPem, cert: A.certPem } });
    const port = await s.listen(0, "127.0.0.1");
    closers.push(() => s.close());
    expect(await peerCN(port)).toBe("a.test");
    await s.reloadTls({ key: B.keyPem, cert: B.certPem });
    expect(await peerCN(port)).toBe("b.test"); // 두 런타임 모두 새 인증서(포트 동일 유지)
  });

  test("SmtpServer(암시적 TLS 465) 인증서 교체가 실제 반영", async () => {
    const s = new SmtpServer({ hostname: "mx.test", maxSizeBytes: 1_000_000, backend: stubSmtpBackend, tls: { key: A.keyPem, cert: A.certPem }, implicitTls: true });
    const port = await s.listen(0, "127.0.0.1");
    closers.push(() => s.close());
    expect(await peerCN(port)).toBe("a.test");
    await s.reloadTls({ key: B.keyPem, cert: B.certPem });
    expect(await peerCN(port)).toBe("b.test");
  });

  test("평문 서버(143)에서 reloadTls는 no-op(에러 없음)", async () => {
    const s = new ImapServer({ hostname: "mx.test", backend: stubImapBackend });
    await s.listen(0, "127.0.0.1");
    closers.push(() => s.close());
    await expect(s.reloadTls({ key: A.keyPem, cert: A.certPem })).resolves.toBeUndefined();
  });
});

/** watch()로 갱신을 임의 발화할 수 있는 인증서 소스. */
function watchableCertSource(initial: TlsMaterial): CertSource & { fire(m: TlsMaterial): void } {
  let onChange: ((m: TlsMaterial) => void) | null = null;
  return {
    mode: "file",
    resolve: async () => initial,
    status: async () => ({ mode: "file" as const, enabled: true, source: "test" }),
    watch(cb) {
      onChange = cb;
      return () => {
        onChange = null;
      };
    },
    fire(m) {
      onChange?.(m);
    },
  };
}

describe("app.reloadAllTls 대상 리스너", () => {
  /**
   * 회귀: reloadAllTls가 993/995/465/443만 교체하고 **25/587(STARTTLS)은 아예 호출하지 않았다.**
   * 증상이 갱신 직후가 아니라 만료 시점에 나타나서 놓치기 쉬운 종류라 배선 자체를 못박는다.
   * (실제 인증서 스왑은 proto-smtp/test/tls-reload.test.ts가 검증 — 여기서는 "호출되는가"만.)
   */
  test("인증서 갱신이 STARTTLS 리스너(25/587)까지 도달한다", async () => {
    const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-tlsreload-"));
    const certSource = watchableCertSource({ key: A.keyPem, cert: A.certPem });
    const app = new IonosphereApp({
      hostname: "mx.test",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      submissionPort: 0,
      certSource,
      resolver: offlineResolver(),
      runMtaWorker: false,
      runWebhookWorker: false,
      runReaper: false,
      blobGcMode: "off",
    });
    await app.start();
    closers.push(async () => {
      await app.stop();
      rmSync(blobRoot, { recursive: true, force: true });
    });

    const seen = new Set<string>();
    const spy = (name: string, srv: { reloadTls(m: TlsMaterial): Promise<void> }): void => {
      const orig = srv.reloadTls.bind(srv);
      srv.reloadTls = async (m: TlsMaterial) => {
        seen.add(name);
        await orig(m);
      };
    };
    expect(app.smtp).toBeDefined();
    expect(app.submission).toBeDefined();
    spy("smtp", app.smtp!);
    spy("submission", app.submission!);

    certSource.fire({ key: B.keyPem, cert: B.certPem });

    // reloadAllTls는 watch 콜백에서 void로 띄워지므로 몇 틱 기다린다.
    for (let i = 0; i < 100 && !(seen.has("smtp") && seen.has("submission")); i++) {
      await new Promise((r) => setTimeout(r, 10));
    }
    expect([...seen].sort()).toEqual(["smtp", "submission"]);
  });
});
