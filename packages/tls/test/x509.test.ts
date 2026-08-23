/** 셀프사인 X.509 생성 — 파싱·SAN·실제 TLS 핸드셰이크 수용 + selfsigned 소스(영속/재사용/refresh). */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { X509Certificate } from "node:crypto";
import * as tls from "node:tls";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSelfSigned, inspectCert, selfSignedCertSource } from "@ionosphere/tls";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs.length = 0;
});
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-ss-"));
  dirs.push(d);
  return d;
}

describe("generateSelfSigned", () => {
  test("X509Certificate로 파싱 — subject/SAN/유효기간/자기서명", () => {
    const { certPem } = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local", "autoconfig.test.local"] });
    const x = new X509Certificate(certPem);
    expect(x.subject).toContain("mx.test.local");
    expect(x.subjectAltName).toContain("mx.test.local");
    expect(x.subjectAltName).toContain("autoconfig.test.local");
    expect(x.issuer).toBe(x.subject); // 셀프사인
    expect(Date.parse(x.validTo)).toBeGreaterThan(Date.now());
    const info = inspectCert(certPem);
    expect(info.sans).toEqual(["mx.test.local", "autoconfig.test.local"]);
    expect(info.selfSigned).toBe(true);
  });

  test("실제 node:tls 핸드셰이크로 수용됨(DER 유효성 증명)", async () => {
    const { keyPem, certPem } = generateSelfSigned({ commonName: "localhost", sans: ["localhost"] });
    const server = tls.createServer({ key: keyPem, cert: certPem }, (sock) => {
      sock.end("ok");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      const peer = await new Promise<tls.PeerCertificate>((resolve, reject) => {
        const c = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false }, () => {
          const cert = c.getPeerCertificate();
          c.end();
          resolve(cert);
        });
        c.on("error", reject);
      });
      expect(peer.subject.CN).toBe("localhost");
    } finally {
      server.close();
    }
  });

  test("SAN 미지정 시 commonName 하나를 SAN으로", () => {
    const { certPem } = generateSelfSigned({ commonName: "solo.test" });
    expect(inspectCert(certPem).sans).toEqual(["solo.test"]);
  });
});

describe("selfSignedCertSource", () => {
  test("resolve가 생성+영속, 재resolve는 재사용(동일 인증서)", async () => {
    const dir = tmp();
    const s = selfSignedCertSource({ commonName: "mx.test.local", dir });
    const a = await s.resolve();
    expect(a).not.toBeNull();
    const persistedCert = readFileSync(join(dir, "tls-selfsigned.cert.pem"));
    expect(Buffer.from(a!.cert).equals(persistedCert)).toBe(true);
    const b = await s.resolve();
    expect(Buffer.from(b!.cert).equals(Buffer.from(a!.cert))).toBe(true); // 재사용(재생성 아님)
  });

  test("refresh는 새 인증서로 재생성(직렬번호 상이)", async () => {
    const dir = tmp();
    const s = selfSignedCertSource({ commonName: "mx.test.local", dir });
    const a = await s.resolve();
    const c = await s.refresh!();
    expect(new X509Certificate(Buffer.from(c.cert)).serialNumber).not.toBe(new X509Certificate(Buffer.from(a!.cert)).serialNumber);
  });

  test("status가 mode/SAN/만료 표시", async () => {
    const dir = tmp();
    const s = selfSignedCertSource({ commonName: "mx.test.local", sans: ["mx.test.local"], dir });
    await s.resolve();
    const st = await s.status();
    expect(st).toMatchObject({ mode: "selfsigned", enabled: true, selfSigned: true });
    expect(st.notAfter).toBeGreaterThan(Date.now());
  });
});
