/**
 * selfsigned CertSource — 셀프사인 인증서를 생성하고 디스크에 영속화한다.
 * 재부팅마다 재생성하면 클라이언트가 매번 재신뢰해야 하므로, 유효한 파일이 있으면 재사용하고
 * 없거나 만료 임박 시에만 생성한다. refresh()로 강제 재생성.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { inspectCert } from "./inspect.ts";
import { generateSelfSigned } from "./x509.ts";
import type { CertSource, CertStatus, TlsMaterial } from "./types.ts";

export interface SelfSignedSourceOptions {
  commonName: string;
  sans?: string[];
  /** 키/인증서 영속 디렉토리. 기본 파일명 tls-selfsigned.{key,cert}.pem. */
  dir: string;
  days?: number;
  /** 남은 유효기간이 이 일수 미만이면 재생성. 기본 30. */
  renewWithinDays?: number;
}

export function selfSignedCertSource(opts: SelfSignedSourceOptions): CertSource {
  const keyPath = join(opts.dir, "tls-selfsigned.key.pem");
  const certPath = join(opts.dir, "tls-selfsigned.cert.pem");
  const renewWithin = opts.renewWithinDays ?? 30;

  async function loadExisting(): Promise<TlsMaterial | null> {
    try {
      const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
      const info = inspectCert(cert);
      if (info.error || info.notAfter === undefined) return null;
      const daysLeft = (info.notAfter - Date.now()) / 86_400_000;
      if (daysLeft < renewWithin) return null; // 만료 임박 → 재생성 유도
      return { key, cert };
    } catch {
      return null;
    }
  }

  async function generateAndPersist(): Promise<TlsMaterial> {
    const gen = generateSelfSigned({ commonName: opts.commonName, ...(opts.sans ? { sans: opts.sans } : {}), ...(opts.days ? { days: opts.days } : {}) });
    await mkdir(dirname(certPath), { recursive: true });
    await writeFile(keyPath, gen.keyPem, { mode: 0o600 });
    await writeFile(certPath, gen.certPem);
    return { key: gen.keyPem, cert: gen.certPem };
  }

  return {
    mode: "selfsigned",
    async resolve() {
      return (await loadExisting()) ?? (await generateAndPersist());
    },
    async refresh() {
      return generateAndPersist();
    },
    async status(): Promise<CertStatus> {
      try {
        const cert = await readFile(certPath);
        return { mode: "selfsigned", enabled: true, source: certPath, ...inspectCert(cert) };
      } catch {
        return { mode: "selfsigned", enabled: true, source: `${certPath} (미생성 — resolve 시 생성)`, selfSigned: true };
      }
    },
  };
}
