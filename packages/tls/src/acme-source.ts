/**
 * acme CertSource — ACME(RFC 8555)로 인증서를 발급/영속하고 만료 임박 시 자동 갱신한다.
 * 계정 키/인증서/개인키를 디스크에 영속(계정 키 재사용). refresh=강제 재발급, watch=주기 갱신 체크.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { noopLogger, type Logger } from "@ionosphere/core";
import { generateAccountKey, requestCertificate, type AcmeChallenge } from "./acme.ts";
import { inspectCert } from "./inspect.ts";
import { checkTransportUrl, insecureTransportWarning } from "./secure-url.ts";
import { assertUsableCert } from "./verify.ts";
import type { CertSource, CertStatus, TlsMaterial } from "./types.ts";

export interface AcmeSourceOptions {
  domains: string[];
  directoryUrl: string;
  /** dns-01(DnsProvider) 또는 http-01(80포트 리스너). 갈래는 판별 유니온 — acme.ts 주석 참고. */
  challenge: AcmeChallenge;
  /** 계정키/인증서/개인키 영속 디렉토리. */
  dir: string;
  contactEmail?: string;
  /** 남은 유효기간이 이 일수 미만이면 갱신. 기본 30. */
  renewWithinDays?: number;
  /** 갱신 체크 주기(ms). 기본 12h. */
  checkIntervalMs?: number;
  fetch?: typeof fetch;
  logger?: Logger;
  dnsPropagationMs?: number;
  pollIntervalMs?: number;
  pollMaxTries?: number;
}

export function acmeCertSource(opts: AcmeSourceOptions): CertSource {
  const log = (opts.logger ?? noopLogger).child({ component: "acme-source" });
  /**
   * 평문 디렉터리는 발급 흐름 전체(계정 키 JWS·챌린지·인증서)를 중간자에게 연다. 막지는 않고
   * 경고한다(url cert와 같은 정책 — secure-url.ts checkTransportUrl 주석).
   *
   * ★경고를 **여기서도** 낸다. AcmeClient는 첫 발급 때 지연 생성되므로 거기에만 두면
   * 기동 로그에 아무것도 안 남고, 몇 주 뒤 갱신 시점에야 처음 드러난다.
   */
  const dir = checkTransportUrl("ACME directory URL", opts.directoryUrl);
  if (dir.insecure) log.warn(insecureTransportWarning("ACME directory URL", dir.url), { phase: "startup" });
  const accountKeyPath = join(opts.dir, "acme-account.key.pem");
  const certPath = join(opts.dir, "acme-cert.pem");
  const keyPath = join(opts.dir, "acme-key.pem");
  const renewWithin = opts.renewWithinDays ?? 30;
  let timer: ReturnType<typeof setInterval> | null = null;

  async function accountKey(): Promise<string> {
    try {
      return (await readFile(accountKeyPath)).toString();
    } catch {
      const pem = generateAccountKey();
      await mkdir(opts.dir, { recursive: true });
      await writeFile(accountKeyPath, pem, { mode: 0o600 });
      return pem;
    }
  }

  async function loadExisting(): Promise<TlsMaterial | null> {
    try {
      const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
      const info = inspectCert(cert);
      if (info.error || info.notAfter === undefined) return null;
      if ((info.notAfter - Date.now()) / 86_400_000 < renewWithin) return null; // 갱신 필요
      return { key, cert };
    } catch {
      return null;
    }
  }

  async function issue(): Promise<TlsMaterial> {
    const accountKeyPem = await accountKey();
    log.info("acme issue 시작", { domains: opts.domains });
    const { certPem, keyPem } = await requestCertificate(
      {
        directoryUrl: opts.directoryUrl,
        accountKeyPem,
        challenge: opts.challenge,
        ...(opts.contactEmail ? { contactEmail: opts.contactEmail } : {}),
        ...(opts.fetch ? { fetch: opts.fetch } : {}),
        ...(opts.logger ? { logger: opts.logger } : {}),
        ...(opts.dnsPropagationMs !== undefined ? { dnsPropagationMs: opts.dnsPropagationMs } : {}),
        ...(opts.pollIntervalMs !== undefined ? { pollIntervalMs: opts.pollIntervalMs } : {}),
        ...(opts.pollMaxTries !== undefined ? { pollMaxTries: opts.pollMaxTries } : {}),
      },
      opts.domains,
    );
    /**
     * 발급분을 **디스크에 쓰기 전에** 검사한다. 예전엔 파싱조차 없이 덮어썼는데, 그러면 응답이
     * 인증서가 아니어도(오류 본문·잘린 체인) 기존 유효 인증서를 지운 뒤에야 리슨에서 터진다.
     * 요청한 도메인이 SAN에 없으면 그 인증서로는 어차피 클라이언트가 붙지 못하므로 같이 본다.
     */
    assertUsableCert("ACME 발급 자재", certPem, keyPem, opts.domains);
    await mkdir(opts.dir, { recursive: true });
    await writeFile(keyPath, keyPem, { mode: 0o600 });
    await writeFile(certPath, certPem);
    return { key: keyPem, cert: certPem };
  }

  return {
    mode: "acme",
    async resolve() {
      return (await loadExisting()) ?? (await issue());
    },
    async refresh() {
      return issue();
    },
    watch(onChange) {
      const interval = opts.checkIntervalMs ?? 12 * 60 * 60 * 1000;
      timer = setInterval(() => {
        void loadExisting()
          .then(async (existing) => {
            if (existing) return; // 아직 유효
            const m = await issue(); // 만료 임박 → 갱신
            onChange(m);
          })
          .catch((e) => log.warn("acme 갱신 실패", { error: e instanceof Error ? e.message : String(e) }));
      }, interval);
      timer.unref?.();
      return () => {
        if (timer) clearInterval(timer);
        timer = null;
      };
    },
    async status(): Promise<CertStatus> {
      try {
        const cert = await readFile(certPath);
        return { mode: "acme", enabled: true, source: `ACME ${opts.directoryUrl}`, ...inspectCert(cert) };
      } catch {
        return { mode: "acme", enabled: false, source: `ACME ${opts.directoryUrl}`, error: "미발급(resolve 시 발급)" };
      }
    },
    close() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
}
