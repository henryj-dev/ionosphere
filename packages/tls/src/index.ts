/**
 * @ionosphere/tls — TLS 인증서 소스 추상화(none/file/selfsigned/url/acme)와 핫리로드.
 * selfsigned/url/acme 소스는 후속 증분에서 추가되며, 각 소스가 CertSource 계약을 만족한다.
 */
export type { CertMode, CertSource, CertStatus, TlsMaterial } from "./types.ts";
export { inspectCert, daysUntilExpiry } from "./inspect.ts";
export { noneCertSource, fileCertSource, type FileCertOptions } from "./sources.ts";
export { selfSignedCertSource, type SelfSignedSourceOptions } from "./selfsigned.ts";
export { urlCertSource, MAX_CERT_FETCH_BYTES, type UrlCertOptions } from "./url.ts";
export { checkTransportUrl, insecureTransportWarning, assertSameOrigin, type TransportUrlCheck } from "./secure-url.ts";
export { assertUsableCert } from "./verify.ts";
export { sealedFileCertSource, type SealedSourceOptions, type SealedCertSource } from "./sealed.ts";
export { generateSelfSigned, generateEcKeyPair, distinguishedName, subjectAltNames, type GeneratedCert, type SelfSignedOptions } from "./x509.ts";
export { acmeCertSource, type AcmeSourceOptions } from "./acme-source.ts";
export { requestCertificate, generateAccountKey, type AcmeOptions, type AcmeChallenge, type DnsProvider, type HttpChallengeResponder } from "./acme.ts";
export { httpChallengeServer, ACME_HTTP_PREFIX, type HttpChallengeServer, type HttpChallengeServerOptions } from "./http-challenge.ts";
export { generateCsr, type GeneratedCsr } from "./csr.ts";
export { b64url, jwkThumbprint, publicJwk, makeJws, type EcJwk } from "./jose.ts";
export * as asn1 from "./asn1.ts";

import type { Logger } from "@ionosphere/core";
import { noneCertSource, fileCertSource } from "./sources.ts";
import { selfSignedCertSource } from "./selfsigned.ts";
import { urlCertSource } from "./url.ts";
import { sealedFileCertSource } from "./sealed.ts";
import { acmeCertSource } from "./acme-source.ts";
import type { AcmeChallenge } from "./acme.ts";
import type { CertSource } from "./types.ts";

/** 소스 선택 설정(모드별 판별 유니온). sealed는 관리 UI 업로드용(개인키 masterKey 봉인). */
export type CertConfig =
  | { mode: "none" }
  | { mode: "file"; keyPath: string; certPath: string; debounceMs?: number }
  | { mode: "selfsigned"; commonName: string; sans?: string[]; dir: string; days?: number; renewWithinDays?: number }
  | {
      mode: "url";
      certUrl: string;
      keyUrl: string;
      headers?: Record<string, string>;
      cacheDir: string;
      refreshIntervalMs?: number;
      expectedHosts?: readonly string[];
      logger?: Logger;
      maxBytes?: number;
    }
  | { mode: "acme"; domains: string[]; directoryUrl: string; challenge: AcmeChallenge; dir: string; contactEmail?: string; renewWithinDays?: number; logger?: Logger }
  | { mode: "sealed"; dir: string; masterKey: string };

/** 설정 → CertSource. 조립층(app.ts)이 env를 이 설정으로 매핑해 호출. */
export function createCertSource(config: CertConfig): CertSource {
  switch (config.mode) {
    case "none":
      return noneCertSource();
    case "file":
      return fileCertSource(config);
    case "selfsigned":
      return selfSignedCertSource(config);
    case "url":
      return urlCertSource(config);
    case "acme":
      return acmeCertSource(config);
    case "sealed":
      return sealedFileCertSource(config);
    default: {
      const _exhaustive: never = config;
      throw new Error(`알 수 없는 TLS 모드: ${JSON.stringify(_exhaustive)}`);
    }
  }
}
