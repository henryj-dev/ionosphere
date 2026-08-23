/** 인증서 메타 추출 — node:crypto X509Certificate 파싱(개인키 무관, 상태 표시용). */
import { X509Certificate } from "node:crypto";
import type { CertStatus } from "./types.ts";

/** PEM(체인이면 첫 리프)에서 subject/SAN/유효기간/자기서명 여부 추출. 실패는 error 필드로. */
export function inspectCert(certPem: string | Buffer): Partial<CertStatus> {
  try {
    const x = new X509Certificate(certPem);
    const sans = x.subjectAltName
      ? x.subjectAltName
          .split(",")
          .map((s) => s.trim().replace(/^DNS:/i, ""))
          .filter((s) => s.length > 0)
      : [];
    return {
      subject: x.subject,
      sans,
      notBefore: Date.parse(x.validFrom),
      notAfter: Date.parse(x.validTo),
      selfSigned: x.issuer === x.subject,
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/** 인증서 만료까지 남은 일수(음수=이미 만료). 파싱 실패 시 null. */
export function daysUntilExpiry(certPem: string | Buffer, now = Date.now()): number | null {
  const info = inspectCert(certPem);
  if (info.notAfter === undefined || Number.isNaN(info.notAfter)) return null;
  return Math.floor((info.notAfter - now) / 86_400_000);
}
