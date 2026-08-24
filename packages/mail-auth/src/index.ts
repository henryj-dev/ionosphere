export {
  canonBody,
  canonHeaderField,
  groupHeaderFields,
  normalizeLineEndings,
  parseHeaderFields,
  resolveHeaderSequence,
  splitMessage,
  type DkimCanonMode,
  type HeaderField,
} from "./canon.ts";
export { dkimSign, RELAY_SAFE_SIGNED_HEADERS, type DkimAlgorithm, type DkimSignOptions } from "./sign.ts";
export { arcSeal, arcVerify, parseArcChain, type ArcSealOptions, type ArcSet, type ArcVerifyResult } from "./arc.ts";
export { dkimVerify, type DkimVerifyOutcome, type DkimVerifyResult } from "./verify.ts";
export { generateDkimKeyPair, type DkimKeyPair } from "./keys.ts";
export { DnsNotFoundError, DnsTemporaryError, type DnsMxRecord, type DnsResolver } from "./dns.ts";
export { checkSpf, parseCidrList, type CidrMatcher, type SpfInput, type SpfResult, type SpfResultValue } from "./spf.ts";
export { checkDmarc, type DmarcDisposition, type DmarcInput, type DmarcResult } from "./dmarc.ts";
// DMARC 집계 리포트 **생성** — 받기만 하던 것을 내는 쪽(dmarc-report.ts 머리 주석).
export {
  buildDmarcReportXml,
  dmarcReportFilename,
  isRuaAuthorized,
  parseRua,
  type DmarcReportInput,
  type DmarcReportRow,
  type RuaTarget,
} from "./dmarc-report.ts";
export {
  buildAuthenticationResults,
  mapToStorageCodes,
  type AuthResultsDmarcInput,
  type AuthResultsInput,
  type AuthResultsSpfInput,
  type AuthStorageCode,
  type StorageCodes,
} from "./authres.ts";
export {
  checkDane,
  hasUsableTlsa,
  tlsaQueryName,
  TLSA_USAGE,
  TLSA_SELECTOR,
  TLSA_MATCHING,
  type DaneResult,
  type DaneTlsaSet,
  type TlsaRecord,
} from "./dane.ts";
