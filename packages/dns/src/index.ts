/**
 * @ionosphere/dns — 자체 재귀 DNS 리졸버(DNSBL 신뢰 조회용).
 * @ionosphere/mail-auth의 DnsResolver 계약을 구현하므로 dnsbl.ts·수신 인증·MX 조회에 드롭인.
 */
export { RecursiveResolver, type RecursiveResolverOptions } from "./resolver.ts";
export { DnsCache, type DnsCacheEntry, type DnsCacheOptions } from "./cache.ts";
export { UdpTcpTransport, type DnsTransport } from "./transport.ts";
export {
  decodeMessage,
  encodeMessage,
  encodeQuery,
  ptrQueryName,
  DnsWireError,
  RCode,
  RRClass,
  RRType,
  type DnsHeader,
  type DnsMessage,
  type DnsQuestion,
  type DnsRecord,
  type RData,
  type RRTypeName,
} from "./wire.ts";
export { ValidatingResolver, type ValidatedAnswer, type ValidatingResolverOptions } from "./validating.ts";
export {
  verifyRrset,
  dsMatchesKey,
  keyTag,
  DNSSEC_ALGO,
  type ValidationResult,
} from "./dnssec.ts";
