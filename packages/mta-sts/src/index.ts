// MTA-STS(RFC 8461) + TLS-RPT(RFC 8460) — 정책 빌드/파싱/평가/조회(순수).
export {
  buildMtaStsPolicy,
  mxMatchesPolicy,
  parseMtaStsPolicy,
  parseMtaStsTxt,
  parseTlsRptTxt,
  stsDnsRecords,
  type MtaStsMode,
  type MtaStsPolicy,
  type StsDnsRecord,
} from "./policy.ts";
export {
  fetchMtaStsPolicy,
  stsEnforcement,
  type MtaStsFetchDeps,
  type MtaStsLookup,
  type StsEnforcement,
} from "./fetch.ts";
