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
// TLS-RPT 리포트 **생성** — MTA-STS를 강제하면서 리포트를 안 내던 것을 고친다.
export {
  buildTlsRptJson,
  parseTlsRptRua,
  tlsRptFilename,
  TLSRPT_SUCCESS,
  type TlsRptInput,
  type TlsRptRow,
} from "./tlsrpt-report.ts";
