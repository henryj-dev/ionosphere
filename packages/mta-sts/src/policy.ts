/**
 * MTA-STS (RFC 8461) + TLS-RPT (RFC 8460) — 정책 빌드/파싱/평가. 순수(외부 의존 없음).
 *
 * 발행(수신자): mta-sts.txt 정책 본문 + `_mta-sts` TXT(정책 id) + `_smtp._tls` TXT(TLS-RPT).
 * 강제(발신자): 수신 도메인의 정책을 조회해 TLS 요구 여부·MX 일치 여부를 판정.
 */

export type MtaStsMode = "enforce" | "testing" | "none";

export interface MtaStsPolicy {
  version: "STSv1";
  mode: MtaStsMode;
  /** MX 호스트 패턴(선두 "*." 와일드카드 1레벨 허용). */
  mx: string[];
  /** 초 단위 최대 캐시 수명. */
  maxAge: number;
}

/** DNS 게시용 레코드(도메인 프로비저닝이 자기 타입으로 매핑). */
export interface StsDnsRecord {
  name: string;
  value: string;
  purpose: string;
}

/**
 * mta-sts.txt 본문 생성(RFC 8461 §3.2). CRLF 구분. mode 기본 testing(안전 도입 —
 * 실패해도 배달은 되지만 리포트로 관측 → 검증 후 enforce로 승격).
 */
export function buildMtaStsPolicy(opts: { mx: string[]; mode?: MtaStsMode; maxAge?: number }): string {
  const mode = opts.mode ?? "testing";
  const maxAge = opts.maxAge ?? 604800; // 7일
  const lines = ["version: STSv1", `mode: ${mode}`, ...opts.mx.map((m) => `mx: ${m}`), `max_age: ${maxAge}`];
  return lines.join("\r\n") + "\r\n";
}

/**
 * 발행 DNS 레코드 — `_mta-sts.<domain>`(정책 id) + `_smtp._tls.<domain>`(TLS-RPT rua).
 * 정책 id는 변경 시마다 갱신해야 발신자 캐시가 무효화된다(여기선 호출자가 타임스탬프 등 주입).
 */
export function stsDnsRecords(domain: string, opts: { policyId: string; rua?: string }): StsDnsRecord[] {
  const records: StsDnsRecord[] = [
    { name: `_mta-sts.${domain}`, value: `v=STSv1; id=${opts.policyId}`, purpose: "MTA-STS 정책 id" },
  ];
  if (opts.rua) {
    records.push({ name: `_smtp._tls.${domain}`, value: `v=TLSRPTv1; rua=${opts.rua}`, purpose: "TLS-RPT 리포트 수신처" });
  }
  return records;
}

/** mta-sts.txt 본문 파싱(발신자). key: value 라인, 알 수 없는 키 무시. */
/**
 * `mx:` 항목 개수 상한.
 *
 * ★왜 필요한가(2026-07-31 실측): 파싱 결과는 워커의 정책 캐시가 도메인마다 들고 있고
 * 그 캐시 상한이 4096개다. 페치 상한(64KB) 안에서 `mx:` 줄을 최대로 채우면 한 정책이
 * **3,087개**가 되고, 캐시가 가득 차면 **RSS 360MB**다(고유 호스트명 기준 — 반복 문자열로
 * 재면 V8 인터닝이 증폭을 숨겨 156MB로 보인다. 증폭 측정은 입력 다양성부터 확인해야 한다).
 * 전 프로토콜이 단일 프로세스라 이 메모리는 메일 서비스 전체와 경합한다.
 *
 * 100인 이유: RFC 8461 §3.2 예시는 mx가 2~4개이고, 현실의 대형 제공자도 한 자릿수다.
 * 100은 정상 정책을 자를 여지가 없을 만큼 넉넉하면서 캐시 총량을 수십 MB로 묶는다.
 *
 * 초과 시 **정책 무효**(null)로 본다. 잘라서 쓰면 정책에 있는 정당한 MX를 우리가 거부해
 * 배달이 조용히 지연되고, 그 절단이 로그에도 안 남는다("조용한 절단 금지").
 * 무효 처리가 fail-open으로 보일 수 있으나, 워커가 **마지막으로 성공한 정책을 유지**하므로
 * (M-1 조치) 한 번이라도 정상 정책을 본 도메인은 강제가 풀리지 않는다.
 */
const MAX_MX_ENTRIES = 100;

export function parseMtaStsPolicy(text: string): MtaStsPolicy | null {
  const mx: string[] = [];
  let mode: MtaStsMode | null = null;
  let version: string | null = null;
  let maxAge: number | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === "version") version = value;
    else if (key === "mode") mode = value === "enforce" || value === "testing" || value === "none" ? value : null;
    else if (key === "mx") mx.push(value.toLowerCase());
    else if (key === "max_age") {
      const n = Number(value);
      if (Number.isFinite(n) && n >= 0) maxAge = n;
    }
  }
  if (version !== "STSv1" || mode === null || maxAge === null || mx.length === 0) return null;
  if (mx.length > MAX_MX_ENTRIES) return null; // 위 주석 — 캐시 메모리 증폭 차단
  return { version: "STSv1", mode, mx, maxAge };
}

/** `_mta-sts` TXT 레코드 파싱 → 정책 id. */
export function parseMtaStsTxt(txt: string): { id: string } | null {
  const parts = txt.split(";").map((p) => p.trim());
  let v: string | null = null;
  let id: string | null = null;
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    const val = p.slice(eq + 1).trim();
    if (k === "v") v = val;
    else if (k === "id") id = val;
  }
  return v === "STSv1" && id ? { id } : null;
}

/** `_smtp._tls` TXT(TLS-RPT) 파싱 → rua 목록. */
export function parseTlsRptTxt(txt: string): { rua: string[] } | null {
  const parts = txt.split(";").map((p) => p.trim());
  let v: string | null = null;
  const rua: string[] = [];
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    const val = p.slice(eq + 1).trim();
    if (k === "v") v = val;
    else if (k === "rua") rua.push(...val.split(",").map((s) => s.trim()).filter(Boolean));
  }
  return v === "TLSRPTv1" && rua.length > 0 ? { rua } : null;
}

/**
 * MX 호스트가 정책 mx 패턴에 부합하는지(RFC 8461 §4.1). 대소문자 무시, 후행 점 제거.
 * "*.example.com"은 정확히 한 레벨(a.example.com O, a.b.example.com X)만 매칭.
 */
export function mxMatchesPolicy(mxHost: string, patterns: readonly string[]): boolean {
  const host = mxHost.toLowerCase().replace(/\.$/, "");
  return patterns.some((raw) => {
    const pat = raw.toLowerCase().replace(/\.$/, "");
    if (pat.startsWith("*.")) {
      const suffix = pat.slice(1); // ".example.com"
      if (!host.endsWith(suffix)) return false;
      const label = host.slice(0, host.length - suffix.length);
      return label.length > 0 && !label.includes("."); // 정확히 한 레벨
    }
    return host === pat;
  });
}
