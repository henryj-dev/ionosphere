/**
 * DMARC 집계 리포트 (RFC 7489 §7.2) — **만들기**와 **보낼 곳 확인**. 순수 함수, I/O는 주입.
 *
 * ★`rua`의 외부 목적지 검증(§7.1)이 이 파일에서 가장 중요한 부분이다. 없으면 누구나
 * 자기 도메인의 DMARC 레코드에 **피해자 주소**를 `rua`로 적어 두고, 전 세계 수신 서버가
 * 매일 그 주소로 리포트를 보내게 만들 수 있다 — 분산 증폭 공격이다. 그래서 다른 조직의
 * 주소로 보내려면 **그 조직이 동의했다는 DNS 레코드**가 있어야 한다.
 */
import { DnsNotFoundError, DnsTemporaryError, type DnsResolver } from "./dns.ts";

/** 한 `<record>` — (소스 IP, 판정, 정렬, 인증 결과)별 개수. */
export interface DmarcReportRow {
  sourceIp: string;
  count: number;
  disposition: "none" | "quarantine" | "reject";
  dkimAligned: boolean;
  spfAligned: boolean;
  headerFrom: string;
  dkimResult: string;
  spfResult: string;
  dkimDomain?: string | null;
  spfDomain?: string | null;
}

export interface DmarcReportInput {
  /** 리포트를 내는 우리 쪽 식별자(§7.2.1.1의 `org_name`·`email`). */
  orgName: string;
  orgEmail: string;
  reportId: string;
  /** 기간 — epoch **초**다(§7.2.1.1의 `date_range`는 초 단위). */
  beginSec: number;
  endSec: number;
  /** 리포트 대상 도메인과 그 도메인의 정책. */
  policyDomain: string;
  policy: { p: string; sp?: string | null; adkim: string; aspf: string; pct?: number | null };
  rows: readonly DmarcReportRow[];
}

/**
 * XML 특수문자 이스케이프.
 *
 * ★값의 출처가 **남이 보낸 메일**이다(`header_from`은 발신자가 정한다). 이스케이프를
 * 빠뜨리면 우리가 만든 리포트가 깨진 XML이 되고, 받는 쪽 파서에 따라서는 그 이상이다.
 */
function xml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;")
    // XML 1.0이 허용하지 않는 제어문자는 아예 뺀다 — 이스케이프해도 유효하지 않다.
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");
}

/** RFC 7489 부록 C 스키마의 집계 리포트 XML. */
export function buildDmarcReportXml(input: DmarcReportInput): string {
  const p = input.policy;
  const lines: string[] = [
    `<?xml version="1.0" encoding="UTF-8" ?>`,
    `<feedback>`,
    `  <report_metadata>`,
    `    <org_name>${xml(input.orgName)}</org_name>`,
    `    <email>${xml(input.orgEmail)}</email>`,
    `    <report_id>${xml(input.reportId)}</report_id>`,
    `    <date_range>`,
    `      <begin>${Math.floor(input.beginSec)}</begin>`,
    `      <end>${Math.floor(input.endSec)}</end>`,
    `    </date_range>`,
    `  </report_metadata>`,
    `  <policy_published>`,
    `    <domain>${xml(input.policyDomain)}</domain>`,
    `    <adkim>${xml(p.adkim)}</adkim>`,
    `    <aspf>${xml(p.aspf)}</aspf>`,
    `    <p>${xml(p.p)}</p>`,
    ...(p.sp ? [`    <sp>${xml(p.sp)}</sp>`] : []),
    ...(p.pct != null ? [`    <pct>${Math.floor(p.pct)}</pct>`] : []),
    `  </policy_published>`,
  ];

  for (const r of input.rows) {
    lines.push(
      `  <record>`,
      `    <row>`,
      `      <source_ip>${xml(r.sourceIp)}</source_ip>`,
      `      <count>${Math.floor(r.count)}</count>`,
      `      <policy_evaluated>`,
      `        <disposition>${xml(r.disposition)}</disposition>`,
      // ★`dkim`/`spf`는 **정렬** 결과다(인증 결과가 아니다) — 아래 auth_results와 다르다.
      `        <dkim>${r.dkimAligned ? "pass" : "fail"}</dkim>`,
      `        <spf>${r.spfAligned ? "pass" : "fail"}</spf>`,
      `      </policy_evaluated>`,
      `    </row>`,
      `    <identifiers>`,
      `      <header_from>${xml(r.headerFrom)}</header_from>`,
      `    </identifiers>`,
      `    <auth_results>`,
    );
    // auth_results는 실제 인증 결과 — 정렬과 구분해서 적어야 상대가 원인을 좁힐 수 있다.
    if (r.dkimDomain) {
      lines.push(`      <dkim>`, `        <domain>${xml(r.dkimDomain)}</domain>`, `        <result>${xml(r.dkimResult)}</result>`, `      </dkim>`);
    }
    lines.push(
      `      <spf>`,
      `        <domain>${xml(r.spfDomain ?? r.headerFrom)}</domain>`,
      `        <result>${xml(r.spfResult)}</result>`,
      `      </spf>`,
      `    </auth_results>`,
      `  </record>`,
    );
  }

  lines.push(`</feedback>`, "");
  return lines.join("\n");
}

/**
 * 리포트 파일명 (RFC 7489 §7.2.1.1).
 *
 * `receiver!policy-domain!begin!end.xml.gz` — 받는 쪽이 파일명만으로 분류할 수 있게 하는
 * 규약이다. `!`를 구분자로 쓰므로 값에 들어 있으면 안 되는데, 도메인에는 나올 수 없다.
 */
export function dmarcReportFilename(receiver: string, policyDomain: string, beginSec: number, endSec: number): string {
  return `${receiver}!${policyDomain}!${Math.floor(beginSec)}!${Math.floor(endSec)}.xml.gz`;
}

// ── rua 목적지 ────────────────────────────────────────────────────────────────

/** `mailto:` URI 하나. `!size` 접미사(§7.2.1)는 파싱하되 상한 판정에만 쓴다. */
export interface RuaTarget {
  email: string;
  /** `!10m` 같은 최대 크기(바이트). 없으면 무제한. */
  maxBytes: number | null;
}

/** `k`/`m`/`g`/`t` 접미사를 바이트로. */
function parseSize(raw: string): number | null {
  const m = /^(\d+)([kmgt])?$/i.exec(raw.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] ?? "").toLowerCase();
  const mult = unit === "k" ? 1024 : unit === "m" ? 1024 ** 2 : unit === "g" ? 1024 ** 3 : unit === "t" ? 1024 ** 4 : 1;
  return n * mult;
}

/**
 * `rua=` 태그 값을 `mailto:` 목적지 목록으로.
 *
 * ★`mailto:`가 아닌 스킴은 **버린다**. RFC 7489는 다른 스킴을 열어 두지만 우리는 메일만
 * 보낸다 — 지원하지 않는 것을 목록에 남기면 나중에 "보냈다고 생각했는데 안 갔다"가 된다.
 */
export function parseRua(raw: string): RuaTarget[] {
  const out: RuaTarget[] = [];
  for (const part of raw.split(",")) {
    const token = part.trim();
    if (token === "") continue;
    const bang = token.indexOf("!");
    const uri = bang === -1 ? token : token.slice(0, bang);
    if (!/^mailto:/i.test(uri)) continue;
    const email = uri.slice("mailto:".length).trim().toLowerCase();
    if (email === "" || !email.includes("@")) continue;
    out.push({ email, maxBytes: bang === -1 ? null : parseSize(token.slice(bang + 1)) });
  }
  return out;
}

/** 주소의 도메인부(소문자). */
function domainOf(email: string): string {
  const at = email.lastIndexOf("@");
  return at === -1 ? "" : email.slice(at + 1).toLowerCase().replace(/\.$/, "");
}

/**
 * 이 `rua` 주소로 보내도 되는가 (RFC 7489 §7.1 External Report Addresses).
 *
 * ★**같은 도메인이면 확인이 필요 없다.** 자기 도메인 리포트를 자기가 받겠다는 것이라
 * 남을 끌어들이지 않는다(하위 도메인도 조직 도메인 기준으로 같게 본다).
 *
 * ★**다른 도메인이면 그 도메인의 동의가 있어야 한다.** `<policy-domain>._report._dmarc.
 * <external-domain>`에 `v=DMARC1`로 시작하는 TXT가 있어야 한다. 없으면 보내지 않는다 —
 * 이 확인이 없으면 누구나 피해자 주소를 `rua`에 적어 **전 세계 수신 서버를 증폭기로** 쓴다.
 *
 * ★조회 실패(temperror)는 **보내지 않는 쪽**으로 수렴시킨다. 보안은 fail closed다 —
 * 리포트 하루치를 못 보내는 것이 남을 공격하는 것보다 낫다.
 */
export async function isRuaAuthorized(
  policyDomain: string,
  ruaEmail: string,
  resolver: DnsResolver,
  /** 정책 도메인의 조직 도메인 — 하위 도메인 판정용. 생략하면 policyDomain 그대로. */
  orgDomain?: string,
): Promise<boolean> {
  const target = domainOf(ruaEmail);
  if (target === "") return false;
  const own = (orgDomain ?? policyDomain).toLowerCase();
  if (target === own || target.endsWith(`.${own}`) || own.endsWith(`.${target}`)) return true;

  const name = `${policyDomain}._report._dmarc.${target}`;
  try {
    const txts = await resolver.txt(name);
    return txts.some((t: string) => /^v\s*=\s*DMARC1\b/i.test(t.trim()));
  } catch (err) {
    // 없으면 거절, 일시 오류도 거절 — 둘 다 "동의를 확인하지 못했다"이다.
    if (err instanceof DnsNotFoundError || err instanceof DnsTemporaryError) return false;
    return false;
  }
}
