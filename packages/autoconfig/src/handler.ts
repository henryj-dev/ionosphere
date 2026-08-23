/**
 * 자동설정 라우터 — 순수 함수(요청 서술 → 응답 또는 null). node:http 무관(어댑터가 감쌈).
 *
 * 지원 경로:
 *  - GET  /mail/config-v1.1.xml                              (Thunderbird, autoconfig.<domain>)
 *  - GET  /.well-known/autoconfig/mail/config-v1.1.xml       (Thunderbird, <domain> 직접)
 *  - POST /autodiscover/autodiscover.xml                     (Outlook POX)
 *  - GET  /autodiscover/autodiscover.json                    (Autodiscover v2)
 *  - GET  /email.mobileconfig | /mobileconfig                (Apple)
 * 매칭 실패 시 null → 어댑터가 404.
 */
import { appleMobileconfig, autodiscoverPox, autodiscoverV2, thunderbirdAutoconfig, type AutoconfigSettings } from "./generate.ts";
import { buildMtaStsPolicy } from "@ionosphere/mta-sts";

export interface AutoconfigRequest {
  method: string;
  host: string; // Host 헤더(포트 포함 가능)
  path: string; // URL pathname
  query: URLSearchParams;
  body?: string; // POST 원문(autodiscover)
}

export interface AutoconfigResponse {
  status: number;
  contentType: string;
  body: string;
}

const XML = "application/xml; charset=utf-8";

/** Host 헤더에서 도메인 추출 — 포트 제거 + autoconfig./autodiscover. 접두 제거. */
export function domainFromHost(host: string): string {
  const bare = host.replace(/:\d+$/, "").toLowerCase();
  return bare.replace(/^(autoconfig|autodiscover)\./, "");
}

/** autodiscover POST 바디에서 이메일 추출(<EMailAddress> 또는 <Email>, 네임스페이스 무관). */
export function emailFromAutodiscoverBody(body: string | undefined): string | null {
  if (!body) return null;
  const m = body.match(/<(?:[\w.-]+:)?E[Mm]ail(?:Address)?>\s*([^<\s]+)\s*<\//);
  return m ? m[1]! : null;
}

/**
 * 후행 슬래시 제거 — **정규식을 쓰지 않는다.**
 *
 * ★왜: `path.replace(/\/+$/, "")`가 폴리노미얼 ReDoS였다(CodeQL js/polynomial-redos).
 * `\/+$`는 끝에 고정돼 있지만 엔진은 **모든 시작 위치에서** 시도하므로, 슬래시가 길게
 * 이어지는 입력에서 O(n²)가 된다. 실측: 슬래시 2000개 2.2ms · 8000개 44ms · 16000개 **205ms**.
 * `req.path`는 공개 HTTP 리스너가 받는 **공격자 입력**이라 요청 하나가 그만큼 CPU를 잡는다.
 * 뒤에서부터 세면 O(n)이고 하는 일은 같다.
 */
function trimTrailingSlashes(path: string): string {
  let end = path.length;
  while (end > 0 && path.charCodeAt(end - 1) === 0x2f) end -= 1;
  return path.slice(0, end);
}

function domainOf(email: string): string | null {
  const at = email.lastIndexOf("@");
  return at > 0 && at < email.length - 1 ? email.slice(at + 1).toLowerCase() : null;
}

export function handleAutoconfig(req: AutoconfigRequest, settings: AutoconfigSettings): AutoconfigResponse | null {
  const method = req.method.toUpperCase();
  const path = trimTrailingSlashes(req.path) || "/"; // 후행 슬래시 정규화
  const lower = path.toLowerCase();

  // ── Thunderbird ──────────────────────────────────────────────────
  if (method === "GET" && (lower === "/mail/config-v1.1.xml" || lower === "/.well-known/autoconfig/mail/config-v1.1.xml")) {
    const email = req.query.get("emailaddress") ?? req.query.get("email");
    const domain = (email && domainOf(email)) ?? domainFromHost(req.host);
    return { status: 200, contentType: XML, body: thunderbirdAutoconfig(domain, settings) };
  }

  // ── Microsoft Autodiscover POX ───────────────────────────────────
  if (method === "POST" && lower === "/autodiscover/autodiscover.xml") {
    const email = emailFromAutodiscoverBody(req.body) ?? req.query.get("email");
    if (!email) return { status: 400, contentType: XML, body: errorPox("email required") };
    return { status: 200, contentType: XML, body: autodiscoverPox(email, settings) };
  }

  // ── Autodiscover v2(JSON) ────────────────────────────────────────
  if (method === "GET" && lower === "/autodiscover/autodiscover.json") {
    const protocol = req.query.get("Protocol") ?? req.query.get("protocol") ?? "AutodiscoverV1";
    return { status: 200, contentType: "application/json; charset=utf-8", body: autodiscoverV2(protocol, settings) };
  }

  // ── MTA-STS 정책(RFC 8461) ───────────────────────────────────────
  // mta-sts.<domain>/.well-known/mta-sts.txt. mx는 우리 mailHost.
  if (method === "GET" && lower === "/.well-known/mta-sts.txt" && settings.mtaSts) {
    const body = buildMtaStsPolicy({
      // ★클라이언트 접속 호스트(imapHost/submissionHost)가 아니라 **MX가 가리키는 호스트**다.
      mx: settings.mtaSts.mx ? [...settings.mtaSts.mx] : [settings.mailHost],
      ...(settings.mtaSts.mode ? { mode: settings.mtaSts.mode } : {}),
      ...(settings.mtaSts.maxAge ? { maxAge: settings.mtaSts.maxAge } : {}),
    });
    return { status: 200, contentType: "text/plain; charset=utf-8", body };
  }

  // ── Apple mobileconfig ───────────────────────────────────────────
  if (method === "GET" && (lower === "/email.mobileconfig" || lower === "/mobileconfig")) {
    const email = req.query.get("email") ?? req.query.get("emailaddress");
    if (!email || !domainOf(email)) return { status: 400, contentType: "text/plain; charset=utf-8", body: "email query parameter required" };
    return { status: 200, contentType: "application/x-apple-aspen-config; charset=utf-8", body: appleMobileconfig(email, settings) };
  }

  return null;
}

/** Autodiscover 오류 응답(POX ErrorCode). */
function errorPox(message: string): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response>
    <Error>
      <ErrorCode>600</ErrorCode>
      <Message>${message}</Message>
    </Error>
  </Response>
</Autodiscover>
`;
}
