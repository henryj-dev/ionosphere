/**
 * 클라이언트 자동설정 문서 생성기 — 순수 함수(입력 설정 → 문자열). HTTP/DNS 무관.
 *
 * 세 생태계 표준을 모두 만든다:
 *  - Mozilla Thunderbird autoconfig (clientConfig v1.1) — ISPDB 포맷
 *  - Microsoft Autodiscover POX(Outlook) + v2(JSON 리다이렉트 포인터)
 *  - Apple .mobileconfig (com.apple.mail.managed 프로파일, 서명 없음)
 *
 * 모든 서버는 암시적 TLS(IMAPS 993 / SMTPS 465) 전제 — 프로젝트가 STARTTLS 대신
 * 암시적 TLS를 라이브로 쓰기 때문(app.ts imapsTls/smtpsPort 주석 참조).
 */
import { sha256hex } from "@ionosphere/core";

/** 서버 전역 설정(호스트/포트/브랜드) — 요청마다 바뀌는 이메일/도메인과 분리. */
export interface AutoconfigSettings {
  /**
   * 기본 메일 서버 FQDN — 예: mx.ionosphere.test.
   * 아래 역할별 호스트를 지정하지 않으면 전부 이 값을 쓴다(기존 단일 호스트 동작 그대로).
   *
   * ★역할별로 쪼갠 이유: 예전엔 이 한 필드가 **세 가지 다른 의미**를 겸했다 —
   * 클라이언트에 광고할 IMAP 호스트, 같은 SMTP 호스트, 그리고 MTA-STS 정책의 `mx:` 목록.
   * 그래서 "클라이언트는 imap.example.com으로 붙게 하자"고 이 값을 바꾸는 순간
   * **MTA-STS의 mx까지 따라 바뀌어 enforce 상태에서 인바운드 메일이 전부 거부**된다.
   * 의미가 다르면 필드도 달라야 한다.
   */
  mailHost: string;
  /** 클라이언트에 광고할 IMAP 호스트. 기본 mailHost. (예: imap.example.com) */
  imapHost?: string;
  /** 클라이언트에 광고할 제출(SMTP submission) 호스트. 기본 mailHost. (예: smtp.example.com) */
  submissionHost?: string;
  /** IMAPS 포트(암시적 TLS). 기본 993. */
  imapPort?: number;
  /** SMTPS submission 포트(암시적 TLS). 기본 465. */
  submissionPort?: number;
  /**
   * 클라이언트에 광고할 POP3 호스트 — **지정하면 POP3도 광고한다**(미지정 시 IMAP만).
   *
   * ★왜 opt-in인가: POP3는 기본적으로 서버에서 메일을 내려받아 지운다(클라이언트 설정에 따라).
   * 여러 기기를 쓰는 사용자에게는 IMAP이 맞고, 자동설정에 둘 다 있으면 클라이언트가 POP3를
   * 고를 수 있다 — Thunderbird는 문서 순서를, Outlook은 자체 우선순위를 쓴다. 그래서 운영자가
   * **명시적으로 켜야** 광고한다. 포트를 열어 둔 것과 광고하는 것은 다른 결정이다.
   *
   * 라이브 예: node-02가 995·110을 열고 DNS에 `pop3.ionosphere.test`이 등록돼 있으나
   * 자동설정에는 없었다(2026-08-03 실측) — 수동 설정만 가능한 상태였다.
   */
  pop3Host?: string;
  /** POP3S 포트(암시적 TLS). 기본 995. `pop3Host`가 없으면 무의미하다. */
  pop3Port?: number;
  /** 브랜드 짧은 이름(Thunderbird displayShortName). 기본 mailHost. */
  brandShort?: string;
  /** 브랜드 이름(displayName/프로파일 이름). 기본 brandShort. */
  brand?: string;
  /**
   * MTA-STS 정책 서빙(RFC 8461) — 지정 시 /.well-known/mta-sts.txt 응답.
   * mode 기본 testing(안전 도입). 미지정 시 MTA-STS 라우트 비활성.
   *
   * ★`mx`는 **MX 레코드가 실제로 가리키는 호스트**여야 한다(클라이언트 접속용 호스트가 아니다).
   * 발신 MTA는 이 목록과 접속한 MX의 인증서 이름을 대조하므로, 틀리면 enforce에서 수신이 죽는다.
   * 생략 시 `[mailHost]` — 단일 호스트 구성에서의 기존 동작.
   */
  mtaSts?: { mode?: "enforce" | "testing" | "none"; maxAge?: number; mx?: readonly string[] };
}

interface Resolved {
  mailHost: string;
  imapHost: string;
  submissionHost: string;
  imapPort: number;
  submissionPort: number;
  /** POP3 광고 대상 — 미설정이면 undefined이고 그 경우 POP3 항목을 만들지 않는다. */
  pop3Host: string | undefined;
  pop3Port: number;
  brandShort: string;
  brand: string;
}

function resolve(s: AutoconfigSettings): Resolved {
  const brandShort = s.brandShort ?? s.mailHost;
  return {
    mailHost: s.mailHost,
    imapHost: s.imapHost ?? s.mailHost,
    submissionHost: s.submissionHost ?? s.mailHost,
    imapPort: s.imapPort ?? 993,
    submissionPort: s.submissionPort ?? 465,
    // ★`pop3Host`는 mailHost로 폴백하지 **않는다** — 폴백하면 POP3가 항상 켜진다.
    // 광고 여부가 이 필드의 존재로 결정되므로 기본값을 주면 opt-in이 무너진다.
    pop3Host: s.pop3Host,
    pop3Port: s.pop3Port ?? 995,
    brandShort,
    brand: s.brand ?? brandShort,
  };
}

/** XML 텍스트/속성 이스케이프(5대 엔티티). */
export function xmlEscape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => (c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === '"' ? "&quot;" : "&apos;"));
}

/**
 * 결정적 UUID(v5 스타일) — 시드 문자열의 sha256 앞 16바이트를 UUID로 포맷.
 * version=5, variant=RFC4122 비트를 세팅. 같은 시드 → 같은 UUID(프로파일 재발급 idempotent).
 */
export function deterministicUuid(seed: string): string {
  const h = sha256hex(seed); // 64 hex
  const b = h.slice(0, 32).split("");
  // version nibble(13번째, 0-index 12) = 5
  b[12] = "5";
  // variant(17번째, 0-index 16) 상위 2비트 = 10 → 8/9/a/b
  const variant = parseInt(b[16]!, 16);
  b[16] = ((variant & 0x3) | 0x8).toString(16);
  const hex = b.join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`.toUpperCase();
}

/**
 * Thunderbird autoconfig (clientConfig v1.1). username은 %EMAILADDRESS% 플레이스홀더라
 * 이메일을 몰라도 되지만, emailProvider id/domain엔 도메인이 필요하다.
 * socketType SSL = 암시적 TLS, authentication password-cleartext = LOGIN/PLAIN(TLS 위 평문).
 */
export function thunderbirdAutoconfig(domain: string, settings: AutoconfigSettings): string {
  const r = resolve(settings);
  const d = xmlEscape(domain);
  const srv = (type: "imap" | "pop3" | "smtp", tag: "incomingServer" | "outgoingServer", port: number, hostname: string) =>
    `    <${tag} type="${type}">
      <hostname>${xmlEscape(hostname)}</hostname>
      <port>${port}</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </${tag}>`;
  /**
   * ★IMAP을 **먼저** 둔다. Thunderbird는 여러 incomingServer 중 문서 순서상 첫 번째를 기본으로
   * 고르므로(ISPDB 관례), 순서가 곧 권고다. POP3가 먼저 오면 다기기 사용자가 기본값으로
   * 메일을 서버에서 내려받아 지우게 된다.
   */
  const incoming = [srv("imap", "incomingServer", r.imapPort, r.imapHost)];
  if (r.pop3Host !== undefined) incoming.push(srv("pop3", "incomingServer", r.pop3Port, r.pop3Host));
  return `<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="${d}">
    <domain>${d}</domain>
    <displayName>${xmlEscape(r.brand)}</displayName>
    <displayShortName>${xmlEscape(r.brandShort)}</displayShortName>
${incoming.join("\n")}
${srv("smtp", "outgoingServer", r.submissionPort, r.submissionHost)}
  </emailProvider>
</clientConfig>
`;
}

/**
 * Microsoft Autodiscover POX(Outlook) 응답. LoginName엔 실제 이메일이 필요하다.
 * SSL on + Encryption SSL = 암시적 TLS. SPA off(통합인증 아님).
 */
export function autodiscoverPox(email: string, settings: AutoconfigSettings): string {
  const r = resolve(settings);
  const login = xmlEscape(email);
  const proto = (type: "IMAP" | "POP3" | "SMTP", port: number, server: string) =>
    `      <Protocol>
        <Type>${type}</Type>
        <Server>${xmlEscape(server)}</Server>
        <Port>${port}</Port>
        <DomainRequired>off</DomainRequired>
        <LoginName>${login}</LoginName>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <Encryption>SSL</Encryption>
        <AuthRequired>on</AuthRequired>
      </Protocol>`;
  // IMAP을 먼저 둔다 — Thunderbird와 같은 이유(순서가 권고다). Outlook은 자체 우선순위를
  // 쓰기도 하지만, 순서를 뒤집을 이유는 없다.
  const protocols = [proto("IMAP", r.imapPort, r.imapHost)];
  if (r.pop3Host !== undefined) protocols.push(proto("POP3", r.pop3Port, r.pop3Host));
  protocols.push(proto("SMTP", r.submissionPort, r.submissionHost));
  return `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
${protocols.join("\n")}
    </Account>
  </Response>
</Autodiscover>
`;
}

/**
 * Autodiscover v2(JSON) — 표준상 실제 autodiscover 엔드포인트로 리다이렉트하는 포인터.
 * 자체 호스팅에선 POX(v1) URL을 돌려준다.
 */
export function autodiscoverV2(protocol: string, settings: AutoconfigSettings): string {
  const r = resolve(settings);
  return JSON.stringify({ Protocol: protocol, Url: `https://${r.mailHost}/autodiscover/autodiscover.xml` });
}

/**
 * Apple .mobileconfig(plist) — com.apple.mail.managed 페이로드 1개.
 * UUID는 이메일+호스트 기반 결정적 생성(재다운로드해도 같은 프로파일로 갱신).
 * ★시드는 역할별 호스트가 아니라 **mailHost로 고정**한다 — imap./smtp.로 나눈다고 시드가 바뀌면
 * iOS가 다른 프로파일로 인식해 기존 계정 옆에 **중복 계정**이 생긴다(설정만 바뀌어야 한다).
 * 서명 없음 — iOS/macOS는 "미검증 프로파일" 경고 후 설치 허용(자체 호스팅 관례).
 *
 * ★`pop3Host`를 켜도 이 프로파일은 **IMAP을 유지한다.** com.apple.mail.managed는
 * `EmailAccountType`으로 프로토콜을 하나만 고르는 구조라(`EmailTypeIMAP` | `EmailTypePOP`)
 * 둘을 함께 담을 수 없다. 둘 다 원하면 페이로드를 두 개 만들어야 하는데, 그러면 iOS에
 * **같은 주소의 계정이 두 개** 생겨 사용자가 어느 쪽에 받았는지 알 수 없게 된다.
 * 프로파일은 "설치하면 바로 쓰는 것"이므로 애매한 선택을 남기지 않고 IMAP으로 고정한다 —
 * POP3가 필요한 사용자는 Thunderbird/Outlook 경로나 수동 설정을 쓴다.
 */
export function appleMobileconfig(email: string, settings: AutoconfigSettings): string {
  const r = resolve(settings);
  const profileUuid = deterministicUuid(`profile:${email}:${r.mailHost}`);
  const payloadUuid = deterministicUuid(`payload:${email}:${r.mailHost}`);
  const id = `app.${r.mailHost.split(".").reverse().join(".")}`;
  const acct = xmlEscape(email);
  const brand = xmlEscape(r.brand);
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.mail.managed</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>${id}.mail.${payloadUuid}</string>
      <key>PayloadUUID</key>
      <string>${payloadUuid}</string>
      <key>PayloadDisplayName</key>
      <string>${brand} (${acct})</string>
      <key>EmailAccountType</key>
      <string>EmailTypeIMAP</string>
      <key>EmailAccountName</key>
      <string>${acct}</string>
      <key>EmailAccountDescription</key>
      <string>${brand}</string>
      <key>EmailAddress</key>
      <string>${acct}</string>
      <key>IncomingMailServerHostName</key>
      <string>${xmlEscape(r.imapHost)}</string>
      <key>IncomingMailServerPortNumber</key>
      <integer>${r.imapPort}</integer>
      <key>IncomingMailServerUseSSL</key>
      <true/>
      <key>IncomingMailServerAuthentication</key>
      <string>EmailAuthPassword</string>
      <key>IncomingMailServerUsername</key>
      <string>${acct}</string>
      <key>OutgoingMailServerHostName</key>
      <string>${xmlEscape(r.submissionHost)}</string>
      <key>OutgoingMailServerPortNumber</key>
      <integer>${r.submissionPort}</integer>
      <key>OutgoingMailServerUseSSL</key>
      <true/>
      <key>OutgoingMailServerAuthentication</key>
      <string>EmailAuthPassword</string>
      <key>OutgoingMailServerUsername</key>
      <string>${acct}</string>
      <key>OutgoingPasswordSameAsIncomingPassword</key>
      <true/>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>${brand} Mail (${acct})</string>
  <key>PayloadIdentifier</key>
  <string>${id}.mail</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${profileUuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
`;
}
