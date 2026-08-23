/**
 * 역할별 호스트 분리 — 클라이언트 광고 호스트(IMAP/SMTP)와 **MTA-STS의 mx는 따로 움직인다**.
 *
 * 왜 이 테스트가 중요한가: 예전엔 `mailHost` 한 필드가 세 의미를 겸했다 — IMAP 호스트,
 * SMTP 호스트, MTA-STS `mx:`. "클라이언트는 imap.example.com으로 붙게 하자"며 그 값을 바꾸면
 * **MTA-STS의 mx까지 따라 바뀌고, enforce 상태에서 발신 MTA가 MX 인증서 이름 대조에 실패해
 * 인바운드 메일이 전부 거부**된다. 설정 한 줄로 수신이 죽는 종류의 결합이라 테스트로 못박는다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { appleMobileconfig, autodiscoverPox, thunderbirdAutoconfig, type AutoconfigSettings } from "../src/generate.ts";
import { handleAutoconfig } from "../src/handler.ts";

/**
 * 역할별로 **전부 다른** 호스트. mailHost를 일부러 MX와 다르게(`mail.`) 둔 게 핵심이다 —
 * mx가 mailHost로 폴백하는 버그가 있으면 정책에 `mail.example.com`이 찍혀 즉시 드러난다.
 * (mailHost와 MX를 같게 두면 그 버그가 통과해버려 테스트가 무의미해진다.)
 */
const SPLIT: AutoconfigSettings = {
  mailHost: "mail.example.com",
  imapHost: "imap.example.com",
  submissionHost: "smtp.example.com",
  mtaSts: { mode: "enforce", mx: ["mx.example.com"] },
};

/** 역할 호스트를 안 준 같은 구성 — UUID 안정성 비교의 짝(mailHost가 같아야 의미가 있다). */
const SPLIT_NO_ROLES: AutoconfigSettings = { mailHost: "mail.example.com", mtaSts: { mode: "enforce" } };

const SINGLE: AutoconfigSettings = { mailHost: "mx.example.com", mtaSts: { mode: "enforce" } };

describe("역할별 호스트 — 클라이언트 광고", () => {
  test("Thunderbird: 수신은 imap., 발신은 smtp.", () => {
    const xml = thunderbirdAutoconfig("example.com", SPLIT);
    expect(xml).toContain("<incomingServer type=\"imap\">");
    // 수신 블록 안에 imap. / 발신 블록 안에 smtp.가 들어가야 한다
    const incoming = xml.slice(xml.indexOf("<incomingServer"), xml.indexOf("</incomingServer>"));
    const outgoing = xml.slice(xml.indexOf("<outgoingServer"), xml.indexOf("</outgoingServer>"));
    expect(incoming).toContain("<hostname>imap.example.com</hostname>");
    expect(outgoing).toContain("<hostname>smtp.example.com</hostname>");
    expect(incoming).not.toContain("smtp.example.com");
    expect(outgoing).not.toContain("imap.example.com");
  });

  test("Outlook POX: IMAP/SMTP 프로토콜별로 다른 Server", () => {
    const xml = autodiscoverPox("u@example.com", SPLIT);
    const imapBlock = xml.slice(xml.indexOf("<Type>IMAP</Type>"), xml.indexOf("<Type>SMTP</Type>"));
    const smtpBlock = xml.slice(xml.indexOf("<Type>SMTP</Type>"));
    expect(imapBlock).toContain("<Server>imap.example.com</Server>");
    expect(smtpBlock).toContain("<Server>smtp.example.com</Server>");
  });

  test("Apple mobileconfig: 수신/발신 호스트가 각각 반영된다", () => {
    const plist = appleMobileconfig("u@example.com", SPLIT);
    expect(plist).toContain("<key>IncomingMailServerHostName</key>\n      <string>imap.example.com</string>");
    expect(plist).toContain("<key>OutgoingMailServerHostName</key>\n      <string>smtp.example.com</string>");
  });

  test("★mobileconfig UUID는 역할 분리로 바뀌지 않는다 — 바뀌면 iOS에 중복 계정이 생긴다", () => {
    const before = appleMobileconfig("u@example.com", SPLIT_NO_ROLES);
    const after = appleMobileconfig("u@example.com", SPLIT);
    const uuid = (s: string) => s.slice(s.indexOf("<key>PayloadUUID</key>"), s.indexOf("<key>PayloadUUID</key>") + 120);
    expect(uuid(after)).toBe(uuid(before)); // 시드는 mailHost 고정
  });
});

describe("★MTA-STS mx는 클라이언트 호스트를 따라가지 않는다", () => {
  async function policy(settings: AutoconfigSettings): Promise<string> {
    const res = await handleAutoconfig(
      { method: "GET", path: "/.well-known/mta-sts.txt", host: "mta-sts.example.com", query: new URLSearchParams() },
      settings,
    );
    return res?.body ?? "";
  }

  test("imap./smtp.로 나눠도 mx는 MX 호스트로 남는다", async () => {
    const body = await policy(SPLIT);
    expect(body).toContain("mx: mx.example.com");
    // 이게 새면 발신 MTA가 MX 인증서 이름 대조에 실패해 enforce에서 수신이 죽는다
    expect(body).not.toContain("imap.example.com");
    expect(body).not.toContain("smtp.example.com");
    expect(body).not.toContain("mail.example.com"); // mailHost 폴백으로 새면 여기서 잡힌다
    expect(body).toContain("mode: enforce");
  });

  test("mx 미지정 시 mailHost로 폴백(단일 호스트 구성의 기존 동작)", async () => {
    const body = await policy(SINGLE);
    expect(body).toContain("mx: mx.example.com");
  });

  test("mx는 여러 개를 나열할 수 있다(서버 분리 대비)", async () => {
    const body = await policy({ ...SPLIT, mtaSts: { mode: "enforce", mx: ["mx1.example.com", "mx2.example.com"] } });
    expect(body).toContain("mx: mx1.example.com");
    expect(body).toContain("mx: mx2.example.com");
  });
});

describe("역할 호스트 미지정 = 기존 동작", () => {
  test("전부 mailHost로 떨어진다", () => {
    const xml = thunderbirdAutoconfig("example.com", SINGLE);
    expect(xml.match(/<hostname>mx\.example\.com<\/hostname>/g)).toHaveLength(2);
  });
});

/**
 * POP3 광고 — **opt-in이다.** 포트를 여는 것과 클라이언트에 권하는 것은 다른 결정이다.
 *
 * 왜 이 구분이 필요한가(2026-08-03 라이브 실측): MRA가 995·110을 열고 DNS에도
 * `pop3.ionosphere.test`이 등록돼 있었지만 자동설정에는 IMAP만 있었다 — 수동 설정만 가능한
 * 상태였다. 그렇다고 995를 연 것만으로 광고를 켜면, POP3를 백업 경로로만 두려던 배치에서
 * 클라이언트가 POP3를 기본으로 골라 **서버에서 메일을 내려받아 지우기 시작한다.**
 * 그래서 호스트를 명시할 때만 실린다(hostname 폴백 없음).
 */
describe("POP3 광고는 opt-in", () => {
  const WITH_POP3: AutoconfigSettings = { ...SPLIT, pop3Host: "pop3.example.com" };

  test("pop3Host 미지정이면 어느 문서에도 POP3가 없다", () => {
    const tb = thunderbirdAutoconfig("example.com", SPLIT);
    expect(tb).not.toContain("pop3");
    expect(tb).not.toContain("POP3");
    const pox = autodiscoverPox("u@example.com", SPLIT);
    expect(pox).not.toContain("<Type>POP3</Type>");
  });

  test("pop3Host를 주면 Thunderbird에 incomingServer가 하나 더 붙는다(995)", () => {
    const xml = thunderbirdAutoconfig("example.com", WITH_POP3);
    expect(xml).toContain('<incomingServer type="pop3">');
    const pop3Block = xml.slice(xml.indexOf('<incomingServer type="pop3">'));
    expect(pop3Block).toContain("<hostname>pop3.example.com</hostname>");
    expect(pop3Block).toContain("<port>995</port>");
    // IMAP은 그대로 남는다 — POP3가 대체하는 것이 아니다.
    expect(xml).toContain('<incomingServer type="imap">');
  });

  test("★IMAP이 POP3보다 먼저 온다 — Thunderbird는 첫 항목을 기본으로 고른다", () => {
    const xml = thunderbirdAutoconfig("example.com", WITH_POP3);
    expect(xml.indexOf('type="imap"')).toBeLessThan(xml.indexOf('type="pop3"'));
  });

  test("Outlook POX에도 POP3가 실리고 IMAP이 먼저다", () => {
    const xml = autodiscoverPox("u@example.com", WITH_POP3);
    expect(xml).toContain("<Type>POP3</Type>");
    const pop3Block = xml.slice(xml.indexOf("<Type>POP3</Type>"), xml.indexOf("<Type>SMTP</Type>"));
    expect(pop3Block).toContain("<Server>pop3.example.com</Server>");
    expect(pop3Block).toContain("<Port>995</Port>");
    expect(xml.indexOf("<Type>IMAP</Type>")).toBeLessThan(xml.indexOf("<Type>POP3</Type>"));
  });

  test("포트를 바꿀 수 있다", () => {
    const xml = thunderbirdAutoconfig("example.com", { ...WITH_POP3, pop3Port: 1995 });
    expect(xml).toContain("<port>1995</port>");
  });

  /**
   * ★Apple 프로파일은 IMAP을 유지한다. `com.apple.mail.managed`는 `EmailAccountType`으로
   * 프로토콜을 하나만 고르므로 둘을 담을 수 없고, 페이로드를 두 개 만들면 iOS에 **같은 주소의
   * 계정이 두 개** 생겨 사용자가 어느 쪽에 받았는지 알 수 없게 된다.
   */
  test("Apple 프로파일은 POP3를 켜도 IMAP으로 남는다(계정 중복 방지)", () => {
    const plist = appleMobileconfig("u@example.com", WITH_POP3);
    expect(plist).toContain("<string>EmailTypeIMAP</string>");
    expect(plist).not.toContain("EmailTypePOP");
    expect(plist).toContain("<string>imap.example.com</string>");
    expect(plist).not.toContain("pop3.example.com");
  });

  test("★UUID는 POP3 추가로 바뀌지 않는다 — 바뀌면 iOS에 중복 계정이 생긴다", () => {
    const uuid = (s: string) => s.slice(s.indexOf("<key>PayloadUUID</key>"), s.indexOf("<key>PayloadUUID</key>") + 120);
    expect(uuid(appleMobileconfig("u@example.com", WITH_POP3))).toBe(uuid(appleMobileconfig("u@example.com", SPLIT)));
  });
});
