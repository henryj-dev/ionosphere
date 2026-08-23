/** 자동설정 — 생성기(3 생태계)·라우터·라이브 HTTP 왕복. */
import { describe, expect, test } from "@ionosphere/testkit";
import {
  appleMobileconfig,
  autodiscoverPox,
  AutoconfigServer,
  deterministicUuid,
  domainFromHost,
  emailFromAutodiscoverBody,
  handleAutoconfig,
  thunderbirdAutoconfig,
  xmlEscape,
  type AutoconfigRequest,
  type AutoconfigSettings,
} from "@ionosphere/autoconfig";

const settings: AutoconfigSettings = { mailHost: "mx.ionosphere.test", brandShort: "Ionosphere" };

function req(method: string, path: string, opts: { host?: string; query?: string; body?: string } = {}): AutoconfigRequest {
  const base: AutoconfigRequest = {
    method,
    host: opts.host ?? "autoconfig.ionosphere.test",
    path,
    query: new URLSearchParams(opts.query ?? ""),
  };
  if (opts.body !== undefined) base.body = opts.body;
  return base;
}

describe("생성기", () => {
  test("Thunderbird: 도메인·호스트·993/465 SSL 포함", () => {
    const xml = thunderbirdAutoconfig("ionosphere.test", settings);
    expect(xml).toContain('<emailProvider id="ionosphere.test">');
    expect(xml).toContain("<hostname>mx.ionosphere.test</hostname>");
    expect(xml).toContain("<port>993</port>");
    expect(xml).toContain("<port>465</port>");
    expect(xml).toContain("<socketType>SSL</socketType>");
    expect(xml).toContain("<username>%EMAILADDRESS%</username>");
    expect(xml).toContain("<displayShortName>Ionosphere</displayShortName>");
  });

  test("Autodiscover POX: LoginName=이메일, IMAP+SMTP", () => {
    const xml = autodiscoverPox("you@ionosphere.test", settings);
    expect(xml).toContain("<LoginName>you@ionosphere.test</LoginName>");
    expect(xml).toContain("<Type>IMAP</Type>");
    expect(xml).toContain("<Type>SMTP</Type>");
    expect(xml).toContain("<Port>465</Port>");
    expect(xml).toContain("<SSL>on</SSL>");
  });

  test("Apple mobileconfig: plist·계정·포트·결정적 UUID", () => {
    const a = appleMobileconfig("you@ionosphere.test", settings);
    expect(a).toContain("<!DOCTYPE plist");
    expect(a).toContain("com.apple.mail.managed");
    expect(a).toContain("<string>you@ionosphere.test</string>");
    expect(a).toContain("<integer>993</integer>");
    expect(a).toContain("<integer>465</integer>");
    // 같은 입력 → 동일 프로파일(idempotent)
    expect(appleMobileconfig("you@ionosphere.test", settings)).toBe(a);
    // 다른 이메일 → 다른 UUID
    expect(appleMobileconfig("other@ionosphere.test", settings)).not.toBe(a);
  });

  test("커스텀 포트 반영", () => {
    const xml = thunderbirdAutoconfig("d.test", { mailHost: "h.test", imapPort: 10993, submissionPort: 10465 });
    expect(xml).toContain("<port>10993</port>");
    expect(xml).toContain("<port>10465</port>");
  });

  test("xmlEscape 5대 엔티티", () => {
    expect(xmlEscape(`<a&b>"c'd`)).toBe("&lt;a&amp;b&gt;&quot;c&apos;d");
  });

  test("deterministicUuid: v5 형식·안정성", () => {
    const u = deterministicUuid("seed");
    expect(u).toMatch(/^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/);
    expect(deterministicUuid("seed")).toBe(u);
    expect(deterministicUuid("other")).not.toBe(u);
  });
});

describe("보조 파서", () => {
  test("domainFromHost: 포트·autoconfig/autodiscover 접두 제거", () => {
    expect(domainFromHost("autoconfig.ionosphere.test:8080")).toBe("ionosphere.test");
    expect(domainFromHost("autodiscover.ionosphere.test")).toBe("ionosphere.test");
    expect(domainFromHost("ionosphere.test")).toBe("ionosphere.test");
  });

  test("emailFromAutodiscoverBody: 네임스페이스 유무 모두", () => {
    expect(emailFromAutodiscoverBody("<EMailAddress>you@x.test</EMailAddress>")).toBe("you@x.test");
    expect(emailFromAutodiscoverBody("<a:EMailAddress>you@x.test</a:EMailAddress>")).toBe("you@x.test");
    expect(emailFromAutodiscoverBody(undefined)).toBeNull();
    expect(emailFromAutodiscoverBody("<other/>")).toBeNull();
  });
});

describe("라우터", () => {
  test("Thunderbird 경로 2종 + 도메인 소스 우선순위(email > host)", () => {
    const wk = handleAutoconfig(req("GET", "/.well-known/autoconfig/mail/config-v1.1.xml", { host: "ionosphere.test" }), settings);
    expect(wk?.status).toBe(200);
    expect(wk?.body).toContain('id="ionosphere.test"');
    // 쿼리 이메일 우선
    const q = handleAutoconfig(req("GET", "/mail/config-v1.1.xml", { host: "autoconfig.other.test", query: "emailaddress=me@chosen.app" }), settings);
    expect(q?.body).toContain('id="chosen.app"');
  });

  test("Autodiscover POX: 바디 이메일 파싱", () => {
    const r = handleAutoconfig(req("POST", "/autodiscover/autodiscover.xml", { body: "<Request><EMailAddress>you@x.test</EMailAddress></Request>" }), settings);
    expect(r?.status).toBe(200);
    expect(r?.contentType).toContain("xml");
    expect(r?.body).toContain("<LoginName>you@x.test</LoginName>");
  });

  test("Autodiscover POX: 이메일 없으면 400 ErrorCode", () => {
    const r = handleAutoconfig(req("POST", "/autodiscover/autodiscover.xml", { body: "<Request/>" }), settings);
    expect(r?.status).toBe(400);
    expect(r?.body).toContain("<ErrorCode>600</ErrorCode>");
  });

  test("Autodiscover v2 JSON: POX URL 포인터", () => {
    const r = handleAutoconfig(req("GET", "/autodiscover/autodiscover.json", { query: "Protocol=AutodiscoverV1" }), settings);
    expect(r?.contentType).toContain("json");
    expect(JSON.parse(r!.body)).toEqual({ Protocol: "AutodiscoverV1", Url: "https://mx.ionosphere.test/autodiscover/autodiscover.xml" });
  });

  test("Apple mobileconfig: 이메일 필수", () => {
    const ok = handleAutoconfig(req("GET", "/email.mobileconfig", { query: "email=you@x.test" }), settings);
    expect(ok?.status).toBe(200);
    expect(ok?.contentType).toContain("apple-aspen-config");
    const bad = handleAutoconfig(req("GET", "/email.mobileconfig"), settings);
    expect(bad?.status).toBe(400);
  });

  test("매칭 실패 → null (어댑터 404), 후행 슬래시 정규화", () => {
    expect(handleAutoconfig(req("GET", "/nope"), settings)).toBeNull();
    // 후행 슬래시 있어도 매칭
    expect(handleAutoconfig(req("GET", "/mail/config-v1.1.xml/"), settings)?.status).toBe(200);
  });

  test("MTA-STS 정책: mtaSts 설정 시 서빙(mx=mailHost), 미설정 시 null", () => {
    // 미설정 → 라우트 없음
    expect(handleAutoconfig(req("GET", "/.well-known/mta-sts.txt"), settings)).toBeNull();
    // 설정 시 정책 본문
    const withSts = { ...settings, mtaSts: { mode: "enforce" as const } };
    const r = handleAutoconfig(req("GET", "/.well-known/mta-sts.txt"), withSts);
    expect(r?.status).toBe(200);
    expect(r?.contentType).toContain("text/plain");
    expect(r?.body).toContain("version: STSv1");
    expect(r?.body).toContain("mode: enforce");
    expect(r?.body).toContain("mx: mx.ionosphere.test");
  });
});

describe("라이브 HTTP 왕복", () => {
  test("서버 listen → GET/POST → close", async () => {
    const server = new AutoconfigServer({ settings });
    const port = await server.listen(0, "127.0.0.1");
    try {
      const g = await fetch(`http://127.0.0.1:${port}/mail/config-v1.1.xml?emailaddress=you@ionosphere.test`);
      expect(g.status).toBe(200);
      expect(await g.text()).toContain("<hostname>mx.ionosphere.test</hostname>");

      const p = await fetch(`http://127.0.0.1:${port}/autodiscover/autodiscover.xml`, {
        method: "POST",
        body: "<Autodiscover><Request><EMailAddress>you@ionosphere.test</EMailAddress></Request></Autodiscover>",
      });
      expect(p.status).toBe(200);
      expect(await p.text()).toContain("<LoginName>you@ionosphere.test</LoginName>");

      const nf = await fetch(`http://127.0.0.1:${port}/nope`);
      expect(nf.status).toBe(404);
    } finally {
      await server.close();
    }
  });
});

describe("경로 정규화", () => {
  /**
   * 후행 슬래시가 길게 이어져도 같은 라우트로 간다. 이 검사가 지키는 것은 라우팅 동작이지만,
   * 같은 자리에서 고친 진짜 문제는 **ReDoS**였다 — `path.replace(/\\/+$/, "")`가 슬래시가
   * 이어지는 입력에서 O(n²)였다(2000개 2.2ms · 8000개 44ms · 16000개 205ms).
   * `req.path`는 공개 리스너가 받는 공격자 입력이라 요청 하나가 그만큼 CPU를 잡는다.
   * 정규식으로 되돌리면 CodeQL js/polynomial-redos가 다시 잡는다.
   */
  test("후행 슬래시가 몇 개든 같은 라우트로 간다", () => {
    const one = handleAutoconfig(req("GET", "/mail/config-v1.1.xml/", { query: "emailaddress=u@ionosphere.test" }), settings);
    const many = handleAutoconfig(req("GET", "/mail/config-v1.1.xml" + "/".repeat(500), { query: "emailaddress=u@ionosphere.test" }), settings);
    expect(one?.status).toBe(200);
    expect(many?.status).toBe(one?.status);
    expect(many?.body).toBe(one?.body);
  });

  test("슬래시만 있는 경로는 루트로 떨어진다(빈 문자열이 되지 않는다)", () => {
    expect(handleAutoconfig(req("GET", "/".repeat(100)), settings)).toBeNull();
  });
});
