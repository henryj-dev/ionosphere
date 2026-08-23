/**
 * 웹훅 대상 URL 검증(SSRF) — 감사 M-14의 **실측 우회 표를 그대로 회귀 테스트로 옮긴 것**.
 *
 * 예전 구현은 `url.hostname`에 정규식 블록리스트를 댔고, 아래 케이스들이 통과했다.
 * 특히 `[::ffff:a9fe:a9fe]`는 IPv4-매핑 IPv6로 쓴 **169.254.169.254**(클라우드 메타데이터)로,
 * 검사 함수의 주석이 스스로 "가장 아픈 표적"이라 부르던 바로 그 주소다.
 *
 * 아래 두 묶음을 함께 둔다 — 한쪽만 보면 "더 세게 막자"가 정상 대상까지 막는 것을 놓친다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";
import { isAllowedWebhookUrl } from "../src/url-guard.ts";
import { WebhookWorker, type FetchFn } from "../src/worker.ts";

describe("isAllowedWebhookUrl", () => {
  test("공개 https/http 대상은 허용", () => {
    expect(isAllowedWebhookUrl("https://hook.example.com/in")).toBe(true);
    expect(isAllowedWebhookUrl("http://203.0.113.10/in")).toBe(true);
    expect(isAllowedWebhookUrl("https://[2606:4700:4700::1111]/in")).toBe(true); // 공개 IPv6
    expect(isAllowedWebhookUrl("https://hook.example.com:8443/in")).toBe(true);
  });

  test("루프백·사설·링크로컬은 거부", () => {
    expect(isAllowedWebhookUrl("http://localhost/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://127.0.0.1/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://[::1]/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://10.0.0.5/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://192.168.1.1/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://172.16.0.1/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://172.31.255.255/in")).toBe(false); // 172.16/12 상단 경계
    expect(isAllowedWebhookUrl("http://100.64.0.1/in")).toBe(false); // CGNAT
    expect(isAllowedWebhookUrl("http://[fc00::1]/in")).toBe(false); // ULA
    expect(isAllowedWebhookUrl("http://[fe80::1]/in")).toBe(false); // 링크로컬
    // 클라우드 메타데이터 — 이 검사의 주 표적
    expect(isAllowedWebhookUrl("http://169.254.169.254/latest/meta-data/")).toBe(false);
  });

  test("경계 바로 바깥은 막지 않는다(과차단 회귀)", () => {
    expect(isAllowedWebhookUrl("http://172.15.0.1/in")).toBe(true);
    expect(isAllowedWebhookUrl("http://172.32.0.1/in")).toBe(true);
    expect(isAllowedWebhookUrl("http://11.0.0.1/in")).toBe(true);
    expect(isAllowedWebhookUrl("http://100.63.0.1/in")).toBe(true);
    expect(isAllowedWebhookUrl("http://169.253.0.1/in")).toBe(true);
    expect(isAllowedWebhookUrl("http://126.255.255.255/in")).toBe(true);
  });

  /** ★M-14 실측 표의 "통과" 항목 전부 — 이것들이 뚫려 있었다. */
  describe("M-14 회귀 — 예전에 통과하던 우회", () => {
    test("후행 점이 앵커를 깨던 케이스", () => {
      expect(isAllowedWebhookUrl("http://localhost./in")).toBe(false);
      expect(isAllowedWebhookUrl("http://127.0.0.1./in")).toBe(false);
    });

    test("IPv4-매핑 IPv6가 루프백·사설·메타데이터를 통째로 우회했다", () => {
      expect(isAllowedWebhookUrl("http://[::ffff:127.0.0.1]/in")).toBe(false);
      expect(isAllowedWebhookUrl("http://[::ffff:a9fe:a9fe]/in")).toBe(false); // = 169.254.169.254
      expect(isAllowedWebhookUrl("http://[0:0:0:0:0:ffff:a9fe:a9fe]/in")).toBe(false); // 같은 주소의 비압축 표기
      expect(isAllowedWebhookUrl("http://[::ffff:10.0.0.1]/in")).toBe(false);
      expect(isAllowedWebhookUrl("http://[::ffff:7f00:1]/in")).toBe(false);
    });

    test("unspecified(::)는 다수 스택에서 로컬호스트로 연결된다", () => {
      expect(isAllowedWebhookUrl("http://[::]/in")).toBe(false);
      expect(isAllowedWebhookUrl("http://0.0.0.0/in")).toBe(false);
    });

    test("메타데이터 DNS 이름은 IP 표기조차 필요 없었다", () => {
      expect(isAllowedWebhookUrl("http://metadata.google.internal/computeMetadata/v1/")).toBe(false);
      expect(isAllowedWebhookUrl("http://metadata/")).toBe(false);
      expect(isAllowedWebhookUrl("http://instance-data/latest/meta-data/")).toBe(false);
      expect(isAllowedWebhookUrl("http://anything.internal/")).toBe(false);
      expect(isAllowedWebhookUrl("http://printer.local/")).toBe(false);
      expect(isAllowedWebhookUrl("http://box.localhost/")).toBe(false);
    });

    /** 표에는 없지만 같은 뿌리(IPv6 안에 IPv4가 박히는 표기) — 표기별로 늘리지 않으려 한 이유. */
    test("IPv4-호환·6to4·NAT64 표기도 같은 규칙으로 되돌린다", () => {
      expect(isAllowedWebhookUrl("http://[::7f00:1]/in")).toBe(false); // 폐기된 IPv4-호환 127.0.0.1
      expect(isAllowedWebhookUrl("http://[2002:7f00:1::]/in")).toBe(false); // 6to4 127.0.0.1
      expect(isAllowedWebhookUrl("http://[64:ff9b::a9fe:a9fe]/in")).toBe(false); // NAT64 169.254.169.254
      expect(isAllowedWebhookUrl("http://[ff02::1]/in")).toBe(false); // 멀티캐스트
      expect(isAllowedWebhookUrl("http://255.255.255.255/in")).toBe(false); // 브로드캐스트
    });
  });

  /**
   * WHATWG URL이 `127.0.0.1`로 **정규화해 주기 때문에** 예전에도 막히던 것들.
   * 정규식을 버리면서 이 경로가 깨지지 않았는지 확인한다 — 파서의 결과만 믿는다는 전제가 여기 있다.
   */
  test("십진·8진·16진 표기는 URL 정규화로 계속 막힌다", () => {
    expect(isAllowedWebhookUrl("http://2130706433/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://0x7f.0.0.1/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://0177.0.0.1/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://127.1/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://0/in")).toBe(false);
    expect(isAllowedWebhookUrl("http://user@169.254.169.254/in")).toBe(false); // userinfo는 호스트가 아니다
    expect(isAllowedWebhookUrl("http://LOCALHOST/in")).toBe(false);
  });

  test("http(s)가 아닌 스킴과 깨진 URL은 거부", () => {
    expect(isAllowedWebhookUrl("file:///etc/passwd")).toBe(false);
    expect(isAllowedWebhookUrl("gopher://x/1")).toBe(false);
    expect(isAllowedWebhookUrl("not a url")).toBe(false);
    // 대괄호 안이 유효한 IPv6가 아니면 판정할 수 없다 → fail closed
    expect(isAllowedWebhookUrl("http://[fe80::1%25eth0]/in")).toBe(false);
  });
});

describe("차단된 대상의 배달 처분", () => {
  test("요청을 보내지 않고 즉시 failed로 닫는다(백오프로 계속 두드리지 않는다)", async () => {
    const db: DbDriver = await openSqlite();
    await migrate(db, allMigrations);
    const id = "D".repeat(26);
    await db.batch([
      {
        sql: `INSERT INTO webhook_deliveries (id, account_id, endpoint_id, url, secret, payload, status, attempts, next_attempt, lease_until, last_error, created_at)
              VALUES (?, 'acc', 'ep', 'http://169.254.169.254/latest/meta-data/', '', '{}', 0, 0, 0, NULL, NULL, 0)`,
        params: [id],
      },
    ]);

    let called = 0;
    const fetchFn: FetchFn = async () => {
      called++;
      return { status: 200 };
    };
    const worker = new WebhookWorker({ db, fetch: fetchFn });
    await worker.tick();

    expect(called).toBe(0); // 소켓을 열지도 않았는가
    const { rows } = await db.query({ sql: "SELECT status, last_error FROM webhook_deliveries WHERE id = ?", params: [id] });
    expect(Number(rows[0]!.status)).toBe(3); // failed — 재시도 대상이 아니다
    expect(String(rows[0]!.last_error)).toContain("blocked url");

    await db.close();
  });
});
