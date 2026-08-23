/** url CertSource — 페치·디스크 캐시·페치실패 폴백·refresh·status + 스킴/내용/크기 게이트(감사 H-1). */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSelfSigned, urlCertSource } from "@ionosphere/tls";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs.length = 0;
});
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "ionosphere-url-"));
  dirs.push(d);
  return d;
}

const { keyPem, certPem } = generateSelfSigned({ commonName: "mx.remote.test", sans: ["mx.remote.test"] });

/** 주입용 fetch — 상태/본문을 제어. */
function fakeFetch(map: Record<string, { status: number; body: string }>, onCall?: () => void): typeof fetch {
  return (async (url: string) => {
    onCall?.();
    const e = map[String(url)];
    if (!e) return { ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) } as Response;
    return { ok: e.status >= 200 && e.status < 300, status: e.status, arrayBuffer: async () => new TextEncoder().encode(e.body).buffer } as Response;
  }) as unknown as typeof fetch;
}

const CERT_URL = "https://vault.test/cert";
const KEY_URL = "https://vault.test/key";
const okMap = { [CERT_URL]: { status: 200, body: certPem }, [KEY_URL]: { status: 200, body: keyPem } };


/** warn 로그만 모으는 로거 — "경고가 반드시 나온다"를 검증하기 위한 것. */
function captureLogger(sink: string[]) {
  const l = {
    debug: () => undefined,
    info: () => undefined,
    warn: (msg: string) => void sink.push(msg),
    error: () => undefined,
    child: () => l,
  };
  return l as unknown as NonNullable<Parameters<typeof urlCertSource>[0]["logger"]>;
}

const PAIR = { host: "mx.remote.test" };
const PLAIN_CERT_URL = "http://10.253.192.10:8080/cert";
const PLAIN_KEY_URL = "http://10.253.192.10:8080/key";
/** 평문 URL로도 정상 자재를 돌려주는 fetch — 경고 반복만 보기 위한 것. */
function pairFetch(): typeof fetch {
  return fakeFetch({ [PLAIN_CERT_URL]: { status: 200, body: certPem }, [PLAIN_KEY_URL]: { status: 200, body: keyPem } });
}

describe("urlCertSource", () => {
  test("resolve가 페치+캐시, status 파싱", async () => {
    const dir = tmp();
    const s = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, fetch: fakeFetch(okMap) });
    const m = await s.resolve();
    expect(Buffer.from(m!.cert).toString()).toBe(certPem);
    expect(Buffer.from(m!.key).toString()).toBe(keyPem);
    const st = await s.status();
    expect(st).toMatchObject({ mode: "url", enabled: true });
    expect(st.sans).toEqual(["mx.remote.test"]);
  });

  test("페치 실패 시 캐시로 폴백", async () => {
    const dir = tmp();
    // 1) 성공 페치로 캐시 채움
    await urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, fetch: fakeFetch(okMap) }).resolve();
    // 2) 새 소스 + 실패 fetch → 캐시 폴백
    const failing = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, fetch: fakeFetch({}) });
    const m = await failing.resolve();
    expect(Buffer.from(m!.cert).toString()).toBe(certPem);
  });

  /**
   * ★캐시 폴백은 **시끄러워야 한다.** 예전엔 catch가 사유를 삼켜서 폴백이 일어난 것도, 왜
   * 일어났는지도 로그에 남지 않았다.
   *
   * 2026-08-03에 이것으로 시간을 잃었다: 인증서 스코프를 바꾸고 재시작했는데 443이 계속 옛
   * 와일드카드를 제시했다. 페치·키쌍·SAN 대조를 수동으로 다 돌려도 전부 통과해 원인을 짚을 수
   * 없었다 — 앱이 조용히 캐시로 폴백한 것이고, 그 캐시가 와일드카드라 새 이름 전부를 덮어
   * `expectedHosts` 검증까지 통과했다. "설정을 바꿨는데 안 바뀐다"로 나타나고 폴백이라는
   * 사실 자체가 감춰진다.
   */
  test("★캐시 폴백은 경고를 남긴다(조용히 낡은 인증서를 쓰지 않는다)", async () => {
    const dir = tmp();
    await urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, fetch: fakeFetch(okMap) }).resolve();
    const warnings: string[] = [];
    const failing = urlCertSource({
      certUrl: CERT_URL,
      keyUrl: KEY_URL,
      cacheDir: dir,
      fetch: fakeFetch({}),
      logger: captureLogger(warnings),
    });
    await failing.resolve();
    expect(warnings.some((w) => w.includes("캐시로 폴백"))).toBe(true);
  });

  test("캐시도 없고 페치 실패 → throw (사유가 메시지에 담긴다)", async () => {
    const s = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), fetch: fakeFetch({}) });
    // 사유 없이 "실패했다"만 던지면 운영자가 원인(404·401·SAN 불일치)을 구분할 수 없다.
    await expect(s.resolve()).rejects.toThrow(/페치 실패/);
  });

  test("refresh는 재페치", async () => {
    const dir = tmp();
    let calls = 0;
    const s = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, fetch: fakeFetch(okMap, () => calls++) });
    await s.resolve();
    const before = calls;
    await s.refresh!();
    expect(calls).toBeGreaterThan(before);
  });

  test("cert가 파싱 불가면 실패", async () => {
    const bad = { [CERT_URL]: { status: 200, body: "not a pem" }, [KEY_URL]: { status: 200, body: keyPem } };
    const s = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), fetch: fakeFetch(bad) });
    await expect(s.resolve()).rejects.toBeTruthy();
  });
});

/**
 * 감사 H-1 회귀 — 이 경로는 **개인키**를 다룬다. 스킴·내용·크기 셋 중 하나라도 빠지면
 * 평문 전송·임의 인증서 주입·단일 프로세스 OOM 중 하나가 그대로 살아난다.
 */
describe("urlCertSource 보안 게이트", () => {
  /**
   * 평문 http:는 **막지 않는다**(운영 결정) — 대신 기동 시 1회, 그리고 **페치할 때마다 매번**
   * 경고를 남긴다. 라이브 cert-api가 관리 VPC 주소라 거부하면 배포가 통째로 막히기 때문이다.
   * 여기서 고정하는 계약은 "경고가 반드시 나온다"는 것이다 — 조용히 지나가면 H-1이 되돌아온다.
   */
  test("원격 http:는 기동 시점에 경고를 남긴다(거부하지는 않는다)", () => {
    const warnings: string[] = [];
    const logger = captureLogger(warnings);
    expect(() =>
      urlCertSource({ certUrl: "http://10.253.192.10:8080/cert", keyUrl: KEY_URL, cacheDir: tmp(), logger }),
    ).not.toThrow();
    expect(warnings.some((w) => w.includes("평문 http:"))).toBe(true);

    // key만 평문이어도 경고 — 개인키 쪽이 더 치명적이다
    const warnings2: string[] = [];
    urlCertSource({ certUrl: CERT_URL, keyUrl: "http://10.253.192.10:8080/key", cacheDir: tmp(), logger: captureLogger(warnings2) });
    expect(warnings2.some((w) => w.includes("평문 http:"))).toBe(true);
  });

  test("https:만 쓰면 경고가 없다(정상 구성은 조용하다)", () => {
    const warnings: string[] = [];
    urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), logger: captureLogger(warnings) });
    expect(warnings).toHaveLength(0);
  });

  test("루프백 http:는 경고하지 않는다(개발 환경 노이즈 방지)", () => {
    const warnings: string[] = [];
    urlCertSource({ certUrl: "http://127.0.0.1:8080/cert", keyUrl: "http://localhost:8080/key", cacheDir: tmp(), logger: captureLogger(warnings) });
    expect(warnings).toHaveLength(0);
  });

  test("페치할 때마다 매번 경고가 반복된다 — 기동 로그 한 줄로 끝나지 않는다", async () => {
    const warnings: string[] = [];
    const src = urlCertSource({
      certUrl: PLAIN_CERT_URL,
      keyUrl: PLAIN_KEY_URL,
      cacheDir: tmp(),
      logger: captureLogger(warnings),
      expectedHosts: [PAIR.host],
      fetch: pairFetch(),
    });
    const atStartup = warnings.length;
    expect(atStartup).toBeGreaterThan(0);

    await src.resolve();
    const afterFirst = warnings.length;
    expect(afterFirst).toBeGreaterThan(atStartup);

    await src.refresh!();
    expect(warnings.length).toBeGreaterThan(afterFirst);
    src.close?.();
  });

  test("cert-key 쌍이 안 맞으면 거부 + **캐시에 남지 않는다**", async () => {
    const dir = tmp();
    const other = generateSelfSigned({ commonName: "mx.remote.test", sans: ["mx.remote.test"] });
    const mismatched = { [CERT_URL]: { status: 200, body: certPem }, [KEY_URL]: { status: 200, body: other.keyPem } };
    const s = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, fetch: fakeFetch(mismatched) });
    await expect(s.resolve()).rejects.toBeTruthy();
    expect(existsSync(join(dir, "url-cert.pem"))).toBe(false);
    expect(existsSync(join(dir, "url-key.pem"))).toBe(false);
  });

  test("오염된 응답이 기존 정상 캐시를 덮어쓰지 않는다(폴백 유지)", async () => {
    const dir = tmp();
    await urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, fetch: fakeFetch(okMap) }).resolve();
    const poison = generateSelfSigned({ commonName: "evil.attacker.test", sans: ["evil.attacker.test"] });
    const bad = { [CERT_URL]: { status: 200, body: poison.certPem }, [KEY_URL]: { status: 200, body: poison.keyPem } };
    const s = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: dir, expectedHosts: ["mx.remote.test"], fetch: fakeFetch(bad) });
    const m = await s.resolve(); // 검증 실패 → 캐시 폴백
    expect(Buffer.from(m!.cert).toString()).toBe(certPem);
    expect(readFileSync(join(dir, "url-cert.pem"), "utf8")).toBe(certPem);
  });

  test("expectedHosts와 SAN이 안 맞으면 거부, 와일드카드는 통과", async () => {
    const wild = generateSelfSigned({ commonName: "ionosphere.test", sans: ["*.ionosphere.test", "ionosphere.test"] });
    const map = { [CERT_URL]: { status: 200, body: wild.certPem }, [KEY_URL]: { status: 200, body: wild.keyPem } };
    const mismatch = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), expectedHosts: ["mx.other.test"], fetch: fakeFetch(map) });
    await expect(mismatch.resolve()).rejects.toBeTruthy();
    const ok = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), expectedHosts: ["mx.ionosphere.test"], fetch: fakeFetch(map) });
    expect(Buffer.from((await ok.resolve())!.cert).toString()).toBe(wild.certPem);
  });

  test("크기 상한 초과는 거부 — content-length 선언과 실제 바이트 양쪽", async () => {
    const huge = "x".repeat(4096);
    // ① content-length로 조기 거절
    const declared = ((async (url: string) =>
      new Response(String(url) === CERT_URL ? huge : keyPem, { headers: { "content-length": String(huge.length) } })) as unknown) as typeof fetch;
    const a = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), maxBytes: 1024, fetch: declared });
    await expect(a.resolve()).rejects.toBeTruthy();
    // ② content-length가 없어도 실제 누적 바이트로 끊는다(chunked·거짓 헤더 대비)
    const chunked = ((async (url: string) => {
      const body = String(url) === CERT_URL ? huge : keyPem;
      return new Response(
        new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(new TextEncoder().encode(body));
            c.close();
          },
        }),
      );
    }) as unknown) as typeof fetch;
    const b = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), maxBytes: 1024, fetch: chunked });
    await expect(b.resolve()).rejects.toBeTruthy();
  });

  test("정상 https + 스트리밍 응답은 그대로 동작", async () => {
    const streaming = ((async (url: string) => new Response(String(url) === CERT_URL ? certPem : keyPem)) as unknown) as typeof fetch;
    const s = urlCertSource({ certUrl: CERT_URL, keyUrl: KEY_URL, cacheDir: tmp(), expectedHosts: ["mx.remote.test"], fetch: streaming });
    const m = await s.resolve();
    expect(Buffer.from(m!.cert).toString()).toBe(certPem);
  });
});
