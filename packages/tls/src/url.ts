/**
 * url CertSource — 인증된 HTTPS에서 cert/key를 페치해 디스크에 캐시한다. 페치 실패 시 캐시로
 * 폴백(부팅 시 원격 불가여도 기존 인증서로 기동). watch()는 주기 재페치로 변경 시 무중단 교체.
 * (앞서 논의한 클러스터 cert export 엔드포인트 소비 경로)
 *
 * 이 경로가 다루는 것은 **개인키**다. 그래서 세 겹으로 잠근다(2026-07-30 감사 H-1):
 *  ① 스킴 — 생성 시점(=기동 시점)에 https: 강제. ② 내용 — 페어링·호스트 대조를 **캐시 쓰기 전에**.
 *  ③ 크기 — 응답 상한. 셋 다 없어서 평문 전송·임의 인증서 주입·단일 프로세스 OOM이 모두 가능했다.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { inspectCert } from "./inspect.ts";
import { checkTransportUrl, insecureTransportWarning } from "./secure-url.ts";
import { noopLogger, type Logger } from "@ionosphere/core";
import { assertUsableCert } from "./verify.ts";
import type { CertSource, CertStatus, TlsMaterial } from "./types.ts";

/**
 * cert/key 응답 하나의 바이트 상한.
 *
 * 근거: fullchain PEM은 보통 수 KB이고, 상한 없이 전량 버퍼링하면 악성·오작동 엔드포인트의
 * 수 GB 응답 하나가 **모든 프로토콜이 올라탄 단일 프로세스**를 OOM으로 죽인다. 부팅·6시간 주기
 * 재페치·관리 API refresh가 전부 이 경로다. 256KiB면 체인 수십 장을 담고도 남는다.
 */
export const MAX_CERT_FETCH_BYTES = 256 * 1024;

export interface UrlCertOptions {
  certUrl: string;
  keyUrl: string;
  /** 인증 헤더 등(예: { authorization: "Bearer ..." }). */
  headers?: Record<string, string>;
  /** 페치 결과 캐시 디렉토리(폴백 + status). */
  cacheDir: string;
  /** 주기 재페치 간격(ms). 기본 6h. */
  refreshIntervalMs?: number;
  /**
   * 이 호스트들 중 하나에 유효한 인증서만 받아들인다(SAN 대조). 비우면 대조를 건너뛰므로
   * 조립층이 반드시 채워야 한다 — 침해된 엔드포인트가 자기가 가진 아무 인증서나 밀어넣는 것을
   * 막는 유일한 검사다.
   */
  expectedHosts?: readonly string[];
  /** 평문 http: 경고를 낼 로거. 생략 시 무음(테스트용) — 조립층은 반드시 넘긴다. */
  logger?: Logger;
  /** 응답 바이트 상한 override(기본 MAX_CERT_FETCH_BYTES). 테스트·특수 배포용. */
  maxBytes?: number;
  /** fetch 주입(테스트). */
  fetch?: typeof fetch;
}

/**
 * 응답을 상한까지만 읽는다.
 *
 * content-length만 믿으면 안 된다 — 헤더는 거짓말할 수 있고 아예 없을 수도 있다(chunked).
 * 그래서 선언값으로 조기 거절하되, **실제로 읽은 바이트**도 세면서 초과 즉시 스트림을 끊는다.
 */
async function readCapped(res: Response, limit: number, what: string): Promise<Buffer> {
  const declared = res.headers?.get?.("content-length");
  if (declared !== null && declared !== undefined && declared !== "" && Number(declared) > limit) {
    throw new Error(`${what} 응답이 상한 초과(content-length ${declared} > ${limit} bytes)`);
  }
  const body: ReadableStream<Uint8Array> | null | undefined = res.body;
  if (!body || typeof body.getReader !== "function") {
    // 스트림이 없는 구현(주입 fetch 등) — 이미 메모리에 올라온 뒤라 길이 검사만 의미가 있다.
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > limit) throw new Error(`${what} 응답이 상한 초과(${buf.length} > ${limit} bytes)`);
    return buf;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined); // 남은 본문을 계속 받아 메모리를 더 쓰지 않는다
      throw new Error(`${what} 응답이 상한 초과(${total} > ${limit} bytes)`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

export function urlCertSource(opts: UrlCertOptions): CertSource {
  const log = (opts.logger ?? noopLogger).child({ component: "tls" });
  /**
   * 스킴 판정은 **기동 시점**에 한 번 한다(첫 페치를 기다리면 그때는 이미 평문으로 흘린 뒤다).
   * 다만 막지는 않고 경고한다 — secure-url.ts `checkTransportUrl` 주석의 운영 결정.
   */
  const certCheck = checkTransportUrl("TLS cert URL", opts.certUrl);
  const keyCheck = checkTransportUrl("TLS key URL", opts.keyUrl);
  const insecure = [
    ...(certCheck.insecure ? [insecureTransportWarning("TLS cert URL", certCheck.url)] : []),
    ...(keyCheck.insecure ? [insecureTransportWarning("TLS key URL", keyCheck.url)] : []),
  ];
  // 최초 실행 시 1회 — 기동 로그만 봐도 드러나야 한다.
  for (const w of insecure) log.warn(w, { phase: "startup" });

  const f = opts.fetch ?? fetch;
  const interval = opts.refreshIntervalMs ?? 6 * 60 * 60 * 1000;
  const limit = opts.maxBytes ?? MAX_CERT_FETCH_BYTES;
  const certCache = join(opts.cacheDir, "url-cert.pem");
  const keyCache = join(opts.cacheDir, "url-key.pem");
  let timer: ReturnType<typeof setInterval> | null = null;
  let lastCert = "";

  async function fetchOnce(): Promise<TlsMaterial> {
    // 매 커넥션마다 — 6시간 주기 재페치·관리 API refresh·부팅 전부 여기를 지난다.
    // 반복 로그가 곧 "아직 평문이다"라는 지속 신호다.
    for (const w of insecure) log.warn(w, { phase: "fetch" });
    // exactOptionalPropertyTypes: headers가 undefined면 키 자체를 넣지 않는다(조건부 스프레드).
    const init: RequestInit = opts.headers ? { headers: opts.headers } : {};
    const [cr, kr] = await Promise.all([f(opts.certUrl, init), f(opts.keyUrl, init)]);
    if (!cr.ok) throw new Error(`cert fetch ${cr.status}`);
    if (!kr.ok) throw new Error(`key fetch ${kr.status}`);
    const cert = await readCapped(cr, limit, "cert");
    const key = await readCapped(kr, limit, "key");
    // ★ 순서가 보안이다: 검증 → 캐시 쓰기. 반대로 하면 오염된 자재가 폴백에 눌러앉는다.
    assertUsableCert("페치한 TLS 자재", cert, key, opts.expectedHosts);
    await mkdir(dirname(certCache), { recursive: true });
    await writeFile(certCache, cert);
    await writeFile(keyCache, key, { mode: 0o600 });
    lastCert = cert.toString("latin1");
    return { key, cert };
  }

  async function fromCache(): Promise<TlsMaterial | null> {
    try {
      const [cert, key] = await Promise.all([readFile(certCache), readFile(keyCache)]);
      // 캐시도 같은 기준으로 검사한다 — 이 수정 이전에 쓰인 캐시나 디스크가 손상된 캐시를
      // "예전엔 통과했으니 괜찮다"고 믿으면 폴백이 검증 우회로가 된다.
      assertUsableCert("캐시된 TLS 자재", cert, key, opts.expectedHosts);
      lastCert = cert.toString("latin1");
      return { key, cert };
    } catch {
      return null;
    }
  }

  return {
    mode: "url",
    async resolve() {
      try {
        return await fetchOnce();
      } catch (err) {
        /**
         * ★캐시 폴백은 **반드시 시끄러워야 한다.** 예전엔 이 catch가 사유를 삼켜서, 폴백이
         * 일어난 것도 왜 일어났는지도 로그에 남지 않았다.
         *
         * 2026-08-03에 이것으로 시간을 잃었다: 스코프를 새 인증서로 바꾸고 재시작했는데 443이
         * 계속 **옛 와일드카드 인증서**를 제시했다. 페치·키쌍·SAN 대조를 수동으로 다 돌려 봐도
         * 전부 통과해서 원인을 짚을 수 없었다 — 앱이 조용히 캐시로 폴백한 것이었고, 그 캐시가
         * 와일드카드라 `expectedHosts`(새 이름 4개)를 **전부 덮어 검증까지 통과**했다.
         * 즉 "설정을 바꿨는데 안 바뀐다"로 나타나고, 폴백이라는 사실 자체가 감춰진다.
         *
         * 폴백은 원격이 죽었을 때 서비스를 살리는 장치이므로 유지한다. 다만 그것이 **정상 경로가
         * 아니라는 것**은 로그에 남아야 한다 — 특히 캐시가 낡은 이름의 인증서일 수 있다.
         */
        const detail = err instanceof Error ? err.message : String(err);
        const cached = await fromCache();
        if (cached) {
          log.warn("url cert 페치 실패 — **캐시로 폴백**한다(제시되는 인증서가 낡았을 수 있다)", {
            certUrl: opts.certUrl,
            error: detail,
            cache: certCache,
          });
          return cached;
        }
        // 사유를 감싸 올린다 — 조립층(app.ts)이 이 메시지를 그대로 로그에 찍는다.
        throw new Error(`url cert 페치 실패 + 쓸 수 있는 캐시 없음: ${detail}`);
      }
    },
    async refresh() {
      return fetchOnce();
    },
    watch(onChange) {
      timer = setInterval(() => {
        const prev = lastCert;
        void fetchOnce()
          .then((m) => {
            if (lastCert !== prev) onChange(m); // 인증서 바이트가 바뀐 경우만 교체
          })
          .catch((err: unknown) => {
            /**
             * 재페치 실패는 다음 주기에 재시도하므로 **던지지 않는다**(한 번의 네트워크 실패로
             * 리스너를 흔들면 안 된다). 다만 조용히 넘기면 안 된다 — 이 실패가 계속되면 갱신이
             * 멈춘 것이고, 그 사실은 **인증서가 만료되는 날**에야 드러난다. 6시간 주기라
             * 로그가 넘치지도 않는다.
             */
            log.warn("url cert 재페치 실패 — 갱신이 반영되지 않았다(다음 주기 재시도)", {
              certUrl: opts.certUrl,
              error: err instanceof Error ? err.message : String(err),
            });
          });
      }, interval);
      timer.unref?.();
      return () => {
        if (timer) clearInterval(timer);
        timer = null;
      };
    },
    async status(): Promise<CertStatus> {
      try {
        const cert = await readFile(certCache);
        return { mode: "url", enabled: true, source: opts.certUrl, ...inspectCert(cert) };
      } catch {
        return { mode: "url", enabled: false, source: opts.certUrl, error: "미페치(캐시 없음)" };
      }
    },
    close() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
}
