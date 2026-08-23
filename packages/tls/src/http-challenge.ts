/**
 * http-01 챌린지 응답 리스너 — `/.well-known/acme-challenge/<token>`만 서빙하는 최소 HTTP 서버.
 *
 * ★왜 이게 있어야 하나(오픈소스 자립성): 예전엔 ACME가 dns-01 전용이고 `DnsProvider` 구현이
 * Cloudflare 하나뿐이라, 다른 DNS를 쓰는 사용자는 `IONOSPHERE_TLS_MODE=acme`를 쓸 수 없었다.
 * http-01은 80포트만 있으면 되고 외부 서비스 계정이 전혀 필요 없다.
 *
 * 설계상 의도적으로 **좁다**:
 *  - GET/HEAD, `/.well-known/acme-challenge/` 접두어, 등록된 토큰 정확 일치 — 그 외 전부 404.
 *    이 리스너는 발급 기간에만 공개 80포트에 떠 있으므로 표면을 넓힐 이유가 없다.
 *  - 토큰은 base64url 문자만 받는다. 경로 조각을 그대로 Map 키로 쓰지만 파일시스템에 닿지 않으므로
 *    경로 탈출 위험은 없고, 그래도 형식을 좁혀 로그 오염을 막는다.
 *  - 응답 본문은 key authorization **원문**이다(RFC 8555 §8.3). dns-01처럼 해시하면 검증이 실패한다.
 *
 * ⚠ 80포트는 특권 포트다. root가 아니면 `CAP_NET_BIND_SERVICE`가 필요하고, 없으면 `listen`이
 * EACCES로 실패한다 — 그 실패를 삼키지 않고 그대로 올린다(fail closed: 조용히 안 뜨면 갱신이
 * 몇 주 뒤에 만료로 드러난다).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { hardenHttpListener, noopLogger, trackListener, type ListenerShutdown, type Logger } from "@ionosphere/core";
import type { HttpChallengeResponder } from "./acme.ts";

/** RFC 8555 §8.3의 고정 경로 접두어. */
export const ACME_HTTP_PREFIX = "/.well-known/acme-challenge/";

/** ACME 토큰은 base64url 문자열이다(RFC 8555 §8.3 "randomly generated ... base64url"). */
const TOKEN_RE = /^[A-Za-z0-9_-]{1,255}$/;

export interface HttpChallengeServerOptions {
  /** 기본 80. 테스트는 0을 넘겨 임의 포트를 받는다. */
  port?: number;
  /** 기본 미지정(전 인터페이스) — CA가 외부에서 닿아야 하므로 루프백으로 묶으면 안 된다. */
  host?: string;
  logger?: Logger;
}

export interface HttpChallengeServer extends HttpChallengeResponder {
  /** 실제 리슨 포트(port:0을 넘겼을 때 확인용). */
  listen(): Promise<number>;
  close(): Promise<void>;
}

/**
 * 리스너를 만든다. `listen()`을 부르기 전에는 소켓을 열지 않는다 — 발급이 필요한 순간에만 열고
 * 끝나면 닫는 사용을 위해서다(80포트를 상시 점유하면 다른 웹서버와 충돌한다).
 */
export function httpChallengeServer(opts: HttpChallengeServerOptions = {}): HttpChallengeServer {
  const log = (opts.logger ?? noopLogger).child({ component: "acme-http-01" });
  const tokens = new Map<string, string>();
  let server: Server | null = null;
  /** 정상 종료 손잡이 — CA 연결이 남아도 close가 끝나게 한다. */
  let shutdown: ListenerShutdown | null = null;

  function handle(req: IncomingMessage, res: ServerResponse): void {
    const path = (req.url ?? "/").split("?")[0] ?? "/";
    const method = req.method ?? "GET";
    if ((method !== "GET" && method !== "HEAD") || !path.startsWith(ACME_HTTP_PREFIX)) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      return void res.end("not found");
    }
    const token = path.slice(ACME_HTTP_PREFIX.length);
    const value = TOKEN_RE.test(token) ? tokens.get(token) : undefined;
    if (value === undefined) {
      // 미등록 토큰을 굳이 로그로 남긴다 — 발급 실패 시 "CA가 왔는데 값이 없었다"와
      // "CA가 오지도 않았다"는 원인이 완전히 다르고, 이 구분이 없으면 진단이 추측이 된다.
      log.warn("acme http-01 미등록 토큰 요청", { token: token.slice(0, 32) });
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      return void res.end("not found");
    }
    // RFC 8555 §8.3: media type은 application/octet-stream 권고, 본문은 key authorization 원문.
    res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(Buffer.byteLength(value)) });
    if (method === "HEAD") return void res.end();
    res.end(value);
  }

  return {
    listen(): Promise<number> {
      const port = opts.port ?? 80;
      return new Promise((resolve, reject) => {
        const s = createServer(handle);
        // ★CA가 붙은 keep-alive 연결이 남으면 server.close()의 콜백이 오지 않는다
        // (listener-shutdown.ts의 2026-07-30 사고와 같은 계열). listen 전에 붙인다.
        const sd = trackListener(s);
        s.once("error", reject);
        hardenHttpListener(s); // 연결 상한 + slowloris 타임아웃(listen 전에 걸어야 빈틈이 없다)
        s.listen(port, opts.host, () => {
          server = s;
          shutdown = sd;
          const addr = s.address();
          const actual = typeof addr === "object" && addr !== null ? addr.port : port;
          log.info("acme http-01 리스너 시작", { port: actual });
          resolve(actual);
        });
      });
    },
    set(token, keyAuthorization) {
      if (!TOKEN_RE.test(token)) return Promise.reject(new Error(`ACME http-01: 토큰 형식이 아니다: ${token.slice(0, 32)}`));
      tokens.set(token, keyAuthorization);
      return Promise.resolve();
    },
    remove(token) {
      tokens.delete(token);
      return Promise.resolve();
    },
    async close(): Promise<void> {
      tokens.clear();
      const sd = shutdown;
      server = null;
      shutdown = null;
      if (sd) await sd.close();
    },
  };
}
