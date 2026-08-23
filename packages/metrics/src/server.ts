/**
 * 메트릭 HTTP 어댑터 — node:http 위 얇은 래퍼(Bun/Node 듀얼). GET /metrics + /healthz.
 * ⚠ 평문 HTTP — 내부 네트워크/프록시 뒤에 두고 외부 노출 금지(스크레이프 전용).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { hardenHttpListener, noopLogger, trackListener, type ListenerShutdown, type Logger } from "@ionosphere/core";
import type { Registry } from "./registry.ts";

export interface MetricsServerDeps {
  registry: Registry;
  /**
   * 받을 Host 화이트리스트(소문자, 포트 제외). **미지정이면 검사하지 않는다.**
   *
   * ★여기만 "미지정=전부 허용"인 이유: 이 포트는 **이름이 아니라 주소로** 긁힌다.
   * Prometheus는 대개 `http://10.0.101.12:9464/metrics`로 붙고, 그때 Host 헤더는
   * `10.0.101.12:9464`이다. 이름 화이트리스트를 기본으로 강제하면 **기존 스크레이프가
   * 조용히 404가 된다** — 지표가 끊긴 것을 아무도 모르는 것이 이 표면의 최악이다.
   * 그래서 검사는 **켜는 쪽이 명시**한다(`IONOSPHERE_HOST_METRICS`). IP 문자열도 값으로 쓸 수 있다.
   */
  allowedHosts?: readonly string[];
  logger?: Logger;
}

export class MetricsServer {
  private readonly deps: MetricsServerDeps;
  private readonly log: Logger;
  private server: Server | null = null;
  /** 정상 종료 손잡이 — close 시 남은 연결을 끊는다. */
  private shutdown: ListenerShutdown | null = null;

  constructor(deps: MetricsServerDeps) {
    this.deps = deps;
    this.log = (deps.logger ?? noopLogger).child({ component: "metrics" });
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => {
        void this.handle(req, res);
      });
      server.once("error", reject);
      // ★trackListener로 닫는다. `server.close(cb)`는 **기존 연결이 전부 끝나야** 콜백이 오는데,
      // keep-alive 연결 하나만 남아도 영영 오지 않는다(2026-07-30 사고와 같은 계열 —
      // listener-shutdown.ts 주석). HTTP 서버 3종이 이 처리에서 빠져 있었고,
      // node:test로 옮기면서 **프로세스가 안 죽는** 형태로 드러났다.
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      hardenHttpListener(server); // 연결 수 상한 + slowloris 타임아웃(listen 전에 걸어야 빈틈이 없다)
      server.listen(port, host, () => {
        this.server = server;
        this.shutdown = shutdown;
        const addr = server.address();
        resolve(typeof addr === "object" && addr !== null ? addr.port : port);
      });
    });
  }

  async close(): Promise<void> {
    // ★shutdown.close()를 쓴다 — 남은 keep-alive 연결을 끊고 나서 닫는다.
    // 예전엔 server.close()만 불렀는데, 그건 기존 연결이 끝나야 콜백이 와서
    // **종료가 영영 끝나지 않는다**(listener-shutdown.ts 주석의 2026-07-30 사고).
    const shutdown = this.shutdown;
    this.server = null;
    this.shutdown = null;
    if (shutdown) await shutdown.close();
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const allow = this.deps.allowedHosts;
    if (allow && allow.length > 0) {
      const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
      if (!allow.includes(host)) {
        this.log.warn("허용되지 않은 Host — 거부", { host });
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        return void res.end("not found");
      }
    }
    const path = (req.url ?? "/").split("?")[0];
    if (req.method === "GET" && path === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      return void res.end('{"ok":true}');
    }
    if (req.method === "GET" && path === "/metrics") {
      try {
        await this.deps.registry.collect();
        const body = this.deps.registry.render();
        res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
        return void res.end(body);
      } catch (err) {
        this.log.error("metrics render failed", { error: String(err) });
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        return void res.end("internal error");
      }
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("not found");
  }
}
