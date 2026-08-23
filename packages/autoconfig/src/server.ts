/**
 * 자동설정 HTTP 어댑터 — node:http 위 얇은 래퍼(Bun/Node 듀얼, Bun.serve 금지).
 * 순수 라우터 handleAutoconfig를 감싸 요청을 서술로 바꾸고 응답을 쓴다.
 *
 * ⚠ TLS 종단은 이 서버 밖(리버스 프록시/향후 ACME)의 몫 — 평문 HTTP로 리슨한다.
 * Autodiscover/mobileconfig는 클라이언트가 https로 접근하므로 실운영은 프록시 뒤에 둘 것.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { hardenHttpListener, noopLogger, trackListener, type ListenerShutdown, type Logger } from "@ionosphere/core";
import { handleAutoconfig, type AutoconfigRequest } from "./handler.ts";
import type { AutoconfigSettings } from "./generate.ts";

export interface AutoconfigServerDeps {
  settings: AutoconfigSettings;
  logger?: Logger;
  /** POST 바디 상한(autodiscover XML은 작다). 기본 64KiB. */
  maxBodyBytes?: number;
}

export class AutoconfigServer {
  private readonly deps: AutoconfigServerDeps;
  private readonly log: Logger;
  private readonly maxBody: number;
  private server: Server | null = null;
  /** 정상 종료 손잡이 — close 시 남은 연결을 끊는다. */
  private shutdown: ListenerShutdown | null = null;

  constructor(deps: AutoconfigServerDeps) {
    this.deps = deps;
    this.log = (deps.logger ?? noopLogger).child({ component: "autoconfig" });
    this.maxBody = deps.maxBodyBytes ?? 64 * 1024;
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
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const method = req.method ?? "GET";
      const areq: AutoconfigRequest = {
        method,
        host: req.headers.host ?? this.deps.settings.mailHost,
        path: url.pathname,
        query: url.searchParams,
      };
      if (method === "POST") areq.body = await this.readBody(req); // exactOptionalPropertyTypes: undefined 대입 회피
      const out = handleAutoconfig(areq, this.deps.settings);
      if (!out) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        return void res.end("not found");
      }
      res.writeHead(out.status, { "Content-Type": out.contentType });
      res.end(out.body);
    } catch (err) {
      this.log.error("autoconfig request failed", { error: String(err) });
      if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("internal error");
    }
  }

  /** 바디를 상한까지만 읽는다(초과 시 잘라 파서에 맡김 — autodiscover XML은 작다). */
  private async readBody(req: IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const c of req) {
      const buf = c as Buffer;
      total += buf.length;
      if (total > this.maxBody) break;
      chunks.push(buf);
    }
    return Buffer.concat(chunks).toString("utf8");
  }
}
