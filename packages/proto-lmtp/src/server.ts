/**
 * LMTP 소켓 어댑터 — node:net 위에서 LmtpEngine을 구동. TCP(host/port) 또는 unix 소켓 경로.
 * 상태머신은 engine.ts에 있고, 여기는 소켓 ↔ 액션 배선(verifyRcpt/deliver 비동기 백엔드 호출 포함).
 */
import * as net from "node:net";
import {
  AUDIT_OUTCOME,
  AUDIT_SURFACE,
  LMTP_IDLE_TIMEOUT_MS,
  MAX_LISTENER_CONNECTIONS,
  noopAuditSink,
  normalizeIp,
  type AuditSink,
} from "@ionosphere/core";
import { LmtpEngine, type LmtpAction, type LmtpDelivery, type LmtpDeliverEnv } from "./engine.ts";

export interface LmtpBackend {
  verifyRecipient(address: string): Promise<{ ok: true } | { ok: false; code: number; enhanced: string; message: string }>;
  /** 수신자별 배달 결과(RCPT 순서 무관 — 엔진이 rcpt로 매칭). */
  deliverLmtp(env: LmtpDeliverEnv): Promise<LmtpDelivery[]>;
}

export interface LmtpServerOptions {
  hostname: string;
  backend: LmtpBackend;
  maxSizeBytes?: number;
  /**
   * 유휴 연결 타임아웃(ms). 기본 `LMTP_IDLE_TIMEOUT_MS`(5분).
   *
   * 옵션으로 뚫어 두는 이유는 **테스트가 실제로 끊기는 것을 확인할 수 있게** 하기 위해서다
   * (5분을 기다리는 테스트는 쓸 수 없고, 그러면 배선이 빠져도 아무도 모른다 —
   * JmapServer의 `eventSourcePollMs`와 같은 이유).
   */
  idleTimeoutMs?: number;
  /**
   * 접근 감사 싱크 — 조립층이 다른 리스너와 같은 인스턴스를 넘긴다.
   *
   * ★LMTP에는 인증이 없다(로컬 배달 전용 소켓). 그래서 **배달 한 줄이 이 표면의 유일한 기록**
   * 이고, 그것이 없으면 "메일함에 글을 쓴 경로 하나가 감사 로그에서 통째로 빠진다".
   *
   * 생략 시 기록하지 않는다(`noopAuditSink`) — 기존 동작 그대로.
   */
  audit?: AuditSink;
}

export class LmtpServer {
  private readonly opts: LmtpServerOptions;
  private server: net.Server | null = null;
  private readonly sockets = new Set<net.Socket>();
  /** 접근 감사 싱크 — 미주입 시 no-op(호출부가 `?.`를 쓰지 않게). */
  private readonly audit: AuditSink;

  constructor(opts: LmtpServerOptions) {
    this.opts = opts;
    this.audit = opts.audit ?? noopAuditSink;
  }

  /** TCP 리슨(테스트/로컬). 반환: 실제 포트. */
  listen(port: number, host = "127.0.0.1"): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = net.createServer((socket) => this.handle(socket, socket.remoteAddress ?? "127.0.0.1"));
      server.once("error", reject);
      // 소켓 고갈 방어 — 초과 연결은 즉시 끊는다(이미 붙은 세션은 살린다).
      server.maxConnections = MAX_LISTENER_CONNECTIONS;
      server.listen(port, host, () => {
        this.server = server;
        const addr = server.address();
        resolve(typeof addr === "object" && addr !== null ? addr.port : port);
      });
    });
  }

  /** unix 소켓 리슨(운영 — 신뢰된 로컬 배달). */
  listenUnix(path: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = net.createServer((socket) => this.handle(socket, "127.0.0.1"));
      server.once("error", reject);
      // unix 소켓도 같은 fd 풀을 쓴다 — 신뢰된 로컬 MDA라도 상한은 TCP 갈래와 같아야 한다.
      server.maxConnections = MAX_LISTENER_CONNECTIONS;
      server.listen(path, () => {
        this.server = server;
        resolve();
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) return resolve();
      for (const s of this.sockets) s.destroy(); // 열린 연결 강제 종료(안 하면 close 대기)
      this.sockets.clear();
      this.server.close((err) => (err ? reject(err) : resolve()));
      this.server = null;
    });
  }

  private handle(socket: net.Socket, clientIp: string): void {
    this.sockets.add(socket);
    socket.on("close", () => this.sockets.delete(socket));
    const engine = new LmtpEngine({ hostname: this.opts.hostname, clientIp, ...(this.opts.maxSizeBytes !== undefined ? { maxSizeBytes: this.opts.maxSizeBytes } : {}) });
    let chain: Promise<void> = Promise.resolve();
    const write = (text: string) => socket.write(text + "\r\n");

    const run = (actions: LmtpAction[]): void => {
      chain = chain.then(() => this.process(engine, actions, write, socket));
    };
    run(engine.greeting());
    socket.on("data", (data) => run(engine.feed(new Uint8Array(data))));
    /**
     * 유휴 타임아웃 — 다른 5개 프로토콜 어댑터와 같은 배선(`setTimeout` + `timeout` 이벤트).
     *
     * ★`socket.setTimeout(ms)`만으로는 아무 일도 일어나지 않는다. node는 `timeout` 이벤트를
     * 낼 뿐 소켓을 닫지 않으므로, 리스너를 함께 달아야 실제로 끊긴다.
     * 여기서 `end()`(destroy 아님)를 쓰는 이유는 421을 상대가 받고 끊게 하기 위해서다.
     */
    socket.setTimeout(this.opts.idleTimeoutMs ?? LMTP_IDLE_TIMEOUT_MS);
    socket.on("timeout", () => {
      if (socket.destroyed) return;
      write("421 4.4.2 Idle timeout, closing connection");
      socket.end();
    });
    socket.on("error", () => socket.destroy());
  }

  /** 액션을 순차 처리 — 비동기(verifyRcpt/deliver)는 await 후 결과를 엔진에 되먹여 재개. */
  private async process(engine: LmtpEngine, actions: LmtpAction[], write: (t: string) => void, socket: net.Socket): Promise<void> {
    for (const action of actions) {
      if (action.kind === "reply") {
        write(action.text);
      } else if (action.kind === "close") {
        socket.end();
      } else if (action.kind === "verifyRcpt") {
        let outcome;
        try {
          outcome = await this.opts.backend.verifyRecipient(action.rcpt);
        } catch {
          outcome = { ok: false as const, code: 451, enhanced: "4.3.0", message: "verify failed" };
        }
        await this.process(engine, engine.rcptResult(outcome), write, socket);
      } else if (action.kind === "deliver") {
        let results: LmtpDelivery[];
        try {
          results = await this.opts.backend.deliverLmtp(action.env);
        } catch {
          results = action.env.rcptTo.map((rcpt) => ({ rcpt, ok: false, code: 451, enhanced: "4.3.0", message: "delivery failed" }));
        }
        /**
         * 배달 기록. LMTP는 **수신자별로 결과가 갈리므로** 성공·실패 수를 함께 남긴다
         * (SMTP는 트랜잭션 하나에 결과 하나라 그 구분이 없다).
         *
         * `raw`는 넣지 않는다(크기만) — 넣으면 감사 로그가 메일 사본이 된다. 수신자 주소도
         * 개별로 넣지 않고 수만 남긴다: 한 트랜잭션에 수백 명이 올 수 있어 줄이 폭발한다.
         */
        const ok = results.filter((r) => r.ok).length;
        this.audit.record({
          ts: Date.now(),
          surface: AUDIT_SURFACE.lmtp,
          action: "deliver",
          // 한 명이라도 받았으면 `ok`, 전부 실패면 `denied`. 부분 실패는 detail의 수로 드러난다.
          outcome: ok > 0 ? AUDIT_OUTCOME.ok : AUDIT_OUTCOME.denied,
          ip: normalizeIp(action.env.clientIp),
          detail: {
            from: action.env.mailFrom,
            rcpts: results.length,
            delivered: ok,
            bytes: action.env.raw.byteLength,
            lhlo: action.env.lhloName,
          },
        });
        await this.process(engine, engine.deliverResult(results), write, socket);
      }
    }
  }
}
