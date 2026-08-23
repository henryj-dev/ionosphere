/**
 * 80 → 443 리다이렉트 종단.
 *
 * 443 프론트가 서빙하는 이름으로 평문 80에 들어오면 같은 이름의 `https://`로 보낸다.
 * 프록시가 아니라 **리다이렉트만** 한다 — 80으로 들어온 요청을 뒤로 넘기면 그 순간
 * 평문 경로가 실제로 동작하게 되고, 그건 우리가 원하는 것의 정반대다.
 *
 * ★443 프론트와 **같은 라우트 표·같은 노출 정책**을 본다(`matchRouteByHost`).
 * 따로 두면 갈린다 — 80은 `admin.`을 리다이렉트하는데 443은 거부하는 식이 되면,
 * 리다이렉트 응답만으로 "그 이름이 존재한다"가 공개 인터페이스에 새어 나간다.
 *
 * ⚠ ACME http-01과 **같은 포트를 다툰다**. 챌린지 서버는 발급 순간에만 80을 열도록
 * 만들어져 있어서(`http-challenge.ts`), 여기서 80을 상시 점유하면 갱신이 EADDRINUSE로
 * 실패한다 — 그것도 **90일 뒤에** 드러난다. 그래서 조립층(main.ts)이 두 설정의 공존을
 * 기동 시점에 막는다.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { hardenHttpListener, noopLogger, trackListener, type ListenerShutdown, type Logger } from "@ionosphere/core";
import { bareHost, matchRouteByHost, ROUTE_EXPOSURE, type HttpsFrontRoute } from "./https-front.ts";
import { isPrivateLocalAddress } from "./internal-address.ts";

/**
 * Location에 실어도 되는 호스트인가.
 *
 * ★검증하는 이유는 두 가지다.
 * ① **헤더 주입**: Host 값은 클라이언트가 정한다. CR/LF나 제어문자가 그대로 `Location`에
 *    들어가면 응답 헤더를 쪼갤 수 있다. node가 대개 막지만, 막아주길 기대하지 않는다
 *    (이 저장소는 런타임 파서 판정이 갈리는 것을 이미 겪었다 — https-front.ts framingReason).
 * ② **엉뚱한 곳으로 보내기**: 문법이 깨진 값을 그대로 반사하면 리다이렉트 대상이 우리가
 *    의도한 이름이 아니게 된다. 판정 불가는 리다이렉트하지 않는다(fail closed).
 *
 * RFC 1123 호스트명 + IPv4만 받는다. IPv6 리터럴(`[::1]`)은 받지 않는다 — 메일 서비스
 * 이름으로 접속하는 정상 경로에 없고, 대괄호 표기를 다루면 검증 표면만 넓어진다.
 */
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

export interface HttpRedirectOptions {
  /** 443 프론트와 **같은 배열**을 넘긴다. 사본을 만들면 한쪽만 갱신되는 상태가 생긴다. */
  routes: readonly HttpsFrontRoute[];
  /** 로컬 주소가 "내부"인지 — 443과 같은 판정을 써야 한다. */
  isInternalAddress?: (addr: string | undefined) => boolean;
  logger?: Logger;
}

export class HttpRedirectServer {
  private readonly opts: HttpRedirectOptions;
  private readonly log: Logger;
  private readonly isInternal: (addr: string | undefined) => boolean;
  private shutdown: ListenerShutdown | null = null;

  constructor(opts: HttpRedirectOptions) {
    this.opts = opts;
    this.log = (opts.logger ?? noopLogger).child({ component: "http-redirect" });
    this.isInternal = opts.isInternalAddress ?? isPrivateLocalAddress;
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    // 443 프론트와 같은 이유로 리스너를 붙인다 — 여기서 새는 에러 하나가 25·587·993을 함께 내린다.
    res.on("error", () => res.destroy());

    const host = bareHost(req.headers.host);
    const target = req.url ?? "/";
    if (!HOSTNAME_RE.test(host) || !target.startsWith("/")) {
      this.reject(res, 400, "bad request");
      return;
    }

    /**
     * 내부 전용 이름은 공개 인터페이스에서 **리다이렉트조차 하지 않는다.**
     * 302를 돌려주면 그 자체가 "이 이름이 여기 있다"는 응답이 된다 — 443에서 404로 감추는
     * 것과 앞뒤가 맞아야 한다.
     */
    const route = matchRouteByHost(this.opts.routes, host);
    if (!route) {
      // 화이트리스트에 없는 이름 — 443이 404를 내는 것과 같아야 한다. 여기서 리다이렉트하면
      // "그 이름은 https로 가면 된다"는 안내가 되어, 없는 이름을 있는 것처럼 만든다.
      this.reject(res, 404, "not found");
      return;
    }
    if (route.exposure === ROUTE_EXPOSURE.internal && !this.isInternal(req.socket.localAddress)) {
      this.log.warn("내부 전용 이름에 공개 인터페이스로 접근 — 리다이렉트하지 않는다", {
        host,
        localAddress: req.socket.localAddress ?? "unknown",
      });
      this.reject(res, 404, "not found");
      return;
    }

    /**
     * **308**을 쓴다(RFC 9110 §15.4.9). 301은 역사적으로 POST를 GET으로 바꾸는 클라이언트가
     * 있어서, 메서드가 조용히 바뀌면 호출자는 "왜 본문이 사라졌지"를 추적하게 된다.
     * 308은 메서드와 본문을 보존한 채 다시 시도하게 한다.
     *
     * ⚠ 이미 평문으로 나간 것은 되돌릴 수 없다. 80에 본문을 실어 보냈다면 그건 이미 노출된
     * 것이고, 리다이렉트는 **다음 요청부터** 안전하게 만들 뿐이다. 그래서 이 종단은 받은 것을
     * 뒤로 넘기지 않는다 — 평문 경로가 동작하게 두면 클라이언트가 계속 그 길을 쓴다.
     */
    res.writeHead(308, {
      location: `https://${host}${target}`,
      "content-length": "0",
      connection: "close",
    });
    res.end();
  }

  /** 거부 응답도 프레이밍을 얹지 않는다(https-front.ts reject와 같은 규율). */
  private reject(res: ServerResponse, status: number, body: string): void {
    if (!res.headersSent) {
      res.writeHead(status, {
        "content-type": "text/plain; charset=utf-8",
        "content-length": String(Buffer.byteLength(body)),
        connection: "close",
      });
    }
    res.end(body);
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server: Server = createServer((req, res) => this.handle(req, res));
      const sd = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      hardenHttpListener(server); // 80은 공개 표면이다 — 연결 상한·slowloris 타임아웃 필수
      const onError = (err: Error): void => reject(err);
      server.once("error", onError);
      server.listen(port, host, () => {
        server.removeListener("error", onError);
        this.shutdown = sd;
        const addr = server.address();
        resolve(typeof addr === "object" && addr !== null ? addr.port : port);
      });
    });
  }

  close(): Promise<void> {
    if (!this.shutdown) return Promise.resolve();
    const sd = this.shutdown;
    this.shutdown = null;
    return sd.close();
  }
}
