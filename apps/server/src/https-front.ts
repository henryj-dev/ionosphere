/**
 * HTTPS 프론트(443 종단) — JMAP·autoconfig 등 평문 HTTP 서버 앞단에서 TLS를 종단하고
 * Host 헤더로 골라 localhost upstream으로 리버스 프록시한다. 자체완결(외부 프록시 불필요).
 *
 * 라우팅: Host **완전 일치** 화이트리스트. 목록에 없는 이름은 404 — 기본 upstream으로 흘리지 않는다.
 * upstream엔 원본 Host를 그대로 넘겨(autoconfig의 domainFromHost·JMAP baseUrl이 도메인을 봄)
 * X-Forwarded-Proto: https를 덧붙인다. 스트리밍(파이프)이라 JMAP SSE도 그대로 통과.
 *
 * 인증서 핫리로드는 proto-imap/smtp와 동일: node=setSecureContext, bun=리스너 재생성(실측).
 */
import { Agent, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import * as https from "node:https";
import { createSecureContext } from "node:tls";
import { hardenHttpListener, noopLogger, type Logger, trackListener, type ListenerShutdown } from "@ionosphere/core";
import type { TlsMaterial } from "@ionosphere/tls";
import { isPrivateLocalAddress } from "./internal-address.ts";

/**
 * 홉바이홉 헤더(RFC 9110 §7.6.1). 프록시는 **양방향** 모두에서 지워야 한다.
 *
 * 과거엔 요청 방향만 지우고 응답은 `ur.headers`를 통째로 베꼈다. 실측(2026-07-31)에서
 * upstream이 보낸 `Connection: close`·`Upgrade: h2c`·`Keep-Alive`가 클라이언트까지 그대로
 * 새어 나갔다 — 뒤가 앞단·클라이언트의 연결 수명을 좌우하게 되는 자리다.
 */
const HOP_BY_HOP: readonly string[] = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

/** `Connection: keep-alive, X-Secret`처럼 나열된 토큰들 — 이것도 홉바이홉이라 지워야 한다. */
function connectionTokens(value: string | string[] | undefined): string[] {
  const raw = Array.isArray(value) ? value.join(",") : (value ?? "");
  return raw
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length > 0);
}

/** rawHeaders(이름,값 교대 배열)에서 같은 이름의 값을 전부 뽑는다. 중복 탐지가 목적이라 원시 배열을 쓴다. */
function rawValues(rawHeaders: readonly string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if ((rawHeaders[i] ?? "").toLowerCase() === name) out.push(rawHeaders[i + 1] ?? "");
  }
  return out;
}

/**
 * 메시지 프레이밍이 모호하면 이유를, 정상이면 null을 돌려준다 (RFC 9112 §6.1).
 *
 * **왜 런타임 파서를 믿지 않고 우리가 또 보는가**: 같은 입력에 bun과 node의 판정이 실제로
 * 갈렸다(실측 2026-07-31). `Content-Length` 중복(값이 같을 때)은 bun 200 / node 400,
 * 거대 청크 크기 `FFFFFFFFFFFFFFFF`는 node 200 / bun 400이었다. 프레이밍 해석이 앞뒤로
 * 갈리는 것이 곧 request smuggling이므로, 런타임 차이에 방어를 맡기지 않고 여기서 닫는다.
 * 재해석하지 않고 **거부**하는 것이 RFC 권고이자 fail closed다.
 */
/**
 * upstream 연결을 **재사용하지 않는** 에이전트.
 *
 * ★이 한 줄이 실측으로 확인된 유일한 실제 스머글링을 닫는다. 클라이언트가 `Content-Length`를
 * 크게 선언하고 바디를 덜 보낸 채 끊으면, 앞단이 뒤로 보낸 요청은 "바디가 모자란" 상태로 남는다.
 * upstream이 바디를 다 읽기 전에 응답하면(401·404·413 즉답 — 흔하고 합법이다) 앞단의 http
 * 클라이언트는 교환이 끝난 줄 알고 **소켓을 풀에 돌려주고**, upstream은 남은 바디를 계속
 * 버리는 중이다. 그 소켓에 실린 다음 요청의 앞부분이 앞 요청의 바디로 먹힌다.
 * bun 실측(2026-07-31): 피해자의 요청이 upstream에 도달조차 못 했고 응답도 받지 못했다.
 *
 * 요청이 끝난 뒤 소켓을 끊는 것만으로 이 부류 전체가 성립하지 않는다 — 재사용이 없으면
 * 오염된 연결도 없다. 뒤는 전부 127.0.0.1이라 연결 비용이 사실상 없어 이 교환이 성립한다.
 * (요청 완료 뒤 destroy만으로는 부족했다: upstream이 즉답하면 우리가 끊기 **전에** 이미
 * 풀로 돌아가 재사용된다.)
 */
const noReuseAgent = new Agent({ keepAlive: false, maxSockets: Infinity });

function framingReason(req: IncomingMessage): string | null {
  const raw = req.rawHeaders;
  const te = rawValues(raw, "transfer-encoding");
  const cl = rawValues(raw, "content-length");
  // 둘 다 있으면 앞뒤가 서로 다른 쪽을 믿을 수 있다 — 재해석 금지, 즉시 거부.
  if (te.length > 0 && cl.length > 0) return "content-length와 transfer-encoding 동시 지정";
  if (te.length > 1) return "transfer-encoding 중복";
  const teValue = te[0];
  // 인식할 수 없는 값은 무시하지 말고 거부한다(`xchunked`·`chunked, identity` 류의 난독화).
  if (teValue !== undefined && teValue.trim().toLowerCase() !== "chunked") {
    return `해석할 수 없는 transfer-encoding: ${teValue}`;
  }
  if (cl.length > 1) return "content-length 중복";
  const clValue = cl[0];
  if (clValue !== undefined && !/^[0-9]+$/.test(clValue.trim())) return `content-length 구문 오류: ${clValue}`;
  // Host는 라우팅 판정의 입력이다. 두 개면 앞단과 뒤가 서로 다른 것을 고를 수 있고,
  // 실제로 bun은 마지막 값을, node는 첫 값을 골랐다(실측).
  if (rawValues(raw, "host").length > 1) return "host 중복";
  // origin-form만 받는다. 뒤는 전부 오리진 서버라 절대 URI를 넘기면 경로 판정이 갈린다.
  const target = req.url ?? "";
  if (!target.startsWith("/")) return `origin-form이 아닌 요청 타깃: ${target}`;
  return null;
}

/**
 * vhost의 노출 정책 — 이 이름을 **어느 인터페이스로 들어온 연결**에만 열 것인가.
 *
 * `as const` 객체 + 유니온인 이유는 CLAUDE.md 규약(erasableSyntaxOnly)이기도 하지만,
 * 오타가 조용히 새 값이 되는 것을 막기 위해서다 — 여기서 오타 하나가 접근 통제를 뚫는다.
 */
export const ROUTE_EXPOSURE = {
  /** 어느 인터페이스로 오든 받는다. MTA-STS·autoconfig·JMAP처럼 **공개여야 하는** 이름. */
  public: "public",
  /** 내부 인터페이스로 들어온 연결만 받는다. 관리 표면. */
  internal: "internal",
} as const;
export type RouteExposure = (typeof ROUTE_EXPOSURE)[keyof typeof ROUTE_EXPOSURE];

export interface HttpsFrontRoute {
  /**
   * 이 upstream이 받을 **정확한** Host 목록(소문자). 접두사가 아니라 완전 일치다.
   *
   * ★접두사에서 화이트리스트로 바꾼 이유(2026-08-07): 예전에는 `mta-sts.` 같은 접두사로
   * 골랐고 **어디에도 안 걸리는 이름은 기본 upstream(JMAP)으로 흘렀다.** 즉 아무 Host나
   * 붙여도 뭔가는 응답했다. 지금은 목록에 없는 이름은 404다 — 우리가 서빙하기로 **명시한**
   * 이름만 존재한다.
   *
   * ⚠ 멀티테넌트에서는 도메인마다 이름이 늘어난다. `mta-sts.<도메인>`은 호스팅하는 **모든**
   * 도메인에 대해 열려 있어야 하고, 빠지면 그 테넌트는 정책을 못 받는다(enforce면 수신 장애).
   * 테넌트를 추가할 때 이 목록도 함께 늘리는 것이 화이트리스트의 비용이다.
   */
  hosts: string[];
  /**
   * 이 이름을 공개할 것인가. **선택이 아니라 필수다.**
   *
   * ★기본값을 두지 않는 이유: 어느 쪽을 기본으로 해도 사고가 난다. 기본 public이면 관리
   * 표면이 조용히 인터넷에 열리고, 기본 internal이면 **MTA-STS 라우트가 조용히 막혀**
   * enforce 상태에서 수신이 통째로 죽는다. 어느 쪽도 기본값이 될 수 없는 값이라
   * 타입으로 결정을 강제한다 — 라우트를 추가하는 모든 자리가 컴파일 에러로 드러난다.
   *
   * ⚠ 판정은 **요청 시점**이라, 내부 전용 이름도 공개 쪽 연결에 인증서는 제시한 뒤 404를
   * 낸다(SNICallback이 소켓을 넘겨주지 않는다). 이름의 존재만 새는 정도이고, 포트를
   * 나누지 않는 한 피할 수 없다.
   */
  exposure: RouteExposure;
  /** upstream 로컬 포트. */
  port: number;
  /**
   * 이 upstream이 **실제로 바인딩된 주소**(미지정 시 upstreamHost 기본값).
   *
   * ★왜 라우트마다 두는가: upstream은 리스너별로 주소가 다를 수 있다
   * (`IONOSPHERE_LISTEN_AUTOCONFIG=10.0.101.12:`처럼 축마다 따로 지정된다).
   * 프론트가 `127.0.0.1`을 가정하면 그 리스너에는 아무도 없어 **502**가 된다 —
   * 라이브에서 autoconfig·autodiscover·MTA-STS가 전부 그렇게 죽어 있었다.
   */
  host?: string;
  /**
   * 이 라우트의 이름으로 올 때 제시할 **전용 인증서**(미지정 시 기본 자료).
   *
   * ★왜 라우트에 붙이는가: 이름과 인증서는 반드시 같이 바뀐다. 따로 두면 라우트만 추가하고
   * 인증서를 빠뜨려 그 이름이 **엉뚱한 인증서**를 제시하는 상태가 조용히 생긴다 — 브라우저는
   * 이름 불일치로 거부하지만 서버 로그에는 아무것도 남지 않아 원인을 짚기 어렵다.
   * (이 저장소가 반복해 겪은 "한쪽만 고쳐서 깨지는" 부류라 소유를 한 곳으로 묶는다.)
   */
  tls?: TlsMaterial;
}

/**
 * Host 헤더에서 포트를 떼고 소문자로 — 이름 판정의 **유일한 정규화**다.
 *
 * ★한 곳에 두는 이유: 라우팅·SNI·80 리다이렉트가 각자 정규화하면 규칙이 갈린다. 예전에
 * SNI만 다른 규칙을 쓰면 "인증서는 admin 것인데 프록시는 JMAP으로 간다"가 됐다.
 */
export function bareHost(host: string | undefined): string {
  return (host ?? "").replace(/:\d+$/, "").toLowerCase();
}

/**
 * Host 화이트리스트에서 라우트를 고른다 — 443 프록시·SNI·80 리다이렉트가 **같은 표**를 본다.
 *
 * 완전 일치다. 접두사 매칭이면 `admin.evil.example`이 `admin.` 라우트에 걸린다 —
 * 우리 도메인이 아닌데도 관리 upstream으로 향하는 이름이 생기는 셈이다.
 */
export function matchRouteByHost(routes: readonly HttpsFrontRoute[], host: string | undefined): HttpsFrontRoute | undefined {
  const bare = bareHost(host);
  if (!bare) return undefined;
  return routes.find((r) => r.hosts.includes(bare));
}

export interface HttpsFrontOptions {
  tls: TlsMaterial;
  /** Host 접두사 매칭 라우트(순서대로 평가). */
  routes: HttpsFrontRoute[];
  /** upstream 연결 호스트(기본 127.0.0.1). */
  upstreamHost?: string;
  /**
   * 로컬 주소가 "내부"인지 판정 — 기본은 사설·루프백 대역(`isPrivateLocalAddress`).
   *
   * 주입 가능한 이유는 두 가지다: ① 내부망이 공개 대역인 토폴로지가 있을 수 있고
   * ② **테스트가 거부 경로를 구동할 수 없다**. 테스트 기기의 주소는 전부 사설이라
   * 기본 판정으로는 "공개 인터페이스로 들어온 연결"을 만들 수 없다.
   */
  isInternalAddress?: (addr: string | undefined) => boolean;
  logger?: Logger;
}

export class HttpsFrontServer {
  private readonly opts: HttpsFrontOptions;
  private readonly log: Logger;
  private readonly upstreamHost: string;
  private readonly isInternal: (addr: string | undefined) => boolean;
  private currentTls: TlsMaterial;
  private server: https.Server | null = null;
  private shutdown: ListenerShutdown | null = null;
  private boundPort = 0;
  private boundHost: string | undefined = undefined;

  constructor(opts: HttpsFrontOptions) {
    this.opts = opts;
    this.log = (opts.logger ?? noopLogger).child({ component: "https-front" });
    this.upstreamHost = opts.upstreamHost ?? "127.0.0.1";
    this.isInternal = opts.isInternalAddress ?? isPrivateLocalAddress;
    this.currentTls = opts.tls;
  }

  /**
   *
   * 포트와 주소를 **함께** 돌려준다. 예전엔 포트만 골라 놓고 주소는 항상 `127.0.0.1`을 썼는데,
   * upstream이 다른 주소에 바인딩돼 있으면 그 조합에는 아무도 없어 502가 된다.
   */
  /**
   * Host → upstream. **화이트리스트에 없으면 undefined**(호출부가 404를 낸다).
   *
   * 예전에는 여기서 기본 upstream으로 흘려보냈다. 그래서 아무 Host나 붙여도 JMAP이 응답했고,
   * "우리가 서빙하는 이름"이라는 목록이 코드 어디에도 없었다.
   */
  private routeTarget(host: string | undefined): { port: number; host: string; exposure: RouteExposure } | undefined {
    const r = matchRouteByHost(this.opts.routes, host);
    return r ? { port: r.port, host: r.host ?? this.upstreamHost, exposure: r.exposure } : undefined;
  }

  /**
   * SNI 이름 → 그 이름 전용 자료. 없으면 undefined(기본 자료를 쓴다).
   *
   * 라우트 매칭과 **같은 규칙**(접두사·소문자·포트 제거)을 쓴다. 여기만 규칙이 다르면
   * "인증서는 admin 것인데 프록시는 JMAP으로 간다" 같은 어긋남이 생긴다.
   */
  private tlsForServername(servername: string): TlsMaterial | undefined {
    const r = matchRouteByHost(this.opts.routes, servername);
    return r?.tls;
  }

  private createServer(): https.Server {
    /**
     * 기본 자료는 그대로 두고 **전용 인증서를 가진 라우트가 있을 때만** SNI를 얹는다.
     *
     * ⚠ SNICallback이 없으면 443은 인증서 하나만 제시한다. mx/mta-sts/autoconfig가 한 인증서에
     * 들어 있고 admin은 별도 인증서(cert-api `mailer-admin`, CN=admin.ionosphere.test)라
     * 한 장으로는 둘 다 만족시킬 수 없다 — 한쪽을 고르면 다른 쪽이 이름 불일치로 깨진다.
     * MTA-STS 정책 서빙이 깨지면 enforce 모드에서 **수신이 막히므로** 기본 자료는 건드리지 않고
     * admin만 SNI로 갈라낸다(fail closed: SNI를 안 보내는 클라이언트는 기본 인증서를 받는다).
     */
    const hasPerRouteTls = this.opts.routes.some((r) => r.tls !== undefined);
    if (!hasPerRouteTls) {
      return https.createServer({ key: this.currentTls.key, cert: this.currentTls.cert }, (req, res) =>
        this.proxy(req, res),
      );
    }
    return https.createServer(
      {
        key: this.currentTls.key,
        cert: this.currentTls.cert,
        SNICallback: (servername, cb) => {
          const m = this.tlsForServername(servername);
          // 전용 자료가 없으면 null을 넘겨 **기본 컨텍스트**를 쓰게 한다. 여기서 에러를 주면
          // 이름을 모르는 클라이언트의 핸드셰이크가 통째로 실패한다(fail open이 아니라 fail broken).
          if (!m) {
            cb(null);
            return;
          }
          try {
            cb(null, createSecureContext({ key: m.key, cert: m.cert }));
          } catch (err) {
            // 컨텍스트 생성 실패(손상된 자료)가 프로세스를 죽이면 25·587·993이 함께 내려간다.
            this.log.error("SNI 컨텍스트 생성 실패 — 기본 인증서로 넘긴다", {
              servername,
              error: String(err),
            });
            cb(null);
          }
        },
      },
      (req, res) => this.proxy(req, res),
    );
  }

  /** 프레이밍이 모호한 연결은 재사용하지 않는다 — 남은 바이트가 다음 요청으로 읽히면 그것이 스머글링이다. */
  private reject(res: ServerResponse, status: number, body: string): void {
    /**
     * ★`content-length`를 **명시**한다. 없으면 node가 응답을 `transfer-encoding: chunked`로
     * 내보내는데, 이 함수는 애초에 **프레이밍이 모호해서** 거부하는 자리다 —
     * 거부 응답 자체가 또 다른 프레이밍을 얹으면 앞뒤가 경계를 다르게 볼 여지를 남긴다.
     * (실측: node에서 502에 `transfer-encoding: chunked`가 붙어 스머글링 방어 테스트가 잡았다.
     * bun에서는 붙지 않아 드러나지 않았다.)
     */
    if (!res.headersSent) {
      res.writeHead(status, {
        "content-type": "text/plain",
        "content-length": String(Buffer.byteLength(body)),
        connection: "close",
      });
    }
    res.end(body);
  }

  private proxy(req: IncomingMessage, res: ServerResponse): void {
    // res의 'error'에 리스너가 없으면 unhandled가 되어 프로세스가 죽는다(main.ts는
    // uncaughtException에서 종료한다). 443은 미인증 공개 표면이고 전 프로토콜이 한 프로세스에
    // 올라가 있어, 여기서 새는 에러 하나가 25·587·993을 함께 내린다.
    // 실측: upstream이 Content-Length보다 많이 보내면 ERR_STREAM_WRITE_AFTER_END로 실제로 죽었다.
    res.on("error", (err) => {
      this.log.error("클라이언트 응답 오류", { error: String(err) });
      res.destroy();
    });

    const bad = framingReason(req);
    if (bad !== null) {
      this.log.warn("요청 프레이밍 거부", { reason: bad });
      this.reject(res, 400, "bad request");
      return;
    }

    const target = this.routeTarget(req.headers.host);
    if (target === undefined) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }
    /**
     * 내부 전용 vhost에 **공개 인터페이스로** 들어온 요청은 거부한다.
     *
     * `localAddress`는 커널이 채우는 "연결이 착지한 우리 쪽 주소"다. `*:443` 한 리스너로도
     * 인터페이스를 구분할 수 있어(실측), 포트를 나누지 않고 이름별로 노출을 가를 수 있다.
     *
     * ★DNS로는 이걸 못 한다. 이름이 내부 IP로만 풀려도 공격자는 **공인 IP에 `Host:` 헤더를
     * 직접 실어** 보낼 수 있다 — DNS는 접근 통제가 아니다. 착지 주소는 위조할 수 없다.
     *
     * 403이 아니라 **404**인 이유: 403은 "여기 뭔가 있다"를 알려준다. 공개 쪽에서는 그 이름이
     * 아예 없는 것처럼 보이는 편이 낫다.
     */
    if (target.exposure === ROUTE_EXPOSURE.internal && !this.isInternal(req.socket.localAddress)) {
      this.log.warn("내부 전용 vhost에 공개 인터페이스로 접근 — 거부", {
        host: req.headers.host ?? "",
        localAddress: req.socket.localAddress ?? "unknown",
      });
      this.reject(res, 404, "not found");
      return;
    }
    // 홉바이홉 헤더는 제거하고 원본 Host는 유지한다.
    const headers = { ...req.headers };
    for (const name of connectionTokens(req.headers.connection)) delete headers[name];
    for (const name of HOP_BY_HOP) delete headers[name];
    headers["x-forwarded-proto"] = "https";
    headers["x-forwarded-host"] = req.headers.host ?? "";
    // 클라이언트 IP를 upstream에 전달한다. 이게 없으면 upstream 눈에는 모든 요청이 127.0.0.1로
    // 보여서 **IP 기반 방어(인증 실패 스로틀링)가 전역 카운터로 퇴화**한다 — 공격자 한 명이
    // 정상 사용자 전부를 잠글 수 있다는 뜻이라 방어가 아니라 자해가 된다.
    // 클라이언트가 보낸 값은 신뢰하지 않고 **덮어쓴다**(우리가 유일한 홉이므로 위조 여지를 없앤다).
    headers["x-forwarded-for"] = req.socket.remoteAddress ?? "";

    const upstream = httpRequest(
      { host: target.host, port: target.port, method: req.method, path: req.url, headers, agent: noReuseAgent },
      (ur) => {
        // upstream이 CL과 TE를 동시에 보내면 응답 프레이밍이 모호하다. 그대로 베끼면
        // **클라이언트가** desync된다 — bun 실측에서 둘 다 붙은 응답이 그대로 나갔고,
        // CL을 믿는 클라이언트와 TE를 믿는 클라이언트가 서로 다른 경계를 보게 된다.
        if (ur.headers["transfer-encoding"] !== undefined && ur.headers["content-length"] !== undefined) {
          this.log.error("upstream 응답 프레이밍 모호(CL+TE)", { port: target.port, host: target.host });
          ur.destroy();
          this.reject(res, 502, "bad gateway");
          return;
        }
        const respHeaders = { ...ur.headers };
        for (const name of connectionTokens(ur.headers.connection)) delete respHeaders[name];
        for (const name of HOP_BY_HOP) delete respHeaders[name];
        res.writeHead(ur.statusCode ?? 502, respHeaders);
        ur.pipe(res);
      },
    );
    upstream.on("error", (err) => {
      this.log.error("upstream 오류", { port: target.port, host: target.host, error: String(err) });
      // ★reject()로 통일한다. 예전엔 여기서 직접 writeHead를 불러 content-length도
      // connection:close도 없었고, node가 chunked를 붙여 **502 자체가 프레이밍을 얹었다**.
      this.reject(res, 502, "bad gateway");
    });
    // ★가장 위험한 자리였다: 클라이언트가 바디를 다 보내지 않고 끊으면 upstream 요청은
    //   "선언한 Content-Length보다 짧은" 상태로 남는다. 이 소켓이 keep-alive 풀로 돌아가면
    //   **다음 사용자의 요청 바이트가 앞 요청의 남은 바디로 먹힌다**. bun 실측에서 실제로
    //   재현됐다 — 피해자 요청이 upstream에 도달조차 못 했고 응답도 받지 못했다(node는
    //   클라이언트가 스스로 소켓을 버려 재현되지 않았다. 런타임에 맡길 수 없는 이유다).
    //   불완전하게 끝난 요청의 연결은 반드시 끊어 풀에서 몰아낸다.
    req.on("close", () => {
      if (!req.complete) upstream.destroy();
    });
    req.on("error", (err) => {
      this.log.warn("클라이언트 요청 오류", { error: String(err) });
      upstream.destroy();
    });
    req.pipe(upstream);
  }

  listen(port: number, host?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = this.createServer();
      const shutdown = trackListener(server); // listen 전에 붙여야 그 사이 연결을 놓치지 않는다
      // ★이 리스너가 가장 위험한 자리다: MTA-STS 정책 배포 때문에 443은 방화벽으로 막을 수 없는
      //   공개 표면인데 연결 수 상한도 타임아웃도 없었다. fd가 마르면 같은 프로세스의
      //   25·587·993이 함께 죽는다. 인증서 교체(reloadTls)는 이 listen을 다시 타므로 재적용된다.
      hardenHttpListener(server);
      const onError = (err: Error): void => reject(err);
      server.once("error", onError);
      server.listen(port, host, () => {
        server.removeListener("error", onError);
        this.server = server;
        this.shutdown = shutdown;
        this.boundHost = host;
        const addr = server.address();
        this.boundPort = typeof addr === "object" && addr !== null ? addr.port : port;
        resolve(this.boundPort);
      });
    });
  }

  /**
   * 인증서 무중단 교체. node=setSecureContext(진짜 무중단), bun=리스너 재생성(close→같은 포트 재listen).
   */
  async reloadTls(material: TlsMaterial): Promise<void> {
    this.currentTls = material;
    if (!this.server) return;
    if ("setSecureContext" in this.server) {
      this.server.setSecureContext({ key: material.key, cert: material.cert });
      return;
    }
    // ★추적된 close를 쓴다. 원시 server.close()는 붙어 있는 연결이 끝날 때까지 콜백이 오지 않아
    //   인증서 갱신이 그대로 멈춘다 — 종료 경로와 **같은 버그**다(listener-shutdown.ts).
    await this.close();
    await this.listen(this.boundPort, this.boundHost);
  }

  /**
   * SNI 라우트의 전용 인증서 교체 — 접두사가 겹치는 라우트를 전부 갱신한다.
   *
   * ★왜 별도 경로인가: `reloadTls`는 **기본 자료**만 바꾼다. 라우트 전용 인증서(admin)는
   * 기본 인증서와 만료일이 다른 별개 발급물이라, 기본 것만 갱신하면 admin 이름만 만료
   * 인증서를 계속 제시한다. 143·110이 재적재 목록에서 빠져 그 두 포트만 만료 인증서를
   * 제시했던 사고와 **같은 부류**다(app.ts tlsListeners 주석).
   *
   * SNICallback이 매 핸드셰이크마다 `opts.routes`를 다시 읽으므로 리스너 재생성이 필요 없다.
   * 대상이 없으면 false — 호출부가 "조용히 아무것도 안 됨"을 구분할 수 있게 한다.
   */
  reloadRouteTls(host: string, material: TlsMaterial): boolean {
    const bare = bareHost(host);
    let hit = false;
    for (const r of this.opts.routes) {
      if (r.tls && r.hosts.includes(bare)) {
        r.tls = material;
        hit = true;
      }
    }
    return hit;
  }

  /**
   * 리스너를 닫고 남은 연결을 끊는다.
   *
   * 이 리스너는 tls.Server라 메일 리스너들과 같은 부류다 — `server.close()`만 부르면 붙어 있는
   * 연결 하나가 종료 전체를 막는다(@ionosphere/core listener-shutdown.ts).
   */
  close(): Promise<void> {
    if (!this.shutdown) return Promise.resolve();
    const shutdown = this.shutdown;
    this.shutdown = null;
    this.server = null;
    return shutdown.close();
  }
}
