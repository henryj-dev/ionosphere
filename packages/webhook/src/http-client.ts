/**
 * 웹훅 전송용 HTTP 클라이언트 — **연결 단계에서 SSRF를 막는다**.
 *
 * 예전에는 전역 `fetch`로 보냈다. URL 문자열만 검사하고 연결은 fetch가 알아서 하므로,
 * 이름이 사설 IP로 해석되는 **DNS 리바인딩 앞에서는 아무 방어도 없었다**(감사 M-14).
 * 판정이 애초에 IP를 보지 않으니 TOCTOU 경쟁조차 필요 없고 A 레코드 하나면 뚫렸다.
 *
 * 그래서 `node:http`/`node:https`로 내려와 **`lookup` 훅**을 잡는다. 훅에서 해석된 주소를
 * 전부 검사하고, 통과한 주소를 그대로 돌려주면 소켓은 **그 IP로만** 연결된다(pinning).
 * 검사한 주소와 연결하는 주소가 같은 값이므로 리바인딩과 TOCTOU가 함께 닫힌다.
 * (전역 `fetch`에는 이 훅을 꽂을 자리가 없다 — 런타임 중립 규약과 별개로 여기 내려온 이유다.
 *  bun·node 모두 훅을 `{all:true}`로 호출하는 것을 실측 확인했다.)
 *
 * 보존해야 하는 성질(감사가 "확인된 좋은 점"으로 지목한 것들 — 바꾸지 말 것):
 *  - **3xx `Location`을 절대 따라가지 않는다.** 반환 타입이 `{ status }`뿐이라 읽을 방법 자체가
 *    없다. 공개 엔드포인트가 `302 → http://169.254.169.254/`로 우회시키는 경로를 구조로 막는다.
 *  - **응답 본문을 아예 읽지 않는다.** 그래서 크기 상한이 필요 없다(읽기 시작하면 필요해진다).
 *  - 요청 전체에 타임아웃을 강제한다.
 */
import { request as httpRequest, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import { lookup as systemLookup } from "node:dns/promises";
import { BlockedAddressError, isAllowedWebhookUrl, isBlockedAddress } from "./url-guard.ts";

/**
 * 배달 함수 — 반환은 상태 코드뿐이다.
 *
 * ★이 타입을 넓히지 말 것. 헤더를 돌려주는 순간 `Location`을 따라가는 코드가 쓰일 수 있고,
 * 본문을 돌려주면 크기 상한과 블라인드 SSRF 오라클 문제가 새로 생긴다.
 */
export type FetchFn = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{ status: number }>;

/** 이름 해석기 — 주입식이라 테스트가 실제 DNS를 때리지 않는다. */
export type ResolveHostFn = (hostname: string) => Promise<readonly { address: string; family: number }[]>;

/** `node:http`가 요구하는 lookup 훅의 형태(@types/node가 export하지 않아 옵션에서 끌어온다). */
type NodeLookup = NonNullable<RequestOptions["lookup"]>;

export interface GuardedFetchOptions {
  /** 요청 전체 타임아웃(ms). 기본 10초. */
  timeoutMs?: number;
  /** 이름 해석기(테스트 주입용). 기본은 OS 리졸버. */
  resolveHost?: ResolveHostFn;
}

const DEFAULT_TIMEOUT_MS = 10_000;

const resolveViaSystem: ResolveHostFn = async (hostname) => {
  // verbatim: OS가 정렬을 바꾸지 않게 둔다 — 어차피 전부 검사하므로 순서에 의존하지 않는다
  const entries = await systemLookup(hostname, { all: true, verbatim: true });
  return entries.map((e) => ({ address: e.address, family: e.family }));
};

/**
 * 해석 결과를 검사하는 `lookup` 훅.
 *
 * ★하나라도 차단 대역이면 **전부** 거부한다. 남은 공개 주소로 연결해 주면 공격자는 공개 A와
 * 사설 A를 한 응답에 섞어 넣어 통과시킬 수 있고, 그 다음 조회에서 순서만 바꾸면 된다.
 */
export function createGuardedLookup(resolveHost: ResolveHostFn): NodeLookup {
  return (hostname, options, callback) => {
    void resolveHost(hostname).then(
      (entries) => {
        const blocked = entries.find((e) => isBlockedAddress(e.address));
        if (blocked) {
          callback(new BlockedAddressError(`blocked url (${hostname} resolved to ${blocked.address})`), "");
          return;
        }
        const family = options.family === 4 || options.family === "IPv4" ? 4 : options.family === 6 || options.family === "IPv6" ? 6 : 0;
        const usable = family === 0 ? entries : entries.filter((e) => e.family === family);
        const first = usable[0];
        if (!first) {
          const err: NodeJS.ErrnoException = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
          err.code = "ENOTFOUND";
          callback(err, "");
          return;
        }
        // all=true는 Happy Eyeballs(autoSelectFamily) 경로다. 검사를 통과한 주소만 넘긴다
        if (options.all === true) callback(null, usable.map((e) => ({ address: e.address, family: e.family })));
        else callback(null, first.address, first.family);
      },
      (err: unknown) => callback(err instanceof Error ? err : new Error(String(err)), ""),
    );
  };
}

export interface SendRequestOptions {
  timeoutMs: number;
  lookup?: NodeLookup;
  /** 연결된 원격 주소 재검증. false를 돌려주면 즉시 끊는다. */
  allowRemote?: (address: string | undefined) => boolean;
}

/**
 * 한 번의 POST — 리다이렉트 없음, 본문 미독, 전체 타임아웃.
 *
 * ⚠ 가드는 걸지 않는다(`lookup`·`allowRemote`를 받을 뿐이다). 패키지 밖으로 내보내지 않는 이유이며,
 * 실사용 경로는 반드시 `createGuardedFetch`를 거쳐야 한다.
 */
export function sendRequest(rawUrl: string, init: { method: string; headers: Record<string, string>; body: string }, opts: SendRequestOptions): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      reject(new Error("invalid url"));
      return;
    }
    const secure = url.protocol === "https:";
    if (!secure && url.protocol !== "http:") {
      reject(new Error(`unsupported scheme ${url.protocol}`));
      return;
    }

    let timer: ReturnType<typeof setTimeout> | undefined;
    let settled = false;
    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      fn();
    };

    // Host 헤더는 대괄호·포트를 그대로 쓰고(url.host), 연결에는 대괄호를 벗긴 값을 쓴다
    const hostname = url.hostname.startsWith("[") && url.hostname.endsWith("]") ? url.hostname.slice(1, -1) : url.hostname;
    const options: RequestOptions = {
      method: init.method,
      hostname,
      port: url.port === "" ? (secure ? 443 : 80) : Number(url.port),
      path: `${url.pathname}${url.search}`,
      headers: { ...init.headers, host: url.host },
      /**
       * ★소켓 풀을 쓰지 않는다. 재사용된 연결은 **이번 요청의 lookup 검사를 거치지 않은** 소켓이라
       * 핀 고정이 무의미해진다. 웹훅은 저빈도라 재사용 이득도 없다.
       */
      agent: false,
      ...(opts.lookup ? { lookup: opts.lookup } : {}),
    };

    const req = (secure ? httpsRequest : httpRequest)(options);
    timer = setTimeout(() => {
      settle(() => {
        req.destroy();
        reject(new Error(`timeout after ${opts.timeoutMs}ms`));
      });
    }, opts.timeoutMs);
    // 소켓이 이벤트 루프를 잡고 있으므로 타이머까지 ref할 필요가 없다(정상 종료를 늦추지 않는다)
    timer.unref?.();

    const allowRemote = opts.allowRemote;
    if (allowRemote) {
      /**
       * 연결 후 재검증(백스톱) — **node 전용이다**.
       *
       * 방어의 본체는 위의 `lookup` 훅이고 그쪽은 양 런타임에서 동작한다(실측: bun·node 모두
       * 훅을 `{all:true}`로 한 번 호출한다). 여기는 훅을 타지 않는 경로(IP 리터럴 직결 등)까지
       * 덮으려는 장치인데, **bun의 클라이언트 소켓은 `connect`를 emit하지 않고 `remoteAddress`도
       * 노출하지 않아**(실측) bun에서는 조용히 아무 일도 하지 않는다. 그래서 이 검사에 기대지
       * 않도록 IP 리터럴은 `isAllowedWebhookUrl`이 소켓을 열기 전에 이미 끊는다 — 여기 없어도
       * 뚫리지 않는다. node에서는 남겨 두는 편이 이득이라 지운다기보다 한계를 적어 둔다.
       */
      req.on("socket", (socket) => {
        const verify = (): void => {
          if (!allowRemote(socket.remoteAddress)) req.destroy(new BlockedAddressError(`blocked url (connected to ${socket.remoteAddress ?? "unknown"})`));
        };
        if (socket.remoteAddress !== undefined) verify();
        else {
          socket.once("connect", verify);
          socket.once("secureConnect", verify); // TLS 경로
        }
      });
    }

    req.on("response", (res) => {
      const status = res.statusCode ?? 0;
      res.destroy(); // 본문을 읽지 않는다 — 소켓만 회수한다
      settle(() => resolve({ status }));
    });
    req.on("error", (err) => settle(() => reject(err)));
    req.end(init.body);
  });
}

/**
 * 실사용 배달 함수 — URL 검사 + 해석 주소 검사 + 핀 고정 연결.
 *
 * URL을 배달 시점에 **다시** 검사한다. 등록 시점 검증만 믿으면 등록 이후에 규칙이 바뀌거나
 * 다른 경로로 행이 들어왔을 때 그대로 나간다(fail closed).
 */
export function createGuardedFetch(opts: GuardedFetchOptions = {}): FetchFn {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const lookup = createGuardedLookup(opts.resolveHost ?? resolveViaSystem);
  return async (url, init) => {
    if (!isAllowedWebhookUrl(url)) throw new BlockedAddressError("blocked url (private/loopback/invalid)");
    return await sendRequest(url, init, {
      timeoutMs,
      lookup,
      allowRemote: (address) => address !== undefined && !isBlockedAddress(address),
    });
  };
}
