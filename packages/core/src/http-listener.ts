/**
 * HTTP 표면 공통 하드닝 — 연결 수 상한과 slowloris 타임아웃을 한 번에 건다.
 *
 * **왜 한 곳에 두는가**(2026-07-30 감사 L-3): 메일 리스너 6종은 각자 `MAX_LISTENER_CONNECTIONS`를
 * 걸고 있었는데 HTTP 리스너 4종(443 프론트·관리 API·autoconfig·metrics)에는 **연결 수 상한도
 * 타임아웃도 하나도 없었다**. 리스너마다 손으로 세 줄을 반복하는 구조였기 때문이다 —
 * 새로 추가되는 HTTP 표면은 앞으로도 조용히 빠진다. 손잡이를 하나로 두면 빠뜨릴 자리가 없다.
 *
 * `trackListener`(정상 종료)와 짝을 이룬다: 저쪽은 "닫을 때 남은 연결을 끊는다",
 * 이쪽은 "열려 있는 동안 연결이 무한히 쌓이지 않게 한다".
 */
import { HTTP_HEADERS_TIMEOUT_MS, HTTP_REQUEST_TIMEOUT_MS, MAX_LISTENER_CONNECTIONS } from "./limits.ts";

/**
 * 하드닝 대상 — `node:http`와 `node:https` 서버를 함께 받기 위한 구조 타입.
 *
 * 타임아웃 두 개를 **선택 필드**로 받는 이유: @types/node의 `https.Server`는 `tls.Server`만
 * 상속해 `headersTimeout`·`requestTimeout` 선언이 없다. 런타임에는 둘 다 있고(node의 https
 * 생성자가 초기화한다. bun 1.3에서도 대입·조회 확인) 값도 그대로 먹는데, 타입 선언만 빠진
 * 자리다. 여기서 선택 필드로 흡수해 호출부마다 캐스팅을 뿌리지 않는다.
 */
export interface HardenableHttpServer {
  maxConnections: number;
  headersTimeout?: number;
  requestTimeout?: number;
}

/**
 * HTTP/HTTPS 리스너에 연결 수 상한과 요청 타임아웃을 적용한다.
 *
 * `listen()` **전에** 부르는 것이 안전하다 — 그 사이에 붙은 연결에도 상한이 걸린다.
 */
export function hardenHttpListener(server: HardenableHttpServer): void {
  // 소켓 고갈 방어 — 초과 연결은 즉시 끊는다(이미 붙은 세션은 살린다).
  server.maxConnections = MAX_LISTENER_CONNECTIONS;
  server.headersTimeout = HTTP_HEADERS_TIMEOUT_MS;
  server.requestTimeout = HTTP_REQUEST_TIMEOUT_MS;
}
