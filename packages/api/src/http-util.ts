/**
 * 관리 API·셀프서비스 HTTP 어댑터가 공유하는 작은 도구 — 에러 형태, JSON 응답, 바디 상한, 클라이언트 주소.
 *
 * 두 서버에 같은 바디 상한·파싱 규칙이 있어야 한다. 한쪽에만 상한이 있던 것이 과거 사고였다(JMAP만 상한이 있고
 * 관리 API에는 없었다) — 그래서 한 곳에 둔다.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { clientIpOf } from "@ionosphere/core";

/** 라우트 핸들러가 의도적으로 던지는 HTTP 상태 있는 에러 — 최상위 catch가 그대로 응답한다. */
export class HttpError extends Error {
  readonly status: number;
  /**
   * 기계가 읽는 사유 — 콘솔이 메시지 문자열이 아니라 이것으로 다음 행동을 고른다
   * (`mfa_required` → 등록 화면, `step_up` → TOTP 재입력 후 재시도, `csrf` → 다시 로그인).
   */
  readonly code: string | undefined;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", ...headers });
  res.end(payload);
}

/**
 * 인증 실패 스로틀 — 왜 필요한가: 관리 콘솔은 443의 `admin.` vhost로 네트워크에 열려 있다.
 * 앞단 방어가 두 겹(노출 정책 = 내부 인터페이스 착지만 허용, Host 화이트리스트)이지만,
 * 둘 다 설정이고 설정은 사람이 하는 일이다. 한 번 틀리면 정적 rootToken 하나가 유일한
 * 장벽으로 남는다.
 * 그 상황에서 대입 공격이 실용적이지 않으려면 실패 횟수 자체를 제한해야 한다(다층 방어).
 *
 * 구현은 @ionosphere/core가 소유한다 — 원래 여기 안에만 있어서 나머지 프로토콜에는 시도 제한이
 * 아예 없었다. 갈래마다 다시 만들면 한쪽이 빠지므로 정본을 하나로 둔다.
 */
export function clientIp(req: IncomingMessage): string {
  return clientIpOf(req.headers["x-forwarded-for"], req.socket.remoteAddress);
}

/**
 * 관리 API 요청 바디 상한.
 *
 * 가장 큰 정상 페이로드는 `/v1/tls/upload`의 인증서 체인 + 개인키(수 KB 수준)라 1MB면
 * 넉넉하다. 상한이 없으면 인증된 키 하나로 메모리를 고갈시킬 수 있었다 —
 * JMAP은 요청·업로드 모두 상한이 있는데(`jmap-server.ts`) 관리 API만 빠져 있었다.
 */
export const MAX_ADMIN_BODY_BYTES = 1024 * 1024;

/** 요청 바디를 JSON으로 읽는다 — 빈 바디는 undefined, 파싱 실패는 400(HttpError)로 정규화. */
export async function readBody(req: IncomingMessage): Promise<unknown> {
  /**
   * ★초과해도 **스트림은 끝까지 흘려보낸다.** 담기만 멈추면 메모리는 묶이고, 소켓은 건강하게
   * 유지된다. 다른 두 방법은 둘 다 실측에서 클라이언트를 매달리게 했다:
   *  · `req.destroy()`로 끊기 → 응답이 클라이언트에 도달하지 못한다
   *  · content-length를 보고 **읽기 전에** 413 응답 → 클라이언트는 아직 본문을 쓰는 중이라
   *    TCP 버퍼가 차고, 서버가 읽지 않으니 클라이언트는 응답을 읽을 차례가 오지 않는다(교착)
   * 대역폭은 클라이언트가 보낸 만큼 쓰지만, 인증된 표면이고 막아야 할 것은 메모리다.
   */
  const chunks: Buffer[] = [];
  let total = 0;
  let tooLarge = false;
  for await (const c of req) {
    const chunk = c as Buffer;
    total += chunk.length;
    if (total > MAX_ADMIN_BODY_BYTES) {
      if (!tooLarge) {
        tooLarge = true;
        chunks.length = 0; // 이미 담은 것도 버린다 — 어차피 거절이다
      }
      continue;
    }
    chunks.push(chunk);
  }
  if (tooLarge) throw new HttpError(413, `request body too large (max ${MAX_ADMIN_BODY_BYTES} bytes)`);
  if (chunks.length === 0) return undefined;
  const raw = Buffer.concat(chunks).toString("utf8");
  if (raw.trim() === "") return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, "invalid JSON body");
  }
}

export function asRecord(body: unknown): Record<string, unknown> {
  return body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
}
