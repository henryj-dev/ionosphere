/**
 * REST 경로 ↔ 명령 매핑 — **API가 자기 로직을 갖지 않기 위한 표.**
 *
 * 이 표가 있기 전에는 라우트마다 핸들러 메서드가 있었고 그 안에 SQL이 있었다. 같은 일을
 * CLI도 따로 했고(`add-domain` ↔ `createDomain`) 그래서 둘이 갈라졌다. 지금 API가 하는 일은
 * ① 인증·스코프 ② 경로에서 인자 뽑기 ③ 명령 호출 ④ 결과를 HTTP로 옮기기, 넷뿐이다.
 *
 * ★기존 REST 계약(경로·응답 형태)은 그대로 둔다. 이 리팩터링은 **내부 구조 변경**이고,
 * 외부에서 보이는 것이 바뀌면 admin-ui와 외부 사용처가 함께 깨진다.
 */

/** 경로에서 뽑은 값을 명령 인자 이름으로 옮기는 규칙. */
export interface RouteSpec {
  method: "GET" | "POST" | "DELETE";
  /** 정규식 — 캡처 그룹은 `params` 순서대로 명령 인자가 된다. */
  pattern: RegExp;
  /** 캡처 그룹 → 명령 인자 이름. */
  params: readonly string[];
  command: string;
  /**
   * 응답을 기존 계약 형태로 맞추는 변환. 없으면 `rows` 또는 `data`를 그대로 낸다.
   *
   * ★이 필드가 필요한 이유가 이 리팩터링의 유일한 마찰이다. 명령 계층은 `{rows}`/`{data}`라는
   * 한 가지 모양을 쓰는데, 기존 REST는 라우트마다 다른 모양을 약속해 뒀다(`[...]`, `{ok:true}`,
   * `{accountId}`). 외부 계약을 지키려면 어딘가에서 옮겨야 하고, 그 자리는 **HTTP 어댑터**다.
   */
  shape?: (result: { rows?: readonly Record<string, unknown>[]; data?: Record<string, unknown>; secret?: { value: string; label: string; hint?: string } }) => unknown;
}

/** 목록형: `rows`를 배열 그대로. */
const rowsOnly: RouteSpec["shape"] = (r) => r.rows ?? [];
/** 단일형: `data`를 객체 그대로. */
const dataOnly: RouteSpec["shape"] = (r) => r.data ?? {};

export const ROUTES: readonly RouteSpec[] = [
  // 테넌트
  { method: "POST", pattern: /^\/v1\/tenants$/, params: [], command: "tenant-create", shape: dataOnly },
  { method: "GET", pattern: /^\/v1\/tenants$/, params: [], command: "tenant-list", shape: rowsOnly },
  // API 키 — 발급 응답은 평문 키를 함께 낸다(저장은 해시뿐이라 이 응답이 유일한 노출 지점).
  {
    method: "POST",
    pattern: /^\/v1\/api-keys$/,
    params: [],
    command: "api-key-create",
    shape: (r) => ({ ...(r.data ?? {}), key: r.secret?.value ?? "" }),
  },
  { method: "GET", pattern: /^\/v1\/api-keys$/, params: [], command: "api-key-list", shape: rowsOnly },
  /**
   * `selfRevoked`는 **어댑터가 채운다**(server.ts). 명령 계층은 "누가 부르는지"를 모르기 때문이다 —
   * 지금 이 요청을 인증한 키와 폐기 대상이 같은지는 HTTP 인증 문맥에만 있는 사실이다.
   */
  { method: "DELETE", pattern: /^\/v1\/api-keys\/([^/]+)$/, params: ["id"], command: "api-key-revoke", shape: dataOnly },
  // 계정
  { method: "POST", pattern: /^\/v1\/accounts$/, params: [], command: "account-create", shape: dataOnly },
  { method: "GET", pattern: /^\/v1\/accounts$/, params: [], command: "account-list", shape: rowsOnly },
  { method: "DELETE", pattern: /^\/v1\/accounts\/([^/]+)$/, params: ["account"], command: "account-delete", shape: dataOnly },
  // 정지·재활성 — 새 라우트. POST를 쓰는 이유는 상태 전이라서다(멱등이지만 리소스 생성이 아니다).
  { method: "POST", pattern: /^\/v1\/accounts\/([^/]+)\/suspend$/, params: ["account"], command: "account-suspend", shape: dataOnly },
  { method: "POST", pattern: /^\/v1\/accounts\/([^/]+)\/activate$/, params: ["account"], command: "account-activate", shape: dataOnly },
  // 앱 비밀번호 — 발급 응답의 평문은 `password` 키로 유지(기존 계약).
  {
    method: "POST",
    pattern: /^\/v1\/accounts\/([^/]+)\/app-passwords$/,
    params: ["account"],
    command: "app-password-create",
    shape: (r) => ({ ...(r.data ?? {}), password: r.secret?.value ?? "" }),
  },
  { method: "GET", pattern: /^\/v1\/accounts\/([^/]+)\/app-passwords$/, params: ["account"], command: "app-password-list", shape: rowsOnly },
  // OAuth 토큰 — CLI에만 있던 것이 API에도 생긴다.
  {
    method: "POST",
    pattern: /^\/v1\/accounts\/([^/]+)\/oauth-tokens$/,
    params: ["account"],
    command: "oauth-token-create",
    shape: (r) => ({ ...(r.data ?? {}), token: r.secret?.value ?? "" }),
  },
  { method: "GET", pattern: /^\/v1\/accounts\/([^/]+)\/oauth-tokens$/, params: ["account"], command: "oauth-token-list", shape: rowsOnly },
  { method: "DELETE", pattern: /^\/v1\/credentials\/([^/]+)$/, params: ["credentialId"], command: "credential-revoke", shape: dataOnly },
  // 도메인
  {
    method: "POST",
    pattern: /^\/v1\/domains$/,
    params: [],
    command: "domain-add",
    // 기존 계약: { domainId, verifyToken, dnsInstructions }
    shape: (r) => {
      const d = r.data ?? {};
      return { domainId: d.domainId, verifyToken: d.verifyToken, dnsInstructions: d.dnsInstructions };
    },
  },
  { method: "GET", pattern: /^\/v1\/domains$/, params: [], command: "domain-list", shape: rowsOnly },
  { method: "POST", pattern: /^\/v1\/domains\/([^/]+)\/verify$/, params: ["domain"], command: "domain-verify", shape: dataOnly },
  { method: "POST", pattern: /^\/v1\/domains\/([^/]+)\/disable$/, params: ["domain"], command: "domain-disable", shape: dataOnly },
  { method: "POST", pattern: /^\/v1\/domains\/([^/]+)\/enable$/, params: ["domain"], command: "domain-enable", shape: dataOnly },
  { method: "DELETE", pattern: /^\/v1\/domains\/([^/]+)$/, params: ["domain"], command: "domain-release", shape: dataOnly },
  // 알리아스
  { method: "POST", pattern: /^\/v1\/aliases$/, params: [], command: "alias-add", shape: dataOnly },
  { method: "GET", pattern: /^\/v1\/aliases$/, params: [], command: "alias-list", shape: rowsOnly },
  { method: "DELETE", pattern: /^\/v1\/aliases\/([^/]+)$/, params: ["alias"], command: "alias-remove", shape: dataOnly },
  // 큐 — 재시도·취소가 새로 생긴다(이전엔 조회뿐이라 DB를 직접 만져야 했다).
  { method: "GET", pattern: /^\/v1\/queue$/, params: [], command: "queue-list", shape: rowsOnly },
  { method: "POST", pattern: /^\/v1\/queue\/retry$/, params: [], command: "queue-retry", shape: dataOnly },
  { method: "POST", pattern: /^\/v1\/queue\/([^/]+)\/retry$/, params: ["id"], command: "queue-retry", shape: dataOnly },
  { method: "POST", pattern: /^\/v1\/queue\/([^/]+)\/cancel$/, params: ["id"], command: "queue-cancel", shape: dataOnly },
  // 차단 목록
  { method: "GET", pattern: /^\/v1\/suppressions$/, params: [], command: "suppression-list", shape: rowsOnly },
  { method: "DELETE", pattern: /^\/v1\/suppressions\/([^/]+)$/, params: ["email"], command: "suppression-remove", shape: dataOnly },
  // 사용량
  { method: "GET", pattern: /^\/v1\/usage$/, params: [], command: "usage", shape: dataOnly },
  // 릴레이(스마트호스트) — CLI에만 있던 것이 API에도 생긴다.
  { method: "GET", pattern: /^\/v1\/smarthosts$/, params: [], command: "smarthost-list", shape: rowsOnly },
  { method: "POST", pattern: /^\/v1\/smarthosts$/, params: [], command: "smarthost-set", shape: dataOnly },
  { method: "DELETE", pattern: /^\/v1\/smarthosts$/, params: [], command: "smarthost-remove", shape: dataOnly },
  // TLS(서버 전역, root 전용)
  { method: "GET", pattern: /^\/v1\/tls$/, params: [], command: "tls-status", shape: dataOnly },
  { method: "POST", pattern: /^\/v1\/tls\/refresh$/, params: [], command: "tls-refresh", shape: dataOnly },
  { method: "POST", pattern: /^\/v1\/tls\/upload$/, params: [], command: "tls-upload", shape: dataOnly },
];

/** 경로·메서드에 맞는 라우트와 경로 인자를 찾는다. */
export function matchRoute(method: string, pathname: string): { route: RouteSpec; pathArgs: Record<string, string> } | null {
  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const m = route.pattern.exec(pathname);
    if (!m) continue;
    const pathArgs: Record<string, string> = {};
    route.params.forEach((name, i) => {
      // 경로 세그먼트는 인코딩돼 있다(이메일의 `@`·`.`). 여기서 한 번만 푼다.
      pathArgs[name] = decodeURIComponent(m[i + 1]!);
    });
    return { route, pathArgs };
  }
  return null;
}
