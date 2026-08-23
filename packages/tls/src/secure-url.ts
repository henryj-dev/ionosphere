/**
 * 원격에서 TLS 자재를 받아오는 URL의 스킴·오리진 게이트(url·acme 소스 공용).
 *
 * 왜 필요한가: 개인키와 `Bearer` 토큰을 `http://`로 받아오면 같은 세그먼트의 중간자가
 * 993/465/443/587 전량을 복호·사칭할 수 있다. 실제로 라이브 env가 `http://…/privkey.pem`이었고,
 * 스킴 검증이 코드 어디에도 없었다(2026-07-30 감사 H-1). 검증은 **기동 시점**에 해야 한다 —
 * 6시간 주기 재페치나 관리 API refresh에서 처음 드러나면 이미 평문으로 흘린 뒤다.
 *
 * 오리진 검사가 따로 있는 이유: ACME는 서버 응답 본문에 담긴 URL을 그대로 따라간다.
 * 검증이 없으면 침해된(혹은 운영자가 잘못 지정한) 디렉터리가 임의 내부 주소를 찍어주는
 * SSRF 프리미티브가 된다.
 */

/**
 * `http:` 예외를 허용할 호스트 = 루프백뿐.
 *
 * 이름은 `localhost`만 받는다. 다른 이름을 허용하면 DNS를 쥔 쪽이 "루프백인 척"할 수 있어
 * 예외가 곧 우회로가 된다.
 */
function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  if (h === "localhost" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

export interface TransportUrlCheck {
  url: URL;
  /**
   * 평문 `http:`로 개인키·토큰이 흐르는가. 참이면 **호출자가 반드시 경고를 남겨야 한다** —
   * 이 값을 무시하는 호출자가 생기지 않도록 아래 `insecureTransportWarning()`을 함께 쓴다.
   */
  insecure: boolean;
}

/**
 * TLS 자재를 받아올 URL의 스킴 판정.
 *
 * ★기동을 **막지 않는다**(운영 결정, 2026-07-31). 라이브 cert-api가 관리 VPC의
 * `http://10.253.192.10:8080`이라 거부하면 배포가 통째로 막힌다. 대신 **눈에 띄지 않을 수 없게**
 * 만든다 — 기동 시 1회, 그리고 **페치할 때마다 매번** 경고를 남긴다. 위험(감사 H-1: 같은
 * 세그먼트의 중간자가 개인키와 `Bearer` 토큰을 얻어 993/465/443/587 전량을 복호·사칭)은
 * 그대로이므로, 로그가 계속 쌓이는 것이 곧 "아직 안 고쳤다"는 표시가 되게 한다.
 *
 * 루프백은 경고하지 않는다 — 개발 환경에서 노이즈만 된다. 그 외 모든 `http:`는 매번 경고한다.
 * 형식이 URL이 아니면 그건 설정 오류이므로 여전히 던진다(fail closed 유지).
 */
export function checkTransportUrl(label: string, raw: string): TransportUrlCheck {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`${label}: URL 형식이 아니다 (${raw})`);
  }
  if (u.protocol === "https:") return { url: u, insecure: false };
  if (u.protocol === "http:") return { url: u, insecure: !isLoopbackHost(u.hostname) };
  throw new Error(`${label}: http(s)가 아니다 (${u.protocol}//${u.host})`);
}

/** 경고 문구 정본 — 기동 로그와 매 페치 로그가 같은 문장을 써야 grep이 한 번에 걸린다. */
export function insecureTransportWarning(label: string, url: URL): string {
  return (
    `${label}이(가) 평문 http: 다 (${url.protocol}//${url.host}) — ` +
    `TLS 개인키와 Bearer 토큰이 네트워크에 그대로 노출된다(감사 H-1). https:로 전환할 것.`
  );
}

/**
 * 서버가 응답 본문에 실어준 URL이 기준 오리진(스킴+호스트+포트)과 같은지 확인한다.
 * 다르면 따라가지 않는다 — 리다이렉트 유도로 내부망을 긁게 하는 SSRF를 막는다.
 */
export function assertSameOrigin(label: string, origin: string, raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`${label}: URL 형식이 아니다 (${raw})`);
  }
  if (u.origin !== origin) throw new Error(`${label}: 기준 오리진(${origin})과 다른 URL은 따라가지 않는다 (${u.origin})`);
  return u;
}
