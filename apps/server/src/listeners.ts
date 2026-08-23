/**
 * 리스너 설정 — 서비스별 **바인딩 주소·포트·기동 여부**를 한 곳에서 정한다.
 *
 * 왜 필요한가: 지금까지 이 셋이 서로 다른 방식으로 정해졌다. 포트는 서비스마다 별도 env,
 * 기동 여부는 "포트가 지정됐는가"라는 부수효과, 바인딩 주소는 코드 안의 휴리스틱
 * (TLS 프론트가 있으면 루프백)이었다. 그래서 "관리 API를 사내 대역에 열고 싶다" 같은 요구를
 * env로 표현할 방법이 없었고, 코드를 고쳐야 했다.
 *
 * ⚠ **기본값은 바꾸지 않는다.** 명시하지 않은 서비스는 종전 동작 그대로다 —
 * 특히 루프백으로 묶여 있던 표면(metrics·TLS 프론트 뒤의 admin/jmap/autoconfig)이
 * 이 기능을 넣었다는 이유로 열리면 안 된다. 여는 것은 **눈에 보이는 선택**이어야 한다.
 */
import { isIP } from "node:net";

/**
 * 설정 가능한 서비스 목록.
 *
 * `as const` 객체 + 유니온인 이유(erasableSyntaxOnly 규약): 서비스를 하나 추가하면
 * 사용처가 **컴파일 에러로 드러난다**. 문자열로 두면 오타가 런타임까지 간다.
 * 값은 env 접미사다 — 자동 변환(camelCase→SNAKE)에 맡기면 `adminTls`→`ADMINTLS` 같은
 * 어긋남이 조용히 생긴다.
 */
export const LISTENER_ENV_SUFFIX = {
  smtp: "SMTP",
  submission: "SUBMISSION",
  smtps: "SMTPS",
  pop3: "POP3",
  pop3s: "POP3S",
  imap: "IMAP",
  imaps: "IMAPS",
  lmtp: "LMTP",
  manageSieve: "MANAGESIEVE",
  jmap: "JMAP",
  admin: "ADMIN",
  autoconfig: "AUTOCONFIG",
  httpsFront: "HTTPS_FRONT",
  httpRedirect: "HTTP_REDIRECT",
  metrics: "METRICS",
} as const;

/** 리스너 이름. */
export type ListenerName = keyof typeof LISTENER_ENV_SUFFIX;

/** 이름 목록(순회용) — 객체 키와 항상 일치한다. */
export const LISTENER_NAMES: readonly ListenerName[] = Object.keys(LISTENER_ENV_SUFFIX) as ListenerName[];

export interface ListenerConfig {
  /**
   * 기동 여부. 생략 시 "포트가 정해졌으면 기동"(종전 동작).
   * `false`면 포트가 있어도 기동하지 않는다 — 포트를 지우지 않고 잠시 끄는 용도.
   */
  enabled?: boolean;
  /**
   * 바인딩 주소. 생략 시 서비스별 기본값(대부분 전 인터페이스, 일부는 루프백).
   * `0.0.0.0`은 모든 IPv4, `::`는 모든 인터페이스, `127.0.0.1`은 루프백.
   */
  host?: string;
  /** 포트. 생략 시 기존 `IONOSPHERE_<X>_PORT`/옵션 값을 쓴다. */
  port?: number;
}

export type ListenerOverrides = Partial<Record<ListenerName, ListenerConfig>>;

/** 파싱 실패를 조용히 넘기지 않기 위한 오류 — env 오타로 리스너가 사라지면 안 된다. */
export class ListenerSpecError extends Error {}

const OFF_VALUES = new Set(["off", "false", "no", "0", "disabled"]);

/**
 * 리스너 사양 문자열을 해석한다.
 *
 * 받는 형태:
 *   `off` / `false` / `no` / `0`   → 기동 안 함
 *   `8080`                          → 포트만(주소는 기본값)
 *   `0.0.0.0:8080`                  → 주소 + 포트
 *   `127.0.0.1:`                    → 주소만(포트는 기본값)
 *   `[::]:8080` / `[::1]:`          → IPv6 리터럴
 *
 * 주소만 줄 때 콜론을 요구하는 이유: `0.0.0.0`과 `8080`을 형태만으로 구분할 수 없어서다.
 * 규칙을 "콜론이 있으면 주소가 앞에 온다"로 두면 사람이 읽고도 판단할 수 있다.
 */
export function parseListenerSpec(raw: string): ListenerConfig {
  const value = raw.trim();
  if (value === "") throw new ListenerSpecError("빈 값 — 끄려면 off, 포트를 주려면 숫자를 쓰십시오");
  if (OFF_VALUES.has(value.toLowerCase())) return { enabled: false };

  // IPv6 리터럴은 대괄호로 감싼다: [::]:8080 / [::1]:
  const v6 = /^\[([^\]]+)\](?::(\d*))?$/.exec(value);
  if (v6) return buildSpec(v6[1]!, v6[2]);

  const lastColon = value.lastIndexOf(":");
  if (lastColon === -1) {
    // 콜론 없음 → 포트만
    return buildSpec(undefined, value);
  }
  const host = value.slice(0, lastColon);
  const port = value.slice(lastColon + 1);
  if (host.includes(":")) {
    // 대괄호 없는 IPv6은 포트와 구분할 수 없다 — 명시적으로 거절한다(조용히 오해하지 않는다).
    throw new ListenerSpecError(`IPv6 주소는 대괄호로 감싸십시오: [${host}]:${port || ""}`);
  }
  return buildSpec(host === "" ? undefined : host, port);
}

/**
 * inet_aton 스타일 정수 표기 한 조각 — 10진(`0`)·8진(`0177`)·16진(`0x7f`).
 * getaddrinfo가 이 형태를 **IP 정수로 재해석**하는 것이 아래 가드의 이유다.
 */
const NUMERIC_ADDRESS_PART = /^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/;
/** LDH 라벨(RFC 1123 §2.1) — 하이픈으로 시작·끝나지 않고 63자 이하. */
const HOSTNAME_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/**
 * 바인딩 주소 문자열을 검증한다 — IP 리터럴이거나 호스트명 형태여야 한다.
 *
 * 왜 필요한가: `IONOSPHERE_LISTEN_ADMIN=0:8080`이 그대로 통과하면 node가 `0`을 정수 IP로
 * 재해석해 **0.0.0.0(전 세계 공개)에 바인딩**한다. 그런데 `0`은 이 파서에서 OFF 값이다 —
 * `0`은 "끔", `0:8080`은 "전면 개방"으로 **한 글자 차이에 의미가 정반대**가 된다.
 * 관리 API에서 이게 일어나면 root 토큰 표면이 통째로 열린다.
 *
 * 같은 재해석은 `2130706433`(10진)·`0x7f000001`(16진)·`192.168.1`(생략형)에도 걸리므로,
 * "점으로 나뉜 조각이 전부 숫자 표기"인 문자열은 isIP가 인정한 정규 표기가 아닌 한 거절한다.
 * 파싱 실패가 기동을 막는 기존 동작(fail closed)과 같은 규율이다 — 추측해서 열지 않는다.
 */
function assertBindHost(host: string): void {
  // IPv6 zone id(`fe80::1%eth0`)는 링크로컬 바인딩에 실제로 필요한데 isIP는 zone을 모른다.
  const percent = host.indexOf("%");
  const bare = percent === -1 ? host : host.slice(0, percent);
  if (isIP(bare) !== 0) return;

  // 후행 점(`example.com.`)은 FQDN 표기라 허용한다.
  const name = host.endsWith(".") ? host.slice(0, -1) : host;
  if (name === "" || name.length > 253) {
    throw new ListenerSpecError(`바인딩 주소 형식이 아닙니다: ${host}`);
  }
  const labels = name.split(".");
  if (labels.length <= 4 && labels.every((l) => NUMERIC_ADDRESS_PART.test(l))) {
    throw new ListenerSpecError(
      `정수 IP 표기는 받지 않습니다(0.0.0.0으로 조용히 뒤집힙니다): ${host} — 점 4개 표기를 쓰십시오`,
    );
  }
  if (!labels.every((l) => HOSTNAME_LABEL.test(l))) {
    throw new ListenerSpecError(`바인딩 주소가 IP도 호스트명도 아닙니다: ${host}`);
  }
}

function buildSpec(host: string | undefined, port: string | undefined): ListenerConfig {
  const spec: ListenerConfig = { enabled: true };
  // 가드는 **조립부**에 둔다 — v4/v6 두 파싱 갈래가 모두 여기로 모이므로 빠질 자리가 없다.
  // host === undefined는 "덮어쓰지 않음"이라 검증 대상이 아니다(`":8080"`이 기본 host를 보존한다).
  if (host !== undefined) {
    assertBindHost(host);
    spec.host = host;
  }
  if (port !== undefined && port !== "") {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 0 || n > 65535) {
      throw new ListenerSpecError(`포트가 0~65535 정수가 아닙니다: ${port}`);
    }
    spec.port = n;
  }
  return spec;
}

/**
 * `IONOSPHERE_LISTEN_<SERVICE>` 환경변수를 모아 오버라이드를 만든다.
 *
 * 예) `IONOSPHERE_LISTEN_ADMIN=0.0.0.0:8080`, `IONOSPHERE_LISTEN_METRICS=off`
 *
 * 파싱 실패는 **던진다**. 오타를 무시하면 "열었다고 생각한 포트가 안 열려 있거나,
 * 껐다고 생각한 포트가 열려 있는" 상태가 되는데 둘 다 조용하다.
 */
export function listenersFromEnv(env: Record<string, string | undefined> = process.env): ListenerOverrides {
  const out: ListenerOverrides = {};
  for (const name of LISTENER_NAMES) {
    const key = `IONOSPHERE_LISTEN_${LISTENER_ENV_SUFFIX[name]}`;
    const raw = env[key];
    if (raw === undefined) continue;
    try {
      out[name] = parseListenerSpec(raw);
    } catch (err) {
      throw new ListenerSpecError(`${key}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return out;
}

/** 리스너 하나의 최종 결정 — 조립층이 이 형태로만 판단하게 해서 갈래를 줄인다. */
export interface ResolvedListener {
  enabled: boolean;
  port: number;
  /** undefined면 노드 기본값(전 인터페이스). */
  host: string | undefined;
}

/**
 * 오버라이드 + 기존 값으로 최종 결정을 만든다.
 *
 * @param override  `IONOSPHERE_LISTEN_*`(또는 옵션)로 들어온 명시적 지정
 * @param legacyPort 기존 `IONOSPHERE_<X>_PORT`/옵션 포트. 없으면 기동하지 않는다는 뜻.
 * @param defaultHost 서비스별 기본 바인딩(루프백으로 묶여 있던 표면은 여기서 온다)
 */
export function resolveListener(
  override: ListenerConfig | undefined,
  legacyPort: number | undefined,
  defaultHost: string | undefined,
): ResolvedListener | undefined {
  const port = override?.port ?? legacyPort;
  // 포트가 어디에도 없으면 기동할 수 없다 — enabled:true만 주고 포트를 안 준 경우도 여기 걸린다.
  if (port === undefined) return undefined;
  const enabled = override?.enabled ?? true;
  if (!enabled) return undefined;
  return { enabled: true, port, host: override?.host ?? defaultHost };
}
