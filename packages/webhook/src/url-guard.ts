/**
 * 웹훅 대상 주소 판정(SSRF) — **문자열 패턴이 아니라 숫자 범위로** 본다.
 *
 * 이 URL은 사용자가 정한 값이라 그대로 요청하면 내부 자원에 닿는다. 가장 아픈 표적은
 * 클라우드 메타데이터(169.254.169.254)다. 본문을 돌려주지 않아 블라인드지만, 내부 서비스에
 * **우리가 서명한 POST를 꽂는 것**만으로 충분히 위험하다.
 *
 * ## 왜 정규식 블록리스트를 버렸나 (2026-07 감사 M-14, 전부 실측 확인된 우회)
 *
 * 예전 구현은 `url.hostname`에 `/^127\./`·`/^\[?::1\]?$/` 같은 정규식을 댔고, 아래가 통과했다:
 *
 * - `http://localhost./` → 후행 점이 `$` 앵커를 깬다(DNS는 같은 이름으로 해석한다)
 * - `http://[::ffff:a9fe:a9fe]/` → **IPv4-매핑 IPv6로 쓴 169.254.169.254**. `[::ffff:127.0.0.1]`
 *   `[::ffff:10.0.0.1]`도 같은 방식으로 루프백·사설 대역을 통째로 우회했다
 * - `http://[::]/` → unspecified. 다수 스택에서 로컬호스트로 연결된다
 * - `http://metadata.google.internal/` → IP 표기조차 필요 없다
 *
 * 표기법마다 정규식을 늘리는 방식은 **다음 표기에서 또 뚫린다**. 그래서 `isIP()`로 주소 여부를
 * 판정하고 옥텟·그룹을 숫자로 비교한다. IPv4-매핑·IPv4-호환·6to4·NAT64처럼 IPv6 안에 IPv4가
 * 박히는 표기는 **하위 32비트를 뽑아 IPv4 규칙에 다시 태운다** — 표기가 늘어도 판정은 하나다.
 *
 * 반대로 십진·8진·16진 표기(`2130706433`·`0x7f.0.0.1`·`0177.0.0.1`·`127.1`)는 WHATWG URL이
 * `127.0.0.1`로 **정규화해 주므로** 여기서 따로 다룰 필요가 없다(감사 실측 확인). 파싱을 한 벌 더
 * 두면 "파서와 검사기가 같은 입력을 다르게 읽는" 결함이 생기므로 URL 파서의 결과만 믿는다.
 *
 * ## 이 파일만으로는 부족하다
 *
 * 여기는 **URL 문자열**만 본다. 이름이 사설 IP로 해석되는 DNS 리바인딩은 URL만 봐서는 절대
 * 막을 수 없다(`evil.com`의 A 레코드가 127.0.0.1이면 끝이다 — TOCTOU 경쟁조차 필요 없다).
 * 본체는 `http-client.ts`의 **연결 단계 검사**다: 해석된 주소를 `isBlockedAddress`로 거르고
 * 통과한 IP로 직접 연결(pinning)한다. 두 검사는 같은 판정 함수를 공유해야 하므로 같이 둔다.
 */
import { isIP } from "node:net";

/** 대상이 차단 대역으로 밝혀졌다 — 재시도해도 결과가 같으므로 워커가 즉시 failed로 닫는다. */
export class BlockedAddressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlockedAddressError";
  }
}

/**
 * 내부 자원으로 해석되는 호스트명 — IP 표기를 쓰지 않는 우회를 막는다.
 *
 * `metadata.google.internal`(GCP)·`instance-data`(AWS)처럼 **이름 자체가 메타데이터 서비스**인
 * 것들이 있다. 실제로는 링크로컬로 해석돼 연결 단계 검사에도 걸리지만, 여기서 먼저 막으면
 * 소켓을 열지 않고 끝난다.
 */
const BLOCKED_HOST_NAMES: readonly string[] = ["localhost", "metadata", "metadata.goog", "instance-data"];

/**
 * 접미사로 막는 이름 공간. `.internal`(GCP 메타데이터 `metadata.google.internal` 포함)·
 * `.local`(mDNS, RFC 6762)·`.home.arpa`(RFC 8375)는 전부 **내부 이름 공간**이라 공개 웹훅
 * 대상이 될 수 없다. `.localhost`는 RFC 6761이 루프백으로 예약했다.
 */
const BLOCKED_HOST_SUFFIXES: readonly string[] = [".localhost", ".internal", ".local", ".home.arpa"];

/** 점표기 IPv4를 옥텟 4개로. `isIP()`가 4를 반환한 문자열만 들어온다는 전제이나 스스로도 검증한다. */
function parseIpv4(text: string): [number, number, number, number] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    out.push(n);
  }
  const [a, b, c, d] = out;
  if (a === undefined || b === undefined || c === undefined || d === undefined) return null;
  return [a, b, c, d];
}

/** 16비트 그룹 두 개에 박힌 IPv4를 꺼낸다(IPv4-매핑·호환·6to4·NAT64 공통). */
function embeddedIpv4(hi: number, lo: number): [number, number, number, number] {
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
}

/**
 * IPv6 문자열을 16비트 그룹 8개로 펼친다. 실패하면 null(호출자는 **차단**으로 다룬다).
 *
 * `::` 압축과 말미 점표기(`::ffff:127.0.0.1`)를 모두 받는다 — `new URL()`은 전자로 정규화해
 * 주지만, 연결 단계에서 넘어오는 `socket.remoteAddress`·DNS 응답은 그렇지 않을 수 있다.
 */
function expandIpv6(raw: string): number[] | null {
  let text = raw;
  const lastColon = text.lastIndexOf(":");
  if (lastColon < 0) return null;
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    const octets = parseIpv4(tail);
    if (!octets) return null;
    const hi = (octets[0] << 8) | octets[1];
    const lo = (octets[2] << 8) | octets[3];
    text = `${text.slice(0, lastColon + 1)}${hi.toString(16)}:${lo.toString(16)}`;
  }

  const halves = text.split("::");
  if (halves.length > 2) return null;
  const [leftText = "", rightText] = halves;
  const toGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const out: number[] = [];
    for (const part of s.split(":")) {
      if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
      out.push(parseInt(part, 16));
    }
    return out;
  };
  const left = toGroups(leftText);
  const right = rightText === undefined ? [] : toGroups(rightText);
  if (!left || !right) return null;

  if (rightText === undefined) return left.length === 8 ? left : null;
  const fill = 8 - left.length - right.length;
  if (fill < 1) return null; // `::`는 최소 한 그룹을 대신한다
  return [...left, ...new Array<number>(fill).fill(0), ...right];
}

/**
 * IPv4 차단 대역. 공개 인터넷으로 라우팅되지 않는 것은 전부 막는다(fail closed).
 * 문서용 대역(192.0.2/24·198.51.100/24·203.0.113/24)은 라우팅되지 않지만 공격 표면이 아니라 둔다.
 */
function isBlockedIpv4(octets: [number, number, number, number]): boolean {
  const [a, b, c] = octets;
  if (a === 0) return true; // 0.0.0.0/8 — unspecified. `http://0/`은 다수 스택에서 로컬호스트다
  if (a === 10) return true; // 사설
  if (a === 127) return true; // 루프백
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 169 && b === 254) return true; // 링크로컬 — 클라우드 메타데이터 169.254.169.254가 여기다
  if (a === 172 && b >= 16 && b <= 31) return true; // 사설 172.16/12
  if (a === 192 && b === 0 && c === 0) return true; // IETF 프로토콜 할당 192.0.0.0/24
  if (a === 192 && b === 168) return true; // 사설
  if (a >= 224) return true; // 멀티캐스트 224/4 · 예약 240/4 · 브로드캐스트 255.255.255.255
  return false;
}

/** IPv6 차단 대역. IPv4가 박힌 표기는 전부 IPv4 규칙으로 되돌린다. */
function isBlockedIpv6(groups: readonly number[]): boolean {
  const [a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0] = groups;

  if (a === 0 && b === 0 && c === 0 && d === 0 && e === 0) {
    // ::ffff:0:0/96 — IPv4-매핑. 감사에서 실제로 뚫린 경로다(`[::ffff:a9fe:a9fe]` = 169.254.169.254)
    if (f === 0xffff) return isBlockedIpv4(embeddedIpv4(g, h));
    if (f === 0) {
      if (g === 0 && h <= 1) return true; // `::`(unspecified)와 `::1`(루프백)
      // ::/96 — 폐기된 IPv4-호환 표기(`[::7f00:1]`). 스택에 따라 여전히 연결된다
      return isBlockedIpv4(embeddedIpv4(g, h));
    }
  }
  // 64:ff9b::/96 — NAT64. 번역기가 있는 망에서 하위 32비트가 그대로 IPv4 목적지가 된다
  if (a === 0x0064 && b === 0xff9b && c === 0 && d === 0 && e === 0 && f === 0) return isBlockedIpv4(embeddedIpv4(g, h));
  // 2002::/16 — 6to4. 두 번째·세 번째 그룹이 IPv4 주소다
  if (a === 0x2002) return isBlockedIpv4(embeddedIpv4(b, c));

  if ((a & 0xfe00) === 0xfc00) return true; // ULA fc00::/7
  if ((a & 0xffc0) === 0xfe80) return true; // 링크로컬 fe80::/10
  if ((a & 0xff00) === 0xff00) return true; // 멀티캐스트 ff00::/8
  return false;
}

/**
 * 주소 문자열(대괄호 없는 IP 리터럴)이 차단 대역인가.
 *
 * **IP로 파싱되지 않으면 차단**한다 — 여기 들어오는 값은 이미 IP여야 하므로(URL의 리터럴,
 * DNS 응답, `socket.remoteAddress`) 파싱 실패는 예상 밖 상황이고 fail closed가 맞다.
 */
export function isBlockedAddress(address: string): boolean {
  const kind = isIP(address);
  if (kind === 4) {
    const octets = parseIpv4(address);
    return octets === null || isBlockedIpv4(octets);
  }
  if (kind === 6) {
    const groups = expandIpv6(address);
    return groups === null || isBlockedIpv6(groups);
  }
  return true;
}

/** 호스트명(IP가 아닌 것)이 내부 이름 공간인가. 후행 점은 이미 제거된 값이 들어온다. */
function isBlockedHostname(name: string): boolean {
  const lower = name.toLowerCase();
  if (BLOCKED_HOST_NAMES.includes(lower)) return true;
  return BLOCKED_HOST_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}

/**
 * 웹훅 대상 URL 검증 — 스킴과 호스트 표기를 본다.
 *
 * ⚠ 이것만으로는 DNS 리바인딩을 막지 못한다. 실제 방어는 `createGuardedFetch`의 연결 단계
 * 검사이며, 이 함수는 소켓을 열기 전에 끊어 내는 1차 관문이다(등록 시점 검증에도 쓸 수 있다).
 */
export function isAllowedWebhookUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return false;

  const host = url.hostname;
  if (host.startsWith("[")) {
    // 대괄호는 IPv6 리터럴의 표시다. 유효한 IPv6가 아니면(존 식별자 등) 판정 불가 → 차단
    if (!host.endsWith("]")) return false;
    const inner = host.slice(1, -1);
    return isIP(inner) === 6 && !isBlockedAddress(inner);
  }

  // 후행 점("localhost.")은 DNS 루트 표기일 뿐 같은 이름이다. 제거 후 비교한다
  const name = host.replace(/\.+$/, "");
  if (name === "") return false;
  if (isIP(name) !== 0) return !isBlockedAddress(name);
  return !isBlockedHostname(name);
}
