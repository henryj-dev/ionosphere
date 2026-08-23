/**
 * `Received:` 트레이스 헤더 조립 (RFC 5321 §4.4, RFC 3848).
 *
 * **왜 core가 소유하나**: 수신(SMTP 25)·LMTP·제출(587/465) 세 갈래가 각자 조립하면 형식이
 * 갈라지고, 그러면 이 헤더를 세는 루프 가드가 한쪽만 맞게 된다. 같이 바뀌는 것은 같이 둔다.
 *
 * ⚠ **이 함수는 신뢰할 수 없는 입력을 헤더에 넣는다.** heloName은 상대가 EHLO로 주는 값이라
 * `EHLO foo\r\nBcc: victim@x` 같은 입력이 **헤더를 새로 만들 수 있다**(이 저장소는 봉투 주소에서
 * 같은 부류를 이미 겪었다 — mta/envelope.ts). 그래서 가드를 **조립 함수 안에** 두고 호출자가
 * 우회할 수 없게 한다. 위반한 값은 통째로 버린다(형식을 깨느니 정보를 덜 적는다).
 */

/** RFC 3848 전송 방식. `with` 절의 기반이 된다. */
export type ReceivedTransport = "esmtp" | "lmtp";

export interface ReceivedInfo {
  transport: ReceivedTransport;
  /** 상대가 EHLO/LHLO로 준 이름. **외부 입력**. */
  heloName?: string | undefined;
  /** TCP 연결에서 얻은 출발지 IP — RFC 5321 §4.4가 넣으라는(SHOULD) 값. */
  clientIp?: string | undefined;
  /** 우리 호스트명(by 절). */
  by: string;
  /** 추적용 식별자(ULID). */
  id?: string | undefined;
  /**
   * 수신자 — **정확히 1명일 때만** 넘긴다.
   *
   * RFC 5321 §4.4: "If the FOR clause appears, it MUST contain exactly one <path>".
   * §7.6은 이유까지 적어 뒀다 — 여러 명일 때 적으면 **BCC 수신자의 신원이 노출된다**.
   */
  forRecipient?: string | undefined;
  /** TLS 세션 정보. 있으면 with 절이 ESMTPS 계열이 되고 (version=… cipher=…)가 붙는다. */
  tls?: { protocol?: string | undefined; cipher?: string | undefined } | undefined;
  /** SASL 인증된 세션인가(제출 경로). with 절에 A가 붙는다. */
  authenticated: boolean;
  /** 시각. 주입식 — 테스트 결정성. */
  date: Date;
}

/**
 * 헤더에 넣어도 안전한 값만 통과시킨다. 아니면 undefined.
 *
 * Received와 Received-SPF가 **같은 가드를 쓴다**. 두 헤더 모두 EHLO 이름·클라이언트 IP·봉투
 * 주소처럼 상대가 정한 값을 담기 때문이다. 가드가 복제되면 한쪽만 고쳐져 조용히 갈라진다.
 *
 * CR/LF는 헤더 주입의 본체고, NUL과 나머지 제어문자는 파서·툴체인을 깨뜨린다.
 * 길이 상한은 한 값이 헤더 전체를 밀어내지 못하게 하는 것(RFC 5322 998옥텟 줄 상한 방어).
 */
export function headerSafeToken(value: string | undefined, maxLen = 255): string | undefined {
  if (value === undefined) return undefined;
  const v = value.trim();
  if (v.length === 0 || v.length > maxLen) return undefined;
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    // 제어문자(0x00–0x1F)·DEL(0x7F) 전부 거부 — CR/LF만 막으면 NUL이 남는다
    if (c < 0x20 || c === 0x7f) return undefined;
  }
  // 괄호는 Received/Received-SPF의 주석 구문을 닫아 버린다
  if (v.includes("(") || v.includes(")")) return undefined;
  // 따옴표·역슬래시는 quoted-string을 깨뜨린다(Received-SPF의 envelope-from이 그 형태다).
  // 이스케이프해서 살리는 대신 버린다 — 무엇이 남는지 추론하기 쉬운 쪽이 낫다.
  if (v.includes('"') || v.includes("\\")) return undefined;
  return v;
}

/**
 * RFC 3848 `with` 키워드.
 *
 * 조합을 호출자가 문자열로 만들지 않게 하는 이유: ESMTPAS 같은 없는 값이 조용히 나가면
 * 수신측 파서가 홉을 못 읽는다. 플래그에서 유도해 잘못된 조합 자체를 만들 수 없게 한다.
 */
function withKeyword(transport: ReceivedTransport, tls: boolean, authenticated: boolean): string {
  const base = transport === "lmtp" ? "LMTP" : "ESMTP";
  return base + (tls ? "S" : "") + (authenticated ? "A" : "");
}

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] as const;

function pad2(n: number): string {
  return n < 10 ? "0" + String(n) : String(n);
}

/**
 * RFC 5322 date-time (`Mon, 28 Jul 2026 06:12:03 +0000`).
 *
 * 저장소에 포매터가 없어 새로 쓴다(`toISOString`은 RFC 5322 형식이 아니다).
 * RFC 5321 §4.4가 "Local time (with an offset) SHOULD be used rather than UT"라 해서
 * **로컬 시각 + 오프셋**으로 낸다 — 서버가 UTC면 자연히 +0000이 된다.
 */
export function rfc5322Date(d: Date): string {
  const offsetMin = -d.getTimezoneOffset(); // 동쪽이 양수
  const sign = offsetMin < 0 ? "-" : "+";
  const abs = Math.abs(offsetMin);
  const day = DAYS[d.getDay()]!;
  const month = MONTHS[d.getMonth()]!;
  return (
    `${day}, ${d.getDate()} ${month} ${d.getFullYear()} ` +
    `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())} ` +
    `${sign}${pad2(Math.floor(abs / 60))}${pad2(abs % 60)}`
  );
}

/**
 * `Received:` 헤더 한 줄(폴딩 포함, 끝에 CRLF 없음)을 만든다.
 *
 * 형식(RFC 5321 §4.4):
 *   Received: from <helo> ([<ip>]) by <by> with <keyword> id <id>
 *           (version=<tls> cipher=<cipher>) for <rcpt>; <date>
 *
 * from 절은 RFC상 SMTP 환경에서 MUST지만 넣을 값이 하나도 안전하지 않을 수 있다
 * (heloName·clientIp 둘 다 가드에 걸리는 경우). 그때는 from을 통째로 생략한다 —
 * 형식이 깨진 헤더보다 절이 빠진 헤더가 낫다. 그런 입력은 어차피 공격이다.
 */
export function buildReceivedHeader(info: ReceivedInfo): string {
  const helo = headerSafeToken(info.heloName);
  const ip = headerSafeToken(info.clientIp, 64);
  const by = headerSafeToken(info.by) ?? "localhost";
  const id = headerSafeToken(info.id, 64);
  const rcpt = headerSafeToken(info.forRecipient, 320);
  const tlsVersion = headerSafeToken(info.tls?.protocol, 32);
  const tlsCipher = headerSafeToken(info.tls?.cipher, 64);

  const parts: string[] = [];
  // from — helo와 IP 중 있는 것을 쓴다. IP는 주소 리터럴로 감싼다(RFC 5321 Extended-Domain).
  if (helo && ip) parts.push(`from ${helo} ([${ip}])`);
  else if (helo) parts.push(`from ${helo}`);
  else if (ip) parts.push(`from [${ip}]`);

  parts.push(`by ${by}`);
  parts.push(`with ${withKeyword(info.transport, info.tls !== undefined, info.authenticated)}`);
  if (id) parts.push(`id ${id}`);
  if (tlsVersion || tlsCipher) {
    const bits = [tlsVersion ? `version=${tlsVersion}` : "", tlsCipher ? `cipher=${tlsCipher}` : ""].filter(Boolean);
    parts.push(`(${bits.join(" ")})`);
  }
  if (rcpt) parts.push(`for <${rcpt}>`);

  // 긴 줄은 접는다(RFC 5322 998옥텟). 폴딩은 CRLF + WSP — 이어지는 줄은 탭으로 시작한다.
  return `Received: ${parts.join("\r\n\t")};\r\n\t${rfc5322Date(info.date)}`;
}
