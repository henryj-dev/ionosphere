/**
 * `date` / `currentdate`(RFC 5260)의 **날짜 조각 추출** — 순수 함수, I/O 0.
 *
 * ★모든 계산을 UTC 기준 정수 산술로 한다. `Date`의 로컬 시간대 메서드(`getHours()` 등)를
 * 쓰면 **서버의 TZ 설정에 따라 스크립트가 다르게 동작한다** — 같은 메일이 서버를 옮기면
 * 다른 메일함으로 간다는 뜻이라, 재현되지 않는 종류의 사고가 된다.
 */

/** RFC 5260 §4가 정의한 date-part 이름들. */
export const DATE_PARTS = [
  "year",
  "month",
  "day",
  "date",
  "julian",
  "hour",
  "minute",
  "second",
  "time",
  "iso8601",
  "std11",
  "zone",
  "weekday",
] as const;
export type DatePart = (typeof DATE_PARTS)[number];

export function isDatePart(s: string): s is DatePart {
  return (DATE_PARTS as readonly string[]).includes(s);
}

const pad = (n: number, w = 2): string => String(Math.abs(n)).padStart(w, "0");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/** `+0900` 같은 오프셋 문자열 → 분. 못 읽으면 null. */
export function parseZoneOffset(zone: string): number | null {
  const m = /^([+-])(\d{2})(\d{2})$/.exec(zone.trim());
  if (!m) return null;
  const minutes = Number(m[2]) * 60 + Number(m[3]);
  return m[1] === "-" ? -minutes : minutes;
}

/** 분 오프셋 → `+0900` 표기. */
function formatZone(offsetMinutes: number): string {
  const sign = offsetMinutes < 0 ? "-" : "+";
  const abs = Math.abs(offsetMinutes);
  return `${sign}${pad(Math.floor(abs / 60))}${pad(abs % 60)}`;
}

/**
 * 한 조각을 문자열로. `ms`는 UTC epoch, `offsetMinutes`는 표시할 시간대.
 *
 * ★비교는 **문자열**로 한다(RFC 5260 §4: 모든 date-part는 문자열이다). 그래서 숫자 조각도
 * 0을 채워 고정 폭으로 낸다 — `"9" < "10"`이 거짓이 되는 함정을 피한다. `relational`의
 * `i;ascii-numeric` 비교자를 쓰면 숫자로도 비교할 수 있다.
 */
export function datePartOf(ms: number, offsetMinutes: number, part: DatePart): string {
  // 오프셋을 더한 "그 시간대의 벽시계"를 UTC 메서드로 읽는다 — 서버 TZ에 의존하지 않는다.
  const d = new Date(ms + offsetMinutes * 60_000);
  switch (part) {
    case "year":
      return String(d.getUTCFullYear()).padStart(4, "0");
    case "month":
      return pad(d.getUTCMonth() + 1);
    case "day":
      return pad(d.getUTCDate());
    case "date":
      return `${String(d.getUTCFullYear()).padStart(4, "0")}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    case "julian":
      // RFC 5260 §4 — Modified Julian Day. 1970-01-01이 40587이다.
      return String(Math.floor(d.getTime() / 86_400_000) + 40587);
    case "hour":
      return pad(d.getUTCHours());
    case "minute":
      return pad(d.getUTCMinutes());
    case "second":
      return pad(d.getUTCSeconds());
    case "time":
      return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    case "iso8601":
      return `${String(d.getUTCFullYear()).padStart(4, "0")}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(
        d.getUTCMinutes(),
      )}:${pad(d.getUTCSeconds())}${offsetMinutes === 0 ? "Z" : `${formatZone(offsetMinutes).slice(0, 3)}:${formatZone(offsetMinutes).slice(3)}`}`;
    case "std11":
      // RFC 5322 date-time 표기(§4의 "std11").
      return `${DAYS[d.getUTCDay()]!}, ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]!} ${d.getUTCFullYear()} ${pad(d.getUTCHours())}:${pad(
        d.getUTCMinutes(),
      )}:${pad(d.getUTCSeconds())} ${formatZone(offsetMinutes)}`;
    case "zone":
      return formatZone(offsetMinutes);
    case "weekday":
      // 0=일요일 … 6=토요일(§4).
      return String(d.getUTCDay());
  }
}

/**
 * RFC 5322 `Date:` 헤더 → `{ ms, offsetMinutes }`. 못 읽으면 null.
 *
 * ★오프셋을 **따로 돌려주는** 이유: `:originalzone`은 "메일에 적힌 그 시간대"로 조각을
 * 내라는 뜻이라(§3), epoch만으로는 복원할 수 없다.
 */
export function parseHeaderDate(value: string): { ms: number; offsetMinutes: number } | null {
  const text = value.trim();
  const ms = Date.parse(text);
  if (Number.isNaN(ms)) return null;
  // 끝의 `+0900`/`-0500`을 읽는다. 이름 시간대(GMT·UT·EST…)는 오프셋을 0으로 본다 —
  // 관례적 약자는 모호하고(RFC 5322 §4.3도 폐기 대상으로 둔다) 추측하면 한 시간씩 틀린다.
  const m = /([+-]\d{4})\s*$/.exec(text);
  const offsetMinutes = m ? (parseZoneOffset(m[1]!) ?? 0) : 0;
  return { ms, offsetMinutes };
}
