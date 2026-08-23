/** RFC 5322 date-time 파싱 (구식 타임존 포함). 실패 시 null — 절대 throw하지 않음. */

const MONTHS: Record<string, number> = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11,
};

// RFC 5322 §4.3 obs-zone: 군용 단일문자 존은 미지로 취급(+0000)한다 — 실사용 전무.
const OBS_ZONES: Record<string, number> = {
  ut: 0,
  gmt: 0,
  est: -5 * 60,
  edt: -4 * 60,
  cst: -6 * 60,
  cdt: -5 * 60,
  mst: -7 * 60,
  mdt: -6 * 60,
  pst: -8 * 60,
  pdt: -7 * 60,
};

const DATE_RE =
  /^(?:[A-Za-z]{3,9}\s*,\s*)?(\d{1,2})\s+([A-Za-z]{3,})\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(?:\([^)]*\))?\s*([+-]\d{4}|[A-Za-z]{1,5})?\s*$/;

export function parseDate(raw: string | null): number | null {
  if (!raw) return null;
  const m = DATE_RE.exec(raw.trim());
  if (!m) return null;
  const [, dayS, monS, yearS, hS, minS, secS, zoneS] = m;

  const mon = MONTHS[monS!.slice(0, 3).toLowerCase()];
  if (mon === undefined) return null;

  const day = Number(dayS);
  let year = Number(yearS);
  if (yearS!.length === 2) year += year < 50 ? 2000 : 1900; // 구식 2자리 연도(관대)
  else if (yearS!.length === 3) year += 1900;

  const hour = Number(hS);
  const min = Number(minS);
  const sec = secS ? Number(secS) : 0;

  let offsetMin = 0;
  if (zoneS) {
    if (/^[+-]\d{4}$/.test(zoneS)) {
      const sign = zoneS[0] === "-" ? -1 : 1;
      offsetMin = sign * (Number(zoneS.slice(1, 3)) * 60 + Number(zoneS.slice(3, 5)));
    } else {
      offsetMin = OBS_ZONES[zoneS.toLowerCase()] ?? 0;
    }
  }

  const ms = Date.UTC(year, mon, day, hour, min, sec) - offsetMin * 60_000;
  return Number.isNaN(ms) ? null : ms;
}
