/**
 * RFC 6376 §3.4 DKIM 정규화(canonicalization): 헤더/본문 각각 relaxed·simple.
 * 순수 함수, I/O 없음. 메시지는 8비트 원문일 수 있어 바이트 단위 왕복이 무손실인
 * "바이너리 문자열"(1바이트=1코드포인트, latin1 대응)로 다룬다 — sign.ts/verify.ts에서
 * `Buffer.from(bytes).toString("latin1")` / `Buffer.from(str, "latin1")`로 왕복한다.
 */

export type DkimCanonMode = "relaxed" | "simple";

/** CRLF|CR|LF 전부 CRLF로 정규화 (실전 8-bit transport에서 bare LF가 섞여 들어오는 것에 대비). */
export function normalizeLineEndings(bin: string): string {
  return bin.replace(/\r\n|\r|\n/g, "\r\n");
}

export interface SplitMessage {
  headerBlock: string;
  body: string;
}

/** 첫 빈 줄(CRLFCRLF)을 기준으로 헤더 블록과 본문을 분리. 못 찾으면 전체를 헤더로 취급. */
export function splitMessage(bin: string): SplitMessage {
  const idx = bin.indexOf("\r\n\r\n");
  if (idx === -1) return { headerBlock: bin, body: "" };
  return { headerBlock: bin.slice(0, idx), body: bin.slice(idx + 4) };
}

export interface HeaderField {
  /** 원본 그대로의 필드명(콜론 앞부분, trim 안 함) */
  name: string;
  /** "Name<원본공백>:<원본공백>value" 전체 원문. 접힘(folding)은 내부 CRLF로 보존, 트레일링 CRLF는 제외. */
  raw: string;
}

// RFC 5322 field-name은 콜론 제외 인쇄가능 US-ASCII(%d33-57/%d59-126, 공백 불허)이지만,
// RFC 6376 §3.4.5 정규화 예시 자체가 "B : Y"처럼 이름 뒤 공백이 있는 헤더를 다루므로
// (relaxed가 콜론 앞 WSP를 제거하는 규칙의 근거) 이름 뒤 트레일링 WSP까지는 허용한다.
const FIELD_NAME_RE = /^[!-9;-~][!-9;-~ \t]*$/;

/** 헤더 블록 → 필드 목록(발생 순, 원본 케이스/공백 보존). 접힌 연속줄은 CRLF까지 그대로 이어붙인다. */
export function parseHeaderFields(headerBlock: string): HeaderField[] {
  if (!headerBlock) return [];
  const physicalLines = headerBlock.split("\r\n");
  const records: string[] = [];
  for (const line of physicalLines) {
    if ((line.startsWith(" ") || line.startsWith("\t")) && records.length > 0) {
      records[records.length - 1] += "\r\n" + line; // 폴딩: 원문 그대로(CRLF 포함) 보존
    } else {
      records.push(line);
    }
  }

  const fields: HeaderField[] = [];
  for (const record of records) {
    const colonIdx = record.indexOf(":");
    if (colonIdx <= 0) continue; // 콜론 없음/빈 이름 — 손상된 줄, 헤더로 보지 않음
    const name = record.slice(0, colonIdx);
    if (!FIELD_NAME_RE.test(name)) continue;
    fields.push({ name, raw: record });
  }
  return fields;
}

/**
 * 단일 헤더 필드를 정규화해 트레일링 CRLF까지 붙여 반환한다.
 * - simple: 원문 그대로 + CRLF (변경 없음이 곧 알고리즘).
 * - relaxed: 필드명 소문자화, 접힘 해제(CRLF 제거·뒤따르는 WSP는 유지), WSP 시퀀스를 단일 SP로 압축,
 *   콜론 앞뒤 및 값 끝의 잔여 WSP 제거.
 */
export function canonHeaderField(field: HeaderField, mode: DkimCanonMode): string {
  if (mode === "simple") return field.raw + "\r\n";

  const colonIdx = field.raw.indexOf(":");
  const name = field.raw.slice(0, colonIdx).trim().toLowerCase();
  let value = field.raw.slice(colonIdx + 1);
  value = value.replace(/\r\n/g, ""); // 언폴딩: 접힘 CRLF만 제거
  value = value.replace(/[ \t]+/g, " "); // WSP 시퀀스 → 단일 SP
  value = value.trim(); // 콜론 뒤 선행 WSP + 값 끝 트레일링 WSP 제거
  return `${name}:${value}\r\n`;
}

/**
 * relaxed 본문의 한 줄: 줄 끝 WSP 제거 + 내부 WSP 시퀀스를 단일 SP로 압축 (RFC 6376 §3.4.4).
 *
 * ★정규식을 쓰지 않는 이유(ReDoS). 예전 구현은 `line.replace(/[ \t]+$/, "")`였는데,
 * `[ \t]+$`는 "공백 런 뒤에 비공백이 오는" 줄에서 시작 위치마다 런 전체를 훑고 실패해
 * **O(줄길이²)**가 된다. 실측: 공백 1000개 줄 0.6ms → 128,000개 줄 14,000ms(2배마다 약 4배).
 * 본문과 `c=relaxed/relaxed` 둘 다 발신자가 정하므로, 인증 전 인바운드 메시지 **한 통**으로
 * 이벤트 루프를 통째로 묶을 수 있었다(0.5MB 본문 = 약 50초, 25MB 상한이면 수십 분).
 * WSP 런을 한 번만 전진하며 읽는 문자 스캐너는 같은 입력에서 선형이다.
 */
function canonRelaxedBodyLine(line: string): string {
  const parts: string[] = [];
  let i = 0;
  while (i < line.length) {
    // 비-WSP 구간은 통째로 잘라 붙인다 — 문자 단위 연결은 긴 줄에서 불필요하게 느리다.
    const textStart = i;
    while (i < line.length && line[i] !== " " && line[i] !== "\t") i++;
    if (i > textStart) parts.push(line.slice(textStart, i));
    while (i < line.length && (line[i] === " " || line[i] === "\t")) i++;
    // 줄 끝에 닿은 WSP 런은 버린다(트레일링 제거), 그 외에는 SP 하나로 압축.
    if (i < line.length) parts.push(" ");
  }
  return parts.join("");
}

/**
 * 본문 정규화 (RFC 6376 §3.4.3/§3.4.4).
 * - simple: 끝의 빈 줄들만 제거, 나머지는 무변경. 완전히 빈 본문은 CRLF 한 줄.
 * - relaxed: 각 줄 끝 WSP 제거 + 줄 내부 WSP 시퀀스를 단일 SP로 압축, 그 다음 끝 빈 줄 제거.
 *   완전히 빈 본문은 빈 문자열(simple과 다름 — RFC 명시적 차이).
 * 두 모드 모두 비어있지 않으면 항상 단일 트레일링 CRLF로 끝난다.
 */
export function canonBody(body: string, mode: DkimCanonMode): string {
  let lines = body.split("\r\n");
  if (mode === "relaxed") {
    lines = lines.map(canonRelaxedBodyLine);
  }
  let end = lines.length;
  while (end > 0 && lines[end - 1] === "") end--;
  lines = lines.slice(0, end);

  if (lines.length === 0) return mode === "simple" ? "\r\n" : "";
  return lines.join("\r\n") + "\r\n";
}

/** 소문자 필드명 → 필드 목록(발생 순, top-to-bottom) 그룹핑. */
export function groupHeaderFields(fields: HeaderField[]): Map<string, HeaderField[]> {
  const groups = new Map<string, HeaderField[]>();
  for (const f of fields) {
    const key = f.name.trim().toLowerCase();
    const arr = groups.get(key);
    if (arr) arr.push(f);
    else groups.set(key, [f]);
  }
  return groups;
}

/**
 * h= 태그 순서대로 헤더 인스턴스를 선택한다. 동일 이름이 h=에 여러 번 나오면 메시지의
 * "맨 아래(본문에 가까운 것)부터" 소비한다 (RFC 6376 §5.4.2 서명 규칙 · §6.1.1 검증 규칙에
 * 공통되는 알고리즘). h=에 나열됐지만 실제로 남은 인스턴스가 없으면 그 자리는 null
 * (= 아무 것도 서명/해시하지 않음)로 표시된다 — 오버서명(from:from)이 "서명 이후 헤더가
 * 추가되면 검증 실패"를 강제하는 메커니즘이 여기서 나온다.
 */
export function resolveHeaderSequence(
  groups: Map<string, HeaderField[]>,
  hNames: string[],
): (HeaderField | null)[] {
  const consumed = new Map<string, number>();
  const result: (HeaderField | null)[] = [];
  for (const rawName of hNames) {
    const name = rawName.trim().toLowerCase();
    const arr = groups.get(name) ?? [];
    const used = consumed.get(name) ?? 0;
    const idx = arr.length - 1 - used;
    result.push(idx >= 0 ? (arr[idx] ?? null) : null);
    consumed.set(name, used + 1);
  }
  return result;
}
