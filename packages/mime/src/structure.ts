/**
 * MIME 구조 파서 — 파트 트리 + 바이트 오프셋 (IMAP BODYSTRUCTURE·BODY[섹션] 지원용).
 *
 * parseMessage(봉투 캐시)와 달리 본문을 해석하지 않고 **경계와 메타데이터만** 뽑는다.
 * 바이너리 문자열(1바이트=1코드포인트) 위에서 동작하므로 문자열 인덱스 == 바이트 오프셋.
 * 이 패키지 계약대로 절대 throw하지 않는다 — 손상 입력은 단일 파트로 축소.
 */
import { MAX_MIME_DEPTH, MAX_MIME_PARTS } from "@ionosphere/core";
import { bytesToBinary } from "./binary.ts";
import { firstHeader, parseContentDisposition, parseContentType, parseHeaders } from "./headers.ts";

export interface MimeDisposition {
  type: string;
  params: Record<string, string>;
}

export interface MimePartInfo {
  /** 파트 시작(헤더 첫 바이트) 오프셋. */
  start: number;
  /** 본문 시작 오프셋(헤더/본문 빈 줄 다음). */
  bodyStart: number;
  /** 파트 끝(exclusive). */
  end: number;
  type: string;
  subtype: string;
  params: Record<string, string>;
  contentId: string | null;
  description: string | null;
  /** Content-Transfer-Encoding — 기본 "7bit". */
  encoding: string;
  disposition: MimeDisposition | null;
  /** 본문 옥텟 수 (end - bodyStart). */
  size: number;
  /** 본문 라인 수 (text/* 및 message/rfc822 BODYSTRUCTURE용). */
  lines: number;
  /** multipart 자식들, message/rfc822면 내포 메시지 1개. */
  children: MimePartInfo[];
}

/**
 * 파트 개수 예산 — 트리 전체가 **하나를** 나눠 쓴다.
 *
 * 형제 폭(얕고 넓은 multipart)과 중첩 깊이 어느 쪽으로 부풀려도 같은 상한에 걸리게 하려면
 * 예산이 하나여야 한다. 깊이 상한만 두면 깊이 1짜리 파트 80만 개를 막지 못한다.
 */
interface PartBudget {
  /** 남은 파트 수. 파트를 만들 때마다 하나씩 줄인다. */
  remaining: number;
  /** 상한을 넘겼는가 — 넘겼으면 잘린 트리를 쓰지 않고 통째로 축소한다(조용한 절단 금지). */
  exceeded: boolean;
}

/**
 * `[from, end)` 안에서 **시작하는** `needle`의 첫 위치 — 없으면 -1.
 *
 * 왜 `bin.indexOf(needle, from)` 한 줄로 두지 않는가: 그 호출은 범위를 넘어 **버퍼 끝까지** 훑는다.
 * 찾는 것이 범위 안에 없는 파트가 N개면 파트마다 메시지 전체를 훑어 O(N × 전체 길이)가 되고,
 * 파트 하나가 5바이트(`--B` + CRLF)면 N은 크기에 비례해 최대가 된다.
 * 실측(2026-07-31): 빈 파트 폭탄 1MB → 8.9초, 2MB → 38초, 4MB → 155초(정확히 4배씩 = 2차식).
 * 수신 상한이 25MB(`MAX_MESSAGE_BYTES`)이므로 한 통으로 약 100분이 나오고,
 * 전 프로토콜이 단일 프로세스라 그동안 25·587·993이 함께 멈춘다. 발신자는 미인증 원격이다.
 *
 * 남은 버퍼가 볼 범위보다 크면 그 범위만 복사해 검색한다 — 복사도 O(범위)라 비용이 항상
 * 범위에 비례한다. `needle`이 `end`를 걸쳐 시작할 수 있으므로 꼬리를 `needle.length - 1`만큼
 * 더 떠서, 범위를 좁힌 것이 **판정을 바꾸지는 않게** 한다.
 */
function indexOfWithin(bin: string, needle: string, from: number, end: number): number {
  if (from >= end) return -1;
  const scanEnd = Math.min(end + needle.length - 1, bin.length);
  let idx: number;
  if (bin.length - from > (scanEnd - from) * 2) {
    const found = bin.slice(from, scanEnd).indexOf(needle);
    idx = found === -1 ? -1 : from + found;
  } else {
    idx = bin.indexOf(needle, from);
  }
  return idx === -1 || idx >= end ? -1 : idx;
}

/**
 * 헤더/본문 경계 탐색 — [from, end) 범위.
 * headerEnd: 헤더 텍스트 끝(빈 줄 제외, exclusive), bodyStart: 본문 시작.
 * 경계가 없으면 둘 다 end(본문 없음).
 */
function findBodyStart(bin: string, from: number, end: number): { headerEnd: number; bodyStart: number } {
  const crlf = indexOfWithin(bin, "\r\n\r\n", from, end);
  const lf = indexOfWithin(bin, "\n\n", from, end);
  let sep = -1;
  let len = 0;
  if (crlf !== -1) {
    sep = crlf;
    len = 4;
  }
  if (lf !== -1 && (sep === -1 || lf < sep)) {
    sep = lf;
    len = 2;
  }
  if (sep === -1) return { headerEnd: end, bodyStart: end };
  return { headerEnd: sep, bodyStart: Math.min(sep + len, end) };
}

function countLines(bin: string, from: number, end: number): number {
  let n = 0;
  for (let i = from; i < end; i++) if (bin.charCodeAt(i) === 0x0a) n++;
  return n;
}

/**
 * 본문 범위에서 multipart 자식 파트 [start, end) 목록 — 바운더리 라인은 제외.
 *
 * `maxRanges`에서 **멈춘다**. 여기서 멈추는 것 자체가 결과를 잘라내는 것은 아니다 —
 * 호출자가 개수를 보고 상한 초과를 판정하려면 상한보다 하나만 더 세어 보면 충분하기 때문에,
 * 80만 개짜리 입력에도 배열이 1025개를 넘지 않게 해 목록 작성 비용까지 묶는다.
 */
function splitParts(bin: string, boundary: string, from: number, end: number, maxRanges: number): Array<[number, number]> {
  const delim = `--${boundary}`;
  const ranges: Array<[number, number]> = [];
  let cursor = from;
  let partStart = -1;
  while (cursor < end && ranges.length < maxRanges) {
    const idx = indexOfWithin(bin, delim, cursor, end);
    if (idx === -1) break;
    // 바운더리는 라인 선두여야 유효
    const atLineStart = idx === from || bin[idx - 1] === "\n";
    const afterIdx = idx + delim.length;
    if (!atLineStart) {
      cursor = afterIdx;
      continue;
    }
    const isFinal = bin.startsWith("--", afterIdx);
    // 이전 파트 종료 — 바운더리 앞 CRLF는 바운더리 소속(RFC 2046)
    if (partStart !== -1) {
      let partEnd = idx;
      if (partEnd > partStart && bin[partEnd - 1] === "\n") partEnd -= 1;
      if (partEnd > partStart && bin[partEnd - 1] === "\r") partEnd -= 1;
      ranges.push([partStart, partEnd]);
      partStart = -1;
    }
    if (isFinal) break;
    // 다음 파트는 바운더리 라인의 개행 다음부터
    const nl = indexOfWithin(bin, "\n", afterIdx, end);
    if (nl === -1) break;
    partStart = nl + 1;
    cursor = partStart;
  }
  // 최종 바운더리 유실(손상 메시지) — 남은 범위를 마지막 파트로
  if (partStart !== -1 && partStart < end && ranges.length < maxRanges) ranges.push([partStart, end]);
  return ranges;
}

function parseRange(bin: string, start: number, end: number, depth: number, budget: PartBudget): MimePartInfo {
  budget.remaining -= 1;
  if (budget.remaining < 0) budget.exceeded = true;

  const { headerEnd, bodyStart } = findBodyStart(bin, start, end);
  const headers = parseHeaders(bin.slice(start, headerEnd));
  const ct = parseContentType(firstHeader(headers, "content-type"));

  const dispo = parseContentDisposition(firstHeader(headers, "content-disposition"));
  const disposition: MimeDisposition | null =
    dispo && dispo.type ? { type: dispo.type, params: dispo.filename !== null ? { filename: dispo.filename } : {} } : null;

  const part: MimePartInfo = {
    start,
    bodyStart,
    end,
    type: ct.type,
    subtype: ct.subtype,
    params: ct.params,
    contentId: firstHeader(headers, "content-id"),
    description: firstHeader(headers, "content-description"),
    encoding: (firstHeader(headers, "content-transfer-encoding") ?? "7bit").trim().toLowerCase() || "7bit",
    disposition,
    size: end - bodyStart,
    lines: countLines(bin, bodyStart, end),
    children: [],
  };

  if (depth >= MAX_MIME_DEPTH || budget.exceeded) return part;

  if (ct.type === "multipart") {
    const boundary = ct.params["boundary"];
    if (boundary) {
      // 예산보다 하나 더 세어 본다 — "딱 맞음"과 "넘침"을 구별해야 조용히 잘라내지 않는다.
      const ranges = splitParts(bin, boundary, bodyStart, end, budget.remaining + 1);
      if (ranges.length > budget.remaining) budget.exceeded = true;
      for (const [s, e] of ranges) {
        if (budget.exceeded) break;
        part.children.push(parseRange(bin, s, e, depth + 1, budget));
      }
    }
    // 바운더리 없음/자식 0개인 multipart는 그대로 둔다 — 포매터가 방어
  } else if (ct.type === "message" && ct.subtype === "rfc822") {
    part.children.push(parseRange(bin, bodyStart, end, depth + 1, budget));
  }
  return part;
}

/** 손상·과대 입력의 축소 결과 — 메시지 전체를 해석하지 않은 단일 text/plain 파트로 본다. */
function collapsedPart(bin: string): MimePartInfo {
  return {
    start: 0,
    bodyStart: 0,
    end: bin.length,
    type: "text",
    subtype: "plain",
    params: {},
    contentId: null,
    description: null,
    encoding: "7bit",
    disposition: null,
    size: bin.length,
    lines: countLines(bin, 0, bin.length),
    children: [],
  };
}

/** 메시지 전체의 MIME 구조 — 절대 throw하지 않는다. */
export function parseStructure(raw: Uint8Array): MimePartInfo {
  const bin = bytesToBinary(raw);
  const budget: PartBudget = { remaining: MAX_MIME_PARTS, exceeded: false };
  try {
    const root = parseRange(bin, 0, bin.length, 0, budget);
    // 상한 초과는 **부분 트리로 넘기지 않는다**. 잘린 트리는 "파트가 그것뿐인 정상 메시지"와
    // 구별되지 않아, 첨부 판정·본문 추출이 실제 메시지와 다른 것을 보게 된다.
    return budget.exceeded ? collapsedPart(bin) : root;
  } catch {
    // 최종 방어선 — 단일 파트로 축소
    return collapsedPart(bin);
  }
}
