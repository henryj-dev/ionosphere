/**
 * MIME 구조 순회: multipart/* 재귀 분해(중첩 지원, 병리적 입력 방지용 깊이 상한),
 * 첫 text/plain 파트 탐색, 없으면 첫 text/html을 스트립해 대체, 첨부 여부 판정.
 */
import { MAX_MIME_DEPTH, MAX_MIME_PARTS } from "@ionosphere/core";
import { decodeTextPart } from "./encoding.ts";
import { firstHeader, parseContentDisposition, parseContentType, parseHeaders, splitHeaderBody } from "./headers.ts";
import { stripHtml } from "./html.ts";

interface WalkState {
  textPlain: string | null;
  textHtmlStripped: string | null;
  hasAttachment: boolean;
  /**
   * 남은 파트 예산 — `parseStructure`와 **같은 상한**을 쓴다.
   *
   * 여기에 상한이 없으면, 구조 파서가 상한 초과로 거부한 메시지를 이쪽은 끝까지 걸어간다.
   * 실측(2026-07-31): 빈 파트 25MB 한 통에 `splitMultipart`가 500만 개짜리 조각 배열을 만들어
   * RSS가 342MB 늘었다. **같은 메시지를 두 파서가 다르게 읽는 것**이 이 저장소가 반복해서
   * 당한 사고 유형이라, 상한도 판정도 한쪽에 맞춘다.
   */
  remaining: number;
  exceeded: boolean;
}

/** 바운더리 라인이 문자열 시작이거나 개행 직후일 때만 유효한 delimiter로 인정(오탐 방지). */
function findValidMarker(s: string, marker: string, from: number): number {
  let pos = from;
  for (;;) {
    const idx = s.indexOf(marker, pos);
    if (idx === -1) return -1;
    if (idx === 0 || s[idx - 1] === "\n") return idx;
    pos = idx + marker.length;
  }
}

/**
 * multipart 본문을 파트별 원문(헤더+공백줄+본문) 문자열 배열로 분리. 닫는 바운더리 누락도 관대 처리.
 * `maxParts`에서 멈춘다 — 호출자는 상한 초과 여부만 알면 되므로 상한보다 하나만 더 세면 충분하고,
 * 그래야 500만 조각짜리 배열을 만들기 전에 멈춘다.
 */
function splitMultipart(bodyText: string, boundary: string, maxParts: number): string[] {
  const marker = "--" + boundary;
  const parts: string[] = [];
  let idx = findValidMarker(bodyText, marker, 0);
  if (idx === -1) return parts;

  while (idx !== -1 && parts.length < maxParts) {
    let end = idx + marker.length;
    const closing = bodyText.slice(end, end + 2) === "--";
    if (closing) end += 2;
    if (bodyText[end] === "\r") end++;
    if (bodyText[end] === "\n") end++;
    if (closing) break;

    const nextIdx = findValidMarker(bodyText, marker, end);
    const partEnd = nextIdx === -1 ? bodyText.length : nextIdx;
    // 바운더리 직전의 개행 1개는 구분자 소속 — 파트 내용에서 제외.
    const content = bodyText.slice(end, partEnd).replace(/\r?\n$/, "");
    parts.push(content);
    idx = nextIdx;
  }
  return parts;
}

function walkEntity(headers: Map<string, string[]>, bodyText: string, depth: number, state: WalkState): void {
  // 깊이 상한은 `@ionosphere/core`가 소유한다 — 예전엔 여기가 15, `structure.ts`가 20이라
  // 16~20단계의 첨부를 BODYSTRUCTURE는 보고 이 판정(`hasAttachment`)은 못 보는 구간이 있었다.
  if (depth > MAX_MIME_DEPTH || state.exceeded) return;
  state.remaining -= 1;
  if (state.remaining < 0) {
    state.exceeded = true;
    return;
  }

  const ct = parseContentType(firstHeader(headers, "content-type"));

  if (ct.type === "multipart") {
    const boundary = ct.params.boundary;
    if (!boundary) return; // 바운더리 없음 — 복구 불가, 건너뜀 (throw 금지)
    // 예산보다 하나 더 세어 본다 — "딱 맞음"과 "넘침"을 구별해야 조용히 잘라내지 않는다.
    const parts = splitMultipart(bodyText, boundary, state.remaining + 1);
    if (parts.length > state.remaining) {
      state.exceeded = true;
      return;
    }
    for (const partStr of parts) {
      if (state.exceeded) break;
      const { headerText, bodyText: partBody } = splitHeaderBody(partStr);
      walkEntity(parseHeaders(headerText), partBody, depth + 1, state);
    }
    return;
  }

  const disposition = parseContentDisposition(firstHeader(headers, "content-disposition"));
  const hasFilename = !!(disposition?.filename || ct.params.name);
  if (disposition?.type === "attachment" || (ct.type !== "text" && hasFilename)) {
    state.hasAttachment = true;
  }

  const cte = (firstHeader(headers, "content-transfer-encoding") ?? "7bit").trim().toLowerCase();
  if (ct.type === "text" && ct.subtype === "plain" && state.textPlain === null) {
    state.textPlain = decodeTextPart(bodyText, cte, ct.params.charset);
  } else if (ct.type === "text" && ct.subtype === "html" && state.textHtmlStripped === null) {
    state.textHtmlStripped = stripHtml(decodeTextPart(bodyText, cte, ct.params.charset));
  }
}

export function extractBody(
  headers: Map<string, string[]>,
  bodyText: string,
): { textBody: string | null; hasAttachment: boolean } {
  // 헤더도 본문도 전혀 없는 완전한 빈/쓰레기 입력 — 기본 text/plain 가정을 적용할 근거가 없으므로 null.
  if (headers.size === 0 && bodyText.length === 0) {
    return { textBody: null, hasAttachment: false };
  }
  const state: WalkState = {
    textPlain: null,
    textHtmlStripped: null,
    hasAttachment: false,
    remaining: MAX_MIME_PARTS,
    exceeded: false,
  };
  try {
    walkEntity(headers, bodyText, 0, state);
  } catch {
    // 순회 중 어떤 예외든 흡수 — 지금까지 찾은 결과로 진행 (throw 금지 원칙, 방어의 마지막 층)
  }
  // 파트 상한을 넘긴 메시지는 **구조를 해석하지 않은 것으로** 본다. `parseStructure`가 같은
  // 상한에서 단일 파트로 축소하는 것과 같은 판정이라, 두 파서가 같은 메시지를 다르게 읽지 않는다.
  if (state.exceeded) return { textBody: null, hasAttachment: false };
  return { textBody: state.textPlain ?? state.textHtmlStripped, hasAttachment: state.hasAttachment };
}

export function computePreview(text: string): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length > 200 ? collapsed.slice(0, 200) : collapsed;
}
