/**
 * RFC 5322/MIME 파서 진입점. 순수 함수, I/O 없음 — SMTP DATA로 들어오는 임의(오염) 입력을
 * 받으므로 parseMessage는 절대 throw하지 않는다: 손상 지점은 null/빈 값으로 축소한다.
 *
 * 알려진 한계 (Phase 0 스코프 — docs/SCHEMA.md §5-2 envelope-cache에 필요한 만큼만 구현):
 * - RFC 2231 파라미터 확장(charset'lang'value, name*0=... 이어붙이기) 미지원.
 * - euc-kr/cp949 등 미지 charset은 latin1 best-effort로 대체(요구사항에 따라 의도적).
 * - multipart/alternative의 "더 나은 표현 우선" 시맨틱 없이, 트리 DFS 순서상 첫 text/plain을 채택.
 * - 스레드 병합·검색 인덱싱 등은 store 레이어의 책임이며 이 패키지 스코프 밖.
 */
import { sha256hex32 } from "@ionosphere/core";
import { parseAddressList } from "./address.ts";
import { bytesToBinary } from "./binary.ts";
import { computePreview, extractBody } from "./body.ts";
import { parseDate } from "./date.ts";
import { firstHeader, parseHeaders, splitHeaderBody } from "./headers.ts";
import { computeThreadRefHashes, extractMsgId, extractMsgIdList } from "./ids.ts";
import { computeSubjectBase } from "./subject.ts";
import type { ParsedMessage } from "./types.ts";

function emptyParsedMessage(): ParsedMessage {
  return {
    headers: new Map(),
    subject: null,
    subjectBase: null,
    messageId: null,
    msgidHash: null,
    inReplyTo: [],
    references: [],
    threadRefHashes: [],
    sentAt: null,
    from: [],
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    sender: [],
    textBody: null,
    preview: null,
    hasAttachment: false,
  };
}

function parseMessageInner(raw: Uint8Array): ParsedMessage {
  const bin = bytesToBinary(raw);
  const { headerText, bodyText } = splitHeaderBody(bin);
  const headers = parseHeaders(headerText);

  const subject = firstHeader(headers, "subject");
  const subjectBase = subject !== null ? computeSubjectBase(subject) : null;

  const messageIdRaw = firstHeader(headers, "message-id");
  const messageId = messageIdRaw !== null ? extractMsgId(messageIdRaw) : null;
  const msgidHash = messageId !== null ? sha256hex32(messageId) : null;

  const inReplyTo = extractMsgIdList(firstHeader(headers, "in-reply-to"));
  const references = extractMsgIdList(firstHeader(headers, "references"));
  const threadRefHashes = computeThreadRefHashes(messageId, inReplyTo, references);

  const sentAt = parseDate(firstHeader(headers, "date"));

  const from = parseAddressList(firstHeader(headers, "from"));
  const to = parseAddressList(firstHeader(headers, "to"));
  const cc = parseAddressList(firstHeader(headers, "cc"));
  const bcc = parseAddressList(firstHeader(headers, "bcc"));
  const replyTo = parseAddressList(firstHeader(headers, "reply-to"));
  const sender = parseAddressList(firstHeader(headers, "sender"));

  const { textBody, hasAttachment } = extractBody(headers, bodyText);
  const preview = textBody !== null ? computePreview(textBody) : null;

  return {
    headers,
    subject,
    subjectBase,
    messageId,
    msgidHash,
    inReplyTo,
    references,
    threadRefHashes,
    sentAt,
    from,
    to,
    cc,
    bcc,
    replyTo,
    sender,
    textBody,
    preview,
    hasAttachment,
  };
}

export function parseMessage(raw: Uint8Array): ParsedMessage {
  try {
    return parseMessageInner(raw);
  } catch {
    return emptyParsedMessage(); // 내부 방어에도 불구한 최종 방어선 — 절대 throw하지 않음
  }
}
