/**
 * JMAP Email 본문 구조 추출 (RFC 8621 §4.1). parseStructure(파트 트리+오프셋)를 EmailBodyPart로
 * 매핑하고, textBody/htmlBody/attachments 분류(§4.1.4 간이판) + 표시용 텍스트 파트 디코드.
 * 이 패키지 계약대로 절대 throw하지 않는다 — 손상 입력은 축소 결과.
 */
import { bytesToBinary } from "./binary.ts";
import { decodeTextPart } from "./encoding.ts";
import { firstHeader, parseHeaders } from "./headers.ts";
import { parseStructure, type MimePartInfo } from "./structure.ts";

/** EmailBodyPart (RFC 8621 §4.1.1) — 기본 bodyProperties. blobId는 다운로드 미배선이라 null(v1). */
export interface EmailBodyPart {
  partId: string | null;
  blobId: string | null;
  size: number;
  name: string | null;
  type: string;
  charset: string | null;
  disposition: string | null;
  cid: string | null;
  language: string[] | null;
  location: string | null;
  subParts: EmailBodyPart[] | null;
}

export interface JmapBodyValue {
  value: string;
  isEncodingProblem: boolean;
  isTruncated: boolean;
}

export interface JmapBody {
  bodyStructure: EmailBodyPart;
  textBody: EmailBodyPart[];
  htmlBody: EmailBodyPart[];
  attachments: EmailBodyPart[];
  /** partId → 디코드된 텍스트(표시 파트만). maxBytes 초과 시 절단. */
  bodyValues: Record<string, JmapBodyValue>;
}

interface Leaf {
  part: EmailBodyPart;
  info: MimePartInfo;
}

/** 전체 메시지의 JMAP 본문 표현 추출. maxBodyValueBytes: bodyValue 절단 상한(0=무제한). */
export function extractJmapBody(raw: Uint8Array, maxBodyValueBytes = 0): JmapBody {
  const bin = bytesToBinary(raw);
  const root = parseStructure(raw);
  const leaves: Leaf[] = [];
  let counter = 0;
  const nextId = (): string => String(++counter);

  const map = (info: MimePartInfo): EmailBodyPart => {
    const isMultipart = info.type === "multipart";
    const type = `${info.type}/${info.subtype}`;
    const name = info.disposition?.params["filename"] ?? info.params["name"] ?? null;
    const part: EmailBodyPart = {
      partId: isMultipart ? null : nextId(),
      blobId: null,
      size: isMultipart ? 0 : info.size,
      name,
      type,
      charset: isMultipart ? null : (info.params["charset"] ?? null),
      disposition: info.disposition?.type ?? null,
      cid: info.contentId,
      language: null,
      location: null,
      subParts: isMultipart ? info.children.map(map) : null,
    };
    if (!isMultipart) leaves.push({ part, info });
    return part;
  };
  const bodyStructure = map(root);

  // 분류(§4.1.4 간이): 첨부(disposition=attachment 또는 비텍스트 비인라인)와 표시 본문 구분.
  const textBody: EmailBodyPart[] = [];
  const htmlBody: EmailBodyPart[] = [];
  const attachments: EmailBodyPart[] = [];
  for (const { part, info } of leaves) {
    const isAttachment = part.disposition === "attachment" || (info.type !== "text" && part.disposition !== "inline" && info.type !== "multipart");
    if (isAttachment) {
      attachments.push(part);
      continue;
    }
    if (info.type === "text" && info.subtype === "html") htmlBody.push(part);
    else if (info.type === "text") textBody.push(part);
    else attachments.push(part); // 텍스트도 첨부도 아닌 인라인(예: image/png inline) — 첨부로
  }
  // 한쪽만 있으면 다른 쪽도 그 표현을 가리킨다(RFC 8621: html 없으면 textBody를, plain 없으면 htmlBody를)
  const effTextBody = textBody.length > 0 ? textBody : htmlBody;
  const effHtmlBody = htmlBody.length > 0 ? htmlBody : textBody;

  // 표시 본문 파트만 디코드해 bodyValues에 담는다.
  // 파트→leaf는 Map으로 찾는다. 배열 `find`로 훑으면 파트 수의 제곱이 되어,
  // 텍스트 파트가 많은 메시지에서 파트 수를 늘리는 것만으로 CPU를 태울 수 있다.
  const leafByPart = new Map<EmailBodyPart, Leaf>(leaves.map((l) => [l.part, l]));
  const bodyValues: Record<string, JmapBodyValue> = {};
  const decodeInto = (parts: EmailBodyPart[]): void => {
    for (const p of parts) {
      if (p.partId === null || p.partId in bodyValues) continue;
      const leaf = leafByPart.get(p);
      if (!leaf) continue;
      const slice = bin.slice(leaf.info.bodyStart, leaf.info.end);
      let value = safeDecode(slice, leaf.info.encoding, p.charset ?? undefined);
      let isTruncated = false;
      if (maxBodyValueBytes > 0 && value.length > maxBodyValueBytes) {
        value = value.slice(0, maxBodyValueBytes);
        isTruncated = true;
      }
      bodyValues[p.partId] = { value, isEncodingProblem: false, isTruncated };
    }
  };
  decodeInto(effTextBody);
  decodeInto(effHtmlBody);

  return { bodyStructure, textBody: effTextBody, htmlBody: effHtmlBody, attachments, bodyValues };
}

function safeDecode(bodyText: string, cte: string, charset: string | undefined): string {
  try {
    return decodeTextPart(bodyText, cte, charset);
  } catch {
    return bodyText; // 최후 방어 — 원문 그대로(throw 금지)
  }
}

/** 특정 파트의 헤더 맵(EmailBodyPart headers 프로퍼티 요청 시). 현재 미사용 — 확장 대비 export. */
export function partHeaders(raw: Uint8Array, part: MimePartInfo): Map<string, string[]> {
  const bin = bytesToBinary(raw);
  return parseHeaders(bin.slice(part.start, part.bodyStart));
}

/** Content-Type name 파라미터 헬퍼(테스트/디버그용). */
export function contentTypeName(raw: Uint8Array): string | null {
  const bin = bytesToBinary(raw);
  const structure = parseStructure(raw);
  const headers = parseHeaders(bin.slice(structure.start, structure.bodyStart));
  return firstHeader(headers, "content-type");
}
