export { parseMessage } from "./parse.ts";
// 헤더 블록 경계·레코드 분리의 **정본**. 헤더를 지우거나 다시 쓰는 쪽이 이것을 그대로 써야
// 파서와 같은 바이트를 같게 읽는다(감사 M-13 — 두 벌로 두면 다음 차이가 또 생긴다).
export { splitHeaderBody, splitHeaderRecords, type HeaderRecord } from "./headers.ts";
export { parseStructure, type MimeDisposition, type MimePartInfo } from "./structure.ts";
// 전송 인코딩 해제기 — IMAP `BINARY[]`(RFC 3516)가 같은 디코더를 써야 본문 표시와
// 바이너리 인출이 같은 바이트를 낸다(두 벌로 두면 base64 관용 처리가 갈린다).
export { base64Decode, quotedPrintableDecode } from "./encoding.ts";
export { extractJmapBody, type EmailBodyPart, type JmapBody, type JmapBodyValue } from "./jmap-body.ts";
export type { ParsedAddress, ParsedMessage } from "./types.ts";
