export { parseMessage } from "./parse.ts";
// 헤더 블록 경계·레코드 분리의 **정본**. 헤더를 지우거나 다시 쓰는 쪽이 이것을 그대로 써야
// 파서와 같은 바이트를 같게 읽는다(감사 M-13 — 두 벌로 두면 다음 차이가 또 생긴다).
export { splitHeaderBody, splitHeaderRecords, type HeaderRecord } from "./headers.ts";
export { parseStructure, type MimeDisposition, type MimePartInfo } from "./structure.ts";
export { extractJmapBody, type EmailBodyPart, type JmapBody, type JmapBodyValue } from "./jmap-body.ts";
export type { ParsedAddress, ParsedMessage } from "./types.ts";
