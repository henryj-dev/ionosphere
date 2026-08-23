/** @ionosphere/mime 공개 타입. envelope-cache 필드는 SCHEMA.md §5-2(messages 테이블)와 정렬. */

export interface ParsedAddress {
  name: string | null;
  email: string; // 정규화: localpart·domain 모두 소문자
}

export interface ParsedMessage {
  /** 소문자 필드명 → 원문(언폴딩·decoded-where-sensible) 값 목록, 발생 순. */
  headers: Map<string, string[]>;

  subject: string | null;
  subjectBase: string | null; // Re:/Fwd: 등 접두사 제거, 공백 압축, ≤190자
  messageId: string | null; // '<' '>' 내용
  msgidHash: string | null; // sha256/32hex
  inReplyTo: string[];
  references: string[];
  threadRefHashes: string[]; // [messageId, ...inReplyTo, ...references]의 sha256/32hex, 중복 제거

  sentAt: number | null; // epoch millis

  from: ParsedAddress[];
  to: ParsedAddress[];
  cc: ParsedAddress[];
  bcc: ParsedAddress[];
  replyTo: ParsedAddress[];
  sender: ParsedAddress[];

  textBody: string | null; // 최선 판정 평문 (text/plain 우선, 없으면 text/html 스트립)
  preview: string | null; // ≤200자, 공백 압축
  hasAttachment: boolean;
}
