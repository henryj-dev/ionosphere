/**
 * message_addresses 변환 — SMTP·IMAP·JMAP **모든 배달/저장 경로가 공유하는 단일 구현**.
 *
 * 이전엔 ADDRESS_KINDS 배열이 backend.ts와 imap-backend.ts에 똑같이 복제돼 있었고
 * (toAppendAddresses 함수까지 바이트 단위로 동일), jmap-backend.ts에는 또 다른 두 가지 형태
 * (Record, 인덱스 배열)와 생 리터럴(`kind === 1 || 2 || 3`)이 있었다. kind 인코딩을 바꾸면
 * 네 곳을 서로 다른 자료구조로 고쳐야 했고, 하나만 빠뜨려도 타입 에러 없이
 * "SMTP로 받은 to가 JMAP에선 cc로 보이는" 조용한 데이터 오류가 났다.
 *
 * 인코딩 자체는 스키마를 소유한 @ionosphere/db(ADDRESS_KIND)가 갖는다.
 */
import { ADDRESS_FIELDS, ADDRESS_KIND } from "@ionosphere/db";
import type { ParsedAddress, ParsedMessage } from "@ionosphere/mime";
import type { AppendAddress } from "@ionosphere/store";

/** ParsedMessage의 주소 헤더들을 message_addresses 행으로 평탄화(pos는 헤더 내 순서). */
export function toAppendAddresses(parsed: ParsedMessage): AppendAddress[] {
  const out: AppendAddress[] = [];
  for (const field of ADDRESS_FIELDS) {
    const kind = ADDRESS_KIND[field];
    (parsed[field] as ParsedAddress[]).forEach((a, pos) => {
      out.push({ kind, pos, name: a.name, email: a.email });
    });
  }
  return out;
}
