import type { Migration } from "../migrate.ts";

/** UID/listing 질의의 공통 선두 인덱스. 결과 캐시는 보조 최적화이고 DB가 정본이다. */
export const m023ListingIndexes: Migration = {
  version: 23,
  name: "listing indexes",
  statements: [
    "CREATE INDEX IF NOT EXISTS ix_mm_listing ON message_mailbox(mailbox_id, uid, message_id)",
    "CREATE INDEX IF NOT EXISTS ix_messages_subject_sort ON messages(account_id, subject_base, id)",
    "CREATE INDEX IF NOT EXISTS ix_header_projection_listing ON message_header_projection(name, sort_value, message_id)",
  ],
};
