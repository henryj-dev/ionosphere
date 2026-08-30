import type { Migration } from "../migrate.ts";

/** 목록 질의용 typed header projection. MIME 원본(blob)은 절대 대체하지 않는다. */
export const m022HeaderProjection: Migration = {
  version: 22,
  name: "header projection",
  statements: [
    `CREATE TABLE IF NOT EXISTS message_header_projection (
      message_id    VARCHAR(26) NOT NULL,
      occurrence    SMALLINT NOT NULL,
      name          VARCHAR(190) NOT NULL,
      kind          VARCHAR(16) NOT NULL,
      display_value TEXT NOT NULL,
      sort_value    TEXT NOT NULL,
      date_value    BIGINT,
      address_value TEXT,
      PRIMARY KEY (message_id, name, occurrence)
    )`,
    "CREATE INDEX IF NOT EXISTS ix_header_projection_date ON message_header_projection(name, date_value, message_id)",
    "CREATE INDEX IF NOT EXISTS ix_header_projection_sort ON message_header_projection(name, sort_value, message_id)",
    `CREATE TABLE IF NOT EXISTS header_backfill_checkpoints (
      id              VARCHAR(32) PRIMARY KEY,
      last_message_id VARCHAR(26) NOT NULL,
      updated_at      BIGINT NOT NULL
    )`,
    "INSERT INTO header_backfill_checkpoints (id, last_message_id, updated_at) VALUES ('default', '', 0)",
  ],
};
