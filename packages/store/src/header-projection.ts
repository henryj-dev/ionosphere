import type { DbDriver, Statement } from "@ionosphere/db";
import type { BlobStore } from "./blob.ts";

export const HEADER_PROJECTION_LIMITS = { nameBytes: 190, displayBytes: 16 * 1024, sortBytes: 4 * 1024, occurrence: 32 } as const;
const HEADER_KINDS = { date: "date", text: "text", address: "address", reference: "reference" } as const;
export type HeaderProjectionKind = (typeof HEADER_KINDS)[keyof typeof HEADER_KINDS];
export const HEADER_PROJECTION_NAMES = ["date", "subject", "from", "to", "cc", "bcc", "message-id", "in-reply-to", "references", "reply-to", "received"] as const;
export type HeaderProjectionName = (typeof HEADER_PROJECTION_NAMES)[number];

export interface HeaderProjection { name: HeaderProjectionName; occurrence: number; kind: HeaderProjectionKind; displayValue: string; sortValue: string; dateValue: number | null; addressValue: string | null; }

function byteClip(value: string, maxBytes: number): string {
  if (new TextEncoder().encode(value).length <= maxBytes) return value;
  let out = "";
  let used = 0;
  for (const character of value) {
    const size = new TextEncoder().encode(character).length;
    if (used + size > maxBytes) break;
    out += character;
    used += size;
  }
  return out;
}

function decodeWord(value: string): string {
  return value.replace(/=\?([^?]+)\?([bBqQ])\?([^?]+)\?=/g, (_whole, charset: string, encoding: string, payload: string) => {
    try {
      const bytes = encoding.toLowerCase() === "b"
        ? Uint8Array.from(Buffer.from(payload, "base64"))
        : Uint8Array.from(Buffer.from(payload.replace(/_/g, " ").replace(/=([0-9a-f]{2})/gi, (_m, hex: string) => String.fromCharCode(Number.parseInt(hex, 16))), "latin1"));
      return new TextDecoder(charset.toLowerCase() === "iso-8859-1" ? "iso-8859-1" : "utf-8", { fatal: false }).decode(bytes);
    } catch { return ""; }
  });
}

function headerKind(name: HeaderProjectionName): HeaderProjectionKind {
  if (name === "date") return HEADER_KINDS.date;
  if (["from", "to", "cc", "bcc", "reply-to"].includes(name)) return HEADER_KINDS.address;
  if (["message-id", "in-reply-to", "references"].includes(name)) return HEADER_KINDS.reference;
  return HEADER_KINDS.text;
}

function addressValue(value: string): string {
  const addresses = [...value.matchAll(/(?:^|,|\s)(?:[^<,]*\s*)?<([^>]+)>/g)].map((match) => match[1]!.trim().toLowerCase());
  return JSON.stringify(addresses.length > 0 ? addresses : value.split(",").map((part) => part.trim().toLowerCase()).filter(Boolean));
}

function referenceValue(value: string): string { return JSON.stringify([...value.matchAll(/<[^>]+>/g)].map((match) => match[0])); }

/** MIME 원본의 header section만 읽고 allowlist 밖의 필드는 버린다. 원본 바이트는 수정하지 않는다. */
export function projectHeaders(raw: Uint8Array | string): HeaderProjection[] {
  const source = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
  const headerEnd = source.search(/\r?\n\r?\n/u);
  const section = headerEnd < 0 ? source : source.slice(0, headerEnd);
  const unfolded: string[] = [];
  for (const line of section.split(/\r?\n/u)) {
    if (/^[ \t]/u.test(line) && unfolded.length > 0) unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    else unfolded.push(line);
  }
  const occurrences = new Map<string, number>();
  const out: HeaderProjection[] = [];
  for (const line of unfolded) {
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    const name = line.slice(0, separator).toLowerCase();
    if (!(HEADER_PROJECTION_NAMES as readonly string[]).includes(name)) continue;
    const next = (occurrences.get(name) ?? 0) + 1;
    occurrences.set(name, next);
    if (next > HEADER_PROJECTION_LIMITS.occurrence) continue;
    const decoded = decodeWord(line.slice(separator + 1).trim());
    const typedName = name as HeaderProjectionName;
    const kind = headerKind(typedName);
    out.push({ name: typedName, occurrence: next, kind, displayValue: byteClip(decoded, HEADER_PROJECTION_LIMITS.displayBytes), sortValue: byteClip(decoded.toLocaleLowerCase("en-US"), HEADER_PROJECTION_LIMITS.sortBytes), dateValue: kind === HEADER_KINDS.date && !Number.isNaN(Date.parse(decoded)) ? Date.parse(decoded) : null, addressValue: kind === HEADER_KINDS.address ? byteClip(addressValue(decoded), HEADER_PROJECTION_LIMITS.sortBytes) : kind === HEADER_KINDS.reference ? byteClip(referenceValue(decoded), HEADER_PROJECTION_LIMITS.sortBytes) : null });
  }
  return out;
}

export interface HeaderBackfillOptions { batchSize?: number; now?: number; }

/** BlobStore read가 실패하면 projection과 checkpoint를 함께 쓰지 않아 재시작 시 누락이 없다. */
export async function backfillHeaderProjection(db: DbDriver, blobs: BlobStore, options: HeaderBackfillOptions = {}): Promise<number> {
  const batchSize = options.batchSize ?? 100;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 1000) throw new Error("header backfill batchSize는 1~1000");
  const checkpoint = await db.query({ sql: "SELECT last_message_id FROM header_backfill_checkpoints WHERE id = ?", params: ["default"] });
  const lastId = checkpoint.rows[0]?.last_message_id == null ? "" : String(checkpoint.rows[0].last_message_id);
  const messages = await db.query({ sql: `SELECT id, blob_id FROM messages WHERE id > ? ORDER BY id LIMIT ${batchSize}`, params: [lastId] });
  if (messages.rows.length === 0) return 0;
  const statements: Statement[] = [];
  let processed = 0;
  for (const row of messages.rows) {
    const messageId = String(row.id);
    const projections = projectHeaders(await blobs.get(String(row.blob_id)));
    statements.push({ sql: "DELETE FROM message_header_projection WHERE message_id = ?", params: [messageId] });
    // Blob을 읽는 동안 메시지가 최종 삭제될 수 있다. 존재 조건을 projection 쓰기와 같은
    // 원자 배치에서 다시 확인하지 않으면 삭제 뒤 고아 projection을 되살린다.
    for (const projection of projections) statements.push({
      sql: "INSERT INTO message_header_projection (message_id, occurrence, name, kind, display_value, sort_value, date_value, address_value) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM messages WHERE id = ?)",
      params: [messageId, projection.occurrence, projection.name, projection.kind, projection.displayValue, projection.sortValue, projection.dateValue, projection.addressValue, messageId],
    });
    statements.push({ sql: "UPDATE header_backfill_checkpoints SET last_message_id = ?, updated_at = ? WHERE id = ?", params: [messageId, options.now ?? Date.now(), "default"] });
    processed++;
  }
  await db.batch(statements);
  return processed;
}
