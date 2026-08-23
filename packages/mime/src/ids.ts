/** Message-ID / In-Reply-To / References 파싱 + 스레딩 해시 (SCHEMA.md §5-2/§5-3). */
import { sha256hex32 } from "@ionosphere/core";

/** 단일 msg-id 헤더에서 '<...>' 내용 추출. 꺾쇠가 없으면 원문을 관대하게 사용. */
export function extractMsgId(raw: string): string | null {
  const m = raw.match(/<([^<>]+)>/);
  if (m) return m[1]!.trim();
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/** In-Reply-To/References처럼 여러 msg-id가 나열될 수 있는 헤더에서 전부 추출. */
export function extractMsgIdList(raw: string | null): string[] {
  if (!raw) return [];
  const out: string[] = [];
  const re = /<([^<>]+)>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    out.push(m[1]!.trim());
  }
  return out;
}

/** [messageId, ...inReplyTo, ...references]의 sha256/32hex, 중복 제거(첫 등장 순서 유지). */
export function computeThreadRefHashes(
  messageId: string | null,
  inReplyTo: readonly string[],
  references: readonly string[],
): string[] {
  const ids = [messageId, ...inReplyTo, ...references].filter(
    (v): v is string => typeof v === "string" && v.length > 0,
  );
  const seen = new Set<string>();
  const hashes: string[] = [];
  for (const id of ids) {
    const h = sha256hex32(id);
    if (!seen.has(h)) {
      seen.add(h);
      hashes.push(h);
    }
  }
  return hashes;
}
