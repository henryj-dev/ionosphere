/** Message-ID / In-Reply-To / References 파싱 + 스레딩 해시 (SCHEMA.md §5-2/§5-3). */
import { MAX_THREAD_REFS, sha256hex32 } from "@ionosphere/core";

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

/**
 * [messageId, ...inReplyTo, ...references]의 sha256/32hex, 중복 제거(첫 등장 순서 유지).
 *
 * ★`MAX_THREAD_REFS`에서 자른다. 상한이 없던 시절 `References:` 한 줄로 메시지 한 통이
 * `thread_refs` 2만 행을 만들고 append가 407ms 동안 이벤트 루프를 잡았다(실측) — 25번
 * 포트에 미인증으로 접속한 상대가 그 값을 정한다. 근거는 `core/limits.ts` 상수 주석에 있다.
 *
 * **앞에서** 자르는 이유: 이 목록의 선두는 `Message-ID`와 `In-Reply-To`, 즉 **가장 가까운
 * 조상**이다. `resolveThread()`는 매치된 스레드 중 하나만 고르면 되므로 가까운 쪽이 남아야
 * 스레딩이 유지된다. 뒤에서 자르면 자기 자신의 Message-ID가 먼저 사라진다.
 */
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
      if (hashes.length >= MAX_THREAD_REFS) break;
    }
  }
  return hashes;
}
