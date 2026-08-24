/**
 * JMAP `SearchSnippet/get`(RFC 8621 §5)의 **조각 만들기** — 순수 함수, I/O 0.
 *
 * ★출력은 **HTML 문자열**이다(§5: "The `subject` and `preview` properties ... contain HTML").
 * 그래서 이 파일의 절반은 이스케이프다. 원문은 남이 보낸 메일의 제목과 본문이고, 그게
 * 그대로 클라이언트의 DOM에 들어간다 — 이스케이프를 빠뜨리면 **메일 한 통으로 스크립트가
 * 실행된다.** 그래서 순서가 중요하다: **먼저 이스케이프하고 그다음에 `<mark>`를 넣는다.**
 * 반대로 하면 우리가 넣은 마크업까지 이스케이프돼 화면에 `&lt;mark&gt;`가 보인다.
 */

/** HTML 특수문자 이스케이프 — `&`를 **가장 먼저** 바꿔야 이중 이스케이프가 안 생긴다. */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** 조각 최대 길이 — 클라이언트 목록의 한 줄에 들어갈 만한 크기. */
const MAX_SNIPPET_CHARS = 255;
/** 첫 매치 앞에 남기는 문맥. 매치가 조각 맨 앞에 붙으면 무슨 문장인지 알 수 없다. */
const LEAD_CONTEXT_CHARS = 40;

/**
 * `text` 안에서 `terms` 중 하나가 처음 나오는 위치(대소문자 무시). 없으면 -1.
 *
 * 여러 항이면 **가장 앞선** 매치를 고른다 — 조각은 하나뿐이라 어디를 보여줄지 골라야 하고,
 * 앞선 쪽이 보통 더 문맥이 있다.
 */
function firstMatch(lower: string, terms: readonly string[]): { at: number; length: number } | null {
  let best: { at: number; length: number } | null = null;
  for (const t of terms) {
    const at = lower.indexOf(t);
    if (at === -1) continue;
    if (best === null || at < best.at) best = { at, length: t.length };
  }
  return best;
}

/**
 * 조각 하나. 매치가 없으면 `null` — §5는 매치가 없는 부분을 `null`로 두라고 한다
 * (빈 문자열로 두면 클라이언트가 "제목이 비었다"로 읽는다).
 *
 * ★매치는 **부분 문자열**로 찾는다. JMAP 검색 자체는 토큰 의미지만(`search_index`),
 * 조각은 "사용자가 친 글자가 어디 있는지 보여 주는" 것이라 부분 문자열이 맞다 —
 * 토큰 경계로 찾으면 `foo`를 검색했을 때 `foobar` 안의 매치를 표시하지 못한다.
 */
export function buildSnippet(text: string | null, terms: readonly string[]): string | null {
  if (text === null || text.length === 0 || terms.length === 0) return null;
  const lower = text.toLowerCase();
  const hit = firstMatch(lower, terms);
  if (hit === null) return null;

  // 창은 첫 매치를 담되 앞 문맥을 조금 남긴다. 매치가 창보다 길면 매치 시작에서 자른다.
  const start = Math.max(0, Math.min(hit.at - LEAD_CONTEXT_CHARS, text.length - MAX_SNIPPET_CHARS));
  const from = Math.max(0, start);
  const to = Math.min(text.length, from + MAX_SNIPPET_CHARS);
  const window = text.slice(from, to);

  /**
   * ★이스케이프 → 마크 순서. 창 안에서 매치를 다시 찾되, **이스케이프된 문자열 위에서**
   * 찾으면 `&amp;` 같은 치환 때문에 위치가 어긋난다. 그래서 원문에서 구간을 나눠 각 조각을
   * 따로 이스케이프하고 `<mark>`로 잇는다 — 이러면 위치 계산과 이스케이프가 섞이지 않는다.
   */
  const windowLower = window.toLowerCase();
  const parts: string[] = [];
  let cursor = 0;
  // 창 안의 모든 매치를 표시한다 — 하나만 표시하면 왜 이 메일이 걸렸는지 덜 보인다.
  for (let guard = 0; guard < MAX_SNIPPET_CHARS; guard++) {
    const next = firstMatch(windowLower.slice(cursor), terms);
    if (next === null) break;
    const at = cursor + next.at;
    parts.push(escapeHtml(window.slice(cursor, at)));
    parts.push(`<mark>${escapeHtml(window.slice(at, at + next.length))}</mark>`);
    cursor = at + next.length;
    if (next.length === 0) break; // 빈 항 방어 — 무한 루프가 된다
  }
  parts.push(escapeHtml(window.slice(cursor)));

  const ellipsisStart = from > 0 ? "…" : "";
  const ellipsisEnd = to < text.length ? "…" : "";
  return `${ellipsisStart}${parts.join("")}${ellipsisEnd}`;
}

/**
 * `Email/query` 필터에서 조각에 표시할 **검색어**를 뽑는다.
 *
 * §5는 `filter`를 그대로 받으므로 전문 검색 항만 의미가 있다. `inMailbox`·`hasKeyword` 같은
 * 구조 조건은 본문에 표시할 글자가 없다 — 그런 필터만 있으면 조각은 전부 `null`이 된다.
 * 빈 문자열은 버린다: 모든 위치에 매치돼 전체가 `<mark>`가 된다.
 */
export function snippetTermsFromFilter(filter: unknown): string[] {
  if (typeof filter !== "object" || filter === null || Array.isArray(filter)) return [];
  const f = filter as Record<string, unknown>;
  const out: string[] = [];
  for (const key of ["text", "subject", "body"]) {
    const v = f[key];
    if (typeof v === "string" && v.trim().length > 0) out.push(v.trim().toLowerCase());
  }
  return [...new Set(out)];
}
