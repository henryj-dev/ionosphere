/**
 * 최소 HTML 태그/엔티티 제거 — text/html 폴백 미리보기 전용.
 * 알려진 한계: 완전한 HTML 파서가 아니다. 잘못 중첩된 태그·CDATA 등은 최선 노력으로만 처리.
 */

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
};

function decodeHtmlEntities(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, ent: string) => {
    if (ent.startsWith("#")) {
      const isHex = ent[1] === "x" || ent[1] === "X";
      const code = isHex ? Number.parseInt(ent.slice(2), 16) : Number.parseInt(ent.slice(1), 10);
      if (Number.isNaN(code) || code < 0 || code > 0x10ffff) return whole;
      try {
        return String.fromCodePoint(code);
      } catch {
        return whole;
      }
    }
    return NAMED_ENTITIES[ent] ?? whole;
  });
}

/** 내용까지 통째로 버리는 요소 — 태그만 지우면 스크립트 본문이 미리보기에 남는다. */
const RAW_TEXT_TAGS = ["script", "style"];

/** 닫는 태그 뒤의 `\s*>` — sticky라 지정한 위치에서만 맞춰 본다. */
const CLOSE_TAIL = /\s*>/y;

/**
 * `<script`/`<style` 블록의 끝(닫는 `>` 바로 다음) — 유효한 닫는 태그가 없으면 -1.
 * `</scriptX`처럼 `>`로 이어지지 않는 후보는 건너뛰고 계속 찾는다(원래 정규식의 lazy 반복과 동일).
 */
function findRawTextEnd(lower: string, tag: string, from: number): number {
  const close = `</${tag}`;
  let at = from;
  for (;;) {
    const idx = lower.indexOf(close, at);
    if (idx === -1) return -1;
    CLOSE_TAIL.lastIndex = idx + close.length;
    if (CLOSE_TAIL.exec(lower) !== null) return CLOSE_TAIL.lastIndex;
    at = idx + close.length;
  }
}

/**
 * 1단계: `<script>...</script>`·`<style>...</style>`를 **내용째로** 제거.
 *
 * ★1단계와 2단계를 섞지 말 것. 걷어낸 정규식은 raw-text 블록을 **문자열 전체에 대해 먼저**
 * 지운 뒤에야 일반 태그를 지웠다. 한 번의 패스로 합치면 `</scriptX<script>본문</script>`처럼
 * **여는 태그 앞에 `<`가 있는** 입력에서 `</scriptX<script>`가 일반 태그로 먼저 먹혀 여는 태그가
 * 사라지고, 그 결과 **스크립트 본문이 미리보기로 새어 나온다**. 실제로 그렇게 짰다가
 * 12만 건 퍼징에서 16,831건 불일치로 잡혔다(2026-07-31). 순서가 곧 동작이다.
 *
 * 2차식이 아닌 이유: 커서가 앞으로만 이동한다. 유일한 예외가 "닫는 태그를 끝내 못 찾는" 경우인데,
 * 그때는 못 찾았다는 사실을 기억해 두 번 훑지 않는다(검색 시작점이 뒤로 가지 않으므로 결과가
 * 뒤집히지 않는다). 이것이 없으면 닫히지 않은 `<script>` N개에 O(N × 길이)가 된다(512KB에 9.5초).
 */
function removeRawTextBlocks(html: string): string {
  const lower = html.toLowerCase();
  const exhausted = new Set<string>();
  let out = "";
  let plain = 0; // 아직 출력하지 않은 구간의 시작
  let i = 0;
  for (;;) {
    const lt = lower.indexOf("<", i);
    if (lt === -1) break;
    const tag = RAW_TEXT_TAGS.find((t) => lower.startsWith(t, lt + 1));
    if (tag === undefined || exhausted.has(tag)) {
      i = lt + 1;
      continue;
    }
    const end = findRawTextEnd(lower, tag, lt);
    if (end === -1) {
      // 닫는 태그가 없으면 이 여는 태그는 블록이 아니다 — 2단계가 일반 태그로 처리한다.
      exhausted.add(tag);
      i = lt + 1;
      continue;
    }
    out += `${html.slice(plain, lt)} `;
    i = end;
    plain = end;
  }
  return out + html.slice(plain);
}

/**
 * 2단계: 남은 `<...>`를 공백으로. 닫히지 않은 `<`는 **원문 그대로 둔다**(`<[^>]*>`와 같은 동작).
 *
 * 걷어낸 `<[^>]*>`는 `>`가 없으면 `<`마다 끝까지 갔다가 한 글자씩 되돌아와 2차식이었다
 * (64KB에 1.9초). 여기서는 `>`를 못 찾은 시점에 멈추므로 전체 스캔이 한 번뿐이다.
 */
function removeTags(html: string): string {
  let out = "";
  let plain = 0;
  let i = 0;
  for (;;) {
    const lt = html.indexOf("<", i);
    if (lt === -1) break;
    const gt = html.indexOf(">", lt + 1);
    if (gt === -1) break;
    out += `${html.slice(plain, lt)} `;
    i = gt + 1;
    plain = i;
  }
  return out + html.slice(plain);
}

export function stripHtml(html: string): string {
  const s = decodeHtmlEntities(removeTags(removeRawTextBlocks(html)));
  return s.replace(/\s+/g, " ").trim();
}
