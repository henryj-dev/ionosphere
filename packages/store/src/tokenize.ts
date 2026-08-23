/**
 * 검색 토크나이저 (SCHEMA.md §8): NFKC 정규화 → 케이스폴드 → CJK 바이그램 + 라틴 단어.
 *
 * 케이스폴드 근사: 완전한 유니코드 케이스폴드는 JS 표준 라이브러리에 없다. 실용적
 * 근사로 String.prototype.toLowerCase()를 쓴다 — 대부분의 언어에는 충분하지만
 * 터키어 dotless-i 같은 로케일 특수 규칙은 반영하지 않는다(v1에서는 수용 가능한 근사).
 */
import { StoreError } from "./errors.ts";

/** search_index.token / message_text 매칭 상한 — 라틴 단어 토큰만 여기 걸린다.
 *  CJK 바이그램은 항상 ≤2자라 이 한도 아래다. */
const MAX_TOKEN_LENGTH = 16;

/**
 * 색인 입력 길이 상한(코드포인트). 이 파일이 두 상한의 단일 소유자다 —
 * 색인 경로(store.indexSearchText)와 검색 경로(store.search / queryEmails)가
 * 같은 토크나이저를 공유하므로 상한도 한 곳에 둔다.
 *
 * 왜 필요한가: CJK 바이그램은 n글자에서 n-1개 토큰을 만들고, 서로 다른 음절 조합이
 * 11172^2가지라 중복 제거가 거의 듣지 않는다. 색인 대상은 미인증 원격이 보낸 메일
 * 본문이라 상한이 없으면 25MB(MAX_MESSAGE_BYTES) 한글 본문 한 통이
 * 8058394개 토큰 · RSS 1.3GB를 만들고, 전 프로토콜이 한 프로세스라 그 OOM은 메일 서비스
 * 전체 중단이다(heap 512MB/768MB 제한에서 실제로 죽는 것을 확인).
 *
 * 디스크 축(2026-07-31 실제 DB 파일 크기로 실측 — 외삽 아님): 행당 **143~150바이트**다.
 * 이 테이블은 전 컬럼이 PRIMARY KEY라(account_id·token·field·message_id) 26자 계정 id와
 * 26자 메시지 id가 포스팅마다 저장되고 별도 페이로드가 없다 — 인덱스가 곧 데이터다.
 * 상한이 없으면 25MB 본문 한 통이 **1,169.7MB**(VACUUM 후 1,104.4MB)를 쓴다.
 * ※이전 주석은 행당 60B를 가정해 484MB라 적고 "(실측)"이라 표시했는데, 그건 **행 수만** 실측한
 *   계산값이었고 실제보다 2.4배 낮았다. 계산을 실측이라 적으면 다음 사람이 재보지 않는다.
 *
 * 값 근거: 64Ki자는 한국어 산문 20쪽 이상이라 정상 메일이 검색에서 누락되지 않으면서,
 * **필드당** 최악 토큰 수를 64Ki개(≈9.9MB)로 묶는다. 상한은 `tokenize()` 호출 단위이므로
 * 메시지 하나의 최악은 4필드(subject·body·from·to)만큼 곱해져 **262,082행 / 38.6MB**다
 * (실측 — 정확히 4배). 상한 없을 때의 1,169.7MB 대비 **약 30배** 줄어든다.
 */
const MAX_INDEX_TEXT_CHARS = 64 * 1024;

/**
 * 질의 문자열 길이 상한(코드포인트). 색인 상한보다 훨씬 작아도 되는 이유:
 * 호출자(store.search / queryEmails)가 이미 토큰 수를 97개
 * (MAX_PARAMS_PER_STATEMENT - 3)로 제한하고 있어, 이보다 긴 질의는 어차피 거부된다.
 * 문제는 그 검사가 tokenize **이후**라 거부 전에 이미 비용을 다 치른다는 점이었다 —
 * 상한을 앞으로 당겨 거부를 싸게 만든다.
 */
const MAX_QUERY_CHARS = 4096;

/** CJK 스크립트 문자 판별 — Unicode property escape (SCHEMA.md §8: Han/Hiragana/Katakana/Hangul). */
const CJK_CHAR_RE = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u;
/** 라틴/숫자 단어 문자 — 글자 또는 숫자(CJK 여부는 별도 우선 판정). */
const WORD_CHAR_RE = /[\p{L}\p{N}]/u;

type CharKind = "cjk" | "word" | "other";

function classify(ch: string): CharKind {
  if (CJK_CHAR_RE.test(ch)) return "cjk";
  if (WORD_CHAR_RE.test(ch)) return "word";
  return "other";
}

/**
 * 텍스트 → 토큰 집합(중복 제거 — v1은 불리언 검색이라 위치/빈도 불필요).
 * - CJK 런: 2자 슬라이딩 윈도 바이그램(중첩). 런 길이가 1이면 그 글자 자체를 1-gram으로 방출.
 * - 라틴/숫자 런: 런 전체를 단어 토큰 하나로(비영숫자 경계로 분리한 것과 동치),
 *   VARCHAR(16) 한도에 맞춰 자른다.
 */
export function tokenize(text: string): string[] {
  // 상한 초과분은 버린다(throw 아님) — 색인은 부가 기능이고 호출자는 메일 저장·배달 경로다.
  // 긴 본문에서 뒷부분이 검색되지 않는 것 < 메일 유실·배달 실패.
  // NFKC 이전에 먼저 자르는 이유: 25MB 문자열 정규화 자체가 비용이라 뒤에서 자르면 늦다.
  // NFKC는 길이를 늘릴 수 있으므로(합자·전각 분해) 정규화 후 코드포인트 단위로 한 번 더 자른다.
  const sliced = text.length > MAX_INDEX_TEXT_CHARS ? text.slice(0, MAX_INDEX_TEXT_CHARS) : text;
  const normalized = sliced.normalize("NFKC").toLowerCase();
  const all = Array.from(normalized); // 코드포인트 단위 순회(서로게이트 쌍 안전)
  const chars = all.length > MAX_INDEX_TEXT_CHARS ? all.slice(0, MAX_INDEX_TEXT_CHARS) : all;
  const tokens = new Set<string>();

  let i = 0;
  while (i < chars.length) {
    const kind = classify(chars[i]!);
    if (kind === "other") {
      i++;
      continue;
    }

    let j = i + 1;
    while (j < chars.length && classify(chars[j]!) === kind) j++;
    const run = chars.slice(i, j);

    if (kind === "cjk") {
      if (run.length === 1) {
        tokens.add(run[0]!);
      } else {
        for (let k = 0; k < run.length - 1; k++) {
          tokens.add(run[k]! + run[k + 1]!);
        }
      }
    } else {
      const word = run.join("").slice(0, MAX_TOKEN_LENGTH);
      if (word.length > 0) tokens.add(word);
    }
    i = j;
  }

  return [...tokens];
}

/**
 * 질의 토크나이저 — 색인과 동일 규칙이어야 매칭된다(토큰 생성 규칙은 tokenize와 동일).
 *
 * 색인 경로와 실패 방식이 다른 것은 의도다: 질의를 조용히 자르면 토큰이 줄어
 * **더 넓게** 매칭돼 사용자가 틀린 결과를 맞는 결과로 오해한다. 호출자가 이미
 * 토큰 과다를 StoreError로 거부하고 있으므로 길이 초과도 같은 방식으로 거부한다.
 */
export function tokenizeQuery(query: string): string[] {
  if (query.length > MAX_QUERY_CHARS) {
    throw new StoreError(`search query too long (max ${MAX_QUERY_CHARS} chars)`);
  }
  return tokenize(query);
}
