/** subject_base 계산 (SCHEMA.md §5-2: VARCHAR(190), 스레딩 보조키 — 정확성 비필수). */

const MAX_LEN = 190;
// Re/Fwd/Fw/Aw(독일어)/Antwort + 선택적 [n] 카운터(Re[2]: 등), 대소문자 무관, 반복 제거.
// sticky(`y`)인 이유는 아래 참조 — `^` 대신 lastIndex가 "문자열 선두"를 대신한다.
const PREFIX_RE = /\s*(re|fw|fwd|aw|antwort)(\[\d+\])?\s*:\s*/iy;

export function computeSubjectBase(subject: string): string {
  // 접두사를 지울 때마다 `replace`로 **새 문자열을 만들면** 겹친 개수 × 길이만큼 복사가 난다.
  // `Re:`를 k번 겹친 제목은 그 자체로 O(길이²)가 되고, 제목 헤더 길이에는 상한이 없다
  // (192KB 입력에 788ms, 2026-07-31 실측 — 수신 상한 25MB까지 그대로 자란다).
  // 위치(lastIndex)만 앞으로 밀면 복사가 사라지고 마지막에 한 번만 자르면 된다.
  let at = 0;
  for (;;) {
    PREFIX_RE.lastIndex = at;
    if (PREFIX_RE.exec(subject) === null) break;
    at = PREFIX_RE.lastIndex;
  }
  const s = subject.slice(at).replace(/\s+/g, " ").trim();
  return s.length > MAX_LEN ? s.slice(0, MAX_LEN) : s;
}
