/**
 * BAD를 받은 명령의 **원문 표본** — 로그 전용(메트릭 라벨로 쓰지 말 것: 상대가 아무 문자열로 라벨을 늘린다).
 *
 * ★왜 필요한가(2026-10-05 v2026.10.05 배포 뒤 실측). UID FETCH가 5분마다 BAD 2건씩 꾸준히 쌓였는데
 * (누적 1802, 같은 창의 ok는 1건) 지표는 "UID FETCH가 BAD"까지만 말한다. **무엇을** 물었기에 BAD인지는
 * 원문이 있어야 안다. 10-02 NAMESPACE→LIST 루프도 같은 모양(광고와 구현의 어긋남 → 반복 BAD)이었고,
 * 그때도 원문이 없어 코드를 읽고 추측해야 했다.
 *
 * ★인자는 **허용 목록**(`ARGS_LOGGED`)에 있는 명령만 남긴다. 처음엔 LOGIN·AUTHENTICATE만 빼는 제외
 * 목록이었는데, 독립 리뷰가 `UID LOGIN user secret`(모르는 UID 하위 명령 → BAD)이 비밀번호를 그대로
 * 남기는 것을 재현했다. 2차 리뷰는 두 가지를 더 찾았다:
 *  - **모르는 명령은 이름도 남기지 않는다.** `UID "secret"`은 하위 이름 자리로 quoted 내용이 복원됐고,
 *    태그 없이 친 `user private-password`는 비밀번호가 명령 이름 자리에 온다. 이름만으로는 구별할 수 없다.
 *  - **허용 목록은 표준 문법(확장 포함)에 자격증명을 싣는 자리가 없는 명령만**이다. 헤더 필드 이름처럼
 *    자유로운 이름은 올 수 있고, 잘못된 명령의 임의 atom은 그대로 남는다 — 그건 수용한 범위다.
 *    명령 이름을 허용해도 그 안의 확장 인자는 무엇이든
 *    올 수 있다 — APPEND CATENATE의 URLAUTH 토큰이 그대로 남았다. 그래서 APPEND·STORE(자유 keyword)·
 *    메일함 조작(COPY·RENAME 등 — 진단에 필요 없는 메일함 이름)은 뺐다.
 * 목록에 넣을 때는 "이 명령의 표준 확장까지 포함해 atom에 비밀이나 자유 텍스트가 올 수 있는가"를 본다.
 *
 * 허용된 명령 안에서는:
 *  - **atom은 남긴다** — FETCH 항목·시퀀스·플래그·메일함 이름처럼 진단에 필요한 것이 다 atom이다.
 *  - **quoted·literal은 내용을 지운다** — literal은 크기만(`{N}`), quoted는 자리만(`"…"`) 남긴다.
 *  - 제어문자·비ASCII는 `?`로 바꾸고 길이를 자른다 — journal 한 줄을 깨뜨리거나 키우지 못하게.
 */
import type { ImapCommandLabel } from "./command-label.ts";
import type { ImapValue, ParsedCommand } from "./parser.ts";

/** 표본 한 줄의 최대 길이 — FETCH 항목 목록 하나는 충분히 담고, 거대한 시퀀스 집합은 자른다. */
export const MAX_COMMAND_SAMPLE_CHARS = 200;

/**
 * 인자까지 남기는 명령 — 라벨의 닫힌 집합(command-label.ts)이라 오타는 컴파일 에러다.
 *  - FETCH·UID FETCH: 시퀀스 + FETCH 항목·헤더 필드 이름·수치(CHANGEDSINCE 등). 이번 조사의 대상이다.
 *  - STATUS: 메일함 + STATUS 항목. SELECT·EXAMINE: 메일함 + CONDSTORE/QRESYNC 파라미터(수치·시퀀스).
 *  - LIST·LSUB: 참조·패턴 + 선택/반환 옵션 — 10-02 LIST-EXTENDED 루프가 바로 이 모양이었다.
 *  - ENABLE: capability 이름. COMPRESS: 알고리즘 이름.
 * 메일함 이름은 남는다 — 위 명령의 BAD를 읽으려면 필요하다(사용자 결정 2026-10-05: 자격증명만 제외).
 * 여기 없는 명령은 라벨 이름만 남는다.
 */
const ARGS_LOGGED: ReadonlySet<ImapCommandLabel> = new Set<ImapCommandLabel>([
  "FETCH", "UID FETCH", "STATUS", "SELECT", "EXAMINE", "LIST", "LSUB", "ENABLE", "COMPRESS",
]);

const ELLIPSIS = "…";
const OMITTED = "[인자 생략]";

/** 출력 가능한 ASCII만 남긴다(공백 포함). */
function printable(s: string): string {
  return s.replace(/[^\x20-\x7e]/g, "?");
}

/**
 * `room`은 남은 글자 수다. 중첩 목록까지 **같은 예산을 나눠 쓴다** — 목록마다 따로 200자를 쓰면 깊은
 * 중첩에서 렌더 비용이 표본 길이와 무관하게 커진다(2차 리뷰). 넘친 만큼은 마지막에 잘린다.
 */
function render(v: ImapValue, room: number): string {
  switch (v.kind) {
    case "atom":
      // 거대한 시퀀스 집합 같은 긴 atom은 먼저 자른다 — 어차피 표본 길이에서 잘린다.
      return printable(v.value.slice(0, room));
    case "quoted":
      return `"${ELLIPSIS}"`;
    case "literal":
      return `{${v.bytes.length}}`;
    case "list":
      return `(${joinValues(v.items, room - 1)})`;
  }
}

/**
 * 공백으로 잇되, `]`로 시작하는 조각은 앞에 붙인다. 파서는 `BODY.PEEK[HEADER.FIELDS (FROM)]`를
 * atom·list·atom(`]`)으로 쪼개므로, 그냥 이으면 원문에 없던 공백이 끼어 "클라이언트가 이상한 공백을
 * 보냈다"로 잘못 읽힌다. 원문과 같은 모양이어야 표본이 진단에 쓸모 있다.
 * 예산을 다 쓰면 더 렌더하지 않는다.
 */
function joinValues(values: readonly ImapValue[], room: number): string {
  let out = "";
  for (const v of values) {
    if (out.length >= room) break;
    const part = render(v, room - out.length);
    out += out === "" || (v.kind === "atom" && part.startsWith("]")) ? part : ` ${part}`;
  }
  return out;
}

/**
 * 명령 라벨과 인자 모양 — 태그는 빼고(진단에 쓸모없고 클라이언트마다 다르다) 최대 200자로 자른다.
 * 이름도 클라이언트 문자열이 아니라 **라벨**(닫힌 집합)을 쓴다. 모르는 명령은 "unknown"뿐이다.
 */
export function imapCommandSample(cmd: ParsedCommand, label: ImapCommandLabel): string {
  if (!ARGS_LOGGED.has(label)) return `${label} ${OMITTED}`;
  // UID 하위 명령은 라벨에 이미 있다 — 첫 인자(하위 명령 이름)를 빼고 잇는다.
  const args = cmd.name === "UID" ? cmd.args.slice(1) : cmd.args;
  const text = args.length > 0 ? `${label} ${joinValues(args, MAX_COMMAND_SAMPLE_CHARS - label.length)}` : label;
  return text.length > MAX_COMMAND_SAMPLE_CHARS ? `${text.slice(0, MAX_COMMAND_SAMPLE_CHARS - 1)}${ELLIPSIS}` : text;
}
