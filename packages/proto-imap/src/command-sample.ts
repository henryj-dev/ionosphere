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
 * 남기는 것을 재현했다. 모르는 명령은 무엇이 실렸는지 알 수 없으므로 이름만 남긴다 — 구현하지 않은
 * 확장(URLAUTH 토큰 등)도 같은 이유다. 계정 식별자(ACL)·검색어(SEARCH 계열)·클라이언트 정보(ID)를
 * 싣는 명령도 이름만 남긴다. 목록에 넣을 때는 "이 명령의 atom에 비밀이나 개인정보가 올 수 있는가"를 본다.
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
/** 모르는 명령 이름의 최대 길이 — 이름 자리에 무엇이든 보낼 수 있다. */
const MAX_UNKNOWN_NAME_CHARS = 32;

/**
 * 인자까지 남기는 명령. 라벨의 닫힌 집합(command-label.ts)이라 오타는 컴파일 에러다.
 * 여기 없는 명령(LOGIN·AUTHENTICATE·ACL 계열·SEARCH/SORT/THREAD·ID·unknown 등)은 이름만 남는다.
 */
const ARGS_LOGGED: ReadonlySet<ImapCommandLabel> = new Set<ImapCommandLabel>([
  "FETCH", "UID FETCH", "STORE", "UID STORE", "COPY", "UID COPY", "MOVE", "UID MOVE", "EXPUNGE", "UID EXPUNGE",
  "SELECT", "EXAMINE", "STATUS", "LIST", "LSUB", "CREATE", "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE",
  "APPEND", "ENABLE", "COMPRESS", "IDLE", "NOOP", "CHECK", "CLOSE", "UNSELECT", "LOGOUT", "CAPABILITY",
  "NAMESPACE", "STARTTLS", "GETQUOTA", "GETQUOTAROOT",
]);

const ELLIPSIS = "…";
const OMITTED = "[인자 생략]";

/** 출력 가능한 ASCII만 남긴다(공백 포함). */
function printable(s: string): string {
  return s.replace(/[^\x20-\x7e]/g, "?");
}

function render(v: ImapValue): string {
  switch (v.kind) {
    case "atom":
      // 거대한 시퀀스 집합 같은 긴 atom은 먼저 자른다 — 어차피 표본 길이에서 잘린다.
      return printable(v.value.slice(0, MAX_COMMAND_SAMPLE_CHARS + 1));
    case "quoted":
      return `"${ELLIPSIS}"`;
    case "literal":
      return `{${v.bytes.length}}`;
    case "list":
      return `(${joinValues(v.items)})`;
  }
}

/**
 * 공백으로 잇되, `]`로 시작하는 조각은 앞에 붙인다. 파서는 `BODY.PEEK[HEADER.FIELDS (FROM)]`를
 * atom·list·atom(`]`)으로 쪼개므로, 그냥 이으면 원문에 없던 공백이 끼어 "클라이언트가 이상한 공백을
 * 보냈다"로 잘못 읽힌다. 원문과 같은 모양이어야 표본이 진단에 쓸모 있다.
 * 길이를 넘으면 더 렌더하지 않는다 — 큰 목록 하나가 명령마다 긴 문자열을 만들지 않게.
 */
function joinValues(values: readonly ImapValue[]): string {
  let out = "";
  for (const v of values) {
    if (out.length > MAX_COMMAND_SAMPLE_CHARS) break;
    const part = render(v);
    out += out === "" || (v.kind === "atom" && part.startsWith("]")) ? part : ` ${part}`;
  }
  return out;
}

/**
 * 명령 이름과 인자 모양 — 태그는 빼고(진단에 쓸모없고 클라이언트마다 다르다) 길이를 자른다.
 * `rawName`은 엔진이 센 이름(UID면 하위 명령까지)이다. 모르는 명령은 그 이름만 정제해 남긴다.
 */
export function imapCommandSample(cmd: ParsedCommand, label: ImapCommandLabel, rawName: string): string {
  if (label === "unknown") return `${printable(rawName.slice(0, MAX_UNKNOWN_NAME_CHARS))} ${OMITTED}`;
  if (!ARGS_LOGGED.has(label)) return `${label} ${OMITTED}`;
  // UID 하위 명령은 라벨에 이미 있다 — 첫 인자(하위 명령 이름)를 빼고 잇는다.
  const args = cmd.name === "UID" ? cmd.args.slice(1) : cmd.args;
  const text = args.length > 0 ? `${label} ${joinValues(args)}` : label;
  return text.length > MAX_COMMAND_SAMPLE_CHARS ? `${text.slice(0, MAX_COMMAND_SAMPLE_CHARS)}${ELLIPSIS}` : text;
}
