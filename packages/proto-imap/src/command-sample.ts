/**
 * BAD를 받은 명령의 **원문 표본** — 로그 전용(메트릭 라벨로 쓰지 말 것: 상대가 아무 문자열로 라벨을 늘린다).
 *
 * ★왜 필요한가(2026-10-05 v2026.10.05 배포 뒤 실측). UID FETCH가 5분마다 BAD 2건씩 꾸준히 쌓였는데
 * (누적 1802, 같은 창의 ok는 1건) 지표는 "UID FETCH가 BAD"까지만 말한다. **무엇을** 물었기에 BAD인지는
 * 원문이 있어야 안다. 10-02 NAMESPACE→LIST 루프도 같은 모양(광고와 구현의 어긋남 → 반복 BAD)이었고,
 * 그때도 원문이 없어 코드를 읽고 추측해야 했다.
 *
 * 무엇을 남기고 무엇을 가리는가:
 *  - **atom은 남긴다** — FETCH 항목·시퀀스·플래그·메일함 이름처럼 진단에 필요한 것이 다 atom이다.
 *  - **quoted·literal은 내용을 지운다** — 자유 문자열(검색어·메시지 본문·ID 값)이 여기로 온다.
 *    literal은 크기만(`{N}`), quoted는 자리만(`"…"`) 남겨 "무엇이 왔는지의 모양"은 보존한다.
 *  - **자격증명이 섞이는 명령은 인자를 통째로 뺀다**(`CREDENTIAL_COMMANDS`). LOGIN의 비밀번호는 atom으로도
 *    올 수 있어서(RFC 9051 astring) 위 규칙만으로는 새어 나간다.
 *  - 제어문자·비ASCII는 `?`로 바꾸고 길이를 자른다 — journal 한 줄을 깨뜨리거나 키우지 못하게.
 */
import type { ImapValue, ParsedCommand } from "./parser.ts";

/** 표본 한 줄의 최대 길이 — FETCH 항목 목록 하나는 충분히 담고, 거대한 시퀀스 집합은 자른다. */
export const MAX_COMMAND_SAMPLE_CHARS = 200;

/**
 * 인자를 남기지 않는 명령. AUTHENTICATE는 SASL-IR(RFC 4959)로 첫 응답(자격증명)을 인자에 싣는다.
 * 새 명령이 자격증명을 받으면 여기에 넣는다 — 빠뜨리면 그 명령이 BAD일 때 journal에 남는다.
 */
const CREDENTIAL_COMMANDS: ReadonlySet<string> = new Set(["LOGIN", "AUTHENTICATE"]);

const ELLIPSIS = "…";

/** 출력 가능한 ASCII만 남긴다(공백 포함). */
function printable(s: string): string {
  return s.replace(/[^\x20-\x7e]/g, "?");
}

function render(v: ImapValue): string {
  switch (v.kind) {
    case "atom":
      return printable(v.value);
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
 */
function joinValues(values: readonly ImapValue[]): string {
  let out = "";
  for (const v of values) {
    const part = render(v);
    out += out === "" || (v.kind === "atom" && part.startsWith("]")) ? part : ` ${part}`;
  }
  return out;
}

/** 명령 이름과 인자 모양 — 태그는 빼고(진단에 쓸모없고 클라이언트마다 다르다) 길이를 자른다. */
export function imapCommandSample(cmd: ParsedCommand): string {
  const name = printable(cmd.name);
  if (CREDENTIAL_COMMANDS.has(cmd.name)) return `${name} [인자 생략]`;
  const text = cmd.args.length > 0 ? `${name} ${joinValues(cmd.args)}` : name;
  return text.length > MAX_COMMAND_SAMPLE_CHARS ? `${text.slice(0, MAX_COMMAND_SAMPLE_CHARS)}${ELLIPSIS}` : text;
}
