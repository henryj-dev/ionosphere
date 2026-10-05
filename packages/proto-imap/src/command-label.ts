/**
 * IMAP 명령 → 메트릭 라벨. **닫힌 집합**이다.
 *
 * ★왜 필요한가(2026-10-01 사서함 호스트): IMAP 세션 두 개가 초당 95회·61회 왕복을 돌았는데
 * 우리 지표에는 흔적이 없었다. 감사 이벤트는 **백엔드 요청에만** 남는데, IDLE/DONE·NOOP(메일함
 * 미선택)·CAPABILITY·ID·ENABLE·NAMESPACE와 모든 BAD 응답은 엔진 안에서 끝나 백엔드를 부르지
 * 않는다. 그래서 명령 단위로 따로 센다.
 *
 * ★라벨을 닫는 이유: 클라이언트가 보낸 명령 이름을 그대로 라벨로 쓰면, 아무 문자열이나 보내는
 * 상대가 라벨 조합을 무한히 늘려 메트릭 저장소를 채울 수 있다(카디널리티 공격). 엔진이 아는
 * 명령만 이름을 쓰고 나머지는 "unknown" 하나로 묶는다. 엔진에 명령을 추가하면 여기도 추가한다 —
 * 빠지면 "unknown"으로 세어질 뿐(안전) 새지는 않는다.
 */
import { valueText, type ParsedCommand } from "./parser.ts";

export const IMAP_COMMAND_LABELS = [
  "APPEND", "AUTHENTICATE", "CAPABILITY", "CHECK", "CLOSE", "COMPRESS", "COPY", "CREATE", "DELETE",
  "DELETEACL", "ENABLE", "EXAMINE", "EXPUNGE", "FETCH", "GETACL", "GETQUOTA", "GETQUOTAROOT", "ID",
  "IDLE", "LIST", "LISTRIGHTS", "LOGIN", "LOGOUT", "LSUB", "MOVE", "MYRIGHTS", "NAMESPACE", "NOOP",
  "RENAME", "REPLACE", "SEARCH", "SELECT", "SETACL", "SETQUOTA", "SORT", "STARTTLS", "STATUS", "STORE",
  "SUBSCRIBE", "THREAD", "UNSELECT", "UNSUBSCRIBE",
  // UID 접두 명령은 하위 명령까지 붙인다 — "UID"만으로는 FETCH 폭주와 STORE 폭주를 가를 수 없다.
  "UID FETCH", "UID STORE", "UID SEARCH", "UID SORT", "UID THREAD", "UID COPY", "UID MOVE", "UID EXPUNGE", "UID REPLACE",
] as const;

export type ImapCommandLabel = (typeof IMAP_COMMAND_LABELS)[number] | "unknown";

const KNOWN = new Set<string>(IMAP_COMMAND_LABELS);

export function imapCommandLabel(cmd: ParsedCommand): ImapCommandLabel {
  let name = cmd.name;
  if (name === "UID") {
    const sub = cmd.args[0] ? valueText(cmd.args[0])?.toUpperCase() : undefined;
    name = sub ? `UID ${sub}` : "UID";
  }
  return KNOWN.has(name) ? (name as ImapCommandLabel) : "unknown";
}

/**
 * 구현하지 않았지만 **이름이 알려진** IMAP 명령 — 세션 요약의 모르는 명령 표본(`unknownCommands`)에
 * 이름 그대로 남는다. 여기 없는 이름은 `UNLISTED_COMMAND_NAME` 하나로 센다.
 *
 * ★왜 허용 목록인가(2026-10-05 BAD 표본 PR의 3차 리뷰): 표본은 클라이언트가 보낸 이름을 대문자로
 * 정제해 남겼는데, 태그 없이 친 `user private-password`는 둘째 단어가 명령 이름 자리에 와서
 * `PRIVATE-PASSWORD`로 남았다. 이름만으로는 오타 명령과 비밀을 구별할 수 없다. 그래서 남는 이름을
 * **출처가 확인된 유한한 어휘**로 제한한다 — 임의 문자열은 남지 않는다(비밀번호가 우연히 `notify`라면
 * 그 단어는 남는다. 보장은 "어휘 밖은 안 남는다"까지다). "어떤 확장을 기대하는 클라이언트인가"를 아는
 * 데는 이것으로 충분하다. 클라이언트가 새 확장을 쓰기 시작하면 OTHER가 늘고, 그때 원문은 BAD 표본
 * (command-sample.ts)이 아니라 클라이언트 쪽에서 확인해 여기 추가한다.
 */
const KNOWN_UNIMPLEMENTED_COMMANDS: ReadonlySet<string> = new Set([
  // RFC 확장
  "GETMETADATA", "SETMETADATA", // RFC 5464 METADATA
  "URLFETCH", "GENURLAUTH", "RESETKEY", // RFC 4467 URLAUTH
  "NOTIFY", // RFC 5465
  "CANCELUPDATE", // RFC 5267 CONTEXT
  "CONVERT", // RFC 5259
  "ESEARCH", // RFC 7377 MULTISEARCH
  "LANGUAGE", "COMPARATOR", // RFC 5255 I18NLEVEL
  "UNAUTHENTICATE", // RFC 8437
  "GETANNOTATION", "SETANNOTATION", // ANNOTATEMORE 초안
  // 주요 구현의 비표준 명령
  "XLIST", // Gmail 구형 특수 폴더 목록
  "XAPPLEPUSHSERVICE", // Apple 메일 푸시(Dovecot XAPS 플러그인)
]);

/** 허용 목록 밖의 모르는 명령 이름 — 무엇이 왔는지 남기지 않는다. */
export const UNLISTED_COMMAND_NAME = "OTHER";

/**
 * 모르는 명령의 요약용 이름. UID 하위 명령은 atom이고 목록에 있을 때만 이름을 남긴다 — quoted·literal은
 * 원문으로 되살아나므로(valueText) 보지 않는다.
 */
export function imapUnknownCommandName(cmd: ParsedCommand): string {
  if (cmd.name === "UID") {
    const first = cmd.args[0];
    const sub = first?.kind === "atom" ? first.value.toUpperCase() : null;
    return sub !== null && KNOWN_UNIMPLEMENTED_COMMANDS.has(sub) ? `UID ${sub}` : `UID ${UNLISTED_COMMAND_NAME}`;
  }
  return KNOWN_UNIMPLEMENTED_COMMANDS.has(cmd.name) ? cmd.name : UNLISTED_COMMAND_NAME;
}
