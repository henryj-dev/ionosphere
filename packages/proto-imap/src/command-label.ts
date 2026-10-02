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
