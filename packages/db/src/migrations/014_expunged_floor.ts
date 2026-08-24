import type { Migration } from "../migrate.ts";

/**
 * 014 — `mailboxes.expunged_floor`: "이 modseq 아래의 삭제는 답할 수 없다"는 하한.
 *
 * ★`expunged` 툼스톤은 여태 **한 번도 지워지지 않았다**(메일함 통째 리핑 때만 사라졌다).
 * 지우지 못한 이유는 디스크가 아까워서가 아니라, QRESYNC(RFC 7162)의 `VANISHED`가 그
 * 테이블에서 나오는데 IMAP에 `changelog_floor` 같은 **하한을 알릴 장치가 없었기** 때문이다.
 * 그냥 지우면 오래 떠나 있던 클라이언트가 "삭제된 적 없다"는 답을 받고 유령 메시지를 영영
 * 들고 있게 된다 — 조용히 틀린 답이라 사용자가 알아차릴 방법도 없다.
 *
 * 이 컬럼이 그 하한이다. `runRetention`이 툼스톤을 지우기 **전에** 여기를 먼저 올리고
 * (`changelog_floor`와 같은 순서 — 반대면 "행은 없는데 floor는 낮은" 창이 생긴다),
 * `syncSince`가 이 값 아래의 요청을 다른 방법으로 답한다.
 *
 * ★그 "다른 방법"이 UIDVALIDITY 상향이 **아니다.** RFC 7162 §3.2.5.2가 이 상황을 위해
 * 이미 답을 두었다: 클라이언트가 준 known-uids(없으면 `1:uidnext-1`로 간주)에서 현재
 * 존재하는 uid를 빼면 사라진 uid가 정확히 나온다. 툼스톤이 없어도 답할 수 있고,
 * UIDVALIDITY를 올려 **모든** 클라이언트의 캐시를 버리게 만들 이유가 없다.
 *
 * 기본값 0은 "아직 아무것도 안 지웠다"이고, 모든 modseq가 0보다 크므로 기존 동작 그대로다.
 */
export const m014ExpungedFloor: Migration = {
  version: 14,
  name: "expunged_floor",
  statements: [`ALTER TABLE mailboxes ADD COLUMN expunged_floor BIGINT NOT NULL DEFAULT 0`],
};
