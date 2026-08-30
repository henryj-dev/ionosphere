/**
 * 전체 명령 목록 — **이 배열이 관리 기능의 정의다.**
 *
 * 여기에 명령을 하나 넣으면 REST 라우트·CLI 서브커맨드·GUI 탭이 **동시에** 생긴다.
 * 반대로 말하면, 세 표면 중 어디에도 손으로 기능을 붙이지 않는다 — 그렇게 붙인 것은
 * 나머지 둘에서 빠지고, 빠진 자리는 "GUI로는 되는데 CLI로는 안 된다"로 나타난다.
 *
 * 순서가 GUI 탭 순서다. 자주 보는 것(사용량·계정)을 앞에, 서버 전역(TLS)을 뒤에 둔다.
 */
import { accountCommands } from "./accounts.ts";
import { domainCommands } from "./domains-cmd.ts";
import { opsCommands } from "./ops.ts";
import { ACCOUNT_STATUS, DOMAIN_STATUS, MTA_QUEUE_STATUS, SUPPRESSION_REASON } from "@ionosphere/db";
import { CommandRegistry } from "./dispatch.ts";
import type { Command } from "./types.ts";
import { sharedMailboxCommands } from "./shared-mailbox.ts";

export const ALL_COMMANDS: readonly Command[] = [...opsCommands, ...accountCommands, ...domainCommands, ...sharedMailboxCommands];

/** 기본 레지스트리. 테스트가 부분집합으로 만들 수 있게 인자를 열어 둔다. */
export function createRegistry(commands: readonly Command[] = ALL_COMMANDS): CommandRegistry {
  return new CommandRegistry(commands);
}

/**
 * 화면·CLI가 숫자를 사람 말로 옮기는 데 필요한 인코딩 — **명령 계층이 소유한다.**
 *
 * ★한때 관리 콘솔이 이 값들의 **자기 사본**을 들고 있었고 스키마와 어긋나 있었다: 0을 "대기",
 * 2를 "비활성"으로 표시했는데 실제로는 0=정지(가역), 2=삭제 드레인(비가역)이었다. 운영자가
 * "비활성화했다가 나중에 되살리지" 하고 누르면 **되돌릴 수 없는 삭제**였다.
 *
 * 정본(@ionosphere/db)에서 값을 가져오고 라벨만 여기 붙인다 — 인코딩이 바뀌면 화면이 따라오고,
 * 라벨 없는 새 값은 이름 그대로 드러난다(조용한 오표시보다 낯선 이름이 낫다).
 * 세 표면이 같은 것을 보므로 CLI의 `list-users`와 GUI의 계정 표가 같은 말을 한다.
 */
export const COMMAND_ENCODINGS = {
  accountStatus: {
    values: ACCOUNT_STATUS,
    labels: { suspended: "정지", active: "활성", deleting: "삭제 중" },
  },
  domainStatus: {
    values: DOMAIN_STATUS,
    labels: { unverified: "미검증", active: "활성", disabled: "비활성" },
  },
  queueStatus: {
    values: MTA_QUEUE_STATUS,
    labels: { queued: "대기", inFlight: "발송 중", done: "완료", bounced: "반송", deferred: "지연", canceled: "취소됨" },
  },
  suppressionReason: {
    values: SUPPRESSION_REASON,
    /**
     * 사유를 갈라 놓은 이유가 화면에서 드러나야 한다 — hardBounce는 **상대의 영구 거절**이고,
     * exhausted는 **우리가 못 보낸 것**(우리 쪽 DNS·네트워크 장애로도 걸린다)이라 해제해도
     * 되는 쪽이다. 둘을 같은 말로 보여주면 운영자가 평판을 깎는 쪽을 골라 해제한다.
     */
    labels: { hardBounce: "영구 거절(5xx)", exhausted: "재시도 소진" },
  },
} as const;

/** 저장 정수 → 사람이 읽는 라벨. 모르는 값은 숨기지 않고 그대로 보여준다(조용한 오표시 금지). */
export function labelFor(encoding: string | undefined, value: unknown): string {
  const enc = encoding ? (COMMAND_ENCODINGS as Record<string, { values: Record<string, number>; labels: Record<string, string> }>)[encoding] : undefined;
  if (!enc) return String(value);
  for (const name of Object.keys(enc.values)) {
    if (enc.values[name] === value) return enc.labels[name] ?? name;
  }
  return String(value);
}
