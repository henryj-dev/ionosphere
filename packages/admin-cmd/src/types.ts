/**
 * 관리 명령 계층의 **계약** — GUI·API·CLI 세 어댑터가 공유하는 정본.
 *
 * 왜 이 계층이 생겼나: 예전에는 관리 로직이 두 곳에 **복제**돼 있었다. `cli.ts add-domain`과
 * `api/server.ts createDomain`이 각자 DKIM을 만들고 각자 batch를 조립했고, 그래서
 * "CLI로 만든 도메인은 verify_token이 없어 나중에 API로 재검증할 수 없다" 같은 갈라짐이
 * 생겼다(cli.ts 주석이 그 사고를 증언한다). 한쪽에 기능을 넣으면 다른 쪽은 조용히 뒤처졌다 —
 * 계정 정지가 자동 집행(mta/abuse.ts)에는 있는데 사람이 쓸 입구는 어디에도 없던 것이 그 예다.
 *
 * 그래서 **명령을 한 번 정의하면 세 표면에 동시에 생기도록** 방향을 뒤집었다:
 *
 *     GUI(무상태) ──HTTP──> API(인증·HTTP 매핑) ──직접호출──> 명령 계층 ──> store/db
 *                                                    CLI(argv·stdin) ──┘
 *
 * 이 계층의 규율:
 *  - **I/O를 모른다.** HttpError도 process.exit도 없다. 실패는 `CommandError`로만 표현하고
 *    어댑터가 각자의 언어(HTTP 상태코드 / 종료코드)로 옮긴다. 엔진/어댑터 분리와 같은 규율이다.
 *  - **인가를 하지 않는다.** 스코프·root 판정은 API의 몫이다. 다만 테넌트 경계는 여기서 지킨다
 *    (`tenantId`를 인자로 받아 SQL에 싣는다) — 그것을 어댑터에 맡기면 표면마다 빠뜨릴 수 있고,
 *    빠진 자리는 "남의 테넌트 자원이 보인다"로 조용히 나타난다.
 *  - **자기 자신을 서술한다.** `describeCommands()`가 이름·인자·설명을 내놓아 GUI가 화면을
 *    그리고 CLI가 usage를 찍는다. 명령을 추가하면 두 화면이 자동으로 따라온다.
 */
import type { DbDriver } from "@ionosphere/db";
import type { Store } from "@ionosphere/store";

/**
 * 명령 실패 — 어댑터가 옮길 수 있도록 **분류**를 들고 다닌다.
 *
 * ★HTTP 상태코드를 여기 두지 않는 이유: 이 계층은 HTTP를 모른다. 그런데 분류마저 없으면
 * 어댑터가 메시지 문자열을 보고 상태코드를 추측하게 되고(과거 API가 StoreError를 전부 400으로
 * 뭉갠 것이 그 모양이다) 404여야 할 것이 400이 된다. 분류는 도메인 언어로 두고 매핑은 어댑터가 한다.
 */
export type CommandFailure =
  /** 인자가 없거나 형식이 틀림 → HTTP 400 / CLI usage */
  | "invalid"
  /** 대상이 없음 → HTTP 404 */
  | "notFound"
  /** 이미 있거나 다른 자원이 잡고 있음 → HTTP 409 */
  | "conflict"
  /** 이 주체가 할 수 없음(테넌트 경계 위반 등) → HTTP 403 */
  | "denied"
  /** 이 배포에 그 기능이 없음(TLS 미구성 등) → HTTP 501 */
  | "unavailable";

export class CommandError extends Error {
  readonly kind: CommandFailure;
  /** 사람이 다음 행동을 알 수 있게 하는 힌트 — CLI가 stderr 둘째 줄에 찍고 API는 무시한다. */
  readonly hint: string | undefined;
  constructor(kind: CommandFailure, message: string, hint?: string) {
    super(message);
    this.name = "CommandError";
    this.kind = kind;
    this.hint = hint;
  }
}

/**
 * 명령이 받는 인자 하나의 서술.
 *
 * GUI가 이걸로 입력 폼을 그리고, CLI가 usage를 찍고, 디스패처가 검증한다 — **세 곳이 같은
 * 서술을 본다**는 것이 요점이다. 예전에 UI가 상태 인코딩 사본을 들고 스키마와 어긋났던 것과
 * 같은 종류의 사고를 구조적으로 막는다.
 */
export interface ArgSpec {
  name: string;
  /** 화면에 보일 한국어 라벨. */
  label: string;
  /**
   * `secret`은 GUI에서 `type=password`, CLI에서 **argv 대신 stdin/env**로 받는다.
   * argv는 같은 호스트의 다른 사용자에게 `ps`로 그대로 보이고 셸 히스토리에도 남는다.
   */
  type: "string" | "secret" | "number" | "boolean" | "enum";
  required: boolean;
  /** `type: "enum"`일 때의 선택지 — GUI가 select를 그린다. */
  choices?: readonly { value: string; label: string }[];
  placeholder?: string;
  /** 왜 이 값이 필요한지 / 무엇을 조심해야 하는지. GUI가 입력 아래에 작게 붙인다. */
  help?: string;
  /**
   * 값을 여러 개 받는다(콤마로 이어 붙인 문자열 하나로 전달된다).
   *
   * ★어댑터가 이걸 봐야 하는 이유: CLI의 `add-alias <주소> <대상> <대상> ...`처럼 **남은 위치
   * 인자를 전부 이 인자에 몰아줘야** 하는 자리가 있다. 이 표시가 없으면 첫 대상만 반영되고
   * 나머지는 조용히 사라진다 — 팬아웃 알리아스가 반쪽으로 만들어지는 사고다.
   */
  variadic?: boolean;
}

/** 결과 표의 컬럼 하나 — GUI가 이걸로 테이블을 그린다(컬럼 목록을 화면에 하드코딩하지 않게). */
export interface FieldSpec {
  key: string;
  label: string;
  /** `bytes`·`time`은 GUI가 사람이 읽는 형태로 바꾼다(생 숫자 12자리를 눈으로 비교하지 않게). */
  format?: "text" | "bytes" | "time" | "number";
  /**
   * 이 컬럼이 쓰는 상태 인코딩의 이름(`accountStatus`·`queueStatus` 등).
   *
   * ★어댑터가 컬럼 이름으로 **추측하지 않게** 하려고 둔다. 예전 화면은 `status`라는 이름과
   * 지금 보고 있는 탭으로 어느 인코딩인지 짐작했는데, 그런 규칙은 표가 하나 늘면 조용히
   * 틀린다 — 그리고 틀린 결과가 "0=대기"처럼 **그럴듯한 오표시**로 나타난다.
   */
  encoding?: string;
}

/**
 * 명령 하나의 서술.
 *
 * `destructive`가 참이면 GUI가 2단계 확인 버튼을 그린다 — 이 값을 화면이 아니라 **명령이**
 * 들고 있는 이유는, 새 파괴적 명령을 추가한 사람이 화면 코드를 잊어도 확인 단계가 따라오게
 * 하기 위해서다. `irreversible`은 그중에서도 되돌릴 수 없는 것(삭제 드레인 등)이다.
 */
export interface CommandSpec {
  name: string;
  /** 화면 그룹 — GUI 탭이 이것으로 만들어진다. */
  group: string;
  label: string;
  summary: string;
  /** 조회 명령인가. API가 GET/POST를 가르고 스코프(read/write)를 정하는 근거다. */
  readOnly: boolean;
  destructive?: boolean;
  irreversible?: boolean;
  /** root 토큰 전용(테넌트 키로는 불가) — 서버 전역 자원을 만지는 명령. */
  rootOnly?: boolean;
  args: readonly ArgSpec[];
  /** 결과가 표라면 그 컬럼들. 단일 객체 결과면 생략. */
  fields?: readonly FieldSpec[];
}

/** 명령이 돌려주는 것 — 표(rows) 또는 단일 객체(data), 그리고 사람에게 할 말. */
export interface CommandResult {
  /** 목록형 결과. */
  rows?: readonly Record<string, unknown>[];
  /** 단일 결과(생성된 id, 상태 등). */
  data?: Record<string, unknown>;
  /** 사람이 읽는 한 줄 — CLI가 stdout에 찍고 GUI가 토스트로 띄운다. */
  message?: string;
  /**
   * **다시 볼 수 없는 평문**(앱 비밀번호·API 키). 서버는 해시만 보관한다.
   * 일반 `data`와 나눠 두면 GUI가 강조 블록으로 그리고 로그·감사에서 걸러낼 수 있다.
   */
  secret?: { label: string; value: string; hint?: string };
}

/** 명령이 실행될 때 받는 문맥 — 어댑터가 채운다. */
export interface CommandContext {
  db: DbDriver;
  store: Store;
  /**
   * 이 명령이 작용할 테넌트. **명령 계층이 SQL에 싣는다**(어댑터에 맡기지 않는다).
   * root 주체가 테넌트를 지정하지 않은 cross-tenant 조회에서만 undefined다.
   */
  tenantId: string | undefined;
  /** root 주체인가 — `rootOnly` 명령의 통과 여부는 어댑터가 판정하지만, 조회 범위는 여기서 갈린다. */
  isRoot: boolean;
  /** DKIM 개인키·릴레이 비밀번호 봉인용. 미지정 시 평문 저장(dev 전용). */
  masterKey?: string | undefined;
  /** DNS 조회 — 도메인 검증 명령이 쓴다. 조립층이 주입(테스트는 가짜). */
  resolveTxt?: ((name: string) => Promise<string[]>) | undefined;
  resolveMx?: ((name: string) => Promise<{ exchange: string; preference: number }[]>) | undefined;
  /** TLS 관리 — 서버 전역이라 조립층만 줄 수 있다. 없으면 관련 명령은 `unavailable`. */
  tls?: TlsAdminPort | undefined;
  /** shared mailbox 관리 포트 — 실제 directory/blob/cache 구현을 조립층에서 주입한다. */
  sharedMailbox?: SharedMailboxAdminPort | undefined;
  /** 입력값을 기록하지 않는 운영 관측 포트. */
  observer?: AdminObserver | undefined;
}

export interface SharedMailboxAdminPort {
  sync(tenantId: string, provider: string): Promise<CommandResult>;
  rebuildHeaders(batchSize: number | undefined): Promise<CommandResult>;
  flushListingCache(): Promise<CommandResult>;
}

export interface AdminObserver {
  record(event: AdminObservation): void;
}

export interface AdminObservation {
  operation: string;
  outcome: "ok" | "fail";
  reason: "success" | CommandFailure;
}

/**
 * TLS 관리 포트 — 명령 계층은 인증서를 **어떻게** 얻는지 모른다(ACME인지 파일인지 봉인인지).
 * 그건 조립층의 결정이고, 여기서는 "상태를 묻고 갱신을 요청한다"만 안다.
 */
export interface TlsAdminPort {
  status(): Promise<Record<string, unknown>>;
  refresh(): Promise<Record<string, unknown>>;
  upload?(certPem: string, keyPem: string): Promise<Record<string, unknown>>;
}

/** 명령 구현 — 서술과 실행을 한 곳에 묶는다(따로 두면 한쪽만 고쳐지는 것이 이 저장소의 사고 패턴). */
export interface Command {
  spec: CommandSpec;
  run(ctx: CommandContext, args: Readonly<Record<string, string>>): Promise<CommandResult>;
}
