/**
 * Sieve 평가기 (RFC 5228 §2/§4/§5). 파싱된 스크립트를 메시지 환경에 대해 실행 → 배달 지시.
 * 순수 함수 — 부수효과 없음. 지원: 베이스(if/elsif/else/stop/require, keep/discard/fileinto/
 * redirect) + fileinto/copy/envelope/imap4flags. 미지원 확장 require는 SieveError.
 *
 * ★`:matches` 글롭은 `@ionosphere/core`(glob.ts)가 소유한다. 예전엔 여기서 패턴을 정규식으로
 * 바꿨는데(`*` → `.*`) 지수 백트래킹이 성립했다 — 사용자가 규칙을 심어 두면 그 뒤로는
 * **원격 발신자가 보낸 `Subject:`** 가 매칭 값이 되므로, 계정 하나로 전 테넌트의 메일을
 * 세울 수 있었다(실측 19.6초). IMAP LIST에 같은 결함이 복제돼 있었다 — glob.ts 머리 주석 참조.
 */
import { compileGlob, SIEVE_MATCH_SYNTAX } from "@ionosphere/core";
import type { SieveArg, SieveCommand, SieveTest } from "./ast.ts";
import { parseSieve } from "./parser.ts";

export class SieveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SieveError";
  }
}

/** 메시지 환경 — 배달 파이프라인이 제공(헤더는 소문자 키). */
export interface SieveEnv {
  headers: Map<string, string[]>;
  envelopeFrom: string;
  envelopeTo: string[];
  size: number;
  /**
   * 이 계정의 메일함 경로들 — `mailboxexists`(RFC 5490 §3.1) 판정용.
   *
   * ★평가기는 순수해야 하므로 조회가 아니라 **주입**이다. 호출자가 안 주면 빈 목록으로 보고
   * `mailboxexists`는 거짓이 된다 — 있는지 모를 때 "있다"고 답하는 것보다 안전한 쪽이다
   * (스크립트가 그 결과로 fileinto를 고르는데, 없는 곳으로 보내면 메일이 INBOX로 샌다).
   */
  mailboxes?: readonly string[];
  /**
   * `subaddress`(RFC 5233)의 구분자. 기본 `+` — 이 저장소의 알리아스 매칭과 같은 값이라야
   * 스크립트가 보는 `:detail`과 서버가 푸는 태그가 일치한다.
   */
  subaddressDelimiter?: string;
}

/** 실행 결과 — 배달 파이프라인이 해석. keep=INBOX 배달, fileinto=지정 메일함. */
export interface SieveResult {
  keep: boolean;
  fileinto: string[];
  /**
   * `fileinto :create`(RFC 5490 §3.2)로 지정된 대상 — **없으면 만들어 달라**는 요청.
   *
   * ★평가기가 직접 만들지 않는다(순수 함수). 없는 메일함에 fileinto하면 지금까지는 조용히
   * INBOX로 샜는데, 사용자 입장에서는 규칙이 동작하지 않는 것으로 보인다. `:create`는 그
   * 실패를 없애는 표준 방법이고, **만드는 일은 배달 계층의 몫**이다.
   */
  fileintoCreate: string[];
  redirect: string[];
  flags: string[];
  discarded: boolean;
  /**
   * `reject`/`ereject`(RFC 5429) — 이 수신자에게 배달하지 않고 **거절 사유를 발신자에게
   * 알린다**. `null`이면 거절 없음.
   *
   * ★`reject`와 `ereject`를 결과에서 구분하지 않는 이유: 둘의 차이는 "어떻게 알리는가"인데
   * (reject는 DSN 생성, ereject는 SMTP 세션에서 5xx) 우리 배달 경로는 **DATA를 받은 뒤**
   * 수신자별로 판정하므로 어느 쪽이든 그 수신자에 대한 5xx로 표현된다. RFC 5429 §2.1도
   * "가능하면 프로토콜 레벨 거절"을 권하고, 그게 우리가 할 수 있는 형태다.
   * (구분이 필요해지면 그때 필드를 나눈다 — 지금 나누면 소비처가 없는 갈래가 생긴다.)
   */
  reject: string | null;
  /**
   * `vacation`(RFC 5230) — 자동 응답 지시. `null`이면 없다.
   *
   * ★평가기는 **보낼지 말지를 정하지 않는다.** 중복 억제(§4.5)와 루프 방지(§4.6)는 저장소와
   * 봉투·헤더를 봐야 하는 판단이라 배달 계층 몫이다. 여기서는 "사용자가 무엇을 요청했나"만
   * 돌려준다 — 이 파일이 순수 함수라는 성질을 지키는 자리다.
   */
  vacation: VacationRequest | null;
}

/** `vacation` 액션의 인자 (RFC 5230 §4). */
export interface VacationRequest {
  /** 본문(필수 위치 인자). */
  reason: string;
  /** `:days` — 같은 상대에게 다시 보내기까지의 최소 간격. 기본 7(§4.1). */
  days: number;
  /** `:subject` — 없으면 배달 계층이 원 제목에서 만든다. */
  subject: string | null;
  /** `:from` — 응답의 From. 없으면 배달 계층이 계정 주소를 쓴다. */
  from: string | null;
  /**
   * `:addresses` — "내 주소"로 인정할 추가 주소들.
   *
   * §4.6이 요구하는 루프 방지의 핵심 입력이다: 수신자 헤더에 **내 주소가 없으면** 보내지
   * 않는다(메일링리스트를 통해 온 메일에 전원 답장하는 사고를 막는다).
   */
  addresses: string[];
  /**
   * `:handle` — "같은 부재 응답인가"의 식별자(§4.4). 스크립트를 고쳐도 핸들이 같으면
   * 억제가 이어진다. 없으면 배달 계층이 본문에서 유도한다.
   */
  handle: string | null;
  /** `:mime` — reason이 이미 MIME 본문이다(헤더 포함). */
  mime: boolean;
}

/**
 * `require`로 받아 주는 확장 — **광고의 정본**이기도 하다.
 *
 * ★ManageSieve의 `"SIEVE"` 능력줄이 이 목록을 그대로 실어야 한다. 예전엔 그쪽에 손으로 적은
 * 사본이 있었고, `reject`·`ereject`·`vacation`을 여기 추가했을 때 그 사본이 안 따라와서
 * **평가기는 받는데 서버는 광고하지 않는** 상태가 됐다. 능력줄을 보고 스크립트를 고르는
 * 클라이언트에게 그건 "이 서버는 자동 응답을 못 한다"와 같다.
 *
 * 순서는 광고에 그대로 나가므로 배열로 둔다(Set은 순서를 약속하지 않는 자료구조로 읽힌다).
 */
export const SUPPORTED_EXTENSION_LIST = [
  "fileinto",
  "envelope",
  "imap4flags",
  "copy",
  "reject",
  "ereject",
  "vacation",
  "mailbox",
  "subaddress",
] as const;

const SUPPORTED_EXTENSIONS: ReadonlySet<string> = new Set(SUPPORTED_EXTENSION_LIST);

interface ExecState {
  env: SieveEnv;
  result: { keep: boolean; fileinto: string[]; fileintoCreate: string[]; redirect: string[]; flags: Set<string>; canceledImplicit: boolean; explicitKeep: boolean; reject: string | null; vacation: VacationRequest | null };
  stopped: boolean;
}

/** 스크립트 소스를 실행. 파싱/require 오류는 throw(호출자가 암묵 keep으로 폴백). */
export function runSieve(src: string, env: SieveEnv): SieveResult {
  const cmds = parseSieve(src);
  const state: ExecState = {
    env,
    result: { keep: false, fileinto: [], fileintoCreate: [], redirect: [], flags: new Set(), canceledImplicit: false, explicitKeep: false, reject: null, vacation: null },
    stopped: false,
  };
  execBlock(cmds, state);
  const r = state.result;
  /**
   * ★거절이 다른 모든 처분을 이긴다(RFC 5429 §2.1: reject는 다른 액션과 함께 쓸 수 없다).
   * 파서 단계에서 막지 않고 여기서 이기게 두는 이유는, 조건 분기 때문에 **정적으로는
   * 공존하지 않는데 문법상으로만 함께 있는** 스크립트가 흔하기 때문이다.
   */
  const keep = r.reject !== null ? false : r.explicitKeep || !r.canceledImplicit;
  if (r.reject !== null) {
    // 거절이면 자동 응답도 하지 않는다 — 받지 않겠다고 해 놓고 답장을 보내는 것은 모순이다.
    return { keep: false, fileinto: [], fileintoCreate: [], redirect: [], flags: [], discarded: false, reject: r.reject, vacation: null };
  }
  return {
    keep,
    fileinto: [...new Set(r.fileinto)],
    fileintoCreate: [...new Set(r.fileintoCreate)],
    redirect: [...new Set(r.redirect)],
    flags: [...r.flags],
    discarded: !keep && r.fileinto.length === 0 && r.redirect.length === 0,
    reject: null,
    vacation: r.vacation,
  };
}

function execBlock(cmds: readonly SieveCommand[], st: ExecState): void {
  let prevMatched = false; // if/elsif 체인 상태
  for (const cmd of cmds) {
    if (st.stopped) return;
    if (cmd.name === "if") {
      prevMatched = evalTest(cmd.test!, st.env);
      if (prevMatched) execBlock(cmd.block ?? [], st);
    } else if (cmd.name === "elsif") {
      if (!prevMatched) {
        prevMatched = evalTest(cmd.test!, st.env);
        if (prevMatched) execBlock(cmd.block ?? [], st);
      }
    } else if (cmd.name === "else") {
      if (!prevMatched) execBlock(cmd.block ?? [], st);
      prevMatched = false;
    } else {
      execAction(cmd, st);
      prevMatched = false;
    }
  }
}

function execAction(cmd: SieveCommand, st: ExecState): void {
  const r = st.result;
  switch (cmd.name) {
    case "require": {
      const exts = firstStrings(cmd.args);
      for (const e of exts) {
        if (!SUPPORTED_EXTENSIONS.has(e)) throw new SieveError(`unsupported extension: ${e}`);
      }
      return;
    }
    case "stop":
      st.stopped = true;
      return;
    case "reject":
    case "ereject": {
      /**
       * RFC 5429 — 배달하지 않고 발신자에게 사유를 알린다. `ereject`는 "프로토콜 레벨로
       * 거절하라"는 뜻이고 `reject`는 DSN도 허용하는데, 우리 배달 경로에서는 둘 다 그
       * 수신자에 대한 5xx가 된다(SieveResult.reject 주석).
       */
      const reason = firstStrings(cmd.args)[0];
      if (reason === undefined) throw new SieveError(`${cmd.name} requires a reason string`);
      r.reject = reason;
      r.canceledImplicit = true;
      return;
    }
    case "keep":
      r.explicitKeep = true;
      return;
    case "discard":
      r.canceledImplicit = true;
      return;
    case "fileinto": {
      const copy = hasTag(cmd.args, "copy");
      const target = firstStrings(cmd.args)[0];
      if (!target) throw new SieveError("fileinto requires a mailbox");
      r.fileinto.push(target);
      // `:create`(RFC 5490 §3.2) — 없으면 만들어 달라. 만드는 것은 배달 계층의 몫이다.
      if (hasTag(cmd.args, "create")) r.fileintoCreate.push(target);
      if (!copy) r.canceledImplicit = true;
      return;
    }
    case "redirect": {
      const copy = hasTag(cmd.args, "copy");
      const addr = firstStrings(cmd.args)[0];
      if (!addr) throw new SieveError("redirect requires an address");
      r.redirect.push(addr);
      if (!copy) r.canceledImplicit = true;
      return;
    }
    case "vacation": {
      /**
       * RFC 5230. `vacation`은 **암묵 keep을 취소하지 않는다**(§4.3) — 자동 응답은 배달에
       * 더해지는 것이지 배달을 대신하는 것이 아니다.
       *
       * ★같은 스크립트에서 두 번 실행되면 첫 번째만 유효하다(§4: "한 번의 실행에 한 번").
       * 조건 분기로 여러 vacation이 쓰인 스크립트가 흔하므로 파서에서 막지 않는다.
       */
      if (r.vacation !== null) return;
      /**
       * ★본문은 **태그가 소비하지 않은** 문자열 인자다. `firstStrings`를 쓰면
       * `vacation :subject "Away" "본문"`에서 `"Away"`가 본문으로 들어간다 — 실제로 그렇게
       * 썼다가 테스트가 잡았다. Sieve 인자는 위치가 의미를 가지므로 태그 소비를 먼저 셈해야 한다.
       */
      const reason = positionalStrings(cmd.args, VACATION_VALUE_TAGS)[0];
      if (reason === undefined) throw new SieveError("vacation requires a reason string");
      const days = tagNumber(cmd.args, "days");
      if (days !== null && (!Number.isInteger(days) || days < 1)) {
        throw new SieveError("vacation :days must be a positive integer");
      }
      r.vacation = {
        reason,
        days: days ?? DEFAULT_VACATION_DAYS,
        subject: tagString(cmd.args, "subject"),
        from: tagString(cmd.args, "from"),
        addresses: tagStrings(cmd.args, "addresses"),
        handle: tagString(cmd.args, "handle"),
        mime: hasTag(cmd.args, "mime"),
      };
      return;
    }
    case "setflag":
      r.flags.clear();
      for (const f of flagArgs(cmd.args)) r.flags.add(f);
      return;
    case "addflag":
      for (const f of flagArgs(cmd.args)) r.flags.add(f);
      return;
    case "removeflag":
      for (const f of flagArgs(cmd.args)) r.flags.delete(f);
      return;
    default:
      throw new SieveError(`unknown command: ${cmd.name}`);
  }
}

// ── 테스트 평가 ────────────────────────────────────────────────────────────────

function evalTest(test: SieveTest, env: SieveEnv): boolean {
  switch (test.name) {
    case "true":
      return true;
    case "false":
      return false;
    case "not":
      return !evalTest(test.tests[0]!, env);
    case "allof":
      return test.tests.every((t) => evalTest(t, env));
    case "anyof":
      return test.tests.some((t) => evalTest(t, env));
    case "exists": {
      const names = firstStrings(test.args).map((s) => s.toLowerCase());
      return names.every((nm) => (env.headers.get(nm)?.length ?? 0) > 0);
    }
    case "size": {
      const over = hasTag(test.args, "over");
      const under = hasTag(test.args, "under");
      const limit = firstNumber(test.args);
      if (limit === null) throw new SieveError("size requires a number");
      if (over) return env.size > limit;
      if (under) return env.size < limit;
      throw new SieveError("size requires :over or :under");
    }
    case "header": {
      const match = matchType(test.args);
      const strs = stringArgs(test.args);
      const names = strs[0] ?? [];
      const keys = strs[1] ?? [];
      const values = names.flatMap((nm) => env.headers.get(nm.toLowerCase()) ?? []);
      return anyMatch(values, keys, match);
    }
    case "address": {
      const match = matchType(test.args);
      const part = addressPart(test.args);
      const delim = env.subaddressDelimiter ?? "+";
      const strs = stringArgs(test.args);
      const names = strs[0] ?? [];
      const keys = strs[1] ?? [];
      const values = names.flatMap((nm) => (env.headers.get(nm.toLowerCase()) ?? []).flatMap((h) => extractAddresses(h).map((a) => addrPart(a, part, delim))));
      return anyMatch(values, keys, match);
    }
    case "envelope": {
      const match = matchType(test.args);
      const part = addressPart(test.args);
      const delim = env.subaddressDelimiter ?? "+";
      const strs = stringArgs(test.args);
      const fields = (strs[0] ?? []).map((s) => s.toLowerCase());
      const keys = strs[1] ?? [];
      const values: string[] = [];
      for (const f of fields) {
        if (f === "from") values.push(addrPart(env.envelopeFrom, part, delim));
        else if (f === "to") for (const t of env.envelopeTo) values.push(addrPart(t, part, delim));
      }
      return anyMatch(values, keys, match);
    }
    /**
     * `mailboxexists`(RFC 5490 §3.1) — 나열한 메일함이 **전부** 있으면 참.
     *
     * ★"하나라도"가 아니라 "전부"다. 스크립트가 보통
     * `if mailboxexists "A" { fileinto "A"; } else { keep; }` 형태라, 일부만 있는데 참이 되면
     * 없는 곳으로 fileinto해 메일이 INBOX로 샌다.
     */
    case "mailboxexists": {
      const names = stringArgs(test.args).flat();
      if (names.length === 0) throw new SieveError("mailboxexists requires a mailbox name");
      const have = new Set(env.mailboxes ?? []);
      return names.every((n) => have.has(n));
    }
    default:
      throw new SieveError(`unknown test: ${test.name}`);
  }
}

// ── 매칭 ──────────────────────────────────────────────────────────────────────

type MatchKind = "is" | "contains" | "matches";

function matchType(args: readonly SieveArg[]): MatchKind {
  if (hasTag(args, "contains")) return "contains";
  if (hasTag(args, "matches")) return "matches";
  return "is"; // 기본
}

/**
 * 하나라도 매칭되면 true. 기본 비교는 i;ascii-casemap(대소문자 무시).
 *
 * ★`:matches` 패턴은 **키마다 한 번만** 컴파일한다. 값이 여러 개일 때(헤더가 여러 줄,
 * 주소가 여럿) 예전 구현은 (값 × 키)마다 정규식을 다시 만들었다.
 */
function anyMatch(values: readonly string[], keys: readonly string[], kind: MatchKind): boolean {
  const matchers = kind === "matches" ? keys.map((k) => compileGlob(k.toLowerCase(), SIEVE_MATCH_SYNTAX)) : null;
  for (const v of values) {
    const vl = v.toLowerCase();
    if (matchers) {
      for (const m of matchers) if (m(vl)) return true;
      continue;
    }
    for (const k of keys) {
      const kl = k.toLowerCase();
      if (kind === "is" && vl === kl) return true;
      if (kind === "contains" && vl.includes(kl)) return true;
    }
  }
  return false;
}

// ── 인자 헬퍼 ──────────────────────────────────────────────────────────────────

/**
 * 태그가 소비하지 않은 **위치 인자** 문자열들.
 *
 * `:tag "값"` 형태에서 `"값"`은 그 태그의 것이지 위치 인자가 아니다. 이 구분이 없으면
 * 태그를 쓴 스크립트와 안 쓴 스크립트가 다른 값을 본문으로 읽는다.
 */
function positionalStrings(args: readonly SieveArg[], valueTags: ReadonlySet<string>): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a?.kind === "tag") {
      /**
       * ★**값을 받는 태그만** 다음 인자를 소비한다. `:mime`·`:copy`처럼 값 없는 태그까지
       * 소비하면 `vacation :mime "본문"`에서 본문이 사라진다 — 태그 목록을 넘기게 한 이유다
       * (모든 태그가 값을 받는다고 가정했다가 그 갈래를 만들 뻔했다).
       */
      if (valueTags.has(a.name)) {
        const next = args[i + 1];
        if (next?.kind === "strings" || next?.kind === "number") i++;
      }
      continue;
    }
    if (a?.kind === "strings") out.push(...a.values);
  }
  return out;
}

/** `vacation`에서 **값을 받는** 태그(RFC 5230 §4). `:mime`은 값이 없다. */
const VACATION_VALUE_TAGS = new Set(["days", "subject", "from", "addresses", "handle"]);

/** RFC 5230 §4.1 — `:days` 기본값. */
const DEFAULT_VACATION_DAYS = 7;

/**
 * `:tag "value"` 형태의 인자에서 값을 꺼낸다.
 *
 * ★태그 **바로 뒤**의 값만 본다. Sieve 인자는 위치가 의미를 갖는데(`vacation :subject "x" "본문"`),
 * "첫 문자열"을 쓰면 태그 값과 위치 인자가 섞인다 — `:subject` 없이 쓴 스크립트의 본문이
 * 제목으로 들어가는 식이다.
 */
function tagString(args: readonly SieveArg[], name: string): string | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a?.kind !== "tag" || a.name !== name) continue;
    const next = args[i + 1];
    if (next?.kind === "strings") return next.values[0] ?? null;
    return null;
  }
  return null;
}

/** `:tag ["a", "b"]` — 목록형 태그 값. 없으면 빈 배열. */
function tagStrings(args: readonly SieveArg[], name: string): string[] {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a?.kind !== "tag" || a.name !== name) continue;
    const next = args[i + 1];
    return next?.kind === "strings" ? [...next.values] : [];
  }
  return [];
}

/** `:tag 7` — 숫자형 태그 값. */
function tagNumber(args: readonly SieveArg[], name: string): number | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a?.kind !== "tag" || a.name !== name) continue;
    const next = args[i + 1];
    return next?.kind === "number" ? next.value : null;
  }
  return null;
}

function hasTag(args: readonly SieveArg[], name: string): boolean {
  return args.some((a) => a.kind === "tag" && a.name === name);
}
function firstStrings(args: readonly SieveArg[]): string[] {
  const a = args.find((x) => x.kind === "strings");
  return a && a.kind === "strings" ? a.values : [];
}
/** 문자열 인자들을 순서대로(header/address의 name-list, key-list). */
function stringArgs(args: readonly SieveArg[]): string[][] {
  return args.filter((a): a is Extract<SieveArg, { kind: "strings" }> => a.kind === "strings").map((a) => a.values);
}
function firstNumber(args: readonly SieveArg[]): number | null {
  const a = args.find((x) => x.kind === "number");
  return a && a.kind === "number" ? a.value : null;
}
function flagArgs(args: readonly SieveArg[]): string[] {
  // setflag/addflag/removeflag [<variable>] <list-of-flags> — 변수 미지원(v1), 문자열 리스트만
  return stringArgs(args).flat().flatMap((s) => s.split(/\s+/).filter((x) => x.length > 0));
}
/** `subaddress`(RFC 5233)가 `:user`/`:detail`을 더한다 — localpart를 구분자로 다시 나눈 것. */
type AddressPart = "all" | "localpart" | "domain" | "user" | "detail";

function addressPart(args: readonly SieveArg[]): AddressPart {
  if (hasTag(args, "localpart")) return "localpart";
  if (hasTag(args, "domain")) return "domain";
  if (hasTag(args, "user")) return "user";
  if (hasTag(args, "detail")) return "detail";
  return "all";
}

/** 헤더 값에서 이메일 주소들 추출(`Name <a@b>` / `a@b` / 쉼표 목록). */
function extractAddresses(header: string): string[] {
  const out: string[] = [];
  for (const part of header.split(",")) {
    const m = /<([^>]*)>/.exec(part);
    const addr = (m ? m[1]! : part).trim();
    if (addr.includes("@")) out.push(addr);
  }
  return out;
}
function addrPart(addr: string, part: AddressPart, delimiter: string): string {
  const at = addr.lastIndexOf("@");
  if (part === "all" || at === -1) return addr;
  if (part === "domain") return addr.slice(at + 1);
  const local = addr.slice(0, at);
  if (part === "localpart") return local;

  /**
   * `subaddress`(RFC 5233 §4) — `user+detail@domain`.
   *
   * ★구분자가 **없으면** `:user`는 localpart 전체이고 `:detail`은 빈 문자열이 아니라
   * **없는 값**이다(§4: "if the address does not include a detail sub-part, the :detail
   * ... is the empty string" — 빈 문자열로 취급한다). 여기서는 빈 문자열로 둔다.
   *
   * ★첫 구분자로 자른다. `a+b+c`의 detail은 `b+c`다 — 태그 안에 구분자가 들어가는 형태를
   * 쓰는 서비스가 있어서, 마지막 것으로 자르면 그런 주소의 태그가 잘린다.
   */
  const idx = delimiter.length > 0 ? local.indexOf(delimiter) : -1;
  if (idx === -1) return part === "user" ? local : "";
  return part === "user" ? local.slice(0, idx) : local.slice(idx + delimiter.length);
}
