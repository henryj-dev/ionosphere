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
}

/** 실행 결과 — 배달 파이프라인이 해석. keep=INBOX 배달, fileinto=지정 메일함. */
export interface SieveResult {
  keep: boolean;
  fileinto: string[];
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
}

const SUPPORTED_EXTENSIONS = new Set(["fileinto", "envelope", "imap4flags", "copy", "reject", "ereject"]);

interface ExecState {
  env: SieveEnv;
  result: { keep: boolean; fileinto: string[]; redirect: string[]; flags: Set<string>; canceledImplicit: boolean; explicitKeep: boolean; reject: string | null };
  stopped: boolean;
}

/** 스크립트 소스를 실행. 파싱/require 오류는 throw(호출자가 암묵 keep으로 폴백). */
export function runSieve(src: string, env: SieveEnv): SieveResult {
  const cmds = parseSieve(src);
  const state: ExecState = {
    env,
    result: { keep: false, fileinto: [], redirect: [], flags: new Set(), canceledImplicit: false, explicitKeep: false, reject: null },
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
    return { keep: false, fileinto: [], redirect: [], flags: [], discarded: false, reject: r.reject };
  }
  return {
    keep,
    fileinto: [...new Set(r.fileinto)],
    redirect: [...new Set(r.redirect)],
    flags: [...r.flags],
    discarded: !keep && r.fileinto.length === 0 && r.redirect.length === 0,
    reject: null,
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
      const strs = stringArgs(test.args);
      const names = strs[0] ?? [];
      const keys = strs[1] ?? [];
      const values = names.flatMap((nm) => (env.headers.get(nm.toLowerCase()) ?? []).flatMap((h) => extractAddresses(h).map((a) => addrPart(a, part))));
      return anyMatch(values, keys, match);
    }
    case "envelope": {
      const match = matchType(test.args);
      const part = addressPart(test.args);
      const strs = stringArgs(test.args);
      const fields = (strs[0] ?? []).map((s) => s.toLowerCase());
      const keys = strs[1] ?? [];
      const values: string[] = [];
      for (const f of fields) {
        if (f === "from") values.push(addrPart(env.envelopeFrom, part));
        else if (f === "to") for (const t of env.envelopeTo) values.push(addrPart(t, part));
      }
      return anyMatch(values, keys, match);
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
function addressPart(args: readonly SieveArg[]): "all" | "localpart" | "domain" {
  if (hasTag(args, "localpart")) return "localpart";
  if (hasTag(args, "domain")) return "domain";
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
function addrPart(addr: string, part: "all" | "localpart" | "domain"): string {
  const at = addr.lastIndexOf("@");
  if (part === "all" || at === -1) return addr;
  return part === "localpart" ? addr.slice(0, at) : addr.slice(at + 1);
}
