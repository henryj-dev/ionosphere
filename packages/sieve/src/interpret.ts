/**
 * Sieve 평가기 (RFC 5228 §2/§4/§5). 파싱된 스크립트를 메시지 환경에 대해 실행 → 배달 지시.
 * 순수 함수 — 부수효과 없음. 지원: 베이스(if/elsif/else/stop/require, keep/discard/fileinto/
 * redirect) + fileinto/copy/envelope/imap4flags. 미지원 확장 require는 SieveError.
 */
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
}

const SUPPORTED_EXTENSIONS = new Set(["fileinto", "envelope", "imap4flags", "copy"]);

interface ExecState {
  env: SieveEnv;
  result: { keep: boolean; fileinto: string[]; redirect: string[]; flags: Set<string>; canceledImplicit: boolean; explicitKeep: boolean };
  stopped: boolean;
}

/** 스크립트 소스를 실행. 파싱/require 오류는 throw(호출자가 암묵 keep으로 폴백). */
export function runSieve(src: string, env: SieveEnv): SieveResult {
  const cmds = parseSieve(src);
  const state: ExecState = {
    env,
    result: { keep: false, fileinto: [], redirect: [], flags: new Set(), canceledImplicit: false, explicitKeep: false },
    stopped: false,
  };
  execBlock(cmds, state);
  const r = state.result;
  const keep = r.explicitKeep || !r.canceledImplicit;
  return {
    keep,
    fileinto: [...new Set(r.fileinto)],
    redirect: [...new Set(r.redirect)],
    flags: [...r.flags],
    discarded: !keep && r.fileinto.length === 0 && r.redirect.length === 0,
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

/** 하나라도 매칭되면 true. 기본 비교는 i;ascii-casemap(대소문자 무시). */
function anyMatch(values: readonly string[], keys: readonly string[], kind: MatchKind): boolean {
  for (const v of values) {
    const vl = v.toLowerCase();
    for (const k of keys) {
      const kl = k.toLowerCase();
      if (kind === "is" && vl === kl) return true;
      if (kind === "contains" && vl.includes(kl)) return true;
      if (kind === "matches" && globMatch(vl, kl)) return true;
    }
  }
  return false;
}

/** Sieve :matches 글롭 — `*`=임의, `?`=1문자. `\*`/`\?`는 리터럴. */
function globMatch(value: string, pattern: string): boolean {
  let re = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "\\") {
      const nxt = pattern[++i];
      re += nxt ? nxt.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : "";
    } else if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(re + "$", "s").test(value);
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
