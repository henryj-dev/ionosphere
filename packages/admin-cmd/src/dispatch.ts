/**
 * 명령 디스패처 — 이름으로 명령을 찾아 **인자를 검증한 뒤** 실행한다.
 *
 * ★검증을 여기 한 곳에 두는 이유가 이 계층의 존재 이유와 같다. 예전에는 API가 `requireString`으로,
 * CLI가 `if (!email)`로 각자 검증했고 규칙이 갈렸다 — 한쪽은 소문자로 정규화하고 다른 쪽은 안 했다.
 * 같은 명령이 표면에 따라 다르게 동작하면 "GUI로는 되는데 CLI로는 안 된다"가 되고, 그 차이는
 * 재현하기 전까지 아무도 모른다. `ArgSpec` 하나가 세 표면의 검증 정본이다.
 */
import { CommandError, type Command, type CommandContext, type CommandResult, type CommandSpec } from "./types.ts";

/** 이름 → 명령. 등록 순서가 곧 GUI 탭·CLI usage의 순서다. */
export class CommandRegistry {
  private readonly byName = new Map<string, Command>();

  constructor(commands: readonly Command[]) {
    for (const c of commands) {
      if (this.byName.has(c.spec.name)) {
        // 같은 이름이 둘이면 나중 것이 조용히 이기고, 그 사실이 어디에도 드러나지 않는다.
        throw new Error(`중복된 명령 이름: ${c.spec.name}`);
      }
      this.byName.set(c.spec.name, c);
    }
  }

  get(name: string): Command | undefined {
    return this.byName.get(name);
  }

  /** 전체 서술 — GUI가 화면을 그리고 CLI가 usage를 찍는 근거. */
  describe(): readonly CommandSpec[] {
    return [...this.byName.values()].map((c) => c.spec);
  }

  list(): readonly Command[] {
    return [...this.byName.values()];
  }
}

/**
 * 인자 검증 — `ArgSpec`대로 좁힌다.
 *
 * 들어오는 값이 전부 문자열인 이유: HTTP 쿼리·JSON·argv 셋 다 문자열이 원본이고, 어댑터마다
 * 다르게 파싱하면 그 차이가 곧 표면 간 갈라짐이 된다. **파싱도 여기서 한 번만** 한다.
 */
export function validateArgs(
  spec: CommandSpec,
  raw: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of spec.args) {
    const v = raw[a.name];
    if (v === undefined || v === "") {
      if (a.required) {
        throw new CommandError("invalid", `필수 인자 누락: ${a.name} (${a.label})`, usageOf(spec));
      }
      continue;
    }
    if (a.type === "number") {
      // Number("")는 0이라 위에서 빈 값을 먼저 걸렀다 — 빈 문자열이 0으로 통과하면
      // `--port=`가 포트 0(임의 포트)이 되어 조용히 엉뚱한 곳에 붙는다.
      if (!Number.isFinite(Number(v))) throw new CommandError("invalid", `${a.name}은(는) 숫자여야 합니다: ${v}`);
    }
    if (a.type === "boolean" && v !== "true" && v !== "false") {
      throw new CommandError("invalid", `${a.name}은(는) true 또는 false여야 합니다: ${v}`);
    }
    if (a.type === "enum" && a.choices && !a.choices.some((c) => c.value === v)) {
      const allowed = a.choices.map((c) => c.value).join(", ");
      throw new CommandError("invalid", `${a.name}의 값이 올바르지 않습니다: ${v} (가능: ${allowed})`);
    }
    out[a.name] = v;
  }
  return out;
}

/** CLI가 stderr에 찍고 API가 힌트로 돌려주는 한 줄. 서술에서 만들어지므로 손으로 관리하지 않는다. */
export function usageOf(spec: CommandSpec): string {
  const parts = spec.args.map((a) => {
    // secret은 argv로 받지 않는다는 규율이 usage에 드러나야 한다 — 안 그러면 운영자가 argv에 적는다.
    if (a.type === "secret") return `[${a.name}: stdin/env]`;
    return a.required ? `--${a.name}=<${a.name}>` : `[--${a.name}=<${a.name}>]`;
  });
  return `${spec.name} ${parts.join(" ")}`.trim();
}

/**
 * 이름으로 찾아 검증 후 실행. **어댑터가 부르는 유일한 입구**다.
 *
 * 인가(스코프·root)를 여기서 하지 않는 이유: 이 계층은 "누가 부르는지"를 모른다. 다만
 * `rootOnly`는 서술에 있으므로 어댑터가 그것을 보고 막는다 — 판단 근거는 여기, 집행은 어댑터.
 */
export async function runCommand(
  registry: CommandRegistry,
  ctx: CommandContext,
  name: string,
  raw: Readonly<Record<string, string | undefined>>,
): Promise<CommandResult> {
  const cmd = registry.get(name);
  if (!cmd) throw new CommandError("notFound", `알 수 없는 명령: ${name}`);
  const args = validateArgs(cmd.spec, raw);
  try {
    const result = await cmd.run(ctx, args);
    ctx.observer?.record({ operation: name, outcome: "ok", reason: "success" });
    return result;
  } catch (error) {
    const reason = error instanceof CommandError ? error.kind : "unavailable";
    ctx.observer?.record({ operation: name, outcome: "fail", reason });
    throw error;
  }
}
