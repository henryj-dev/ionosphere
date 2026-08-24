/**
 * Sieve `variables` (RFC 5229) — 변수 저장·전개·수식어. 순수 함수, I/O 0.
 *
 * ★전개는 **쓰는 시점**에 한다(파싱 시점이 아니라). `${n}`은 가장 최근 `:matches`가 정하고
 * 그건 실행 순서에 달렸기 때문이다 — 미리 펴 두면 조건 분기마다 다른 값이어야 할 자리가
 * 한 값으로 굳는다.
 */

/** 변수 이름 규칙 (RFC 5229 §3): `[A-Za-z_][A-Za-z0-9_]*`, 네임스페이스는 `ns.name` 형태. */
const VAR_NAME = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;

export function isValidVariableName(name: string): boolean {
  return VAR_NAME.test(name);
}

/** `set`의 수식어 — 적용 **순서가 규정돼 있다**(§4의 precedence). */
const MODIFIER_ORDER = ["lower", "upper", "lowerfirst", "upperfirst", "quotewildcard", "length"] as const;
export type Modifier = (typeof MODIFIER_ORDER)[number];

export function isModifier(name: string): name is Modifier {
  return (MODIFIER_ORDER as readonly string[]).includes(name);
}

/**
 * 수식어들을 값에 적용한다.
 *
 * ★순서가 중요하다(§4): `:length`가 가장 나중이라 다른 수식어를 거친 **결과의** 길이를 낸다.
 * 순서를 안 정하면 `set :upper :length "x" "ab"`가 구현마다 다른 답을 낸다.
 * `:lower`/`:upper`처럼 서로 배타적인 것을 함께 쓰면 목록 순서대로 뒤엣것이 이긴다.
 */
export function applyModifiers(value: string, mods: ReadonlySet<Modifier>): string {
  let v = value;
  for (const m of MODIFIER_ORDER) {
    if (!mods.has(m)) continue;
    switch (m) {
      case "lower":
        v = v.toLowerCase();
        break;
      case "upper":
        v = v.toUpperCase();
        break;
      case "lowerfirst":
        v = v.length === 0 ? v : v[0]!.toLowerCase() + v.slice(1);
        break;
      case "upperfirst":
        v = v.length === 0 ? v : v[0]!.toUpperCase() + v.slice(1);
        break;
      case "quotewildcard":
        /**
         * ★`*`·`?`·`\`를 이스케이프한다(§4). 변수 값을 `:matches` 패턴에 끼워 넣을 때
         * 그 값 안의 와일드카드가 **패턴으로 해석되지 않게** 하는 것이 목적이다 —
         * 없으면 발신자가 제목에 `*`를 넣어 남의 필터 규칙을 바꿀 수 있다.
         */
        v = v.replace(/[\\*?]/g, (c) => `\\${c}`);
        break;
      case "length":
        v = String(v.length);
        break;
    }
  }
  return v;
}

/** 변수 저장소 — 이름은 대소문자를 구분하지 않는다(§3). */
export class SieveVariables {
  private readonly vars = new Map<string, string>();
  /** 가장 최근 `:matches`의 캡처 — `${1}`..`${9}`. `${0}`은 매칭된 값 전체다. */
  private matches: string[] = [];

  set(name: string, value: string): void {
    this.vars.set(name.toLowerCase(), value);
  }

  /** `:matches`가 성공할 때마다 덮어쓴다 — "가장 최근"이 규격의 말이다(§3). */
  setMatches(whole: string, captures: readonly string[]): void {
    this.matches = [whole, ...captures];
  }

  get(name: string): string {
    const lower = name.toLowerCase();
    /**
     * ★숫자 변수는 **먼저** 본다. 사용자가 `set "1" "x"`를 할 수 없게 하는 것이 아니라
     * (이름 규칙이 숫자로 시작하는 것을 막는다), 숫자 이름이 일반 변수와 섞이지 않게 하려는
     * 것이다 — 섞이면 `${1}`이 언제 캡처이고 언제 변수인지 알 수 없다.
     */
    if (/^\d+$/.test(lower)) return this.matches[Number(lower)] ?? "";
    return this.vars.get(lower) ?? "";
  }

  /**
   * `${name}` 전개. 모르는 변수는 **빈 문자열**이다(§3) — 오류가 아니다.
   *
   * ★재귀 전개를 하지 않는다(§3: "the expansion is not recursive"). 값 안의 `${...}`를
   * 다시 펴면 사용자가 보낸 문자열이 변수 이름이 되어, 발신자가 제목에 `${x}`를 넣어 남의
   * 변수를 읽는 형태가 된다.
   *
   * ★이름이 규칙에 안 맞으면 `${...}`를 **그대로 둔다**(§3). 지우면 본문에 우연히 들어간
   * `${1 + 2}` 같은 문자열이 사라진다.
   */
  expand(text: string): string {
    if (!text.includes("${")) return text; // 대다수 문자열이 여기서 끝난다
    let out = "";
    let i = 0;
    while (i < text.length) {
      const start = text.indexOf("${", i);
      if (start === -1) {
        out += text.slice(i);
        break;
      }
      const end = text.indexOf("}", start + 2);
      if (end === -1) {
        out += text.slice(i);
        break;
      }
      const name = text.slice(start + 2, end);
      out += text.slice(i, start);
      // 숫자(캡처)이거나 이름 규칙에 맞을 때만 전개한다.
      out += /^\d+$/.test(name) || isValidVariableName(name) ? this.get(name) : text.slice(start, end + 1);
      i = end + 1;
    }
    return out;
  }
}
