/**
 * 와일드카드 매칭 정본 — **선형 시간**. IMAP LIST와 Sieve `:matches`가 공유한다.
 *
 * ★왜 정규식을 버렸나(2026-08-23 검수, 실측): 두 곳 모두 `*`를 `.*`로 치환해
 * `new RegExp()`에 넘겼다. 인접한 `.*`가 여러 개면 V8이 지수적으로 백트랙한다.
 *
 *   Sieve `:matches`  패턴 `"*x"×16 + "Z"` vs 값 `"x"×32`  → **19,653ms**
 *   IMAP  LIST       패턴 `"*a"×22 + "b"` vs 이름 `"a"×44` → **120초 초과**(측정 중단)
 *
 * 전 프로토콜이 단일 프로세스라 그 시간 동안 25·587·993·995·443이 **함께** 멈춘다.
 * 도달 경로도 둘 다 열려 있었다 — IMAP은 인증된 사용자가 `LIST` 한 줄로(패턴도 매칭 대상인
 * 메일함 이름도 본인이 정한다), Sieve는 사용자가 `:matches` 규칙을 심어 두면 그 뒤로는
 * **원격 발신자가 보낸 `Subject:`** 가 매칭 값이 된다(자기 계정 하나로 전 테넌트를 멈출 수 있다).
 *
 * ★왜 core가 소유하는가: 같은 알고리즘이 두 패키지에 복제돼 있다는 것 자체가 소유자 부재
 * 신호다(CLAUDE.md §응집도). 한쪽만 고치면 다른 쪽이 그대로 남고, 세 번째 사용처가 생기면
 * 또 복제된다. SASL 파싱·프로토콜 한도를 core로 올린 것과 같은 이유다.
 *
 * 알고리즘: `*`의 마지막 위치를 기억하고 되돌아가는 2포인터 백트랙. 별이 k개일 때 최악
 * O(n·k)이고 되돌아갈 지점이 **하나뿐**이라 지수 폭발이 성립하지 않는다.
 */

/** 매칭 문법 — 프로토콜마다 와일드카드의 뜻이 다르다. */
export interface GlobSyntax {
  /**
   * 임의 길이 와일드카드(`*`). 문자열 어디든 건너뛴다.
   *
   * IMAP `*`는 계층 구분자를 **포함해** 전부, Sieve `*`도 임의 문자열이라 둘이 같다.
   */
  star: string;
  /**
   * 구분자를 넘지 못하는 와일드카드(IMAP `%`). `null`이면 그 문법이 없다.
   * `boundary`와 짝으로만 의미가 있다.
   */
  starWithin?: string | undefined;
  /** `starWithin`이 넘지 못하는 문자(IMAP 계층 구분자 `/`). */
  boundary?: string | undefined;
  /** 1문자 와일드카드(Sieve `?`). `null`이면 그 문법이 없다. */
  single?: string | undefined;
  /**
   * 다음 문자를 리터럴로 만드는 이스케이프(Sieve `\`). `null`이면 이스케이프가 없다.
   *
   * ★IMAP은 이스케이프가 없다 — RFC 9051의 list-mailbox 문법에 그런 규칙이 없고,
   * 있다고 가정하면 이름에 `\`가 든 메일함이 매칭에서 사라진다.
   */
  escape?: string | undefined;
  /** 대소문자 무시 비교인가. */
  caseInsensitive: boolean;
}

/** IMAP LIST (RFC 9051 §6.3.9) — `*`=전부, `%`=구분자 제외. 대소문자 **구분**. */
export function imapListSyntax(delimiter: string): GlobSyntax {
  return { star: "*", starWithin: "%", boundary: delimiter, caseInsensitive: false };
}

/** Sieve `:matches` (RFC 5228 §2.7.1) — `*`=임의, `?`=1문자, `\`=리터럴 이스케이프. */
export const SIEVE_MATCH_SYNTAX: GlobSyntax = {
  star: "*",
  single: "?",
  escape: "\\",
  // 기본 비교자 i;ascii-casemap(RFC 5228 §2.7.3) — 호출부가 이미 소문자화하지만 여기서도 보장한다.
  caseInsensitive: true,
};

/** 패턴 토큰 — 파싱을 매칭에서 분리해야 이스케이프 규칙이 루프 안에 섞이지 않는다. */
type Token =
  | { kind: "literal"; ch: string }
  | { kind: "star" }
  | { kind: "starWithin" }
  | { kind: "single" };

function tokenize(pattern: string, syntax: GlobSyntax): Token[] {
  const out: Token[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (syntax.escape !== undefined && ch === syntax.escape) {
      const next = pattern[i + 1];
      // 패턴 끝의 홀로 남은 이스케이프는 버린다(기존 정규식 구현과 같은 처분).
      if (next !== undefined) {
        out.push({ kind: "literal", ch: next });
        i++;
      }
      continue;
    }
    if (ch === syntax.star) {
      // 연속된 `*`는 하나와 같다 — 되돌아갈 지점을 늘리지 않는다(그게 폭발의 원인이었다).
      if (out[out.length - 1]?.kind !== "star") out.push({ kind: "star" });
      continue;
    }
    if (syntax.starWithin !== undefined && ch === syntax.starWithin) {
      out.push({ kind: "starWithin" });
      continue;
    }
    if (syntax.single !== undefined && ch === syntax.single) {
      out.push({ kind: "single" });
      continue;
    }
    out.push({ kind: "literal", ch });
  }
  return out;
}

/**
 * 토큰 열과 값을 맞춘다 — **동적 계획법**. `dp[j]` = "여기까지의 토큰이 값의 앞 j글자를 먹었나".
 *
 * ★왜 2포인터(마지막 `*` 하나만 되돌아가는 표준 글롭 방식)가 아닌가: 그 방식은 와일드카드가
 * `*`·`?`뿐일 때만 옳다. `%`가 섞이면 **되돌아갈 지점이 하나로 부족하다** — `%`가 구분자에
 * 막혀 소진되면 그 앞의 `*`를 더 늘려야 답이 나오는 입력이 있다(`*a%b` vs `xa/ab`는 참인데
 * 2포인터는 거짓을 낸다). 그렇다고 `%`마다 재귀로 후보를 훑으면 그 자체가 지수가 된다
 * (이 파일의 첫 구현이 그랬고 `glob.test.ts`의 `%` 케이스가 328ms로 그것을 잡았다).
 *
 * DP는 토큰 수 n · 값 길이 m에 대해 **항상 O(n·m)** 이다. 되돌아가는 개념이 없으므로
 * 백트래킹 폭발이 성립할 수 없다 — 이 함수가 막아야 하는 것이 정확히 그것이다.
 *
 * 행 하나(`Uint8Array`)만 굴려 메모리는 O(m)이고, 도달 가능한 위치가 하나도 없으면 즉시
 * 실패로 끊는다(정상 입력의 대다수가 여기서 빠진다).
 */
function matchTokens(tokens: readonly Token[], value: string, syntax: GlobSyntax): boolean {
  const m = value.length;
  // 비교를 루프 밖에서 한 번만 정규화한다 — 안에서 toLowerCase()를 부르면 m·n번 돈다.
  const hay = syntax.caseInsensitive ? value.toLowerCase() : value;
  const boundary = syntax.boundary;

  let prev = new Uint8Array(m + 1);
  let cur = new Uint8Array(m + 1);
  prev[0] = 1; // 토큰 0개는 값 0글자만 먹는다

  for (const tok of tokens) {
    cur.fill(0);
    switch (tok.kind) {
      case "literal": {
        const ch = syntax.caseInsensitive ? tok.ch.toLowerCase() : tok.ch;
        for (let j = 1; j <= m; j++) {
          if (prev[j - 1] === 1 && hay[j - 1] === ch) cur[j] = 1;
        }
        break;
      }
      case "single":
        for (let j = 1; j <= m; j++) cur[j] = prev[j - 1] ?? 0;
        break;
      case "star": {
        // `*`는 임의 길이를 먹는다 — 앞에서부터의 누적 OR.
        let run = 0;
        for (let j = 0; j <= m; j++) {
          run |= prev[j] ?? 0;
          cur[j] = run;
        }
        break;
      }
      case "starWithin": {
        /**
         * `%`는 **구분자를 넘지 못한다.** 그래서 누적 OR을 구분자에서 끊는다 —
         * 바로 앞 글자가 구분자면 그 자리에서 창이 다시 시작하고(빈 소비만 가능),
         * 아니면 창이 이어진다.
         */
        let run = prev[0] ?? 0;
        cur[0] = run;
        for (let j = 1; j <= m; j++) {
          const here = prev[j] ?? 0;
          run = boundary !== undefined && hay[j - 1] === boundary ? here : run | here;
          cur[j] = run;
        }
        break;
      }
    }
    // 도달 가능한 위치가 없으면 남은 토큰을 볼 이유가 없다.
    let alive = false;
    for (let j = 0; j <= m; j++) {
      if (cur[j] === 1) {
        alive = true;
        break;
      }
    }
    if (!alive) return false;
    const swap = prev;
    prev = cur;
    cur = swap;
  }

  return prev[m] === 1;
}

/**
 * 값이 패턴에 맞는가. **정규식을 만들지 않는다** — 위 파일 주석의 ReDoS가 이 함수의 존재 이유다.
 *
 * 패턴을 반복 사용할 때는 `compileGlob()`으로 토큰화를 한 번만 하는 편이 낫다.
 */
export function globMatch(pattern: string, value: string, syntax: GlobSyntax): boolean {
  return matchTokens(tokenize(pattern, syntax), value, syntax);
}

/**
 * 패턴을 미리 토큰화해 재사용 가능한 매처로 만든다.
 *
 * ★왜 필요한가: 호출부가 **루프 안에서** 매칭한다(IMAP은 메일함마다, Sieve는 값×키마다).
 * 예전 구현은 그 자리마다 `new RegExp()`을 다시 컴파일했다 — 정규식을 없애도 토큰화를
 * 매번 하면 같은 낭비가 남는다.
 */
export function compileGlob(pattern: string, syntax: GlobSyntax): (value: string) => boolean {
  const tokens = tokenize(pattern, syntax);
  return (value: string) => matchTokens(tokens, value, syntax);
}
