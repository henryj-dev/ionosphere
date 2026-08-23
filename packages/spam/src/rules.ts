/**
 * 휴리스틱 룰 — **헤더와 봉투만** 본다. 본문은 읽지 않는다.
 *
 * ★이 제약은 성능이 아니라 약속이다. PLAN.md §8의 머리가 "운영자는 사용자 메일 내용을
 * 열람하지 않는다"이고, 그 약속은 "콘텐츠 비의존 통제"로 지킨다고 적혀 있다. 스팸 판정이
 * 본문을 읽기 시작하면 그 약속이 코드에서 깨진다 — 룰을 고를 때 이 선을 먼저 본다.
 *
 * ★룰을 고르는 두 번째 기준은 **오탐 비용**이다. 스팸 판정의 실패는 대칭이 아니다:
 * 스팸 한 통을 받는 것보다 **정상 메일 한 통을 잃는 것**이 훨씬 나쁘다. 그래서 여기 있는
 * 룰은 전부 "정상 메일이라면 이럴 이유가 없다"에 가까운 것만 남겼다. 대문자 비율·느낌표
 * 개수 같은 고전적 룰은 **언어 편향**이 커서(한국어·일본어 본문에서 오탐) 넣지 않는다.
 */
import type { ParsedMessage } from "@ionosphere/mime";

/** 룰 하나의 판정. `weight`는 점수 엔진이 합산한다(양수 = 스팸 쪽). */
export interface RuleHit {
  rule: string;
  weight: number;
  /** 운영자가 읽을 근거. **본문 조각을 넣지 않는다.** */
  detail?: string;
}

export interface RuleInput {
  parsed: ParsedMessage;
  /** 봉투 발신자(MAIL FROM). 빈 문자열이면 반송(null sender). */
  mailFrom: string;
  /** EHLO/HELO 이름. */
  heloName?: string;
  clientIp?: string;
}

/** 헤더 첫 값. */
function header(p: ParsedMessage, name: string): string | undefined {
  return p.headers.get(name)?.[0];
}

/** `Display Name <addr@dom>` 또는 `addr@dom`에서 주소만. */
function addrOf(value: string | undefined): string | null {
  if (!value) return null;
  const angle = value.match(/<([^>]*)>/);
  const raw = (angle?.[1] ?? value).trim();
  return raw.includes("@") ? raw.toLowerCase() : null;
}

function domainOf(addr: string | null): string | null {
  if (!addr) return null;
  const at = addr.lastIndexOf("@");
  return at < 0 ? null : addr.slice(at + 1).toLowerCase();
}

/**
 * 양방향 제어문자 — 표시 이름을 시각적으로 뒤집어 주소를 위장하는 데 쓰인다.
 * 정상 메일이 표시 이름에 이걸 넣을 이유가 없다(오탐이 사실상 0인 몇 안 되는 신호).
 */
const BIDI_OVERRIDE = /[\u202a-\u202e\u2066-\u2069]/;

/**
 * ★같은 문자가 **디코딩 안 된 raw 바이트**로도 온다.
 *
 * 헤더는 ASCII가 원칙이라(RFC 5322) 비ASCII는 encoded-word로 와야 하고, 그건 파서가 디코딩해
 * 위 문자 클래스에 걸린다. 그런데 규격을 무시하고 8비트 UTF-8을 헤더에 그대로 싣는 발신자가
 * 실제로 많다 — 그때 파서는 바이트를 그대로 주므로 `U+202E`가 `\u00e2\u0080\u00ae`(UTF-8 3바이트)로
 * 보인다. 한쪽만 보면 **규격을 안 지키는 쪽이 오히려 검사를 빠져나간다.**
 * (실측으로 확인하고 추가한 갈래다.)
 */
const BIDI_RAW_UTF8 = /\u00e2\u0080[\u00aa-\u00ae]|\u00e2\u0081[\u00a6-\u00a9]/;

function hasBidiOverride(v: string): boolean {
  return BIDI_OVERRIDE.test(v) || BIDI_RAW_UTF8.test(v);
}

export function evaluateRules(input: RuleInput): RuleHit[] {
  const hits: RuleHit[] = [];
  const p = input.parsed;

  /**
   * ① Message-ID 없음. RFC 5322 §3.6.4가 SHOULD이고, 정상 MUA·MTA는 사실상 전부 넣는다.
   * 없다는 것은 대개 스크립트가 직접 만든 메시지라는 뜻이다.
   */
  if (!p.messageId) hits.push({ rule: "no-message-id", weight: 1.5 });

  /** ② Date 없음. 같은 이유. 스레딩·정렬도 깨지므로 정상 발신자에게도 손해다. */
  if (!header(p, "date")) hits.push({ rule: "no-date", weight: 1.0 });

  /** ③ From 없음 — RFC 5322 MUST 위반. 정상 경로에서 나올 수 없다. */
  const fromRaw = header(p, "from");
  if (!fromRaw) {
    hits.push({ rule: "no-from", weight: 3.0 });
  } else if (hasBidiOverride(fromRaw)) {
    /**
     * ④ From에 양방향 제어문자 — 표시 이름을 뒤집어 주소를 위장한다.
     * 오탐이 사실상 없어 가중치를 높게 준다.
     */
    hits.push({ rule: "from-bidi-override", weight: 4.0 });
  }

  /**
   * ⑤ 표시 이름 안에 **다른 도메인의 주소**가 들어 있다.
   * `"security@bank.example" <attacker@evil.example>` 형태 — 메일 앱이 표시 이름만 보여줄 때
   * 그대로 속는다. 표시 이름의 주소와 실제 주소의 **도메인이 다를 때만** 잡는다
   * (자기 주소를 표시 이름에 그대로 쓰는 정상 메일이 흔하기 때문).
   */
  if (fromRaw) {
    const actual = domainOf(addrOf(fromRaw));
    const displayPart = fromRaw.split("<")[0] ?? "";
    const inDisplay = displayPart.match(/[\w.+-]+@[\w.-]+\.\w+/);
    if (actual && inDisplay) {
      const shown = domainOf(inDisplay[0].toLowerCase());
      if (shown && shown !== actual) {
        hits.push({ rule: "display-name-address-mismatch", weight: 3.0, detail: `${shown} vs ${actual}` });
      }
    }
  }

  /**
   * ⑥ To·Cc가 **둘 다 없다**. 수신자가 헤더 어디에도 없으면 BCC 대량발송의 흔한 모양이다.
   * (정상 메일링리스트는 List-* 헤더를 달거나 To에 리스트 주소를 넣는다.)
   */
  if (!header(p, "to") && !header(p, "cc") && !header(p, "list-id")) {
    hits.push({ rule: "no-recipient-header", weight: 1.0 });
  }

  /**
   * ⑦ HELO가 FQDN이 아니다(점이 없거나 IP 리터럴). RFC 5321 §4.1.1.1이 FQDN 또는
   * 대괄호 주소 리터럴을 요구한다 — 점 없는 이름은 규격 위반이다.
   * ⚠ 가중치를 낮게 둔다: 설정이 엉성한 정상 서버도 있다.
   */
  const helo = input.heloName?.trim();
  if (helo && !helo.startsWith("[") && !helo.includes(".")) {
    hits.push({ rule: "helo-not-fqdn", weight: 1.0, detail: helo });
  }

  /**
   * ⑧ 봉투 발신자 도메인과 From 도메인이 다르다.
   * ⚠ **가중치를 아주 낮게** 둔다. 메일링리스트·포워딩·바운스는 정상적으로 다르다
   * (그래서 DMARC가 SPF **또는** DKIM 정렬 중 하나만 요구한다). 단독으로는 신호가 못 되고,
   * 다른 신호와 겹칠 때만 의미가 있다.
   */
  const envDomain = domainOf(input.mailFrom.toLowerCase() || null);
  const fromDomain = domainOf(addrOf(fromRaw));
  if (envDomain && fromDomain && envDomain !== fromDomain) {
    hits.push({ rule: "envelope-from-mismatch", weight: 0.5, detail: `${envDomain} vs ${fromDomain}` });
  }

  return hits;
}
