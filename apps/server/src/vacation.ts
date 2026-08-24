/**
 * Sieve `vacation` 자동 응답의 **판정과 조립** (RFC 5230 §4.5·§4.6). 순수 함수, I/O 0.
 *
 * ★이 파일의 대부분은 "보내지 않을 이유"다. 자동 응답에서 어려운 것은 보내는 쪽이 아니라
 * 멈추는 쪽이다 — 잘못 보내면 무한 루프이거나, 메일링리스트 전원에게 부재 알림을 뿌리거나,
 * 바운스에 답장해 메일 폭풍을 만든다. 그래서 게이트를 한 함수에 모아 두고 **이유를 남긴다**
 * (운영자가 "왜 답장이 안 갔나"에 답할 수 있어야 한다).
 */
import { rfc5322Date, sha256hex32 } from "@ionosphere/core";
import type { ParsedMessage } from "@ionosphere/mime";
import type { VacationRequest } from "@ionosphere/sieve";

/** 보내지 않기로 한 이유 — 로그에 그대로 남는다. */
export type VacationSkip =
  | "null-sender"
  | "auto-submitted"
  | "mailing-list"
  | "bulk-precedence"
  | "not-addressed-to-me"
  | "self";

export type VacationDecision =
  | { send: false; reason: VacationSkip }
  | { send: true; to: string; handle: string; days: number };

/** 헤더 첫 값(소문자 키 맵). */
function header(parsed: ParsedMessage, name: string): string | null {
  return parsed.headers.get(name)?.[0] ?? null;
}

/**
 * 자동 응답을 보내도 되는가 (RFC 5230 §4.6).
 *
 * 게이트 순서는 **싼 것부터**가 아니라 **확실한 것부터**다 — null 발신자와 자동 제출 표시는
 * 논쟁의 여지가 없는 거절 사유이고, 수신자 판정은 그다음이다.
 */
export function decideVacation(input: {
  request: VacationRequest;
  parsed: ParsedMessage;
  /** 봉투 발신자 — 응답이 갈 곳이자 루프 차단의 첫 기준. */
  envelopeFrom: string;
  /** 이 계정의 주소들(대표 주소 + 알리아스). `:addresses`와 합쳐 "내 주소"를 만든다. */
  ownAddresses: readonly string[];
}): VacationDecision {
  const { request, parsed, envelopeFrom } = input;

  /**
   * ★null 발신자(`<>`)에는 절대 답하지 않는다. 그건 바운스이거나 다른 자동 발송이고,
   * 답하면 그 답이 다시 바운스돼 돌아온다. RFC 5230 §4.6의 첫 조건이다.
   */
  if (envelopeFrom.trim() === "") return { send: false, reason: "null-sender" };

  /**
   * ★`Auto-Submitted:`(RFC 3834) — `no`가 아니면 자동 발송이다. 우리 DSN도 이 헤더를
   * 달고 나가므로, 이 검사가 없으면 우리 바운스에 우리 부재 응답이 붙는다.
   */
  const autoSubmitted = header(parsed, "auto-submitted");
  if (autoSubmitted !== null && autoSubmitted.trim().toLowerCase() !== "no") {
    return { send: false, reason: "auto-submitted" };
  }

  /**
   * ★메일링리스트에는 답하지 않는다. 답하면 리스트 전원이 내 부재 알림을 받고, 그중 누군가도
   * 부재 응답을 켜 뒀다면 그때부터 서로 답한다.
   */
  for (const h of ["list-id", "list-post", "list-unsubscribe", "list-help"]) {
    if (header(parsed, h) !== null) return { send: false, reason: "mailing-list" };
  }
  const precedence = header(parsed, "precedence")?.trim().toLowerCase();
  if (precedence === "bulk" || precedence === "list" || precedence === "junk") {
    return { send: false, reason: "bulk-precedence" };
  }

  const own = new Set(
    [...input.ownAddresses, ...request.addresses].map((a) => a.trim().toLowerCase()).filter((a) => a.length > 0),
  );

  /** 자기 자신에게는 답하지 않는다 — 전달·복사 설정에서 실제로 도는 형태다. */
  if (own.has(envelopeFrom.trim().toLowerCase())) return { send: false, reason: "self" };

  /**
   * ★수신자 헤더에 **내 주소가 있어야** 한다(§4.6). 없다는 것은 이 메일이 나를 직접 향한
   * 것이 아니라는 뜻이다 — 리스트 헤더가 없는 리스트, Bcc 대량 발송, 캐치올로 들어온 메일이
   * 여기 걸린다. 이 검사가 자동 응답을 "받은 사람에게만" 묶는 마지막 장치다.
   */
  const addressed = [...parsed.to, ...parsed.cc].some((a) => own.has(a.email.trim().toLowerCase()));
  if (!addressed) return { send: false, reason: "not-addressed-to-me" };

  return {
    send: true,
    to: envelopeFrom,
    /**
     * `:handle`이 없으면 본문에서 유도한다(§4.4의 취지 — 같은 부재 응답이면 같은 핸들).
     * 제목까지 섞는 이유: 본문이 같고 제목만 바꾼 경우도 "같은 응답"으로 보는 편이
     * 중복 억제 쪽으로 안전하게 틀린다.
     */
    handle: request.handle ?? sha256hex32(`${request.subject ?? ""}\u0000${request.reason}`),
    days: request.days,
  };
}

/** 응답 제목 — `:subject`가 없으면 원 제목에 `Auto:`를 붙인다(§4.2 권고). */
function replySubject(request: VacationRequest, parsed: ParsedMessage): string {
  if (request.subject !== null) return request.subject;
  const original = parsed.subject?.trim();
  return original ? `Auto: ${original}` : "Automatic reply";
}

/** 헤더 값에 실을 수 없는 문자를 지운다 — 값의 출처가 사용자 스크립트와 원 메일이다. */
function headerSafe(value: string, maxLen: number): string {
  const cleaned = value.replace(/[\r\n\0]/g, " ").trim();
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) : cleaned;
}

/**
 * 자동 응답 메시지 바이트.
 *
 * ★`Auto-Submitted: auto-replied`(RFC 3834)를 **반드시** 단다. 이것이 상대의 자동 응답기가
 * 우리에게 답하지 않게 하는 표시고, 우리 쪽 `decideVacation`이 보는 것과 같은 헤더다 —
 * 둘이 같은 규약을 쓰기 때문에 루프가 닫힌다.
 */
export function buildVacationReply(input: {
  request: VacationRequest;
  parsed: ParsedMessage;
  to: string;
  /** From — `:from`이 없으면 조립층이 계정 주소를 넘긴다. */
  from: string;
  now?: Date;
}): Uint8Array {
  const { request, parsed } = input;
  const from = headerSafe(request.from ?? input.from, 320);
  const headers = [
    `From: ${from}`,
    `To: ${headerSafe(input.to, 320)}`,
    `Subject: ${headerSafe(replySubject(request, parsed), 400)}`,
    `Date: ${rfc5322Date(input.now ?? new Date())}`,
    "Auto-Submitted: auto-replied",
    // RFC 3834 §3.1.5 — 자동 응답에는 이 표시도 관례다(옛 클라이언트가 이것만 보기도 한다).
    "Precedence: bulk",
    "X-Auto-Response-Suppress: All",
  ];
  const messageId = parsed.messageId;
  if (messageId !== null) {
    const mid = headerSafe(`<${messageId}>`, 400);
    headers.push(`In-Reply-To: ${mid}`, `References: ${mid}`);
  }

  /**
   * `:mime`이면 reason이 **이미 MIME 본문**이다(헤더 포함) — 우리가 Content-Type을 덧붙이면
   * 두 벌이 된다. 아니면 평문으로 감싼다.
   */
  if (request.mime) {
    return new Uint8Array(Buffer.from(`${headers.join("\r\n")}\r\n${request.reason}`, "utf8"));
  }
  headers.push("Content-Type: text/plain; charset=utf-8", "MIME-Version: 1.0");
  return new Uint8Array(Buffer.from(`${headers.join("\r\n")}\r\n\r\n${request.reason}\r\n`, "utf8"));
}
