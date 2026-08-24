/**
 * DSN(Delivery Status Notification) 생성 — RFC 3464 `multipart/report`. 순수 함수, I/O 0.
 *
 * ★왜 이게 없었나가 아니라 **없으면 무엇이 깨지나**: 발송이 영구 실패하면 워커가 큐 행을
 * `bounced`로 닫고 수신자를 suppression에 넣는 것으로 끝났다. 587로 제출한 사용자는 250을
 * 받은 뒤 **아무것도 통보받지 못한다.** `GET /v1/queue`를 보는 테넌트 관리자만 안다.
 * 사용자 체감으로 "보냈는데 안 갔고 아무 말도 없었다"이고, 메일 서버에서 이게 가장 나쁜
 * 실패 형태다. RFC 5321 §6.1이 MUST로 요구하고("MUST formulate and mail a notification
 * message"), `docs/PROTOCOLS.md`도 DSN 생성을 MUST 티어 · Phase 1로 이미 적어 뒀다.
 *
 * ★받을 준비는 이미 돼 있었다: `enqueue.ts`의 `SystemRelay.envFrom: "null-sender"`가
 * "RFC 5321 §4.5.5가 DSN의 reverse-path를 null로 요구하고, 이중 바운스도 이것으로 끊긴다"고
 * 적힌 채 존재했다. 만드는 쪽만 없었다.
 *
 * 설계 결정:
 *
 * · **원문 전체가 아니라 헤더만 동봉한다**(`message/rfc822-headers`, RFC 6522 §4).
 *   25MB 메시지가 실패하면 바운스도 25MB가 되고, 그것이 다시 실패하면 큐가 원문 두 벌을
 *   붙든다. 헤더만으로도 발신자는 "어느 메일인지"를 안다 — 그게 DSN의 목적이다.
 *
 * · **본문을 읽지 않는다.** PLAN §8의 "운영자는 사용자 메일 내용을 열람하지 않는다"를
 *   여기서도 지킨다(`arf.ts`가 같은 이유로 식별자 헤더 하나만 꺼내는 것과 같은 규율).
 *
 * · 진단 문구는 **이미 `redactForTenant()`를 통과한 값**을 받는다(`worker.ts` M-11) —
 *   DSN은 발신자에게 그대로 가므로 우리 인프라 내부가 실려서는 안 된다.
 */
import { rfc5322Date } from "@ionosphere/core";

/** 이 DSN이 무엇을 알리는가 (RFC 3464 §2.3.3 `Action`). */
export const DSN_ACTION = {
  /** 영구 실패 — 더 시도하지 않는다. */
  failed: "failed",
  /** 아직 큐에 있다 — 지연 통보(RFC 5321 §4.5.4.1). */
  delayed: "delayed",
} as const;
export type DsnAction = (typeof DSN_ACTION)[keyof typeof DSN_ACTION];

export interface DsnRecipient {
  /** 실패한 수신자 주소. */
  rcpt: string;
  action: DsnAction;
  /**
   * RFC 3463 enhanced status code (`5.1.1` 등). 원격이 준 것이 없으면 코드에서 유도한다.
   */
  status: string;
  /** 원격 MTA의 거절 문구 — **이미 테넌트 노출용으로 정제된 값**이어야 한다. */
  diagnostic?: string | undefined;
  /** 응답을 준 상대(진단용). 없으면 생략. */
  remoteMta?: string | undefined;
}

export interface DsnInput {
  /** 원 메시지의 봉투 발신자 — DSN이 갈 곳. 비어 있으면 DSN을 만들면 안 된다(이중 바운스). */
  originalEnvelopeFrom: string;
  /** 보고 MTA 이름(우리 호스트). `Reporting-MTA`와 `From:`에 쓴다. */
  reportingMta: string;
  recipients: readonly DsnRecipient[];
  /** 원 메시지 원문 — 헤더 블록만 잘라 동봉한다. */
  originalMessage: Uint8Array;
  /** 원 메시지의 `Message-ID`(있으면 `In-Reply-To`·`References`로 스레딩). */
  originalMessageId?: string | undefined;
  /** 테스트 결정성. 생략 시 `new Date()`. */
  now?: Date | undefined;
  /** 테스트 결정성. 생략 시 난수 바운더리. */
  boundary?: string | undefined;
};

/** SMTP 코드 → RFC 3463 enhanced status. 원격이 enhanced를 안 주는 경우의 폴백. */
export function enhancedStatusFor(code: number, action: DsnAction): string {
  const cls = action === DSN_ACTION.delayed ? 4 : code >= 500 ? 5 : 4;
  // 코드별 세부는 추정하지 않는다 — 틀린 세부보다 일반값이 낫다(x.0.0은 "기타"로 정의돼 있다).
  if (code === 550 || code === 551) return `${cls}.1.1`; // 그런 사용자 없음
  if (code === 552) return `${cls}.2.2`; // 사서함 용량 초과
  if (code === 553) return `${cls}.1.3`; // 주소 문법
  if (code === 450 || code === 451 || code === 452) return `${cls}.3.0`;
  return `${cls}.0.0`;
}

/** 헤더 블록만 — 빈 줄 이전까지(CRLF·LF·CR 혼용 관용). 못 찾으면 전체를 헤더로 본다. */
function headerBlockOf(raw: Uint8Array): string {
  // latin1 왕복은 바이트 보존이다(mail-auth canon.ts와 같은 규율).
  const bin = Buffer.from(raw).toString("latin1");
  for (const sep of ["\r\n\r\n", "\n\n", "\r\r"]) {
    const i = bin.indexOf(sep);
    if (i !== -1) return bin.slice(0, i);
  }
  return bin;
}

/**
 * 헤더 값에 실을 수 없는 문자를 지운다.
 *
 * ★DSN은 **공격자가 정한 값**(수신자 주소·원격 응답 문구)을 헤더에 싣는다. CR/LF가 그대로
 * 들어가면 그것이 곧 헤더 주입이다 — 우리가 만든 메시지가 우리 파서를 속이는 형태가 된다.
 */
function headerSafe(value: string, maxLen: number): string {
  const cleaned = value.replace(/[\r\n\0]/g, " ").trim();
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) : cleaned;
}

/** 사람이 읽는 첫 파트 — 클라이언트가 이것만 보여 주는 경우가 많다. */
function humanText(input: DsnInput): string {
  const failed = input.recipients.filter((r) => r.action === DSN_ACTION.failed);
  const delayed = input.recipients.filter((r) => r.action === DSN_ACTION.delayed);
  const lines: string[] = [`This is an automatically generated Delivery Status Notification.`, ""];
  if (failed.length > 0) {
    lines.push("Delivery to the following recipient(s) failed permanently:", "");
    for (const r of failed) {
      lines.push(`  ${headerSafe(r.rcpt, 320)}`);
      if (r.diagnostic) lines.push(`    ${headerSafe(r.diagnostic, 400)}`);
    }
    lines.push("");
  }
  if (delayed.length > 0) {
    lines.push("Delivery to the following recipient(s) is delayed:", "");
    for (const r of delayed) {
      lines.push(`  ${headerSafe(r.rcpt, 320)}`);
      if (r.diagnostic) lines.push(`    ${headerSafe(r.diagnostic, 400)}`);
    }
    lines.push("", "The server will keep trying. You do not need to resend the message.", "");
  }
  return lines.join("\r\n");
}

/** `message/delivery-status` 파트 — 기계가 읽는 부분(RFC 3464 §2). */
function deliveryStatus(input: DsnInput): string {
  const blocks: string[] = [`Reporting-MTA: dns; ${headerSafe(input.reportingMta, 255)}`];
  for (const r of input.recipients) {
    const fields = [
      "",
      `Final-Recipient: rfc822; ${headerSafe(r.rcpt, 320)}`,
      `Action: ${r.action}`,
      `Status: ${headerSafe(r.status, 32)}`,
    ];
    if (r.remoteMta) fields.push(`Remote-MTA: dns; ${headerSafe(r.remoteMta, 255)}`);
    if (r.diagnostic) fields.push(`Diagnostic-Code: smtp; ${headerSafe(r.diagnostic, 400)}`);
    blocks.push(fields.join("\r\n"));
  }
  return blocks.join("\r\n") + "\r\n";
}

/** 바운더리 — 원문에 우연히 등장하지 않도록 난수를 쓴다. */
function makeBoundary(): string {
  return `=_ionosphere_dsn_${Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0")}${Date.now().toString(36)}`;
}

/**
 * DSN 메시지 바이트를 만든다.
 *
 * ⚠ **호출자가 이중 바운스를 먼저 끊어야 한다** — `originalEnvelopeFrom`이 비어 있으면
 * (null sender) DSN을 만들지 말 것. 여기서 던지지 않고 호출자 책임으로 두는 이유는, 그
 * 판정에 필요한 맥락(큐 행이 시스템 발송인가)이 워커에 있기 때문이다. 다만 실수로 빈 값이
 * 오면 만들지 않도록 방어는 한다.
 */
export function buildDsn(input: DsnInput): Uint8Array | null {
  if (input.originalEnvelopeFrom.trim() === "") return null;
  if (input.recipients.length === 0) return null;

  const now = input.now ?? new Date();
  const boundary = input.boundary ?? makeBoundary();
  const anyFailed = input.recipients.some((r) => r.action === DSN_ACTION.failed);
  const subject = anyFailed ? "Undelivered Mail Returned to Sender" : "Delivery Status Notification (Delayed)";

  const headers = [
    `From: Mail Delivery Subsystem <MAILER-DAEMON@${headerSafe(input.reportingMta, 255)}>`,
    `To: ${headerSafe(input.originalEnvelopeFrom, 320)}`,
    `Subject: ${subject}`,
    `Date: ${rfc5322Date(now)}`,
    // RFC 3834 §3.1.7 — 자동 응답이 이 메시지에 다시 답하지 않게 한다(루프 차단의 한 겹).
    "Auto-Submitted: auto-replied",
    `Content-Type: multipart/report; report-type=delivery-status; boundary="${boundary}"`,
    "MIME-Version: 1.0",
  ];
  if (input.originalMessageId) {
    const mid = headerSafe(input.originalMessageId, 400);
    headers.push(`In-Reply-To: ${mid}`, `References: ${mid}`);
  }

  const body = [
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    humanText(input),
    `--${boundary}`,
    "Content-Type: message/delivery-status",
    "",
    deliveryStatus(input),
    `--${boundary}`,
    // 원문 전체가 아니라 헤더만 — 위 파일 주석 참조.
    "Content-Type: message/rfc822-headers",
    "",
    headerBlockOf(input.originalMessage),
    "",
    `--${boundary}--`,
    "",
  ].join("\r\n");

  return new Uint8Array(Buffer.from(headers.join("\r\n") + "\r\n" + body, "latin1"));
}
