/**
 * ARF(Abuse Reporting Format, RFC 5965) 파서 — 피드백 루프(FBL) 리포트에서
 * "우리 발송 중 어느 것이 신고당했는가"를 뽑는다. 순수 함수, I/O 없음.
 *
 * ★**본문을 읽지 않는다.** PLAN.md §8의 머리("운영자는 사용자 메일 내용을 열람하지 않는다")를
 * 여기서도 지킨다 — 리포트에 원문이 통째로 동봉돼 오지만, 우리가 꺼내는 것은 **식별자 헤더
 * 하나**뿐이다. 필요한 것이 "어느 발송인가"이지 "무슨 내용인가"가 아니기 때문이다.
 *
 * ★상관관계를 `verp_token`이 아니라 **헤더 식별자**로 잡는 이유: VERP는 봉투 재작성이
 * 붙어야 쓸 수 있는데 `enqueue.ts`가 그 작업을 의도적으로 미뤄 뒀다. 헤더 식별자는 봉투를
 * 건드리지 않고 지금 성립한다 — 없는 전제를 기다리지 않는다.
 */

/** 우리가 발송에 싣는 상관관계 헤더. 값은 `mta_queue.id`(ULID). */
export const FEEDBACK_ID_HEADER = "X-Ionosphere-Feedback-Id";

export interface ArfReport {
  /** `Feedback-Type:` — `abuse`·`fraud`·`not-spam` 등(RFC 5965 §7.3). */
  feedbackType: string;
  /** 동봉된 원문에서 찾은 우리 발송 식별자. 없으면 null(상관관계 불가). */
  queueId: string | null;
  /** `Original-Mail-From:` — 있으면 로그·진단에 쓴다. */
  originalMailFrom: string | null;
}

/** 헤더 블록에서 필드 하나(첫 값). 접힘(folding)을 편다. */
function headerValue(block: string, name: string): string | null {
  const re = new RegExp(`^${name}:[ \\t]*([^\\r\\n]*(?:\\r?\\n[ \\t][^\\r\\n]*)*)`, "im");
  const m = re.exec(block);
  return m?.[1] ? m[1].replace(/\r?\n[ \t]+/g, " ").trim() : null;
}

/**
 * ARF 리포트를 파싱한다. 형식이 아니면 null — **던지지 않는다.**
 * 이 입력은 외부에서 오고, 파싱 실패가 수신 처리를 멈추면 안 된다.
 *
 * `multipart/report; report-type=feedback-report`의 구조를 따르되, 파트 분해를 엄격히 하지
 * 않고 **필요한 필드만 훑는다**. 발신자마다 파트 구성이 미묘하게 다르고(Yahoo·MS가 서로
 * 다르다), 엄격한 파서는 그 차이에서 조용히 0건을 만든다 — 신고를 놓치는 쪽이 더 나쁘다.
 */
export function parseArf(raw: string): ArfReport | null {
  // `message/feedback-report` 파트가 있어야 ARF다. 없으면 그냥 메일이다.
  if (!/content-type:\s*message\/feedback-report/i.test(raw)) return null;

  const feedbackType = headerValue(raw, "Feedback-Type");
  if (!feedbackType) return null;

  return {
    feedbackType: feedbackType.toLowerCase(),
    queueId: headerValue(raw, FEEDBACK_ID_HEADER),
    originalMailFrom: headerValue(raw, "Original-Mail-From"),
  };
}

/**
 * 자동 정지 집계에 넣을 신고인가.
 *
 * ★`not-spam`은 **신고가 아니라 정정**이다(RFC 5965 §7.3). 이걸 세면 사용자가 "스팸
 * 아님"을 눌렀는데 발신자가 정지되는, 정반대 결과가 된다.
 * `abuse`·`fraud`만 센다 — 나머지(`virus`·`other`)는 발신자 책임으로 보기 애매하다.
 */
export function isCountableComplaint(feedbackType: string): boolean {
  return feedbackType === "abuse" || feedbackType === "fraud";
}
