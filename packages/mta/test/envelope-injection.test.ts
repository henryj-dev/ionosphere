/**
 * 봉투 주소 CR/LF 주입 차단.
 *
 * 수신 엔진은 CRLF로만 줄을 자르므로 `MAIL FROM:<a\nb@c>` 처럼 **단일 LF**가 주소 안에
 * 그대로 남는다(정규식 `<([^>]*)>`는 LF를 걸러내지 않는다). 그 값이 큐를 거쳐 발신 SMTP
 * 명령 줄로 나가면 bare-LF를 줄 종료로 받아들이는 상대 MTA에서 **임의 명령이 주입된다** —
 * 추가 RCPT를 끼워 넣어 우리 쪽 수신자 회계·suppression·과금을 우회할 수 있다.
 *
 * 적재 시점과 전송 시점 양쪽을 검증한다. 전송 시점 검사가 따로 필요한 이유: 이 수정 이전에
 * 이미 DB에 들어간 오염된 값이 있을 수 있다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { ulid } from "@ionosphere/core";
import { enqueueMessage, OutboundRejectedError } from "../src/enqueue.ts";
import { isSafeEnvelopeAddress } from "../src/envelope.ts";
import { sendSmtp } from "../src/smtp-client.ts";
import { freshDb, verifiedDomain } from "./helpers.ts";

const LF_INJECTED = "victim@test.local\nRCPT TO:<extra@evil.test>";
const CR_INJECTED = "victim@test.local\rRCPT TO:<extra@evil.test>";

describe("isSafeEnvelopeAddress", () => {
  test("정상 주소는 통과, null sender(빈 문자열)도 통과", () => {
    expect(isSafeEnvelopeAddress("user@example.test")).toBe(true);
    expect(isSafeEnvelopeAddress("")).toBe(true); // <> 바운스
  });

  test("줄바꿈·NUL·꺾쇠·공백은 거부", () => {
    expect(isSafeEnvelopeAddress(LF_INJECTED)).toBe(false);
    expect(isSafeEnvelopeAddress(CR_INJECTED)).toBe(false);
    expect(isSafeEnvelopeAddress("a\u0000b@x.test")).toBe(false);
    expect(isSafeEnvelopeAddress("a<b@x.test")).toBe(false);
    expect(isSafeEnvelopeAddress("a b@x.test")).toBe(false);
  });
});

describe("적재 시점 차단(enqueueMessage)", () => {
  test("수신자에 LF가 있으면 큐에 넣지 않는다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "test.local");

    await expect(
      enqueueMessage(db, {
        tenantId,
        blobId: "a".repeat(64),
        sizeBytes: 10,
        envFrom: "sender@test.local",
        rcpts: [LF_INJECTED],
      }),
    ).rejects.toThrow(OutboundRejectedError);

    const { rows } = await db.query({ sql: "SELECT id FROM mta_queue" });
    expect(rows).toHaveLength(0); // 오염된 값이 DB에 남지 않는다
    await db.close();
  });

  test("envelope-from에 LF가 있으면 거부한다", async () => {
    const db = await freshDb();
    const tenantId = ulid();
    await verifiedDomain(db, tenantId, "test.local");

    const err = await enqueueMessage(db, {
      tenantId,
      blobId: "b".repeat(64),
      sizeBytes: 10,
      envFrom: LF_INJECTED,
      rcpts: ["ok@remote.test"],
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OutboundRejectedError);
    expect((err as OutboundRejectedError).reason).toBe("invalid-address");
    await db.close();
  });
});

describe("전송 시점 차단(sendSmtp)", () => {
  test("이미 오염된 값이 큐에 있어도 소켓에 쓰지 않는다", async () => {
    // 연결조차 시도하지 않아야 하므로, 아무도 듣지 않는 포트를 준다 —
    // 검사가 없으면 연결 실패(code 0)가 되고, 검사가 있으면 그 전에 550으로 막힌다.
    const res = await sendSmtp({
      host: "127.0.0.1",
      port: 1,
      ehloName: "mx.test",
      mailFrom: "sender@test.local",
      rcptTo: [LF_INJECTED],
      raw: new TextEncoder().encode("Subject: x\r\n\r\nbody\r\n"),
      tls: "never",
      timeoutMs: 2000,
    });

    expect(res.ok).toBe(false);
    expect(res.code).toBe(550);
    expect(res.permanent).toBe(true); // 주소가 틀린 것이라 재시도해도 같다
    expect(res.message).toContain("injection guard");
  });
});
