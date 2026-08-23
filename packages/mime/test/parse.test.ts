import { sha256hex32 } from "@ionosphere/core";
import { parseMessage } from "@ionosphere/mime";
import { describe, expect, test } from "@ionosphere/testkit";

function toBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function crlf(lines: string[]): string {
  return lines.join("\r\n");
}

function b64(s: string): string {
  return Buffer.from(s, "utf-8").toString("base64");
}

/** 순수 ASCII/UTF-8 문자열을 본문용 quoted-printable로 인코딩 (테스트 픽스처 전용 헬퍼). */
function qpEncode(s: string): string {
  const bytes = Buffer.from(s, "utf-8");
  let out = "";
  for (const b of bytes) {
    if (b === 0x3d || b < 0x20 || b > 0x7e) {
      out += "=" + b.toString(16).toUpperCase().padStart(2, "0");
    } else {
      out += String.fromCharCode(b);
    }
  }
  return out;
}

describe("parseMessage — 단순 평문 메시지", () => {
  test("envelope 필드 + preview", () => {
    const raw = crlf([
      "From: Alice <alice@Example.com>",
      "To: Bob <bob@example.com>",
      "Subject: Hello there",
      "Date: Wed, 22 Jul 2026 10:00:00 +0900",
      "Message-ID: <abc123@example.com>",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Hello, this is a simple test message body.",
    ]);
    const msg = parseMessage(toBytes(raw));

    expect(msg.subject).toBe("Hello there");
    expect(msg.subjectBase).toBe("Hello there");
    expect(msg.messageId).toBe("abc123@example.com");
    expect(msg.msgidHash).toBe(sha256hex32("abc123@example.com"));
    expect(msg.msgidHash).toHaveLength(32);
    expect(msg.from).toEqual([{ name: "Alice", email: "alice@example.com" }]);
    expect(msg.to).toEqual([{ name: "Bob", email: "bob@example.com" }]);
    expect(msg.sentAt).toBe(Date.UTC(2026, 6, 22, 1, 0, 0)); // +0900 → UTC 01:00
    expect(msg.textBody).toBe("Hello, this is a simple test message body.");
    expect(msg.preview).toBe("Hello, this is a simple test message body.");
    expect(msg.hasAttachment).toBe(false);
    expect(msg.headers.get("from")).toEqual(["Alice <alice@Example.com>"]);
  });
});

describe("parseMessage — 폴딩 헤더 + RFC 2047", () => {
  test("폴딩된 Subject 언폴딩", () => {
    const raw = crlf([
      "From: test@example.com",
      "To: a@b.com",
      "Subject: Fwd: multi",
      " line",
      " subject",
      "",
      "body",
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.subject).toBe("Fwd: multi line subject");
    expect(msg.subjectBase).toBe("multi line subject");
  });

  test("B-인코딩 (UTF-8 한글) Subject 디코딩", () => {
    const encoded = `=?UTF-8?B?${b64("안녕")}?=`;
    const raw = crlf(["From: a@b.com", "To: c@d.com", `Subject: ${encoded}`, "", "body", ""]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.subject).toBe("안녕");
  });

  test("Q-인코딩 Subject 디코딩", () => {
    const raw = crlf([
      "From: a@b.com",
      "To: c@d.com",
      "Subject: =?UTF-8?Q?Caf=C3=A9_test?=",
      "",
      "body",
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.subject).toBe("Café test");
  });
});

describe("parseMessage — 주소 형식", () => {
  test('"Name" <a@B.com>, bare, list of 3 (콤마 포함 quoted display-name)', () => {
    const raw = crlf([
      "From: a@example.com",
      'To: "Alice A" <alice@EXAMPLE.com>, bare@example.com, "Carol, C" <carol@example.com>',
      "",
      "body",
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.to).toEqual([
      { name: "Alice A", email: "alice@example.com" },
      { name: null, email: "bare@example.com" },
      { name: "Carol, C", email: "carol@example.com" },
    ]);
  });

  test("그룹 구문 → 멤버로 평탄화", () => {
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      "Cc: Group: g1@example.com, g2@example.com;",
      "",
      "body",
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.cc).toEqual([
      { name: null, email: "g1@example.com" },
      { name: null, email: "g2@example.com" },
    ]);
  });

  test("손상된 주소는 전부 건너뜀 (throw 없음)", () => {
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      "Bcc: not-an-email, <>, @nodomain.com, missing@",
      "",
      "body",
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.bcc).toEqual([]);
  });
});

describe("parseMessage — MIME 구조", () => {
  test("multipart/alternative → text/plain 채택, multipart/mixed 첨부 → hasAttachment true", () => {
    const b1 = "AAA111";
    const b2 = "BBB222";
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      "Subject: multipart test",
      `Content-Type: multipart/mixed; boundary="${b1}"`,
      "",
      `--${b1}`,
      `Content-Type: multipart/alternative; boundary="${b2}"`,
      "",
      `--${b2}`,
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Plain text version.",
      `--${b2}`,
      "Content-Type: text/html; charset=utf-8",
      "",
      "<p>HTML version</p>",
      `--${b2}--`,
      `--${b1}`,
      'Content-Type: application/octet-stream; name="file.bin"',
      'Content-Disposition: attachment; filename="file.bin"',
      "Content-Transfer-Encoding: base64",
      "",
      b64("binary-ish-content"),
      `--${b1}--`,
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.textBody).toBe("Plain text version.");
    expect(msg.hasAttachment).toBe(true);
  });

  test("text/plain 없고 text/html만 있으면 스트립된 텍스트를 textBody로 사용", () => {
    const b1 = "ONLYHTML";
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      `Content-Type: multipart/alternative; boundary="${b1}"`,
      "",
      `--${b1}`,
      "Content-Type: text/html; charset=utf-8",
      "",
      "<p>Hello <b>World</b></p>",
      `--${b1}--`,
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.textBody).toBe("Hello World");
    expect(msg.hasAttachment).toBe(false);
  });
});

describe("parseMessage — 전송 인코딩 디코딩", () => {
  test("base64 본문 (UTF-8 한글) 디코딩", () => {
    const text = "안녕하세요, 테스트입니다.";
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: base64",
      "",
      b64(text),
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.textBody).toBe(text);
  });

  test("quoted-printable 본문 (UTF-8 한글) 디코딩", () => {
    const text = "안녕하세요, QP 테스트입니다.";
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      qpEncode(text),
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.textBody).toBe(text);
  });
});

describe("parseMessage — 스레딩 해시", () => {
  test("References/In-Reply-To → threadRefHashes 중복 제거, 32hex", () => {
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      "Message-ID: <msg3@example.com>",
      "In-Reply-To: <msg1@example.com>",
      "References: <msg1@example.com> <msg2@example.com>",
      "",
      "body",
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.inReplyTo).toEqual(["msg1@example.com"]);
    expect(msg.references).toEqual(["msg1@example.com", "msg2@example.com"]);
    expect(msg.threadRefHashes).toEqual([
      sha256hex32("msg3@example.com"),
      sha256hex32("msg1@example.com"),
      sha256hex32("msg2@example.com"),
    ]);
    for (const h of msg.threadRefHashes) expect(h).toHaveLength(32);
  });
});

describe("parseMessage — subjectBase", () => {
  test("Re:/RE:/Fwd: 반복 접두사 제거", () => {
    // 헤더 비ASCII는 RFC 2047 encoded-word로 실어야 표준 준수 (본문과 달리 raw UTF-8 헤더는 미지원).
    const encodedKorean = `=?UTF-8?B?${b64("안녕")}?=`;
    const raw = crlf([
      "From: a@example.com",
      "To: b@example.com",
      `Subject: Re: RE: Fwd: ${encodedKorean}`,
      "",
      "body",
      "",
    ]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.subject).toBe("Re: RE: Fwd: 안녕");
    expect(msg.subjectBase).toBe("안녕");
  });

  test("190자 초과 시 절단", () => {
    const longSubject = "a".repeat(250);
    const raw = crlf(["From: a@example.com", "To: b@example.com", `Subject: ${longSubject}`, "", "body", ""]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.subjectBase).toHaveLength(190);
    expect(msg.subjectBase).toBe("a".repeat(190));
  });
});

describe("parseMessage — 날짜 파싱", () => {
  test("+0900 타임존", () => {
    const raw = crlf(["From: a@example.com", "To: b@example.com", "Date: Wed, 22 Jul 2026 10:00:00 +0900", "", "body", ""]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.sentAt).toBe(Date.UTC(2026, 6, 22, 1, 0, 0));
  });

  test("구식 GMT 타임존", () => {
    const raw = crlf(["From: a@example.com", "To: b@example.com", "Date: 22 Jul 2026 10:00:00 GMT", "", "body", ""]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.sentAt).toBe(Date.UTC(2026, 6, 22, 10, 0, 0));
  });

  test("Date 헤더 없음 → null", () => {
    const raw = crlf(["From: a@example.com", "To: b@example.com", "", "body", ""]);
    const msg = parseMessage(toBytes(raw));
    expect(msg.sentAt).toBeNull();
  });
});

describe("parseMessage — 견고성 (throw 금지)", () => {
  test("무작위 바이트 → 예외 없이 null 값들로 축소", () => {
    const random = new Uint8Array(256);
    crypto.getRandomValues(random);
    expect(() => parseMessage(random)).not.toThrow();
    const msg = parseMessage(random);
    expect(msg.subject === null || typeof msg.subject === "string").toBe(true);
    expect(msg.from).toEqual([]);
  });

  test("빈 입력 → 예외 없이 전부 null/빈 값", () => {
    expect(() => parseMessage(new Uint8Array(0))).not.toThrow();
    const msg = parseMessage(new Uint8Array(0));
    expect(msg.subject).toBeNull();
    expect(msg.messageId).toBeNull();
    expect(msg.sentAt).toBeNull();
    expect(msg.textBody).toBeNull();
    expect(msg.preview).toBeNull();
    expect(msg.hasAttachment).toBe(false);
    expect(msg.from).toEqual([]);
    expect(msg.headers.size).toBe(0);
  });

  test("헤더만 있고 본문 없음 / 콜론 없는 손상된 헤더 줄 → throw 없음", () => {
    const raw = crlf(["From a@example.com (콜론 없음, 손상)", "To: b@example.com", "", ""]);
    expect(() => parseMessage(toBytes(raw))).not.toThrow();
    const msg = parseMessage(toBytes(raw));
    expect(msg.to).toEqual([{ name: null, email: "b@example.com" }]);
  });
});
