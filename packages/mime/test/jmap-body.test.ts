/** extractJmapBody — JMAP EmailBodyPart 구조·분류·bodyValues 디코드 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { extractJmapBody } from "../src/jmap-body.ts";

const enc = new TextEncoder();
function crlf(s: string): Uint8Array {
  return enc.encode(s.replaceAll("\n", "\r\n"));
}

describe("단일 파트", () => {
  test("text/plain — textBody+htmlBody 모두 이 파트, bodyValue 디코드", () => {
    const raw = crlf("Subject: hi\nContent-Type: text/plain; charset=utf-8\n\nhello world\n");
    const b = extractJmapBody(raw);
    expect(b.bodyStructure.type).toBe("text/plain");
    expect(b.textBody).toHaveLength(1);
    expect(b.htmlBody).toHaveLength(1); // html 없으면 text를 가리킴
    const pid = b.textBody[0]!.partId!;
    expect(b.bodyValues[pid]!.value).toBe("hello world\r\n");
  });

  test("quoted-printable 디코드", () => {
    const raw = crlf("Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nhi=3Dthere\n");
    const b = extractJmapBody(raw);
    const pid = b.textBody[0]!.partId!;
    expect(b.bodyValues[pid]!.value).toContain("hi=there");
  });

  test("maxBodyValueBytes 절단 → isTruncated", () => {
    const raw = crlf("Content-Type: text/plain\n\n0123456789abcdef\n");
    const b = extractJmapBody(raw, 5);
    const pid = b.textBody[0]!.partId!;
    expect(b.bodyValues[pid]!.value).toBe("01234");
    expect(b.bodyValues[pid]!.isTruncated).toBe(true);
  });
});

describe("multipart/alternative", () => {
  const raw = crlf(
    [
      'Content-Type: multipart/alternative; boundary="B"',
      "",
      "--B",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "plain version",
      "--B",
      "Content-Type: text/html; charset=utf-8",
      "",
      "<b>html version</b>",
      "--B--",
      "",
    ].join("\n"),
  );

  test("textBody=plain, htmlBody=html, 각 bodyValue", () => {
    const b = extractJmapBody(raw);
    expect(b.bodyStructure.type).toBe("multipart/alternative");
    expect(b.bodyStructure.subParts).toHaveLength(2);
    expect(b.textBody[0]!.type).toBe("text/plain");
    expect(b.htmlBody[0]!.type).toBe("text/html");
    expect(b.bodyValues[b.textBody[0]!.partId!]!.value).toBe("plain version");
    expect(b.bodyValues[b.htmlBody[0]!.partId!]!.value).toBe("<b>html version</b>");
  });
});

describe("multipart/mixed with attachment", () => {
  const raw = crlf(
    [
      'Content-Type: multipart/mixed; boundary="M"',
      "",
      "--M",
      "Content-Type: text/plain",
      "",
      "body text",
      "--M",
      "Content-Type: application/pdf; name=doc.pdf",
      "Content-Disposition: attachment; filename=doc.pdf",
      "Content-Transfer-Encoding: base64",
      "",
      "QUJD",
      "--M--",
      "",
    ].join("\n"),
  );

  test("텍스트는 textBody, pdf는 attachments(name/type/disposition)", () => {
    const b = extractJmapBody(raw);
    expect(b.textBody).toHaveLength(1);
    expect(b.textBody[0]!.type).toBe("text/plain");
    expect(b.attachments).toHaveLength(1);
    const att = b.attachments[0]!;
    expect(att.type).toBe("application/pdf");
    expect(att.disposition).toBe("attachment");
    expect(att.name).toBe("doc.pdf");
    // 첨부는 bodyValues에 안 들어감(표시 본문만)
    expect(b.bodyValues[att.partId!]).toBeUndefined();
  });
});

describe("손상 입력 — throw 금지", () => {
  test("빈 입력도 단일 파트로 축소", () => {
    const b = extractJmapBody(new Uint8Array(0));
    expect(b.bodyStructure).toBeDefined();
    expect(Array.isArray(b.textBody)).toBe(true);
  });
});
