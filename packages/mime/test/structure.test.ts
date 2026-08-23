/** parseStructure — MIME 파트 트리·오프셋 테스트. */
import { describe, expect, test } from "@ionosphere/testkit";
import { parseStructure } from "../src/structure.ts";

const enc = new TextEncoder();

function crlf(s: string): Uint8Array {
  return enc.encode(s.replaceAll("\n", "\r\n"));
}

describe("parseStructure — 단일 파트", () => {
  test("텍스트 메시지 — 오프셋/크기/라인 수", () => {
    const raw = crlf("Subject: hi\nContent-Type: text/plain; charset=utf-8\n\nhello\nworld\n");
    const p = parseStructure(raw);
    expect(p.type).toBe("text");
    expect(p.subtype).toBe("plain");
    expect(p.params["charset"]).toBe("utf-8");
    expect(p.children).toHaveLength(0);
    const body = raw.subarray(p.bodyStart, p.end);
    expect(new TextDecoder().decode(body)).toBe("hello\r\nworld\r\n");
    expect(p.size).toBe(body.length);
    expect(p.lines).toBe(2);
    expect(p.encoding).toBe("7bit");
  });

  test("Content-Type 없음 → text/plain 기본값", () => {
    const p = parseStructure(crlf("Subject: x\n\nbody\n"));
    expect(p.type).toBe("text");
    expect(p.subtype).toBe("plain");
  });

  test("본문 없음(빈 줄 없음) — size 0", () => {
    const p = parseStructure(crlf("Subject: only-header"));
    expect(p.size).toBe(0);
    expect(p.bodyStart).toBe(p.end);
  });

  test("CTE/Content-ID/디스포지션 추출", () => {
    const raw = crlf(
      "Content-Type: application/pdf; name=doc.pdf\nContent-Transfer-Encoding: BASE64\nContent-ID: <cid1>\nContent-Disposition: attachment; filename=doc.pdf\n\nQUJD\n",
    );
    const p = parseStructure(raw);
    expect(p.type).toBe("application");
    expect(p.encoding).toBe("base64");
    expect(p.contentId).toBe("<cid1>");
    expect(p.disposition).toEqual({ type: "attachment", params: { filename: "doc.pdf" } });
  });
});

describe("parseStructure — multipart", () => {
  const MSG = crlf(
    [
      "From: a@x",
      'Content-Type: multipart/mixed; boundary="BB"',
      "",
      "preamble",
      "--BB",
      "Content-Type: text/plain",
      "",
      "part one",
      "--BB",
      "Content-Type: application/octet-stream",
      "Content-Transfer-Encoding: base64",
      "",
      "QUJD",
      "--BB--",
      "epilogue",
      "",
    ].join("\n"),
  );

  test("자식 2개 — 각 파트의 타입·본문 바이트 정확", () => {
    const p = parseStructure(MSG);
    expect(p.type).toBe("multipart");
    expect(p.children).toHaveLength(2);
    const [c1, c2] = p.children;
    expect(c1!.type).toBe("text");
    expect(new TextDecoder().decode(MSG.subarray(c1!.bodyStart, c1!.end))).toBe("part one");
    expect(c2!.type).toBe("application");
    expect(c2!.encoding).toBe("base64");
    expect(new TextDecoder().decode(MSG.subarray(c2!.bodyStart, c2!.end))).toBe("QUJD");
  });

  test("중첩 multipart/alternative", () => {
    const raw = crlf(
      [
        'Content-Type: multipart/mixed; boundary="OUT"',
        "",
        "--OUT",
        'Content-Type: multipart/alternative; boundary="IN"',
        "",
        "--IN",
        "Content-Type: text/plain",
        "",
        "plain",
        "--IN",
        "Content-Type: text/html",
        "",
        "<b>html</b>",
        "--IN--",
        "--OUT--",
        "",
      ].join("\n"),
    );
    const p = parseStructure(raw);
    expect(p.children).toHaveLength(1);
    const alt = p.children[0]!;
    expect(alt.subtype).toBe("alternative");
    expect(alt.children.map((c) => c.subtype)).toEqual(["plain", "html"]);
  });

  test("최종 바운더리 유실(손상) — 남은 범위를 마지막 파트로", () => {
    const raw = crlf(['Content-Type: multipart/mixed; boundary="B"', "", "--B", "Content-Type: text/plain", "", "tail"].join("\n"));
    const p = parseStructure(raw);
    expect(p.children).toHaveLength(1);
    expect(new TextDecoder().decode(raw.subarray(p.children[0]!.bodyStart, p.children[0]!.end))).toBe("tail");
  });

  test("바운더리 파라미터 없음 — 자식 없이 단일 취급", () => {
    const p = parseStructure(crlf("Content-Type: multipart/mixed\n\nbody\n"));
    expect(p.children).toHaveLength(0);
  });
});

describe("parseStructure — message/rfc822", () => {
  test("내포 메시지 1개 — 재귀 구조", () => {
    const raw = crlf(
      [
        'Content-Type: multipart/mixed; boundary="M"',
        "",
        "--M",
        "Content-Type: message/rfc822",
        "",
        "Subject: inner",
        "Content-Type: text/plain",
        "",
        "inner body",
        "--M--",
        "",
      ].join("\n"),
    );
    const p = parseStructure(raw);
    const rfc = p.children[0]!;
    expect(rfc.type).toBe("message");
    expect(rfc.children).toHaveLength(1);
    const inner = rfc.children[0]!;
    expect(inner.type).toBe("text");
    // 바운더리 앞 CRLF는 바운더리 소속(RFC 2046) — 내포 본문에 트레일링 CRLF 없음
    expect(new TextDecoder().decode(raw.subarray(inner.bodyStart, inner.end))).toBe("inner body");
  });
});
