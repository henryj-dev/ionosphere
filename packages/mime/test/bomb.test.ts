/**
 * MIME 폭탄·파서 2차식 회귀 테스트 (2026-07-31 감사).
 *
 * 수신 메시지는 **미인증 원격**이 임의로 만들고, 전 프로토콜이 단일 프로세스에 올라가므로
 * 파서 하나가 CPU를 붙들면 25·587·993이 함께 멈춘다. 여기서 지키는 것은 두 가지다:
 *   1) 폭탄 입력이 **상한에 걸려 거부**된다(조용히 잘린 트리를 내지 않는다).
 *   2) 정상 MIME(중첩 multipart·첨부·message/rfc822)은 **그대로 파싱된다**.
 *
 * 시간 단언은 넉넉히 잡는다 — 고치기 전 실측이 초 단위(빈 파트 폭탄 1MB에 8.9초,
 * `<script>` 512KB에 9.5초)였고 지금은 밀리초라, 느슨한 상한으로도 2차식 재발은 확실히 걸린다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { MAX_MIME_PARTS } from "@ionosphere/core";
import { parseMessage } from "../src/parse.ts";
import { parseStructure } from "../src/structure.ts";
import { extractJmapBody } from "../src/jmap-body.ts";
import { stripHtml } from "../src/html.ts";
import { computeSubjectBase } from "../src/subject.ts";

/** 바이너리 문자열 → 바이트(1문자=1바이트). TextEncoder는 비ASCII를 늘려서 못 쓴다. */
function bin(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function elapsed(fn: () => void): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

const BUDGET_MS = 5000;

describe("파트 개수 상한", () => {
  test(`파트 ${MAX_MIME_PARTS}개까지는 그대로 파싱된다`, () => {
    // 루트도 파트 하나를 쓰므로 자식은 상한보다 하나 적어야 딱 맞는다.
    const children = MAX_MIME_PARTS - 1;
    const raw = bin(
      `Content-Type: multipart/mixed; boundary="B"\r\n\r\n${"--B\r\nContent-Type: text/plain\r\n\r\nx\r\n".repeat(children)}--B--\r\n`,
    );
    const p = parseStructure(raw);
    expect(p.type).toBe("multipart");
    expect(p.children).toHaveLength(children);
  });

  test("상한을 넘기면 잘린 트리가 아니라 단일 파트로 축소된다", () => {
    // 조용히 잘라내면 "파트가 그것뿐인 정상 메시지"와 구별되지 않는다 — 그게 새 결함이 된다.
    const raw = bin(
      `Content-Type: multipart/mixed; boundary="B"\r\n\r\n${"--B\r\nContent-Type: text/plain\r\n\r\nx\r\n".repeat(MAX_MIME_PARTS)}--B--\r\n`,
    );
    const p = parseStructure(raw);
    expect(p.children).toHaveLength(0);
    expect(p.type).toBe("text");
    expect(p.subtype).toBe("plain");
    expect(p.end).toBe(raw.length);
  });
});

describe("파트 개수 폭탄 — 2차식 회귀", () => {
  test("빈 파트 1MB(약 20만 파트)를 상한 안에서 처리한다", () => {
    // 고치기 전: 1MB에 8.9초, 2MB에 38초, 4MB에 155초(정확히 4배씩 = O(n²)).
    // 원인은 `findBodyStart`가 파트 범위가 아니라 **버퍼 끝까지** indexOf를 돌린 것이었다.
    const head = 'Content-Type: multipart/mixed; boundary="B"\r\n\r\n';
    const raw = bin(head + "--B\r\n".repeat(Math.floor((1024 * 1024 - head.length) / 5)));
    let p!: ReturnType<typeof parseStructure>;
    expect(elapsed(() => (p = parseStructure(raw)))).toBeLessThan(BUDGET_MS);
    expect(p.children).toHaveLength(0); // 상한 초과 → 축소
  });

  test("자식마다 존재하지 않는 바운더리를 선언해도 빨리 끝난다", () => {
    // `splitParts`의 낭비 스캔 경로 — 고치기 전 4.5MB에 8.1초.
    const raw = bin(
      `Content-Type: multipart/mixed; boundary="B"\r\n\r\n${'--B\r\nContent-Type: multipart/x; boundary="NONE"\r\n\r\n\n\nx\r\n'.repeat(20000)}--B--\r\n`,
    );
    expect(elapsed(() => parseStructure(raw))).toBeLessThan(BUDGET_MS);
  });

  test("parseMessage·extractJmapBody도 같은 입력에서 버티고 throw하지 않는다", () => {
    const head = 'Content-Type: multipart/mixed; boundary="B"\r\n\r\n';
    const raw = bin(head + "--B\r\n".repeat(Math.floor((1024 * 1024 - head.length) / 5)));
    let m!: ReturnType<typeof parseMessage>;
    expect(elapsed(() => (m = parseMessage(raw)))).toBeLessThan(BUDGET_MS);
    expect(elapsed(() => extractJmapBody(raw, 1024))).toBeLessThan(BUDGET_MS);
    // 두 파서가 **같은 판정**을 내야 한다: `parseStructure`가 단일 파트로 축소한 메시지를
    // 본문 추출기가 계속 걸어 들어가면, 같은 입력을 서로 다르게 읽는 상태가 다시 생긴다.
    expect(m.textBody).toBeNull();
    expect(m.hasAttachment).toBe(false);
  });
});

describe("중첩 깊이", () => {
  test("깊이 10,000짜리 중첩 multipart에 스택 오버플로가 나지 않는다", () => {
    const open: string[] = [];
    const close: string[] = [];
    for (let i = 0; i < 10000; i++) {
      open.push(`Content-Type: multipart/mixed; boundary="b${i}"\r\n\r\n--b${i}\r\n`);
      close.unshift(`\r\n--b${i}--\r\n`);
    }
    const raw = bin(`${open.join("")}Content-Type: text/plain\r\n\r\nhi${close.join("")}`);
    expect(elapsed(() => parseStructure(raw))).toBeLessThan(BUDGET_MS);
    expect(elapsed(() => parseMessage(raw))).toBeLessThan(BUDGET_MS);
  });

  test("깊이 10,000짜리 message/rfc822 체인도 마찬가지", () => {
    let s = "Content-Type: text/plain\r\n\r\nhi\r\n";
    for (let i = 0; i < 10000; i++) s = `Content-Type: message/rfc822\r\n\r\n${s}`;
    const raw = bin(s);
    let p!: ReturnType<typeof parseStructure>;
    expect(elapsed(() => (p = parseStructure(raw)))).toBeLessThan(BUDGET_MS);
    // 깊이 상한에서 절단되므로 무한히 내려가지 않는다.
    let d = 0;
    for (let cur = p; cur.children[0] !== undefined; cur = cur.children[0]) d += 1;
    expect(d).toBeLessThanOrEqual(21);
  });
});

describe("헤더 폭탄", () => {
  test("헤더 20만 줄", () => {
    const raw = bin(`${Array.from({ length: 200000 }, (_, i) => `X-H${i}: v`).join("\r\n")}\r\n\r\nbody`);
    let m!: ReturnType<typeof parseMessage>;
    expect(elapsed(() => (m = parseMessage(raw)))).toBeLessThan(BUDGET_MS);
    expect(m.headers.size).toBe(200000);
  });

  test("Content-Type 파라미터 10만 개", () => {
    const params = Array.from({ length: 100000 }, (_, i) => `p${i}=v`).join("; ");
    const raw = bin(`Content-Type: text/plain; ${params}\r\n\r\nx`);
    expect(elapsed(() => parseStructure(raw))).toBeLessThan(BUDGET_MS);
  });
});

describe("파서 2차식(ReDoS 계열) 회귀", () => {
  test("stripHtml — 닫히지 않은 `<`가 20만 개", () => {
    // `<[^>]*>`의 백트래킹. 고치기 전 64KB에 1.9초.
    const s = "<".repeat(200000);
    expect(elapsed(() => stripHtml(s))).toBeLessThan(BUDGET_MS);
  });

  test("stripHtml — 닫히지 않은 `<script>`가 10만 개", () => {
    // `<(script|style)[\s\S]*?</\1\s*>`의 lazy 반복. 고치기 전 512KB에 9.5초.
    const s = "<script>".repeat(100000);
    expect(elapsed(() => stripHtml(s))).toBeLessThan(BUDGET_MS);
  });

  test("stripHtml — 여는 태그 앞에 `<`가 있어도 스크립트 본문이 새지 않는다", () => {
    // 2차식을 고치면서 raw-text 제거와 일반 태그 제거를 **한 패스로 합쳤다가** 낸 회귀다.
    // `</scriptX<script>`가 일반 태그로 먼저 먹히면 여는 태그가 사라져 본문이 미리보기에 남는다.
    // 원래 정규식은 raw-text 블록을 문자열 전체에 대해 먼저 지웠으므로 그 순서를 지켜야 한다.
    expect(stripHtml("</scriptX<script>SECRET()</script>")).not.toContain("SECRET");
    expect(stripHtml("<<script>LEAK</script>")).not.toContain("LEAK");
    expect(stripHtml("<div>a</div><style>.x{color:red}</style>b")).toBe("a b");
  });

  test("computeSubjectBase — `Re:`가 20만 번 겹친 제목", () => {
    // 반복 `replace`가 매번 새 문자열을 만들어 O(길이²)였다. 고치기 전 192KB에 788ms.
    const s = "Re:".repeat(200000);
    expect(elapsed(() => computeSubjectBase(s))).toBeLessThan(BUDGET_MS);
    expect(computeSubjectBase(s)).toBe("");
  });
});

describe("정상 MIME은 그대로 파싱된다", () => {
  const NORMAL = bin(
    [
      // 비ASCII는 여기서 쓰지 않는다 — `bin`은 1문자=1바이트라 UTF-8 인코딩을 하지 않는다.
      // charset 처리는 parse.test.ts의 몫이고, 여기서 볼 것은 접두사 제거뿐이다.
      "Subject: Re: Re: normal mail",
      'Content-Type: multipart/mixed; boundary="OUT"',
      "",
      "--OUT",
      'Content-Type: multipart/alternative; boundary="IN"',
      "",
      "--IN",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "hello plain",
      "--IN",
      "Content-Type: text/html; charset=utf-8",
      "",
      "<p>hello <b>html</b></p>",
      "--IN--",
      "--OUT",
      "Content-Type: application/pdf; name=doc.pdf",
      "Content-Transfer-Encoding: base64",
      "Content-Disposition: attachment; filename=doc.pdf",
      "",
      "QUJD",
      "--OUT--",
      "",
    ].join("\r\n"),
  );

  test("중첩 multipart + 첨부의 트리·본문·첨부 판정", () => {
    const p = parseStructure(NORMAL);
    expect(p.subtype).toBe("mixed");
    expect(p.children.map((c) => `${c.type}/${c.subtype}`)).toEqual(["multipart/alternative", "application/pdf"]);
    expect(p.children[0]!.children.map((c) => c.subtype)).toEqual(["plain", "html"]);
    expect(p.children[1]!.disposition).toEqual({ type: "attachment", params: { filename: "doc.pdf" } });

    const m = parseMessage(NORMAL);
    expect(m.textBody).toBe("hello plain");
    expect(m.hasAttachment).toBe(true);
    expect(m.subject).toBe("Re: Re: normal mail");
    expect(m.subjectBase).toBe("normal mail");

    const jb = extractJmapBody(NORMAL, 1024);
    expect(jb.textBody).toHaveLength(1);
    expect(jb.htmlBody).toHaveLength(1);
    expect(jb.attachments).toHaveLength(1);
    expect(jb.bodyValues[jb.textBody[0]!.partId!]!.value).toBe("hello plain");
  });

  test("text/plain이 없으면 html 폴백이 여전히 동작한다", () => {
    const raw = bin(
      ['Content-Type: text/html; charset=utf-8', "", "<div>a <script>bad()</script> <b>b</b> &amp; c</div>"].join("\r\n"),
    );
    // script는 내용까지 사라지고, 태그는 공백이 되며, 엔티티는 디코드된다.
    expect(parseMessage(raw).textBody).toBe("a b & c");
  });

  test("base64/quoted-printable 본문 디코딩", () => {
    const b64 = bin(["Content-Type: text/plain", "Content-Transfer-Encoding: base64", "", "aGVsbG8gd29ybGQ="].join("\r\n"));
    expect(parseMessage(b64).textBody).toBe("hello world");
    const qp = bin(["Content-Type: text/plain", "Content-Transfer-Encoding: quoted-printable", "", "a=3Db=\r\nc"].join("\r\n"));
    expect(parseMessage(qp).textBody).toBe("a=bc");
  });
});
