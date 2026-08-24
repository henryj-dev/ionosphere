/**
 * DKIM `l=`(본문 길이 제한)과 `i=`(AUID) 검증 회귀.
 *
 * ★`l=`을 읽지 않고 본문 전체를 해싱하던 시절, `l=`을 붙인 정상 발신자의 서명이 **전부
 * `fail`** 이었다. DKIM fail은 DMARC를 fail로 밀기 때문에 정상 메일이 거절될 수 있다 —
 * verify.ts 머리가 기록한 Ed25519 사고(규격을 지키는 발신자를 우리가 전부 fail로 판정했다)와
 * 같은 계열이다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { dkimVerify } from "@ionosphere/mail-auth";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const P = publicKey.export({ format: "der", type: "spki" }).toString("base64");
const resolveTxt = async (): Promise<string[]> => [`v=DKIM1; k=rsa; p=${P}`];

const HEADERS = "From: a@x.test\r\nSubject: hi\r\n";
const BODY = "signed part\r\n";

/**
 * `l=`을 실은 서명을 손으로 만든다 — relaxed/relaxed, h=from:subject.
 * `extraBody`는 서명 **밖**의 꼬리다(l= 뒤에 붙는 부분).
 */
function sign(opts: { l?: number; i?: string; extraBody?: string }): Uint8Array {
  const canonBody = BODY; // relaxed 정규화 결과가 원문과 같도록 단순한 본문을 쓴다
  const covered = opts.l === undefined ? canonBody : canonBody.slice(0, opts.l);
  const bh = createHash("sha256").update(Buffer.from(covered, "latin1")).digest("base64");

  const tags =
    `v=1; a=rsa-sha256; c=relaxed/relaxed; d=x.test; s=s1; h=from:subject; bh=${bh};` +
    `${opts.l !== undefined ? ` l=${opts.l};` : ""}${opts.i !== undefined ? ` i=${opts.i};` : ""} b=`;

  // AuthMessage: 정규화된 h= 헤더들 + b= 값을 비운 DKIM-Signature(트레일링 CRLF 없음)
  const canonHeaders = "from:a@x.test\r\nsubject:hi\r\n";
  const sigCanon = `dkim-signature:${tags}`;
  const signer = createSign("sha256");
  signer.update(Buffer.from(canonHeaders + sigCanon, "latin1"));
  const b = signer.sign(privateKey).toString("base64");

  const raw = `DKIM-Signature: ${tags}${b}\r\n${HEADERS}\r\n${canonBody}${opts.extraBody ?? ""}`;
  return new Uint8Array(Buffer.from(raw, "latin1"));
}

describe("DKIM l= (본문 길이 제한)", () => {
  test("l= 없는 정상 서명은 통과한다(기준선)", async () => {
    const [r] = await dkimVerify(sign({}), resolveTxt);
    expect(r!.result).toBe("pass");
  });

  /** ★수정 전에는 이것이 `fail`이었다 — 정상 발신자의 서명을 우리가 거절했다. */
  test("l=이 본문 전체를 덮으면 통과한다", async () => {
    const [r] = await dkimVerify(sign({ l: BODY.length }), resolveTxt);
    expect(r!.result).toBe("pass");
  });

  test("l= 뒤에 붙은 꼬리가 있어도 앞부분 서명은 통과한다", async () => {
    const [r] = await dkimVerify(sign({ l: BODY.length, extraBody: "appended by a list\r\n" }), resolveTxt);
    expect(r!.result).toBe("pass");
  });

  /** 선언한 길이가 실제보다 길면 본문이 잘려 나간 것이다 — 통과시키면 안 된다(§3.5). */
  test("l=이 본문보다 길면 fail", async () => {
    const [r] = await dkimVerify(sign({ l: BODY.length + 500 }), resolveTxt);
    expect(r!.result).toBe("fail");
    expect(r!.error).toContain("본문 절단");
  });

  test("l=이 음수/비정수면 permerror", async () => {
    const raw = Buffer.from(sign({ l: 5 })).toString("latin1").replace("l=5;", "l=-1;");
    const [r] = await dkimVerify(new Uint8Array(Buffer.from(raw, "latin1")), resolveTxt);
    expect(r!.result).toBe("permerror");
  });
});

describe("DKIM i= (AUID)", () => {
  test("d=와 같은 도메인이면 통과", async () => {
    const [r] = await dkimVerify(sign({ i: "user@x.test" }), resolveTxt);
    expect(r!.result).toBe("pass");
  });

  test("d=의 하위 도메인이면 통과", async () => {
    const [r] = await dkimVerify(sign({ i: "user@mail.x.test" }), resolveTxt);
    expect(r!.result).toBe("pass");
  });

  /** RFC 6376 §6.1.1 — 하위 도메인이 아니면 서명을 무시해야 한다(MUST). */
  test("d=와 무관한 도메인이면 permerror", async () => {
    const [r] = await dkimVerify(sign({ i: "user@evil.test" }), resolveTxt);
    expect(r!.result).toBe("permerror");
    expect(r!.error).toContain("i=");
  });

  test("`x.test`를 접미사로만 갖는 도메인은 하위 도메인이 아니다", async () => {
    const [r] = await dkimVerify(sign({ i: "user@notx.test" }), resolveTxt);
    expect(r!.result).toBe("permerror");
  });
});
