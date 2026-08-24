/**
 * ManageSieve AUTHENTICATE SCRAM-SHA-256 — 엔진 배선 검증.
 *
 * 네 번째이자 마지막 프로토콜. 교환 규칙은 `core/scram-session.ts` 한 곳에 있고,
 * 여기서는 **ManageSieve 문법으로도 같은 계약이 성립하는지**만 본다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { deriveScramKeys, type ScramStoredKeys } from "@ionosphere/core";
import { ManageSieveEngine, type ManageSieveAction } from "../src/engine.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const b64 = (s: string): string => Buffer.from(s).toString("base64");
const texts = (a: ManageSieveAction[]): string =>
  a.filter((x) => x.kind === "reply").map((x) => (x as { text: string }).text).join("\n");
const kinds = (a: ManageSieveAction[]): string[] => a.map((x) => x.kind);

function newEngine(scramOffered: boolean): ManageSieveEngine {
  return new ManageSieveEngine({
    hostname: "sieve.test",
    secure: true,
    scramOffered,
    scramDecoySecret: randomBytes(32),
  });
}

function proofFor(password: string, salt: Buffer, iterations: number, authMessage: string): string {
  const salted = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const sig = createHmac("sha256", storedKey).update(authMessage).digest();
  const p = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) p[i] = clientKey[i]! ^ sig[i]!;
  return p.toString("base64");
}

/** `{n+}\r\n<b64>` 리터럴 응답에서 디코딩된 SASL 메시지. */
function saslPayload(t: string): string {
  const m = /\{\d+\+\}\r\n(\S+)/.exec(t);
  return m ? Buffer.from(m[1]!, "base64").toString() : "";
}

describe("ManageSieve AUTHENTICATE SCRAM-SHA-256", () => {
  test("★백엔드가 못 하면 SASL 목록에 광고하지 않는다", () => {
    const t = texts(newEngine(false).greeting());
    expect(t).toContain('"SASL" "PLAIN"');
    expect(t).not.toContain("SCRAM-SHA-256");
  });

  test("광고할 때는 PLAIN보다 앞에 온다", () => {
    const t = texts(newEngine(true).greeting());
    expect(t).toContain('"SASL" "SCRAM-SHA-256 PLAIN"');
  });

  test("광고하지 않으면 시도해도 거절한다", () => {
    const e = newEngine(false);
    e.greeting();
    expect(texts(e.feed(enc('AUTHENTICATE "SCRAM-SHA-256"\r\n')))).toContain("unsupported SASL mechanism");
  });

  test("★전체 교환: 초기응답 → server-first → client-final → server-final → 빈 줄", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    e.greeting();

    const cn = "sievenonce12";
    const a1 = e.feed(enc(`AUTHENTICATE "SCRAM-SHA-256" "${b64(`n,,n=user,r=${cn}`)}"\r\n`));
    expect(kinds(a1)).toContain("scramKeys");

    const serverFirst = saslPayload(texts(e.scramKeysResult(keys as ScramStoredKeys)));
    expect(serverFirst).toMatch(/^r=.+,s=.+,i=4096$/);

    const full = /r=([^,]+)/.exec(serverFirst)![1]!;
    const salt = Buffer.from(/s=([^,]+)/.exec(serverFirst)![1]!, "base64");
    const wp = `c=biws,r=${full}`;
    const am = `n=user,r=${cn},${serverFirst},${wp}`;
    const p = proofFor("pencil", salt, 4096, am);

    const t3 = texts(e.feed(enc(`"${b64(`${wp},p=${p}`)}"\r\n`)));
    // ★OK가 아니라 server-final 리터럴이 와야 한다 — 클라이언트가 서버를 검증한다.
    expect(saslPayload(t3).startsWith("v=")).toBe(true);
    /**
     * ★"OK"가 **응답으로** 오면 안 된다는 뜻이지, 페이로드 어딘가에 그 두 글자가 없어야
     * 한다는 뜻이 아니다. 예전엔 `not.toContain("OK")`였는데, server-final은 난수 기반
     * base64라 우연히 `OK`를 품는 날이 있었다(2026-08-24 실측) — 시간이 아니라 **난수**로
     * 흔들리는 플레이크다. 상태 줄만 본다.
     */
    expect(t3.split("\n").some((line) => /^OK\b/.test(line.trim()))).toBe(false);

    expect(kinds(e.feed(enc('""\r\n')))).toContain("authVerified");
  });

  test("★증명이 틀리면 실패하고 server-final을 주지 않는다", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    e.greeting();
    e.feed(enc(`AUTHENTICATE "SCRAM-SHA-256" "${b64("n,,n=user,r=nonce12345")}"\r\n`));
    const serverFirst = saslPayload(texts(e.scramKeysResult(keys as ScramStoredKeys)));
    const full = /r=([^,]+)/.exec(serverFirst)![1]!;
    const bogus = Buffer.alloc(32, 7).toString("base64");
    const a = e.feed(enc(`"${b64(`c=biws,r=${full},p=${bogus}`)}"\r\n`));
    const t = texts(a);
    expect(t).toContain("authentication failed");
    expect(saslPayload(t)).toBe("");
    /**
     * ★거절 응답만으로는 부족하다 — **어댑터가 볼 액션**이 나와야 한다.
     * 예전엔 여기서 reply만 나왔고, 어댑터의 스로틀·감사는 `authVerified` 케이스 안에 있어서
     * 실행되지 않았다. 결과는 SCRAM으로 무제한 대입이 **무기록**으로 가능한 상태였다.
     */
    expect(kinds(a)).toContain("authFailed");
    const failed = a.find((x) => x.kind === "authFailed") as { user?: string; mechanism: string };
    expect(failed.user).toBe("user");
    expect(failed.mechanism).toBe("SCRAM-SHA-256");
  });

  test("★없는 계정도 server-first를 받는다 — 열거 방어", () => {
    const e = newEngine(true);
    e.greeting();
    e.feed(enc(`AUTHENTICATE "SCRAM-SHA-256" "${b64("n,,n=ghost@x.test,r=nonce12345")}"\r\n`));
    expect(saslPayload(texts(e.scramKeysResult(null)))).toMatch(/^r=.+,s=.+,i=\d+$/);
  });

  test("초기 응답 없이 시작하면 빈 챌린지로 client-first를 기다린다", () => {
    const e = newEngine(true);
    e.greeting();
    expect(texts(e.feed(enc('AUTHENTICATE "SCRAM-SHA-256"\r\n')))).toContain('""');
    expect(kinds(e.feed(enc(`"${b64("n,,n=user,r=nonce12345")}"\r\n`)))).toContain("scramKeys");
  });

  test("취소(*)는 교환을 끝낸다", () => {
    const e = newEngine(true);
    e.greeting();
    e.feed(enc('AUTHENTICATE "SCRAM-SHA-256"\r\n'));
    expect(texts(e.feed(enc('"*"\r\n')))).toContain("aborted");
  });
});
