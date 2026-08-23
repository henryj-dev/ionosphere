/**
 * POP3 AUTH SCRAM-SHA-256 — 엔진 배선 검증.
 *
 * SMTP·IMAP과 **같은 계약**을 POP3 문법으로. 교환 규칙은 `core/scram-session.ts` 한 곳에 있다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { deriveScramKeys, type ScramStoredKeys } from "@ionosphere/core";
import { Pop3Engine, type Pop3Action } from "../src/engine.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const b64 = (s: string): string => Buffer.from(s).toString("base64");
const texts = (a: Pop3Action[]): string =>
  a.filter((x) => x.kind === "reply").map((x) => (x as { text: string }).text).join("\n");
const kinds = (a: Pop3Action[]): string[] => a.map((x) => x.kind);

function newEngine(scramOffered: boolean): Pop3Engine {
  return new Pop3Engine({ hostname: "pop.test", secure: true, scramOffered, scramDecoySecret: randomBytes(32) });
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

/** `+ <b64>` 응답에서 디코딩된 SASL 메시지. */
function saslPayload(t: string): string {
  const line = t.split("\n").find((l) => l.startsWith("+ ")) ?? "";
  return Buffer.from(line.slice(2).trim(), "base64").toString();
}

describe("POP3 AUTH SCRAM-SHA-256", () => {
  test("★백엔드가 못 하면 CAPA·AUTH 목록에 광고하지 않는다", () => {
    const e = newEngine(false);
    e.greeting();
    expect(texts(e.feed(enc("CAPA\r\n")))).not.toContain("SCRAM-SHA-256");
    expect(texts(e.feed(enc("AUTH\r\n")))).not.toContain("SCRAM-SHA-256");
  });

  test("광고할 때는 PLAIN보다 앞에 온다", () => {
    const e = newEngine(true);
    e.greeting();
    const capa = texts(e.feed(enc("CAPA\r\n")));
    expect(capa).toContain("SCRAM-SHA-256");
    expect(capa.indexOf("SCRAM-SHA-256")).toBeLessThan(capa.indexOf("PLAIN"));
  });

  test("광고하지 않으면 시도해도 거절한다", () => {
    const e = newEngine(false);
    e.greeting();
    expect(texts(e.feed(enc("AUTH SCRAM-SHA-256\r\n")))).toContain("-ERR");
  });

  test("★전체 교환: SASL-IR → +server-first → client-final → +server-final → 빈 응답", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    e.greeting();

    const cn = "popnonce123";
    const a1 = e.feed(enc(`AUTH SCRAM-SHA-256 ${b64(`n,,n=user,r=${cn}`)}\r\n`));
    expect(kinds(a1)).toContain("scramKeys");

    const serverFirst = saslPayload(texts(e.scramKeysResult(keys as ScramStoredKeys)));
    expect(serverFirst).toMatch(/^r=.+,s=.+,i=4096$/);

    const full = /r=([^,]+)/.exec(serverFirst)![1]!;
    const salt = Buffer.from(/s=([^,]+)/.exec(serverFirst)![1]!, "base64");
    const wp = `c=biws,r=${full}`;
    const am = `n=user,r=${cn},${serverFirst},${wp}`;
    const p = proofFor("pencil", salt, 4096, am);

    const t3 = texts(e.feed(enc(`${b64(`${wp},p=${p}`)}\r\n`)));
    // ★+OK가 아니라 `+ server-final`이 와야 한다 — 클라이언트가 서버를 검증한다.
    expect(t3.startsWith("+ ")).toBe(true);
    expect(saslPayload(t3).startsWith("v=")).toBe(true);
    expect(t3).not.toContain("+OK");

    expect(kinds(e.feed(enc("\r\n")))).toContain("authVerified");
  });

  test("★증명이 틀리면 실패하고 server-final을 주지 않는다", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    e.greeting();
    e.feed(enc(`AUTH SCRAM-SHA-256 ${b64("n,,n=user,r=nonce12345")}\r\n`));
    const serverFirst = saslPayload(texts(e.scramKeysResult(keys as ScramStoredKeys)));
    const full = /r=([^,]+)/.exec(serverFirst)![1]!;
    const bogus = Buffer.alloc(32, 5).toString("base64");
    const a = e.feed(enc(`${b64(`c=biws,r=${full},p=${bogus}`)}\r\n`));
    const t = texts(a);
    expect(t).toContain("-ERR");
    expect(t).not.toContain("+ ");
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
    e.feed(enc(`AUTH SCRAM-SHA-256 ${b64("n,,n=ghost@x.test,r=nonce12345")}\r\n`));
    expect(saslPayload(texts(e.scramKeysResult(null)))).toMatch(/^r=.+,s=.+,i=\d+$/);
  });

  test("초기 응답 없이 시작하면 `+ `로 client-first를 기다린다", () => {
    const e = newEngine(true);
    e.greeting();
    expect(texts(e.feed(enc("AUTH SCRAM-SHA-256\r\n")))).toContain("+ ");
    expect(kinds(e.feed(enc(`${b64("n,,n=user,r=nonce12345")}\r\n`)))).toContain("scramKeys");
  });

  test("취소(*)는 교환을 끝낸다", () => {
    const e = newEngine(true);
    e.greeting();
    e.feed(enc("AUTH SCRAM-SHA-256\r\n"));
    expect(texts(e.feed(enc("*\r\n")))).toContain("cancelled");
  });
});
