/**
 * IMAP AUTHENTICATE SCRAM-SHA-256 — 엔진 배선 검증.
 *
 * SMTP와 **같은 계약**을 IMAP 문법으로 확인한다(규칙은 `core/scram-session.ts` 한 곳에 있다):
 *  ① 백엔드가 못 하면 CAPABILITY에 광고하지 않는다
 *  ② server-final은 `+ <b64>`로 따로 보내고, 클라이언트 빈 응답 뒤에 태그 OK
 *  ③ 없는 계정도 server-first를 받는다(열거 방어)
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { deriveScramKeys, type ScramStoredKeys } from "@ionosphere/core";
import { ImapEngine, type ImapAction } from "../src/engine.ts";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const b64 = (s: string): string => Buffer.from(s).toString("base64");

function texts(actions: ImapAction[]): string {
  return actions.filter((a) => a.kind === "reply").map((a) => (a as { text: string }).text).join("\n");
}
const kinds = (actions: ImapAction[]): string[] => actions.map((a) => a.kind);

function newEngine(scramOffered: boolean): ImapEngine {
  return new ImapEngine({
    hostname: "imap.test",
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

/** `+ <b64>` 응답에서 디코딩된 SASL 메시지. */
function saslPayload(t: string): string {
  const line = t.split("\n").find((l) => l.startsWith("+ ")) ?? "";
  return Buffer.from(line.slice(2).trim(), "base64").toString();
}

describe("IMAP AUTHENTICATE SCRAM-SHA-256", () => {
  test("★백엔드가 못 하면 CAPABILITY에 광고하지 않는다", () => {
    expect(texts(newEngine(false).greeting())).not.toContain("AUTH=SCRAM-SHA-256");
  });

  test("광고할 때는 PLAIN보다 앞에 온다", () => {
    const cap = texts(newEngine(true).greeting());
    expect(cap).toContain("AUTH=SCRAM-SHA-256");
    expect(cap.indexOf("AUTH=SCRAM-SHA-256")).toBeLessThan(cap.indexOf("AUTH=PLAIN"));
  });

  test("광고하지 않으면 시도해도 거절한다", () => {
    const e = newEngine(false);
    e.greeting();
    expect(texts(e.feed(enc("a1 AUTHENTICATE SCRAM-SHA-256\r\n")))).toContain("NO");
  });

  test("★전체 교환: SASL-IR → +server-first → client-final → +server-final → 빈 응답 → OK", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    e.greeting();

    const clientNonce = "imapnonce123";
    const a1 = e.feed(enc(`a1 AUTHENTICATE SCRAM-SHA-256 ${b64(`n,,n=user,r=${clientNonce}`)}\r\n`));
    expect(kinds(a1)).toContain("scramKeys");

    const serverFirst = saslPayload(texts(e.scramKeysResult(keys as ScramStoredKeys)));
    expect(serverFirst).toMatch(/^r=.+,s=.+,i=4096$/);

    const fullNonce = /r=([^,]+)/.exec(serverFirst)![1]!;
    const salt = Buffer.from(/s=([^,]+)/.exec(serverFirst)![1]!, "base64");
    const withoutProof = `c=biws,r=${fullNonce}`;
    const authMessage = `n=user,r=${clientNonce},${serverFirst},${withoutProof}`;
    const p = proofFor("pencil", salt, 4096, authMessage);

    const t3 = texts(e.feed(enc(`${b64(`${withoutProof},p=${p}`)}\r\n`)));
    // ★태그 OK가 아니라 `+ server-final`이 와야 한다 — 클라이언트가 서버를 검증한다.
    expect(t3.startsWith("+ ")).toBe(true);
    expect(saslPayload(t3).startsWith("v=")).toBe(true);
    expect(t3).not.toContain("a1 OK");

    const a4 = e.feed(enc("\r\n"));
    expect(kinds(a4)).toContain("authVerified");
  });

  test("★증명이 틀리면 실패하고 server-final을 주지 않는다", async () => {
    const keys = await deriveScramKeys("pencil", { iterations: 4096 });
    const e = newEngine(true);
    e.greeting();
    e.feed(enc(`a1 AUTHENTICATE SCRAM-SHA-256 ${b64("n,,n=user,r=nonce12345")}\r\n`));
    const serverFirst = saslPayload(texts(e.scramKeysResult(keys as ScramStoredKeys)));
    const fullNonce = /r=([^,]+)/.exec(serverFirst)![1]!;
    const bogus = Buffer.alloc(32, 3).toString("base64");
    const a = e.feed(enc(`${b64(`c=biws,r=${fullNonce},p=${bogus}`)}\r\n`));
    const t = texts(a);
    expect(t).toContain("AUTHENTICATIONFAILED");
    expect(t).not.toContain("+ ");
    /**
     * ★거절 응답만으로는 부족하다 — **어댑터가 볼 액션**이 나와야 한다.
     * 예전엔 여기서 reply만 나왔고, 어댑터의 스로틀·감사는 `authVerified` 케이스 안에 있어서
     * 실행되지 않았다. 결과는 SCRAM으로 무제한 대입이 **무기록**으로 가능한 상태였다.
     * 이 테스트가 없으면 그 상태가 "응답이 맞으니 통과"로 다시 돌아간다.
     */
    expect(kinds(a)).toContain("authFailed");
    const failed = a.find((x) => x.kind === "authFailed") as { user?: string; mechanism: string };
    // 사용자명이 실려야 한다 — 없으면 감사 로그가 "누가 시도했는지"를 모른다.
    expect(failed.user).toBe("user");
    expect(failed.mechanism).toBe("SCRAM-SHA-256");
  });

  test("★없는 계정에 대한 증명 실패도 기록된다 — 존재하지 않는 계정으로 대입해도 남아야 한다", () => {
    // 열거 방어로 교환이 끝까지 가는 갈래다. 그 대가로 기록이 빠지면 방어가 사각지대를 만든다.
    const e = newEngine(true);
    e.greeting();
    e.feed(enc(`a1 AUTHENTICATE SCRAM-SHA-256 ${b64("n,,n=ghost@x.test,r=nonce12345")}\r\n`));
    const serverFirst = saslPayload(texts(e.scramKeysResult(null)));
    const fullNonce = /r=([^,]+)/.exec(serverFirst)![1]!;
    const bogus = Buffer.alloc(32, 7).toString("base64");
    const a = e.feed(enc(`${b64(`c=biws,r=${fullNonce},p=${bogus}`)}\r\n`));

    expect(kinds(a)).toContain("authFailed");
    expect((a.find((x) => x.kind === "authFailed") as { user?: string }).user).toBe("ghost@x.test");
  });

  test("client-first가 깨졌으면 사용자명 없이 기록한다 — 모르는 것과 빈 값은 다르다", () => {
    const e = newEngine(true);
    e.greeting();
    const a = e.feed(enc(`a1 AUTHENTICATE SCRAM-SHA-256 ${b64("쓰레기")}\r\n`));

    expect(kinds(a)).toContain("authFailed");
    // `user: ""`가 찍히면 감사 로그에서 "빈 사용자명으로 시도"로 잘못 읽힌다.
    expect((a.find((x) => x.kind === "authFailed") as { user?: string }).user).toBeUndefined();
  });

  test("★없는 계정도 server-first를 받는다 — 열거 방어", () => {
    const e = newEngine(true);
    e.greeting();
    e.feed(enc(`a1 AUTHENTICATE SCRAM-SHA-256 ${b64("n,,n=ghost@x.test,r=nonce12345")}\r\n`));
    const serverFirst = saslPayload(texts(e.scramKeysResult(null)));
    expect(serverFirst).toMatch(/^r=.+,s=.+,i=\d+$/);
  });

  test("초기 응답 없이 시작하면 `+ `로 client-first를 기다린다", () => {
    const e = newEngine(true);
    e.greeting();
    expect(texts(e.feed(enc("a1 AUTHENTICATE SCRAM-SHA-256\r\n")))).toContain("+ ");
    expect(kinds(e.feed(enc(`${b64("n,,n=user,r=nonce12345")}\r\n`)))).toContain("scramKeys");
  });
});
