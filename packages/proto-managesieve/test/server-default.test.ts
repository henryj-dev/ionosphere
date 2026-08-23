/**
 * 어댑터 기본값이 **막는 쪽**인지 — `allowInsecureAuth`를 안 주면 평문 AUTH는 닫혀야 한다.
 *
 * 과거 결함: 5개 프로토콜 어댑터 중 여기만 `?? true`였다. 라이브는 app.ts가 항상 명시 전달해서
 * 영향이 없었지만, 기본값이 여는 쪽이면 **옵션을 빠뜨린 새 호출부 하나**로 4190이 평문
 * AUTHENTICATE PLAIN을 받게 된다. ManageSieve는 TLS 리스너도 STARTTLS도 없어 비밀번호가
 * 그대로 회선에 흐른다("보안은 fail closed" — CLAUDE.md).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { connect } from "node:net";
import { ManageSieveServer, type ManageSieveBackend } from "../src/server.ts";

/** 어떤 호출이 와도 실패로 답하는 백엔드 — 이 테스트는 인증 도달 여부만 본다. */
const denyBackend: ManageSieveBackend = {
  authenticate: () => Promise.resolve(null),
  putScript: () => Promise.resolve({ ok: false, message: "no" }),
  checkScript: () => ({ ok: false, message: "no" }),
  listScripts: () => Promise.resolve([]),
  getScript: () => Promise.resolve(null),
  deleteScript: () => Promise.resolve({ ok: false, message: "no" }),
  setActive: () => Promise.resolve({ ok: false, message: "no" }),
  renameScript: () => Promise.resolve({ ok: false, message: "no" }),
};

/** SASL PLAIN = authzid NUL authcid NUL passwd. 소스에 리터럴 NUL을 두지 않는다(CLAUDE.md). */
const NUL = String.fromCharCode(0);
const PLAIN_B64 = Buffer.from(`${NUL}u@sieve.test${NUL}pw`, "utf8").toString("base64");

let server: ManageSieveServer | null = null;

afterEach(async () => {
  await server?.close();
  server = null;
});

/** 그리팅(완결 라인까지)을 읽고 명령 하나를 보내 응답 완결 라인까지 수집. */
async function exchange(port: number, command: string): Promise<{ greeting: string[]; response: string }> {
  const sock = connect(port, "127.0.0.1");
  const lines: string[] = [];
  let buf = "";
  const waiters: ((l: string) => void)[] = [];
  sock.on("data", (c: Buffer) => {
    buf += c.toString("latin1");
    let i: number;
    while ((i = buf.indexOf("\r\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 2);
      lines.push(line);
      waiters.shift()?.(line);
    }
  });
  const readUntil = (pred: (l: string) => boolean): Promise<string> =>
    new Promise<string>((resolve) => {
      const check = (l: string): void => {
        if (pred(l)) resolve(l);
        else waiters.push(check);
      };
      waiters.push(check);
    });

  await readUntil((l) => /^(OK|NO|BYE)\b/.test(l));
  const greeting = [...lines];
  sock.write(command + "\r\n");
  const response = await readUntil((l) => /^(OK|NO|BYE)\b/.test(l));
  sock.end();
  await new Promise<void>((r) => sock.on("close", () => r()));
  return { greeting, response };
}

describe("ManageSieveServer 기본값", () => {
  test("allowInsecureAuth 미지정 → 평문 AUTH 차단 + SASL 미광고", async () => {
    server = new ManageSieveServer({ hostname: "sieve.test", backend: denyBackend });
    const port = await server.listen(0, "127.0.0.1");

    const { greeting, response } = await exchange(port, `AUTHENTICATE "PLAIN" "${PLAIN_B64}"`);
    expect(greeting).toContain('"SASL" ""');
    expect(greeting.some((l) => l.includes("STARTTLS"))).toBe(false);
    expect(response).toStartWith("NO");
    expect(response).toContain("TLS required");
  });

  test("명시적으로 열면 종전대로 광고·수용한다(백엔드 판정까지 도달)", async () => {
    server = new ManageSieveServer({ hostname: "sieve.test", backend: denyBackend, allowInsecureAuth: true });
    const port = await server.listen(0, "127.0.0.1");

    const { greeting, response } = await exchange(port, `AUTHENTICATE "PLAIN" "${PLAIN_B64}"`);
    expect(greeting).toContain('"SASL" "PLAIN"');
    // 백엔드가 거절했다는 뜻 — TLS 게이트가 아니라 자격증명 판정까지 갔다.
    expect(response).toContain("authentication failed");
  });
});
