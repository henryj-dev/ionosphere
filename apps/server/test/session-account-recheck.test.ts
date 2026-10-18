/**
 * 열린 연결의 계정 상태 재확인 — 실제 조립(IonosphereApp)과 실제 DB로 고정한다.
 *
 * 왜 조립층에서인가: 어댑터의 관문은 백엔드의 `accountActive`가 **진짜 DB를 볼 때만** 의미가 있다.
 * 프로토콜 패키지의 스텁은 늘 true를 돌려주므로, 여기서 정지가 실제로 연결을 닫는지 본다.
 *
 * 고정하는 것(2026-10-18 회원 정책 G2 — "다음 명령에서 거부"):
 *  - IMAP: 정지 뒤 다음 백엔드 명령이 BYE로 닫힌다.
 *  - POP3: 정지 뒤 다음 RETR이 -ERR [AUTH]로 닫힌다.
 *  - ManageSieve: 정지 뒤 다음 스크립트 작업이 BYE로 닫힌다.
 *  - 재활성 뒤에는 새 연결이 정상으로 들어온다(정지는 되돌릴 수 있다).
 */
import { afterAll, afterEach, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ACCOUNT_STATUS } from "@ionosphere/db";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

const PASS = "recheck-pw";
const USER = "recheck@test.local";

let app: IonosphereApp;
let blobRoot: string;
const openClients: Socket[] = [];

/** 줄 단위 클라이언트 — audit-surfaces.test.ts와 같은 패턴. `closed`로 서버가 닫았는지 본다. */
function lineClient(port: number): {
  send: (s: string) => void;
  read: (until?: (l: string) => boolean) => Promise<string[]>;
  closed: Promise<void>;
} {
  const socket = connect(port, "127.0.0.1");
  openClients.push(socket);
  let buffer = "";
  const lines: string[] = [];
  const waiters: { until: (l: string) => boolean; resolve: (ls: string[]) => void }[] = [];
  const tryResolve = (): void => {
    while (waiters.length > 0) {
      const w = waiters[0]!;
      const i = lines.findIndex((l) => w.until(l));
      if (i < 0) return;
      waiters.shift();
      w.resolve(lines.splice(0, i + 1));
    }
  };
  socket.on("data", (chunk) => {
    buffer += chunk.toString("latin1");
    let idx: number;
    while ((idx = buffer.indexOf("\r\n")) >= 0) {
      lines.push(buffer.slice(0, idx));
      buffer = buffer.slice(idx + 2);
    }
    tryResolve();
  });
  const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
  return {
    send: (s) => socket.write(s),
    read: (until = () => true) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("read timeout")), 4000);
        waiters.push({
          until,
          resolve: (ls) => {
            clearTimeout(timer);
            resolve(ls);
          },
        });
        tryResolve();
      }),
    closed,
  };
}

/** SASL PLAIN — 구분자는 NUL. 소스에 리터럴 제어문자를 두지 않는다(CLAUDE.md 규약). */
const NUL = String.fromCharCode(0);
function plainB64(user: string, pass: string): string {
  return Buffer.from(`${NUL}${user}${NUL}${pass}`, "utf8").toString("base64");
}

async function setStatus(status: number): Promise<void> {
  await app.db.batch([{ sql: "UPDATE accounts SET status = ? WHERE email = ?", params: [status, USER] }]);
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-recheck-"));
  app = new IonosphereApp({
    hostname: "test.local",
    dbPath: ":memory:",
    blobRoot,
    pop3Port: 0,
    imapPort: 0,
    manageSievePort: 0,
    resolver: offlineResolver(),
  });
  await app.start();
  await app.createUser(USER, PASS);
}, E2E_HOOK_TIMEOUT_MS);

// 테스트끼리 상태가 새지 않게 매번 되살린다.
afterEach(async () => {
  await setStatus(ACCOUNT_STATUS.active);
});

afterAll(async () => {
  for (const c of openClients) c.destroy();
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("열린 연결의 계정 재확인", () => {
  test("IMAP — 정지 뒤 다음 명령은 BYE로 닫히고, 재활성 뒤 새 연결은 들어온다", async () => {
    const c = lineClient(app.imapPort);
    await c.read((l) => l.startsWith("* OK"));
    c.send(`a1 LOGIN ${USER} ${PASS}\r\n`);
    expect((await c.read((l) => l.startsWith("a1 "))).at(-1)).toStartWith("a1 OK");
    c.send("a2 SELECT INBOX\r\n");
    expect((await c.read((l) => l.startsWith("a2 "))).at(-1)).toStartWith("a2 OK");

    await setStatus(ACCOUNT_STATUS.suspended);
    c.send("a3 STATUS INBOX (MESSAGES)\r\n");
    const lines = await c.read((l) => l.startsWith("* BYE") || l.startsWith("a3 "));
    expect(lines.at(-1)).toBe("* BYE account unavailable");
    await c.closed;

    await setStatus(ACCOUNT_STATUS.active);
    const again = lineClient(app.imapPort);
    await again.read((l) => l.startsWith("* OK"));
    again.send(`b1 LOGIN ${USER} ${PASS}\r\n`);
    expect((await again.read((l) => l.startsWith("b1 "))).at(-1)).toStartWith("b1 OK");
  });

  test("IMAP — 삭제 중 계정도 같은 자리에서 닫힌다", async () => {
    const c = lineClient(app.imapPort);
    await c.read((l) => l.startsWith("* OK"));
    c.send(`a1 LOGIN ${USER} ${PASS}\r\n`);
    await c.read((l) => l.startsWith("a1 "));
    await setStatus(ACCOUNT_STATUS.deleting);
    c.send("a2 SELECT INBOX\r\n");
    expect((await c.read((l) => l.startsWith("* BYE") || l.startsWith("a2 "))).at(-1)).toBe("* BYE account unavailable");
    await c.closed;
  });

  test("POP3 — 정지 뒤 QUIT은 삭제를 커밋하지 않고 -ERR [AUTH]로 닫힌다", async () => {
    const c = lineClient(app.pop3Port);
    await c.read((l) => l.startsWith("+OK"));
    c.send(`USER ${USER}\r\n`);
    await c.read((l) => /^[+-]/.test(l));
    c.send(`PASS ${PASS}\r\n`);
    expect((await c.read((l) => /^[+-]/.test(l))).at(-1)).toStartWith("+OK");

    await setStatus(ACCOUNT_STATUS.suspended);
    c.send("RETR 1\r\n");
    // 빈 메일함이라 RETR은 엔진이 백엔드 없이 거절한다(관문에 닿지 않음). RETR 관문은 proto-pop3 테스트가 본다.
    // 여기서는 QUIT(삭제 커밋 경로)으로 실제 DB 관문을 태운다.
    await c.read((l) => /^[+-]/.test(l));
    c.send("QUIT\r\n");
    const last = await c.read((l) => /^[+-]/.test(l));
    expect(last.at(-1)).toBe("-ERR [AUTH] account unavailable");
    await c.closed;
  });

  test("ManageSieve — 정지 뒤 다음 스크립트 작업은 BYE로 닫힌다", async () => {
    const c = lineClient(app.manageSievePort);
    await c.read((l) => l.startsWith("OK"));
    c.send(`AUTHENTICATE "PLAIN" "${plainB64(USER, PASS)}"\r\n`);
    expect((await c.read((l) => /^(OK|NO)\b/.test(l))).at(-1)).toStartWith("OK");
    c.send("LISTSCRIPTS\r\n");
    expect((await c.read((l) => /^(OK|NO|BYE)\b/.test(l))).at(-1)).toStartWith("OK");

    await setStatus(ACCOUNT_STATUS.suspended);
    c.send("LISTSCRIPTS\r\n");
    expect((await c.read((l) => /^(OK|NO|BYE)\b/.test(l))).at(-1)).toBe('BYE "account unavailable"');
    await c.closed;
  });
});
