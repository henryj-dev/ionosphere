/**
 * SCRAM end-to-end — **실제 앱**에서 켜지는지.
 *
 * 엔진·세션·저장 계층은 각 패키지 테스트가 덮는다. 여기서 보는 것은 그 셋이 **연결됐는지**다:
 * 백엔드가 `scramKeys`/`scramAuthorize`를 제공 → 어댑터가 광고 → 실제 계정으로 로그인 성공.
 *
 * ★이 파일이 있는 이유: 앞서 스팸 점수 엔진에서 **앱→백엔드 배선 하나를 빠뜨려 게이트가
 * 아예 안 도는데도 단위 테스트는 전부 통과**한 적이 있다. 조립은 조립으로만 확인된다.
 */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { createHash, createHmac, pbkdf2Sync } from "node:crypto";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

let app: IonosphereApp;
let blobRoot: string;
const USER = "scram@mx.test";
const PASS = "correct-horse-battery";

/** 한 줄씩 주고받는 최소 POP3 클라이언트. */
function talk(port: number, lines: string[]): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1");
    const out: string[] = [];
    let buf = "";
    let i = -1;
    const t = setTimeout(() => {
      s.destroy();
      reject(new Error(`timeout; got=${JSON.stringify(out)}`));
    }, 8000);
    s.on("data", (d) => {
      buf += d.toString("latin1");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        out.push(line);
        // 멀티라인(CAPA 등)은 "." 로 끝난다 — 그 전까지는 다음 명령을 보내지 않는다.
        if (line === "." || (!line.startsWith("+OK") && !line.startsWith("-ERR") && !line.startsWith("+ ")) === false) {
          if (out.length > 0 && (line === "." || line.startsWith("+OK") || line.startsWith("-ERR") || line.startsWith("+ "))) {
            i += 1;
            if (i >= lines.length) {
              clearTimeout(t);
              s.end();
              resolve(out);
              return;
            }
            s.write(`${lines[i]}\r\n`);
          }
        }
      }
    });
    s.on("error", reject);
  });
}

/** 클라이언트 쪽 SCRAM proof. */
function proofFor(password: string, salt: Buffer, iterations: number, authMessage: string): string {
  const salted = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const sig = createHmac("sha256", storedKey).update(authMessage).digest();
  const p = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) p[i] = clientKey[i]! ^ sig[i]!;
  return p.toString("base64");
}

beforeAll(async () => {
  blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-scram-e2e-"));
  app = new IonosphereApp({
    hostname: "mx.test",
    dbPath: ":memory:",
    blobRoot,
    smtpPort: 0,
    pop3Port: 0,
    // submission(587)도 띄운다 — 여기가 **라이브에서 SCRAM을 광고하지 않던 표면**이다.
    submissionPort: 0,
    // TLS 미구성이면 앱이 `allowInsecureAuth`를 스스로 켠다(app.ts `!tlsConfigured`) —
    // 평문 회선에서 교환을 볼 수 있는 이유가 그것이다. 별도 옵션이 필요 없다.
    runMtaWorker: false,
    resolver: offlineResolver(),
  });
  await app.start();
  await app.createUser(USER, PASS);
}, E2E_HOOK_TIMEOUT_MS);

afterAll(async () => {
  await app.stop();
  rmSync(blobRoot, { recursive: true, force: true });
}, E2E_HOOK_TIMEOUT_MS);

describe("SCRAM end-to-end (POP3)", () => {
  test("★백엔드가 붙어 있어 CAPA에 SCRAM이 광고된다", async () => {
    const out = (await talk(app.pop3Port, ["CAPA", "QUIT"])).join("\n");
    // 배선이 하나라도 빠지면 이 줄이 안 나온다 — 조립 실패가 여기서 드러난다.
    expect(out).toContain("SCRAM-SHA-256");
  });

  test("★실제 계정으로 SCRAM 로그인이 성공한다", async () => {
    const cn = "e2enonce123";
    const first = Buffer.from(`n,,n=${USER},r=${cn}`).toString("base64");

    // 1) AUTH + client-first → `+ <server-first>`
    const s = connect(app.pop3Port, "127.0.0.1");
    const readLine = (): Promise<string> =>
      new Promise((res, rej) => {
        const onData = (d: Buffer): void => {
          buf += d.toString("latin1");
          const nl = buf.indexOf("\r\n");
          if (nl >= 0) {
            const line = buf.slice(0, nl);
            buf = buf.slice(nl + 2);
            s.off("data", onData);
            res(line);
          }
        };
        let _ = 0;
        void _;
        s.on("data", onData);
        s.once("error", rej);
      });
    let buf = "";
    try {
      await readLine(); // 배너
      s.write(`AUTH SCRAM-SHA-256 ${first}\r\n`);
      const serverFirstLine = await readLine();
      expect(serverFirstLine.startsWith("+ ")).toBe(true);
      const serverFirst = Buffer.from(serverFirstLine.slice(2), "base64").toString();

      const full = /r=([^,]+)/.exec(serverFirst)![1]!;
      const salt = Buffer.from(/s=([^,]+)/.exec(serverFirst)![1]!, "base64");
      const iters = Number(/i=(\d+)/.exec(serverFirst)![1]!);
      const wp = `c=biws,r=${full}`;
      const am = `n=${USER},r=${cn},${serverFirst},${wp}`;
      const p = proofFor(PASS, salt, iters, am);

      // 2) client-final → `+ <server-final>`
      s.write(`${Buffer.from(`${wp},p=${p}`).toString("base64")}\r\n`);
      const serverFinalLine = await readLine();
      expect(serverFinalLine.startsWith("+ ")).toBe(true);
      expect(Buffer.from(serverFinalLine.slice(2), "base64").toString().startsWith("v=")).toBe(true);

      // 3) 빈 응답 → +OK (로그인 완료)
      s.write("\r\n");
      expect(await readLine()).toStartWith("+OK");

      // 4) 인증된 세션에서 실제 명령이 동작한다 — 세션이 계정에 묶였다는 증거.
      s.write("STAT\r\n");
      expect(await readLine()).toStartWith("+OK");
    } finally {
      s.destroy();
    }
  });

  test("★틀린 비밀번호는 실패한다", async () => {
    const cn = "e2ebad12345";
    const s = connect(app.pop3Port, "127.0.0.1");
    let buf = "";
    const readLine = (): Promise<string> =>
      new Promise((res, rej) => {
        const onData = (d: Buffer): void => {
          buf += d.toString("latin1");
          const nl = buf.indexOf("\r\n");
          if (nl >= 0) {
            const line = buf.slice(0, nl);
            buf = buf.slice(nl + 2);
            s.off("data", onData);
            res(line);
          }
        };
        s.on("data", onData);
        s.once("error", rej);
      });
    try {
      await readLine();
      s.write(`AUTH SCRAM-SHA-256 ${Buffer.from(`n,,n=${USER},r=${cn}`).toString("base64")}\r\n`);
      const sf = Buffer.from((await readLine()).slice(2), "base64").toString();
      const full = /r=([^,]+)/.exec(sf)![1]!;
      const salt = Buffer.from(/s=([^,]+)/.exec(sf)![1]!, "base64");
      const iters = Number(/i=(\d+)/.exec(sf)![1]!);
      const wp = `c=biws,r=${full}`;
      const p = proofFor("wrong-password", salt, iters, `n=${USER},r=${cn},${sf},${wp}`);
      s.write(`${Buffer.from(`${wp},p=${p}`).toString("base64")}\r\n`);
      expect(await readLine()).toStartWith("-ERR");
    } finally {
      s.destroy();
    }
  });
});

/**
 * submission(587) — **라이브에서 실제로 깨져 있던 표면.**
 *
 * 465 실측이 `250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER`였다. SCRAM이 없었다. 엔진
 * (`proto-smtp/src/engine.ts`)과 어댑터(`server.ts`)는 완성돼 있었고 IMAP·POP3 백엔드에도
 * 있었는데 **`IonosphereSmtpBackend`만 `scramKeys`/`scramAuthorize`를 구현하지 않았다** —
 * `SmtpServer`가 백엔드 메서드 유무로 `scramOffered`를 판정하므로 항상 false였다.
 *
 * 단위 테스트는 전부 통과했다. 조립은 조립으로만 확인된다(스팸 게이트에서 같은 사고가 있었다).
 */
describe("SCRAM end-to-end (submission 587)", () => {
  /**
   * EHLO 능력 목록. **`talk()`을 쓰지 않는다** — 그것은 POP3 전용이라 `+OK`/`-ERR`만 프롬프트로
   * 인식하고 SMTP의 `220`/`250`에는 아무것도 보내지 않는다(재사용했다가 8초 타임아웃을 봤다).
   *
   * SMTP 다중 라인 응답은 `250-`로 이어지고 마지막만 `250 `(공백)이다 — 그 줄이 오면 끝이다.
   */
  function ehlo(port: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const s = connect(port, "127.0.0.1");
      const out: string[] = [];
      let buf = "";
      let greeted = false;
      const t = setTimeout(() => {
        s.destroy();
        reject(new Error(`ehlo timeout; got=${JSON.stringify(out)}`));
      }, 8000);
      s.on("data", (d) => {
        buf += d.toString("latin1");
        let nl: number;
        while ((nl = buf.indexOf("\r\n")) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 2);
          out.push(line);
          if (!greeted && line.startsWith("220")) {
            greeted = true;
            s.write("EHLO probe.test\r\n");
            continue;
          }
          // `250 `(공백)이 마지막 줄 — `250-`는 계속된다.
          if (greeted && /^250 /.test(line)) {
            clearTimeout(t);
            s.end("QUIT\r\n");
            resolve(out.join("\n"));
            return;
          }
        }
      });
      s.on("error", reject);
    });
  }

  /**
   * 줄 단위 SMTP 클라이언트.
   *
   * ★**버퍼에 이미 있는 줄을 먼저 확인한다.** 이것이 이 헬퍼의 존재 이유다 — EHLO 다중 라인
   * 응답은 보통 **한 청크로** 도착하는데, `data` 이벤트만 기다리는 리더는 첫 줄을 꺼내고 나머지가
   * 버퍼에 남은 상태로 오지 않는 다음 이벤트를 기다린다(그렇게 매달리는 것을 여기서 겪었다).
   */
  function smtpClient(port: number): {
    write: (s: string) => void;
    readLine: () => Promise<string>;
    readEhlo: () => Promise<void>;
    close: () => void;
  } {
    const s = connect(port, "127.0.0.1");
    let buf = "";
    const lines: string[] = [];
    let waiter: { resolve: (l: string) => void; timer: ReturnType<typeof setTimeout> } | null = null;
    const drain = (): void => {
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        lines.push(buf.slice(0, nl));
        buf = buf.slice(nl + 2);
      }
      if (waiter !== null && lines.length > 0) {
        const w = waiter;
        waiter = null;
        clearTimeout(w.timer);
        w.resolve(lines.shift()!);
      }
    };
    s.on("data", (d: Buffer) => {
      buf += d.toString("latin1");
      drain();
    });
    s.on("error", () => {
      /* 테스트 종료 시 destroy로 끊는 것이 정상 경로다 */
    });
    const readLine = (): Promise<string> =>
      new Promise((res, rej) => {
        // 이미 읽어 둔 줄이 있으면 소켓을 기다리지 않는다.
        if (lines.length > 0) {
          res(lines.shift()!);
          return;
        }
        /**
         * ★전체 스위트와 함께 돌 때는 8초가 빠듯하다(실측에서 여기서만 타임아웃이 났다).
         * 이 테스트가 재는 것은 **SCRAM 교환의 정확성**이지 응답 속도가 아니므로, 부하에
         * 흔들리는 값으로 실패를 만들면 신호가 아니라 잡음이 된다.
         */
        waiter = { resolve: res, timer: setTimeout(() => rej(new Error("readLine timeout")), 20000) };
      });
    return {
      write: (t) => s.write(t),
      readLine,
      /** 다중 라인 250을 마지막 줄(`250 ` 공백)까지 소진한다. */
      readEhlo: async () => {
        for (;;) {
          if (/^\d{3} /.test(await readLine())) return;
        }
      },
      close: () => s.destroy(),
    };
  }

  test("★submission이 SCRAM-SHA-256을 광고한다 — 라이브에서 빠져 있던 바로 그 값", async () => {
    const caps = await ehlo(app.submissionPort);
    expect(caps).toContain("SCRAM-SHA-256");
    // 순서도 계약이다 — 다수 클라이언트가 광고 순서를 선호도로 읽어서, PLAIN이 앞에 있으면
    // 더 안전한 메커니즘을 두고도 평문을 고른다.
    expect(caps.indexOf("SCRAM-SHA-256")).toBeLessThan(caps.indexOf("PLAIN"));
  });

  test("★25번(relay)은 SCRAM을 광고하지 않는다 — 인증 자체가 없는 표면", async () => {
    // `scramFns`를 클래스 메서드로 두지 않고 옵션으로 받는 이유가 이것이다. 클래스에 두면
    // relay 백엔드도 메서드를 갖게 되어, AUTH를 광고하지 않아야 할 표면이 SCRAM을 광고한다.
    const caps = await ehlo(app.smtpPort);
    expect(caps).not.toContain("SCRAM-SHA-256");
    expect(caps).not.toContain("AUTH ");
  });

  test("★실제 계정으로 submission SCRAM 로그인이 성공한다", async () => {
    const cn = "subnonce4567";
    const c = smtpClient(app.submissionPort);
    const { readLine, readEhlo } = c;
    try {
      await readLine(); // 220 배너
      c.write("EHLO probe.test\r\n");
      await readEhlo();

      c.write(`AUTH SCRAM-SHA-256 ${Buffer.from(`n,,n=${USER},r=${cn}`).toString("base64")}\r\n`);
      const sfLine = await readLine();
      expect(sfLine.startsWith("334 ")).toBe(true);
      const sf = Buffer.from(sfLine.slice(4), "base64").toString();

      const full = /r=([^,]+)/.exec(sf)![1]!;
      const salt = Buffer.from(/s=([^,]+)/.exec(sf)![1]!, "base64");
      const iters = Number(/i=(\d+)/.exec(sf)![1]!);
      const wp = `c=biws,r=${full}`;
      const p = proofFor(PASS, salt, iters, `n=${USER},r=${cn},${sf},${wp}`);

      // client-final → **334 server-final**(235가 아니다 — 클라이언트가 서버를 검증한다)
      c.write(`${Buffer.from(`${wp},p=${p}`).toString("base64")}\r\n`);
      const finalLine = await readLine();
      expect(finalLine.startsWith("334 ")).toBe(true);
      expect(Buffer.from(finalLine.slice(4), "base64").toString().startsWith("v=")).toBe(true);

      // 빈 응답 → 235
      c.write("\r\n");
      expect(await readLine()).toStartWith("235");

      // 인증된 세션이 실제로 발송 권한을 얻었다 — 세션이 계정에 묶였다는 증거.
      c.write(`MAIL FROM:<${USER}>\r\n`);
      expect(await readLine()).toStartWith("250");
    } finally {
      c.close();
    }
  });

  test("★틀린 비밀번호는 535로 실패한다", async () => {
    const cn = "subbad78901";
    const c = smtpClient(app.submissionPort);
    const { readLine, readEhlo } = c;
    try {
      await readLine();
      c.write("EHLO probe.test\r\n");
      await readEhlo();
      c.write(`AUTH SCRAM-SHA-256 ${Buffer.from(`n,,n=${USER},r=${cn}`).toString("base64")}\r\n`);
      const sf = Buffer.from((await readLine()).slice(4), "base64").toString();
      const full = /r=([^,]+)/.exec(sf)![1]!;
      const salt = Buffer.from(/s=([^,]+)/.exec(sf)![1]!, "base64");
      const iters = Number(/i=(\d+)/.exec(sf)![1]!);
      const wp = `c=biws,r=${full}`;
      const p = proofFor("wrong-password", salt, iters, `n=${USER},r=${cn},${sf},${wp}`);
      c.write(`${Buffer.from(`${wp},p=${p}`).toString("base64")}\r\n`);
      expect(await readLine()).toStartWith("535");
    } finally {
      c.close();
    }
  });
});
