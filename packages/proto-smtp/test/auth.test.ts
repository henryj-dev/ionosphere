/**
 * SASL AUTH(PLAIN/LOGIN) + Submission 프로파일 테스트.
 * 엔진 레벨은 engine.test.ts와 동일한 스크립트된 바이트 시퀀스 스타일,
 * 어댑터/암시적 TLS 레벨은 server.test.ts/starttls.test.ts 스타일(실 소켓)을 따른다.
 */
import { readFileSync } from "node:fs";
import { connect, type Socket } from "node:net";
import * as path from "node:path";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { SmtpEngine, type SmtpAction } from "../src/engine.ts";
import { SmtpServer, type SmtpBackend } from "../src/server.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const cert = readFileSync(path.join(here, "fixtures/cert.pem"));
const key = readFileSync(path.join(here, "fixtures/key.pem"));

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function text(actions: SmtpAction[]): string {
  return actions
    .filter((a): a is Extract<SmtpAction, { kind: "reply" }> => a.kind === "reply")
    .map((a) => a.text)
    .join("");
}

function b64(s: string): string {
  return Buffer.from(s).toString("base64");
}

type EngineOverrides = Partial<{
  hostname: string;
  maxSizeBytes: number;
  tlsAvailable: boolean;
  profile: "relay" | "submission";
  authOffered: boolean;
  allowInsecureAuth: boolean;
}>;

function makeEngine(overrides: EngineOverrides = {}): SmtpEngine {
  return new SmtpEngine({
    hostname: "mx.example.test",
    maxSizeBytes: 1_000_000,
    tlsAvailable: false,
    ...overrides,
  });
}

/** greeting + EHLO까지 진행한 엔진을 반환. */
function greeted(engine: SmtpEngine): void {
  engine.greeting();
  engine.feed(bytes("EHLO client.test\r\n"));
}

describe("EHLO — AUTH 광고 조건 (RFC 4954: 평문에는 allowInsecureAuth 없이 광고 금지)", () => {
  test("authOffered=true, TLS 없음, allowInsecureAuth 없음 → AUTH 미광고 + 커맨드도 502", () => {
    const engine = makeEngine({ authOffered: true });
    engine.greeting();
    const t = text(engine.feed(bytes("EHLO c\r\n")));
    expect(t).not.toContain("AUTH");

    const authActions = engine.feed(bytes("AUTH PLAIN " + b64("\0a\0p") + "\r\n"));
    expect(text(authActions)).toStartWith("502 ");
  });

  test("authOffered=true + allowInsecureAuth=true → AUTH PLAIN LOGIN 광고", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    engine.greeting();
    const t = text(engine.feed(bytes("EHLO c\r\n")));
    expect(t).toContain("AUTH PLAIN LOGIN");
  });

  test("authOffered=false → allowInsecureAuth 상관없이 미광고", () => {
    const engine = makeEngine({ authOffered: false, allowInsecureAuth: true });
    engine.greeting();
    const t = text(engine.feed(bytes("EHLO c\r\n")));
    expect(t).not.toContain("AUTH");
  });
});

describe("AUTH PLAIN", () => {
  test("초기응답 인라인 happy path → 235, deliver 액션에 authenticatedAs 반영", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    greeted(engine);

    const payload = b64("\0alice\0secret");
    let actions = engine.feed(bytes(`AUTH PLAIN ${payload}\r\n`));
    const authAction = actions.find((a): a is Extract<SmtpAction, { kind: "auth" }> => a.kind === "auth");
    expect(authAction).toEqual({ kind: "auth", user: "alice", pass: "secret" });

    actions = engine.authResult(true);
    expect(text(actions)).toBe("235 2.7.0 Authentication successful\r\n");

    engine.feed(bytes("MAIL FROM:<alice@example.test>\r\n"));
    engine.feed(bytes("RCPT TO:<bob@example.test>\r\n"));
    engine.rcptResult({ ok: true });
    engine.feed(bytes("DATA\r\n"));
    const dataActions = engine.feed(bytes("hi\r\n.\r\n"));
    const deliverAction = dataActions.find((a): a is Extract<SmtpAction, { kind: "deliver" }> => a.kind === "deliver");
    expect(deliverAction).toBeDefined();
    expect(deliverAction!.authenticatedAs).toBe("alice");
  });

  test("초기응답 없이 334 연속행 플로우", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    greeted(engine);

    let actions = engine.feed(bytes("AUTH PLAIN\r\n"));
    expect(text(actions)).toBe("334\r\n");

    actions = engine.feed(bytes(b64("\0bob\0hunter2") + "\r\n"));
    const authAction = actions.find((a): a is Extract<SmtpAction, { kind: "auth" }> => a.kind === "auth");
    expect(authAction).toEqual({ kind: "auth", user: "bob", pass: "hunter2" });

    actions = engine.authResult(true);
    expect(text(actions)).toBe("235 2.7.0 Authentication successful\r\n");
  });

  test("틀린 비밀번호 → 535", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    greeted(engine);
    engine.feed(bytes(`AUTH PLAIN ${b64("\0alice\0wrong")}\r\n`));
    const actions = engine.authResult(false);
    expect(text(actions)).toBe("535 5.7.8 Authentication credentials invalid\r\n");
  });

  test("잘못된 base64 → 501, 세션은 계속 사용 가능", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    greeted(engine);
    const actions = engine.feed(bytes("AUTH PLAIN !!!!\r\n"));
    expect(text(actions)).toStartWith("501 ");

    const noopActions = engine.feed(bytes("NOOP\r\n"));
    expect(text(noopActions)).toBe("250 2.0.0 OK\r\n");
  });
});

describe("AUTH LOGIN", () => {
  test("전체 챌린지 플로우: 334 Username → 334 Password → auth 액션 → 235", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    greeted(engine);

    let actions = engine.feed(bytes("AUTH LOGIN\r\n"));
    expect(text(actions)).toBe("334 VXNlcm5hbWU6\r\n");

    actions = engine.feed(bytes(b64("carol") + "\r\n"));
    expect(text(actions)).toBe("334 UGFzc3dvcmQ6\r\n");

    actions = engine.feed(bytes(b64("p4ssw0rd") + "\r\n"));
    const authAction = actions.find((a): a is Extract<SmtpAction, { kind: "auth" }> => a.kind === "auth");
    expect(authAction).toEqual({ kind: "auth", user: "carol", pass: "p4ssw0rd" });

    actions = engine.authResult(true);
    expect(text(actions)).toBe("235 2.7.0 Authentication successful\r\n");
  });

  test("`*` 로 취소 → 501 5.7.0, 세션 계속 사용 가능", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    greeted(engine);

    engine.feed(bytes("AUTH LOGIN\r\n"));
    const actions = engine.feed(bytes("*\r\n"));
    expect(text(actions)).toBe("501 5.7.0 Authentication cancelled\r\n");

    const noopActions = engine.feed(bytes("NOOP\r\n"));
    expect(text(noopActions)).toBe("250 2.0.0 OK\r\n");
  });
});

describe("이미 인증됨 → 재AUTH 503", () => {
  test("성공적 AUTH 이후 다시 AUTH 시도하면 503", () => {
    const engine = makeEngine({ authOffered: true, allowInsecureAuth: true });
    greeted(engine);
    engine.feed(bytes(`AUTH PLAIN ${b64("\0alice\0secret")}\r\n`));
    engine.authResult(true);

    const actions = engine.feed(bytes(`AUTH PLAIN ${b64("\0alice\0secret")}\r\n`));
    expect(text(actions)).toStartWith("503 ");
  });
});

describe("submission 프로파일 — MAIL 전 인증 필수 (RFC 6409)", () => {
  test("AUTH 전 MAIL FROM → 530, AUTH 이후엔 정상 트랜잭션(deliver에 authenticatedAs)", () => {
    const engine = makeEngine({ profile: "submission", authOffered: true, allowInsecureAuth: true });
    greeted(engine);

    let actions = engine.feed(bytes("MAIL FROM:<alice@example.test>\r\n"));
    expect(text(actions)).toBe("530 5.7.0 Authentication required\r\n");

    engine.feed(bytes(`AUTH PLAIN ${b64("\0alice\0secret")}\r\n`));
    actions = engine.authResult(true);
    expect(text(actions)).toBe("235 2.7.0 Authentication successful\r\n");

    actions = engine.feed(bytes("MAIL FROM:<alice@example.test>\r\n"));
    expect(text(actions)).toBe("250 2.1.0 OK\r\n");

    engine.feed(bytes("RCPT TO:<bob@example.test>\r\n"));
    engine.rcptResult({ ok: true });
    engine.feed(bytes("DATA\r\n"));
    const dataActions = engine.feed(bytes("hello\r\n.\r\n"));
    const deliverAction = dataActions.find((a): a is Extract<SmtpAction, { kind: "deliver" }> => a.kind === "deliver");
    expect(deliverAction).toBeDefined();
    expect(deliverAction!.authenticatedAs).toBe("alice");
  });
});

// ── 어댑터 레벨(실 소켓) ──────────────────────────────────────────────

interface Delivered {
  mailFrom: string;
  rcptTo: string[];
  raw: Uint8Array;
  authenticatedAs: string | null;
}

function makeAuthBackend(validUser: string, validPass: string): { backend: SmtpBackend; delivered: Delivered[] } {
  const delivered: Delivered[] = [];
  const backend: SmtpBackend = {
    verifyRecipient: async () => ({ ok: true }),
    deliver: async (env) => {
      delivered.push(env);
      return { ok: true, queuedId: "q-auth-1" };
    },
    authenticate: async (user, pass) => ({ ok: user === validUser && pass === validPass }),
  };
  return { backend, delivered };
}

function lineReader(socket: Socket | TLSSocket): () => Promise<string> {
  let buf = "";
  return () =>
    new Promise((resolve) => {
      const tryFlush = (): boolean => {
        const idx = buf.indexOf("\r\n");
        if (idx === -1) return false;
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        resolve(line);
        return true;
      };
      if (tryFlush()) return;
      const onData = (chunk: Buffer): void => {
        buf += chunk.toString("utf-8");
        if (tryFlush()) socket.off("data", onData);
      };
      socket.on("data", onData);
    });
}

let activeServers: SmtpServer[] = [];

afterEach(async () => {
  await Promise.all(activeServers.map((s) => s.close()));
  activeServers = [];
});

describe("SmtpServer 어댑터 — AUTH PLAIN 전체 왕복", () => {
  test("allowInsecureAuth + 가짜 backend.authenticate: AUTH PLAIN → MAIL → ... → deliver가 authenticatedAs를 봄", async () => {
    const { backend, delivered } = makeAuthBackend("bob", "hunter2");
    const server = new SmtpServer({
      hostname: "srv.test",
      maxSizeBytes: 1_000_000,
      backend,
      allowInsecureAuth: true,
    });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const socket = connect(port, "127.0.0.1");
    const readLine = lineReader(socket);
    await new Promise<void>((resolve) => socket.once("connect", resolve));

    expect(await readLine()).toStartWith("220 ");
    socket.write("EHLO client.test\r\n");
    let line = await readLine();
    let sawAuth = false;
    while (line.startsWith("250-")) {
      if (line.includes("AUTH PLAIN LOGIN")) sawAuth = true;
      line = await readLine();
    }
    if (line.includes("AUTH PLAIN LOGIN")) sawAuth = true;
    expect(sawAuth).toBe(true);

    socket.write(`AUTH PLAIN ${b64("\0bob\0hunter2")}\r\n`);
    expect(await readLine()).toBe("235 2.7.0 Authentication successful");

    socket.write("MAIL FROM:<bob@example.test>\r\n");
    expect(await readLine()).toBe("250 2.1.0 OK");
    socket.write("RCPT TO:<carol@example.test>\r\n");
    expect(await readLine()).toBe("250 2.1.5 carol@example.test OK");
    socket.write("DATA\r\n");
    expect(await readLine()).toStartWith("354 ");
    socket.write("Subject: hi\r\n\r\nbody\r\n.\r\n");
    expect(await readLine()).toBe("250 2.6.0 queued as q-auth-1");

    socket.end();
    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.authenticatedAs).toBe("bob");
  });
});

describe("암시적 TLS(465류)", () => {
  test("implicitTls: tls.connect 클라이언트로 접속 즉시 TLS, EHLO 동작 + AUTH 광고", async () => {
    const { backend } = makeAuthBackend("x", "y");
    const server = new SmtpServer({
      hostname: "srv.test",
      maxSizeBytes: 1_000_000,
      backend,
      tls: { key, cert },
      implicitTls: true,
    });
    activeServers.push(server);
    const port = await server.listen(0, "127.0.0.1");

    const socket = tlsConnect({ port, host: "127.0.0.1", rejectUnauthorized: false });
    await new Promise<void>((resolve, reject) => {
      socket.once("secureConnect", resolve);
      socket.once("error", reject);
    });
    const readLine = lineReader(socket);

    expect(await readLine()).toStartWith("220 ");
    socket.write("EHLO client.test\r\n");
    let line = await readLine();
    let sawAuth = false;
    while (line.startsWith("250-")) {
      if (line.includes("AUTH PLAIN LOGIN")) sawAuth = true;
      line = await readLine();
    }
    if (line.includes("AUTH PLAIN LOGIN")) sawAuth = true;
    expect(sawAuth).toBe(true);
    // 암시적 TLS에서는 이미 암호화되어 있으므로 STARTTLS를 재광고하지 않는다
    expect(line).not.toContain("STARTTLS");

    socket.destroy();
  });
});
