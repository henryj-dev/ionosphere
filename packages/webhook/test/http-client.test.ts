/**
 * 웹훅 HTTP 클라이언트 — 연결 단계 SSRF 방어(감사 M-14의 본체)와 전송 성질 회귀.
 *
 * 예전에는 전역 `fetch`로 보냈고 검사는 URL 문자열만 봤다. 그래서 **DNS 리바인딩은 완전히
 * 열려 있었다** — `evil.com`의 A 레코드가 127.0.0.1이면 그대로 내부로 POST가 나갔고,
 * 판정이 애초에 IP를 보지 않으니 TOCTOU 경쟁조차 필요 없었다.
 *
 * 여기서는 **실제 DNS를 때리지 않는다**. 해석기를 주입해 "이 이름은 이 주소로 해석된다"를
 * 테스트가 정하고, 그 결과로 소켓이 열리는지 아닌지를 **살아 있는 로컬 서버의 수신 기록**으로
 * 판정한다(로그가 비어 있으면 바이트가 나가지 않은 것이다).
 */
import { afterEach, describe, expect, test } from "@ionosphere/testkit";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { BlockedAddressError } from "../src/url-guard.ts";
import { createGuardedFetch, createGuardedLookup, sendRequest, type ResolveHostFn } from "../src/http-client.ts";
import { WebhookWorker } from "../src/worker.ts";

interface Recorded {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
}
type Respond = (res: import("node:http").ServerResponse) => void;

let open: Server[] = [];
afterEach(async () => {
  const servers = open;
  open = [];
  for (const s of servers) {
    s.closeAllConnections?.();
    await new Promise<void>((r) => s.close(() => r()));
  }
});

async function startServer(respond: Respond): Promise<{ port: number; log: Recorded[] }> {
  const log: Recorded[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      log.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      respond(res);
    });
    // 클라이언트가 본문을 읽지 않고 끊으면 ECONNRESET이 온다 — 테스트 프로세스를 죽이지 않게 삼킨다
    req.on("error", () => {});
    res.on("error", () => {});
  });
  open.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const addr = server.address();
  return { port: typeof addr === "object" && addr !== null ? addr.port : 0, log };
}

const POST = { method: "POST", headers: { "content-type": "application/json" }, body: '{"x":1}' };

/** 주입 해석기 — 이름 → 주소 목록. 실제 DNS는 쓰지 않는다. */
function resolverOf(table: Record<string, readonly { address: string; family: number }[]>): ResolveHostFn {
  return async (hostname) => {
    const hit = table[hostname];
    if (!hit) throw new Error(`unexpected lookup: ${hostname}`);
    return hit;
  };
}

function callLookup(
  lookup: ReturnType<typeof createGuardedLookup>,
  hostname: string,
  options: { family?: number; all?: boolean } = {},
): Promise<{ err: Error | null; address: string | { address: string; family: number }[]; family: number | undefined }> {
  return new Promise((resolve) => {
    lookup(hostname, options, (err, address, family) => resolve({ err, address, family }));
  });
}

describe("createGuardedLookup — 해석된 주소를 검사하고 그 주소로 고정한다", () => {
  test("공개 주소는 통과하고 **해석된 값 그대로** 넘어간다(pinning)", async () => {
    const lookup = createGuardedLookup(resolverOf({ "hook.example.com": [{ address: "203.0.113.10", family: 4 }] }));
    const { err, address, family } = await callLookup(lookup, "hook.example.com");
    expect(err).toBeNull();
    expect(address).toBe("203.0.113.10"); // 이 IP로 연결된다 — 재조회가 없으므로 리바인딩 창이 없다
    expect(family).toBe(4);
  });

  test("사설·루프백으로 해석되면 차단(★DNS 리바인딩)", async () => {
    const lookup = createGuardedLookup(resolverOf({ "evil.example.com": [{ address: "127.0.0.1", family: 4 }] }));
    const { err } = await callLookup(lookup, "evil.example.com");
    expect(err).toBeInstanceOf(BlockedAddressError);
    expect(String(err?.message)).toContain("blocked url");
  });

  test("IPv4-매핑·링크로컬로 해석되는 경우도 같은 판정", async () => {
    const lookup = createGuardedLookup(
      resolverOf({
        "a.example.com": [{ address: "::ffff:169.254.169.254", family: 6 }],
        "b.example.com": [{ address: "169.254.169.254", family: 4 }],
        "c.example.com": [{ address: "fd00::1", family: 6 }],
      }),
    );
    for (const name of ["a.example.com", "b.example.com", "c.example.com"]) {
      expect((await callLookup(lookup, name)).err).toBeInstanceOf(BlockedAddressError);
    }
  });

  /** 하나라도 섞이면 전부 거부 — 남은 공개 주소로 연결해 주면 다음 조회에서 순서만 바꾸면 된다. */
  test("공개 주소와 사설 주소가 섞이면 응답 전체를 거부한다", async () => {
    const lookup = createGuardedLookup(
      resolverOf({ "mixed.example.com": [{ address: "203.0.113.10", family: 4 }, { address: "10.0.0.1", family: 4 }] }),
    );
    const { err } = await callLookup(lookup, "mixed.example.com");
    expect(err).toBeInstanceOf(BlockedAddressError);
  });

  test("all=true(Happy Eyeballs)에도 검사한 주소만 넘긴다", async () => {
    const lookup = createGuardedLookup(
      resolverOf({ "dual.example.com": [{ address: "203.0.113.10", family: 4 }, { address: "2606:4700::1111", family: 6 }] }),
    );
    const { err, address } = await callLookup(lookup, "dual.example.com", { all: true });
    expect(err).toBeNull();
    expect(address).toEqual([{ address: "203.0.113.10", family: 4 }, { address: "2606:4700::1111", family: 6 }]);
  });

  test("family 지정 시 해당 계열만, 남는 게 없으면 ENOTFOUND", async () => {
    const lookup = createGuardedLookup(resolverOf({ "v4only.example.com": [{ address: "203.0.113.10", family: 4 }] }));
    expect((await callLookup(lookup, "v4only.example.com", { family: 4 })).address).toBe("203.0.113.10");
    const miss = await callLookup(lookup, "v4only.example.com", { family: 6 });
    expect((miss.err as NodeJS.ErrnoException | null)?.code).toBe("ENOTFOUND");
  });

  test("해석 실패는 그대로 전달한다(차단과 구분)", async () => {
    const lookup = createGuardedLookup(async () => {
      throw new Error("EAI_AGAIN");
    });
    const { err } = await callLookup(lookup, "down.example.com");
    expect(err).not.toBeInstanceOf(BlockedAddressError);
    expect(String(err?.message)).toContain("EAI_AGAIN");
  });
});

describe("createGuardedFetch — 바이트가 나가는지로 판정한다", () => {
  /**
   * URL 문자열(`rebind.example.com`)에는 막을 근거가 없다 — 그래서 이 테스트가 실패하지 않는다는
   * 것은 곧 **실행 중인 런타임이 `lookup` 훅을 실제로 태웠다**는 증거다(에러 문구로 못 박는다).
   * bun·node가 훅을 다르게 다루면 여기서 먼저 터진다.
   */
  test("★리바인딩: 이름이 로컬 서버로 해석되면 요청이 도달하지 않는다", async () => {
    const { port, log } = await startServer((res) => res.end("ok"));
    const fetchFn = createGuardedFetch({
      timeoutMs: 2_000,
      resolveHost: resolverOf({ "rebind.example.com": [{ address: "127.0.0.1", family: 4 }] }),
    });

    const err = await fetchFn(`http://rebind.example.com:${port}/hook`, POST).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BlockedAddressError);
    expect(String((err as Error).message)).toContain("resolved to 127.0.0.1");
    expect(log).toHaveLength(0); // 서버는 아무것도 못 받았다
  });

  test("URL에 사설 IP 리터럴을 직접 쓰면 소켓을 열기 전에 끊는다", async () => {
    const { port, log } = await startServer((res) => res.end("ok"));
    const fetchFn = createGuardedFetch({ timeoutMs: 2_000, resolveHost: resolverOf({}) });

    await expect(fetchFn(`http://127.0.0.1:${port}/hook`, POST)).rejects.toBeInstanceOf(BlockedAddressError);
    await expect(fetchFn(`http://[::ffff:127.0.0.1]:${port}/hook`, POST)).rejects.toBeInstanceOf(BlockedAddressError);
    expect(log).toHaveLength(0);
  });
});

describe("sendRequest — 전송 성질(리다이렉트·본문·타임아웃)", () => {
  test("2xx를 그대로 돌려주고 메서드·헤더·본문이 도착한다", async () => {
    const { port, log } = await startServer((res) => {
      res.statusCode = 204;
      res.end();
    });
    const res = await sendRequest(`http://127.0.0.1:${port}/hook?a=1`, POST, { timeoutMs: 2_000 });
    expect(res).toEqual({ status: 204 });
    expect(log).toHaveLength(1);
    expect(log[0]!.method).toBe("POST");
    expect(log[0]!.path).toBe("/hook?a=1");
    expect(log[0]!.body).toBe('{"x":1}');
    expect(log[0]!.headers.host).toBe(`127.0.0.1:${port}`);
    expect(log[0]!.headers["content-type"]).toBe("application/json");
  });

  /**
   * ★3xx를 따라가지 않는다. 따라가면 공개 엔드포인트가 `302 → http://169.254.169.254/`로
   * **DNS 조작 없이** URL 검사를 우회시킬 수 있다. 반환 타입이 `{ status }`뿐이라 Location을
   * 읽을 방법 자체가 없다는 것을 요청 횟수로 확인한다.
   */
  test("3xx Location을 따라가지 않는다", async () => {
    const { port, log } = await startServer((res) => {
      res.statusCode = 302;
      res.setHeader("location", "http://169.254.169.254/latest/meta-data/");
      res.end();
    });
    const res = await sendRequest(`http://127.0.0.1:${port}/hook`, POST, { timeoutMs: 2_000 });
    expect(res).toEqual({ status: 302 }); // 2xx가 아니므로 워커가 재시도/실패로 처리한다
    expect(log).toHaveLength(1); // 두 번째 요청이 없다
  });

  /** 본문을 읽는다면 서버가 끝내지 않는 응답에 매달려 타임아웃까지 갔을 것이다. */
  test("응답 본문을 기다리지 않는다(그래서 크기 상한이 필요 없다)", async () => {
    const { port } = await startServer((res) => {
      res.statusCode = 200;
      res.write("x".repeat(1024)); // 헤더만 보내고 끝내지 않는다
    });
    const res = await sendRequest(`http://127.0.0.1:${port}/hook`, POST, { timeoutMs: 5_000 });
    expect(res).toEqual({ status: 200 });
  });

  test("응답이 없으면 타임아웃으로 끊는다", async () => {
    const { port } = await startServer(() => {
      /* 영원히 응답하지 않는다 */
    });
    await expect(sendRequest(`http://127.0.0.1:${port}/hook`, POST, { timeoutMs: 150 })).rejects.toThrow(/timeout/);
  });
});

describe("WebhookWorker + 가드 fetch", () => {
  test("리바인딩으로 차단된 건은 재시도하지 않고 failed로 닫는다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const { port, log } = await startServer((res) => res.end("ok"));
    const id = "R".repeat(26);
    await db.batch([
      {
        sql: `INSERT INTO webhook_deliveries (id, account_id, endpoint_id, url, secret, payload, status, attempts, next_attempt, lease_until, last_error, created_at)
              VALUES (?, 'acc', 'ep', ?, '', '{}', 0, 0, 0, NULL, NULL, 0)`,
        params: [id, `http://rebind.example.com:${port}/hook`],
      },
    ]);

    const worker = new WebhookWorker({
      db,
      fetch: createGuardedFetch({ timeoutMs: 2_000, resolveHost: resolverOf({ "rebind.example.com": [{ address: "127.0.0.1", family: 4 }] }) }),
    });
    expect(await worker.tick()).toBe(1);

    const { rows } = await db.query({ sql: "SELECT status, attempts, last_error FROM webhook_deliveries WHERE id = ?", params: [id] });
    expect(Number(rows[0]!.status)).toBe(3); // failed — 백오프로 계속 두드리지 않는다
    expect(Number(rows[0]!.attempts)).toBe(0);
    expect(String(rows[0]!.last_error)).toContain("blocked url");
    expect(log).toHaveLength(0);

    await db.close();
  });
});
