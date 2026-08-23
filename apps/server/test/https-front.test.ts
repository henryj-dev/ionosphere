/**
 * HTTPS 프론트(443 종단) 테스트 — TLS 종단 후 Host 헤더로 upstream을 골라 리버스 프록시하는지,
 * 원본 Host·바디가 보존되는지, 인증서 핫리로드가 새 연결에 반영되는지 검증한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { spawnSync } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import { networkInterfaces } from "node:os";
import * as tlsMod from "node:tls";
import { generateSelfSigned } from "@ionosphere/tls";
import { HttpsFrontServer } from "../src/https-front.ts";
import { PROBE_OK, probeVerdict } from "./helpers.ts";

/** 요청을 그대로 반향하는 upstream(라벨·Host·메서드·바디 확인용). */
function upstream(label: string): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const srv = createServer((req: IncomingMessage, res: ServerResponse) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ label, host: req.headers.host, xfp: req.headers["x-forwarded-proto"], method: req.method, body }),
        );
      });
    });
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr !== null ? addr.port : 0;
      resolve({ port, close: () => new Promise((r) => srv.close(() => r())) });
    });
  });
}

interface Res {
  status: number;
  body: string;
}
/** self-signed 대상이라 rejectUnauthorized:false로 https 요청. */
function httpsReq(port: number, host: string, method = "GET", body?: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: "127.0.0.1", port, path: "/x", method, servername: host, headers: { host }, rejectUnauthorized: false },
      (r) => {
        let data = "";
        r.on("data", (c) => (data += c));
        r.on("end", () => resolve({ status: r.statusCode ?? 0, body: data }));
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

describe("HttpsFrontServer", () => {
  test("Host 접두사로 upstream 라우팅 + 원본 Host·XFP 보존", async () => {
    const ac = await upstream("autoconfig");
    const jm = await upstream("jmap");
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test", sans: ["*.ionosphere.test", "ionosphere.test"] });
    const front = new HttpsFrontServer({
      tls: { key: tls.keyPem, cert: tls.certPem },
      routes: [
        { hosts: ["mta-sts.ionosphere.test", "autoconfig.ionosphere.test", "autodiscover.ionosphere.test"], port: ac.port, exposure: "public" },
        { hosts: ["mx.ionosphere.test"], port: jm.port, exposure: "public" },
      ],
    });
    const port = await front.listen(0, "127.0.0.1");

    const r1 = JSON.parse((await httpsReq(port, "mta-sts.ionosphere.test")).body);
    expect(r1.label).toBe("autoconfig");
    expect(r1.host).toBe("mta-sts.ionosphere.test"); // 원본 Host 보존
    expect(r1.xfp).toBe("https"); // X-Forwarded-Proto 주입

    const r2 = JSON.parse((await httpsReq(port, "autodiscover.ionosphere.test")).body);
    expect(r2.label).toBe("autoconfig");

    const r3 = JSON.parse((await httpsReq(port, "mx.ionosphere.test")).body);
    expect(r3.label).toBe("jmap"); // 매칭 없음 → defaultPort

    await front.close();
    await ac.close();
    await jm.close();
  });

  test("POST 바디 통과", async () => {
    const jm = await upstream("jmap");
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const front = new HttpsFrontServer({ tls: { key: tls.keyPem, cert: tls.certPem }, routes: [{ hosts: ["mx.ionosphere.test"], port: jm.port, exposure: "public" }] });
    const port = await front.listen(0, "127.0.0.1");

    const r = JSON.parse((await httpsReq(port, "mx.ionosphere.test", "POST", '{"using":[]}')).body);
    expect(r.method).toBe("POST");
    expect(r.body).toBe('{"using":[]}');

    await front.close();
    await jm.close();
  });

  test("매칭 없고 defaultPort 없으면 404", async () => {
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const front = new HttpsFrontServer({ tls: { key: tls.keyPem, cert: tls.certPem }, routes: [] });
    const port = await front.listen(0, "127.0.0.1");

    const r = await httpsReq(port, "mx.ionosphere.test");
    expect(r.status).toBe(404);

    await front.close();
  });

  test("reloadTls 후 새 인증서가 서빙된다", async () => {
    const jm = await upstream("jmap");
    const first = generateSelfSigned({ commonName: "old.ionosphere.test" });
    const front = new HttpsFrontServer({ tls: { key: first.keyPem, cert: first.certPem }, routes: [{ hosts: ["mx.ionosphere.test"], port: jm.port, exposure: "public" }] });
    const port = await front.listen(0, "127.0.0.1");

    // 교체 전 인증서 CN 확인
    const before = await peerCn(port);
    expect(before).toContain("old.ionosphere.test");

    const second = generateSelfSigned({ commonName: "new.ionosphere.test" });
    await front.reloadTls({ key: second.keyPem, cert: second.certPem });

    const after = await peerCn(port);
    expect(after).toContain("new.ionosphere.test");

    await front.close();
    await jm.close();
  });
});

/**
 * SNI 라우트(443에 관리 콘솔을 얹기 위한 것) — 이름마다 **다른 인증서**를 제시하는지.
 *
 * ★왜 필요한가: 443의 기본 인증서에는 mx/mta-sts/autoconfig가 들어 있고 admin은 별개 발급물이라
 * 한 장으로 둘 다 만족시킬 수 없다. 기본 인증서를 admin 것으로 바꿔 해결하면 MTA-STS 정책 서빙이
 * 이름 불일치로 깨지고, enforce 모드에서는 **수신이 막힌다**. 갈라내는 쪽이 유일한 답이다.
 */
describe("HttpsFrontServer — 라우트별 인증서(SNI)", () => {
  test("admin 이름엔 전용 인증서, 나머지엔 기본 인증서", async () => {
    const ad = await upstream("admin");
    const jm = await upstream("jmap");
    const base = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const admin = generateSelfSigned({ commonName: "admin.ionosphere.test" });
    const front = new HttpsFrontServer({
      tls: { key: base.keyPem, cert: base.certPem },
      routes: [
        { hosts: ["admin.ionosphere.test"], port: ad.port, tls: { key: admin.keyPem, cert: admin.certPem }, exposure: "public" },
        { hosts: ["mta-sts.ionosphere.test"], port: jm.port, exposure: "public" },
      ],
    });
    const port = await front.listen(0, "127.0.0.1");

    expect(await peerCnFor(port, "admin.ionosphere.test")).toBe("admin.ionosphere.test");
    // 다른 이름은 기본 자료 — 여기가 무너지면 MTA-STS·autoconfig가 이름 불일치로 깨진다.
    expect(await peerCnFor(port, "mta-sts.ionosphere.test")).toBe("mx.ionosphere.test");
    // SNI를 아예 보내지 않는 클라이언트도 기본 인증서를 받아야 한다(fail open이 아니라 정상 동작).
    expect(await peerCnFor(port, undefined)).toBe("mx.ionosphere.test");

    // 인증서가 갈렸어도 프록시는 라우트 규칙대로 간다 — 둘이 어긋나면
    // "인증서는 admin인데 내용은 JMAP"이 된다.
    const r = JSON.parse((await httpsReq(port, "admin.ionosphere.test")).body);
    expect(r.label).toBe("admin");

    await front.close();
    await ad.close();
    await jm.close();
  });

  test("reloadRouteTls가 SNI 자료만 갈아끼운다(기본 자료는 그대로)", async () => {
    const ad = await upstream("admin");
    const base = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const admin = generateSelfSigned({ commonName: "admin.ionosphere.test" });
    const front = new HttpsFrontServer({
      tls: { key: base.keyPem, cert: base.certPem },
      routes: [{ hosts: ["admin.ionosphere.test"], port: ad.port, tls: { key: admin.keyPem, cert: admin.certPem }, exposure: "public" }],
    });
    const port = await front.listen(0, "127.0.0.1");
    expect(await peerCnFor(port, "admin.ionosphere.test")).toBe("admin.ionosphere.test");

    // ★이 경로가 없으면 admin 이름만 만료 인증서를 계속 제시한다 — 143·110이 재적재 목록에서
    // 빠져 그 두 포트만 만료 인증서를 제시했던 사고와 같은 부류다(app.ts tlsListeners 주석).
    const renewed = generateSelfSigned({ commonName: "admin2.ionosphere.test" });
    expect(front.reloadRouteTls("admin.ionosphere.test", { key: renewed.keyPem, cert: renewed.certPem })).toBe(true);

    expect(await peerCnFor(port, "admin.ionosphere.test")).toBe("admin2.ionosphere.test");
    expect(await peerCnFor(port, "mta-sts.ionosphere.test")).toBe("mx.ionosphere.test"); // 기본은 불변

    // 대상이 없으면 false — 호출부가 "조용히 아무것도 안 됨"을 구분할 수 있어야 한다.
    expect(front.reloadRouteTls("nosuch.ionosphere.test", { key: renewed.keyPem, cert: renewed.certPem })).toBe(false);

    await front.close();
    await ad.close();
  });
});

/** SNI 이름을 지정해 상대 인증서 CN을 읽는다(peerCn은 servername이 고정이라 별도). */
function peerCnFor(port: number, servername: string | undefined): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = tlsMod.connect(
      { host: "127.0.0.1", port, rejectUnauthorized: false, ...(servername ? { servername } : { servername: "" }) },
      () => {
        const cert = sock.getPeerCertificate();
        sock.end();
        resolve(cert && cert.subject ? String(cert.subject.CN ?? "") : "");
      },
    );
    sock.on("error", reject);
  });
}

/**
 * 원시 바이트를 그대로 흘려 넣고 waitMs 동안 응답을 모은다.
 * HTTP 클라이언트 라이브러리는 악성 프레이밍을 만들어 주지 않아서 소켓에 직접 쓴다.
 */
function rawTls(port: number, payload: string, waitMs = 350): Promise<string> {
  return new Promise((resolve) => {
    let out = "";
    const sock = tlsMod.connect(
      { host: "127.0.0.1", port, rejectUnauthorized: false, servername: "mx.ionosphere.test" },
      () => sock.write(Buffer.from(payload, "latin1")),
    );
    sock.setEncoding("latin1");
    sock.on("data", (c: string) => (out += c));
    sock.on("error", () => {});
    setTimeout(() => {
      sock.destroy();
      resolve(out);
    }, waitMs);
  });
}

/** 크래프트한 응답 바이트를 그대로 뱉는 가짜 upstream(응답 방향 검증용). */
function rawUpstream(response: string): Promise<{ port: number; close: () => Promise<void> }> {
  const socks: net.Socket[] = [];
  const srv = net.createServer((sock) => {
    socks.push(sock);
    sock.on("error", () => {});
    let sent = false;
    sock.on("data", () => {
      if (sent) return;
      sent = true;
      sock.write(Buffer.from(response, "latin1"));
    });
  });
  return new Promise((resolve) => {
    srv.listen(0, "127.0.0.1", () => {
      const a = srv.address();
      resolve({
        port: typeof a === "object" && a !== null ? a.port : 0,
        close: () =>
          new Promise((r) => {
            for (const s of socks) s.destroy();
            srv.close(() => r());
          }),
      });
    });
  });
}

const front = (tlsPem: { keyPem: string; certPem: string }, port: number): HttpsFrontServer =>
  new HttpsFrontServer({ tls: { key: tlsPem.keyPem, cert: tlsPem.certPem }, routes: [{ hosts: ["mx.ionosphere.test"], port, exposure: "public" }] });

describe("HttpsFrontServer — request smuggling 방어", () => {
  // 앞단과 뒤가 메시지 경계를 다르게 보면 미인증 원격이 인증 사용자의 요청에 자기 요청을
  // 끼워 넣을 수 있다. RFC 9112 §6.1 권고대로 **재해석하지 말고 거부**하는지 본다.
  test("모호한 프레이밍은 400으로 거부한다", async () => {
    const jm = await upstream("jmap");
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const f = front(tls, jm.port);
    const port = await f.listen(0, "127.0.0.1");
    const H = "Host: mx.ionosphere.test\r\n";

    const bad: Array<[string, string]> = [
      ["CL.TE", `POST /a HTTP/1.1\r\n${H}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n`],
      ["TE.CL", `POST /a HTTP/1.1\r\n${H}Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n`],
      ["TE 난독화(xchunked)", `POST /a HTTP/1.1\r\n${H}Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n`],
      ["TE chunked, identity", `POST /a HTTP/1.1\r\n${H}Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n`],
      ["TE 중복", `POST /a HTTP/1.1\r\n${H}Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n`],
      ["CL 중복(다른 값)", `POST /a HTTP/1.1\r\n${H}Content-Length: 5\r\nContent-Length: 6\r\n\r\nhelloX`],
      // ↓ bun이 그냥 통과시키던 것들 — 런타임이 아니라 우리 검사가 막는다는 증거.
      ["CL 중복(같은 값)", `POST /a HTTP/1.1\r\n${H}Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello`],
      ["Host 중복", `GET /a HTTP/1.1\r\n${H}Host: autoconfig.ionosphere.test\r\n\r\n`],
      ["절대 URI 요청 타깃", `GET http://autoconfig.ionosphere.test/a HTTP/1.1\r\n${H}\r\n`],
      ["CL 콤마 목록", `POST /a HTTP/1.1\r\n${H}Content-Length: 5, 6\r\n\r\nhello`],
      ["CL 선행 +", `POST /a HTTP/1.1\r\n${H}Content-Length: +5\r\n\r\nhello`],
    ];
    for (const [label, raw] of bad) {
      const first = (await rawTls(port, raw)).split("\r\n")[0] ?? "";
      expect(`${label} → ${first}`).toBe(`${label} → HTTP/1.1 400 Bad Request`);
    }

    await f.close();
    await jm.close();
  });

  test("정상 요청은 그대로 통과한다(GET·POST CL·POST chunked)", async () => {
    const jm = await upstream("jmap");
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const f = front(tls, jm.port);
    const port = await f.listen(0, "127.0.0.1");
    const H = "Host: mx.ionosphere.test\r\n";

    expect((await rawTls(port, `GET /a HTTP/1.1\r\n${H}\r\n`)).split("\r\n")[0]).toBe("HTTP/1.1 200 OK");
    const cl = await rawTls(port, `POST /a HTTP/1.1\r\n${H}Content-Length: 5\r\n\r\nhello`);
    expect(cl).toContain('"body":"hello"');
    const chunked = await rawTls(
      port,
      `POST /a HTTP/1.1\r\n${H}Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n`,
    );
    expect(chunked).toContain('"body":"hello"');

    await f.close();
    await jm.close();
  });

  // `Connection: keep-alive, X-Secret`으로 나열된 헤더도 홉바이홉이다(RFC 9110 §7.6.1).
  test("Connection에 나열된 헤더는 upstream으로 넘기지 않는다", async () => {
    const seen: Array<Record<string, unknown>> = [];
    const srv = createServer((req: IncomingMessage, res: ServerResponse) => {
      seen.push({ ...req.headers });
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const a = srv.address();
    const upPort = typeof a === "object" && a !== null ? a.port : 0;
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const f = front(tls, upPort);
    const port = await f.listen(0, "127.0.0.1");

    await rawTls(
      port,
      "GET /a HTTP/1.1\r\nHost: mx.ionosphere.test\r\nConnection: keep-alive, X-Secret\r\nX-Secret: leaked\r\n\r\n",
    );
    expect(seen.length).toBe(1);
    expect(seen[0]?.["x-secret"]).toBeUndefined();

    await f.close();
    await new Promise<void>((r) => srv.close(() => r()));
  });

  test("upstream이 CL+TE를 동시에 보내면 502로 끊는다(응답 desync 차단)", async () => {
    const up = await rawUpstream(
      "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const f = front(tls, up.port);
    const port = await f.listen(0, "127.0.0.1");

    const out = await rawTls(port, "GET /a HTTP/1.1\r\nHost: mx.ionosphere.test\r\n\r\n");
    expect(out.split("\r\n")[0]).toBe("HTTP/1.1 502 Bad Gateway");
    // 클라이언트에게 CL과 TE가 함께 나가면 그 자체가 desync다.
    expect(out.toLowerCase()).not.toContain("transfer-encoding");

    await f.close();
    await up.close();
  });

  test("upstream 응답의 홉바이홉 헤더는 클라이언트로 새지 않는다", async () => {
    const up = await rawUpstream(
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nUpgrade: h2c\r\nConnection: upgrade\r\nKeep-Alive: timeout=99\r\nProxy-Connection: x\r\n\r\nok",
    );
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const f = front(tls, up.port);
    const port = await f.listen(0, "127.0.0.1");

    const out = (await rawTls(port, "GET /a HTTP/1.1\r\nHost: mx.ionosphere.test\r\n\r\n")).toLowerCase();
    expect(out).toContain("200 ok");
    expect(out).not.toContain("upgrade: h2c");
    expect(out).not.toContain("timeout=99");
    expect(out).not.toContain("proxy-connection");

    await f.close();
    await up.close();
  });

  // ★핵심 회귀: 바디를 덜 보내고 끊은 요청이 upstream 연결에 남으면, upstream이 남은 바디를
  //   버리는 동안 **다음 사용자의 요청 바이트가 그 바디로 먹힌다**(bun에서 실제로 재현됐다).
  test("잘린 바디 요청이 다음 요청을 오염시키지 않는다(업스트림 연결 재사용 금지)", async () => {
    const seen: string[] = [];
    const srv = createServer((req: IncomingMessage, res: ServerResponse) => {
      seen.push(`${req.method} ${req.url}`);
      if (req.url === "/attack") {
        // 바디를 다 읽기 전에 즉답 — 401·404·413에서 흔하고 합법인 동작이다.
        res.writeHead(401, { "content-length": "6" });
        res.end("denied");
        return;
      }
      req.on("data", () => {});
      req.on("end", () => {
        res.writeHead(200, { "content-length": "2" });
        res.end("ok");
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const a = srv.address();
    const upPort = typeof a === "object" && a !== null ? a.port : 0;
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const f = front(tls, upPort);
    const port = await f.listen(0, "127.0.0.1");

    await rawTls(port, "GET /warmup HTTP/1.1\r\nHost: mx.ionosphere.test\r\n\r\n", 300);

    // 공격자: Content-Length 200을 선언하고 10바이트만 보낸 뒤 정상 FIN.
    await new Promise<void>((resolve) => {
      const s = tlsMod.connect(
        { host: "127.0.0.1", port, rejectUnauthorized: false, servername: "mx.ionosphere.test" },
        () => {
          s.write("POST /attack HTTP/1.1\r\nHost: mx.ionosphere.test\r\nContent-Length: 200\r\n\r\nAAAAAAAAAA");
          setTimeout(() => {
            s.end();
            setTimeout(resolve, 250);
          }, 120);
        },
      );
      s.on("error", () => resolve());
      setTimeout(resolve, 1500);
    });

    // 피해자: 평범한 요청이 upstream에 **온전히** 도달해야 한다.
    const victim = await rawTls(
      port,
      "GET /victim HTTP/1.1\r\nHost: mx.ionosphere.test\r\nAuthorization: Bearer VICTIM\r\n\r\n",
      600,
    );
    expect(seen).toContain("GET /victim");
    expect(victim.split("\r\n")[0]).toBe("HTTP/1.1 200 OK");

    await f.close();
    await new Promise<void>((r) => srv.close(() => r()));
  });

  // res의 'error'에 리스너가 없으면 unhandled가 되고 main.ts는 uncaughtException에서 프로세스를
  // 종료한다 — 443 하나가 25·587·993을 함께 내리는 자리라 반드시 잡혀 있어야 한다.
  test("upstream이 Content-Length보다 많이 보내도 프로세스가 죽지 않는다", async () => {
    const up = await rawUpstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello");
    const tls = generateSelfSigned({ commonName: "mx.ionosphere.test" });
    const f = front(tls, up.port);
    const port = await f.listen(0, "127.0.0.1");

    await rawTls(port, "GET /a HTTP/1.1\r\nHost: mx.ionosphere.test\r\n\r\n", 400);
    // 여기까지 왔다는 것이 곧 검증이다(uncaughtException이면 러너가 죽는다).
    const after = await rawTls(port, "GET /b HTTP/1.1\r\nHost: mx.ionosphere.test\r\n\r\n", 400);
    expect(after.length).toBeGreaterThan(0);

    await f.close();
    await up.close();
  });

  /**
   * ★위 테스트만으로는 방어가 고정되지 않는다(뮤테이션으로 확인): bun은 Content-Length 초과분을
   * 조용히 잘라서 res 'error' 자체가 안 난다. 이 결함은 **node에서만** 재현되고 라이브가 node라
   * (운영 저장소의 systemd 유닛) node 하위 프로세스로 실제 실행해 고정한다.
   * 방어를 빼면 unhandled 'error' → node 기본 종료로 exit 1이 된다(실측).
   */
  test("[node] upstream 과다 전송이 프로세스를 죽이지 않는다", () => {
    const probe = new URL("./https-front-crash-probe.ts", import.meta.url).pathname;
    const r = spawnSync("node", [probe], { encoding: "utf8", timeout: 30_000 });
    expect(probeVerdict(r)).toBe(PROBE_OK);
  });
});

/** 새 TLS 연결의 서버 인증서 subject CN을 읽는다(핫리로드 검증). */
function peerCn(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = tlsMod.connect({ host: "127.0.0.1", port, servername: "x", rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate();
      sock.end();
      resolve(cert && cert.subject ? String(cert.subject.CN ?? "") : "");
    });
    sock.on("error", reject);
  });
}

/**
 * ★upstream이 **루프백이 아닌 주소**에 바인딩된 경우 — 라이브에서 502를 냈던 구성이다.
 *
 * 무엇이 잘못됐었나: 프론트가 upstream 연결 주소를 항상 `127.0.0.1`로 가정했는데,
 * `IONOSPHERE_LISTEN_AUTOCONFIG=10.0.101.12:`처럼 축별로 주소를 지정하면 리스너는 **그 주소에만**
 * 붙는다. 두 값이 어긋나 프론트가 아무도 없는 루프백에 연결했고, autoconfig·autodiscover·
 * MTA-STS 정책이 전부 502였다. DNS는 `_mta-sts`로 정책이 있다고 광고하는 중이라 발신 MTA만
 * 조용히 실패했다 — 우리 쪽 로그에는 아무 흔적도 남지 않는 종류의 고장이다.
 *
 * 이 테스트가 없으면 같은 회귀가 또 조용히 지나간다: 포트만 맞으면 단위 테스트는 전부 통과한다.
 */
describe("HttpsFrontServer — upstream이 루프백 밖 주소에 있을 때", () => {
  /** 비루프백 IPv4가 없는 환경(CI 컨테이너 등)에서는 이 시나리오를 만들 수 없다. */
  const nonLoopback = Object.values(networkInterfaces())
    .flat()
    .find((i) => i && i.family === "IPv4" && !i.internal)?.address;

  function upstreamOn(host: string, label: string): Promise<{ port: number; close: () => Promise<void> }> {
    return new Promise((resolve, reject) => {
      const srv = createServer((_req: IncomingMessage, res: ServerResponse) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end(label);
      });
      srv.once("error", reject);
      srv.listen(0, host, () => {
        const addr = srv.address();
        const port = typeof addr === "object" && addr !== null ? addr.port : 0;
        resolve({ port, close: () => new Promise((r) => srv.close(() => r())) });
      });
    });
  }

  test.skipIf(!nonLoopback)("route.host를 주면 그 주소로 연결한다 (autoconfig/MTA-STS 경로)", async () => {
    const host = nonLoopback as string;
    const up = await upstreamOn(host, "autoconfig-ok");
    const cert = generateSelfSigned({ commonName: "mta-sts.test.local", sans: ["mta-sts.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [{ hosts: ["mta-sts.test.local", "autoconfig.test.local"], port: up.port, host, exposure: "public" }],
    });
    const fp = await front.listen(0, "127.0.0.1");
    try {
      const r = await httpsReq(fp, "mta-sts.test.local");
      expect(r.status).toBe(200);
      expect(r.body).toBe("autoconfig-ok");
    } finally {
      await front.close();
      await up.close();
    }
  });

  test.skipIf(!nonLoopback)("route.host가 없으면 127.0.0.1로 가서 502 — 이것이 라이브 증상이었다", async () => {
    const host = nonLoopback as string;
    const up = await upstreamOn(host, "unreachable-from-loopback");
    const cert = generateSelfSigned({ commonName: "mta-sts.test.local", sans: ["mta-sts.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      // host를 주지 않는다 = 예전 동작. upstream은 비루프백에만 있으므로 루프백 연결은 실패한다.
      routes: [{ hosts: ["mta-sts.test.local"], port: up.port, exposure: "public" }],
    });
    const fp = await front.listen(0, "127.0.0.1");
    try {
      const r = await httpsReq(fp, "mta-sts.test.local");
      expect(r.status).toBe(502);
    } finally {
      await front.close();
      await up.close();
    }
  });

  test.skipIf(!nonLoopback)("defaultHost도 같은 규칙을 따른다 (JMAP·관리 콘솔 경로)", async () => {
    const host = nonLoopback as string;
    const up = await upstreamOn(host, "jmap-ok");
    const cert = generateSelfSigned({ commonName: "any.test.local", sans: ["any.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [{ hosts: ["any.test.local"], port: up.port, host, exposure: "public" }],
    });
    const fp = await front.listen(0, "127.0.0.1");
    try {
      const r = await httpsReq(fp, "any.test.local");
      expect(r.status).toBe(200);
      expect(r.body).toBe("jmap-ok");
    } finally {
      await front.close();
      await up.close();
    }
  });
});

/**
 * vhost 노출 정책 — 이름마다 "공개 인터페이스로 들어온 연결도 받을지"를 가른다.
 *
 * 판정 입력은 소켓의 **로컬** 주소(연결이 착지한 우리 쪽 인터페이스)다. 테스트 기기의 주소는
 * 전부 사설이라 기본 판정으로는 "공개 인터페이스"를 만들 수 없어서, `isInternalAddress`를
 * 주입해 루프백을 **공개로 취급**시킨다. 그래야 거부 경로가 실제로 구동된다.
 */
describe("HttpsFrontServer — vhost 노출 정책(exposure)", () => {
  /** 요청 횟수를 세는 upstream — "404를 냈다"와 "upstream에 닿지 않았다"는 다른 사실이다. */
  function countingUpstream(label: string): Promise<{ port: number; hits: () => number; close: () => Promise<void> }> {
    let hits = 0;
    return new Promise((resolve) => {
      const srv = createServer((_req, res) => {
        hits += 1;
        res.writeHead(200, { "content-type": "text/plain" });
        res.end(label);
      });
      srv.listen(0, "127.0.0.1", () => {
        const addr = srv.address();
        const port = typeof addr === "object" && addr !== null ? addr.port : 0;
        resolve({ port, hits: () => hits, close: () => new Promise((r) => srv.close(() => r())) });
      });
    });
  }

  /** 루프백을 "공개"로 취급한다 — 내부는 10/8뿐이라고 보는 판정. */
  const treatLoopbackAsPublic = (addr: string | undefined): boolean => (addr ?? "").includes("10.");

  test("★내부 전용 vhost는 공개 인터페이스로 오면 404 — upstream에 닿지도 않는다", async () => {
    const admin = await countingUpstream("admin");
    const jm = await countingUpstream("jmap");
    const cert = generateSelfSigned({ commonName: "x.test.local", sans: ["x.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [
        { hosts: ["admin.test.local"], port: admin.port, exposure: "internal" },
        { hosts: ["other.test.local"], port: jm.port, exposure: "public" },
      ],
      isInternalAddress: treatLoopbackAsPublic,
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      const r = await httpsReq(port, "admin.test.local");
      expect(r.status).toBe(404);
      // 거부가 프록시 **앞에서** 일어나야 한다. upstream이 한 번이라도 불리면 그건 통과한 것이다.
      expect(admin.hits()).toBe(0);
      // 공개 vhost는 영향을 받지 않는다.
      expect((await httpsReq(port, "other.test.local")).status).toBe(200);
    } finally {
      await front.close();
      await admin.close();
      await jm.close();
    }
  });

  test("내부 인터페이스로 들어오면 같은 vhost가 통과한다", async () => {
    const admin = await countingUpstream("admin");
    const cert = generateSelfSigned({ commonName: "x.test.local", sans: ["x.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [{ hosts: ["admin.test.local"], port: admin.port, exposure: "internal" }],
      // 판정을 주입하지 않는다 = 기본(사설·루프백 = 내부). 127.0.0.1은 내부다.
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      const r = await httpsReq(port, "admin.test.local");
      expect(r.status).toBe(200);
      expect(r.body).toBe("admin");
      expect(admin.hits()).toBe(1);
    } finally {
      await front.close();
      await admin.close();
    }
  });

  test("★MTA-STS·autoconfig는 공개 인터페이스에서도 살아 있어야 한다 — 막히면 수신이 죽는다", async () => {
    const ac = await countingUpstream("autoconfig");
    const cert = generateSelfSigned({ commonName: "x.test.local", sans: ["x.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [
        { hosts: ["mta-sts.test.local", "autoconfig.test.local", "autodiscover.test.local"], port: ac.port, exposure: "public" },
      ],
      isInternalAddress: treatLoopbackAsPublic, // 전부 공개 인터페이스로 들어온 셈
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      // MTA-STS 정책은 발신 MTA가 인터넷에서 가져간다. enforce 상태에서 이게 404면
      // 상대가 정책을 확인하지 못해 **인바운드가 전부 거부**된다.
      for (const name of ["mta-sts.test.local", "autoconfig.test.local", "autodiscover.test.local"]) {
        const r = await httpsReq(port, name);
        expect(r.status).toBe(200);
        expect(r.body).toBe("autoconfig");
      }
    } finally {
      await front.close();
      await ac.close();
    }
  });

  test("★화이트리스트에 없는 이름은 404 — 기본 upstream으로 흘리지 않는다", async () => {
    const jm = await countingUpstream("jmap");
    const cert = generateSelfSigned({ commonName: "x.test.local", sans: ["x.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      // 라우트는 있는데 요청 이름이 그 목록에 없다.
      routes: [{ hosts: ["known.test.local"], port: jm.port, exposure: "public" }],
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      expect((await httpsReq(port, "any.test.local")).status).toBe(404);
      expect(jm.hits()).toBe(0);
    } finally {
      await front.close();
      await jm.close();
    }
  });
});

/**
 * Host 화이트리스트 — "우리가 서빙하기로 한 이름"만 존재한다.
 *
 * ★예전에는 접두사 매칭 + 기본 upstream이라 **아무 Host나 붙여도 JMAP이 응답했다.**
 * 그래서 우리가 서빙하는 이름 목록이 코드 어디에도 없었다. 여기서 그걸 못박는다.
 */
describe("HttpsFrontServer — Host 화이트리스트", () => {
  test("★목록에 없는 이름은 전부 404 — 기본 upstream으로 흘리지 않는다", async () => {
    const jm = await upstream("jmap");
    const cert = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [{ hosts: ["mx.test.local"], port: jm.port, exposure: "public" }],
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      expect((await httpsReq(port, "mx.test.local")).status).toBe(200);
      for (const other of ["evil.example", "test.local", "mx.test.local.evil.example", ""]) {
        expect((await httpsReq(port, other)).status).toBe(404);
      }
    } finally {
      await front.close();
      await jm.close();
    }
  });

  test("★접두사가 아니라 완전 일치 — 남의 도메인이 우리 라우트에 걸리면 안 된다", async () => {
    const ad = await upstream("admin");
    const cert = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [{ hosts: ["admin.test.local"], port: ad.port, exposure: "public" }],
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      expect((await httpsReq(port, "admin.test.local")).status).toBe(200);
      // 접두사 매칭이던 시절에는 이 이름이 admin upstream으로 향했다.
      expect((await httpsReq(port, "admin.evil.example")).status).toBe(404);
      expect((await httpsReq(port, "admin.test.local.evil.example")).status).toBe(404);
    } finally {
      await front.close();
      await ad.close();
    }
  });

  test("포트가 붙은 Host도 같은 이름으로 본다", async () => {
    const jm = await upstream("jmap");
    const cert = generateSelfSigned({ commonName: "mx.test.local", sans: ["mx.test.local"] });
    const front = new HttpsFrontServer({
      tls: { key: cert.keyPem, cert: cert.certPem },
      routes: [{ hosts: ["mx.test.local"], port: jm.port, exposure: "public" }],
    });
    const port = await front.listen(0, "127.0.0.1");
    try {
      expect((await httpsReq(port, "mx.test.local:443")).status).toBe(200);
      expect((await httpsReq(port, "MX.TEST.LOCAL")).status).toBe(200); // 대소문자 무관
    } finally {
      await front.close();
      await jm.close();
    }
  });
});
