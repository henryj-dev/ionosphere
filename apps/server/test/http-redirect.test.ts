/**
 * 80 → 443 리다이렉트 종단.
 *
 * 여기서 고정하는 계약:
 *  ① 443이 서빙하는 이름으로 80에 오면 같은 이름의 https로 **308**(메서드·본문 보존)
 *  ② 경로와 쿼리를 보존하고, Location에 포트를 남기지 않는다
 *  ③ ★내부 전용 이름은 공개 인터페이스에서 **리다이렉트조차 하지 않는다** — 302를 주면
 *    그 응답 자체가 "이 이름이 여기 있다"를 흘린다(443이 404로 감추는 것과 앞뒤가 맞아야 한다)
 *  ④ Host가 문법에 안 맞으면 리다이렉트하지 않는다(헤더 주입·엉뚱한 대상 방지)
 *  ⑤ **프록시하지 않는다** — 평문 경로가 동작하면 클라이언트가 계속 그 길을 쓴다
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { request } from "node:http";
import { connect } from "node:net";
import { HttpRedirectServer } from "../src/http-redirect.ts";
import type { HttpsFrontRoute } from "../src/https-front.ts";

interface Res {
  status: number;
  location: string | undefined;
  body: string;
}

/** `Host`를 직접 실어 보낸다 — 리다이렉트 판정의 입력이 그 헤더다. */
function get(port: number, host: string, path = "/", method = "GET"): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method, headers: { host } }, (r) => {
      let body = "";
      r.on("data", (c) => (body += c));
      r.on("end", () =>
        resolve({ status: r.statusCode ?? 0, location: r.headers.location, body: body.slice(0, 200) }),
      );
    });
    req.on("error", reject);
    req.end();
  });
}

const ROUTES: HttpsFrontRoute[] = [
  { hosts: ["mta-sts.ionosphere.test", "autoconfig.ionosphere.test"], port: 1, exposure: "public" },
  { hosts: ["admin.ionosphere.test"], port: 2, exposure: "internal" },
];

/** 루프백을 "공개"로 취급 — 테스트 기기 주소가 전부 사설이라 거부 경로를 이렇게만 구동할 수 있다. */
const treatLoopbackAsPublic = (addr: string | undefined): boolean => (addr ?? "").includes("10.");

async function withServer(
  opts: Partial<ConstructorParameters<typeof HttpRedirectServer>[0]>,
  fn: (port: number) => Promise<void>,
): Promise<void> {
  const srv = new HttpRedirectServer({ routes: ROUTES, ...opts });
  const port = await srv.listen(0, "127.0.0.1");
  try {
    await fn(port);
  } finally {
    await srv.close();
  }
}

describe("HttpRedirectServer — 80 → 443", () => {
  test("공개 이름은 308로 https에 보낸다 — 경로·쿼리 보존", async () => {
    await withServer({}, async (port) => {
      const r = await get(port, "mta-sts.ionosphere.test", "/.well-known/mta-sts.txt?x=1");
      expect(r.status).toBe(308);
      expect(r.location).toBe("https://mta-sts.ionosphere.test/.well-known/mta-sts.txt?x=1");
    });
  });

  test("Location에 포트를 남기지 않는다 — `Host: name:80`으로 와도", async () => {
    await withServer({}, async (port) => {
      const r = await get(port, "autoconfig.ionosphere.test:80", "/mail/config-v1.1.xml");
      expect(r.location).toBe("https://autoconfig.ionosphere.test/mail/config-v1.1.xml");
    });
  });

  test("★308이라 메서드가 GET으로 바뀌지 않는다 (301의 함정)", async () => {
    await withServer({}, async (port) => {
      const r = await get(port, "mta-sts.ionosphere.test", "/x", "POST");
      // 308은 클라이언트가 **같은 메서드로** 다시 시도하게 한다. 301이면 POST가 GET이 되어
      // 호출자가 "왜 본문이 사라졌지"를 추적하게 된다.
      expect(r.status).toBe(308);
      expect(r.location).toBe("https://mta-sts.ionosphere.test/x");
    });
  });

  test("★내부 전용 이름은 공개 인터페이스에서 리다이렉트조차 하지 않는다 — 404", async () => {
    await withServer({ isInternalAddress: treatLoopbackAsPublic }, async (port) => {
      const r = await get(port, "admin.ionosphere.test", "/");
      expect(r.status).toBe(404);
      // 302/308을 주면 그 응답 자체가 이름의 존재를 알려준다. Location이 있으면 실패다.
      expect(r.location).toBeUndefined();
      // 공개 이름은 같은 인터페이스에서도 정상 리다이렉트되어야 한다(무차별 차단이 아니다).
      expect((await get(port, "mta-sts.ionosphere.test", "/")).status).toBe(308);
    });
  });

  test("내부 인터페이스로 오면 같은 이름이 308이다", async () => {
    // 판정을 주입하지 않는다 = 기본(루프백·사설 = 내부).
    await withServer({}, async (port) => {
      const r = await get(port, "admin.ionosphere.test", "/v1/tls");
      expect(r.status).toBe(308);
      expect(r.location).toBe("https://admin.ionosphere.test/v1/tls");
    });
  });

  test("Host 문법이 깨지면 리다이렉트하지 않는다 (헤더 주입·엉뚱한 대상 방지)", async () => {
    await withServer({}, async (port) => {
      for (const bad of ["-bad.example", "under_score.example", "..x", "x..y"]) {
        const r = await get(port, bad, "/");
        expect(r.status).toBe(400);
        expect(r.location).toBeUndefined();
      }
    });
  });

  test("★Host가 아예 없으면 400 — 리다이렉트할 이름이 없다", async () => {
    // node의 http 클라이언트는 Host를 자동으로 채워 넣어서 이 경우를 만들 수 없다.
    // 원시 소켓으로 보낸다 — HTTP/1.0 클라이언트·스캐너가 실제로 이렇게 온다.
    await withServer({}, async (port) => {
      const raw = await new Promise<string>((resolve, reject) => {
        const sock = connect({ host: "127.0.0.1", port }, () => {
          sock.write("GET / HTTP/1.0\r\n\r\n");
        });
        let buf = "";
        sock.on("data", (d) => (buf += d));
        sock.on("end", () => resolve(buf));
        sock.on("error", reject);
      });
      expect(raw).toContain("400");
      expect(raw.toLowerCase()).not.toContain("location:");
    });
  });

  test("★화이트리스트에 없는 이름은 404 — 리다이렉트하지 않는다", async () => {
    await withServer({}, async (port) => {
      for (const unknown of ["evil.example", "ionosphere.test", "mta-sts.evil.example", "admin.evil.example"]) {
        const r = await get(port, unknown, "/");
        expect(r.status).toBe(404);
        expect(r.location).toBeUndefined();
      }
    });
  });

  test("★접두사가 아니라 완전 일치다 — `admin.evil.example`이 admin 라우트에 걸리면 안 된다", async () => {
    await withServer({}, async (port) => {
      // 접두사 매칭이던 시절에는 이 이름이 admin upstream으로 향했다.
      expect((await get(port, "admin.evil.example", "/")).status).toBe(404);
      expect((await get(port, "admin.ionosphere.test", "/")).status).toBe(308);
    });
  });

  test("★프록시하지 않는다 — 본문을 보내도 응답은 리다이렉트뿐이다", async () => {
    await withServer({}, async (port) => {
      const r = await get(port, "mta-sts.ionosphere.test", "/", "POST");
      // upstream 응답이 아니라 빈 본문의 308이어야 한다. 평문 경로가 동작하면
      // 클라이언트는 계속 그 길을 쓰고, 리다이렉트를 넣은 의미가 사라진다.
      expect(r.status).toBe(308);
      expect(r.body).toBe("");
    });
  });
});
