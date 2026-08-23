/**
 * SCRAM-SHA-256 — **RFC 7677 §5의 공식 테스트 벡터**로 검증한다.
 *
 * ★자기가 만든 값으로 자기 구현을 확인하면 "일관되게 틀린" 것을 잡지 못한다.
 * 규격 문서의 벡터는 다른 구현들이 상호운용에 실제로 쓰는 값이라, 이걸 통과하면
 * 최소한 우리끼리만 맞는 상태는 아니다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import {
  buildServerFirst,
  deriveScramKeys,
  parseClientFirst,
  verifyClientFinal,
} from "../src/scram.ts";

/** RFC 7677 §5 — username=user, password=pencil. */
const V = {
  clientFirst: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
  clientFirstBare: "n=user,r=rOprNGfwEbeRWgbNEkqO",
  gs2Header: "n,,",
  serverNonceSuffix: "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
  fullNonce: "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
  saltB64: "W22ZaJ0SNY7soEsUEjb6gQ==",
  iterations: 4096,
  serverFirst: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
  clientFinal:
    "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
  serverFinal: "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
} as const;

async function vectorKeys(): Promise<{ storedKey: Buffer; serverKey: Buffer }> {
  const k = await deriveScramKeys("pencil", {
    salt: Buffer.from(V.saltB64, "base64"),
    iterations: V.iterations,
  });
  return { storedKey: k.storedKey, serverKey: k.serverKey };
}

describe("SCRAM-SHA-256 — RFC 7677 §5 벡터", () => {
  test("client-first 파싱", () => {
    const cf = parseClientFirst(V.clientFirst);
    expect(cf).not.toBeNull();
    expect(cf!.username).toBe("user");
    expect(cf!.clientNonce).toBe("rOprNGfwEbeRWgbNEkqO");
    expect(cf!.gs2Header).toBe(V.gs2Header);
    // AuthMessage 계산에 원문 그대로가 필요하다 — 재조립하면 미묘하게 달라진다.
    expect(cf!.bare).toBe(V.clientFirstBare);
  });

  test("server-first가 벡터와 바이트까지 일치한다", () => {
    const msg = buildServerFirst({
      clientNonce: "rOprNGfwEbeRWgbNEkqO",
      serverNonce: V.serverNonceSuffix,
      salt: Buffer.from(V.saltB64, "base64"),
      iterations: V.iterations,
    });
    expect(msg).toBe(V.serverFirst);
  });

  test("★client-final 증명이 통과하고 server-final이 벡터와 같다", async () => {
    const { storedKey, serverKey } = await vectorKeys();
    const r = verifyClientFinal({
      clientFirstBare: V.clientFirstBare,
      serverFirst: V.serverFirst,
      clientFinal: V.clientFinal,
      expectedNonce: V.fullNonce,
      gs2Header: V.gs2Header,
      storedKey,
      serverKey,
    });
    expect(r.ok).toBe(true);
    expect(r.serverFinal).toBe(V.serverFinal);
  });
});

describe("SCRAM-SHA-256 — 거절해야 하는 것", () => {
  test("★틀린 비밀번호의 증명은 통과하지 못한다", async () => {
    const wrong = await deriveScramKeys("notpencil", {
      salt: Buffer.from(V.saltB64, "base64"),
      iterations: V.iterations,
    });
    const r = verifyClientFinal({
      clientFirstBare: V.clientFirstBare,
      serverFirst: V.serverFirst,
      clientFinal: V.clientFinal,
      expectedNonce: V.fullNonce,
      gs2Header: V.gs2Header,
      storedKey: wrong.storedKey,
      serverKey: wrong.serverKey,
    });
    expect(r.ok).toBe(false);
    expect(r.serverFinal).toBeUndefined();
  });

  test("★nonce가 다르면 거절 — 재전송 공격 방지", async () => {
    const { storedKey, serverKey } = await vectorKeys();
    const r = verifyClientFinal({
      clientFirstBare: V.clientFirstBare,
      serverFirst: V.serverFirst,
      clientFinal: V.clientFinal,
      expectedNonce: `${V.fullNonce}x`, // 서버가 기대하는 nonce가 다름
      gs2Header: V.gs2Header,
      storedKey,
      serverKey,
    });
    expect(r.ok).toBe(false);
  });

  test("★`c=`가 gs2 헤더와 안 맞으면 거절 — 채널 바인딩 다운그레이드", async () => {
    const { storedKey, serverKey } = await vectorKeys();
    const tampered = V.clientFinal.replace("c=biws", "c=eSws"); // "y,," 로 위조
    const r = verifyClientFinal({
      clientFirstBare: V.clientFirstBare,
      serverFirst: V.serverFirst,
      clientFinal: tampered,
      expectedNonce: V.fullNonce,
      gs2Header: V.gs2Header,
      storedKey,
      serverKey,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("channel-binding-mismatch");
  });

  test("★채널 바인딩을 요구하는 클라이언트(p=)는 받지 않는다 — 없는 보안을 있다고 하지 않는다", () => {
    expect(parseClientFirst("p=tls-exporter,,n=user,r=abc")).toBeNull();
  });

  test("깨진 client-first는 null (조용히 통과시키지 않는다)", () => {
    for (const bad of ["", "n,,", "n,,r=onlynonce", "n,,n=user", "garbage", "n,,n=user,r=has,comma"]) {
      expect(parseClientFirst(bad)).toBeNull();
    }
  });

  test("사용자명 이스케이프(=2C·=3D)를 되돌린다", () => {
    expect(parseClientFirst("n,,n==2Cuser=3Dx,r=abc")?.username).toBe(",user=x");
    // 이스케이프 대상이 아닌 `=`는 잘못된 입력이다.
    expect(parseClientFirst("n,,n=us=er,r=abc")).toBeNull();
  });
});

describe("deriveScramKeys", () => {
  test("같은 salt·반복이면 결정적, 다른 salt면 달라진다", async () => {
    const salt = Buffer.alloc(16, 7);
    const a = await deriveScramKeys("pw", { salt, iterations: 4096 });
    const b = await deriveScramKeys("pw", { salt, iterations: 4096 });
    const c = await deriveScramKeys("pw", { salt: Buffer.alloc(16, 8), iterations: 4096 });
    expect(a.storedKey.equals(b.storedKey)).toBe(true);
    expect(a.storedKey.equals(c.storedKey)).toBe(false);
  });

  test("★StoredKey와 ServerKey는 서로 다르다 — 역할이 다르다", async () => {
    const k = await deriveScramKeys("pw", { salt: Buffer.alloc(16, 1), iterations: 4096 });
    // StoredKey는 클라이언트 검증용, ServerKey는 서버가 자기를 증명하는 용도다.
    // 같으면 서버 저장분만으로 클라이언트를 흉내 낼 수 있게 된다.
    expect(k.storedKey.equals(k.serverKey)).toBe(false);
  });
});
