/**
 * SCRAM 서버 세션 — 이 파일이 지키는 것은 교환 절차보다 **계정 열거 방어**다.
 *
 * 존재하지 않는 사용자에게 즉시 실패를 돌려주면, 응답 시점·형태만으로 "그 계정이 없다"가
 * 새어 나간다. 인증 실패는 **한 가지 답**이어야 한다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { deriveScramKeys, ScramServerSession, type ScramStoredKeys } from "../src/index.ts";

const DECOY = randomBytes(32);

/** 클라이언트 쪽 계산 — 실제 클라이언트가 하는 것과 같다. */
function clientProof(password: string, keys: { salt: Buffer; iterations: number }, authMessage: string): string {
  const salted = pbkdf2Sync(password, keys.salt, keys.iterations, 32, "sha256");
  const clientKey = createHmac("sha256", salted).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const sig = createHmac("sha256", storedKey).update(authMessage).digest();
  const proof = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) proof[i] = clientKey[i]! ^ sig[i]!;
  return proof.toString("base64");
}

/** 한 번의 완전한 교환을 돌린다. `keys`가 null이면 "계정 없음" 상황. */
function exchange(password: string, keys: ScramStoredKeys | null, username = "user"): { ok: boolean; serverFirst: string } {
  const s = new ScramServerSession(DECOY);
  const clientNonce = "cnonce0001";
  const first = s.start(`n,,n=${username},r=${clientNonce}`);
  expect(first.need).toBe("lookup");

  const second = s.provideKeys(keys);
  if (second.need !== "send") throw new Error("expected send");
  const serverFirst = second.message;

  const fullNonce = /r=([^,]+)/.exec(serverFirst)?.[1] ?? "";
  const salt = Buffer.from(/s=([^,]+)/.exec(serverFirst)?.[1] ?? "", "base64");
  const iterations = Number(/i=(\d+)/.exec(serverFirst)?.[1] ?? "0");

  const withoutProof = `c=${Buffer.from("n,,").toString("base64")},r=${fullNonce}`;
  const authMessage = `n=${username},r=${clientNonce},${serverFirst},${withoutProof}`;
  const p = clientProof(password, { salt, iterations }, authMessage);
  const final = s.final(`${withoutProof},p=${p}`);
  return { ok: final.need === "done", serverFirst };
}

describe("ScramServerSession", () => {
  test("맞는 비밀번호면 성공하고 server-final을 준다", async () => {
    const k = await deriveScramKeys("pencil", { iterations: 4096 });
    const s = new ScramServerSession(DECOY);
    s.start("n,,n=user,r=abc123");
    const sent = s.provideKeys(k);
    if (sent.need !== "send") throw new Error("expected send");
    const fullNonce = /r=([^,]+)/.exec(sent.message)?.[1] ?? "";
    const withoutProof = `c=biws,r=${fullNonce}`;
    const authMessage = `n=user,r=abc123,${sent.message},${withoutProof}`;
    const p = clientProof("pencil", { salt: k.salt, iterations: k.iterations }, authMessage);
    const done = s.final(`${withoutProof},p=${p}`);
    expect(done.need).toBe("done");
    if (done.need !== "done") throw new Error("unreachable");
    expect(done.username).toBe("user");
    expect(done.message.startsWith("v=")).toBe(true);
  });

  test("틀린 비밀번호는 실패한다", async () => {
    const k = await deriveScramKeys("pencil", { iterations: 4096 });
    expect(exchange("wrong", k).ok).toBe(false);
  });

  test("★계정이 없어도 교환이 끝까지 진행된다 — 실패는 proof 단계에서만 드러난다", () => {
    // 즉시 실패를 돌려주면 "그 계정이 없다"가 응답 형태로 샌다.
    const r = exchange("anything", null);
    expect(r.ok).toBe(false);
    // server-first가 정상 형태여야 한다 — 있는 계정과 구분되면 안 된다.
    expect(r.serverFirst).toMatch(/^r=.+,s=.+,i=\d+$/);
  });

  test("★없는 계정의 salt는 매번 같다 — 재시도만으로 가짜임이 드러나면 안 된다", () => {
    const a = exchange("x", null, "ghost@x.test").serverFirst;
    const b = exchange("x", null, "ghost@x.test").serverFirst;
    const saltOf = (m: string): string => /s=([^,]+)/.exec(m)?.[1] ?? "";
    expect(saltOf(a)).toBe(saltOf(b));
    expect(saltOf(a)).not.toBe("");
    // 사용자명이 다르면 salt도 달라야 한다(같으면 그것대로 신호가 된다).
    expect(saltOf(a)).not.toBe(saltOf(exchange("x", null, "other@x.test").serverFirst));
  });

  test("★nonce는 매 세션 달라진다 — 재전송 방지", () => {
    const nonceOf = (m: string): string => /r=([^,]+)/.exec(m)?.[1] ?? "";
    expect(nonceOf(exchange("x", null).serverFirst)).not.toBe(nonceOf(exchange("x", null).serverFirst));
  });

  test("단계를 건너뛰거나 되돌리면 실패한다 (상태머신 계약)", async () => {
    const k = await deriveScramKeys("pw", { iterations: 4096 });
    const s = new ScramServerSession(DECOY);
    // start 전에 키를 주면 실패
    expect(s.provideKeys(k).need).toBe("failed");

    const s2 = new ScramServerSession(DECOY);
    s2.start("n,,n=u,r=abc");
    // provideKeys 전에 final을 주면 실패
    expect(s2.final("c=biws,r=abc,p=AAAA").need).toBe("failed");

    const s3 = new ScramServerSession(DECOY);
    s3.start("n,,n=u,r=abc");
    s3.provideKeys(k);
    s3.final("c=biws,r=nope,p=AAAA");
    // 닫힌 세션은 다시 못 쓴다
    expect(s3.final("c=biws,r=abc,p=AAAA").need).toBe("failed");
  });

  test("깨진 client-first는 lookup 단계에 가지도 않는다", () => {
    const s = new ScramServerSession(DECOY);
    expect(s.start("garbage").need).toBe("failed");
  });
});
