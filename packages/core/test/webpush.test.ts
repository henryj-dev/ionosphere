/**
 * Web Push 암호화 (RFC 8291 `aes128gcm`).
 *
 * ★암호화는 **복호화로만** 검증할 수 있다. "예외가 안 났다"는 아무 보증도 아니다 —
 * 키 유도의 `info` 문자열 하나만 틀려도 함수는 조용히 성공하고, 상대가 복호화하지 못하는
 * 형태로만 드러난다. 그래서 이 파일은 구독자 쪽 복호화를 직접 구현해 왕복을 돈다.
 */
import { createDecipheriv, createECDH, createHmac } from "node:crypto";
import { describe, expect, test } from "@ionosphere/testkit";
import { encryptWebPush } from "../src/webpush.ts";

const b64url = (b: Buffer): string => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** 구독자 한 명 — P-256 키쌍 + 16바이트 auth 비밀. */
function subscriber(): { keys: { p256dh: string; auth: string }; privateKey: Buffer; authSecret: Buffer } {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const authSecret = Buffer.alloc(16, 7);
  return {
    keys: { p256dh: b64url(ecdh.getPublicKey()), auth: b64url(authSecret) },
    privateKey: ecdh.getPrivateKey(),
    authSecret,
  };
}

function hkdf(salt: Buffer, ikm: Buffer, info: Buffer, length: number): Buffer {
  const prk = createHmac("sha256", salt).update(ikm).digest();
  return createHmac("sha256", prk).update(Buffer.concat([info, Buffer.from([1])])).digest().subarray(0, length);
}

/**
 * 구독자 쪽 복호화 — RFC 8188 헤더를 풀고 RFC 8291 키 유도를 거꾸로 밟는다.
 *
 * 우리 구현과 **같은 파일을 공유하지 않는다.** 공유하면 양쪽이 같이 틀려도 통과한다 —
 * 규격을 보고 독립적으로 쓴 것이라야 검증이 된다.
 */
function decrypt(body: Buffer, sub: ReturnType<typeof subscriber>): Buffer {
  const salt = body.subarray(0, 16);
  const idLen = body.readUInt8(20);
  const serverPublic = body.subarray(21, 21 + idLen);
  const ciphertext = body.subarray(21 + idLen);

  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(sub.privateKey);
  const shared = ecdh.computeSecret(serverPublic);

  const clientPublic = ecdh.getPublicKey();
  const keyInfo = Buffer.concat([Buffer.from("WebPush: info\u0000", "utf8"), clientPublic, serverPublic]);
  const ikm = hkdf(sub.authSecret, shared, keyInfo, 32);
  const cek = hkdf(salt, ikm, Buffer.from("Content-Encoding: aes128gcm\u0000", "utf8"), 16);
  const nonce = hkdf(salt, ikm, Buffer.from("Content-Encoding: nonce\u0000", "utf8"), 12);

  const tag = ciphertext.subarray(ciphertext.length - 16);
  const d = createDecipheriv("aes-128-gcm", cek, nonce);
  d.setAuthTag(tag);
  const plain = Buffer.concat([d.update(ciphertext.subarray(0, ciphertext.length - 16)), d.final()]);
  // 마지막 바이트는 레코드 구분자(0x02)다.
  expect(plain[plain.length - 1]).toBe(0x02);
  return plain.subarray(0, plain.length - 1);
}

describe("encryptWebPush 왕복", () => {
  test("구독자가 원문을 복원한다", () => {
    const sub = subscriber();
    const payload = Buffer.from(JSON.stringify({ "@type": "StateChange", changed: { acc: { Email: "5" } } }), "utf8");
    const { body } = encryptWebPush(payload, sub.keys);
    expect(decrypt(body, sub).toString("utf8")).toBe(payload.toString("utf8"));
  });

  test("빈 페이로드도 왕복한다", () => {
    const sub = subscriber();
    const { body } = encryptWebPush(Buffer.alloc(0), sub.keys);
    expect(decrypt(body, sub).length).toBe(0);
  });

  test("유니코드도 왕복한다", () => {
    const sub = subscriber();
    const payload = Buffer.from("한글과 이모지 🚀", "utf8");
    expect(decrypt(encryptWebPush(payload, sub.keys).body, sub).toString("utf8")).toBe("한글과 이모지 🚀");
  });

  /** ★같은 입력이라도 salt가 매번 달라야 한다 — 같은 salt로 두 번 쓰면 GCM 전제가 깨진다. */
  test("매번 다른 salt·키를 쓴다", () => {
    const sub = subscriber();
    const payload = Buffer.from("same", "utf8");
    const a = encryptWebPush(payload, sub.keys).body;
    const b = encryptWebPush(payload, sub.keys).body;
    expect(a.equals(b)).toBe(false);
    expect(a.subarray(0, 16).equals(b.subarray(0, 16))).toBe(false); // salt
    // 그래도 둘 다 복호화된다
    expect(decrypt(a, sub).toString("utf8")).toBe("same");
    expect(decrypt(b, sub).toString("utf8")).toBe("same");
  });

  test("헤더 형식 (RFC 8188 §2.1)", () => {
    const sub = subscriber();
    const { body } = encryptWebPush(Buffer.from("x"), sub.keys);
    expect(body.readUInt32BE(16)).toBe(4096); // rs
    expect(body.readUInt8(20)).toBe(65); // keyid 길이 = uncompressed P-256
    expect(body[21]).toBe(0x04); // 서버 공개키가 uncompressed 표기
  });

  /** 다른 구독자의 키로는 풀 수 없다 — 당연하지만 키 유도가 실제로 섞였다는 증거다. */
  test("남의 키로는 복호화되지 않는다", () => {
    const a = subscriber();
    const b = subscriber();
    const { body } = encryptWebPush(Buffer.from("secret"), a.keys);
    let threw = false;
    try {
      decrypt(body, b);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});

describe("입력 검증", () => {
  test("공개키 형식이 틀리면 거절", () => {
    expect(() => encryptWebPush(Buffer.from("x"), { p256dh: b64url(Buffer.alloc(64)), auth: b64url(Buffer.alloc(16)) })).toThrow();
    // 압축 표기(0x02/0x03)는 받지 않는다
    const bad = Buffer.alloc(65);
    bad[0] = 0x02;
    expect(() => encryptWebPush(Buffer.from("x"), { p256dh: b64url(bad), auth: b64url(Buffer.alloc(16)) })).toThrow();
  });

  test("auth 비밀 길이가 틀리면 거절", () => {
    const sub = subscriber();
    expect(() => encryptWebPush(Buffer.from("x"), { p256dh: sub.keys.p256dh, auth: b64url(Buffer.alloc(8)) })).toThrow();
  });

  /** ★조용히 자르지 않는다 — 잘린 JSON은 상대가 파싱에 실패하고 원인을 알 수 없다. */
  test("레코드 크기를 넘으면 거절", () => {
    const sub = subscriber();
    expect(() => encryptWebPush(Buffer.alloc(5000), sub.keys)).toThrow();
  });
});
