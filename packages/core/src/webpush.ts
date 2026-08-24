/**
 * Web Push 메시지 암호화 (RFC 8291 `aes128gcm`) — JMAP `PushSubscription`(RFC 8620 §7.2)용.
 *
 * ## 왜 암호화가 **선택이 아닌가**
 *
 * 푸시는 사용자가 지정한 제3자 엔드포인트를 거쳐 간다(브라우저 푸시 서비스 등). 그 중계자는
 * 우리와 사용자 사이에 있는 남이다. `StateChange`는 본문을 담지 않지만 **계정 id와 어떤
 * 타입이 언제 바뀌었는지**를 담는다 — 그것만으로 "이 사람이 언제 메일을 받았는지"의 시계열이
 * 만들어진다. RFC 8620 §7.2.1이 `keys`가 있으면 암호화하라고 정한 이유다.
 *
 * ## 왜 직접 구현하나
 *
 * 의존성이 `node:` 빌트인뿐이라는 규약 때문이다. `node:crypto`에 ECDH·HKDF·AES-GCM이 다
 * 있어서 조립만 하면 된다 — 원시 암호를 새로 만드는 것이 아니라 RFC가 정한 **순서대로
 * 엮는** 일이다.
 *
 * ## 한 번에 한 레코드만 만든다
 *
 * RFC 8188의 `aes128gcm`은 여러 레코드로 나눌 수 있지만, `StateChange`는 항상 작다(수백
 * 바이트). 레코드 분할을 구현하면 쓰이지 않는 갈래가 생기고, 쓰이지 않는 갈래는 틀려도
 * 아무도 모른다. 그래서 본문이 레코드 크기를 넘으면 **오류로 거절한다**.
 */
import { createCipheriv, createECDH, createHmac, randomBytes } from "node:crypto";

/** 구독자가 준 공개키 쌍 (RFC 8291 §2 / RFC 8030). */
export interface WebPushKeys {
  /** 구독자의 P-256 공개키(uncompressed, base64url). */
  p256dh: string;
  /** 구독자의 인증 비밀 16바이트(base64url). */
  auth: string;
}

/**
 * 레코드 크기 — 헤더의 `rs`. 4096이면 본문 최대 4096-16(태그)-1(패딩 구분자) = 4079바이트다.
 * `StateChange`는 수백 바이트라 여유가 크다.
 */
const RECORD_SIZE = 4096;
/** GCM 인증 태그 길이. */
const TAG_BYTES = 16;

function b64urlToBuf(raw: string): Buffer {
  return Buffer.from(raw.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/**
 * HKDF (RFC 5869) — `node:crypto`의 `hkdfSync`를 쓰지 않고 직접 엮는다.
 *
 * ★`hkdfSync`는 Node 버전에 따라 반환형이 `ArrayBuffer`와 `Buffer`로 갈렸다. 두 줄짜리
 * HMAC 조합이라 여기서 만드는 편이 버전 차이를 신경 쓰지 않아도 된다.
 */
function hkdf(salt: Buffer, ikm: Buffer, info: Buffer, length: number): Buffer {
  const prk = createHmac("sha256", salt).update(ikm).digest();
  // length가 32 이하인 용도만 쓰므로 한 블록이면 충분하다(T(1)).
  const t = createHmac("sha256", prk).update(Buffer.concat([info, Buffer.from([1])])).digest();
  return t.subarray(0, length);
}

export interface EncryptResult {
  /** `Content-Encoding: aes128gcm` 본문 전체(헤더 포함). */
  body: Buffer;
}

/**
 * 페이로드를 `aes128gcm`으로 암호화한다.
 *
 * ★`salt`·`serverKey`를 주입받을 수 있게 한 이유는 **테스트 결정성**뿐이다. 운영에서는
 * 반드시 생략해 매번 새 난수를 쓴다 — 같은 salt로 두 번 암호화하면 GCM의 전제가 깨진다.
 */
export function encryptWebPush(
  payload: Uint8Array,
  keys: WebPushKeys,
  test?: { salt?: Buffer; serverPrivateKey?: Buffer },
): EncryptResult {
  const clientPublic = b64urlToBuf(keys.p256dh);
  const authSecret = b64urlToBuf(keys.auth);
  if (clientPublic.length !== 65 || clientPublic[0] !== 0x04) {
    throw new Error("p256dh must be a 65-byte uncompressed P-256 point");
  }
  if (authSecret.length !== 16) throw new Error("auth must be 16 bytes");

  const maxPlaintext = RECORD_SIZE - TAG_BYTES - 1;
  if (payload.length > maxPlaintext) {
    // 레코드 분할을 구현하지 않는다(위 머리 주석) — 조용히 자르는 것보다 거절이 낫다.
    throw new Error(`push payload too large (${payload.length} > ${maxPlaintext})`);
  }

  const ecdh = createECDH("prime256v1");
  if (test?.serverPrivateKey) ecdh.setPrivateKey(test.serverPrivateKey);
  else ecdh.generateKeys();
  const serverPublic = ecdh.getPublicKey();
  const sharedSecret = ecdh.computeSecret(clientPublic);
  const salt = test?.salt ?? randomBytes(16);

  /**
   * RFC 8291 §3.4 — 두 단계 HKDF다.
   *
   * ★`info` 문자열은 **NUL로 끝난다**(`\u0000`). 공백으로 잘못 적으면 다른 키가 나오고,
   *   그건 오류 없이 **상대가 복호화하지 못하는** 형태로만 드러난다 — 소스에는 escape로 쓴다
   *   (리터럴 제어문자 금지 규약과도 같은 방향이다).
   *
   * ① `auth_secret`을 salt로 써서 공유 비밀에서 IKM을 뽑는다. info에 **양쪽 공개키**를
   *    넣는 것이 요점이다(`WebPush: info` ‖ ua_public ‖ as_public) — 중간자가 자기 키로
   *    바꿔치기해도 다른 키가 나온다.
   * ② 그 IKM과 진짜 salt로 CEK·nonce를 뽑는다.
   */
  const keyInfo = Buffer.concat([Buffer.from("WebPush: info\u0000", "utf8"), clientPublic, serverPublic]);
  const ikm = hkdf(authSecret, sharedSecret, keyInfo, 32);

  const cek = hkdf(salt, ikm, Buffer.from("Content-Encoding: aes128gcm\u0000", "utf8"), 16);
  const nonce = hkdf(salt, ikm, Buffer.from("Content-Encoding: nonce\u0000", "utf8"), 12);

  /**
   * RFC 8188 §2 — 마지막 레코드는 평문 뒤에 `0x02`를 붙인다(중간 레코드는 `0x01`).
   * 우리는 항상 하나뿐이라 언제나 `0x02`다.
   */
  const cipher = createCipheriv("aes-128-gcm", cek, nonce);
  const ciphertext = Buffer.concat([cipher.update(Buffer.concat([payload, Buffer.from([0x02])])), cipher.final(), cipher.getAuthTag()]);

  /** 헤더: salt(16) ‖ rs(4, big-endian) ‖ idlen(1) ‖ keyid(= 서버 공개키 65). */
  const header = Buffer.alloc(16 + 4 + 1);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD_SIZE, 16);
  header.writeUInt8(serverPublic.length, 20);

  return { body: Buffer.concat([header, serverPublic, ciphertext]) };
}
