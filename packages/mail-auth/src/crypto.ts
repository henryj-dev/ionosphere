/**
 * DKIM/ARC 서명·검증 프리미티브의 **정본**. 순수 함수(네트워크 I/O 없음).
 *
 * ★왜 별도 모듈인가: 예전에는 이 로직이 `sign.ts`·`verify.ts`·`arc.ts`에 **세 벌** 있었고,
 * 그래서 아래 규격 위반이 세 곳에 동형으로 복제돼 있었다. 정규화는 `canon.ts`가 소유하는데
 * 크립토는 소유자가 없었던 것이다(`canon.ts`는 RFC 6376 §3.4 정규화 전용이라 여기에 섞지 않는다).
 * 새 호출부가 생겨도 규율을 다시 지킬 필요가 없도록 소유자를 만든다.
 */
import { createHash, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from "node:crypto";

/** DKIM 서명 알고리즘. rsa-sha1은 RFC 8301에서 금지돼 아예 표현하지 않는다. */
export type DkimAlgorithm = "rsa-sha256" | "ed25519-sha256";

/**
 * 서명 대상 바이트를 알고리즘에 맞게 서명한다.
 *
 * ★RFC 8463 §3 (2026-08-01 실사고로 발견한 규격 위반의 핵심):
 *   "The Ed25519-SHA256 signing algorithm computes a message hash as defined in Section 3 of
 *    [RFC6376] using SHA-256 as the hash-alg. It **signs the hash** with the PureEdDSA variant."
 * 즉 ed25519-sha256은 정규화된 원문이 아니라 그 **SHA-256 다이제스트(32바이트)**를 서명한다.
 *
 * 예전에는 `cryptoSign(null, data, key)`로 원문을 그대로 서명했다. Ed25519가 내부적으로 SHA-512를
 * 쓰므로 서명·검증 자체는 성립했고, **검증 쪽도 같은 방식이라 자체 테스트가 전부 통과했다.**
 * 그래서 외부 검증자만 실패했다 — Gmail 실측 `dkim=fail header.s=ed1`, 독립 구현(dkimpy) 대조에서
 * RSA는 pass인데 Ed25519만 FAIL. 라이브는 Ed25519를 우선 선택하므로(`backend.ts` selectorFor)
 * **발송 메일 전체의 우리 서명이 외부에서 무효**였다.
 *
 * RSA 쪽은 `cryptoSign("sha256", …)`이 node 내부에서 다이제스트를 만들어 주므로 대칭이 아니다 —
 * 그 비대칭이 결함을 눈에 안 띄게 만든 원인이기도 하다.
 */
export function signDkimData(data: Buffer, algorithm: DkimAlgorithm, privateKey: string): Buffer {
  if (algorithm === "rsa-sha256") return cryptoSign("sha256", data, privateKey);
  return cryptoSign(null, sha256(data), privateKey);
}

/** `signDkimData`의 역. 검증 실패는 예외가 아니라 false다(호출자가 결과 객체로 감싼다). */
export function verifyDkimData(
  data: Buffer,
  algorithm: DkimAlgorithm,
  key: KeyObject,
  signature: Buffer,
): boolean {
  if (algorithm === "rsa-sha256") return cryptoVerify("sha256", data, key, signature);
  return cryptoVerify(null, sha256(data), key, signature);
}

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

/**
 * DKIM TXT의 `p=` 값(RAW 32바이트)에서 Ed25519 공개키를 만든다.
 *
 * RFC 8463 §3은 `p=`를 **RAW 32바이트의 base64**로 정한다(SPKI DER 아님 — RSA와 다르다).
 * 예전에는 `verify.ts`가 JWK(`kty:OKP`)로, `arc.ts`가 SPKI prefix(`302a300506032b6570032100`)를
 * 붙여서 — 같은 일을 두 방식으로 했다. 둘 다 동작하지만 한쪽만 고치면 갈라진다.
 *
 * ★JWK를 정본으로 택한 이유: SPKI 조립 방식은 길이 바이트가 prefix에 박혀 있어 **33바이트 p=를
 * 조용히 받아들인다**(초과분이 버려진다). JWK 경로는 길이를 명시적으로 거부할 수 있다.
 *
 * 길이 검사를 여기서 하는 이유: 32바이트가 아니면 아래 임포트가 애매한 예외를 던지는데,
 * 호출자는 그것을 "키 파싱 오류"로만 보고해 원인(길이)이 드러나지 않았다.
 */
export function ed25519PublicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 공개키 길이 이상(${raw.length}바이트, 32 필요)`);
  }
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** RSA 공개키 최소 비트수 — RFC 8301 §3.2("Signers MUST use RSA keys of at least 1024 bits"). */
const MIN_RSA_BITS = 1024;

/**
 * DKIM TXT의 `p=` 값에서 공개키를 만든다 — 알고리즘별 와이어 포맷 차이를 여기서 흡수한다.
 * RSA는 SPKI DER, Ed25519는 RAW 32바이트(RFC 8463 §3).
 *
 * 실패를 예외가 아니라 result 유니온으로 돌려주는 이유: 호출자(`verify.ts`·`arc.ts`)가 사유를
 * `permerror` 메시지·`reason`에 넣어야 한다. CLAUDE.md "실패 표현을 한 레이어에서 섞지 말 것".
 *
 * ★RSA 비트수 검사가 여기 있어야 하는 이유: 예전에는 `verify.ts`에만 있고 `arc.ts`에는 **없었다**.
 * 즉 DKIM은 1024비트 미만을 거부하는데 ARC는 받아들이는 비대칭이었다. 정본에 두면 그럴 수 없다.
 */
export type DkimPublicKeyResult = { ok: true; key: KeyObject } | { ok: false; reason: string };

export function dkimPublicKey(pubKeyBytes: Buffer, algorithm: DkimAlgorithm): DkimPublicKeyResult {
  try {
    if (algorithm === "ed25519-sha256") {
      return { ok: true, key: ed25519PublicKeyFromRaw(pubKeyBytes) };
    }
    const key = createPublicKey({ key: pubKeyBytes, format: "der", type: "spki" });
    const bits = key.asymmetricKeyDetails?.modulusLength;
    if (!bits || bits < MIN_RSA_BITS) {
      return { ok: false, reason: `RSA 키 크기 부족(${bits ?? "?"}비트, 최소 ${MIN_RSA_BITS})` };
    }
    return { ok: true, key };
  } catch (err) {
    return { ok: false, reason: `키 파싱 오류: ${err instanceof Error ? err.message : String(err)}` };
  }
}
