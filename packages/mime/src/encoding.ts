/**
 * 전송 인코딩(base64/quoted-printable) 디코더 + charset 디코딩 + RFC 2047 encoded-word.
 * 전부 malformed 입력에 관대하다 — 절대 throw하지 않고 최선의 결과를 반환한다 (Phase 0 견고성 규칙).
 */
import { binaryToBytes, bytesToBinary } from "./binary.ts";

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_TABLE: Record<string, number> = {};
for (let i = 0; i < B64_CHARS.length; i++) {
  B64_TABLE[B64_CHARS[i]!] = i;
}

/**
 * 관대한 base64 디코더: 알파벳 외 문자(개행·공백·'=' 등)는 무시, 불완전 꼬리는 버림.
 *
 * 중간 결과를 `number[]`로 모으지 않는 이유: 요소 하나당 8바이트가 들어 입력의 몇 배가 순간적으로
 * 잡힌다(16MB 입력에 RSS +398MB, 2026-07-31 실측). 수신 상한이 25MB라 통당 수백 MB가 튄다.
 * 디코딩 결과는 아무리 커도 입력의 3/4이므로(6비트를 8비트로 펴는 것이라 **팽창하지 않는다**)
 * 그만큼만 미리 잡고 6비트씩 흘려 담으면 봉우리가 사라진다.
 */
export function base64Decode(text: string): Uint8Array {
  const out = new Uint8Array(Math.ceil(text.length / 4) * 3);
  let n = 0;
  let acc = 0; // 아직 바이트를 이루지 못한 하위 비트들
  let bits = 0;
  for (let i = 0; i < text.length; i++) {
    const v = B64_TABLE[text[i]!];
    if (v === undefined) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, n); // 남은 bits(<8)는 불완전 꼬리 — 버린다
}

/**
 * 본문 quoted-printable 디코더. `text`는 바이너리 문자열(1문자=1바이트)이어야 한다.
 *
 * `number[]`로 모으지 않는 이유는 `base64Decode`와 같다 — 16MB 입력에 RSS +230MB가 튀었다
 * (2026-07-31 실측). 출력 바이트 하나는 입력 문자를 최소 하나 소비하므로 상한은 입력 길이다.
 */
export function quotedPrintableDecode(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  let n = 0;
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === "=") {
      const next2 = text.slice(i + 1, i + 3);
      if (next2 === "\r\n") {
        i += 3; // 소프트 라인브레이크
        continue;
      }
      if (text[i + 1] === "\n") {
        i += 2; // 관대: bare LF 소프트 브레이크도 허용
        continue;
      }
      if (/^[0-9A-Fa-f]{2}$/.test(next2)) {
        out[n++] = Number.parseInt(next2, 16);
        i += 3;
        continue;
      }
      out[n++] = 0x3d; // 잘못된 '=' 시퀀스 — 리터럴로 취급 (throw 금지)
      i += 1;
      continue;
    }
    out[n++] = ch.charCodeAt(0) & 0xff;
    i += 1;
  }
  return out.subarray(0, n);
}

/** RFC 2047 Q-encoding (헤더 encoded-word 전용, 본문 QP와 다름: '_' = 공백). */
function qEncodingDecode(text: string): Uint8Array {
  const withSpaces = text.replace(/_/g, " ");
  const out: number[] = [];
  let i = 0;
  while (i < withSpaces.length) {
    const ch = withSpaces[i]!;
    if (ch === "=" && /^[0-9A-Fa-f]{2}$/.test(withSpaces.slice(i + 1, i + 3))) {
      out.push(Number.parseInt(withSpaces.slice(i + 1, i + 3), 16));
      i += 3;
      continue;
    }
    out.push(ch.charCodeAt(0) & 0xff);
    i += 1;
  }
  return new Uint8Array(out);
}

/**
 * charset 지정 바이트 → 문자열. 지원: utf-8 (실제 디코딩), us-ascii/iso-8859-1(=latin1 무손실 매핑).
 * 그 외 미지원 charset(euc-kr/cp949 등, 스코프 밖)은 latin1 best-effort로 대체 — 절대 throw 없음.
 *
 * charset 미선언·미지원인 경우: 엄격 UTF-8 시도 → 실패 시 latin1.
 * (Content-Type 없이 UTF-8 원시 바이트를 보내는 발신자가 실존 — e2e에서 발견.
 *  유효한 UTF-8이면 그게 정답일 확률이 압도적이고, latin1 폴백은 무손실이라 안전.)
 */
export function decodeBytesWithCharset(bytes: Uint8Array, charsetRaw: string | undefined): string {
  const cs = charsetRaw?.trim().toLowerCase().replace(/^"(.*)"$/, "$1");
  if (cs === "utf-8" || cs === "utf8") {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
  if (cs === "us-ascii" || cs === "iso-8859-1" || cs === "latin1") {
    return bytesToBinary(bytes);
  }
  // 미선언 또는 미지원 charset
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return bytesToBinary(bytes);
  }
}

const ENCODED_WORD = /=\?[^?\s]+\?[bBqQ]\?[^?]*\?=/g;
// 인접한 encoded-word 사이의 순수 공백/탭은 무시한다 (RFC 2047 §2) — 미리 제거 후 개별 디코딩.
const ENCODED_WORD_GAP = /(=\?[^?\s]+\?[bBqQ]\?[^?]*\?=)[ \t]+(?=\=\?[^?\s]+\?[bBqQ]\?[^?]*\?=)/g;

/** Subject/주소 display-name 등에 등장하는 RFC 2047 encoded-word를 디코딩. 실패 시 원문 유지. */
export function decodeEncodedWords(input: string): string {
  const collapsed = input.replace(ENCODED_WORD_GAP, "$1");
  return collapsed.replace(ENCODED_WORD, (match) => {
    try {
      const body = match.slice(2, -2); // '=?' 와 '?=' 제거
      const firstQ = body.indexOf("?");
      if (firstQ === -1) return match;
      const charset = body.slice(0, firstQ);
      const enc = body[firstQ + 1];
      const rest = body.slice(firstQ + 3);
      const bytes = enc === "b" || enc === "B" ? base64Decode(rest) : qEncodingDecode(rest);
      return decodeBytesWithCharset(bytes, charset);
    } catch {
      return match; // 디코딩 실패 — 원문 그대로 (throw 금지)
    }
  });
}

/** 본문 파트 디코딩: Content-Transfer-Encoding 해제 후 charset 디코딩. `bodyText`는 바이너리 문자열. */
export function decodeTextPart(bodyText: string, cte: string, charset: string | undefined): string {
  let bytes: Uint8Array;
  switch (cte) {
    case "base64":
      bytes = base64Decode(bodyText);
      break;
    case "quoted-printable":
      bytes = quotedPrintableDecode(bodyText);
      break;
    default:
      // 7bit/8bit/binary/미지 인코딩 — 그대로 통과 (throw 금지)
      bytes = binaryToBytes(bodyText);
      break;
  }
  return decodeBytesWithCharset(bytes, charset);
}
