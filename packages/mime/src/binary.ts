/**
 * 바이트 ↔ "바이너리 문자열" 변환.
 * 메시지 전체를 1바이트=1코드포인트(latin1 대응) 문자열로 다루면
 * 헤더 파싱·바운더리 탐색·구조 분리를 순수 문자열 연산으로 처리할 수 있고,
 * 왕복 변환이 항상 무손실(0-255 전 범위 1:1)이라 인코딩 손상 위험이 없다.
 * ICU 의존(TextDecoder("latin1") 등)을 피하기 위해 수동 루프로 구현한다.
 */

const CHUNK = 0x8000;

export function bytesToBinary(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return out;
}

export function binaryToBytes(bin: string): Uint8Array {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i) & 0xff;
  }
  return out;
}
