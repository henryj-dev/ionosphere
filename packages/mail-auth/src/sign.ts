/**
 * RFC 6376 DKIM 서명 생성 + RFC 8463 Ed25519 지원.
 *
 * l=(본문 길이 제한) 태그는 의도적으로 미지원한다: l=을 허용하면 공격자가 서명된 본문 뒤에
 * 임의 콘텐츠를 이어붙여도 서명이 그대로 유효해지는 "본문 트렁케이션 공격"이 가능해진다.
 * 보안상 이 패키지는 항상 본문 전체를 해시한다.
 */
import { createHash } from "node:crypto";
import {
  canonBody,
  canonHeaderField,
  groupHeaderFields,
  normalizeLineEndings,
  parseHeaderFields,
  resolveHeaderSequence,
  splitMessage,
  type DkimCanonMode,
  type HeaderField,
} from "./canon.ts";
import { signDkimData } from "./crypto.ts";

// 타입 정본은 crypto.ts다(서명 프리미티브와 같이 둔다). 기존 import 경로를 깨지 않기 위해 재노출한다.
export type { DkimAlgorithm } from "./crypto.ts";
import type { DkimAlgorithm } from "./crypto.ts";

export interface DkimSignOptions {
  domain: string; // d=
  selector: string; // s=
  privateKey: string; // PEM (PKCS#8) — RSA 또는 Ed25519
  algorithm: DkimAlgorithm;
  headerCanon?: DkimCanonMode; // 기본 relaxed
  bodyCanon?: DkimCanonMode; // 기본 relaxed
  signedHeaders?: string[]; // 기본: DEFAULT_SIGNED_HEADERS (존재하는 것만; from은 필수 — 없으면 throw)
  timestamp?: number; // t= (초). 테스트 재현성용 주입
  expiration?: number; // x= optional
  /** l=(본문 길이 제한) 미지원 — 보안상 의도적 제외 (본문 트렁케이션 공격 방지). 항상 undefined. */
  bodyLengthLimit?: never;
}

const DEFAULT_SIGNED_HEADERS = [
  "from",
  "to",
  "cc",
  "subject",
  "date",
  "message-id",
  "reply-to",
  "in-reply-to",
  "references",
  "mime-version",
  "content-type",
  "content-transfer-encoding",
];

/**
 * 릴레이(스마트호스트) 경유 발송용 서명 헤더 목록 — 기본 목록에서 **`message-id`만 뺀 것**이다.
 *
 * 왜 필요한가(2026-07-31 실측): Cloudflare Email Service는 중계하면서 `Message-ID`를 자기 것으로
 * **재작성한다.** 그래서 `message-id`가 `h=`에 있으면 우리 서명이 목적지에서 항상 깨졌다.
 *   제출한 것: `<dmarc-probe-1785485979876@ionosphere.test>`
 *   배달된 것: `<JCQm2EytCvpC9PHZvghqJvtWhBzR12sNWnks@ionosphere.test>`
 * Google DMARC 리포트가 `dkim d=ionosphere.test s=ed1 → fail`로 확인해 줬고, 같은 리포트에서
 * `bh=`는 우리 서명과 Cloudflare 서명이 동일했다 — 즉 본문은 무사하고 **헤더 해시만** 깨졌다.
 *
 * ★기본값을 바꾸지 않고 별도 목록으로 두는 이유: 릴레이를 쓰지 않는 배포는 `Message-ID`가
 * 재작성되지 않으므로 서명 범위를 줄일 이유가 없다. RFC 6376 §5.4가 `Message-ID` 서명을
 * 권고(SHOULD)하므로 기본은 권고를 따르고, **특정 릴레이의 제약을 라이브러리 기본값으로
 * 승격시키지 않는다**(승격하면 왜 뺐는지가 코드에서 사라진다).
 *
 * 잔여 위험: 릴레이 경유 메일은 `Message-ID` 위조로 스레딩 조작·중복제거 회피가 가능해진다.
 * 받아들이는 근거는 **그 필드가 어차피 보호되지 않는다**는 것이다 — 릴레이가 이미 바꾸므로
 * 서명에 넣어도 검증이 늘 실패해 검증자가 신뢰할 수 없다. `From`·`To`·`Subject`·`Date`·본문은
 * 그대로 서명된다.
 */
export const RELAY_SAFE_SIGNED_HEADERS: readonly string[] = DEFAULT_SIGNED_HEADERS.filter(
  (h) => h !== "message-id",
);

const FOLD_WIDTH = 78;

/** DKIM-Signature 헤더의 b= 값(서명 base64)만 78컬럼 폭으로 접어 이어붙인다. */
function foldSignatureTail(headLength: number, tail: string): string {
  let out = "";
  let col = headLength;
  let cursor = 0;
  while (cursor < tail.length) {
    const room = Math.max(FOLD_WIDTH - col, 1);
    out += tail.slice(cursor, cursor + room);
    cursor += room;
    if (cursor < tail.length) {
      out += "\r\n\t";
      col = 1; // 접힘 연속줄은 탭 하나로 시작
    }
  }
  return out;
}

/**
 * DKIM-Signature 헤더 한 줄을 생성해 반환한다 (트레일링 CRLF 없음 — 호출자가 prepend 시
 * `dkimSign(...) + "\r\n" + rawMessage` 형태로 붙인다).
 */
export function dkimSign(raw: Uint8Array, opts: DkimSignOptions): string {
  const bin = Buffer.from(raw).toString("latin1");
  const { headerBlock, body } = splitMessage(normalizeLineEndings(bin));
  const fields = parseHeaderFields(headerBlock);
  const groups = groupHeaderFields(fields);

  if (!groups.has("from")) {
    throw new Error("dkimSign: 메시지에 From 헤더가 없어 서명할 수 없습니다");
  }

  const headerCanon: DkimCanonMode = opts.headerCanon ?? "relaxed";
  const bodyCanon: DkimCanonMode = opts.bodyCanon ?? "relaxed";

  const candidates = (opts.signedHeaders ?? DEFAULT_SIGNED_HEADERS)
    .map((n) => n.toLowerCase())
    .filter((n) => n !== "from" && groups.has(n));
  // 오버서명(기본 활성): From을 h=에 한 번 더(from:from) 넣어, 서명 후 From 헤더가
  // 추가되는 공격을 막는다 — resolveHeaderSequence의 "맨 아래부터 소비" 규칙과 결합해 동작.
  const hNames = ["from", "from", ...candidates];

  const resolved = resolveHeaderSequence(groups, hNames);
  const headerHashInput = resolved.map((f) => (f ? canonHeaderField(f, headerCanon) : "")).join("");

  const canonicalBody = canonBody(body, bodyCanon);
  const bh = createHash("sha256").update(Buffer.from(canonicalBody, "latin1")).digest("base64");

  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);

  const tagParts = [
    "v=1",
    `a=${opts.algorithm}`,
    `c=${headerCanon}/${bodyCanon}`,
    `d=${opts.domain}`,
    `s=${opts.selector}`,
    `t=${timestamp}`,
  ];
  if (opts.expiration !== undefined) tagParts.push(`x=${opts.expiration}`);
  tagParts.push(`h=${hNames.join(":")}`);
  tagParts.push(`bh=${bh}`);
  tagParts.push("b=");

  const unsignedHeaderText = `DKIM-Signature: ${tagParts.join("; ")}`;
  const dkimField: HeaderField = { name: "DKIM-Signature", raw: unsignedHeaderText };
  // DKIM-Signature 필드 자신도 해시에 포함하되, 트레일링 CRLF는 붙이지 않는다 (RFC 6376 §3.7).
  const dkimFieldCanon = canonHeaderField(dkimField, headerCanon).replace(/\r\n$/, "");

  const dataToSign = Buffer.from(headerHashInput + dkimFieldCanon, "latin1");

  const sigB64 = signDkimData(dataToSign, opts.algorithm, opts.privateKey).toString("base64");

  // 접힘은 b= 값 안에서만 일어나도록 한다: 그 앞부분(v=/a=/c=/.../bh=/b=)은 해시에 쓰인
  // 그대로 한 줄로 유지해야 c=*/simple(무변경 정규화)에서도 해시 입력=전송 바이트가 항상 일치한다.
  const foldedSig = foldSignatureTail(unsignedHeaderText.length, sigB64);
  return unsignedHeaderText + foldedSig;
}
