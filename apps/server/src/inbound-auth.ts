/**
 * 수신 인증 파이프라인 (Phase 2) — 받은 메일에 SPF/DKIM/DMARC를 실행하고
 * Authentication-Results 헤더 값 + message_auth 저장 코드를 산출한다.
 *
 * 원본(raw)은 DKIM 검증에 그대로 쓰고, 검증 후 AR 헤더를 앞에 붙여 저장한다
 * (수신 MTA가 AR 헤더를 추가하는 것은 표준 — RFC 8601).
 */
import {
  buildAuthenticationResults,
  checkDmarc,
  checkSpf,
  dkimVerify,
  mapToStorageCodes,
  type DnsResolver,
  type SpfResultValue,
} from "@ionosphere/mail-auth";
import { headerSafeToken } from "@ionosphere/core";
import { splitHeaderBody, splitHeaderRecords } from "@ionosphere/mime";
import type { ParsedMessage } from "@ionosphere/mime";

export interface InboundAuthInput {
  raw: Uint8Array;
  parsed: ParsedMessage;
  clientIp: string;
  heloName: string;
  mailFrom: string; // 봉투 발신 (널 리턴패스면 "")
  authservId: string; // 우리 호스트명 (예: mx.ionosphere.test)
  /**
   * 접속 IP가 **우리가 운영하는 신뢰 릴레이**인가 — true면 SPF를 돌리지 않는다.
   *
   * ★왜 필요한가(2026-08-17 실측): 로컬 도메인 수신자는 MtaWorker가 릴레이를 태우지 않고 우리
   * MX로 직송한다(`@ionosphere/mta` worker.ts). 3대 분리 후 그 홉은 사설망을 타므로 MX가 보는
   * 접속 IP가 `10.0.82.134`(MSA 내부 주소)다. apex SPF에는 MSA의 **공인** IP만 있고 `-all`이라
   * 판정은 필연적으로 `fail`이고, 고칠 방법이 SPF 레코드 쪽에는 없다 — 사설 대역을 공개
   * SPF에 적는 것은 외부 수신자에게 무의미하고 그 대역 전체에 우리 도메인을 위임하는 것이다.
   *
   * 즉 여기서 `fail`은 발신자에 대한 사실이 아니라 **우리 배치에 대한 사실**이다. 그걸 신호로
   * 쓰면 greylist가 우리 MSA를 지연시키고 점수 엔진이 내부 메일마다 가산한다. 그래서 결과를
   * 뒤집지 않고 **평가 자체를 하지 않는다** — A-R에서 spf 절을 빼고 Received-SPF도 안 만든다.
   * 이 파일의 규율("확인하지 않은 결과를 적을 수 없다")을 그대로 따른 것이다.
   *
   * ⚠ 이 플래그가 끄는 것은 **SPF 하나뿐**이다. DKIM·DMARC는 그대로 돈다. 내부 홉이라고
   * 인증 파이프라인 전체를 끄면 DKIM 회귀(과거 릴레이 Message-ID 재작성 사고)를 우리 손으로
   * 볼 수 없게 된다 — 그 사고를 드러낸 것이 바로 판정 문자열의 변화였다.
   */
  trustedRelay?: boolean;
}

export interface InboundAuthResult {
  /** Authentication-Results 헤더 "값" (필드명 제외, authserv-id로 시작). */
  authResults: string;
  /** message_auth 저장 코드 (SCHEMA §9-3). spf가 null이면 검사 안 함(신뢰 릴레이). */
  codes: { spf: number | null; dkim: number; dmarc: number };
  /** 요약 (로그용·점수 엔진 입력). spf가 없으면 평가하지 않은 것 — `none`으로 채우지 않는다. */
  summary: { spf?: string; dkim: string; dmarc: string };
  /** DMARC 집계 리포트용 원자료 — `summary`보다 상세하다(위 반환부 주석). */
  dmarcReport: {
    policyDomain: string;
    headerFrom: string;
    disposition: string;
    dkimAligned: boolean;
    spfAligned: boolean;
    dkimResult: string;
    spfResult: string;
    dkimDomain: string | null;
    spfDomain: string | null;
  };
  /**
   * RFC 7208 §9.1 Received-SPF 헤더 한 줄(필드명 포함). A-R보다 정보가 많다(§9.2).
   * SPF를 돌리지 않았으면 **없다** — 검사하지 않은 판정을 헤더로 주장할 수 없다.
   */
  receivedSpf?: string;
}

function domainOf(email: string): string {
  const at = email.lastIndexOf("@");
  return at >= 0 ? email.slice(at + 1).toLowerCase() : "";
}


/**
 * RFC 7208 §9.1 `Received-SPF` 조립.
 *
 * **A-R과 무엇이 다른가**: §9.2가 직접 적어 뒀다 — Authentication-Results는
 * "provide less information than the Received-SPF field". A-R은 결과 요약이고,
 * Received-SPF는 `client-ip`·`helo`·`envelope-from`을 담아 **판정을 재구성**할 수 있게 하는 게
 * 목적이다. §9는 둘을 나란히 제시하며 "Both are in common use"라고 한다 — 그래서 둘 다 낸다.
 *
 * ⚠ §9.1의 MUST: "SPF verifiers MUST make sure that the Received-SPF header field does not
 * contain invalid characters, is not excessively long, and does not contain malicious data
 * that has been provided by the sender." helo·envelope-from·client-ip이 전부 상대가 정하는
 * 값이므로, Received와 **같은 가드**(headerSafeToken)를 통과한 것만 넣는다.
 */
export interface ReceivedSpfInput {
  result: SpfResultValue;
  /** 우리 호스트명(receiver=). */
  receiver: string;
  clientIp: string;
  heloName: string;
  /** 봉투 발신. 널 리턴패스(바운스)면 빈 문자열. */
  mailFrom: string;
  /** SPF가 실제로 검사한 도메인 — 주석에 쓴다. */
  domain: string;
}

/** 결과별 주석(§9.1 "SHOULD include a (...) style comment"). 통상적 문구를 따른다. */
function spfComment(input: ReceivedSpfInput, sender: string, ip: string): string {
  const r = input.receiver;
  switch (input.result) {
    case "pass":
      return `${r}: domain of ${sender} designates ${ip} as permitted sender`;
    case "fail":
      return `${r}: domain of ${sender} does not designate ${ip} as permitted sender`;
    case "softfail":
      return `${r}: transitioning domain of ${sender} does not designate ${ip} as permitted sender`;
    case "neutral":
      return `${r}: ${ip} is neither permitted nor denied by domain of ${sender}`;
    case "none":
      return `${r}: ${sender} does not designate permitted sender hosts`;
    case "temperror":
      return `${r}: error in processing during lookup of ${sender}`;
    case "permerror":
      return `${r}: permanent error in processing during lookup of ${sender}`;
  }
}

export function buildReceivedSpf(input: ReceivedSpfInput): string {
  const receiver = headerSafeToken(input.receiver) ?? "localhost";
  const ip = headerSafeToken(input.clientIp, 64);
  const helo = headerSafeToken(input.heloName);
  const from = headerSafeToken(input.mailFrom, 320);
  // 널 리턴패스는 MAIL FROM을 검사할 수 없어 HELO 신원으로 판정한다(§2.3).
  const identity = input.mailFrom ? "mailfrom" : "helo";
  const sender = from ?? headerSafeToken(input.domain) ?? helo ?? "unknown";

  const pairs: string[] = [`receiver=${receiver}`];
  if (ip) pairs.push(`client-ip=${ip}`);
  // envelope-from은 quoted-string 형태다(§9.1 예시). 가드가 따옴표를 거른 뒤라 안전하다.
  pairs.push(`envelope-from="${from ?? "<>"}"`);
  if (helo) pairs.push(`helo=${helo}`);
  pairs.push(`identity=${identity}`);

  // 접힘은 CRLF + TAB. 한 줄이 998옥텟을 넘지 않게 절 단위로 나눈다(RFC 5322 §2.1.1).
  return `Received-SPF: ${input.result} (${spfComment(input, sender, ip ?? "unknown")})\r\n\t${pairs.join("; ")}`;
}

export async function runInboundAuth(
  input: InboundAuthInput,
  resolver: DnsResolver,
): Promise<InboundAuthResult> {
  const fromDomain = input.parsed.from[0] ? domainOf(input.parsed.from[0].email) : "";

  // SPF (접속 IP + HELO + MAIL FROM). 신뢰 릴레이면 평가하지 않는다 — InboundAuthInput 주석 참조.
  const spf = input.trustedRelay
    ? null
    : await checkSpf({ ip: input.clientIp, helo: input.heloName, mailFrom: input.mailFrom }, resolver);

  // DKIM (원본 바이트 기준)
  const dkim = await dkimVerify(input.raw, (name) => resolver.txt(name));

  /**
   * DMARC (From 도메인 + SPF/DKIM 정렬).
   *
   * SPF를 안 돌린 경우 `none`을 넣는다 — DMARC 입장에서 "SPF 증거 없음"이고, 정렬은 DKIM
   * 하나로만 판단된다(RFC 7489 §4.2는 둘 중 하나만 통과해도 pass다). 여기서 `pass`를 넣어
   * 통과시키는 것은 **검사하지 않은 것을 통과로 위조**하는 것이라 하지 않는다.
   */
  const dmarc = await checkDmarc(
    {
      fromDomain,
      spf: { result: spf?.result ?? "none", domain: spf?.domain ?? "" },
      dkim: dkim.map((d) => ({ result: d.result, domain: d.domain })),
    },
    resolver,
  );

  const authResults = buildAuthenticationResults(input.authservId, {
    // spf 절 자체를 생략한다(RFC 8601은 평가한 메서드만 적는다).
    ...(spf
      ? {
          spf: {
            result: spf.result,
            domain: spf.domain || input.heloName,
            identity: input.mailFrom ? "mailfrom" : "helo",
          },
        }
      : {}),
    dkim,
    dmarc: { result: dmarc.result, fromDomain },
  });

  // DKIM 종합: 하나라도 pass면 pass, 서명 없으면 none, 그 외 첫 결과
  const dkimOutcome = dkim.length === 0 ? "none" : dkim.some((d) => d.result === "pass") ? "pass" : dkim[0]!.result;
  const codes = mapToStorageCodes(spf?.result ?? null, dkimOutcome, dmarc.result);

  return {
    authResults,
    codes,
    summary: { ...(spf ? { spf: spf.result } : {}), dkim: dkimOutcome, dmarc: dmarc.result },
    /**
     * DMARC 집계 리포트(RFC 7489 §7.2)용 원자료.
     *
     * ★`summary`로는 부족하다. 리포트는 **정렬**(alignment)과 **인증 결과**를 따로 적어야
     * 하고(§7.2의 `policy_evaluated` vs `auth_results`), 어느 도메인이 서명했는지도 실어야
     * 상대가 원인을 좁힌다. 그 값들은 여기서만 알 수 있다.
     */
    dmarcReport: {
      policyDomain: dmarc.orgDomain ?? fromDomain,
      headerFrom: fromDomain,
      disposition: dmarc.disposition,
      dkimAligned: dmarc.alignment.dkim,
      spfAligned: dmarc.alignment.spf,
      dkimResult: dkimOutcome,
      spfResult: spf?.result ?? "none",
      dkimDomain: dkim.find((d) => d.result === "pass")?.domain ?? dkim[0]?.domain ?? null,
      spfDomain: spf?.domain ?? null,
    },
    ...(spf
      ? {
          receivedSpf: buildReceivedSpf({
            result: spf.result,
            receiver: input.authservId,
            clientIp: input.clientIp,
            heloName: input.heloName,
            mailFrom: input.mailFrom,
            domain: spf.domain,
          }),
        }
      : {}),
  };
}

/**
 * AR 헤더를 원문 앞에 접두 (수신 MTA 표준 동작).
 * authResults는 이미 authserv-id로 시작한다(buildAuthenticationResults) — 중복 접두 금지.
 */
export function prependAuthResults(authResults: string, raw: Uint8Array): Uint8Array {
  const header = `Authentication-Results: ${authResults}\r\n`;
  const headerBytes = new TextEncoder().encode(header);
  const out = new Uint8Array(headerBytes.length + raw.length);
  out.set(headerBytes, 0);
  out.set(raw, headerBytes.length);
  return out;
}

/**
 * 호스트 신원 정규화 — 소문자화 + **후행 점 제거**.
 *
 * 왜 후행 점인가: DNS에서 `mx.example.com.`(루트까지 적은 절대표기)과 `mx.example.com`은
 * **같은 이름**이다. 문자열 동등 비교만 하면 공격자가 점 하나를 붙여 "우리 것" 판정을 피하면서도
 * A-R을 읽는 사람·필터에게는 여전히 우리 호스트로 보이게 만들 수 있다(감사 M-13 (c)).
 * 비교하는 양쪽이 반드시 이 함수를 통과해야 한다 — 한쪽만 정규화하면 그 자체가 우회다.
 */
function normalizeHostId(id: string): string {
  return id.trim().toLowerCase().replace(/\.+$/, "");
}

/** 필드 값에서 authserv-id를 뽑는다(주석 제거 → 첫 세미콜론 앞). 입력은 언폴딩된 레코드다. */
function authservIdOf(field: string): string {
  const value = field.slice(field.indexOf(":") + 1);
  const withoutComments = value.replace(/\([^)]*\)/g, " ");
  const idPart = withoutComments.split(";")[0] ?? "";
  return normalizeHostId(idPart);
}

/**
 * 우리 authserv-id를 사칭한 Authentication-Results를 제거한다 (RFC 8601 §5 — **MUST**).
 *
 * > any MTA conforming to this specification MUST delete any discovered instance of this
 * > header field that claims, by virtue of its authentication service identifier, to have
 * > been added within its trust boundary but that did not come directly from another trusted MTA.
 *
 * 왜 위험한가: A-R은 "**우리가** 검증했다"는 주장이다. 공격자가 본문에
 * `Authentication-Results: <우리 id>; dmarc=pass …` 를 넣어 보내면, 우리가 진짜 결과를 위에
 * 얹어도 위조본이 그대로 남는다. A-R을 읽는 MUA·필터가 authserv-id로 찾다가 위조본을 집으면
 * **인증에 실패한 메일이 통과한 것처럼 보인다.**
 *
 * 남의 id로 된 A-R은 **남긴다** — 상류 MTA가 남긴 정당한 정보이고, 전부 지우면 릴레이·포워딩을
 * 거친 메일의 인증 이력이 사라진다(§5도 신뢰하는 외부 결과를 남겨 둘 여지를 명시한다).
 *
 * ⚠ 반드시 **DKIM 검증을 끝낸 뒤에** 부른다. 헤더를 지우면 그 헤더를 덮은 서명이 깨지는데,
 *   우리 검증은 원본(env.raw)으로 이미 끝나 있어야 한다. RFC도 이 손실을 인정하고 제거를 요구한다.
 *
 * 바이트 보존을 위해 latin1로 왕복한다 — 8비트 헤더가 있어도 원문이 변형되지 않는다.
 */
/**
 * 헤더 블록에서 필드명이 `fieldName`이고 조건에 맞는 필드를 통째로 제거한다(본문은 손대지 않는다).
 *
 * 두 제거기(A-R·Received-SPF)가 공유한다 — 블록 분리와 바이트 보존은 같은 문제이고,
 * 복제하면 한쪽만 고쳐져 갈라진다. 다른 것은 "무엇을 우리 것으로 볼 것인가"뿐이다.
 *
 * ⚠ 경계 판정과 레코드 분리는 **반드시 `@ionosphere/mime`의 것을 쓴다.** 여기에 자체 정규식을 두면
 * 파서와 검사기가 같은 바이트를 다르게 읽는 순간 위조본이 통과한다. 실제로 그랬다(감사 M-13):
 *  - 자체 `/\r?\n\r?\n/`는 `\n\r\n`에도 매치돼 헤더 블록을 파서보다 **일찍 끝냈고**, 그 뒤의
 *    위조 헤더를 아예 쳐다보지 않았다. 파서(`splitHeaderBody`)는 리터럴 3종만 보므로 계속 헤더였다.
 *  - 자체 `/^Authentication-Results:/`는 콜론이 붙어야 매치됐지만, 파서는 이름을 trim한 뒤 받았다.
 * 둘 다 "경계를 두 벌 두었다"는 하나의 원인에서 나왔고, 소유자를 mime으로 통일하면 **정의상**
 * 함께 닫힌다.
 *
 * 바이트 보존을 위해 latin1로 왕복한다 — 8비트 헤더가 있어도 원문이 변형되지 않는다.
 * 레코드의 `raw`가 **끝의 개행까지** 담으므로, 지우지 않은 것을 이어 붙이면 나머지는 그대로다.
 */
function stripHeaderFields(raw: Uint8Array, fieldName: string, isOurs: (unfolded: string) => boolean): Uint8Array {
  const text = Buffer.from(raw).toString("latin1");
  // 헤더 블록만 대상 — 본문에 헤더처럼 생긴 줄이 있어도 건드리지 않는다.
  const { headerText } = splitHeaderBody(text);
  const rest = text.slice(headerText.length);

  let removed = false;
  let head = "";
  for (const record of splitHeaderRecords(headerText)) {
    if (record.name === fieldName && isOurs(record.unfolded)) {
      removed = true;
      continue;
    }
    head += record.raw;
  }
  if (!removed) return raw; // 위조본 없음 — 원본 그대로(불필요한 복사도 피한다)
  return new Uint8Array(Buffer.from(head + rest, "latin1"));
}

export function stripForgedAuthResults(raw: Uint8Array, authservId: string): Uint8Array {
  const ours = normalizeHostId(authservId);
  if (!ours) return raw;
  return stripHeaderFields(raw, "authentication-results", (field) => authservIdOf(field) === ours);
}

/**
 * 이 Received-SPF가 **누구 것이라고 주장**하는가. 식별할 수 없으면 null.
 *
 * 두 곳을 본다:
 *  ① `receiver=<호스트>` — RFC 7208 §9.1이 정한 **기계가 읽는 신원**
 *  ② 주석의 선두 `(<호스트>: …)` — RFC 예시가 정한 형태이고 우리도 그렇게 낸다
 *
 * ②까지 보는 이유: `receiver`는 **선택 키**라 빼 버리면 ①만으로는 안 걸린다.
 * 입력은 이미 언폴딩된 레코드다(`splitHeaderRecords`).
 */
function receivedSpfReceiverId(field: string): string | null {
  const receiver = /(?:^|[;\s])receiver\s*=\s*"?([^";\s]+)"?/i.exec(field);
  if (receiver) return normalizeHostId(receiver[1]!);
  const comment = /\(\s*([^\s:()]+)\s*:/.exec(field);
  return comment ? normalizeHostId(comment[1]!) : null;
}

/**
 * 지울 것인가. **우리 것이거나, 누구 것인지 알 수 없으면** 지운다.
 *
 * 후자가 fail closed 판단이다(CLAUDE.md "보안은 fail closed"). `Received-SPF: pass` 한 줄처럼
 * receiver도 주석도 없는 형태는 신원을 확인할 방법이 아예 없는데, 헤더를 훑는 사람이나 순진한
 * 필터에게는 **우리가 붙인 pass와 구별되지 않는다** — 그래서 남겨 두는 쪽이 더 위험하다.
 * 잃는 것은 신원을 안 밝힌 상류 MTA의 정보 한 줄뿐이고, 그것은 애초에 신뢰할 근거가 없다.
 * 우리 자신의 Received-SPF는 항상 `receiver=`를 넣으므로(`buildReceivedSpf`) 이 규칙에 걸리지 않는다.
 */
function receivedSpfShouldStrip(field: string, ours: string): boolean {
  const id = receivedSpfReceiverId(field);
  return id === null || id === ours;
}

/**
 * 우리를 사칭한 Received-SPF를 제거한다.
 *
 * ⚠ RFC 7208에는 RFC 8601 §5 같은 **삭제 MUST가 없다.** §9.1은 "우리 것이 다른 모든
 * Received-SPF보다 위에 와야 한다"만 요구하고 그건 맨 앞에 붙이는 것으로 충족된다.
 * 그런데도 지우는 이유는 **오독 위험이 A-R과 같은 부류**이기 때문이다 — 헤더를 훑는 사람이나
 * 순진한 필터가 아래쪽의 `Received-SPF: pass`를 집으면 SPF에 실패한 메일이 통과한 것처럼 보인다.
 */
export function stripForgedReceivedSpf(raw: Uint8Array, receiver: string): Uint8Array {
  const ours = normalizeHostId(receiver);
  if (!ours) return raw;
  return stripHeaderFields(raw, "received-spf", (field) => receivedSpfShouldStrip(field, ours));
}
