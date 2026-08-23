/**
 * 도메인 DKIM 프로비저닝 — API(createDomain)와 CLI(add-domain)가 공유하는 단일 코드 경로
 * (STATUS §9 "add-domain 일원화": 이전엔 CLI만 키를 만들고 API verify 플로우는 키가 없어
 * 검증 통과 후에도 서명 발송이 불가능했다).
 *
 * RSA-2048 + Ed25519 이중 서명 키(PROTOCOLS §7 권장)를 생성하고, dkim_keys INSERT 문과
 * 게시해야 할 DNS 레코드 목록을 돌려준다. 개인키는 masterKey가 있으면 secretbox 봉인.
 */
import { randomBytes } from "node:crypto";
import { seal, ulid } from "@ionosphere/core";
import { generateDkimKeyPair } from "@ionosphere/mail-auth";
import { stsDnsRecords } from "@ionosphere/mta-sts";
import type { DbDriver, Statement } from "@ionosphere/db";

export interface DnsRecordInstruction {
  type: "TXT";
  name: string;
  value: string;
  /** 사람용 설명 (예: "DKIM rsa1"). */
  purpose: string;
}

export interface DkimProvision {
  statements: Statement[];
  dnsRecords: DnsRecordInstruction[];
  /**
   * false면 masterKey 미설정으로 개인키가 **평문 저장**된다 — 호출자(REST/CLI)는 반드시
   * 경고를 남길 것. 이 플래그가 없던 시절 REST 경로만 조용히 평문 저장했다.
   */
  sealed: boolean;
}

/** DKIM 키 2종(rsa1/ed1) 생성 — 호출자가 statements를 도메인 생성 배치에 합류시킨다. */
export function provisionDkimKeys(domainId: string, domainName: string, masterKey: string | undefined): DkimProvision {
  const now = Date.now();
  const rsa = generateDkimKeyPair("rsa-sha256");
  const ed = generateDkimKeyPair("ed25519-sha256");
  const rsaSealed = seal(rsa.privateKeyPem, masterKey);
  const edSealed = seal(ed.privateKeyPem, masterKey);
  const statements: Statement[] = [
    {
      sql: `INSERT INTO dkim_keys (id, domain_id, selector, algo, private_key, key_version, active, created_at)
            VALUES (?, ?, 'rsa1', 0, ?, 1, 1, ?)`,
      params: [ulid(), domainId, rsaSealed.value, now],
    },
    {
      sql: `INSERT INTO dkim_keys (id, domain_id, selector, algo, private_key, key_version, active, created_at)
            VALUES (?, ?, 'ed1', 1, ?, 1, 1, ?)`,
      params: [ulid(), domainId, edSealed.value, now],
    },
  ];
  const dnsRecords: DnsRecordInstruction[] = [
    { type: "TXT", name: `rsa1._domainkey.${domainName}`, value: rsa.dnsRecord, purpose: "DKIM rsa1" },
    { type: "TXT", name: `ed1._domainkey.${domainName}`, value: ed.dnsRecord, purpose: "DKIM ed1" },
    { type: "TXT", name: domainName, value: "v=spf1 mx ~all", purpose: "SPF (서버 IP 정책에 맞게 조정)" },
    { type: "TXT", name: `_dmarc.${domainName}`, value: "v=DMARC1; p=none", purpose: "DMARC 최소 (대량 발송 요건)" },
    // MTA-STS(RFC 8461) + TLS-RPT(RFC 8460) — 정책 본문은 mta-sts.<domain>/.well-known/mta-sts.txt
    // 로 서빙(autoconfig 서버). id는 정책 변경 시 갱신 필요. mta-sts CNAME/A는 배포 설정 몫.
    ...stsDnsRecords(domainName, { policyId: String(now), rua: `mailto:tls-reports@${domainName}` }).map(
      (r): DnsRecordInstruction => ({ type: "TXT", name: r.name, value: r.value, purpose: r.purpose }),
    ),
  ];
  return { statements, dnsRecords, sealed: rsaSealed.sealed && edSealed.sealed };
}

/**
 * 도메인 이름이 받아들여질 수 없을 때 던진다. `status`는 호출자가 그대로 HTTP 상태로 옮긴다
 * (형식·예약어=400, 이미 점유=409). REST와 CLI가 같은 판정을 쓰되 표현만 다르게 하려고
 * HttpError(server.ts 전용)가 아닌 이 패키지 소유의 에러로 둔다.
 */
export class DomainNameError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "DomainNameError";
    this.status = status;
  }
}

/**
 * `domains.status`의 검증 완료 값(SCHEMA §4). `@ionosphere/db`의 `domain-lookup.ts`가 같은 값을
 * 자기 사본으로 들고 있다 — domains.status 인코딩은 아직 `columns.ts`가 소유하지 않아서다
 * (admin-ui.ts:79에도 같은 메모가 있다). 소유자가 생기면 세 곳을 한꺼번에 걷어낼 것.
 */
const DOMAIN_STATUS_VERIFIED = 1;

/** RFC 1035 §2.3.4 — 와이어 포맷 255바이트에서 길이/루트 바이트를 뺀 표시 길이 상한. */
const MAX_DOMAIN_NAME_LENGTH = 253;
/** RFC 1035 §2.3.4 — 레이블 하나의 상한. */
const MAX_DOMAIN_LABEL_LENGTH = 63;
/** LDH(letter-digit-hyphen, RFC 1123 §2.1) — 하이픈은 레이블 처음·끝에 올 수 없다. */
const LABEL_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

/**
 * 이 이름과 그 **하위 전부**를 거부한다.
 *
 * 고른 기준은 "특수용도라서"가 아니라 **로컬 이름 해석이 메일을 가로챌 수 있어서**다.
 * 이 이름들은 공개 DNS가 아니라 각 호스트/링크가 스스로 답하므로, 테넌트가 이걸 메일
 * 도메인으로 잡으면 시스템 메일(`root@localhost` 등)이나 같은 링크의 다른 기기로 갈 메일이
 * 그 테넌트 사서함으로 들어온다. 발송 쪽도 MX를 찾을 수 없어 영구 큐 적체가 된다.
 *
 * 반대로 `.test`(RFC 6761 §6.2)·`.example`(RFC 2606 §2)은 **일부러 넣지 않았다**:
 * 공개 DNS에 절대 존재하지 않고 로컬 가로채기 의미도 없어 남에게 피해를 줄 수 없는 반면,
 * 이 저장소의 테스트 픽스처가 바로 그 용도로 쓰고 있다(119개 파일). 문서용 정확한 이름
 * `example.com` 계열만 아래 RESERVED_DOMAIN_NAMES로 막는다.
 *
 * ICANN이 사설용으로 예약한 `.internal`도 넣지 않았다 — 사내 배포가 정당하게 쓸 이름이다.
 */
export const RESERVED_DOMAIN_SUFFIXES = [
  "localhost", // RFC 6761 §6.3 — 항상 루프백
  "localdomain", // /etc/hosts 기본 항목 관행
  "local", // RFC 6762 mDNS — 같은 링크의 아무 기기나 응답할 수 있다
  "invalid", // RFC 6761 §6.4 — 존재하지 않음이 보장된 이름
  "onion", // RFC 7686 — Tor 전용, 일반 DNS로 해석되지 않는다
  "arpa", // RFC 3172 인프라 트리(RFC 8375 `home.arpa` 포함)
] as const;

/**
 * 소유권 검증 TXT 레코드 이름의 접두사.
 *
 * ★`LEGACY_OWNERSHIP_TXT_PREFIX`를 함께 두는 이유: 개명(mailer → ionosphere) 전에 검증을 마친
 * 도메인들은 `_mailer-verify` 레코드를 **이미 DNS에 게시해 두었다.** 검증이 새 이름만 본다면
 * 재검증 시점에 전부 실패하고, 그 실패는 도메인 비활성화로 이어진다 — 운영자가 남의 DNS를
 * 고칠 수는 없다. 그래서 게시 안내는 새 이름으로 하되 **확인은 둘 다 받는다.**
 * 구 이름 지원을 걷어내려면 모든 도메인이 새 레코드를 올린 뒤에 할 것.
 */
export const OWNERSHIP_TXT_PREFIX = "_ionosphere-verify";
export const LEGACY_OWNERSHIP_TXT_PREFIX = "_mailer-verify";

/** 정확히 이 이름만 거부(하위는 허용). RFC 2606 §3 문서 전용 도메인. */
export const RESERVED_DOMAIN_NAMES = ["example.com", "example.net", "example.org"] as const;

/**
 * 공용 메일 서비스 도메인 — 남의 이름을 우리 쪽 로컬 도메인으로 등록하지 못하게 한다.
 *
 * 감사 5차 H-4가 지목한 시나리오: 아무 테넌트나 `gmail.com` 행을 만들면 그 행이 라우팅
 * 판정에 섞여 스마트호스트 우회·DKIM 키 혼선이 났다. 판정 쪽은 `@ionosphere/db`의
 * `lookupDomainRouting`으로 이미 막았지만, **생성 자체를 막는 것이 한 겹 더 싸다**.
 * 완전한 목록일 수 없고 그럴 필요도 없다 — 소유권 검증(TXT)이 진짜 방어선이고 이건
 * 오타·명백한 악용을 즉시 되돌려 주는 층이다. 새 이름은 여기에만 추가한다.
 */
export const PUBLIC_MAILBOX_DOMAINS = [
  "gmail.com",
  "googlemail.com",
  "google.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "msn.com",
  "yahoo.com",
  "ymail.com",
  "aol.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "proton.me",
  "protonmail.com",
  "pm.me",
  "gmx.com",
  "gmx.net",
  "gmx.de",
  "mail.com",
  "mail.ru",
  "yandex.ru",
  "yandex.com",
  "zoho.com",
  "fastmail.com",
  "hey.com",
  "qq.com",
  "163.com",
  "126.com",
  "naver.com",
  "daum.net",
  "hanmail.net",
  "nate.com",
  "kakao.com",
] as const;

/** `name`이 `suffix` 자신이거나 그 하위인가 — 레이블 경계로만 본다(`notlocalhost`는 무관). */
function isUnderSuffix(name: string, suffix: string): boolean {
  return name === suffix || name.endsWith(`.${suffix}`);
}

/**
 * 도메인 이름 형식·예약어 검사. 통과하면 아무것도 하지 않고, 아니면 DomainNameError(400).
 *
 * provisionDomain 안에서 부른다 — REST·CLI 어느 쪽으로 들어와도 **행이 만들어지기 전에**
 * 걸리게 하려는 것이다. 호출자마다 손으로 붙이면 언젠가 한쪽이 빠지고, 빠진 자리는
 * "검사 없음"이라 조용히 통과한다(스코프 관문을 라우트마다 두지 않은 것과 같은 이유).
 */
export function assertUsableDomainName(name: string): void {
  if (name !== name.trim().toLowerCase()) {
    throw new DomainNameError(400, "domain name must be lowercase and trimmed");
  }
  if (name.length === 0) throw new DomainNameError(400, "domain name required");
  if (name.length > MAX_DOMAIN_NAME_LENGTH) {
    throw new DomainNameError(400, `domain name too long (max ${MAX_DOMAIN_NAME_LENGTH})`);
  }
  // IDN은 punycode(xn--)로 정규화해서 넘겨야 한다. `domains.name_utf8`이 원본 표기용 컬럼이지만
  // 아직 아무도 채우지 않으므로, 비ASCII를 받아 두면 저장 표기와 DNS 조회 표기가 갈린다.
  if (!/^[\x21-\x7e]+$/.test(name)) {
    throw new DomainNameError(400, "domain name must be ASCII (IDN은 punycode xn-- 형식으로)");
  }
  const labels = name.split(".");
  if (labels.length < 2) {
    // 최상위 레이블 하나짜리(`localhost`, `test`)는 메일 도메인이 될 수 없다.
    throw new DomainNameError(400, "domain name must have at least two labels");
  }
  for (const label of labels) {
    if (label.length === 0) throw new DomainNameError(400, "domain name has an empty label");
    if (label.length > MAX_DOMAIN_LABEL_LENGTH) {
      throw new DomainNameError(400, `domain label too long (max ${MAX_DOMAIN_LABEL_LENGTH}): ${label}`);
    }
    if (!LABEL_RE.test(label)) throw new DomainNameError(400, `invalid domain label: ${label}`);
  }
  // 최상위 레이블이 전부 숫자면 IP 주소 표기다(RFC 3696 §2). `1.2.3.4`를 도메인으로 등록하면
  // MX 조회가 성립하지 않아 큐에 영구 적체된다.
  if (/^[0-9]+$/.test(labels[labels.length - 1]!)) {
    throw new DomainNameError(400, "domain name must not be an IP address");
  }

  for (const suffix of RESERVED_DOMAIN_SUFFIXES) {
    if (isUnderSuffix(name, suffix)) {
      throw new DomainNameError(400, `reserved domain (special-use TLD): ${name}`);
    }
  }
  if ((RESERVED_DOMAIN_NAMES as readonly string[]).includes(name)) {
    throw new DomainNameError(400, `reserved domain (documentation-only): ${name}`);
  }
  if ((PUBLIC_MAILBOX_DOMAINS as readonly string[]).includes(name)) {
    throw new DomainNameError(400, `public mailbox provider domain cannot be claimed: ${name}`);
  }
}

/**
 * 이 테넌트가 이 이름을 새로 만들어도 되는지 **생성 시점에** 확인한다.
 *
 * ★이것은 보안 경계가 아니다. 진짜 유일성 보장은 `domain_name_claims.name PRIMARY KEY`이고,
 * 그 앵커는 소유권 검증에 성공할 때(REST) 또는 생성 배치 안에서(CLI preVerified) 들어간다 —
 * 즉 원자적이다. 여기 검사는 확인-후-행동이라 경합에 열려 있지만, 열려 있어도 잃는 게 없다:
 * 통과시켜도 verify 단계에서 409로 막힌다. 목적은 **DKIM 키까지 다 만들고 DNS 레코드를
 * 게시한 뒤에야** "그 이름은 남의 것"이라고 알려 주던 순서를 앞당기는 것이다.
 *
 * CLI(preVerified)는 부르지 않아도 된다 — 앵커를 같은 배치에서 넣으므로 BatchConflictError로
 * 즉시 드러난다. 이쪽이 오히려 더 강한 보장이다.
 */
export async function assertDomainNameAvailable(db: DbDriver, tenantId: string, name: string): Promise<void> {
  const { rows } = await db.query({ sql: "SELECT tenant_id, status FROM domains WHERE name = ?", params: [name] });
  for (const row of rows) {
    if (String(row.tenant_id) === tenantId) {
      // 같은 테넌트가 같은 이름을 두 번 가지면 활성 DKIM 키가 2세트가 되고, 서명 시 어느 키가
      // 뽑히는지 비결정적이 된다(감사 5차 H-4 ③) — 그 메일은 dkim=fail로 떨어진다.
      throw new DomainNameError(409, `domain already exists: ${name}`);
    }
    if (Number(row.status) === DOMAIN_STATUS_VERIFIED) {
      throw new DomainNameError(409, `domain name already active elsewhere: ${name}`);
    }
  }
}

/** provisionDomain 입력. */
export interface ProvisionDomainInput {
  domainId: string;
  tenantId: string;
  /** 소문자 정규화된 도메인명. */
  name: string;
  /** DKIM 개인키 봉인용. 미지정 시 평문 저장(반환 sealed=false). */
  masterKey?: string | undefined;
  /**
   * true면 소유권 검증을 건너뛰고 즉시 활성(status=1) + 이름 앵커 즉시 등록.
   * CLI add-domain(자사 도메인 전제)용. REST 플로우는 false(검증 후 활성).
   */
  preVerified?: boolean;
  /** 타임스탬프 주입(테스트). 기본 Date.now(). */
  now?: number;
}

/** provisionDomain 결과 — 호출자가 statements를 한 배치로 실행한다. */
export interface DomainProvision extends DkimProvision {
  /** 소유권 검증 토큰. preVerified여도 발급·저장한다(나중에 재검증 가능해야 하므로). */
  verifyToken: string;
}

/**
 * 도메인 생성 전체(도메인 행 + DKIM 키 + 필요 시 이름 앵커)를 한 곳에서 만든다.
 *
 * 이전엔 REST(server.ts)와 CLI(cli.ts)가 각각 INSERT를 작성해 **컬럼 목록이 갈라져 있었다** —
 * CLI 경로는 `verify_token`과 `name_utf8`을 빼먹어서, CLI로 만든 도메인은 이후 API로
 * 재검증할 수 없었다. 두 경로의 진짜 차이(즉시 활성 여부)만 preVerified로 남긴다.
 *
 * 이름 검사(assertUsableDomainName)를 **여기서** 하는 이유도 같다. 예전엔 생성 경로에 형식·
 * 예약어 검사가 한 줄도 없어서 아무 테넌트나 `gmail.com` 미검증 행 + DKIM 키를 만들 수 있었다
 * (감사 5차 H-4). 검사를 호출자에 두면 REST만, 혹은 CLI만 갖게 된다.
 * @throws DomainNameError 이름이 형식에 맞지 않거나 예약된 이름일 때(status=400).
 */
export function provisionDomain(input: ProvisionDomainInput): DomainProvision {
  assertUsableDomainName(input.name);
  const now = input.now ?? Date.now();
  const verifyToken = randomBytes(16).toString("hex"); // 32-hex
  const status = input.preVerified ? 1 : 0;
  const dkim = provisionDkimKeys(input.domainId, input.name, input.masterKey);
  const statements: Statement[] = [
    {
      sql: `INSERT INTO domains (id, tenant_id, name, name_utf8, status, verify_token, claimed_at, created_at)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?)`,
      params: [input.domainId, input.tenantId, input.name, status, verifyToken, now, now],
    },
    // 이름 앵커(전역 유일성)는 소유권이 확정된 뒤에 — REST는 verify 성공 시 별도로 넣는다.
    ...(input.preVerified
      ? [{ sql: "INSERT INTO domain_name_claims (name, domain_id) VALUES (?, ?)", params: [input.name, input.domainId] }]
      : []),
    ...dkim.statements,
  ];
  return {
    statements,
    dnsRecords: [
      { type: "TXT", name: `${OWNERSHIP_TXT_PREFIX}.${input.name}`, value: verifyToken, purpose: "소유권 검증 토큰" },
      ...dkim.dnsRecords,
    ],
    sealed: dkim.sealed,
    verifyToken,
  };
}
