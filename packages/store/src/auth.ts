/**
 * 자격증명 (SCHEMA.md §4 credentials).
 * secret은 자기서술 포맷 — Phase 0은 scrypt (node:crypto 내장, 의존성 제로 원칙).
 * 포맷: `scrypt$N$r$p$saltB64$hashB64[ scram256$i$salt$storedKey$serverKey]`.
 * 두 세그먼트를 **함께** 둔다 — SCRAM으로 갈아타면 PBKDF2가 scrypt를 대체해 오프라인
 * 대입 내성이 내려간다. 옛 행은 첫 세그먼트만 있고, 첫 로그인 때 SCRAM 키가 지연 생성된다.
 *
 * 주의: credentials는 change_log 엔티티가 아니고 카운터/state를 건드리지 않으므로
 * modseq 클레임 없이 단순 삽입 (§3-3 전역 불변식은 "계정 메일 데이터" 쓰기에 적용).
 */
import { randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from "node:crypto";
import { ulid } from "@ionosphere/core";
import { CREDENTIAL_KIND, credentialKindName, type CredentialKind, type CredentialKindName, type DbDriver } from "@ionosphere/db";
import { deriveScramKeys } from "@ionosphere/core";

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 64;

/**
 * ★반드시 비동기 scrypt를 쓴다. `scryptSync`는 **이벤트 루프를 통째로 막는다** —
 * 실측 1회 약 40ms이고, authenticate는 계정의 자격증명 수만큼 돈다. 한 프로세스에 SMTP·IMAP·
 * POP3·JMAP이 함께 올라가 있으므로 인증 시도 몇 개로 서버 전체가 멈춘다(무인증 DoS).
 * 콜백형 scrypt는 libuv 스레드풀에서 돌아 그 시간 동안 다른 연결이 계속 처리된다.
 */
function scryptAsync(password: string, salt: Buffer, keylen: number, opts: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, keylen, opts, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

export async function hashSecret(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await scryptAsync(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  const scrypt = `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString("base64")}$${hash.toString("base64")}`;
  /**
   * SCRAM 세그먼트를 **여기서 함께** 만든다 — 평문을 손에 쥔 자리이기 때문이다.
   * (기존 행은 첫 로그인 때 지연 생성된다. 새로 만드는 것까지 지연시킬 이유는 없다.)
   * 비밀번호 설정은 드문 동작이라 KDF 두 번의 비용이 문제가 되지 않는다.
   */
  return `${scrypt}${SECRET_SEP}${await buildScramSegment(password)}`;
}

/** 저장값에서 읽는 파라미터의 상한 — DB가 오염돼도 메모리 폭탄이 되지 않게. */
const MAX_STORED_N = 1 << 20;
const MAX_STORED_R = 32;
const MAX_STORED_P = 16;

/**
 * 저장 포맷 — `<scrypt 세그먼트>[ <scram256 세그먼트>]` (구분자: 공백 한 칸).
 *
 * ★왜 SCRAM으로 **교체**하지 않는가: SCRAM은 PBKDF2를 쓰는데 그건 메모리 하드가 아니라
 * scrypt보다 오프라인 대입에 약하다. SCHEMA의 원안은 either/or였지만, 그대로 가면 SCRAM을
 * 켜는 순간 **모든 계정의 비밀번호 저장 강도가 내려간다**. 그래서 둘을 함께 둔다:
 * PLAIN·LOGIN 검증은 계속 scrypt가 하고, SCRAM 교환에만 두 번째 세그먼트를 쓴다.
 *
 * ★공백을 구분자로 쓰는 이유: base64에도 scrypt 포맷에도 공백이 없다. 그래서 **기존 행은
 * 그대로 첫 세그먼트만 있는 상태**가 되어 파싱이 자연히 하위호환된다 — 마이그레이션이 필요 없다.
 */
const SECRET_SEP = " ";

/** 저장값에서 scrypt 세그먼트만. 두 번째 세그먼트가 없으면 전체가 그것이다. */
function scryptSegment(stored: string): string {
  const sp = stored.indexOf(SECRET_SEP);
  return sp < 0 ? stored : stored.slice(0, sp);
}

/** 저장된 SCRAM 파라미터 — 없으면 null(아직 지연 생성 전). */
export interface StoredScram {
  iterations: number;
  salt: Buffer;
  storedKey: Buffer;
  serverKey: Buffer;
}

export function scramSegment(stored: string): StoredScram | null {
  const sp = stored.indexOf(SECRET_SEP);
  if (sp < 0) return null;
  const parts = stored.slice(sp + 1).split("$");
  if (parts.length !== 5 || parts[0] !== "scram256") return null;
  const iterations = Number(parts[1]);
  // DB가 오염돼도 PBKDF2 반복이 폭탄이 되지 않게 상한을 둔다(scrypt 파라미터와 같은 규율).
  if (!Number.isInteger(iterations) || iterations < 4096 || iterations > 10_000_000) return null;
  try {
    const salt = Buffer.from(parts[2]!, "base64");
    const storedKey = Buffer.from(parts[3]!, "base64");
    const serverKey = Buffer.from(parts[4]!, "base64");
    if (salt.length === 0 || storedKey.length !== 32 || serverKey.length !== 32) return null;
    return { iterations, salt, storedKey, serverKey };
  } catch {
    return null;
  }
}

/** 비밀번호에서 SCRAM 세그먼트를 만든다(지연 생성·비밀번호 변경 시 호출). */
export async function buildScramSegment(password: string): Promise<string> {
  const k = await deriveScramKeys(password);
  return `scram256$${k.iterations}$${k.salt.toString("base64")}$${k.storedKey.toString("base64")}$${k.serverKey.toString("base64")}`;
}

export async function verifySecret(password: string, stored: string): Promise<boolean> {
  const parts = scryptSegment(stored).split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4]!, "base64");
  const expected = Buffer.from(parts[5]!, "base64");
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (n < 2 || n > MAX_STORED_N || r < 1 || r > MAX_STORED_R || p < 1 || p > MAX_STORED_P) return false;
  try {
    const actual = await scryptAsync(password, salt, expected.length, { N: n, r, p, maxmem: 256 * 1024 * 1024 });
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    // 파라미터 조합이 maxmem을 넘는 등 — 검증 실패로 수렴시킨다(호출자는 | null 계약만 본다).
    return false;
  }
}

/**
 * 계정이 없을 때 태울 더미 해시. 없으면 "계정 없음"이 즉시 null을 돌려줘
 * **응답 시간만으로 계정 존재 여부가 샌다**(존재하면 자격증명당 ~40ms).
 * 완전한 평탄화는 아니다 — 실제 경로는 자격증명 개수만큼 도니까. 존재/부재 구분만 없앤다.
 */
let dummySecretPromise: Promise<string> | null = null;
function dummySecret(): Promise<string> {
  dummySecretPromise ??= hashSecret(randomBytes(32).toString("hex"));
  return dummySecretPromise;
}

/**
 * 앱 비밀번호용 랜덤 문자열 — 16 소문자(4-4-4-4 그룹, Google 앱비번 스타일).
 * 편향 없는 rejection sampling(randomBytes). 약 75비트 엔트로피.
 */
export function generateAppPassword(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const limit = 256 - (256 % alphabet.length); // 234 — 이 이상 바이트는 버려 편향 제거
  const chars: string[] = [];
  while (chars.length < 16) {
    for (const b of randomBytes(32)) {
      if (b >= limit) continue;
      chars.push(alphabet[b % alphabet.length]!);
      if (chars.length === 16) break;
    }
  }
  return `${chars.slice(0, 4).join("")}-${chars.slice(4, 8).join("")}-${chars.slice(8, 12).join("")}-${chars.slice(12, 16).join("")}`;
}

/**
 * 앱 비밀번호 생성 — 평문은 이 반환값으로 "한 번만" 노출(저장은 해시). 하이픈은 저장/검증에서
 * 무시(사용자가 공백/하이픈 섞어 입력해도 인증되도록 정규화). kind=1로 저장.
 */
export async function createAppPassword(
  db: DbDriver,
  accountId: string,
  label: string,
): Promise<{ id: string; password: string }> {
  const password = generateAppPassword();
  const id = await createCredential(db, { accountId, password: normalizeAppPassword(password), kind: CREDENTIAL_KIND.appPassword, label });
  return { id, password };
}

/** 앱 비밀번호 정규화 — 공백·하이픈 제거 후 소문자(입력 관용). */
function normalizeAppPassword(s: string): string {
  return s.replace(/[\s-]/g, "").toLowerCase();
}

/** OAuth 액세스 토큰 생성 — URL-safe base64 32바이트(~256비트). */
export function generateOAuthToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * 자체 발급 OAuth 베어러 토큰 생성(kind=2) — SASL XOAUTH2/OAUTHBEARER로 로그인. 평문 토큰은
 * 반환값으로 한 번만 노출(저장은 해시). authenticate가 kind=2를 원문 검증하므로 별도 배선 불필요.
 * 외부 IdP(OIDC) 토큰 검증이 필요하면 상위 계층에서 훅으로 대체 가능(현재는 자체 발급 전용).
 */
export async function createOAuthToken(
  db: DbDriver,
  accountId: string,
  label: string,
): Promise<{ id: string; token: string }> {
  const token = generateOAuthToken();
  const id = await createCredential(db, { accountId, password: token, kind: 2, label });
  return { id, token };
}

/** 계정의 자격증명 목록(비밀은 제외). kind 필터 가능(1=앱 비번). */
export async function listCredentials(
  db: DbDriver,
  accountId: string,
  kind?: 0 | 1 | 2,
): Promise<{ id: string; kind: number; label: string | null; createdAt: number; lastUsedAt: number | null }[]> {
  const { rows } = await db.query({
    sql: `SELECT id, kind, label, created_at, last_used_at FROM credentials WHERE account_id = ?${kind !== undefined ? " AND kind = ?" : ""} ORDER BY created_at`,
    params: kind !== undefined ? [accountId, kind] : [accountId],
  });
  return rows.map((r) => ({
    id: String(r.id),
    kind: Number(r.kind),
    label: r.label == null ? null : String(r.label),
    createdAt: Number(r.created_at),
    lastUsedAt: r.last_used_at == null ? null : Number(r.last_used_at),
  }));
}

/** 자격증명 폐기 — 부가 자격증명(앱 비번·OAuth 토큰)만 삭제. 기본 비밀번호는 지우면 계정이 잠긴다. */
export async function revokeCredential(db: DbDriver, accountId: string, id: string): Promise<boolean> {
  const r = await db.batch([
    {
      sql: `DELETE FROM credentials WHERE id = ? AND account_id = ? AND kind != ${CREDENTIAL_KIND.password}`,
      params: [id, accountId],
    },
  ]);
  return (r[0]?.changes ?? 0) > 0;
}

/** 자격증명 생성. kind 생략 시 기본 비밀번호(CREDENTIAL_KIND.password). */
export async function createCredential(
  db: DbDriver,
  input: { accountId: string; password: string; kind?: CredentialKind; label?: string; scopes?: string },
): Promise<string> {
  const id = ulid();
  await db.batch([
    {
      sql: `INSERT INTO credentials (id, account_id, kind, label, secret, scopes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      params: [id, input.accountId, input.kind ?? CREDENTIAL_KIND.password, input.label ?? null, await hashSecret(input.password), input.scopes ?? null, Date.now()],
    },
  ]);
  return id;
}

/**
 * email+password 인증 → accountId 또는 null.
 * 계정 status=1만 허용 (§7-7 가시성 계약). scope 검사는 호출자(프로토콜별) 몫.
 */
export async function authenticate(
  db: DbDriver,
  email: string,
  password: string,
): Promise<{ accountId: string; credentialId: string; credKind: CredentialKindName | undefined } | null> {
  const { rows: accounts } = await db.query({
    sql: "SELECT id FROM accounts WHERE email = ? AND status = 1",
    params: [email.toLowerCase()],
  });
  const accountId = accounts[0]?.id as string | undefined;
  if (!accountId) {
    // 타이밍 평탄화 — 위 dummySecret 주석 참조.
    await verifySecret(password, await dummySecret());
    return null;
  }

  const { rows: creds } = await db.query({
    sql: "SELECT id, kind, secret FROM credentials WHERE account_id = ?",
    params: [accountId],
  });
  const normalizedApp = normalizeAppPassword(password);
  for (const c of creds) {
    // 원문 우선 검증(기본 비번·원문 저장 앱비번 하위호환). 앱 비번(kind=1)은 실패 시
    // 정규화 입력(하이픈/공백 무시)으로 한 번 더 — createAppPassword가 정규화 저장하므로.
    const secret = String(c.secret);
    const matched =
      (await verifySecret(password, secret)) ||
      (Number(c.kind) === 1 && normalizedApp !== password && (await verifySecret(normalizedApp, secret)));
    if (matched) {
      const credentialId = String(c.id);
      // last_used_at 갱신(베스트에포트 — 실패해도 인증 성공엔 무관)
      try {
        await db.batch([{ sql: "UPDATE credentials SET last_used_at = ? WHERE id = ?", params: [Date.now(), credentialId] }]);
      } catch {
        /* 무시 */
      }
      /**
       * ★SCRAM 키 **지연 생성**(SCHEMA §4 credentials 주석의 설계).
       *
       * SCRAM 키는 평문 비밀번호에서만 유도할 수 있는데, 우리는 scrypt 해시만 갖고 있다.
       * 그래서 **인증이 성공한 이 순간**이 평문을 손에 쥔 유일한 자리다. 여기서 만들어 두지
       * 않으면 기존 계정은 비밀번호를 바꾸기 전까지 영영 SCRAM을 못 쓴다.
       *
       * 베스트에포트다 — 실패해도 인증 성공에는 영향이 없다(다음 로그인에 다시 시도한다).
       * 매칭된 값(`password` 또는 정규화된 앱 비번)으로 유도해야 SCRAM 교환의 입력과 맞는다.
       */
      if (scramSegment(secret) === null) {
        void (async () => {
          try {
            const matchedValue = (await verifySecret(password, secret)) ? password : normalizedApp;
            const seg = await buildScramSegment(matchedValue);
            await db.batch([
              {
                sql: "UPDATE credentials SET secret = ? WHERE id = ? AND secret = ?",
                params: [`${secret}${SECRET_SEP}${seg}`, credentialId, secret],
              },
            ]);
          } catch {
            /* 무시 — 다음 로그인에 다시 시도한다 */
          }
        })();
      }
      // ★`credKind`를 함께 돌려준다 — 접근 감사 로그가 "이 로그인이 기본 비밀번호인가 앱
      // 비밀번호인가 OAuth 토큰인가"를 구분해야 한다. 예전엔 이 값이 쿼리에는 있는데 반환에
      // 없어서, 어느 로그에도 그 구분이 남지 않았다. 인코딩 역매핑은 소유 패키지(@ionosphere/db).
      return { accountId, credentialId, credKind: credentialKindName(Number(c.kind)) };
    }
  }
  return null;
}

/**
 * SCRAM 교환에 쓸 저장 키 조회 — 없으면 null.
 *
 * ★**기본 비밀번호 자격증명(kind=0)만** 대상이다. SCRAM의 server-first는 salt와 반복
 * 횟수를 **하나만** 실을 수 있는데, 한 계정에 앱 비밀번호가 여러 개 있으면 어느 것의
 * salt를 보낼지 정할 수 없다. 그래서 규칙을 하나로 못박는다: SCRAM은 기본 비밀번호로만,
 * 앱 비밀번호는 PLAIN으로. 여러 개 중 하나를 고르면 "왜 이 앱 비밀번호만 SCRAM이 되지"가
 * 된다.
 *
 * ★없는 계정·정지 계정·SCRAM 키 미생성 모두 **같은 null**을 돌려준다. 호출부(엔진)가
 * 가짜 salt로 교환을 끝까지 진행하므로 여기서 갈래를 나눌 이유가 없고, 나누면 그 자체가
 * 계정 열거의 실마리가 된다.
 */
export async function scramKeysFor(db: DbDriver, email: string): Promise<StoredScram | null> {
  const { rows } = await db.query({
    sql: `SELECT c.secret AS secret
            FROM credentials c
            JOIN accounts a ON a.id = c.account_id
           WHERE a.email = ? AND a.status = 1 AND c.kind = ?
           ORDER BY c.created_at ASC`,
    params: [email.toLowerCase(), CREDENTIAL_KIND.password],
  });
  const secret = rows[0]?.secret;
  return typeof secret === "string" ? scramSegment(secret) : null;
}

/**
 * SCRAM 증명 통과 뒤의 최종 승인 — 계정이 살아 있는가.
 *
 * ★비밀번호를 증명한 것과 들어와도 되는 것은 다른 사실이다. 정지된 계정도 비밀번호는
 * 맞을 수 있다. PLAIN 경로는 `authenticate`가 `status = 1`을 함께 보지만, SCRAM은 검증을
 * 엔진이 하므로 이 확인이 **따로** 있어야 한다 — 없으면 정지가 SCRAM에서만 새어 나간다.
 */
export async function scramAuthorize(db: DbDriver, email: string): Promise<{ accountId: string } | null> {
  const { rows } = await db.query({
    sql: "SELECT id FROM accounts WHERE email = ? AND status = 1",
    params: [email.toLowerCase()],
  });
  const id = rows[0]?.id;
  return typeof id === "string" ? { accountId: id } : null;
}
