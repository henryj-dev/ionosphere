import { createHash, createHmac, pbkdf2Sync } from "node:crypto";
import { buildServerFirst, parseClientFirst, verifyClientFinal } from "@ionosphere/core";
import { describe, expect, test } from "@ionosphere/testkit";
import { allMigrations, migrate, openSqlite } from "@ionosphere/db";
import { authenticate, createCredential, hashSecret, scramSegment, verifySecret } from "@ionosphere/store";
import { ulid } from "@ionosphere/core";

describe("auth (SCHEMA §4 credentials)", () => {
  test("hashSecret 자기서술 포맷 + verify 왕복", async () => {
    const stored = await hashSecret("비밀번호123!");
    expect(stored.startsWith("scrypt$16384$8$1$")).toBe(true);
    expect(await verifySecret("비밀번호123!", stored)).toBe(true);
    expect(await verifySecret("틀린비번", stored)).toBe(false);
  });

  test("verify는 손상된 포맷에 false (throw 금지)", async () => {
    expect(await verifySecret("x", "")).toBe(false);
    expect(await verifySecret("x", "argon2id$future$format")).toBe(false);
    expect(await verifySecret("x", "scrypt$bad")).toBe(false);
  });

  /**
   * 저장값의 scrypt 파라미터는 외부 입력으로 취급한다 — DB가 오염돼도 메모리 폭탄이 되면 안 된다.
   * 상한 밖이면 검증 실패로 수렴(throw 금지 — 호출자는 `| null` 계약만 방어한다).
   */
  test("verify는 상식 밖 scrypt 파라미터를 거부한다", async () => {
    const salt = Buffer.from("0123456789abcdef").toString("base64");
    const hash = Buffer.alloc(64).toString("base64");
    expect(await verifySecret("x", `scrypt$1073741824$8$1$${salt}$${hash}`)).toBe(false); // N 과대
    expect(await verifySecret("x", `scrypt$16384$9999$1$${salt}$${hash}`)).toBe(false); // r 과대
    expect(await verifySecret("x", `scrypt$16384$8$0$${salt}$${hash}`)).toBe(false); // p=0
  });

  /**
   * 이벤트 루프가 막히지 않는지 — scryptSync였을 때는 인증 1회가 ~40ms 동안 **모든** 연결을
   * 세웠다(SMTP·IMAP·POP3·JMAP이 한 프로세스). 해싱이 도는 동안 타이머가 계속 돌아야 한다.
   */
  test("해싱이 이벤트 루프를 막지 않는다", async () => {
    let ticks = 0;
    const timer = setInterval(() => ticks++, 1);
    try {
      await Promise.all(Array.from({ length: 4 }, () => hashSecret("password-for-loop-check")));
    } finally {
      clearInterval(timer);
    }
    expect(ticks).toBeGreaterThan(0);
  });

  test("authenticate: 계정+자격증명 매치, status/소문자 정규화", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const acct = ulid();
    await db.batch([
      {
        sql: "INSERT INTO tenants (id, name, status, created_at) VALUES (?, 't', 1, 0)",
        params: [ulid()],
      },
      {
        sql: `INSERT INTO accounts (id, tenant_id, email, status, uidvalidity_last, created_at)
              VALUES (?, ?, 'user@example.com', 1, 0, 0)`,
        params: [acct, ulid()],
      },
    ]);
    await createCredential(db, { accountId: acct, password: "pw-1", kind: 1, label: "테스트기기" });

    const ok = await authenticate(db, "USER@Example.COM", "pw-1", "imap"); // 대소문자 정규화
    expect(ok?.accountId).toBe(acct);
    expect(await authenticate(db, "user@example.com", "wrong", "imap")).toBeNull();
    expect(await authenticate(db, "ghost@example.com", "pw-1", "imap")).toBeNull();

    // status=0 계정은 인증 불가 (§7-7 가시성)
    await db.batch([{ sql: "UPDATE accounts SET status = 0 WHERE id = ?", params: [acct] }]);
    expect(await authenticate(db, "user@example.com", "pw-1", "imap")).toBeNull();
    await db.close();
  });
});

/**
 * SCRAM 저장 세그먼트 — `<scrypt> <scram256>` 복합 포맷.
 *
 * ★핵심 계약은 **하위호환**이다. 기존 행은 scrypt 세그먼트 하나뿐인데, 그 행으로도
 * 검증이 그대로 돼야 한다(마이그레이션 없이 굴러가야 하므로).
 */
describe("SCRAM 저장 포맷", () => {
  test("★scrypt만 있는 옛 행도 그대로 검증된다 (마이그레이션 불필요)", async () => {
    // 이 저장소가 예전에 쓰던 형태를 직접 만든다.
    const legacy = (await hashSecret("pw1")).split(" ")[0]!;
    expect(legacy.startsWith("scrypt$")).toBe(true);
    expect(await verifySecret("pw1", legacy)).toBe(true);
    expect(await verifySecret("wrong", legacy)).toBe(false);
    // 아직 SCRAM 키가 없다 — 첫 로그인 때 지연 생성될 대상이다.
    expect(scramSegment(legacy)).toBeNull();
  });

  test("새로 만든 비밀번호는 두 세그먼트를 함께 갖는다", async () => {
    const stored = await hashSecret("pw2");
    expect(await verifySecret("pw2", stored)).toBe(true);
    const scram = scramSegment(stored);
    expect(scram).not.toBeNull();
    expect(scram!.storedKey.length).toBe(32);
    expect(scram!.serverKey.length).toBe(32);
    expect(scram!.iterations).toBeGreaterThanOrEqual(4096);
  });

  test("★SCRAM 세그먼트가 붙어도 scrypt 검증 결과가 달라지지 않는다", async () => {
    const stored = await hashSecret("pw3");
    expect(await verifySecret("pw3", stored)).toBe(true);
    expect(await verifySecret("pw3 ", stored)).toBe(false); // 구분자를 비밀번호에 넣어도 통과 못 함
    expect(await verifySecret("", stored)).toBe(false);
  });

  test("깨진 SCRAM 세그먼트는 null로 수렴한다 (조용히 잘못된 키를 쓰지 않는다)", async () => {
    const base = (await hashSecret("pw4")).split(" ")[0]!;
    for (const bad of [
      `${base} scram256$4095$AAAA$AAAA$AAAA`, // 반복 하한 미달
      `${base} scram256$100000$AAAA$c2hvcnQ=$c2hvcnQ=`, // 키 길이 불일치
      `${base} bogus$1$2$3$4`,
      `${base} scram256$100000$AAAA`,
    ]) {
      expect(scramSegment(bad)).toBeNull();
      // 그래도 비밀번호 검증은 계속 된다 — 한쪽이 깨져도 로그인이 막히면 안 된다.
      expect(await verifySecret("pw4", bad)).toBe(true);
    }
  });

  test("★유도한 키가 RFC 교환에서 실제로 통과한다 (저장 → 검증 왕복)", async () => {
    const stored = await hashSecret("pencil");
    const scram = scramSegment(stored)!;
    const cf = parseClientFirst("n,,n=user,r=clientnonce123");
    const sn = "servernonce456";
    const serverFirst = buildServerFirst({
      clientNonce: cf!.clientNonce,
      serverNonce: sn,
      salt: scram.salt,
      iterations: scram.iterations,
    });
    // 클라이언트 쪽 계산을 직접 해서 proof를 만든다.
    const full = `${cf!.clientNonce}${sn}`;
    const withoutProof = `c=${Buffer.from(cf!.gs2Header).toString("base64")},r=${full}`;
    const authMessage = `${cf!.bare},${serverFirst},${withoutProof}`;
    const salted = pbkdf2Sync("pencil", scram.salt, scram.iterations, 32, "sha256");
    const clientKey = createHmac("sha256", salted).update("Client Key").digest();
    const clientSig = createHmac("sha256", createHash("sha256").update(clientKey).digest())
      .update(authMessage)
      .digest();
    const proof = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) proof[i] = clientKey[i]! ^ clientSig[i]!;

    const r = verifyClientFinal({
      clientFirstBare: cf!.bare,
      serverFirst,
      clientFinal: `${withoutProof},p=${proof.toString("base64")}`,
      expectedNonce: full,
      gs2Header: cf!.gs2Header,
      storedKey: scram.storedKey,
      serverKey: scram.serverKey,
    });
    expect(r.ok).toBe(true);
  });
});

describe("SCRAM 지연 생성", () => {
  test("★옛 행(scrypt만)이 로그인 한 번에 SCRAM 키를 갖게 된다", async () => {
    const db = await openSqlite();
    await migrate(db, allMigrations);
    const accountId = ulid();
    await db.batch([
      {
        sql: "INSERT INTO accounts (id, tenant_id, email, status, quota_bytes, used_bytes, created_at) VALUES (?, ?, ?, 1, 0, 0, ?)",
        params: [accountId, ulid(), "old@x.test", Date.now()],
      },
    ]);
    // 옛 포맷으로 직접 넣는다 — scrypt 세그먼트만.
    const legacy = (await hashSecret("pw")).split(" ")[0]!;
    await db.batch([
      {
        sql: "INSERT INTO credentials (id, account_id, kind, secret, created_at) VALUES (?, ?, 0, ?, ?)",
        params: [ulid(), accountId, legacy, Date.now()],
      },
    ]);

    expect(await authenticate(db, "old@x.test", "pw", "imap")).not.toBeNull();

    // 지연 생성은 베스트에포트(비동기)라 잠깐 기다린다. 인증 성공을 막지 않는 것이 설계다.
    for (let i = 0; i < 40; i++) {
      const { rows } = await db.query({ sql: "SELECT secret FROM credentials WHERE account_id = ?", params: [accountId] });
      if (scramSegment(String(rows[0]?.secret ?? "")) !== null) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const { rows } = await db.query({ sql: "SELECT secret FROM credentials WHERE account_id = ?", params: [accountId] });
    const secret = String(rows[0]?.secret ?? "");
    expect(scramSegment(secret)).not.toBeNull();
    // ★scrypt 세그먼트는 그대로여야 한다 — 비밀번호 저장 강도를 내리지 않는 것이 이 설계의 요점이다.
    expect(secret.startsWith(legacy)).toBe(true);
    expect(await verifySecret("pw", secret)).toBe(true);
    db.close?.();
  });
});
