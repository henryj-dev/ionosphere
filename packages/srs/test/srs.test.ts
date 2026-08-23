/** SRS — 재작성·되돌리기 왕복·해시/타임스탬프 검증·체인(SRS1)·감사 H-3/H-7 회귀. */
import { describe, expect, test } from "@ionosphere/testkit";
import { isSrsAddress, srsForward, srsReverse } from "@ionosphere/srs";

const opts = { secret: "test-secret-key" };
const DAY = 86_400_000;
const now = 1_700_000_000_000; // 고정 기준시각

/** SRS 주소의 해시 필드(로컬파트 두 번째 필드)를 꺼낸다. */
function hashOf(srsAddress: string): string {
  return srsAddress.split("@")[0]!.split("=")[1]!;
}

describe("SRS0 왕복", () => {
  test("forward → SRS0 형식, reverse → 원 발신자", () => {
    const fwd = srsForward("alice@origin.example", "fwd.mine", { ...opts, now });
    expect(fwd).toMatch(/^SRS0=[A-Z2-7]+=[A-Z2-7]{2}=origin\.example=alice@fwd\.mine$/);
    expect(isSrsAddress(fwd)).toBe(true);
    const rev = srsReverse(fwd, { ...opts, now });
    expect(rev).toEqual({ ok: true, address: "alice@origin.example" });
  });

  test("로컬파트에 '='가 있어도 복원", () => {
    const fwd = srsForward("a=b@origin.example", "fwd.mine", { ...opts, now });
    expect(srsReverse(fwd, { ...opts, now })).toEqual({ ok: true, address: "a=b@origin.example" });
  });

  test("해시 변조 → bad-hash", () => {
    const fwd = srsForward("alice@origin.example", "fwd.mine", { ...opts, now });
    const tampered = fwd.replace(/^SRS0=..../, "SRS0=XXXX");
    expect(srsReverse(tampered, { ...opts, now }).ok).toBe(false);
    expect(srsReverse(tampered, { ...opts, now })).toMatchObject({ reason: "bad-hash" });
  });

  test("다른 secret으로는 되돌릴 수 없음", () => {
    const fwd = srsForward("alice@origin.example", "fwd.mine", { ...opts, now });
    expect(srsReverse(fwd, { secret: "other", now }).ok).toBe(false);
  });

  test("maxAge 초과 → expired", () => {
    const fwd = srsForward("alice@origin.example", "fwd.mine", { ...opts, now });
    const later = now + 30 * DAY;
    expect(srsReverse(fwd, { ...opts, now: later, maxAgeDays: 21 })).toMatchObject({ ok: false, reason: "expired" });
    // 창 안(20일)이면 성공
    expect(srsReverse(fwd, { ...opts, now: now + 20 * DAY, maxAgeDays: 21 }).ok).toBe(true);
  });
});

describe("SRS1 체인(재포워딩)", () => {
  test("이미 SRS0인 발신자를 재포워딩 → SRS1, reverse는 원 포워더의 SRS0 반환", () => {
    // A 포워더가 만든 SRS0 주소가 B 포워더로 다시 포워딩되는 상황
    const srs0 = srsForward("alice@origin.example", "a.fwd", { ...opts, now }); // SRS0=..@a.fwd
    const srs1 = srsForward(srs0, "b.fwd", { ...opts, now });
    expect(srs1).toMatch(/^SRS1=[A-Z2-7]+=[A-Z2-7]{2}=a\.fwd=.+@b\.fwd$/);
    // b.fwd가 되돌리면 a.fwd의 SRS0 주소가 나와야 함
    const rev = srsReverse(srs1, { ...opts, now });
    expect(rev.ok).toBe(true);
    if (rev.ok) {
      expect(rev.address).toMatch(/^SRS0=.+@a\.fwd$/);
      // 그 SRS0을 a.fwd가 되돌리면 최종 원 발신자
      expect(srsReverse(rev.address, { ...opts, now })).toEqual({ ok: true, address: "alice@origin.example" });
    }
  });

  test("SRS1 재포워딩(SRS1 → SRS1)도 원 포워더 보존", () => {
    const srs0 = srsForward("alice@origin.example", "a.fwd", { ...opts, now });
    const srs1 = srsForward(srs0, "b.fwd", { ...opts, now });
    const srs1b = srsForward(srs1, "c.fwd", { ...opts, now });
    expect(srs1b).toMatch(/^SRS1=[A-Z2-7]+=[A-Z2-7]{2}=a\.fwd=.+@c\.fwd$/);
    const rev = srsReverse(srs1b, { ...opts, now });
    expect(rev.ok && rev.address).toMatch(/^SRS0=.+@a\.fwd$/);
  });
});

describe("비-SRS 처리", () => {
  test("일반 주소 reverse → not-srs", () => {
    expect(srsReverse("bob@plain.example", opts)).toEqual({ ok: false, reason: "not-srs" });
    expect(isSrsAddress("bob@plain.example")).toBe(false);
  });

  test("잘못된 주소 forward → throw", () => {
    expect(() => srsForward("no-at-sign", "fwd.mine", opts)).toThrow();
  });

  test("망가진 SRS0 → bad-format", () => {
    expect(srsReverse("SRS0=onlyhash@fwd.mine", opts)).toMatchObject({ ok: false, reason: "bad-format" });
  });
});

/**
 * H-3 회귀 — 예전 해시는 base64 4글자(24비트)인데 비교 전에 소문자로 접혀 실질 2²¹이었다.
 * `RCPT TO`가 무제한 검증 오라클이라 미인증 원격이 무차별 대입할 수 있었다.
 */
describe("H-3 회귀 — 해시 공간", () => {
  test("해시는 base32 12글자(60비트)다", () => {
    const hash = hashOf(srsForward("alice@origin.example", "fwd.mine", { ...opts, now }));
    expect(hash).toMatch(/^[A-Z2-7]{12}$/);
    expect(hash.length).toBe(12);
    // 32^12 = 2^60 — 예전 실질 2²¹(38^4)과 비교해 2^39배
    expect(Math.round(Math.log2(32 ** hash.length))).toBe(60);
  });

  test("대소문자 접힘이 공간을 줄이지 않는다 — 알파벳에 대소문자 쌍이 없다", () => {
    // 해시가 A-Z/2-7만 쓰므로 소문자 정규화는 서로 다른 두 심볼을 하나로 합치지 못한다.
    // base64였다면 'a'와 'A'가 합쳐져 알파벳이 64→38로 붕괴했다(H-3의 실체).
    for (let i = 0; i < 64; i++) {
      const hash = hashOf(srsForward(`user${i}@origin.example`, "fwd.mine", { ...opts, now }));
      expect(hash).toBe(hash.toUpperCase());
      expect(hash).not.toMatch(/[a-z+/]/);
    }
  });

  test("파이프라인이 주소를 소문자화해도 왕복이 살아 있다", () => {
    // backend.ts runInboundPipeline이 배달 직전 수신자를 통째로 소문자화하므로
    // srsReverse가 보는 주소는 항상 소문자다. 여기가 깨지면 실제 바운스가 전부 드롭된다.
    const srs0 = srsForward("Alice@Origin.Example", "Fwd.Mine", { ...opts, now });
    expect(srsReverse(srs0.toLowerCase(), { ...opts, now })).toMatchObject({ ok: true });
    const srs1 = srsForward(srs0, "b.fwd", { ...opts, now });
    expect(srsReverse(srs1.toLowerCase(), { ...opts, now })).toMatchObject({ ok: true });
  });

  test("길이가 같은 다른 해시·알파벳 밖 문자는 거절", () => {
    const fwd = srsForward("alice@origin.example", "fwd.mine", { ...opts, now });
    const hash = hashOf(fwd);
    // 같은 길이, 유효 알파벳, 값만 다름
    const wrong = hash === "AAAAAAAAAAAA" ? "BBBBBBBBBBBB" : "AAAAAAAAAAAA";
    expect(srsReverse(fwd.replace(hash, wrong), { ...opts, now })).toMatchObject({ reason: "bad-hash" });
    // base32 밖 문자(1·0·8·9는 알파벳에 없다)
    expect(srsReverse(fwd.replace(hash, "111111111111"), { ...opts, now })).toMatchObject({ reason: "bad-hash" });
    // 길이 불일치
    expect(srsReverse(fwd.replace(hash, "AAAA"), { ...opts, now })).toMatchObject({ reason: "bad-hash" });
  });
});

/**
 * 서명 범위에 포워더 도메인이 들어간다 — 예전엔 로컬파트만 서명해서 같은 토큰을
 * 임의 도메인 뒤에 붙여도 통과했고, 그게 오픈 릴레이(C-1)의 뿌리 중 하나였다.
 */
describe("포워더 도메인 바인딩", () => {
  test("같은 로컬파트를 다른 도메인에 붙이면 bad-hash", () => {
    const fwd = srsForward("alice@origin.example", "fwd.mine", { ...opts, now });
    const moved = fwd.replace("@fwd.mine", "@attacker.example");
    expect(srsReverse(moved, { ...opts, now })).toMatchObject({ ok: false, reason: "bad-hash" });
  });

  test("SRS1도 새 포워더 도메인에 묶인다", () => {
    const srs0 = srsForward("alice@origin.example", "a.fwd", { ...opts, now });
    const srs1 = srsForward(srs0, "b.fwd", { ...opts, now });
    expect(srsReverse(srs1.replace("@b.fwd", "@evil.example"), { ...opts, now })).toMatchObject({
      ok: false,
      reason: "bad-hash",
    });
  });

  test("도메인 대소문자 차이는 통과한다(도메인은 대소문자 무시)", () => {
    const fwd = srsForward("alice@origin.example", "fwd.mine", { ...opts, now });
    expect(srsReverse(fwd.replace("@fwd.mine", "@FWD.MINE"), { ...opts, now })).toMatchObject({ ok: true });
  });
});

/** H-7 회귀 — SRS1에는 타임스탬프도 만료 검사도 없어 secret 회전까지 영구 유효한 릴레이 토큰이었다. */
describe("H-7 회귀 — SRS1 만료", () => {
  test("SRS1도 maxAge를 넘기면 expired", () => {
    const srs0 = srsForward("alice@origin.example", "a.fwd", { ...opts, now });
    const srs1 = srsForward(srs0, "b.fwd", { ...opts, now });
    expect(srsReverse(srs1, { ...opts, now: now + 20 * DAY, maxAgeDays: 21 }).ok).toBe(true);
    expect(srsReverse(srs1, { ...opts, now: now + 30 * DAY, maxAgeDays: 21 })).toMatchObject({
      ok: false,
      reason: "expired",
    });
  });

  test("만료된 SRS0을 SRS1으로 승격해도 되살아나지 않는다", () => {
    const srs0 = srsForward("alice@origin.example", "a.fwd", { ...opts, now });
    const late = now + 30 * DAY; // SRS0은 이미 만료된 시점
    const promoted = srsForward(srs0, "b.fwd", { ...opts, now: late });
    // 바깥 tt는 갓 찍혔지만 안쪽 SRS0의 tt가 30일 전이라 거절돼야 한다
    expect(srsReverse(promoted, { ...opts, now: late, maxAgeDays: 21 })).toMatchObject({
      ok: false,
      reason: "expired",
    });
  });

  test("SRS1 → SRS1 재서명이 시계를 리셋하지 않는다", () => {
    const srs0 = srsForward("alice@origin.example", "a.fwd", { ...opts, now });
    const srs1 = srsForward(srs0, "b.fwd", { ...opts, now });
    // 15일 뒤 체인을 한 홉 더 돌려도 만료 시계는 최초 발급 기준으로 흐른다
    const rechained = srsForward(srs1, "c.fwd", { ...opts, now: now + 15 * DAY });
    expect(srsReverse(rechained, { ...opts, now: now + 25 * DAY, maxAgeDays: 21 })).toMatchObject({
      ok: false,
      reason: "expired",
    });
  });

  test("타임스탬프 없는 구 형식 SRS1은 수용하지 않는다", () => {
    // 구 형식: SRS1=hash=srsdomain=guts (tt 없음). 하위 호환을 넣으면 H-7이 그대로 남는다.
    const legacy = "SRS1=AAAAAAAAAAAA=a.fwd=BBBB=NN=origin.example=alice@b.fwd";
    expect(srsReverse(legacy, { ...opts, now }).ok).toBe(false);
  });
});
