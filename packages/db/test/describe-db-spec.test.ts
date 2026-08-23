/**
 * 연결 문자열 마스킹 — **비밀번호가 로그로 나가지 않는지.**
 *
 * ★이 함수가 틀리면 되돌릴 수 없다. 로그는 journald·감사 파일·오브젝트 스토리지로 흘러가고,
 * 그 뒤에 지운다 해도 이미 복사된 곳들을 회수할 방법이 없다. DB 비밀번호는 그 자체로 전
 * 테넌트 메일 접근이라 대가가 가장 크다.
 *
 * 정본을 `@ionosphere/db`에 둔 이유도 같다 — 예전엔 `cli.ts`와 `scripts/migrate-to-sql.ts`가 같은
 * 정규식을 각자 들고 있었고, 마스킹을 잊은 **세 번째 자리**가 생기는 순간 새어 나간다.
 */
import { describe, expect, test } from "@ionosphere/testkit";
import { describeDbSpec } from "../src/open.ts";

describe("describeDbSpec", () => {
  test("★비밀번호를 지운다 — 호스트·포트·DB 이름은 남긴다", () => {
    const out = describeDbSpec("postgres://postgres:s3cret-pw@10.0.192.42:5432/postgres");
    expect(out).not.toContain("s3cret-pw");
    // 감출 것만 감춘다 — "어느 DB를 보는가"에 답하지 못하면 이 로그의 존재 이유가 사라진다.
    expect(out).toContain("10.0.192.42:5432/postgres");
    expect(out).toContain("<자격증명>");
  });

  test("★비밀번호에 특수문자가 들어가도 샌 곳이 없다", () => {
    // URL에 들어갈 수 있는 문자들(인코딩된 @·/·: 포함)로 만든 값.
    for (const pw of ["a%40b", "p:w/d", "!#$%^&*()", "한글비밀번호", "x".repeat(64)]) {
      const out = describeDbSpec(`postgres://user:${pw}@db.internal:5432/mail`);
      expect(out).not.toContain(pw);
      expect(out).toContain("db.internal:5432/mail");
    }
  });

  test("사용자명만 있고 비밀번호가 없어도 지운다", () => {
    // 사용자명도 계정 정보다 — 남겨 둘 이유가 없고, 남기면 대입 공격의 절반이 공짜가 된다.
    const out = describeDbSpec("mysql://ionosphere@db.internal:3306/mail");
    expect(out).not.toContain("ionosphere@");
    expect(out).toContain("db.internal:3306/mail");
  });

  test("★파일 경로는 그대로 둔다 — 감출 것이 없고, 감추면 진단이 불가능해진다", () => {
    expect(describeDbSpec("/var/lib/ionosphere/ionosphere.db")).toBe("/var/lib/ionosphere/ionosphere.db");
    expect(describeDbSpec("sqlite:/var/lib/ionosphere/ionosphere.db")).toBe("sqlite:/var/lib/ionosphere/ionosphere.db");
    expect(describeDbSpec(":memory:")).toBe(":memory:");
  });

  test("자격증명이 없는 URL은 건드리지 않는다", () => {
    expect(describeDbSpec("postgres://db.internal:5432/mail")).toBe("postgres://db.internal:5432/mail");
  });

  test("★인코딩되지 않은 @가 비밀번호에 있어도 새지 않는다 — 그 대가로 호스트가 가려질 수 있다", () => {
    /**
     * `p@ss`처럼 `@`가 인코딩되지 않으면 어디까지가 비밀번호인지 URL만으로는 알 수 없다.
     * 그래서 **마지막 `@`**까지 가린다 — 진단 정보를 조금 잃더라도 자격증명을 남기지 않는다.
     */
    const leaky = describeDbSpec("postgres://user:p@ss@db.internal:5432/mail");
    expect(leaky).not.toContain("p@ss");
    expect(leaky).not.toContain("ss@db");

    /**
     * 그 대가: 자격증명이 없는데 **경로에** `@`가 있으면 호스트까지 가려진다.
     * 드문 형태이고(DB 이름에 `@`), 반대 방향의 실수(비밀번호 노출)는 되돌릴 수 없다.
     */
    expect(describeDbSpec("postgres://db.internal:5432/mail@backup")).toBe("postgres://<자격증명>@backup");
  });
});
