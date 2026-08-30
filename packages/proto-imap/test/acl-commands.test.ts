import { describe, expect, test } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapBackendResponse } from "../src/engine.ts";

const enc = new TextEncoder();

function authed(): ImapEngine {
  const engine = new ImapEngine({ hostname: "imap.test", allowInsecureAuth: true });
  engine.feed(enc.encode("a0 LOGIN u p\r\n"));
  engine.authResult({ accountId: "acc" });
  return engine;
}

function replies(actions: ImapAction[]): string[] {
  return actions.filter((action): action is { kind: "reply"; text: string } => action.kind === "reply").map((action) => action.text);
}

function run(engine: ImapEngine, command: string, response: ImapBackendResponse): { request: ImapBackendRequest; output: string[] } {
  const actions = engine.feed(enc.encode(command));
  const backend = actions.find((action): action is { kind: "backend"; req: ImapBackendRequest } => action.kind === "backend");
  if (!backend) throw new Error("backend action missing");
  return { request: backend.req, output: replies(engine.backendResult(response)) };
}

describe("IMAP ACL commands", () => {
  test("GETACL은 identifier/right 쌍을 반환한다", () => {
    const result = run(authed(), "a1 GETACL Shared\r\n", { kind: "acl", mailbox: "Shared", entries: [{ identifier: "p1", rights: "lrkxte" }] });
    expect(result.request).toEqual({ kind: "getAcl", name: "Shared" });
    expect(result.output).toEqual(["* ACL \"Shared\" p1 lrkxte", "a1 OK GETACL completed"]);
  });

  test("SETACL·DELETEACL은 identifier와 rights를 backend에 그대로 전달한다", () => {
    const engine = authed();
    const set = run(engine, "a1 SETACL Shared p1 lrcd\r\n", { kind: "ok" });
    expect(set.request).toEqual({ kind: "setAcl", name: "Shared", identifier: "p1", rights: "lrcd" });
    expect(set.output[0]).toBe("a1 OK SETACL completed");
    const del = run(engine, "a2 DELETEACL Shared p1\r\n", { kind: "ok" });
    expect(del.request).toEqual({ kind: "deleteAcl", name: "Shared", identifier: "p1" });
    expect(del.output[0]).toBe("a2 OK DELETEACL completed");
  });

  test("LISTRIGHTS·MYRIGHTS는 빈 권리도 정상 응답한다", () => {
    const engine = authed();
    const listed = run(engine, "a1 LISTRIGHTS Shared p1\r\n", { kind: "rights", mailbox: "Shared", identifier: "p1", rights: "" });
    expect(listed.output).toEqual(["* LISTRIGHTS \"Shared\" p1 \"\" ", "a1 OK LISTRIGHTS completed"]);
    const mine = run(engine, "a2 MYRIGHTS Shared\r\n", { kind: "rights", mailbox: "Shared", identifier: "p1", rights: "lr" });
    expect(mine.request).toEqual({ kind: "myRights", name: "Shared" });
    expect(mine.output).toEqual(["* MYRIGHTS \"Shared\" lr", "a2 OK MYRIGHTS completed"]);
  });
});
