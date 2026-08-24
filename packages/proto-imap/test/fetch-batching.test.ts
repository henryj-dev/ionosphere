/**
 * FETCH·SEARCH 배치 회귀 — **한 번에 몇 통을 백엔드에 요청하는가**.
 *
 * 예전엔 메일함 **전체** uid를 한 요청에 실었고, 백엔드가 그만큼의 블롭을 전부 메모리에
 * 올렸다: `UID FETCH 1:* BODY[]`나 `SEARCH BODY "x"` 한 줄이 5만 통 × 50KB = 2.5GB다.
 * 전 프로토콜이 단일 프로세스라 그 순간 서비스 전체가 위태로워진다.
 *
 * 그래서 이 파일은 응답 내용이 아니라 **요청 크기**를 본다 — 결과가 맞는지는 기존
 * fetch/store-search 테스트가 이미 지킨다.
 */
import { describe, test } from "node:test";
import { expect } from "@ionosphere/testkit";
import { ImapEngine, type ImapAction, type ImapBackendRequest, type ImapFetchData } from "@ionosphere/proto-imap";

const enc = new TextEncoder();
const TOTAL = 500;
const UIDS = Array.from({ length: TOTAL }, (_, i) => i + 1);
const RAW = enc.encode("From: a@x.test\r\nSubject: s\r\n\r\nbody\r\n");

/** 엔진을 selected 상태까지 몰고 가면서, 백엔드 요청의 uid 개수를 전부 기록한다. */
function drive(command: string, opts: { withRaw: boolean } = { withRaw: true }): number[] {
  const sizes: number[] = [];
  const e = new ImapEngine({ hostname: "imap.test", secure: true });

  const answer = (req: ImapBackendRequest): Parameters<ImapEngine["backendResult"]>[0] => {
    if (req.kind === "selectMailbox") {
      return {
        kind: "selected",
        mailbox: {
          name: "INBOX",
          role: "inbox",
          uidvalidity: 1,
          uidnext: TOTAL + 1,
          highestmodseq: 1,
          totalCount: TOTAL,
          unreadCount: 0,
          totalBytes: 0,
        },
        uids: UIDS,
        firstUnseenSeq: null,
      };
    }
    if (req.kind === "fetchMessages") {
      sizes.push(req.uids.length);
      const messages: ImapFetchData[] = req.uids.map((uid) => ({
        uid,
        flags: [],
        internalDateMs: 0,
        size: RAW.length,
        modseq: 1,
        ...(opts.withRaw && req.needRaw ? { raw: RAW } : {}),
      }));
      return { kind: "messages", messages };
    }
    return { kind: "ok" };
  };

  // 액션에 백엔드 요청이 있으면 즉시 답해 연쇄를 끝까지 돌린다.
  const pump = (actions: ImapAction[]): void => {
    for (const a of actions) {
      if (a.kind === "backend") pump(e.backendResult(answer(a.req)));
    }
  };

  pump(e.feed(enc.encode('a1 LOGIN u p\r\n')));
  pump(e.authResult({ accountId: "acct" }));
  pump(e.feed(enc.encode('a2 SELECT INBOX\r\n')));
  sizes.length = 0; // SELECT 단계의 요청은 세지 않는다
  pump(e.feed(enc.encode(command)));
  return sizes;
}

describe("FETCH·SEARCH 배치", () => {
  test("UID FETCH 1:* BODY[] — 원문 요청은 작은 배치로 나뉜다", () => {
    const sizes = drive("a3 UID FETCH 1:* BODY[]\r\n");
    expect(sizes.length > 1).toBe(true); // 한 방에 다 가져오지 않는다
    expect(Math.max(...sizes) <= 32).toBe(true); // FETCH_BATCH_RAW
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(TOTAL); // 하나도 빠뜨리지 않는다
  });

  test("UID FETCH 1:* FLAGS — 메타데이터는 더 큰 배치", () => {
    const sizes = drive("a3 UID FETCH 1:* FLAGS\r\n");
    expect(Math.max(...sizes) <= 512).toBe(true); // FETCH_BATCH_META
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(TOTAL);
  });

  test("SEARCH BODY — 원문이 필요한 검색도 나뉜다", () => {
    const sizes = drive('a3 SEARCH BODY "body"\r\n');
    expect(sizes.length > 1).toBe(true);
    expect(Math.max(...sizes) <= 32).toBe(true);
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(TOTAL);
  });

  test("SEARCH ALL — 메타데이터만 필요한 검색", () => {
    const sizes = drive("a3 SEARCH ALL\r\n");
    expect(Math.max(...sizes) <= 512).toBe(true);
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(TOTAL);
  });

  /** 배치 경계에서 seq 번호가 어긋나면 클라이언트가 다른 메시지를 가리킨다. */
  test("배치를 넘어가도 seq 번호가 이어진다", () => {
    const e = new ImapEngine({ hostname: "imap.test", secure: true });
    const out: string[] = [];
    const answer = (req: ImapBackendRequest): Parameters<ImapEngine["backendResult"]>[0] => {
      if (req.kind === "selectMailbox") {
        return {
          kind: "selected",
          mailbox: { name: "INBOX", role: "inbox", uidvalidity: 1, uidnext: TOTAL + 1, highestmodseq: 1, totalCount: TOTAL, unreadCount: 0, totalBytes: 0 },
          uids: UIDS,
          firstUnseenSeq: null,
        };
      }
      if (req.kind === "fetchMessages") {
        return {
          kind: "messages",
          messages: req.uids.map((uid) => ({ uid, flags: [], internalDateMs: 0, size: 1, modseq: 1 })),
        };
      }
      return { kind: "ok" };
    };
    const pump = (actions: ImapAction[]): void => {
      for (const a of actions) {
        if (a.kind === "backend") pump(e.backendResult(answer(a.req)));
        else if (a.kind === "replyBinary") out.push(Buffer.from(a.bytes).toString("latin1").trim());
      }
    };
    pump(e.feed(enc.encode("a1 LOGIN u p\r\n")));
    pump(e.authResult({ accountId: "acct" }));
    pump(e.feed(enc.encode("a2 SELECT INBOX\r\n")));
    out.length = 0;
    // BODY[]로 요청해 **작은 배치(32)** 경계를 여러 번 넘게 한다 — 500통이면 16번 나뉜다.
    pump(e.feed(enc.encode("a3 UID FETCH 1:* BODY.PEEK[HEADER]\r\n")));

    expect(out).toHaveLength(TOTAL);
    // seq는 1부터 끊김 없이 이어져야 한다 — 어긋나면 클라이언트가 다른 메시지를 가리킨다.
    out.forEach((line, i) => {
      expect(line.startsWith(`* ${i + 1} FETCH`)).toBe(true);
    });
  });
});
