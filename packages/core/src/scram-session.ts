/**
 * SCRAM-SHA-256 **서버 세션 상태머신** — 프로토콜 중립. I/O 없음.
 *
 * SMTP·IMAP·POP3·ManageSieve가 각자 SCRAM을 구현하면 네 벌이 미묘하게 갈린다. 이 저장소는
 * 이미 그 대가를 치렀다(SASL 파싱을 갈래마다 두었다가 `@ionosphere/core/sasl.ts`로 올렸다).
 * 그래서 교환 규칙은 여기 한 곳에 두고, 엔진은 **줄을 넣고 지시를 받는** 역할만 한다.
 *
 * 흐름:
 *   start(clientFirst) → {need:"lookup", username}      // 어댑터가 저장된 키를 찾아온다
 *   provideKeys(keys|null) → {send: serverFirst}
 *   final(clientFinal) → {ok, send: serverFinal} | {ok:false}
 */
import {
  buildServerFirst,
  parseClientFirst,
  serverNonce,
  verifyClientFinal,
  SCRAM_DEFAULT_ITERATIONS,
} from "./scram.ts";
import { createHmac } from "node:crypto";

/** 저장소에서 찾아온 SCRAM 파라미터. */
export interface ScramStoredKeys {
  iterations: number;
  salt: Buffer;
  storedKey: Buffer;
  serverKey: Buffer;
}

export type ScramStep =
  | { need: "lookup"; username: string }
  | { need: "send"; message: string }
  | { need: "done"; ok: true; username: string; message: string }
  /**
   * 실패. **`username`을 함께 돌려주는 이유는 감사·스로틀 때문이다.**
   *
   * ★과거 이 값이 없어서 SCRAM 증명 실패가 무기록으로 지나갔다. 엔진은 거절 응답만 내고
   * (`authVerified`를 emit하지 않으므로) 어댑터의 `authThrottle.recordFailure`·`audit.record`가
   * 아예 실행되지 않았다 — 즉 SCRAM으로는 **무제한 비밀번호 추측이 로그 한 줄 없이** 가능했다.
   * 실패를 기록하려면 "누구로 시도했는지"가 필요하고, 그 값을 아는 곳은 여기뿐이다.
   *
   * client-first 파싱 자체가 실패하면 사용자명을 알 수 없어 undefined다(자격증명을 시험한
   * 것이 아니라 형식이 틀린 경우다 — 둘을 구분할 수 있어야 한다).
   */
  | { need: "failed"; username?: string };

/**
 * ★계정이 없거나 SCRAM 키가 없을 때도 **교환을 끝까지 진행한다.**
 *
 * 여기서 즉시 실패를 돌려주면 "그 사용자가 없다" 또는 "그 사용자는 SCRAM을 못 쓴다"가
 * 응답 시점만으로 새어 나간다 — 계정 열거(enumeration)다. RFC 5802 §7이 지목하는 지점이고,
 * 해법은 **사용자명에서 결정적으로 만든 가짜 salt**로 정상 형태의 server-first를 보내고
 * proof 검증에서 실패시키는 것이다. 같은 사용자명에는 항상 같은 salt가 나와야 한다 —
 * 매번 다르면 재시도만으로 "진짜가 아니다"가 드러난다.
 */
function fakeKeys(username: string, secret: Buffer): ScramStoredKeys {
  const salt = createHmac("sha256", secret).update(`salt:${username}`).digest().subarray(0, 16);
  return {
    iterations: SCRAM_DEFAULT_ITERATIONS,
    salt,
    // 어떤 proof로도 맞을 수 없는 값 — 검증은 반드시 실패한다.
    storedKey: createHmac("sha256", secret).update(`stored:${username}`).digest(),
    serverKey: createHmac("sha256", secret).update(`server:${username}`).digest(),
  };
}

export class ScramServerSession {
  private state: "init" | "awaitingKeys" | "awaitingFinal" | "closed" = "init";
  private clientFirstBare = "";
  private gs2Header = "";
  private username = "";
  /** 두 조각을 **따로** 보관한다 — 합친 문자열에서 길이로 잘라내면 nonce 길이가 바뀔 때 조용히 깨진다. */
  private clientNonce = "";
  private serverNoncePart = "";
  private fullNonce = "";
  private serverFirst = "";
  private keys: ScramStoredKeys | null = null;
  /** 가짜 salt 유도용 서버 비밀 — 프로세스마다 다르면 재시작 전후로 salt가 달라진다. */
  private readonly decoySecret: Buffer;

  constructor(decoySecret: Buffer) {
    this.decoySecret = decoySecret;
  }

  /** client-first를 넣는다. 형식이 틀리면 즉시 실패(교환을 시작하지도 않았다). */
  start(clientFirst: string): ScramStep {
    if (this.state !== "init") return this.fail();
    const cf = parseClientFirst(clientFirst);
    if (!cf) return this.fail();
    this.clientFirstBare = cf.bare;
    this.gs2Header = cf.gs2Header;
    this.username = cf.username;
    this.clientNonce = cf.clientNonce;
    this.serverNoncePart = serverNonce();
    this.fullNonce = `${this.clientNonce}${this.serverNoncePart}`;
    this.state = "awaitingKeys";
    return { need: "lookup", username: cf.username };
  }

  /** 저장된 키(없으면 null). null이어도 **교환은 계속된다** — 위 fakeKeys 주석 참조. */
  provideKeys(keys: ScramStoredKeys | null): ScramStep {
    if (this.state !== "awaitingKeys") return this.fail();
    this.keys = keys ?? fakeKeys(this.username, this.decoySecret);
    this.serverFirst = buildServerFirst({
      clientNonce: this.clientNonce,
      serverNonce: this.serverNoncePart,
      salt: this.keys.salt,
      iterations: this.keys.iterations,
    });
    this.state = "awaitingFinal";
    return { need: "send", message: this.serverFirst };
  }

  /** client-final을 넣는다. 성공이면 server-final을 함께 돌려준다. */
  final(clientFinal: string): ScramStep {
    if (this.state !== "awaitingFinal" || !this.keys) return this.fail();
    const v = verifyClientFinal({
      clientFirstBare: this.clientFirstBare,
      serverFirst: this.serverFirst,
      clientFinal,
      expectedNonce: this.fullNonce,
      gs2Header: this.gs2Header,
      storedKey: this.keys.storedKey,
      serverKey: this.keys.serverKey,
    });
    this.state = "closed";
    if (!v.ok || !v.serverFinal) return this.fail();
    return { need: "done", ok: true, username: this.username, message: v.serverFinal };
  }

  /**
   * 실패로 닫는다. `username`은 **알고 있을 때만** 싣는다 — client-first를 파싱하기도 전에
   * 실패하면 빈 문자열이 남아 감사 로그에 `user: ""`가 찍힌다(모르는 것과 빈 값은 다르다).
   */
  private fail(): ScramStep {
    this.state = "closed";
    return { need: "failed", ...(this.username ? { username: this.username } : {}) };
  }
}
