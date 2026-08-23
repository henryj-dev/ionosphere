import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { DnsNotFoundError, type DnsResolver } from "@ionosphere/mail-auth";

/** 실 DNS를 타지 않는 오프라인 리졸버 — 모든 조회를 NotFound로 (SPF/DKIM/DMARC → none). */
export function offlineResolver(): DnsResolver {
  const nf = (): never => {
    throw new DnsNotFoundError("offline");
  };
  return {
    txt: async () => nf(),
    mx: async () => nf(),
    a: async () => nf(),
    aaaa: async () => nf(),
    ptr: async () => nf(),
  };
}

/**
 * SMTP 대화 헬퍼 — **테스트 플레이크의 정본 수정**.
 *
 * 각 테스트 파일이 손으로 짠 SMTP 클라이언트가 두 가지를 가정하고 있었다:
 *  ① 멀티라인 응답(EHLO의 `250-…`)이 **한 번의 data 이벤트로** 도착한다
 *  ② 버퍼에 응답이 하나만 들어 있다(`buf = ""`로 통째로 버렸다)
 * 둘 다 TCP가 보장하지 않는다. 평소엔 맞아떨어지다가 부하가 걸려 세그먼트가 쪼개지거나
 * 두 응답이 붙어 오면 명령을 한 박자 일찍 보내 대화가 어긋나고, 그대로 멈춰
 * **bun의 5초 테스트 타임아웃**에 걸렸다. 전체 스위트를 돌릴 때만 간헐 실패하던 원인이다.
 *
 * 그래서 여기서는 줄 단위로 읽고, **응답의 마지막 줄(4번째 문자가 공백)에서만** 다음 명령을
 * 보낸다. 남은 바이트는 버리지 않고 버퍼에 유지한다.
 */
export interface SmtpReply {
  code: number;
  /** 응답 마지막 줄 전문(진단용). */
  text: string;
}

export interface SmtpDeliverOptions {
  port: number;
  from: string;
  to: string | readonly string[];
  /** 메시지 원문. 개행은 CRLF로 정규화된다. */
  data: string;
  ehlo?: string;
  /** 지정 시 EHLO 직후 AUTH PLAIN. */
  auth?: { user: string; pass: string };
  /** 465류 암시적 TLS로 접속(자체서명 허용). */
  implicitTls?: boolean;
  servername?: string;
  timeoutMs?: number;
}

export interface SmtpDeliverResult {
  /** RCPT TO 응답들(수신자 순서). */
  rcpt: SmtpReply[];
  /** 마지막 응답 — 정상 흐름이면 DATA 종료(`250`), 중단됐으면 그 지점의 오류 응답. */
  final: SmtpReply;
}

/**
 * 한 통을 배달하고 각 단계 응답을 돌려준다. 프로토콜 오류(4xx/5xx)는 **던지지 않고**
 * `final`에 담아 반환한다 — 거절을 검증하는 테스트가 예외를 잡을 필요 없게.
 * 연결 실패·타임아웃만 reject한다.
 */
export function smtpDeliver(opts: SmtpDeliverOptions): Promise<SmtpDeliverResult> {
  const rcpts = typeof opts.to === "string" ? [opts.to] : [...opts.to];
  const body = opts.data.replace(/\r?\n/g, "\r\n");
  return new Promise((resolve, reject) => {
    const sock = opts.implicitTls
      ? tlsConnect({
          port: opts.port,
          host: "127.0.0.1",
          rejectUnauthorized: false,
          ...(opts.servername ? { servername: opts.servername } : {}),
        })
      : netConnect(opts.port, "127.0.0.1");
    sock.setEncoding("utf8");

    const rcptReplies: SmtpReply[] = [];
    let buf = "";
    let rcptIdx = 0;
    /** 대화 단계 — 응답 한 개마다 하나씩 전진한다. */
    let stage: "greet" | "ehlo" | "auth" | "mail" | "rcpt" | "data" | "body" | "done" = "greet";

    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`smtpDeliver timeout (stage=${stage})`));
    }, opts.timeoutMs ?? 20_000);

    const finish = (reply: SmtpReply): void => {
      clearTimeout(timer);
      try {
        sock.write("QUIT\r\n");
      } catch {
        // 이미 닫힌 소켓 — 결과에는 영향 없다.
      }
      sock.end();
      resolve({ rcpt: rcptReplies, final: reply });
    };

    const onReply = (reply: SmtpReply): void => {
      // 4xx/5xx는 그 지점에서 대화를 끝낸다(거절 검증용).
      if (reply.code >= 400 && stage !== "greet") {
        if (stage === "rcpt") rcptReplies.push(reply);
        finish(reply);
        return;
      }
      switch (stage) {
        case "greet":
          stage = "ehlo";
          sock.write(`EHLO ${opts.ehlo ?? "client.test"}\r\n`);
          return;
        case "ehlo":
          if (opts.auth) {
            stage = "auth";
            sock.write(`AUTH PLAIN ${Buffer.from(`\0${opts.auth.user}\0${opts.auth.pass}`).toString("base64")}\r\n`);
            return;
          }
          stage = "mail";
          sock.write(`MAIL FROM:<${opts.from}>\r\n`);
          return;
        case "auth":
          stage = "mail";
          sock.write(`MAIL FROM:<${opts.from}>\r\n`);
          return;
        case "mail":
          stage = "rcpt";
          sock.write(`RCPT TO:<${rcpts[rcptIdx]}>\r\n`);
          return;
        case "rcpt":
          rcptReplies.push(reply);
          rcptIdx++;
          if (rcptIdx < rcpts.length) {
            sock.write(`RCPT TO:<${rcpts[rcptIdx]}>\r\n`);
            return;
          }
          stage = "data";
          sock.write("DATA\r\n");
          return;
        case "data":
          stage = "body";
          sock.write(`${body}\r\n.\r\n`);
          return;
        case "body":
          stage = "done";
          finish(reply);
          return;
        default:
          return;
      }
    };

    sock.on("data", (chunk: string) => {
      buf += chunk;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2); // ★남은 바이트를 버리지 않는다
        // 멀티라인 응답은 마지막 줄만 "완료"다. `250-`는 계속, `250 `는 끝.
        if (line.length >= 4 && line[3] === "-") continue;
        onReply({ code: Number(line.slice(0, 3)), text: line });
        if (stage === "done") return;
      }
    });
    sock.on("error", (e: Error) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

/**
 * IonosphereApp을 통째로 띄우는 훅(`beforeAll`/`afterAll`)에 주는 타임아웃.
 *
 * bun의 기본 테스트 타임아웃은 5초다. 파일 하나만 돌리면 앱 기동이 300ms대지만, 전체 스위트를
 * 연속으로 돌리는 동안 머신이 포화되면 이 훅이 간헐적으로 5초를 넘겼다. 훅이 실패하면
 * **그 파일의 모든 테스트가 한꺼번에 실패**한다(`(unnamed)` 항목이 섞여 나오는 게 신호였다).
 * 실측: 5초에서 10회 중 2회 실패.
 *
 * ★전역으로 올리지 않고 이 훅들에만 주는 이유: 순수 유닛 테스트까지 25초를 주면 진짜 무한 대기가
 * 25초 뒤에야 드러난다. 느려질 수 있는 건 "소켓 여러 개 + 마이그레이션"을 하는 기동 훅뿐이라
 * 거기에만 여유를 준다. (bunfig.toml의 `[test] timeout`은 bun 1.3.14가 무시한다 — 실측 확인.)
 */
export const E2E_HOOK_TIMEOUT_MS = 25_000;

/**
 * node 하위 프로세스 프로브의 판정 정본 — 성공이면 `"status=0"`을 돌려준다.
 *
 * 왜 함수로 두는가: 프로브 테스트가 두 곳(managesieve-starttls·https-front)에 있고, 둘 다
 * `status=${r.status} ${r.stderr}`를 손으로 조립해 `"status=0"`과 비교하고 있었다. 그래서
 * **node가 stderr에 찍는 무해한 경고 한 줄이 테스트 실패로 나왔다** — 로컬 node 26은
 * 조용하지만 CI의 node 24는 `ExperimentalWarning: SQLite is an experimental feature`를 찍어,
 * 프로브가 exit 0으로 성공했는데도 CI만 빨간불이 됐다(2026-07-31 자동배포 게이트가 잡았다).
 *
 * stderr를 아예 버리지 않는 이유: 프로브가 죽었을 때 스택이 유일한 진단 정보다. 그래서
 * **런타임 잡음만** 걸러내고 나머지는 그대로 남긴다 — 실패는 여전히 원인과 함께 보인다.
 */
export function probeVerdict(r: { status: number | null; stderr?: string | null; error?: Error | undefined }): string {
  const noise = [
    // node --experimental 계열 경고. 버전이 올라가며 나타나거나 사라지므로 판정에서 제외한다.
    /^\(node:\d+\) ExperimentalWarning: .*$/,
    /^\(Use `node --trace-warnings \.\.\.` to show where the warning was created\)$/,
  ];
  const stderr = (r.stderr ?? "")
    .split("\n")
    .filter((line) => line.trim() !== "" && !noise.some((re) => re.test(line.trim())))
    .join("\n");
  return `${r.error ? `node 실행 실패: ${String(r.error)}` : ""}status=${r.status} ${stderr}`.trim();
}

/** 프로브가 성공했을 때 probeVerdict가 돌려주는 값. */
export const PROBE_OK = "status=0";
