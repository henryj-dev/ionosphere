/**
 * node 전용 접근 프로토콜 STARTTLS 프로브 — 143(IMAP STARTTLS)·110(POP3 STLS).
 * 테스트 러너가 아니라 **하위 프로세스**로 실행된다(managesieve-starttls-probe와 같은 규율).
 *
 * 왜 별도 프로세스인가: 서버측 TLS 업그레이드는 bun ≤1.3.14에서 완료되지 않는다
 * (oven-sh/bun#25044). 그래서 조립층이 그 런타임에서는 STARTTLS를 **자동으로 끈다** —
 * bun에서 돌리면 "광고 안 됨"이 정상 동작이라 **기능 부재와 구분되지 않는다.**
 * 라이브는 node이므로(운영 저장소의 systemd 유닛) node에서 반드시 잡혀 있어야 한다.
 *
 * 고정하는 것: 평문 143/110이 STARTTLS·STLS를 광고하고, 평문에서는 인증이 여전히 막혀 있으며,
 * **업그레이드 후 로그인이 성공한다.** 이 경로가 죽으면 두 포트는 "연결은 되는데 로그인은
 * 영원히 불가능한" 상태가 된다 — 오류가 아니라 기능 없음이라 아무도 소리치지 않고,
 * 사용자는 "비밀번호가 틀렸다"고 생각한다.
 *
 * ★인프로세스로 앱을 띄운다(하위 프로세스 spawn 아님). 예전엔 main.ts를 spawn하고 고정 3.5초를
 * 기다렸는데, 그 12초가 **다른 테스트의 5초 타임아웃을 밀어내** 전체 실행에서만 Sieve 테스트가
 * 무더기로 실패했다(단독 실행은 통과 — 진단이 가장 어려운 형태다).
 *
 * 정상이면 exit 0, 어긋나면 사유를 stderr에 남기고 exit 1.
 */
import { SOCKET_DEADLINE_MS } from "@ionosphere/testkit";
import { connect } from "node:net";
import * as tls from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSignedCertSource } from "@ionosphere/tls";
import { IonosphereApp } from "../src/app.ts";
// helpers.ts는 `bun:` import가 없어 node에서도 그대로 로드된다 — 리졸버를 복제하지 않는다.
import { offlineResolver } from "./helpers.ts";

const USER = "u@starttls.test.local";
const PASS = "pw-starttls";

function fail(msg: string): never {
  process.stderr.write(`프로브 실패: ${msg}\n`);
  process.exit(1);
}

/** 평문으로 한 덩어리 보내고 응답을 모은다. */
function plain(port: number, send: string, waitMs = 400): Promise<string> {
  return new Promise((resolve, reject) => {
    let out = "";
    const s = connect(port, "127.0.0.1", () => s.write(send));
    s.on("data", (c) => (out += c.toString()));
    s.on("error", reject);
    setTimeout(() => {
      s.destroy();
      resolve(out);
    }, waitMs);
  });
}

/**
 * 평문으로 붙어 업그레이드 명령을 보낸 뒤 **같은 소켓을 TLS로 승격**하고 이어서 명령을 보낸다.
 * 실제 클라이언트(Thunderbird 등)가 하는 일이고, 어댑터의 소켓 교체는 이 경로로만 드러난다.
 *
 * ★청크 경계를 신뢰하지 않고 **단계**로 진행한다. 서버는 인사말과 업그레이드 응답을 각각
 * 별도 청크로 보내는데(실측), 버퍼 누적으로 판정하면 인사말 단계에서 조건이 참이 되어
 * 명령 전에 승격하고, 남은 평문이 TLS 레코드로 읽혀 `ERR_SSL_WRONG_VERSION_NUMBER`가 난다.
 */
function upgrade(port: number, startCmd: string, okMark: string, after: string, waitMs = 500): Promise<string> {
  return new Promise((resolve, reject) => {
    const raw = connect(port, "127.0.0.1");
    let phase: "greeting" | "starting" = "greeting";
    let upgraded = false;
    const onData = (c: Buffer): void => {
      const text = c.toString();
      if (phase === "greeting") {
        phase = "starting";
        raw.write(startCmd);
        return;
      }
      if (!text.includes(okMark)) return;
      upgraded = true;
      raw.removeListener("data", onData);
      const secure = tls.connect({ socket: raw, rejectUnauthorized: false }, () => secure.write(after));
      let out = "";
      secure.on("data", (b: Buffer) => (out += b.toString()));
      secure.on("error", reject);
      setTimeout(() => {
        secure.destroy();
        resolve(out);
      }, waitMs);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    /**
     * ★업그레이드가 오지 않으면 **끊고 실패시킨다.** 없으면 프로브가 영원히 매달려 실패가
     * "멈춤"으로 나타난다(뮤테이션 검증에서 실제로 그랬다). 기능 부재는 타임아웃이 아니라
     * 메시지로 드러나야 한다.
     */
    setTimeout(() => {
      if (upgraded) return;
      raw.destroy();
      reject(new Error(`업그레이드 응답 없음(${okMark} 미도달) — STARTTLS/STLS가 광고·수락되지 않는다`));
    }, SOCKET_DEADLINE_MS);
  });
}

const tlsDir = mkdtempSync(join(tmpdir(), "ionosphere-access-tls-"));
const blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-access-blobs-"));

const app = new IonosphereApp({
  hostname: "starttls.test.local",
  dbPath: ":memory:",
  blobRoot,
  imapPort: 0,
  pop3Port: 0,
  // 라이브와 같은 형태: certSource만 채우고 전역 tls는 비운다.
  certSource: selfSignedCertSource({ commonName: "starttls.test.local", sans: ["starttls.test.local"], dir: tlsDir }),
  resolver: offlineResolver(),
  runMtaWorker: false,
  runWebhookWorker: false,
  runReaper: false,
  blobGcMode: "off",
});
await app.start();
await app.createUser(USER, PASS);

// ── IMAP 143 ──────────────────────────────────────────────
const imapCaps = await plain(app.imapPort, "a1 CAPABILITY\r\n");
if (!imapCaps.includes("STARTTLS")) fail(`IMAP 평문 CAPABILITY에 STARTTLS가 없다: ${JSON.stringify(imapCaps.slice(0, 160))}`);
if (!imapCaps.includes("LOGINDISABLED")) fail("IMAP 평문에서 LOGINDISABLED가 빠졌다 — 평문 인증이 열렸다면 위험하다");

const imapLogin = await upgrade(app.imapPort, "a1 STARTTLS\r\n", "a1 OK", `a2 LOGIN ${USER} ${PASS}\r\n`);
if (!imapLogin.includes("a2 OK")) fail(`IMAP STARTTLS 후 LOGIN 실패: ${JSON.stringify(imapLogin.slice(0, 160))}`);

const imapTwice = await upgrade(app.imapPort, "a1 STARTTLS\r\n", "a1 OK", "a2 STARTTLS\r\n");
if (!/a2 (BAD|NO)/.test(imapTwice)) fail(`IMAP 이중 STARTTLS가 거절되지 않았다: ${JSON.stringify(imapTwice.slice(0, 160))}`);

// ── POP3 110 ──────────────────────────────────────────────
const popCaps = await plain(app.pop3Port, "CAPA\r\n");
if (!popCaps.includes("STLS")) fail(`POP3 평문 CAPA에 STLS가 없다: ${JSON.stringify(popCaps.slice(0, 160))}`);
if (/^USER\r?$/m.test(popCaps)) fail("POP3 평문 CAPA가 USER를 광고한다 — 시도 후 실패로 자격증명 오해를 부른다");

const popPlain = await plain(app.pop3Port, `USER ${USER}\r\n`);
if (!popPlain.includes("-ERR")) fail(`POP3 평문 USER가 거부되지 않았다: ${JSON.stringify(popPlain.slice(0, 160))}`);
if (!popPlain.toLowerCase().includes("tls")) fail("POP3 평문 USER 거부 사유에 TLS 안내가 없다");

const popLogin = await upgrade(app.pop3Port, "STLS\r\n", "+OK", `USER ${USER}\r\nPASS ${PASS}\r\nSTAT\r\n`);
if (!/maildrop has \d+ messages/.test(popLogin)) fail(`POP3 STLS 후 로그인 실패: ${JSON.stringify(popLogin.slice(0, 160))}`);

await app.stop();
rmSync(tlsDir, { recursive: true, force: true });
rmSync(blobRoot, { recursive: true, force: true });
process.exit(0);
