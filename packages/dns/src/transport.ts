/**
 * DNS 전송 계층 — node:dgram(UDP 512바이트) + node:net(TCP, TC 비트 폴백).
 * 리졸버는 이 인터페이스에만 의존하므로 테스트에서 mock transport를 주입해
 * 재귀/위임 로직을 네트워크 없이 결정적으로 검증한다.
 */
import { createSocket } from "node:dgram";
import { connect, isIP } from "node:net";
import { DnsTemporaryError } from "@ionosphere/mail-auth";

/**
 * 응답 데이터그램의 **출처가 우리가 물어본 서버인지** 판정.
 *
 * 왜 필요한가: UDP 소켓은 바인딩된 포트로 오는 **아무 데이터그램이나** 받는다. 출처를 확인하지
 * 않으면 off-path 공격자가 포트와 트랜잭션 ID만 맞히면 위조 응답을 심을 수 있고, 그 결과는
 * 캐시에 들어가 SPF/DKIM/DMARC/MTA-STS 판정 근거가 된다 — 캐시 포이즈닝이 곧 인증 우회다.
 *
 * `server`가 리터럴 IP일 때만 강제한다. 호스트명으로 설정된 업스트림은 OS가 해석한 주소로
 * 응답이 오므로 문자열 비교가 성립하지 않는다 — 그 구성까지 깨뜨리지 않으려는 절충이고,
 * 실제 공격 표면(루트힌트·IP로 지정한 업스트림)은 전부 리터럴 IP라 보호된다.
 */
export function isExpectedSource(server: string, from: string): boolean {
  if (isIP(server) === 0) return true; // 호스트명 설정 — 비교 불가, 검사 생략
  return normalizeAddr(server) === normalizeAddr(from);
}

/** IPv4-mapped IPv6 표기 차이만 흡수한다(`::ffff:1.2.3.4` ↔ `1.2.3.4`). */
function normalizeAddr(addr: string): string {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  return (m ? m[1]! : addr).toLowerCase();
}

export interface DnsTransport {
  /** UDP 질의 — 응답 원시 바이트 반환. 타임아웃/네트워크 오류는 DnsTemporaryError. */
  queryUdp(server: string, packet: Uint8Array, timeoutMs: number): Promise<Uint8Array>;
  /** TCP 질의 — TC(truncated) 응답 재시도용. 2바이트 길이 프리픽스 프레이밍. */
  queryTcp(server: string, packet: Uint8Array, timeoutMs: number): Promise<Uint8Array>;
}

/** 실제 소켓 기반 전송(53번 포트 고정). */
export class UdpTcpTransport implements DnsTransport {
  queryUdp(server: string, packet: Uint8Array, timeoutMs: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const socket = createSocket(server.includes(":") ? "udp6" : "udp4");
      let done = false;
      const finish = (fn: () => void): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try {
          socket.close();
        } catch {
          // 이미 닫힘 — 무시
        }
        fn();
      };
      const timer = setTimeout(() => finish(() => reject(new DnsTemporaryError(`UDP 타임아웃 ${server}`))), timeoutMs);
      // 출처가 다른 데이터그램은 **버리고 계속 기다린다**(finish하지 않는다) — 위조 시도 하나로
      // 정상 응답까지 놓치면 공격자가 해석을 막는 수단을 얻는다. 타임아웃이 종료를 책임진다.
      socket.on("message", (msg, rinfo) => {
        if (!isExpectedSource(server, rinfo.address)) return;
        finish(() => resolve(new Uint8Array(msg)));
      });
      socket.on("error", (err) => finish(() => reject(new DnsTemporaryError(`UDP 오류 ${server}: ${String(err)}`))));
      socket.send(packet, 53, server, (err) => {
        if (err) finish(() => reject(new DnsTemporaryError(`UDP 전송 실패 ${server}: ${String(err)}`)));
      });
    });
  }

  queryTcp(server: string, packet: Uint8Array, timeoutMs: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const socket = connect({ host: server, port: 53 });
      const chunks: Buffer[] = [];
      let expected = -1;
      let done = false;
      const finish = (fn: () => void): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        socket.destroy();
        fn();
      };
      const timer = setTimeout(() => finish(() => reject(new DnsTemporaryError(`TCP 타임아웃 ${server}`))), timeoutMs);
      socket.on("connect", () => {
        const framed = Buffer.alloc(2 + packet.length);
        framed.writeUInt16BE(packet.length, 0);
        framed.set(packet, 2);
        socket.write(framed);
      });
      socket.on("data", (d: Buffer) => {
        chunks.push(d);
        const buf = Buffer.concat(chunks);
        if (expected < 0 && buf.length >= 2) expected = buf.readUInt16BE(0);
        if (expected >= 0 && buf.length >= 2 + expected) {
          finish(() => resolve(new Uint8Array(buf.subarray(2, 2 + expected))));
        }
      });
      socket.on("error", (err) => finish(() => reject(new DnsTemporaryError(`TCP 오류 ${server}: ${String(err)}`))));
      socket.on("close", () => finish(() => reject(new DnsTemporaryError(`TCP 조기 종료 ${server}`))));
    });
  }
}
