/**
 * 리스너 정상 종료 — 열린 연결을 끊고 close를 끝낸다.
 *
 * **왜 필요한가**(2026-07-30 실사고): `server.close(cb)`는 node 의미상 "새 연결만 막고,
 * **기존 연결이 전부 끝나면** 콜백"이다. IMAP IDLE처럼 오래 붙어 있는 연결이 하나만 있어도
 * 콜백이 영영 오지 않는다. 그래서 SIGTERM 핸들러가 `app.stop()`에서 멈췄고 systemd가 90초 뒤
 * SIGKILL했다 — 배포마다 SQLite가 쓰기 도중 죽고 배달 중이던 큐 리스가 정리되지 않았다.
 *
 * `closeAllConnections()`는 **http.Server에만** 있다. 메일 리스너는 net/tls.Server라 쓸 수 없다
 * (실측: bun 1.3.14 · node 24 둘 다 `undefined`). 그래서 소켓을 직접 추적한다.
 *
 * **한 곳에 두는 이유**: 리스너가 10종이라 각자 Set을 들면 한 곳만 빠뜨려도 그 리스너 하나가
 * 종료 전체를 막는다. 그리고 그 사실은 배포 때까지 드러나지 않는다.
 */
import type { Server, Socket } from "node:net";

/** 추적 중인 리스너를 닫는 손잡이. */
export interface ListenerShutdown {
  /**
   * 리스너를 닫고 남은 연결을 끊는다.
   *
   * 남은 연결을 **기다리지 않고 끊는** 이유: 종료는 빠르고 결정적이어야 한다. 기다리면
   * "얼마나?"가 생기고, 그 시간이 systemd 타임아웃을 넘으면 결국 SIGKILL이라 나아지는 게 없다.
   * 끊어도 유실은 없다 — DATA 도중이면 상대가 250을 못 받아 재전송하고, IMAP은 재접속한다.
   */
  close(): Promise<void>;
}

/**
 * 리스너의 활성 소켓을 추적하고 정상 종료 손잡이를 돌려준다.
 *
 * `listen()` **전에** 부르는 것이 안전하다 — 그 사이에 붙은 연결을 놓치지 않는다.
 * TLS 서버도 `connection`(원시 소켓)이 먼저 뜨므로 그것만 추적하면 된다. STARTTLS로 승격해도
 * 원시 소켓을 끊으면 그 위의 TLS 세션도 함께 끊긴다.
 */
export function trackListener(server: Server): ListenerShutdown {
  const sockets = new Set<Socket>();
  server.on("connection", (socket: Socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  return {
    close(): Promise<void> {
      return new Promise((resolve, reject) => {
        if (!server.listening && sockets.size === 0) {
          resolve();
          return;
        }
        let settled = false;
        server.close((err) => {
          if (settled) return;
          settled = true;
          if (err) reject(err);
          else resolve();
        });
        // close()는 새 연결만 막는다 — 남은 것을 끊어야 콜백이 온다.
        for (const socket of sockets) socket.destroy();
        sockets.clear();
      });
    },
  };
}
