/**
 * "이 연결이 **내부 인터페이스로** 들어왔는가" 판정 — 443 vhost의 노출 정책(`exposure`)용.
 *
 * 입력은 소켓의 **로컬** 주소(`socket.localAddress`)다. 즉 커널이 알려주는 "연결이 착지한
 * 우리 쪽 인터페이스 주소"이지, 상대가 보낸 값이 아니다. 이 구분이 이 파일의 전제다.
 *
 * ★왜 `@ionosphere/webhook`의 `isBlockedAddress`를 쓰지 않는가 — 두 가지가 다르다.
 *
 * ① **위협 모델이 다르다.** 웹훅 가드의 입력은 **공격자가 정하는** URL·DNS 응답이라
 *    `[::ffff:a9fe:a9fe]`(IPv4-매핑)·6to4·NAT64 같은 별표기로 우회를 시도한다 — 감사 M-14에서
 *    실제로 뚫린 경로다. 여기 입력은 커널이 채우므로 그런 난독화가 성립하지 않는다.
 *    (그래도 IPv4-매핑은 다룬다. 듀얼스택 `*` 바인딩에서 커널이 실제로 `::ffff:10.0.101.12`
 *    형태로 준다 — 실측 확인.)
 * ② **의미가 다르다.** 저쪽은 "SSRF 목적지로 금지"이고 여기는 "내부 인터페이스"다. 지금은
 *    집합이 겹치지만, 한쪽 목록을 넓히는 변경이 다른 쪽의 **접근 통제**를 조용히 움직이면
 *    안 된다. 같은 이유로 이 판정을 웹훅 쪽에 위임하지 않는다.
 *
 * ⚠ 이것은 방화벽의 **대체가 아니라 이중화**다. 라이브 방화벽(heliopause)은 중앙에서 관리돼
 * 우리가 통제하지 못하므로, 앱이 한 겹 더 막는다.
 */

/** 사설·루프백·링크로컬 IPv4 대역인가. */
function isPrivateV4(a: number, b: number): boolean {
  if (a === 10) return true; // 사설 10/8 — 이 배포의 VPC(10.17)와 메시(10.254)가 여기다
  if (a === 127) return true; // 루프백
  if (a === 172 && b >= 16 && b <= 31) return true; // 사설 172.16/12
  if (a === 192 && b === 168) return true; // 사설 192.168/16
  if (a === 169 && b === 254) return true; // 링크로컬
  return false;
}

/**
 * 이 로컬 주소가 내부 인터페이스인가. **판정할 수 없으면 false**(= 공개로 간주, fail closed).
 *
 * 판정 불가를 "내부"로 읽으면 주소를 못 읽는 상황에서 관리 표면이 통째로 열린다.
 * 반대로 읽으면 최악이 "관리 콘솔이 안 열린다"이고, 그건 되돌릴 수 있는 실패다.
 */
export function isPrivateLocalAddress(addr: string | undefined): boolean {
  if (!addr) return false;
  const s = addr.trim().toLowerCase();
  if (s === "::1") return true; // IPv6 루프백

  // IPv4-매핑 IPv6(`::ffff:10.0.101.12`) — 듀얼스택 바인딩에서 커널이 주는 형태다.
  const mapped = s.startsWith("::ffff:") ? s.slice("::ffff:".length) : s;

  const v4 = mapped.split(".");
  if (v4.length === 4) {
    const nums = v4.map((p) => (/^[0-9]{1,3}$/.test(p) ? Number(p) : -1));
    if (nums.some((n) => n < 0 || n > 255)) return false;
    return isPrivateV4(nums[0] ?? -1, nums[1] ?? -1);
  }

  // ULA fc00::/7 — 첫 헥스텟의 상위 7비트가 1111110.
  const head = s.split(":")[0] ?? "";
  if (/^[0-9a-f]{1,4}$/.test(head)) {
    const first = Number.parseInt(head, 16);
    if ((first & 0xfe00) === 0xfc00) return true; // ULA
    if ((first & 0xffc0) === 0xfe80) return true; // 링크로컬 fe80::/10
  }
  return false;
}
