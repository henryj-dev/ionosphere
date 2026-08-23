/**
 * DNSSEC 검증 리졸버 — 루트 신뢰앵커부터 위임 체인을 따라 서명을 검증한다.
 *
 * 존재 이유는 **DANE 하나**다. TLSA 레코드는 검증되지 않으면 쓸 수 없다 — DNS를 속일 수 있는
 * 공격자가 TLSA를 심으면 우리가 그의 인증서를 고정하게 되고, DANE가 막으려던 공격이 DANE를
 * 통해 성립한다. 그래서 "검증했다"를 타입으로 돌려주는 물건이 필요하다.
 *
 * `RecursiveResolver`(iterative)와 나란히 두고 합치지 않은 이유:
 * 저쪽은 **주소를 얻는 것**이 목적이라 실패 시 계속 진행해야 하고, 이쪽은 **판정을 내리는 것**이
 * 목적이라 애매하면 멈춰야 한다. 한 클래스에 두 규율을 담으면 한쪽이 반드시 느슨해진다.
 *
 * ★한계 — **NSEC/NSEC3를 구현하지 않았다.** 그래서 "레코드가 없다"를 **안전하게 증명하지
 * 못한다**. 공격자가 DS를 지우면 우리는 "서명되지 않은 위임"으로 보고 `insecure`를 돌려주고,
 * 호출부는 DANE를 적용하지 않는다 — 즉 DANE 도입 **이전 동작(opportunistic TLS)**으로 되돌아갈
 * 뿐이다. 같은 공격자는 TLSA를 지우는 것으로도 같은 결과를 얻으므로 새로 생긴 구멍이 아니다.
 * 반대로 **잘못된 TLSA를 신뢰하는 경로는 없다** — 그것이 이 모듈이 지켜야 하는 성질이다.
 */
import { randomInt } from "node:crypto";
import { RecursiveResolver } from "./resolver.ts";
import { UdpTcpTransport, type DnsTransport } from "./transport.ts";
import { dsMatchesKey, verifyRrset } from "./dnssec.ts";
import { decodeMessage, encodeQuery, RCode, RRType, type DnsMessage, type DnsRecord, type RData } from "./wire.ts";

type DsRdata = Extract<RData, { kind: "DS" }>;
type DnskeyRdata = Extract<RData, { kind: "DNSKEY" }>;

/**
 * IANA 루트 신뢰앵커(root-anchors.xml). DS 형식이라 `dsMatchesKey`를 그대로 쓴다.
 *
 * 둘을 다 두는 이유: KSK-2017은 아직 폐기되지 않았고 KSK-2024가 롤오버 중이다. 한쪽만 두면
 * 롤오버가 끝나는 날(또는 되돌려지는 날) 전 세계 배달이 조용히 opportunistic으로 떨어진다.
 */
const ROOT_ANCHORS: readonly DsRdata[] = [
  {
    kind: "DS",
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digest: hexBytes("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
  },
  {
    kind: "DS",
    keyTag: 38696,
    algorithm: 8,
    digestType: 2,
    digest: hexBytes("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
  },
];

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** IANA 루트 서버(a~m). `resolver.ts`와 같은 목록이지만 저쪽 상수는 비공개다. */
const ROOT_HINTS: readonly string[] = [
  "198.41.0.4",
  "170.247.170.2",
  "192.33.4.12",
  "199.7.91.13",
  "192.203.230.10",
  "192.5.5.241",
  "192.112.36.4",
  "198.97.190.53",
  "192.36.148.17",
  "192.58.128.30",
  "193.0.14.129",
  "199.7.83.42",
  "202.12.27.33",
];

/** 위임 단계 상한 — 이름의 라벨 수를 넘길 일이 없다. 무한 위임 루프 방어. */
const MAX_DELEGATIONS = 24;

export type ValidatedAnswer =
  /** 루트 앵커까지 서명이 이어졌다. `records`는 요청한 타입의 RRset. */
  | { status: "secure"; records: readonly DnsRecord[] }
  /** 서명이 없거나(비서명 존) 증명할 수 없다 — **조작 신호가 아니다**. */
  | { status: "insecure"; reason: string }
  /** 서명이 **있는데 맞지 않는다** — 조작 신호. */
  | { status: "bogus"; reason: string };

export interface ValidatingResolverOptions {
  rootHints?: readonly string[];
  timeoutMs?: number;
  transport?: DnsTransport;
  randomId?: () => number;
  /** 신뢰앵커 교체(테스트·사설 루트). 기본 IANA 루트. */
  trustAnchors?: readonly DsRdata[];
  /** 현재 시각(ms). 서명 유효기간 판정에 쓴다. 테스트 주입용. */
  now?: () => number;
  /**
   * 서버 목록에 질의하는 함수(DO=1). 테스트가 와이어를 거치지 않고 시나리오를 구성하도록 연다.
   * 기본 구현은 `transport`로 UDP→(TC면) TCP.
   */
  query?: (servers: readonly string[], name: string, qtype: number) => Promise<DnsMessage>;
}

function normName(name: string): string {
  return name.toLowerCase().replace(/\.$/, "");
}

/** `a.b.c` → 이 이름이 속할 수 있는 존 경계 후보. 위임을 따라갈 때 방향 확인용. */
function isSubOrEqual(child: string, parent: string): boolean {
  const c = normName(child);
  const p = normName(parent);
  if (p === "") return true; // 루트
  return c === p || c.endsWith(`.${p}`);
}

export class ValidatingResolver {
  private readonly rootHints: readonly string[];
  private readonly timeoutMs: number;
  private readonly transport: DnsTransport;
  private readonly randomId: () => number;
  private readonly anchors: readonly DsRdata[];
  private readonly now: () => number;
  private readonly queryFn: (servers: readonly string[], name: string, qtype: number) => Promise<DnsMessage>;
  /** NS 이름에 글루가 없을 때 주소를 얻는 용도. **주소는 신뢰 대상이 아니다**(서명이 신뢰 대상). */
  private readonly addrResolver: RecursiveResolver;

  constructor(opts?: ValidatingResolverOptions) {
    this.rootHints = opts?.rootHints ?? ROOT_HINTS;
    this.timeoutMs = opts?.timeoutMs ?? 5000;
    this.transport = opts?.transport ?? new UdpTcpTransport();
    this.randomId = opts?.randomId ?? (() => randomInt(0, 0x10000));
    this.anchors = opts?.trustAnchors ?? ROOT_ANCHORS;
    this.now = opts?.now ?? (() => Date.now());
    this.queryFn = opts?.query ?? ((servers, name, qtype) => this.queryServers(servers, name, qtype));
    this.addrResolver = new RecursiveResolver({
      rootHints: this.rootHints,
      timeoutMs: this.timeoutMs,
      ...(opts?.transport ? { transport: opts.transport } : {}),
    });
  }

  /**
   * 이름·타입을 해석하고 **루트까지 서명 체인을 검증**한다.
   *
   * 던지지 않는다 — 조회 실패도 판정의 일부(`insecure`)다. 호출부가 try/catch와 상태 분기를
   * 둘 다 다루게 하면 한쪽이 빠진다.
   */
  async validated(name: string, qtype: number): Promise<ValidatedAnswer> {
    try {
      return await this.walk(name, qtype);
    } catch (err) {
      // 조회 실패는 **조작 신호가 아니다**. bogus로 올리면 상대 DNS가 흔들릴 때마다
      // 배달이 멈춘다.
      return { status: "insecure", reason: `조회 실패: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  private async walk(name: string, qtype: number): Promise<ValidatedAnswer> {
    const target = normName(name);
    let servers: readonly string[] = this.rootHints;
    let zone = "";
    let keys = await this.rootKeys();
    if (keys.status !== "secure") return keys.answer;
    let zoneKeys: readonly DnsRecord[] = keys.keys;

    for (let step = 0; step < MAX_DELEGATIONS; step++) {
      const msg = await this.queryFn(servers, target, qtype);
      if (msg.header.rcode === RCode.NXDOMAIN) {
        // 부재 증명(NSEC/NSEC3) 미구현 — "없다"를 검증하지 못한다.
        return { status: "insecure", reason: "NXDOMAIN — 부재를 검증할 수 없다" };
      }
      if (msg.header.rcode !== RCode.NOERROR) {
        return { status: "insecure", reason: `RCODE=${msg.header.rcode}` };
      }

      const answers = msg.answers.filter((r) => r.type === qtype && r.class === 1 && normName(r.name) === target);
      if (answers.length > 0) {
        const sigs = rrsigsFor(msg.answers, target, qtype);
        const v = verifyRrset(answers, sigs, zoneKeys, this.now());
        if (v.status === "secure") return { status: "secure", records: answers };
        return { status: v.status, reason: v.reason };
      }

      // CNAME은 검증 대상이 하나 더 늘어난다(체인 각 단계의 서명). TLSA/MX에 CNAME은
      // 규격 위반이라 여기서는 지원하지 않고 정직하게 미검증으로 돌린다.
      if (msg.answers.some((r) => r.type === RRType.CNAME)) {
        return { status: "insecure", reason: "CNAME 체인은 검증하지 않는다" };
      }

      const nsRecords = msg.authorities.filter((r) => r.type === RRType.NS && r.rdata.kind === "NS");
      if (nsRecords.length === 0) {
        return { status: "insecure", reason: "NODATA — 부재를 검증할 수 없다" };
      }

      const child = normName(nsRecords[0]!.name);
      // 위임은 반드시 아래로 내려가야 한다. 옆이나 위로 가는 위임은 조작이거나 고장이다.
      if (!isSubOrEqual(target, child) || (zone !== "" && !isSubOrEqual(child, zone)) || child === zone) {
        return { status: "insecure", reason: `위임 방향이 이상하다: ${zone || "."} → ${child}` };
      }

      const dsRecords = msg.authorities.filter((r) => r.type === RRType.DS && normName(r.name) === child);
      if (dsRecords.length === 0) {
        /**
         * ★서명되지 않은 위임. 여기서부터 아래는 DNSSEC 보호를 받지 않는다.
         * NSEC/NSEC3가 없어 "DS가 정말 없는지"를 증명하지 못하므로 조작 가능성이 남지만,
         * 결과는 "DANE 미적용"이라 공격자가 얻는 것은 **원래 상태**다(모듈 머리말 참고).
         */
        return { status: "insecure", reason: `서명되지 않은 위임: ${child}` };
      }
      const dsV = verifyRrset(dsRecords, rrsigsFor(msg.authorities, child, RRType.DS), zoneKeys, this.now());
      if (dsV.status !== "secure") return { status: dsV.status, reason: `DS 검증 실패(${child}): ${dsV.reason}` };

      servers = await this.nextServers(msg, nsRecords);
      if (servers.length === 0) return { status: "insecure", reason: `위임 NS 주소 없음: ${child}` };

      const childKeys = await this.zoneKeys(child, servers, dsRecords);
      if (childKeys.status !== "secure") return childKeys.answer;
      zoneKeys = childKeys.keys;
      zone = child;
    }
    return { status: "insecure", reason: "위임 상한 초과" };
  }

  /** 루트 DNSKEY를 받아 신뢰앵커(DS)로 검증한다. 체인의 출발점. */
  private async rootKeys(): Promise<{ status: "secure"; keys: readonly DnsRecord[] } | { status: "fail"; answer: ValidatedAnswer }> {
    const msg = await this.queryFn(this.rootHints, ".", RRType.DNSKEY);
    return this.validateDnskeySet(".", msg, this.anchors);
  }

  /** 자식 존의 DNSKEY를 받아 부모가 서명한 DS로 검증한다. */
  private async zoneKeys(
    zone: string,
    servers: readonly string[],
    dsRecords: readonly DnsRecord[],
  ): Promise<{ status: "secure"; keys: readonly DnsRecord[] } | { status: "fail"; answer: ValidatedAnswer }> {
    const msg = await this.queryFn(servers, zone, RRType.DNSKEY);
    const ds = dsRecords.map((r) => r.rdata).filter((d): d is DsRdata => d.kind === "DS");
    return this.validateDnskeySet(zone, msg, ds);
  }

  /**
   * DNSKEY RRset 검증 — 두 단계를 **둘 다** 해야 한다.
   * 1. DS가 가리키는 키(KSK)가 이 집합 안에 있는가
   * 2. 그 KSK가 **이 집합 전체에 서명**했는가
   *
   * ★2를 빼면 공격자가 자기 ZSK를 집합에 끼워 넣고 그것으로 아래를 전부 위조할 수 있다.
   * DS는 KSK 하나만 고정하므로, 나머지 키의 정당성은 KSK 서명으로만 나온다.
   */
  private validateDnskeySet(
    zone: string,
    msg: DnsMessage,
    ds: readonly DsRdata[],
  ): { status: "secure"; keys: readonly DnsRecord[] } | { status: "fail"; answer: ValidatedAnswer } {
    const target = normName(zone);
    const keyRrs = msg.answers.filter((r) => r.type === RRType.DNSKEY && normName(r.name) === target);
    if (keyRrs.length === 0) {
      return { status: "fail", answer: { status: "insecure", reason: `DNSKEY 없음: ${zone}` } };
    }
    const anchored = keyRrs.filter((r) => {
      const k = r.rdata;
      if (k.kind !== "DNSKEY") return false;
      return ds.some((d) => dsMatchesKey(d, target, k as DnskeyRdata));
    });
    if (anchored.length === 0) {
      return { status: "fail", answer: { status: "bogus", reason: `DS와 맞는 DNSKEY 없음: ${zone}` } };
    }
    const v = verifyRrset(keyRrs, rrsigsFor(msg.answers, target, RRType.DNSKEY), anchored, this.now());
    if (v.status !== "secure") {
      return { status: "fail", answer: { status: v.status, reason: `DNSKEY 자체서명 실패(${zone}): ${v.reason}` } };
    }
    return { status: "secure", keys: keyRrs };
  }

  /** 위임 응답에서 다음 서버 주소(글루 우선, 없으면 NS 이름 해석). */
  private async nextServers(msg: DnsMessage, nsRecords: readonly DnsRecord[]): Promise<readonly string[]> {
    const nsNames = new Set<string>();
    for (const r of nsRecords) {
      if (r.rdata.kind === "NS") nsNames.add(normName(r.rdata.target));
    }
    const glue: string[] = [];
    for (const r of msg.additionals) {
      if (r.class !== 1) continue;
      if ((r.rdata.kind === "A" || r.rdata.kind === "AAAA") && nsNames.has(normName(r.name))) {
        glue.push(r.rdata.address);
      }
    }
    if (glue.length > 0) return glue;

    for (const nsName of nsNames) {
      try {
        return await this.addrResolver.a(nsName);
      } catch {
        // 다음 NS 이름 시도.
      }
    }
    return [];
  }

  /** 기본 질의 — 서버를 순회하며 DO=1로 묻는다. */
  private async queryServers(servers: readonly string[], name: string, qtype: number): Promise<DnsMessage> {
    let lastErr: unknown = new Error(`질의할 서버 없음: ${name}`);
    for (const server of servers) {
      try {
        const id = this.randomId() & 0xffff;
        const packet = encodeQuery(id, name, qtype, false, true);
        let raw = await this.transport.queryUdp(server, packet, this.timeoutMs);
        let msg = decodeMessage(raw);
        if (msg.header.tc) {
          raw = await this.transport.queryTcp(server, packet, this.timeoutMs);
          msg = decodeMessage(raw);
        }
        if (msg.header.id !== id) throw new Error(`트랜잭션 ID 불일치 ${server}`);
        const q = msg.questions[0];
        if (!q || normName(q.name) !== normName(name) || q.type !== qtype) {
          throw new Error(`질문 불일치 ${server}`);
        }
        return msg;
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }
}

/** 주어진 이름·타입을 덮는 RRSIG만 고른다. */
function rrsigsFor(records: readonly DnsRecord[], owner: string, covered: number): DnsRecord[] {
  return records.filter(
    (r) => r.type === RRType.RRSIG && normName(r.name) === normName(owner) && r.rdata.kind === "RRSIG" && r.rdata.typeCovered === covered,
  );
}
