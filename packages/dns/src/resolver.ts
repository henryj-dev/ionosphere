/**
 * 재귀 DNS 리졸버 — @ionosphere/mail-auth의 DnsResolver 계약 구현.
 *
 * 목적: Spamhaus 등 주요 DNSBL은 퍼블릭 리졸버(8.8.8.8/1.1.1.1) 경유 조회를 차단한다
 * (조용히 "미등재"로 응답 → 무력화). 그래서 루트힌트부터 authoritative 서버를 직접 따라가는
 * **iterative(반복) 리졸버**를 자체 구현해 DNSBL을 신뢰성 있게 조회한다.
 *
 * 모드:
 * - iterative(기본): 루트 → TLD → authoritative를 위임(referral) 따라가며 직접 질의(RD=0).
 * - upstream(opts.upstreams 지정 시): 주어진 재귀 리졸버에 RD=1로 위임(테스트/특수 환경용).
 *
 * 와이어 포맷 조립/파싱은 wire.ts(순수)에, 소켓은 transport.ts에 분리했다.
 * 에러 매핑(dnsbl.ts가 의존): NXDOMAIN/NODATA → DnsNotFoundError,
 * SERVFAIL/타임아웃/네트워크/포맷오류 → DnsTemporaryError.
 */
import { randomInt } from "node:crypto";
import { DnsNotFoundError, DnsTemporaryError, type DnsMxRecord, type DnsResolver } from "@ionosphere/mail-auth";
import { DnsCache, type DnsCacheOptions } from "./cache.ts";
import { UdpTcpTransport, type DnsTransport } from "./transport.ts";
import {
  decodeMessage,
  encodeQuery,
  ptrQueryName,
  RCode,
  RRType,
  type DnsMessage,
  type DnsRecord,
} from "./wire.ts";

/** IANA 루트 서버 A 레코드(2024 기준, a~m). */
const DEFAULT_ROOT_HINTS: readonly string[] = [
  "198.41.0.4", // a.root-servers.net
  "170.247.170.2", // b
  "192.33.4.12", // c
  "199.7.91.13", // d
  "192.203.230.10", // e
  "192.5.5.241", // f
  "192.112.36.4", // g
  "198.97.190.53", // h
  "192.36.148.17", // i
  "192.58.128.30", // j
  "193.0.14.129", // k
  "199.7.83.42", // l
  "202.12.27.33", // m
];

export interface RecursiveResolverOptions {
  /** 루트 서버 IP 목록. 기본 IANA 루트힌트. */
  rootHints?: readonly string[];
  /** 지정 시 iterative 대신 이 재귀 리졸버들에 RD=1로 위임. */
  upstreams?: readonly string[];
  /** 질의당 타임아웃(ms). 기본 3000. */
  timeoutMs?: number;
  /** 서버 하나당 재시도 횟수. 기본 1(총 2회 시도). */
  retriesPerServer?: number;
  /** 캐시 인스턴스 주입(공유/테스트). 미지정 시 내부 생성. */
  cache?: DnsCache;
  /** 캐시 옵션(cache 미지정 시). */
  cacheOptions?: DnsCacheOptions;
  /** 전송 계층 주입(테스트 mock). 기본 UdpTcpTransport. */
  transport?: DnsTransport;
  /** 랜덤 트랜잭션 ID 생성기(테스트 결정성). 기본 crypto 기반. */
  randomId?: () => number;
}

/** 위임(referral) 따라가기 상한 — 무한 위임 루프 방지. */
const MAX_DELEGATIONS = 32;
/** CNAME 체인 상한. */
const MAX_CNAME = 8;
/** 글루 없는 NS 이름 재귀 해석 깊이 상한. */
const MAX_GLUE_DEPTH = 6;
/** 글루 없을 때 실제로 해석 시도할 NS 이름 개수 상한. */
const MAX_NS_RESOLVE = 2;

function normName(name: string): string {
  return name.toLowerCase().replace(/\.$/, "");
}

/** Fisher-Yates — 원본을 건드리지 않는다(호출자가 루트힌트 상수를 넘긴다). */
function shuffled<T>(items: readonly T[]): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

/**
 * 응답의 answer 섹션에서 qname/qtype에 해당하는 레코드를 CNAME 체인을 따라 수집.
 * - records 있으면 최종 답.
 * - cnameTarget 있으면 "체인 끝까지 갔지만 최종 타입 레코드가 이 응답엔 없음"(다른 서버서 재해석 필요).
 */
function collectAnswers(
  msg: DnsMessage,
  qname: string,
  qtype: number,
): { records: DnsRecord[]; cnameTarget: string | null } {
  let name = normName(qname);
  const seen = new Set<string>();
  let followed = false;
  for (;;) {
    const direct = msg.answers.filter(
      (r) => r.type === qtype && r.class === 1 && normName(r.name) === name,
    );
    if (direct.length > 0) return { records: direct, cnameTarget: null };

    const cname = msg.answers.find((r) => r.type === RRType.CNAME && r.class === 1 && normName(r.name) === name);
    if (!cname || cname.rdata.kind !== "CNAME") {
      return { records: [], cnameTarget: followed ? name : null };
    }
    if (seen.has(name)) return { records: [], cnameTarget: null }; // CNAME 루프 방어
    seen.add(name);
    name = normName(cname.rdata.target);
    followed = true;
  }
}

export class RecursiveResolver implements DnsResolver {
  private readonly rootHints: readonly string[];
  private readonly upstreams: readonly string[] | undefined;
  private readonly timeoutMs: number;
  private readonly retriesPerServer: number;
  private readonly cache: DnsCache;
  private readonly transport: DnsTransport;
  private readonly randomId: () => number;

  constructor(opts?: RecursiveResolverOptions) {
    this.rootHints = opts?.rootHints ?? DEFAULT_ROOT_HINTS;
    this.upstreams = opts?.upstreams;
    this.timeoutMs = opts?.timeoutMs ?? 3000;
    this.retriesPerServer = opts?.retriesPerServer ?? 1;
    this.cache = opts?.cache ?? new DnsCache(opts?.cacheOptions);
    this.transport = opts?.transport ?? new UdpTcpTransport();
    // ★Math.random 금지 — V8의 xorshift128+는 출력 몇 개로 내부 상태가 복원돼 다음 ID가
    // 예측된다. 트랜잭션 ID는 위조 응답을 막는 엔트로피의 절반(나머지 절반은 출처 검증)이라
    // 암호학적 난수여야 한다.
    this.randomId = opts?.randomId ?? (() => randomInt(0, 0x10000));
  }

  // ── DnsResolver 계약 구현 ──

  async txt(name: string): Promise<string[]> {
    const records = await this.resolveRecords(name, RRType.TXT);
    const out = records.filter((r) => r.rdata.kind === "TXT").map((r) => (r.rdata as { text: string }).text);
    if (out.length === 0) throw new DnsNotFoundError(`빈 TXT: ${name}`);
    return out;
  }

  async mx(name: string): Promise<DnsMxRecord[]> {
    const records = await this.resolveRecords(name, RRType.MX);
    const out: DnsMxRecord[] = [];
    for (const r of records) {
      if (r.rdata.kind === "MX") out.push({ exchange: r.rdata.exchange, preference: r.rdata.preference });
    }
    if (out.length === 0) throw new DnsNotFoundError(`빈 MX: ${name}`);
    return out;
  }

  async a(name: string): Promise<string[]> {
    const records = await this.resolveRecords(name, RRType.A);
    const out = records.filter((r) => r.rdata.kind === "A").map((r) => (r.rdata as { address: string }).address);
    if (out.length === 0) throw new DnsNotFoundError(`빈 A: ${name}`);
    return out;
  }

  async aaaa(name: string): Promise<string[]> {
    const records = await this.resolveRecords(name, RRType.AAAA);
    const out = records.filter((r) => r.rdata.kind === "AAAA").map((r) => (r.rdata as { address: string }).address);
    if (out.length === 0) throw new DnsNotFoundError(`빈 AAAA: ${name}`);
    return out;
  }

  async ptr(ip: string): Promise<string[]> {
    const qname = ptrQueryName(ip);
    if (!qname) throw new DnsNotFoundError(`잘못된 IP(PTR): ${ip}`);
    const records = await this.resolveRecords(qname, RRType.PTR);
    const out = records.filter((r) => r.rdata.kind === "PTR").map((r) => (r.rdata as { target: string }).target);
    if (out.length === 0) throw new DnsNotFoundError(`빈 PTR: ${ip}`);
    return out;
  }

  // ── 내부 해석 ──

  /** 캐시 확인 후 실제 해석. 캐시 저장까지 담당. */
  private async resolveRecords(name: string, qtype: number): Promise<DnsRecord[]> {
    const cached = this.cache.get(name, qtype);
    if (cached) {
      if (cached.negative) throw new DnsNotFoundError(`캐시(네거티브): ${name}`);
      return cached.records;
    }
    const records = await this.resolveUncached(name, qtype, 0);
    this.cache.setPositive(name, qtype, records);
    return records;
  }

  /** upstream 모드면 위임, 아니면 iterative. 네거티브는 여기서 캐시 후 throw. */
  private async resolveUncached(name: string, qtype: number, depth: number): Promise<DnsRecord[]> {
    if (this.upstreams && this.upstreams.length > 0) {
      return this.resolveViaUpstream(name, qtype);
    }
    return this.resolveIterative(name, qtype, depth);
  }

  /** 업스트림 재귀 리졸버에 RD=1 위임. */
  private async resolveViaUpstream(name: string, qtype: number): Promise<DnsRecord[]> {
    const msg = await this.queryServers(this.upstreams!, name, qtype, true);
    return this.finalizeAnswer(msg, name, qtype);
  }

  /** 루트힌트부터 위임을 따라가는 반복 해석. */
  private async resolveIterative(name: string, qtype: number, depth: number): Promise<DnsRecord[]> {
    if (depth > MAX_GLUE_DEPTH) throw new DnsTemporaryError(`글루 해석 깊이 초과: ${name}`);

    let nsAddrs: readonly string[] = this.rootHints;
    let currentName = normName(name);
    let cnameGuard = 0;

    for (let delegations = 0; delegations < MAX_DELEGATIONS; delegations++) {
      const msg = await this.queryServers(nsAddrs, currentName, qtype, false);
      const rcode = msg.header.rcode;

      if (rcode === RCode.NXDOMAIN) {
        this.cache.setNegative(name, qtype, soaMinimum(msg));
        throw new DnsNotFoundError(`NXDOMAIN: ${currentName}`);
      }
      if (rcode !== RCode.NOERROR) {
        throw new DnsTemporaryError(`RCODE=${rcode}: ${currentName}`);
      }

      const { records, cnameTarget } = collectAnswers(msg, currentName, qtype);
      if (records.length > 0) return records;

      if (cnameTarget) {
        // CNAME 체인이 이 응답에서 끝나지 않음 → 대상을 루트부터 재해석.
        if (++cnameGuard > MAX_CNAME) throw new DnsTemporaryError(`CNAME 체인 초과: ${name}`);
        currentName = cnameTarget;
        nsAddrs = this.rootHints;
        continue;
      }

      /**
       * 답 없음 → 위임(referral)인지 NODATA인지 판별.
       *
       * ★**bailiwick 검사**: NS 레코드의 소유 이름이 질의 이름의 조상이어야 한다. 이게 없으면
       * `evil.test`의 네임서버가 `gmail.com NS ns.evil.test`를 authority에 실어 우리를 다른
       * zone으로 끌고 갈 수 있다. 우리 캐시는 질의 이름으로만 저장하므로 다른 이름을 오염시키진
       * 못하지만, **이 질의의 해석 경로**를 남에게 넘기는 것은 그 자체로 표준이 금지하는 형태다
       * (RFC 1034 §4.3.2의 "이 zone에 대한 위임"이라는 전제).
       */
      const inBailiwick = (owner: string): boolean => {
        const o = normName(owner);
        const q = normName(currentName);
        return o === "" || q === o || q.endsWith(`.${o}`);
      };
      const nsRecords = msg.authorities.filter(
        (r) => r.type === RRType.NS && r.rdata.kind === "NS" && inBailiwick(r.name),
      );
      const hasSoa = msg.authorities.some((r) => r.type === RRType.SOA);
      if (nsRecords.length === 0 || hasSoa) {
        // 권한 응답인데 해당 타입 없음(NODATA) → 영구 없음.
        this.cache.setNegative(name, qtype, soaMinimum(msg));
        throw new DnsNotFoundError(`NODATA: ${currentName}`);
      }

      nsAddrs = await this.nextServers(msg, nsRecords, depth);
      if (nsAddrs.length === 0) throw new DnsTemporaryError(`위임 NS 해석 실패: ${currentName}`);
    }
    throw new DnsTemporaryError(`위임 상한 초과: ${name}`);
  }

  /** 위임 응답에서 다음 질의할 NS IP 목록(글루 우선, 없으면 NS 이름 A 해석). */
  private async nextServers(
    msg: DnsMessage,
    nsRecords: DnsRecord[],
    depth: number,
  ): Promise<readonly string[]> {
    const nsNames = new Set<string>();
    for (const r of nsRecords) {
      if (r.rdata.kind === "NS") nsNames.add(normName(r.rdata.target));
    }
    /**
     * ★글루에는 zone 제약을 걸지 **않는다.** 실제 위임의 상당수가 zone 밖 NS 이름을 쓴다
     * (`example.com NS ns1.provider.net`). 그걸 거부하면 그 이름을 따로 재귀 해석해야 하는데,
     * `MAX_NS_RESOLVE`(2)에 걸려 정상 도메인이 해석되지 않을 수 있다 — 표준이 금지하는
     * 형태를 막으려다 표준을 따르는 도메인을 죽이는 셈이다.
     *
     * 안전한 이유: 캐시 키가 **질의 이름**이라(`resolve()`) 글루가 다른 이름의 캐시를 오염시킬
     * 수 없다. 글루가 가리키는 주소로 잘못 물어도 그 답은 위 `collectAnswers`가 질의 이름으로
     * 다시 거른다. 정말 막아야 하는 것 — "다른 zone으로 해석 경로를 넘기는 것" — 은 위의
     * NS bailiwick 검사가 이미 닫았다.
     */

    // 글루(additional의 A/AAAA) 수집.
    const glue: string[] = [];
    for (const r of msg.additionals) {
      if (r.class !== 1) continue;
      if ((r.rdata.kind === "A" || r.rdata.kind === "AAAA") && nsNames.has(normName(r.name))) {
        glue.push(r.rdata.address);
      }
    }
    if (glue.length > 0) return glue;

    // 글루 없음 → NS 이름 몇 개를 재귀 해석(A 우선).
    const resolved: string[] = [];
    let attempts = 0;
    for (const nsName of nsNames) {
      if (attempts >= MAX_NS_RESOLVE) break;
      attempts++;
      try {
        const addrs = await this.resolveIterative(nsName, RRType.A, depth + 1);
        for (const r of addrs) {
          if (r.rdata.kind === "A") resolved.push(r.rdata.address);
        }
        if (resolved.length > 0) break;
      } catch {
        // 이 NS 이름 해석 실패 — 다음 후보 시도.
      }
    }
    return resolved;
  }

  /** 응답에서 최종 답 추출(upstream 모드용). 없으면 적절한 에러. */
  private finalizeAnswer(msg: DnsMessage, name: string, qtype: number): DnsRecord[] {
    if (msg.header.rcode === RCode.NXDOMAIN) {
      this.cache.setNegative(name, qtype, soaMinimum(msg));
      throw new DnsNotFoundError(`NXDOMAIN: ${name}`);
    }
    if (msg.header.rcode !== RCode.NOERROR) throw new DnsTemporaryError(`RCODE=${msg.header.rcode}: ${name}`);
    const { records } = collectAnswers(msg, name, qtype);
    if (records.length === 0) {
      this.cache.setNegative(name, qtype, soaMinimum(msg));
      throw new DnsNotFoundError(`NODATA: ${name}`);
    }
    return records;
  }

  /**
   * 여러 서버를 순회하며 질의(각 서버 retriesPerServer+1회). TC면 TCP 재시도.
   * 전부 실패(타임아웃/네트워크/SERVFAIL/ID불일치)하면 DnsTemporaryError.
   * NXDOMAIN 같은 유효 응답은 즉시 반환(에러 아님).
   */
  private async queryServers(
    servers: readonly string[],
    name: string,
    qtype: number,
    rd: boolean,
  ): Promise<DnsMessage> {
    let lastErr: unknown = new DnsTemporaryError(`질의할 서버 없음: ${name}`);
    // 순서를 섞는다 — 고정 순서면 항상 목록 첫 서버(루트힌트 a, 특정 TLD 서버)에만 부하가 몰리고,
    // 그 서버가 느려질 때마다 모든 질의가 같이 느려진다. 공격자 입장에서도 표적이 예측 가능해진다.
    for (const server of shuffled(servers)) {
      for (let attempt = 0; attempt <= this.retriesPerServer; attempt++) {
        try {
          return await this.queryOne(server, name, qtype, rd);
        } catch (err) {
          lastErr = err;
        }
      }
    }
    if (lastErr instanceof DnsTemporaryError) throw lastErr;
    throw new DnsTemporaryError(`모든 서버 질의 실패: ${name} (${String(lastErr)})`);
  }

  /** 단일 서버 UDP 질의(+TC 시 TCP). ID/질문 검증. */
  private async queryOne(server: string, name: string, qtype: number, rd: boolean): Promise<DnsMessage> {
    const id = this.randomId() & 0xffff;
    const packet = encodeQuery(id, name, qtype, rd);

    let raw = await this.transport.queryUdp(server, packet, this.timeoutMs);
    let msg = decodeMessage(raw);
    if (msg.header.tc) {
      raw = await this.transport.queryTcp(server, packet, this.timeoutMs);
      msg = decodeMessage(raw);
    }
    if (msg.header.id !== id) throw new DnsTemporaryError(`트랜잭션 ID 불일치 ${server}`);
    const q = msg.questions[0];
    if (!q || normName(q.name) !== normName(name) || q.type !== qtype) {
      throw new DnsTemporaryError(`질문 불일치 ${server}`);
    }
    return msg;
  }
}

/** 권한 섹션 SOA의 minimum TTL(네거티브 캐시용). 없으면 undefined. */
function soaMinimum(msg: DnsMessage): number | undefined {
  for (const r of msg.authorities) {
    if (r.rdata.kind === "SOA") return r.rdata.minimum;
  }
  return undefined;
}
