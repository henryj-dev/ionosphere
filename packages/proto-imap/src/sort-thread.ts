/**
 * SORT / THREAD (RFC 5256)의 **정렬과 묶기** — 순수 함수, I/O 0.
 *
 * ★정렬 키는 스토어가 물질화해 둔 값으로 온다(`ImapSortKeys`). 여기서 원문을 파싱하지
 * 않는 것이 요점이다 — 정렬 한 번에 메일함 전체 블롭을 메모리에 올릴 이유가 없다.
 */
import { valueText, type ImapValue } from "./parser.ts";

/** SORT/THREAD 정렬 키 (RFC 5256). 없는 값은 빈 문자열/0 — 정렬에서 맨 앞으로 간다. */
export interface ImapSortKeys {
  /** `Re:`/`Fwd:` 접두사를 뗀 제목(RFC 5256 §2.1 base subject). */
  subjectBase: string;
  /** Date 헤더 시각. 없으면 0. */
  sentAtMs: number;
  /** 스레딩 묶음 — THREAD가 이 값으로 묶는다. */
  threadId: string;
  from: string;
  to: string;
  cc: string;
}

/** 정렬 기준 하나. `REVERSE`는 바로 다음 기준 **하나만** 뒤집는다(§3). */
export interface SortSpec {
  key: "ARRIVAL" | "CC" | "DATE" | "FROM" | "SIZE" | "SUBJECT" | "TO";
  reverse: boolean;
}

const SORT_KEYS = new Set(["ARRIVAL", "CC", "DATE", "FROM", "SIZE", "SUBJECT", "TO"]);

/** 정렬 대상 하나 — 엔진이 배치를 돌며 모은다. */
export interface SortItem {
  /** 응답에 쓸 번호(seq 또는 uid, 모드에 따라). */
  num: number;
  seq: number;
  uid: number;
  keys: ImapSortKeys;
}

/**
 * `(REVERSE DATE SUBJECT)` 같은 리스트를 해석. 알 수 없는 기준이면 null(BAD).
 *
 * ★`REVERSE`는 **바로 다음 하나**에만 걸린다(§3 ABNF: `"REVERSE" SP sort-key`).
 * 남은 전부를 뒤집는 것으로 오해하면 `(REVERSE DATE SUBJECT)`의 제목 순서가 거꾸로 간다.
 */
export function parseSortSpec(items: readonly ImapValue[]): SortSpec[] | null {
  const out: SortSpec[] = [];
  let reverse = false;
  for (const item of items) {
    const t = valueText(item)?.toUpperCase();
    if (t === undefined || t === null) return null;
    if (t === "REVERSE") {
      if (reverse) return null; // `REVERSE REVERSE`는 문법 오류다
      reverse = true;
      continue;
    }
    if (!SORT_KEYS.has(t)) return null;
    out.push({ key: t as SortSpec["key"], reverse });
    reverse = false;
  }
  // 매달린 `REVERSE`(뒤에 기준이 없다)도 문법 오류다.
  if (reverse || out.length === 0) return null;
  return out;
}

/** 문자열 비교 — 정렬 키는 이미 소문자로 정규화돼 온다. */
function cmpStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * 한 기준으로 비교. `meta`는 ARRIVAL·SIZE용(스토어가 준 값).
 *
 * ★값이 없는 것(빈 제목, Date 없음)은 **앞으로** 온다. RFC는 순서를 규정하지 않지만,
 * 한쪽으로 몰아 두면 클라이언트가 목록 끝에서 "왜 여기 섞여 있지"를 겪지 않는다.
 */
function cmpBy(spec: SortSpec, a: SortItem, b: SortItem, meta: Map<number, { internalDateMs: number; size: number }>): number {
  switch (spec.key) {
    case "ARRIVAL":
      return (meta.get(a.uid)?.internalDateMs ?? 0) - (meta.get(b.uid)?.internalDateMs ?? 0);
    case "SIZE":
      return (meta.get(a.uid)?.size ?? 0) - (meta.get(b.uid)?.size ?? 0);
    case "DATE":
      /**
       * ★`DATE`는 **Date 헤더**이고 `ARRIVAL`이 도착 시각이다(§3). Date가 없으면 도착 시각으로
       * 떨어뜨린다 — RFC 5256 §2.2가 "the internal date"를 쓰라고 명시한다.
       */
      return (a.keys.sentAtMs || (meta.get(a.uid)?.internalDateMs ?? 0)) - (b.keys.sentAtMs || (meta.get(b.uid)?.internalDateMs ?? 0));
    case "SUBJECT":
      return cmpStr(a.keys.subjectBase, b.keys.subjectBase);
    case "FROM":
      return cmpStr(a.keys.from, b.keys.from);
    case "TO":
      return cmpStr(a.keys.to, b.keys.to);
    case "CC":
      return cmpStr(a.keys.cc, b.keys.cc);
  }
}

/**
 * `* SORT n n n` 한 줄.
 *
 * ★마지막 동점 처리는 **번호 오름차순**이다(§3: "in the order they appear in the mailbox"의
 * 취지). 없으면 같은 질의가 실행할 때마다 다른 순서를 낼 수 있고, 그건 클라이언트 화면이
 * 이유 없이 흔들린다는 뜻이다.
 */
export function formatSortLine(
  hits: readonly SortItem[],
  spec: readonly SortSpec[],
  meta: Map<number, { internalDateMs: number; size: number }>,
): string {
  const sorted = [...hits].sort((a, b) => {
    for (const s of spec) {
      const r = cmpBy(s, a, b, meta);
      if (r !== 0) return s.reverse ? -r : r;
    }
    return a.seq - b.seq;
  });
  return `* SORT${sorted.length > 0 ? " " + sorted.map((h) => h.num).join(" ") : ""}`;
}

/**
 * `* THREAD (1)(2 3)` 한 줄.
 *
 * ★두 알고리즘 모두 **스토어의 `thread_id`로 묶는다.** 원문의 References/In-Reply-To를 다시
 * 파싱하지 않는 이유: 배달 시점에 이미 그 헤더로 스레드를 정했고(`thread_refs`), 여기서 다시
 * 계산하면 두 벌이 되어 갈라진다 — 같은 메일이 IMAP THREAD와 JMAP Thread에서 다른 묶음으로
 * 보이는 형태다.
 *
 * 차이는 **묶음 사이의 순서**다:
 *  · ORDEREDSUBJECT — 묶음의 대표 제목순, 묶음 안은 시각순(§4.1의 "subject sort")
 *  · REFERENCES     — 묶음의 가장 이른 시각순, 묶음 안도 시각순(§4.2)
 *
 * 묶음 안을 평평하게 내보낸다. 규격은 부모-자식 중첩을 허용하지만 우리에겐 부모 관계가
 * 물질화돼 있지 않고(스레드 소속만 안다), **없는 관계를 지어내는 것보다 평평한 쪽이 정직하다**.
 */
export function formatThreadLine(hits: readonly SortItem[], algorithm: string): string {
  const groups = new Map<string, SortItem[]>();
  for (const h of hits) {
    // thread_id가 비어 있으면 자기 혼자 한 묶음이다(묶을 근거가 없다). NUL 접두사는
    // ULID에 나올 수 없어 실제 thread_id와 절대 겹치지 않는다 — 소스에는 escape로 쓴다.
    const key = h.keys.threadId === "" ? `\u0000solo-${h.uid}` : h.keys.threadId;
    const g = groups.get(key);
    if (g) g.push(h);
    else groups.set(key, [h]);
  }

  const ordered = [...groups.values()];
  for (const g of ordered) g.sort((a, b) => a.keys.sentAtMs - b.keys.sentAtMs || a.seq - b.seq);
  ordered.sort((a, b) => {
    const x = a[0]!;
    const y = b[0]!;
    if (algorithm === "ORDEREDSUBJECT") {
      const r = cmpStr(x.keys.subjectBase, y.keys.subjectBase);
      if (r !== 0) return r;
    }
    return x.keys.sentAtMs - y.keys.sentAtMs || x.seq - y.seq;
  });

  const body = ordered.map((g) => `(${g.map((h) => h.num).join(" ")})`).join("");
  return `* THREAD${body.length > 0 ? " " + body : ""}`;
}
