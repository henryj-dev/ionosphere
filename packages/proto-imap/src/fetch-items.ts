/**
 * FETCH 데이터 항목 파서 (RFC 9051 §6.4.5).
 *
 * 범용 값 파서(parser.ts)는 `[`/`]`를 atom 문자로 수용하므로 대부분의 섹션은
 * "BODY[HEADER]" 같은 단일 atom으로 들어온다. 예외는 HEADER.FIELDS의 필드 리스트:
 * `BODY[HEADER.FIELDS (From To)]`가 [atom "BODY[HEADER.FIELDS", list, atom "]"]로
 * 쪼개져 오므로 여기서 재조립한다.
 */
import type { ImapValue } from "./parser.ts";
import { valueText } from "./parser.ts";
import type { SectionSpec } from "./fetch-format.ts";

export type FetchItem =
  | { kind: "flags" }
  | { kind: "uid" }
  /** CONDSTORE (RFC 7162) — 응답 `MODSEQ (n)`. */
  | { kind: "modseq" }
  | { kind: "internaldate" }
  | { kind: "rfc822size" }
  | { kind: "envelope" }
  | { kind: "body" }
  | { kind: "bodystructure" }
  | {
      kind: "section";
      peek: boolean;
      spec: SectionSpec;
      partial: { start: number; count: number } | null;
      /** 응답에 쓸 라벨 — partial은 `<start>`만 표기(RFC 규정). */
      label: string;
    };

/** 실패(BAD 대상) 시 null. */
export function parseFetchItems(values: readonly ImapValue[]): FetchItem[] | null {
  // FETCH 1 (FLAGS UID) — 리스트 하나면 풀어서, 아니면 값들 그대로
  let flat: readonly ImapValue[] = values;
  if (values.length === 1 && values[0]?.kind === "list") flat = values[0].items;
  if (flat.length === 0) return null;

  const items: FetchItem[] = [];
  let i = 0;
  while (i < flat.length) {
    const v = flat[i];
    if (!v) return null;
    const text = valueText(v);
    if (text === null) return null;

    // 프래그먼트 섹션: "...[HEADER.FIELDS" + (필드 리스트) + "]..." 재조립
    if (text.includes("[") && !text.includes("]")) {
      const fieldsVal = flat[i + 1];
      const closeVal = flat[i + 2];
      const closeText = closeVal ? valueText(closeVal) : null;
      if (!fieldsVal || fieldsVal.kind !== "list" || closeText === null || !closeText.startsWith("]")) return null;
      const fields: string[] = [];
      for (const f of fieldsVal.items) {
        const ft = valueText(f);
        if (ft === null) return null;
        fields.push(ft);
      }
      const item = parseSingleItem(`${text}]${closeText.slice(1)}`, fields);
      if (!item || Array.isArray(item)) return null; // 섹션 재조립 경로에서 매크로는 불가
      items.push(item);
      i += 3;
      continue;
    }

    const item = parseSingleItem(text, null);
    if (!item) return null;
    if (Array.isArray(item)) items.push(...item);
    else items.push(item);
    i += 1;
  }
  return items;
}

const MACROS: Record<string, FetchItem[]> = {
  ALL: [{ kind: "flags" }, { kind: "internaldate" }, { kind: "rfc822size" }, { kind: "envelope" }],
  FAST: [{ kind: "flags" }, { kind: "internaldate" }, { kind: "rfc822size" }],
  FULL: [{ kind: "flags" }, { kind: "internaldate" }, { kind: "rfc822size" }, { kind: "envelope" }, { kind: "body" }],
};

function parseSingleItem(text: string, fields: string[] | null): FetchItem | FetchItem[] | null {
  const upper = text.toUpperCase();

  if (fields === null) {
    const macro = MACROS[upper];
    if (macro) return [...macro];
    switch (upper) {
      case "FLAGS":
        return { kind: "flags" };
      case "UID":
        return { kind: "uid" };
      case "MODSEQ":
        return { kind: "modseq" };
      case "INTERNALDATE":
        return { kind: "internaldate" };
      case "RFC822.SIZE":
        return { kind: "rfc822size" };
      case "ENVELOPE":
        return { kind: "envelope" };
      case "BODY":
        return { kind: "body" };
      case "BODYSTRUCTURE":
        return { kind: "bodystructure" };
      // RFC822 계열 — BODY[...] 별칭(라벨은 원형 유지, RFC 9051 §6.4.5)
      case "RFC822":
        return { kind: "section", peek: false, spec: { path: [], sub: null, fields: [] }, partial: null, label: "RFC822" };
      case "RFC822.HEADER":
        return { kind: "section", peek: true, spec: { path: [], sub: "HEADER", fields: [] }, partial: null, label: "RFC822.HEADER" };
      case "RFC822.TEXT":
        return { kind: "section", peek: false, spec: { path: [], sub: "TEXT", fields: [] }, partial: null, label: "RFC822.TEXT" };
    }
  }

  // BODY[...] / BODY.PEEK[...]
  const m = /^(BODY|BODY\.PEEK)\[([^\]]*)\](<(\d+)\.(\d+)>)?$/i.exec(text);
  if (!m || m[2] === undefined) return null;
  const peek = (m[1] ?? "").toUpperCase() === "BODY.PEEK";
  const spec = parseSectionSpec(m[2], fields);
  if (!spec) return null;
  const partial = m[4] !== undefined && m[5] !== undefined ? { start: Number(m[4]), count: Number(m[5]) } : null;

  // 응답 라벨: BODY[정규화된 섹션] + (partial이면 <start>)
  let inner = spec.path.join(".");
  if (spec.sub) {
    if (inner.length > 0) inner += ".";
    inner += spec.sub;
    if (spec.fields.length > 0) inner += ` (${spec.fields.join(" ")})`;
  }
  const label = `BODY[${inner}]${partial ? `<${partial.start}>` : ""}`;
  return { kind: "section", peek, spec, partial, label };
}

function parseSectionSpec(inner: string, fields: string[] | null): SectionSpec | null {
  if (inner.length === 0) {
    return fields === null ? { path: [], sub: null, fields: [] } : null;
  }
  const segs = inner.split(".");
  const path: number[] = [];
  let idx = 0;
  while (idx < segs.length && /^[1-9]\d*$/.test(segs[idx] ?? "")) {
    path.push(Number(segs[idx]));
    idx += 1;
  }
  const rest = segs.slice(idx).join(".").toUpperCase();
  if (rest === "") {
    return fields === null && path.length > 0 ? { path, sub: null, fields: [] } : null;
  }
  switch (rest) {
    case "HEADER":
    case "TEXT":
      return fields === null ? { path, sub: rest, fields: [] } : null;
    case "MIME":
      // MIME은 파트 전용(RFC 9051)
      return fields === null && path.length > 0 ? { path, sub: "MIME", fields: [] } : null;
    case "HEADER.FIELDS":
    case "HEADER.FIELDS.NOT":
      return fields !== null && fields.length > 0 ? { path, sub: rest, fields: fields.map((f) => f.toUpperCase()) } : null;
    default:
      return null;
  }
}
