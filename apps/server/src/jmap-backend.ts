/**
 * JMAP Mail capability 모듈 — 스토어 백엔드 (RFC 8621). 현재 Mailbox 타입(get/changes/query).
 * Email/Thread/EmailSubmission은 후속 증분. proto-jmap의 표준 헬퍼에 스토어 소스를 주입한다.
 */
import { ADDRESS_FIELDS, RECIPIENT_KINDS, type DbDriver } from "@ionosphere/db";
import { toAppendAddresses } from "./addresses.ts";
import { buildSnippet, snippetTermsFromFilter } from "./snippet.ts";
import {
  getVacationResponse,
  lookupBlob,
  setVacationResponse,
  Store,
  type BlobStore,
  type JmapEmailFilter,
  type JmapEmailMeta,
  type MailboxRow,
  type VacationResponseRow,
} from "@ionosphere/store";
import { extractJmapBody, parseMessage, type ParsedAddress, type ParsedMessage } from "@ionosphere/mime";
import {
  isUnsafeKey,
  MethodError,
  requireAccountId,
  SetItemError,
  standardChanges,
  standardGet,
  standardQueryChanges,
  standardSet,
  MAIL_CAPABILITY,
  QUOTA_CAPABILITY,
  SUBMISSION_CAPABILITY,
  VACATION_CAPABILITY,
  type CapabilityModule,
  type GetSource,
  type JmapObject,
  type MethodContext,
  type SetSource,
} from "@ionosphere/proto-jmap";
import { principalContext } from "./principal-context.ts";
import { StoreError, type AppendAddress } from "@ionosphere/store";
import { DEFAULT_RATE_LIMIT, enqueueMessage, findUnsafeAddress, isSafeEnvelopeAddress, OutboundRejectedError, type OutboundPolicy } from "@ionosphere/mta";

/**
 * `SearchSnippet/get` 한 번에 받을 수 있는 메시지 수. 조각은 **본문 원문을 읽으므로**
 * `/get`류보다 비싸다 — 상한이 없으면 한 요청으로 계정 전체 본문을 메모리에 올린다.
 */
const MAX_SNIPPET_EMAILS = 100;

/** 단일 사용자 계정 — 소유자는 전권. JMAP Mailbox.myRights (RFC 8621 §2). */
const OWNER_RIGHTS = {
  mayReadItems: true,
  mayAddItems: true,
  mayRemoveItems: true,
  maySetSeen: true,
  maySetKeywords: true,
  mayCreateChild: true,
  mayRename: true,
  mayDelete: true,
  maySubmit: true,
} as const;

/**
 * MailboxRow → JMAP Mailbox 객체 (RFC 8621 §2). name은 리프명(계층은 parentId), 루트는 parentId=null.
 * ★편차: totalThreads/unreadThreads는 스레드 카운트를 메일함별로 물질화하지 않아 이메일 수로 근사
 * (SCHEMA에 per-mailbox 스레드 카운터 없음). sortOrder는 현재 항상 0(createMailbox 기본값).
 */
function toJmapMailbox(row: MailboxRow): JmapObject {
  return {
    id: row.id,
    name: row.name,
    parentId: row.parentId === "" ? null : row.parentId,
    role: row.role,
    sortOrder: 0,
    totalEmails: row.totalCount,
    unreadEmails: row.unreadCount,
    totalThreads: row.totalCount,
    unreadThreads: row.unreadCount,
    myRights: { ...OWNER_RIGHTS },
    isSubscribed: row.subscribed,
  };
}

async function requestedAccountId(args: Record<string, unknown>, authenticatedAccountId: string): Promise<string> {
  const accountId = args.accountId;
  if (typeof accountId !== "string" || accountId.length === 0) throw new MethodError("invalidArguments", { description: "accountId 누락" });
  if (accountId === authenticatedAccountId) return accountId;
  return accountId;
}

async function accessibleJmapMailboxes(db: DbDriver, store: Store, authenticatedAccountId: string, requestedAccountId: string): Promise<{ rows: MailboxRow[]; context: Awaited<ReturnType<typeof principalContext>> }> {
  const context = await principalContext(db, authenticatedAccountId);
  const rows = (await store.listAccessibleMailboxes(context)).filter((row) => row.accountId === requestedAccountId);
  if (requestedAccountId !== authenticatedAccountId && rows.length === 0) throw new MethodError("accountNotFound");
  return { rows, context };
}

async function mailboxRights(store: Store, context: Awaited<ReturnType<typeof principalContext>>, row: MailboxRow): Promise<Record<string, unknown>> {
  const [read, insert, write, remove, create] = await Promise.all([
    store.authorizeMailbox(context, row.id, "read"),
    store.authorizeMailbox(context, row.id, "insert"),
    store.authorizeMailbox(context, row.id, "write"),
    store.authorizeMailbox(context, row.id, "delete"),
    store.authorizeMailbox(context, row.id, "create"),
  ]);
  return {
    mayReadItems: read.allowed,
    mayAddItems: insert.allowed,
    mayRemoveItems: remove.allowed,
    maySetSeen: write.allowed,
    maySetKeywords: write.allowed,
    mayCreateChild: create.allowed,
    mayRename: remove.allowed && create.allowed,
    mayDelete: remove.allowed,
    maySubmit: false,
  };
}

type ScopedJmapEntity = "email" | "mailbox" | "thread";
type ScopedJmapState = "email" | "mailbox" | "thread";

async function scopedJmapState(db: DbDriver, store: Store, authenticatedAccountId: string, requestedAccountId: string, entity: ScopedJmapState): Promise<string> {
  const states = await store.jmapState(requestedAccountId);
  if (requestedAccountId === authenticatedAccountId) return states[entity];
  const context = await principalContext(db, authenticatedAccountId);
  if ((await store.accessibleMailboxIds(context, requestedAccountId)).length === 0) throw new MethodError("accountNotFound");
  return `${states[entity]}.${states.permission}`;
}

async function scopedJmapChanges(args: Record<string, unknown>, authenticatedAccountId: string, db: DbDriver, store: Store, entity: ScopedJmapEntity): Promise<Record<string, unknown>> {
  const requestedAccountId = await requestedAccountIdFromArgs(args, authenticatedAccountId);
  if (requestedAccountId === authenticatedAccountId) {
    return standardChanges(args, authenticatedAccountId, { changes: (accountId, sinceState, maxChanges) => store.jmapChanges(accountId, entity, sinceState, maxChanges) });
  }
  if (typeof args.sinceState !== "string") throw new MethodError("invalidArguments", { description: "sinceState 누락" });
  const context = await principalContext(db, authenticatedAccountId);
  if ((await store.accessibleMailboxIds(context, requestedAccountId)).length === 0) throw new MethodError("accountNotFound");
  const [sinceEntity, sincePermission, ...extra] = args.sinceState.split(".");
  if (!sinceEntity || !sincePermission || extra.length > 0 || !/^\d+$/.test(sinceEntity) || !/^\d+$/.test(sincePermission)) throw new MethodError("cannotCalculateChanges");
  const states = await store.jmapState(requestedAccountId);
  if (sincePermission !== states.permission) throw new MethodError("cannotCalculateChanges");
  let maxChanges = 256;
  if (args.maxChanges !== undefined && args.maxChanges !== null) {
    if (typeof args.maxChanges !== "number" || !Number.isInteger(args.maxChanges) || args.maxChanges < 1) throw new MethodError("invalidArguments", { description: "maxChanges는 양의 정수" });
    maxChanges = args.maxChanges;
  }
  const result = await store.jmapChanges(requestedAccountId, entity, sinceEntity, maxChanges);
  if (result.cannotCalculate) throw new MethodError("cannotCalculateChanges");
  return {
    accountId: requestedAccountId,
    oldState: args.sinceState,
    newState: `${result.newState}.${states.permission}`,
    hasMoreChanges: result.hasMoreChanges,
    created: result.created,
    updated: result.updated,
    destroyed: result.destroyed,
  };
}

async function requestedAccountIdFromArgs(args: Record<string, unknown>, authenticatedAccountId: string): Promise<string> {
  return requestedAccountId(args, authenticatedAccountId);
}

async function jmapMailboxGet(args: Record<string, unknown>, authenticatedAccountId: string, db: DbDriver, store: Store): Promise<Record<string, unknown>> {
  const accountId = await requestedAccountId(args, authenticatedAccountId);
  const { rows, context } = await accessibleJmapMailboxes(db, store, authenticatedAccountId, accountId);
  const rights = new Map(await Promise.all(rows.map(async (row) => [row.id, await mailboxRights(store, context, row)] as const)));
  const ids = args.ids;
  if (ids !== null && ids !== undefined && (!Array.isArray(ids) || ids.some((id) => typeof id !== "string"))) throw new MethodError("invalidArguments");
  const wanted = ids === null || ids === undefined ? rows : rows.filter((row) => (ids as string[]).includes(row.id));
  const found = new Set(wanted.map((row) => row.id));
  const notFound = ids === null || ids === undefined ? [] : (ids as string[]).filter((id) => !found.has(id));
  return { accountId, state: await scopedJmapState(db, store, authenticatedAccountId, accountId, "mailbox"), list: wanted.map((row) => ({ ...toJmapMailbox(row), myRights: rights.get(row.id) ?? {} })), notFound };
}

/** message_addresses.kind → JMAP Email 주소 프로퍼티명. 인코딩은 @ionosphere/db 소유. */
const ADDRESS_PROP = ADDRESS_FIELDS;

/** 메타 전용(블롭 불필요) JMAP Email 프로퍼티 — 이 집합에 없으면 본문 파싱 필요. */
const CHEAP_EMAIL_PROPS = new Set([
  "id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt", "sentAt", "subject", "preview", "hasAttachment",
  "from", "to", "cc", "bcc", "replyTo", "sender",
]);

/** JmapEmailMeta → JMAP Email(메타 부분). 본문 프로퍼티는 addBodyProps가 채운다. */
function toJmapEmailMeta(m: JmapEmailMeta): JmapObject {
  const addr: Record<string, { name: string | null; email: string }[]> = {};
  for (const a of m.addresses) {
    const prop = ADDRESS_PROP[a.kind];
    if (!prop) continue;
    (addr[prop] ??= []).push({ name: a.name, email: a.email });
  }
  const keywords: Record<string, boolean> = {};
  for (const k of m.keywords) keywords[k] = true;
  const mailboxIds: Record<string, boolean> = {};
  for (const id of m.mailboxIds) mailboxIds[id] = true;
  return {
    id: m.id,
    blobId: m.blobId,
    threadId: m.threadId,
    mailboxIds,
    keywords,
    size: m.size,
    receivedAt: new Date(m.receivedAt).toISOString().replace(/\.\d{3}Z$/, "Z"),
    sentAt: m.sentAt === null ? null : new Date(m.sentAt).toISOString().replace(/\.\d{3}Z$/, "Z"),
    subject: m.subject,
    preview: m.preview ?? "",
    hasAttachment: m.hasAttachment,
    from: addr.from ?? null,
    to: addr.to ?? null,
    cc: addr.cc ?? null,
    bcc: addr.bcc ?? null,
    replyTo: addr.replyTo ?? null,
    sender: addr.sender ?? null,
  };
}

export function buildMailModule(db: DbDriver, store: Store, blobs: BlobStore): CapabilityModule {
  const mailboxGetSource: GetSource = {
    state: async (accountId) => (await store.jmapState(accountId)).mailbox,
    get: async (accountId, ids) => {
      const all = await store.listMailboxes(accountId);
      if (ids === null) return { list: all.map(toJmapMailbox), notFound: [] };
      const byId = new Map(all.map((m) => [m.id, m]));
      const list: JmapObject[] = [];
      const notFound: string[] = [];
      for (const id of ids) {
        const row = byId.get(id);
        if (row) list.push(toJmapMailbox(row));
        else notFound.push(id);
      }
      return { list, notFound };
    },
  };

  const mailboxChangesSource = {
    changes: (accountId: string, sinceState: string, maxChanges: number) => store.jmapChanges(accountId, "mailbox", sinceState, maxChanges),
  };

  const emailChangesSource = {
    changes: (accountId: string, sinceState: string, maxChanges: number) => store.jmapChanges(accountId, "email", sinceState, maxChanges),
  };

  const mailboxSetSource = buildMailboxSetSource(store);

  const threadGetSource: GetSource = {
    state: async (accountId) => (await store.jmapState(accountId)).thread,
    get: async (accountId, ids) => {
      const threads = await store.getThreadsForJmap(accountId, ids);
      const list: JmapObject[] = threads.map((t) => ({ id: t.id, emailIds: t.emailIds }));
      const found = new Set(list.map((t) => t.id));
      const notFound = ids === null ? [] : ids.filter((i) => !found.has(i));
      return { list, notFound };
    },
  };
  const threadChangesSource = {
    changes: (accountId: string, sinceState: string, maxChanges: number) => store.jmapChanges(accountId, "thread", sinceState, maxChanges),
  };

  return {
    capability: MAIL_CAPABILITY,
    methods: {
      "Mailbox/get": (args, ctx) => jmapMailboxGet(args, ctx.accountId, db, store),
      "Mailbox/changes": (args, ctx) => scopedJmapChanges(args, ctx.accountId, db, store, "mailbox"),
      "Mailbox/query": (args, ctx) => mailboxQuery(args, ctx.accountId, store),
      "Mailbox/set": (args, ctx) => standardSet(args, ctx.accountId, ctx, mailboxSetSource),
      "Email/get": (args, ctx) => emailGet(args, ctx.accountId, db, store, blobs),
      "Email/changes": (args, ctx) => scopedJmapChanges(args, ctx.accountId, db, store, "email"),
      "Email/query": (args, ctx) => emailQuery(args, ctx.accountId, db, store),
      "Email/set": (args, ctx) => standardSet(args, ctx.accountId, ctx, buildEmailSetSource(db, store, blobs)),
      "Email/import": (args, ctx) => emailImport(args, ctx, store, buildEmailSetSource(db, store, blobs)),
      "Email/copy": (args, ctx) => emailCopy(args, ctx.accountId),
      // RFC 8620 §5.6 — 델타를 계산할 수 없다는 것을 **규격의 말로** 알린다(standard.ts 주석).
      "SearchSnippet/get": (args, ctx) => searchSnippetGet(args, ctx.accountId, store),
      /**
       * `Blob/copy`(RFC 8620 §6.3) — **계정 간** 블롭 복사. `Email/copy`와 같은 이유로
       * 우리 세션에서는 늘 거절이지만, 그 거절이 **규격이 정한 거절**인 것이 중요하다
       * (`emailCopy` 주석 참조).
       */
      "Blob/copy": (args, ctx) => emailCopy(args, ctx.accountId),
      "Email/queryChanges": (args, ctx) => standardQueryChanges(args, ctx.accountId),
      "Mailbox/queryChanges": (args, ctx) => standardQueryChanges(args, ctx.accountId),
      "Thread/get": (args, ctx) => jmapThreadGet(args, ctx.accountId, db, store),
      "Thread/changes": (args, ctx) => scopedJmapChanges(args, ctx.accountId, db, store, "thread"),
    },
  };
}

/** JMAP Mailbox/set → store CRUD 매핑 (RFC 8621 §2.5). name/parentId/role/isSubscribed 지원. */
function buildMailboxSetSource(store: Store): SetSource {
  const resolveParent = (raw: unknown, createdIds: Record<string, string>): string => {
    if (raw === null || raw === undefined) return ""; // 루트
    if (typeof raw !== "string") throw new SetItemError("invalidProperties", { properties: ["parentId"] });
    if (raw.startsWith("#")) {
      const id = createdIds[raw.slice(1)];
      if (!id) throw new SetItemError("invalidProperties", { description: "미해석 parentId creationId" });
      return id;
    }
    return raw;
  };
  const mapStoreErr = (err: unknown): never => {
    if (err instanceof StoreError) {
      const m = err.message;
      if (m.includes("already exists")) throw new SetItemError("invalidProperties", { description: m });
      if (m.includes("not found")) throw new SetItemError("notFound", { description: m });
      if (m.includes("children")) throw new SetItemError("mailboxHasChild");
      if (m.includes("INBOX")) throw new SetItemError("forbidden", { description: m });
      throw new SetItemError("invalidProperties", { description: m });
    }
    throw err;
  };

  return {
    state: async (accountId) => (await store.jmapState(accountId)).mailbox,
    create: async (accountId, props, ctx) => {
      const name = props.name;
      if (typeof name !== "string" || name.length === 0) throw new SetItemError("invalidProperties", { properties: ["name"] });
      const parentId = resolveParent(props.parentId, ctx.createdIds);
      const role = typeof props.role === "string" ? props.role : undefined;
      let result: { mailboxId: string };
      try {
        result = await store.createMailbox({ accountId, name, ...(parentId !== "" ? { parentId } : {}), ...(role ? { role } : {}) });
      } catch (err) {
        mapStoreErr(err);
      }
      const id = result!.mailboxId;
      // 구독 기본값은 true — 명시적 false면 반영
      const subscribed = props.isSubscribed !== false;
      if (!subscribed) await store.setSubscribed(accountId, id, false);
      const serverProps: Record<string, unknown> = {
        sortOrder: 0,
        totalEmails: 0,
        unreadEmails: 0,
        totalThreads: 0,
        unreadThreads: 0,
        myRights: { ...OWNER_RIGHTS },
        isSubscribed: subscribed,
        role: role ?? null,
      };
      return { id, serverProps };
    },
    update: async (accountId, id, patch) => {
      // 현재 상태 확보(name/parentId 부분 패치 병합용)
      const all = await store.listMailboxes(accountId);
      const cur = all.find((m) => m.id === id);
      if (!cur) throw new SetItemError("notFound");
      const keys = Object.keys(patch);
      const unsupported = keys.filter((k) => !["name", "parentId", "isSubscribed", "role", "sortOrder"].includes(k));
      if (unsupported.length > 0) throw new SetItemError("invalidProperties", { properties: unsupported });

      if ("name" in patch || "parentId" in patch) {
        const newName = "name" in patch ? patch.name : cur.name;
        if (typeof newName !== "string" || newName.length === 0) throw new SetItemError("invalidProperties", { properties: ["name"] });
        const newParentId = "parentId" in patch ? resolveParent(patch.parentId, {}) : cur.parentId;
        try {
          await store.renameMailbox({ accountId, mailboxId: id, newParentId, newName });
        } catch (err) {
          mapStoreErr(err);
        }
      }
      if (typeof patch.isSubscribed === "boolean") {
        await store.setSubscribed(accountId, id, patch.isSubscribed);
      }
      // role/sortOrder 변경은 v1 미지원 — 값이 왔으면 조용히 무시(에러 대신, 위 화이트리스트로 통과만)
      return null; // 서버 재계산 프로퍼티 없음
    },
    destroy: async (accountId, id) => {
      try {
        await store.deleteMailbox({ accountId, mailboxId: id });
      } catch (err) {
        mapStoreErr(err);
      }
    },
  };
}

/**
 * JMAP Email/set → store 매핑 (RFC 8621 §4.6, v1). keywords 변경(읽음/플래그) 지원.
 * ★v1 범위: keywords 패치만. mailboxIds(이동)·create(import)·destroy는 후속 증분
 * (멤버십 제거/전체 파기 스토어 레시피 필요). 그 프로퍼티가 오면 invalidProperties로 명확히 거부.
 */
function buildEmailSetSource(db: DbDriver, store: Store, blobs: BlobStore): SetSource {
  return {
    state: async (accountId) => (await store.jmapState(accountId)).email,
    create: async (accountId, props, ctx) => {
      // Email/set create = import (RFC 8621 §4.8) — 업로드된 blobId의 원문을 파싱해 메일함에 배치
      const blobId = props.blobId;
      if (typeof blobId !== "string") throw new SetItemError("invalidProperties", { properties: ["blobId"] });
      const mbxObj = props.mailboxIds;
      if (typeof mbxObj !== "object" || mbxObj === null || Array.isArray(mbxObj)) throw new SetItemError("invalidProperties", { properties: ["mailboxIds"] });
      const mailboxIds: string[] = [];
      for (const [k, v] of Object.entries(mbxObj as Record<string, unknown>)) {
        if (v !== true) throw new SetItemError("invalidProperties", { description: "mailboxId 값은 true" });
        mailboxIds.push(k.startsWith("#") ? (ctx.createdIds[k.slice(1)] ?? k) : k);
      }
      if (mailboxIds.length === 0) throw new SetItemError("invalidProperties", { properties: ["mailboxIds"] });
      const keywords: string[] = [];
      if (props.keywords && typeof props.keywords === "object" && !Array.isArray(props.keywords)) {
        for (const [k, v] of Object.entries(props.keywords as Record<string, unknown>)) if (v === true) keywords.push(k.toLowerCase());
      }
      // 업로드 블롭의 세대는 blobs 원장이 정본이다 — 0을 가정하면 GC가 부활시킨(gen+1) 블롭을 못 읽는다.
      const uploaded = await lookupBlob(db, blobId);
      if (!uploaded) throw new SetItemError("blobNotFound");
      let raw: Uint8Array;
      try {
        raw = await blobs.get(blobId, uploaded.generation);
      } catch {
        throw new SetItemError("blobNotFound");
      }
      const parsed = parseMessage(raw);
      const receivedAt = typeof props.receivedAt === "string" && !Number.isNaN(Date.parse(props.receivedAt)) ? Date.parse(props.receivedAt) : Date.now();
      let result;
      try {
        result = await store.appendMessage({
          accountId,
          mailboxIds,
          blobId,
          blobGeneration: uploaded.generation,
          sizeBytes: raw.length,
          receivedAt,
          envelope: toAppendEnvelope(parsed),
          keywords,
          searchText: toSearchText(parsed),
        });
      } catch (err) {
        throw wrapStore(err);
      }
      return { id: result.messageId, serverProps: { blobId, threadId: result.threadId, size: raw.length } };
    },
    update: async (accountId, id, patch) => {
      await applyEmailPatch(store, accountId, id, patch);
      return null;
    },
    destroy: async (accountId, id) => {
      try {
        await store.destroyMessage(accountId, id);
      } catch (err) {
        if (err instanceof StoreError && err.message.includes("not found")) throw new SetItemError("notFound");
        throw wrapStore(err);
      }
    },
  };
}

/**
 * Email 패치 적용 (RFC 8621 §4.6 PatchObject) — keywords·mailboxIds. Email/set update와
 * EmailSubmission onSuccessUpdateEmail이 공용. SetItemError를 throw.
 */
async function applyEmailPatch(store: Store, accountId: string, id: string, patch: Record<string, unknown>): Promise<void> {
  const fullKeywords = "keywords" in patch;
  const kwPaths = Object.keys(patch).filter((k) => k.startsWith("keywords/"));
  const fullMailboxIds = "mailboxIds" in patch;
  const mbxPaths = Object.keys(patch).filter((k) => k.startsWith("mailboxIds/"));
  const otherKeys = Object.keys(patch).filter(
    (k) => k !== "keywords" && !k.startsWith("keywords/") && k !== "mailboxIds" && !k.startsWith("mailboxIds/"),
  );
  if (otherKeys.length > 0) throw new SetItemError("invalidProperties", { properties: otherKeys });
  if (fullKeywords && kwPaths.length > 0) throw new SetItemError("invalidPatch", { description: "keywords 전체/patch 혼용 불가" });
  if (fullMailboxIds && mbxPaths.length > 0) throw new SetItemError("invalidPatch", { description: "mailboxIds 전체/patch 혼용 불가" });

  const metas = await store.getEmailsForJmap(accountId, [id]);
  const meta = metas[0];
  if (!meta) throw new SetItemError("notFound");

  const curKw = new Set(meta.keywords);
  let desired: Set<string> | undefined;
  if (fullMailboxIds || mbxPaths.length > 0) {
    const current = new Set(meta.mailboxIds);
    desired = desiredMailboxIds(patch, fullMailboxIds, mbxPaths, current);
    if (desired.size === 0) throw new SetItemError("invalidProperties", { properties: ["mailboxIds"], description: "이메일은 최소 1개 메일함에 있어야 함" });
    const owned = new Set((await store.listMailboxes(accountId)).map((m) => m.id));
    if ([...desired].some((mailboxId) => !owned.has(mailboxId))) throw new SetItemError("invalidProperties", { properties: ["mailboxIds"], description: "메일함이 없거나 다른 계정에 속함" });
  }
  const kwChange = keywordChange(patch, fullKeywords, kwPaths, curKw);
  if (kwChange.add.length > 0 || kwChange.remove.length > 0) {
    try {
      await store.setKeywords({ accountId, messageId: id, add: kwChange.add, remove: kwChange.remove });
    } catch (err) {
      throw wrapStore(err);
    }
  }

  if (fullMailboxIds || mbxPaths.length > 0) {
    const current = new Set(meta.mailboxIds);
    const target = desired!;
    const toAdd = [...target].filter((m) => !current.has(m));
    const toRemove = [...current].filter((m) => !target.has(m));
    try {
      if (toAdd.length === 1 && toRemove.length === 1) {
        await store.moveMessage({ accountId, messageId: id, fromMailboxId: toRemove[0]!, toMailboxId: toAdd[0]! });
      } else {
        for (const m of toAdd) await store.copyMessage({ accountId, messageId: id, toMailboxId: m });
        for (const m of toRemove) await store.removeMessageFromMailbox(accountId, id, m);
      }
    } catch (err) {
      throw wrapStore(err);
    }
  }
}

/** ParsedMessage → appendMessage envelope(주소 kind/pos 사전계산 — backend.ts와 대칭). */
function toAppendEnvelope(parsed: ParsedMessage): {
  subject: string | null;
  subjectBase: string | null;
  msgidHash: string | null;
  sentAt: number | null;
  preview: string | null;
  hasAttachment: boolean;
  addresses: AppendAddress[];
  threadRefHashes: readonly string[];
} {
  // SMTP/IMAP 경로와 **동일한** 단일 변환(addresses.ts) — 예전엔 여기만 따로 구현돼 있었다.
  const addresses: AppendAddress[] = toAppendAddresses(parsed);
  return {
    subject: parsed.subject,
    subjectBase: parsed.subjectBase,
    msgidHash: parsed.msgidHash,
    sentAt: parsed.sentAt,
    preview: parsed.preview,
    hasAttachment: parsed.hasAttachment,
    addresses,
    threadRefHashes: parsed.threadRefHashes,
  };
}

function toSearchText(parsed: ParsedMessage): { subject?: string; body?: string; from?: string; to?: string } {
  return {
    ...(parsed.subject ? { subject: parsed.subject } : {}),
    ...(parsed.textBody ? { body: parsed.textBody } : {}),
    ...(parsed.from[0] ? { from: `${parsed.from[0].name ?? ""} ${parsed.from[0].email}` } : {}),
    ...(parsed.to.length > 0 ? { to: parsed.to.map((a) => a.email).join(" ") } : {}),
  };
}

/** JMAP submission capability 모듈 — Identity(§6) + EmailSubmission(§7). */
/**
 * EmailSubmission 모듈. rateLimit은 SMTP submission(587/465)과 **동일한 설정**을 받아야 한다 —
 * 미지정 시 DEFAULT_RATE_LIMIT으로 폴백하면 운영자가 건 한도를 JMAP만 우회하게 된다(과거 결함).
 */
export function buildSubmissionModule(db: DbDriver, store: Store, blobs: BlobStore, outbound?: OutboundPolicy): CapabilityModule {
  const identityGet = async (args: Record<string, unknown>, accountId: string): Promise<Record<string, unknown>> => {
    const acc = requireAccountId(args, accountId);
    const ids = args.ids === null || args.ids === undefined ? null : args.ids;
    if (ids !== null && (!Array.isArray(ids) || ids.some((x) => typeof x !== "string"))) throw new MethodError("invalidArguments", { description: "ids" });
    const all = await store.getIdentities(acc);
    const list = ids === null ? all : all.filter((i) => (ids as string[]).includes(i.id));
    const found = new Set(list.map((i) => i.id));
    const notFound = ids === null ? [] : (ids as string[]).filter((i) => !found.has(i));
    return {
      accountId: acc,
      state: await store.jmapState(accountId).then((s) => s.identity),
      list: list.map((i) => ({ id: i.id, name: i.name, email: i.email, replyTo: i.replyTo, bcc: null, textSignature: i.textSignature, htmlSignature: i.htmlSignature, mayDelete: false })),
      notFound,
    };
  };
  const submissionChangesSource = {
    changes: (accountId: string, sinceState: string, maxChanges: number) => store.jmapChanges(accountId, "submission", sinceState, maxChanges),
  };
  const submissionGetSource: GetSource = {
    state: async (accountId) => (await store.jmapState(accountId)).submission,
    get: async (accountId, ids) => {
      const subs = await store.getSubmissions(accountId, ids);
      const list: JmapObject[] = subs.map((s) => ({
        id: s.id,
        identityId: s.identityId,
        emailId: s.emailId,
        sendAt: new Date(s.sendAt).toISOString().replace(/\.\d{3}Z$/, "Z"),
        undoStatus: s.undoStatus === 2 ? "canceled" : s.undoStatus === 1 ? "final" : "pending",
      }));
      const found = new Set(list.map((s) => s.id));
      const notFound = ids === null ? [] : ids.filter((i) => !found.has(i));
      return { list, notFound };
    },
  };

  return {
    capability: SUBMISSION_CAPABILITY,
    methods: {
      "Identity/get": (args, ctx) => identityGet(args, ctx.accountId),
      "Identity/set": (args, ctx) => standardSet(args, ctx.accountId, ctx, buildIdentitySetSource(store)),
      "Identity/changes": async (args, ctx) => {
        const acc = requireAccountId(args, ctx.accountId);
        if (typeof args.sinceState !== "string") throw new MethodError("invalidArguments");
        return await store.jmapChanges(acc, "identity", args.sinceState, Number(args.maxChanges ?? 0) || 256);
      },
      "EmailSubmission/get": (args, ctx) => standardGet(args, ctx.accountId, submissionGetSource),
      "EmailSubmission/changes": (args, ctx) => standardChanges(args, ctx.accountId, submissionChangesSource),
      "EmailSubmission/set": (args, ctx) => emailSubmissionSet(args, ctx.accountId, ctx, db, store, blobs, outbound),
    },
  };
}

/**
 * EmailSubmission/set (RFC 8621 §7.5) — create만(발송). 이메일 원문을 MTA 큐에 적재하고
 * email_submissions 기록. onSuccessUpdateEmail(초안→보낸함 이동 등)을 부수효과로 적용.
 * ★v1: 즉시 발송만(maxDelayedSend=0), undoStatus=final. update/destroy(취소)는 미지원.
 * 외부 도메인 실배달은 MTA 워커·아웃바운드 정책에 의존(발신 도메인 미검증이면 게이트 거부).
 */
async function emailSubmissionSet(
  args: Record<string, unknown>,
  accountId: string,
  ctx: MethodContext,
  db: DbDriver,
  store: Store,
  blobs: BlobStore,
  /** SMTP submission과 **동일해야 하는** 발송 정책(레이트리밋·내부 전용). 조립부가 한 값을 양쪽에 넘긴다. */
  outbound?: OutboundPolicy,
): Promise<Record<string, unknown>> {
  const acc = requireAccountId(args, accountId);
  const oldState = (await store.jmapState(acc)).submission;
  if (args.ifInState !== undefined && args.ifInState !== null && args.ifInState !== oldState) throw new MethodError("stateMismatch");

  const tenantId = await store.getAccountTenantId(acc);
  if (!tenantId) throw new MethodError("accountNotFound");
  const identities = await store.getIdentities(acc);
  const identityIds = new Set(identities.map((i) => i.id));

  const created: Record<string, Record<string, unknown>> = {};
  const notCreated: Record<string, { type: string; [k: string]: unknown }> = {};
  const createArg = asObjectLocal(args.create);
  // creationId → 해당 submission이 참조한 emailId (onSuccessUpdateEmail 해석용)
  const emailByCreation: Record<string, string> = {};

  if (createArg) {
    for (const [creationId, rawProps] of Object.entries(createArg)) {
      const props = asObjectLocal(rawProps);
      if (!props) {
        notCreated[creationId] = { type: "invalidProperties" };
        continue;
      }
      try {
        const emailId = resolveRef(props.emailId, ctx.createdIds);
        if (!emailId) throw new SetItemError("invalidProperties", { properties: ["emailId"] });
        const identityId = typeof props.identityId === "string" ? props.identityId : "";
        if (!identityIds.has(identityId)) throw new SetItemError("invalidProperties", { properties: ["identityId"] });

        const metas = await store.getEmailsForJmap(acc, [emailId]);
        const meta = metas[0];
        if (!meta) throw new SetItemError("notFound", { description: "emailId" });

        // envelope: 인자 우선, 없으면 이메일 헤더에서 유도(mailFrom=identity, rcptTo=to/cc/bcc)
        const identity = identities.find((i) => i.id === identityId)!;
        const env = asObjectLocal(props.envelope);
        const envFrom = env ? String((asObjectLocal(env.mailFrom)?.email as string) ?? identity.email) : identity.email;
        const rcpts = env
          ? (Array.isArray(env.rcptTo) ? env.rcptTo.map((r) => String((r as Record<string, unknown>).email)) : [])
          : meta.addresses.filter((a) => RECIPIENT_KINDS.includes(a.kind)).map((a) => a.email);
        if (rcpts.length === 0) throw new SetItemError("noRecipients");

        /**
         * 봉투 안전성은 **행을 만들기 전에** 본다. 아래 `createSubmission`이 큐 적재보다 먼저
         * 실행되는 이유는 행 id가 큐 입력에 필요해서인데(순서를 뒤집을 수 없다), 그 탓에 봉투가
         * 거부되면 **CRLF 주입 페이로드가 담긴 행이 DB에 남았다**(감사 5차 §9-5 조사 중 발견).
         * `EmailSubmission/get`이 그 행을 유령 제출로 보여 주기까지 한다.
         *
         * 정본 검사는 `enqueueMessage` 안에 그대로 있다 — 여기서 거르는 것은 조기 실패일 뿐,
         * 이 호출을 빠뜨린 갈래가 생겨도 게이트가 막는다.
         */
        if (!isSafeEnvelopeAddress(envFrom)) {
          throw new SetItemError("forbidden", { description: `unsafe envelope-from: ${JSON.stringify(envFrom)}` });
        }
        const unsafeRcpt = findUnsafeAddress(rcpts);
        if (unsafeRcpt !== null) {
          throw new SetItemError("forbidden", { description: `unsafe recipient: ${JSON.stringify(unsafeRcpt)}` });
        }

        // MTA 큐 적재(§8 게이트: 발신 도메인 미검증 → OutboundRejectedError)
        const submissionId = await store.createSubmission(acc, {
          identityId,
          messageId: emailId,
          blobId: meta.blobId,
          envFrom,
          sendAt: Date.now(),
          undoStatus: 1, // final(즉시)
        });
        try {
          await enqueueMessage(
            db,
            {
              tenantId,
              accountId: acc,
              submissionId,
              blobId: meta.blobId,
              sizeBytes: meta.size,
              blobGeneration: meta.blobGeneration,
              envFrom,
              rcpts,
            },
            { rateLimit: outbound?.rateLimit ?? DEFAULT_RATE_LIMIT, ...(outbound?.localOnly ? { localOnly: true } : {}) },
          );
        } catch (err) {
          try { await store.cancelSubmission(acc, submissionId); } catch { /* 보상 실패도 원래 거절을 가리지 않는다. */ }
          if (err instanceof OutboundRejectedError) {
            // external-disabled/domain-unverified는 정책상 영구 실패 → forbidden(재시도해도 같다)
            throw new SetItemError(err.reason === "rate-limited" ? "rateLimit" : "forbidden", { description: err.message });
          }
          throw err;
        }
        created[creationId] = { id: submissionId, sendAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), undoStatus: "final" };
        ctx.createdIds[creationId] = submissionId;
        emailByCreation[creationId] = emailId;
      } catch (err) {
        notCreated[creationId] = err instanceof SetItemError ? err.setError : { type: "serverFail", description: err instanceof Error ? err.message : String(err) };
      }
    }
  }

  // onSuccessUpdateEmail (RFC 8621 §7.5) — 성공한 submission이 참조한 이메일에 패치 적용(부수효과)
  const onSuccess = asObjectLocal(args.onSuccessUpdateEmail);
  if (onSuccess) {
    for (const [subRef, patch] of Object.entries(onSuccess)) {
      const creationId = subRef.startsWith("#") ? subRef.slice(1) : subRef;
      const emailId = emailByCreation[creationId];
      const p = asObjectLocal(patch);
      if (!emailId || !p) continue; // 실패한/미지 submission 참조는 무시
      try {
        await applyEmailPatch(store, acc, emailId, p);
      } catch {
        // 부수효과 실패는 submission 성공을 되돌리지 않음(발송은 이미 큐 적재됨) — 조용히 무시
      }
    }
  }

  const newState = (await store.jmapState(acc)).submission;
  return { accountId: acc, oldState, newState, created, updated: {}, destroyed: [], notCreated, notUpdated: {}, notDestroyed: {} };
}

function asObjectLocal(v: unknown): Record<string, unknown> | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}
function resolveRef(v: unknown, createdIds: Record<string, string>): string | null {
  if (typeof v !== "string") return null;
  return v.startsWith("#") ? (createdIds[v.slice(1)] ?? null) : v;
}

function wrapStore(err: unknown): Error {
  if (err instanceof StoreError) return new SetItemError("invalidProperties", { description: err.message });
  return err instanceof Error ? err : new Error(String(err));
}

/** keywords 패치 → add/remove. */
function keywordChange(patch: Record<string, unknown>, full: boolean, paths: string[], current: Set<string>): { add: string[]; remove: string[] } {
  if (full) {
    const kwObj = patch.keywords;
    if (typeof kwObj !== "object" || kwObj === null || Array.isArray(kwObj)) throw new SetItemError("invalidProperties", { properties: ["keywords"] });
    const desired = new Set<string>();
    for (const [k, v] of Object.entries(kwObj as Record<string, unknown>)) {
      if (v !== true) throw new SetItemError("invalidProperties", { description: "keyword 값은 true여야 함" });
      desired.add(k.toLowerCase());
    }
    return { add: [...desired].filter((k) => !current.has(k)), remove: [...current].filter((k) => !desired.has(k)) };
  }
  const add: string[] = [];
  const remove: string[] = [];
  for (const key of paths) {
    const kw = key.slice("keywords/".length).toLowerCase();
    const v = patch[key];
    if (v === true) add.push(kw);
    else if (v === null || v === false) remove.push(kw);
    else throw new SetItemError("invalidPatch", { description: `keyword 값 오류: ${key}` });
  }
  return { add, remove };
}

/** mailboxIds 패치 → 목표 집합. */
function desiredMailboxIds(patch: Record<string, unknown>, full: boolean, paths: string[], current: Set<string>): Set<string> {
  if (full) {
    const obj = patch.mailboxIds;
    if (typeof obj !== "object" || obj === null || Array.isArray(obj)) throw new SetItemError("invalidProperties", { properties: ["mailboxIds"] });
    const desired = new Set<string>();
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (v !== true) throw new SetItemError("invalidProperties", { description: "mailboxId 값은 true여야 함" });
      desired.add(k);
    }
    return desired;
  }
  const desired = new Set(current);
  for (const key of paths) {
    const mbx = key.slice("mailboxIds/".length);
    const v = patch[key];
    if (v === true) desired.add(mbx);
    else if (v === null || v === false) desired.delete(mbx);
    else throw new SetItemError("invalidPatch", { description: `mailboxId 값 오류: ${key}` });
  }
  return desired;
}

/** Email/get 기본 프로퍼티 (RFC 8621 §4.6). */
const DEFAULT_EMAIL_PROPS = [
  "id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt", "messageId", "inReplyTo", "references",
  "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview", "bodyValues", "textBody", "htmlBody", "attachments",
];

function strArrayOrNull(v: unknown, field: string): string[] | null {
  if (v === null || v === undefined) return null;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new MethodError("invalidArguments", { description: field });
  return v as string[];
}

/** Email/get (RFC 8621 §4.6) — 메타는 DB, 본문 프로퍼티 요청 시에만 블롭 파싱. ids=null은 미지원. */
async function emailGet(args: Record<string, unknown>, accountId: string, db: DbDriver, store: Store, blobs: BlobStore): Promise<Record<string, unknown>> {
  const acc = await requestedAccountId(args, accountId);
  const context = await principalContext(db, accountId);
  const allowedMailboxIds = await store.accessibleMailboxIds(context, acc);
  if (acc !== accountId && allowedMailboxIds.length === 0) throw new MethodError("accountNotFound");
  const ids = strArrayOrNull(args.ids, "ids");
  if (ids === null) throw new MethodError("invalidArguments", { description: "Email/get은 ids 필수(Email/query로 먼저 조회)" });
  const properties = strArrayOrNull(args.properties, "properties") ?? DEFAULT_EMAIL_PROPS;
  const propSet = new Set(properties);
  const maxBodyValueBytes = typeof args.maxBodyValueBytes === "number" && args.maxBodyValueBytes > 0 ? args.maxBodyValueBytes : 0;
  const fetchText = args.fetchTextBodyValues === true;
  const fetchHtml = args.fetchHTMLBodyValues === true;
  const fetchAll = args.fetchAllBodyValues === true;

  // 본문/헤더 파생 프로퍼티가 하나라도 요청되면 블롭 파싱 필요
  const needBody = properties.some((p) => !CHEAP_EMAIL_PROPS.has(p));

  const state = await scopedJmapState(db, store, accountId, acc, "email");
  const metas = await store.getEmailsForJmap(acc, ids, allowedMailboxIds);
  const byId = new Map(metas.map((m) => [m.id, m]));

  const list: JmapObject[] = [];
  const notFound: string[] = [];
  for (const id of ids) {
    const meta = byId.get(id);
    if (!meta) {
      notFound.push(id);
      continue;
    }
    const obj = toJmapEmailMeta(meta);
    if (needBody) {
      let raw: Uint8Array | null = null;
      try {
        raw = await blobs.get(meta.blobId, meta.blobGeneration);
      } catch {
        raw = null; // 블롭 소실 — 본문 프로퍼티는 null/빈값(메타는 유지)
      }
      addBodyProps(obj, raw, { fetchText, fetchHtml, fetchAll, maxBodyValueBytes });
    }
    list.push(project(obj, propSet));
  }
  return { accountId: acc, state, list, notFound };
}

/** 블롭에서 본문/헤더 파생 프로퍼티 추가(RFC 8621 §4.1). raw=null이면 안전한 빈값. */
function addBodyProps(
  obj: JmapObject,
  raw: Uint8Array | null,
  opts: { fetchText: boolean; fetchHtml: boolean; fetchAll: boolean; maxBodyValueBytes: number },
): void {
  if (raw === null) {
    obj.bodyStructure = null;
    obj.textBody = [];
    obj.htmlBody = [];
    obj.attachments = [];
    obj.bodyValues = {};
    obj.messageId = null;
    obj.inReplyTo = null;
    obj.references = null;
    return;
  }
  const parsed = parseMessage(raw);
  obj.messageId = parsed.messageId === null ? null : [parsed.messageId];
  obj.inReplyTo = parsed.inReplyTo.length > 0 ? parsed.inReplyTo : null;
  obj.references = parsed.references.length > 0 ? parsed.references : null;

  const body = extractJmapBody(raw, opts.maxBodyValueBytes);
  obj.bodyStructure = body.bodyStructure as unknown as Record<string, unknown>;
  obj.textBody = body.textBody as unknown as Record<string, unknown>[];
  obj.htmlBody = body.htmlBody as unknown as Record<string, unknown>[];
  obj.attachments = body.attachments as unknown as Record<string, unknown>[];

  // bodyValues는 fetch* 플래그가 지정한 파트만(RFC 8621 §4.6)
  const wantParts = new Set<string>();
  if (opts.fetchAll) for (const k of Object.keys(body.bodyValues)) wantParts.add(k);
  if (opts.fetchText) for (const p of body.textBody) if (p.partId) wantParts.add(p.partId);
  if (opts.fetchHtml) for (const p of body.htmlBody) if (p.partId) wantParts.add(p.partId);
  const bodyValues: Record<string, unknown> = {};
  for (const [partId, v] of Object.entries(body.bodyValues)) {
    if (wantParts.has(partId)) bodyValues[partId] = v;
  }
  obj.bodyValues = bodyValues;
}

/** id는 항상 포함, 요청 프로퍼티만 남김. */
function project(obj: JmapObject, props: Set<string>): JmapObject {
  const out: JmapObject = { id: obj.id };
  for (const p of props) {
    if (p !== "id" && p in obj) out[p] = obj[p];
  }
  return out;
}

/** Email/query (RFC 8621 §4.4, v1) — inMailbox/날짜/크기/키워드 필터 + receivedAt 정렬. */
async function emailQuery(args: Record<string, unknown>, accountId: string, db: DbDriver, store: Store): Promise<Record<string, unknown>> {
  const acc = await requestedAccountId(args, accountId);
  const context = await principalContext(db, accountId);
  const allowedMailboxIds = await store.accessibleMailboxIds(context, acc);
  if (acc !== accountId && allowedMailboxIds.length === 0) throw new MethodError("accountNotFound");
  const state = await scopedJmapState(db, store, accountId, acc, "email");

  const filter: JmapEmailFilter = {};
  if (args.filter !== undefined && args.filter !== null) {
    if (typeof args.filter !== "object" || Array.isArray(args.filter)) throw new MethodError("unsupportedFilter");
    const f = args.filter as Record<string, unknown>;
    const allowed = ["inMailbox", "before", "after", "minSize", "maxSize", "hasKeyword", "notKeyword", "text", "subject", "body", "from", "to"];
    for (const key of Object.keys(f)) if (!allowed.includes(key)) throw new MethodError("unsupportedFilter", { description: key });
    if (typeof f.inMailbox === "string") filter.inMailbox = f.inMailbox;
    if (typeof f.before === "string") filter.before = Date.parse(f.before);
    if (typeof f.after === "string") filter.after = Date.parse(f.after);
    if (typeof f.minSize === "number") filter.minSize = f.minSize;
    if (typeof f.maxSize === "number") filter.maxSize = f.maxSize;
    if (typeof f.hasKeyword === "string") filter.hasKeyword = f.hasKeyword;
    if (typeof f.notKeyword === "string") filter.notKeyword = f.notKeyword;
    // 전문 검색(FTS, RFC 8621 §4.4.1) — search_index CJK 바이그램 배선
    if (typeof f.text === "string") filter.text = f.text;
    if (typeof f.subject === "string") filter.subject = f.subject;
    if (typeof f.body === "string") filter.body = f.body;
    if (typeof f.from === "string") filter.from = f.from;
    if (typeof f.to === "string") filter.to = f.to;
  }

  // 정렬 — v1은 receivedAt만(기본 내림차순). 다른 프로퍼티는 unsupportedSort.
  let ascending = false;
  const sort = args.sort;
  if (Array.isArray(sort) && sort.length > 0) {
    if (sort.length > 1) throw new MethodError("unsupportedSort", { description: "다중 정렬 미지원(v1)" });
    const s = sort[0] as Record<string, unknown>;
    if (s.property !== "receivedAt") throw new MethodError("unsupportedSort", { description: String(s.property) });
    ascending = s.isAscending === true;
  }

  const position = typeof args.position === "number" && args.position >= 0 ? args.position : 0;
  const limit = typeof args.limit === "number" && args.limit >= 0 ? Math.min(args.limit, 500) : 500;
  const { ids, total } = await store.queryEmails(acc, filter, ascending, position, limit, allowedMailboxIds);
  return { accountId: acc, queryState: state, canCalculateChanges: false, position, total, limit, ids };
}

async function jmapThreadGet(args: Record<string, unknown>, accountId: string, db: DbDriver, store: Store): Promise<Record<string, unknown>> {
  const acc = await requestedAccountId(args, accountId);
  const ids = args.ids;
  if (ids !== null && ids !== undefined && (!Array.isArray(ids) || ids.some((id) => typeof id !== "string"))) throw new MethodError("invalidArguments");
  const context = await principalContext(db, accountId);
  const allowedMailboxIds = await store.accessibleMailboxIds(context, acc);
  if (acc !== accountId && allowedMailboxIds.length === 0) throw new MethodError("accountNotFound");
  const threads = await store.getThreadsForJmap(acc, ids === null || ids === undefined ? null : ids as string[], allowedMailboxIds);
  const list = threads.map((thread) => ({ id: thread.id, emailIds: thread.emailIds }));
  const found = new Set(list.map((thread) => thread.id));
  const notFound = ids === null || ids === undefined ? [] : (ids as string[]).filter((id) => !found.has(id));
  return { accountId: acc, state: await scopedJmapState(db, store, accountId, acc, "thread"), list, notFound };
}

/**
 * Mailbox/query (RFC 8621 §2.3) — 필터(parentId/role/hasAnyRole/isSubscribed) + 정렬(sortOrder,name)
 * + 페이징. 메일함은 소수라 전량 로드 후 앱에서 처리. canCalculateChanges=false(v1).
 */
async function mailboxQuery(args: Record<string, unknown>, accountId: string, store: Store): Promise<Record<string, unknown>> {
  const acc = requireAccountId(args, accountId);
  const state = (await store.jmapState(acc)).mailbox;
  let rows = await store.listMailboxes(acc);

  const filter = args.filter;
  if (filter !== undefined && filter !== null) {
    if (typeof filter !== "object" || Array.isArray(filter)) throw new MethodError("unsupportedFilter");
    const f = filter as Record<string, unknown>;
    for (const key of Object.keys(f)) {
      if (!["parentId", "role", "hasAnyRole", "isSubscribed"].includes(key)) throw new MethodError("unsupportedFilter", { description: key });
    }
    if ("parentId" in f) {
      const pid = f.parentId === null ? "" : f.parentId;
      rows = rows.filter((m) => m.parentId === pid);
    }
    if ("role" in f) rows = rows.filter((m) => m.role === f.role);
    if (typeof f.hasAnyRole === "boolean") rows = rows.filter((m) => (m.role !== null) === f.hasAnyRole);
    if (typeof f.isSubscribed === "boolean") rows = rows.filter((m) => m.subscribed === f.isSubscribed);
  }

  // 정렬 — 지원: sortOrder, name. 미지원 프로퍼티는 unsupportedSort.
  const sort = args.sort;
  if (Array.isArray(sort) && sort.length > 0) {
    const comparators: ((a: MailboxRow, b: MailboxRow) => number)[] = [];
    for (const s of sort) {
      const prop = (s as Record<string, unknown>)?.property;
      const asc = (s as Record<string, unknown>)?.isAscending !== false;
      const dir = asc ? 1 : -1;
      if (prop === "sortOrder") comparators.push(() => 0); // 전부 0 — 안정정렬 유지
      else if (prop === "name") comparators.push((a, b) => dir * a.name.localeCompare(b.name));
      else throw new MethodError("unsupportedSort", { description: String(prop) });
    }
    rows = [...rows].sort((a, b) => {
      for (const cmp of comparators) {
        const r = cmp(a, b);
        if (r !== 0) return r;
      }
      return 0;
    });
  }

  const total = rows.length;
  const position = typeof args.position === "number" && args.position >= 0 ? args.position : 0;
  const limit = typeof args.limit === "number" && args.limit >= 0 ? Math.min(args.limit, 500) : 500;
  const ids = rows.slice(position, position + limit).map((m) => m.id);

  return {
    accountId: acc,
    queryState: state,
    canCalculateChanges: false,
    position,
    total,
    limit,
    ids,
  };
}

/**
 * Email/import (RFC 8621 §4.8) — 업로드된 블롭을 메일함에 들인다.
 *
 * ★변이 자체는 `Email/set`의 create와 **같은 코드**를 부른다. 같은 일(블롭 파싱 → 배치)을
 * 두 벌로 두면 한쪽만 고쳐져 갈라진다 — 이 저장소가 반복해서 겪은 사고다. 다른 것은 봉투뿐:
 * `create`가 아니라 `emails`를 받고, 결과 키가 `created`/`notCreated`다.
 *
 * ★`Email/set`과 달리 `#creationId` 참조가 없다(§4.8: 이미 업로드된 블롭만 들인다).
 * 그래서 빈 `createdIds`를 넘긴다 — 넘기지 않으면 소스가 mailboxIds의 `#` 접두사를
 * 해석하려다 미정의를 만난다.
 */
async function emailImport(
  args: Record<string, unknown>,
  ctx: MethodContext,
  store: Store,
  source: SetSource,
): Promise<Record<string, unknown>> {
  const acc = requireAccountId(args, ctx.accountId);
  const oldState = (await store.jmapState(acc)).email;

  if (args.ifInState !== undefined && args.ifInState !== null) {
    if (typeof args.ifInState !== "string") throw new MethodError("invalidArguments", { description: "ifInState" });
    if (args.ifInState !== oldState) throw new MethodError("stateMismatch");
  }

  const emails = args.emails;
  if (typeof emails !== "object" || emails === null || Array.isArray(emails)) {
    throw new MethodError("invalidArguments", { description: "emails는 객체여야 함" });
  }

  // 프로토타입 없는 집계 — 키가 전부 클라이언트 문자열이다(set.ts의 같은 주석 참조).
  const created = Object.create(null) as Record<string, Record<string, unknown>>;
  const notCreated = Object.create(null) as Record<string, unknown>;

  for (const [id, props] of Object.entries(emails as Record<string, unknown>)) {
    // `created[id] = …`가 프로토타입 교체가 되면 그 항목이 응답에서 조용히 사라진다(safe-key.ts).
    if (isUnsafeKey(id)) {
      notCreated[id] = { type: "invalidProperties", description: "허용되지 않는 id" };
      continue;
    }
    if (typeof props !== "object" || props === null || Array.isArray(props)) {
      notCreated[id] = { type: "invalidProperties", description: "객체가 아님" };
      continue;
    }
    if (!source.create) {
      notCreated[id] = { type: "forbidden", description: "import 미지원" };
      continue;
    }
    try {
      const { id: newId, serverProps } = await source.create(acc, props as Record<string, unknown>, { ...ctx, createdIds: {} });
      created[id] = { id: newId, ...serverProps };
    } catch (err) {
      if (err instanceof SetItemError) {
        notCreated[id] = err.setError;
        continue;
      }
      throw err;
    }
  }

  const newState = (await store.jmapState(acc)).email;
  return { accountId: acc, oldState, newState, created, notCreated };
}


/**
 * Email/copy (RFC 8620 §5.4 · RFC 8621 §4.7) — **계정 간** 복사.
 *
 * ★이 서버의 세션에는 계정이 하나뿐이다. 그래서 이 메서드는 늘 거절로 끝나지만, 그 거절이
 * **규격이 정한 거절**인 것이 중요하다. 등록하지 않으면 클라이언트가 `unknownMethod`를 받고,
 * 그건 "이 서버는 JMAP 메일을 제대로 안 한다"는 신호라 관련 기능 전체를 접게 만든다.
 *
 * · `fromAccountId === accountId` → `invalidArguments`.
 *   §5.4가 "This MUST be different to the 'fromAccountId'"라고만 하고 전용 오류를 두지
 *   않아서, 표준 오류 중 "인자가 유효하지 않다"에 해당하는 것을 쓴다.
 * · 그 밖의 `fromAccountId` → `fromAccountNotFound`. 세션이 아는 계정이 하나뿐이므로
 *   다른 이름은 전부 "없는 계정"이 맞다 — 있는 척하고 빈 결과를 주면 클라이언트가
 *   "복사했는데 아무것도 안 왔다"로 읽는다.
 */
async function emailCopy(args: Record<string, unknown>, accountId: string): Promise<Record<string, unknown>> {
  requireAccountId(args, accountId);
  const from = args.fromAccountId;
  if (typeof from !== "string" || from.length === 0) {
    throw new MethodError("invalidArguments", { description: "fromAccountId 누락" });
  }
  if (from === accountId) {
    throw new MethodError("invalidArguments", { description: "fromAccountId는 accountId와 달라야 함" });
  }
  throw new MethodError("fromAccountNotFound");
}

/**
 * SearchSnippet/get (RFC 8621 §5) — 검색 결과에 "왜 걸렸는지"를 보여 주는 조각.
 *
 * ★`message_text`의 **유일한 독자**다. 그 테이블은 여태 쓰기만 하고 아무도 읽지 않아서
 * 순수 비용이자 프라이버시 표면이었는데(감사 G3), 이 메서드가 그 존재 이유다.
 * 여기를 지우면 `message_text` 쓰기도 함께 지워야 한다.
 *
 * ★인출은 **계정으로 좁혀서** 한다(`getMessageTextForSnippets`). `message_text`에는
 * account_id가 없어서 id만으로 조회하면 남의 메일 본문이 나온다.
 *
 * ★조각이 없는 것(`notFound`)과 매치가 없는 것(`subject: null`)은 다르다. 전자는 그런
 * 메시지가 없다는 뜻이고, 후자는 있는데 검색어가 그 부분에 없다는 뜻이다.
 */
async function searchSnippetGet(args: Record<string, unknown>, accountId: string, store: Store): Promise<Record<string, unknown>> {
  const acc = requireAccountId(args, accountId);
  const emailIds = args.emailIds;
  if (!Array.isArray(emailIds) || emailIds.some((x) => typeof x !== "string")) {
    throw new MethodError("invalidArguments", { description: "emailIds는 문자열 배열이어야 함" });
  }
  if (emailIds.length > MAX_SNIPPET_EMAILS) {
    // §5는 상한을 `maxObjectsInGet`으로 두라고 한다 — 조각은 본문을 읽으므로 더욱 상한이 필요하다.
    throw new MethodError("requestTooLarge", { description: `emailIds는 최대 ${MAX_SNIPPET_EMAILS}개` });
  }

  const terms = snippetTermsFromFilter(args.filter);
  const texts = await store.getMessageTextForSnippets(acc, emailIds as string[]);

  const list: Record<string, unknown>[] = [];
  const notFound: string[] = [];
  for (const id of emailIds as string[]) {
    const t = texts.get(id);
    if (!t) {
      notFound.push(id);
      continue;
    }
    list.push({ emailId: id, subject: buildSnippet(t.subject, terms), preview: buildSnippet(t.body, terms) });
  }
  return { accountId: acc, list, notFound };
}


/**
 * JMAP Quota (RFC 9425) — **데이터는 이미 있다.** `accounts.quota_bytes`/`used_bytes`/
 * `message_count`가 그것이고, IMAP QUOTA(RFC 9208)가 같은 값을 이미 보여 준다.
 * 두 표면이 같은 소스를 봐야 "IMAP에서는 찼다는데 JMAP에서는 아니다"가 생기지 않는다.
 */
export function buildQuotaModule(store: Store): CapabilityModule {
  /** 쿼터 객체 두 개 — 저장 용량과 메시지 수. id가 곧 resourceType이다(루트가 하나뿐이라). */
  const quotaObjects = async (accountId: string): Promise<JmapObject[]> => {
    const q = await store.getQuota(accountId);
    return [
      {
        id: "octets",
        resourceType: "octets",
        used: q.usedBytes,
        // `quota_bytes === 0`은 **무제한**이다(스토어의 기존 계약) — JMAP에서는 null이 그 뜻이다.
        hardLimit: q.quotaBytes > 0 ? q.quotaBytes : null,
        scope: "account",
        name: "account-storage",
        types: ["Mail"],
        warnLimit: null,
        softLimit: null,
        description: null,
      },
      {
        id: "count",
        resourceType: "count",
        used: q.messageCount,
        // 메시지 수 상한은 두지 않는다 — 스키마에 그런 컬럼이 없고, 있는 척하면 거짓이다.
        hardLimit: null,
        scope: "account",
        name: "account-messages",
        types: ["Mail"],
        warnLimit: null,
        softLimit: null,
        description: null,
      },
    ];
  };

  const getSource: GetSource = {
    // 쿼터는 메시지가 오갈 때마다 바뀐다 — email state를 그대로 쓴다(같은 것이 움직이면 같이 움직인다).
    state: async (accountId) => (await store.jmapState(accountId)).email,
    get: async (accountId, ids) => {
      const all = await quotaObjects(accountId);
      if (ids === null) return { list: all, notFound: [] };
      const byId = new Map(all.map((q) => [q.id, q]));
      const list: JmapObject[] = [];
      const notFound: string[] = [];
      for (const id of ids) {
        const o = byId.get(id);
        if (o) list.push(o);
        else notFound.push(id);
      }
      return { list, notFound };
    },
  };

  return {
    capability: QUOTA_CAPABILITY,
    methods: {
      "Quota/get": (args, ctx) => standardGet(args, ctx.accountId, getSource),
      /**
       * ★델타를 계산할 수 없다. `change_log`는 쿼터 변화를 따로 적지 않고, 적더라도
       * "얼마나 늘었나"는 메시지 변화에서 유도되는 값이라 별도 기록이 중복이다.
       * 규격이 그 상황을 위해 둔 오류를 낸다 — 클라이언트는 `Quota/get`을 다시 부르면 된다.
       */
      "Quota/changes": (args, ctx) => standardChanges(args, ctx.accountId, { changes: async () => ({ cannotCalculate: true }) }),
      /**
       * 쿼터 객체는 **둘뿐**이라 질의가 전량 나열과 같다. 필터·정렬을 받아 주는 척하지 않고
       * 명시적으로 거절한다 — 받아 놓고 무시하면 클라이언트가 걸러진 줄 안다.
       */
      "Quota/query": async (args, ctx) => {
        const acc = requireAccountId(args, ctx.accountId);
        if (args.filter !== undefined && args.filter !== null) throw new MethodError("unsupportedFilter");
        if (Array.isArray(args.sort) && args.sort.length > 0) throw new MethodError("unsupportedSort");
        const ids = (await quotaObjects(acc)).map((q) => q.id);
        const state = (await store.jmapState(acc)).email;
        return { accountId: acc, queryState: state, canCalculateChanges: false, position: 0, total: ids.length, limit: ids.length, ids };
      },
    },
  };
}


/**
 * JMAP VacationResponse (RFC 8621 §8) — 부재 자동 응답 **설정**의 싱글턴.
 *
 * ★설정만 여기 있고 **판정은 배달 경로가 한다.** RFC 5230 §4.6의 루프 방지 게이트와
 * 중복 억제(`vacation_sent`)는 Sieve `vacation`이 쓰는 것을 그대로 쓴다 — 두 벌로 두면
 * 자동 응답이 두 번 나가거나, 한쪽만 게이트를 고쳐서 메일링리스트에 부재 알림을 뿌린다.
 *
 * ★Sieve 스크립트를 생성하지 않는다. 생성하면 `/get`에서 다시 파싱해야 하고, 그러면
 * 사용자가 손으로 고친 스크립트를 우리가 덮어쓰거나 잘못 읽는 갈래가 생긴다.
 */
export function buildVacationModule(db: DbDriver, store: Store): CapabilityModule {
  /** 싱글턴 id는 규격이 `"singleton"`으로 못박았다(§8). */
  const SINGLETON = "singleton";

  const toJmap = (v: VacationResponseRow): JmapObject => ({
    id: SINGLETON,
    isEnabled: v.isEnabled,
    fromDate: v.fromDate === null ? null : new Date(v.fromDate).toISOString(),
    toDate: v.toDate === null ? null : new Date(v.toDate).toISOString(),
    subject: v.subject,
    textBody: v.textBody,
    htmlBody: v.htmlBody,
  });

  const getSource: GetSource = {
    state: async (accountId) => (await store.jmapState(accountId)).email,
    get: async (accountId, ids) => {
      const v = await getVacationResponse(db, accountId);
      // 싱글턴 외의 id는 notFound다 — 없는 객체를 만들어 주지 않는다.
      if (ids !== null && !ids.includes(SINGLETON)) return { list: [], notFound: [...ids] };
      const notFound = ids === null ? [] : ids.filter((i) => i !== SINGLETON);
      return { list: [toJmap(v)], notFound };
    },
  };

  /** ISO 날짜 → epoch ms. `null`은 "제한 없음", 형식 오류는 SetItemError. */
  const parseDate = (raw: unknown, field: string): number | null => {
    if (raw === null || raw === undefined) return null;
    if (typeof raw !== "string") throw new SetItemError("invalidProperties", { properties: [field] });
    const ms = Date.parse(raw);
    if (Number.isNaN(ms)) throw new SetItemError("invalidProperties", { properties: [field] });
    return ms;
  };
  const parseText = (raw: unknown, field: string): string | null => {
    if (raw === null || raw === undefined) return null;
    if (typeof raw !== "string") throw new SetItemError("invalidProperties", { properties: [field] });
    return raw;
  };

  const setSource: SetSource = {
    state: async (accountId) => (await store.jmapState(accountId)).email,
    /**
     * ★생성은 없다 — 싱글턴은 **항상 존재한다**(§8: 서버가 하나를 갖고 있다).
     * `create`를 지원하는 척하면 클라이언트가 만들려다 실패하고, 실패 이유가 모호해진다.
     */
    update: async (accountId, id, patch) => {
      if (id !== SINGLETON) throw new SetItemError("notFound");
      const cur = await getVacationResponse(db, accountId);
      /**
       * ★패치는 현재 값 **위에** 얹는다. 통째로 덮으면 `isEnabled`만 바꾸려던 클라이언트가
       * 본문을 지우게 된다 — RFC 8620 §5.3의 PatchObject 시맨틱이 그것이다.
       */
      const next: VacationResponseRow = {
        isEnabled: "isEnabled" in patch ? patch.isEnabled === true : cur.isEnabled,
        fromDate: "fromDate" in patch ? parseDate(patch.fromDate, "fromDate") : cur.fromDate,
        toDate: "toDate" in patch ? parseDate(patch.toDate, "toDate") : cur.toDate,
        subject: "subject" in patch ? parseText(patch.subject, "subject") : cur.subject,
        textBody: "textBody" in patch ? parseText(patch.textBody, "textBody") : cur.textBody,
        htmlBody: "htmlBody" in patch ? parseText(patch.htmlBody, "htmlBody") : cur.htmlBody,
      };
      /**
       * ★켜면서 본문이 없으면 거절한다. 빈 자동 응답은 상대에게 빈 메일을 보내는 것이라
       * 안 보내느니만 못하고, 사용자는 켜 뒀다고 믿는다.
       */
      if (next.isEnabled && (next.textBody ?? "").trim() === "" && (next.htmlBody ?? "").trim() === "") {
        throw new SetItemError("invalidProperties", { properties: ["textBody"], description: "본문 없이 켤 수 없습니다" });
      }
      if (next.fromDate !== null && next.toDate !== null && next.fromDate > next.toDate) {
        throw new SetItemError("invalidProperties", { properties: ["fromDate", "toDate"], description: "fromDate가 toDate보다 늦습니다" });
      }
      await setVacationResponse(db, accountId, next);
      return null;
    },
    // 삭제도 없다 — 싱글턴을 지울 수 없다. 끄려면 `isEnabled: false`다.
  };

  return {
    capability: VACATION_CAPABILITY,
    methods: {
      "VacationResponse/get": (args, ctx) => standardGet(args, ctx.accountId, getSource),
      "VacationResponse/set": (args, ctx) => standardSet(args, ctx.accountId, ctx, setSource),
    },
  };
}


/**
 * `Identity/set` (RFC 8621 §6.3).
 *
 * ★핵심은 **주소 소유 검사**다. 없으면 사용자가 남의 주소로 신원을 만들 수 있다. 발송
 * 게이트(`enqueueMessage`의 §8 도메인 검증)가 나중에 막긴 하지만, 그때는 사용자가 이미
 * 보낸 줄 아는 상태다 — 실패는 **만들 때** 나야 원인이 보인다.
 *
 * ★기본 신원은 **합성**이다(`getIdentities`가 신원 행이 없으면 계정 주소로 하나를 만든다).
 * 그건 DB에 없으므로 수정·삭제 대상이 아니고, 그 사실을 `notFound`로 알린다 —
 * 조용히 성공시키면 사용자가 바꿨다고 믿는다.
 */
function buildIdentitySetSource(store: Store): SetSource {
  const str = (raw: unknown, field: string, allowNull: boolean): string | null => {
    if (raw === null || raw === undefined) {
      if (allowNull) return null;
      throw new SetItemError("invalidProperties", { properties: [field] });
    }
    if (typeof raw !== "string") throw new SetItemError("invalidProperties", { properties: [field] });
    return raw;
  };

  const requireOwned = async (accountId: string, email: string): Promise<void> => {
    const allowed = await store.sendableAddresses(accountId);
    if (!allowed.has(email.toLowerCase())) {
      /**
       * ★`forbidden`이지 `invalidProperties`가 아니다. 주소 형식이 틀린 게 아니라 **권한이
       * 없는** 것이고, 클라이언트가 그 둘을 다르게 표시해야 사용자가 무엇을 고칠지 안다.
       */
      throw new SetItemError("forbidden", { description: `보낼 수 없는 주소입니다: ${email}` });
    }
  };

  return {
    state: async (accountId) => (await store.jmapState(accountId)).submission,
    create: async (accountId, props) => {
      const email = str(props.email, "email", false)!;
      await requireOwned(accountId, email);
      const v = {
        email,
        name: str(props.name, "name", true),
        replyTo: str(props.replyTo, "replyTo", true),
        textSignature: str(props.textSignature, "textSignature", true) ?? "",
        htmlSignature: str(props.htmlSignature, "htmlSignature", true) ?? "",
      };
      const id = await store.createIdentity(accountId, v);
      // 서버가 정하는 값(RFC 8621 §6.1: mayDelete는 서버 소관)도 함께 돌려준다.
      return { id, serverProps: { ...v, mayDelete: true } };
    },
    update: async (accountId, id, patch) => {
      const all = await store.getIdentities(accountId);
      const cur = all.find((i) => i.id === id);
      if (!cur) throw new SetItemError("notFound");
      // 패치는 현재 값 **위에** 얹는다 — 통째로 덮으면 서명만 바꾸려다 이름이 지워진다.
      const v = {
        email: "email" in patch ? str(patch.email, "email", false)! : cur.email,
        name: "name" in patch ? str(patch.name, "name", true) : cur.name,
        replyTo: "replyTo" in patch ? str(patch.replyTo, "replyTo", true) : cur.replyTo,
        textSignature: "textSignature" in patch ? (str(patch.textSignature, "textSignature", true) ?? "") : cur.textSignature,
        htmlSignature: "htmlSignature" in patch ? (str(patch.htmlSignature, "htmlSignature", true) ?? "") : cur.htmlSignature,
      };
      if (v.email.toLowerCase() !== cur.email.toLowerCase()) await requireOwned(accountId, v.email);
      // 합성 기본 신원은 DB에 없다 — 바꿨다고 믿게 두지 않는다.
      if (!(await store.updateIdentity(accountId, id, v))) throw new SetItemError("notFound");
      return null;
    },
    destroy: async (accountId, id) => {
      if (!(await store.deleteIdentity(accountId, id))) throw new SetItemError("notFound");
    },
  };
}
