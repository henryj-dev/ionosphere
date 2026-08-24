// @ionosphere/proto-imap — IMAP 순수 파서 + 상태머신 (Phase 3). 소켓 어댑터는 추후 server.ts.
export {
  ImapEngine,
  type ImapAction,
  type ImapAuthResult,
  type ImapBackendRequest,
  type ImapBackendResponse,
  type ImapEngineOptions,
  type ImapFetchData,
  type ImapMailbox,
  type ImapState,
} from "./engine.ts";
export {
  extractSection,
  formatBodyStructure,
  formatEnvelope,
  formatInternalDate,
  literalWire,
  nstring,
  wireToBytes,
  type SectionSpec,
} from "./fetch-format.ts";
export { parseFetchItems, type FetchItem } from "./fetch-items.ts";
export { ImapServer, type ImapBackend, type ImapServerOptions } from "./server.ts";
export {
  HIERARCHY_DELIMITER,
  matchesListPattern,
  normalizeMailboxName,
  quoteMailboxName,
  roleToAttribute,
} from "./list-match.ts";
export { ImapLineReader, type LinePart, type LineReaderOptions, type ReaderEvent } from "./reader.ts";
export {
  ImapParseError,
  parseCommand,
  parseValues,
  valueText,
  type ImapValue,
  type ParsedCommand,
} from "./parser.ts";
export { matchSequenceSet, normalizeRanges, parseSequenceSet, type SeqRange } from "./sequence-set.ts";
export { formatSortLine, formatThreadLine, parseSortSpec, type ImapSortKeys, type SortItem, type SortSpec } from "./sort-thread.ts";
