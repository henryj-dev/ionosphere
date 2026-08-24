// @ionosphere/sieve — Sieve 인터프리터 (RFC 5228 + fileinto/envelope/imap4flags/copy). 순수, I/O 없음.
export { parseSieve } from "./parser.ts";
export { tokenize, SieveSyntaxError, type Token } from "./lexer.ts";
export { runSieve, SieveError, SUPPORTED_EXTENSION_LIST, type SieveEnv, type SieveResult, type VacationRequest } from "./interpret.ts";
export type { SieveArg, SieveCommand, SieveTest } from "./ast.ts";
