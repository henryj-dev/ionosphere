// POP3 표면 — PLAN.md §4: 순수 상태머신(engine) + 얇은 소켓 어댑터(server). 스토어 계약: docs/SCHEMA.md §7-5
export {
  Pop3Engine,
  type Pop3Action,
  type Pop3AuthResult,
  type Pop3EngineMessage,
  type Pop3EngineOptions,
  type Pop3OpenMaildropResult,
  type Pop3RetrieveResult,
  type Pop3State,
} from "./engine.ts";
export {
  InProcessMaildropLock,
  Pop3Server,
  type Pop3Backend,
  type Pop3MaildropMessage,
  type Pop3ServerOptions,
} from "./server.ts";
