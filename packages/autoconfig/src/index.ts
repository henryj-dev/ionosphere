// 클라이언트 자동설정(Thunderbird/Outlook/Apple) — 순수 생성기 + 얇은 HTTP 어댑터.
export {
  appleMobileconfig,
  autodiscoverPox,
  autodiscoverV2,
  deterministicUuid,
  thunderbirdAutoconfig,
  xmlEscape,
  type AutoconfigSettings,
} from "./generate.ts";
export {
  domainFromHost,
  emailFromAutodiscoverBody,
  handleAutoconfig,
  type AutoconfigRequest,
  type AutoconfigResponse,
} from "./handler.ts";
export { AutoconfigServer, type AutoconfigServerDeps } from "./server.ts";
