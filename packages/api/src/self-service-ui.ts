/**
 * 메일 계정 셀프서비스 화면 — 자기완결 HTML(인라인 CSS/JS, 외부 리소스 0). 보안 헤더는 관리 콘솔과 같은 것을 쓴다.
 *
 * 세션은 HttpOnly 쿠키로만 다니고, CSRF 토큰은 메모리에만 둔다(`GET /account/session`이 다시 준다).
 *
 * 이 파일의 HTML/JS는 TS 템플릿 리터럴 안에 있다 — 내부에서 백틱과 달러-중괄호를 쓰지 말 것(문자열 결합으로).
 * JS 문자열 안의 큰따옴표는 이스케이프하지 말고 작은따옴표로 감쌀 것(admin-ui.ts 머리말과 같은 이유).
 */
export const SELF_SERVICE_UI_HTML = `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>메일 계정 관리</title>
<style>
  :root { color-scheme: light dark; --bd: #8883; --acc: #3b82f6; --danger: #dc2626; }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 system-ui, sans-serif; margin: 0 auto; padding: 1.2rem; max-width: 760px; }
  h1 { font-size: 1.2rem; margin: 0 0 .8rem; }
  h2 { font-size: 1rem; margin: 1.2rem 0 .4rem; }
  input, button { font: inherit; padding: .4rem .5rem; border: 1px solid var(--bd); border-radius: 6px; background: transparent; color: inherit; }
  button { cursor: pointer; background: var(--acc); color: #fff; border-color: transparent; }
  button.ghost { background: transparent; color: inherit; border-color: var(--bd); }
  .row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: flex-end; margin: .3rem 0; }
  .field { display: flex; flex-direction: column; gap: .15rem; }
  .field > span { font-size: 12px; opacity: .7; }
  .field small { font-size: 11px; opacity: .6; max-width: 26rem; }
  .card { border: 1px solid var(--bd); border-radius: 8px; padding: .8rem; margin-top: .6rem; }
  .hidden { display: none; }
  .muted { opacity: .65; }
  .err { color: var(--danger); }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--bd); font-size: 13px; }
  .secret { border: 2px solid var(--acc); border-radius: 8px; padding: .8rem; margin: .6rem 0; }
  .secret .value { font: 600 16px/1.5 ui-monospace, monospace; user-select: all; word-break: break-all; }
</style>
</head>
<body>
<h1>메일 계정 관리</h1>
<div class="card" id="login">
  <div class="row">
    <label class="field"><span>메일 주소</span><input id="email" autocomplete="username" size="26"></label>
    <label class="field"><span>비밀번호</span><input id="password" type="password" autocomplete="current-password" size="18"><small>메일 계정의 기본 비밀번호(앱 비밀번호는 안 됩니다)</small></label>
    <label class="field"><span>TOTP</span><input id="totp" inputmode="numeric" autocomplete="one-time-code" size="8" placeholder="등록했다면"></label>
    <label class="field"><span>복구 코드</span><input id="recovery" autocomplete="off" size="12" placeholder="앱을 잃었다면"></label>
    <button id="signin">로그인</button>
  </div>
  <p id="loginStatus" class="err"></p>
</div>
<div class="card hidden" id="app">
  <div class="row"><span id="whoami"></span> <button id="signout" class="ghost">로그아웃</button></div>
  <div id="secret"></div>
  <div id="enroll" class="hidden">
    <h2>인증 앱(TOTP) 등록</h2>
    <p class="muted">비밀번호 변경·앱 비밀번호 발급은 TOTP를 등록해야 할 수 있습니다. 등록 코드는 관리자에게서 따로 받습니다.</p>
    <div id="enrollSecret"></div>
    <div class="row">
      <label class="field"><span>등록 코드</span><input id="enrollGrant" autocomplete="off" size="20"><small>복구 코드로 들어왔다면 자동으로 채워집니다. 비어 있으면 복구 코드를 하나 더 써서 다시 로그인하십시오.</small></label>
      <button id="enrollStart" class="ghost">비밀 만들기</button>
      <label class="field"><span>앱에 보이는 6자리</span><input id="enrollCode" inputmode="numeric" size="8"></label>
      <button id="enrollConfirm">등록 확정</button>
    </div>
  </div>
  <h2>앱 비밀번호</h2>
  <p class="muted">메일 앱마다 따로 발급해 쓰는 비밀번호입니다. 하나를 지워도 다른 앱은 계속 동작합니다.</p>
  <div class="row">
    <label class="field"><span>라벨</span><input id="apLabel" size="16" placeholder="iPhone Mail"></label>
    <button id="apCreate">발급</button>
  </div>
  <div id="apList"></div>
  <h2>비밀번호 변경</h2>
  <p class="muted">메일 앱의 앱 비밀번호는 그대로 유지됩니다. 바꾸면 이 화면에서 로그아웃됩니다.</p>
  <div class="row">
    <label class="field"><span>현재 비밀번호</span><input id="pwCurrent" type="password" autocomplete="current-password" size="16"></label>
    <label class="field"><span>새 비밀번호</span><input id="pwNew" type="password" autocomplete="new-password" size="16"></label>
    <button id="pwChange">변경</button>
  </div>
</div>
<script>
const $ = (s) => document.querySelector(s);
const state = { csrf: "", me: null, secret: null };

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && state.csrf) headers["x-csrf-token"] = state.csrf;
  const res = await fetch(path, { method, credentials: "same-origin", headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!res.ok) {
    const err = new Error((data && data.error) || res.status + " " + res.statusText);
    err.code = data && data.code ? data.code : "";
    throw err;
  }
  return data;
}

/** 민감 작업 — 서버가 step_up으로 거절하면 6자리를 받아 재인증하고 한 번만 다시 부른다. */
async function sensitive(method, path, body) {
  try {
    return await api(method, path, body);
  } catch (e) {
    if (e.code === "mfa_required") throw new Error("먼저 인증 앱(TOTP)을 등록해야 합니다");
    if (e.code !== "step_up") throw e;
    const code = window.prompt("인증 앱의 6자리 코드를 입력하십시오.");
    if (!code) throw e;
    await api("POST", "/account/session/mfa/verify", { code: code.trim() });
    return await api(method, path, body);
  }
}

function showSecret() {
  $("#secret").innerHTML = state.secret ? '<div class="secret"><div><strong>' + esc(state.secret.label) + '</strong></div><div class="value">' + esc(state.secret.value) + '</div><div class="muted">지금 한 번만 보입니다. ' + esc(state.secret.hint || "") + "</div></div>" : "";
}

async function renderApps() {
  try {
    const res = await api("GET", "/account/app-passwords");
    const rows = (res && res.rows) || [];
    $("#apList").innerHTML = rows.length === 0 ? '<p class="muted">(없음)</p>' :
      "<table><tr><th>라벨</th><th>허용 표면</th><th>최근 사용</th><th></th></tr>" + rows.map((r) =>
        "<tr><td>" + esc(r.label) + "</td><td>" + esc(r.scopes) + "</td><td>" + (r.lastUsedAt ? esc(new Date(r.lastUsedAt).toLocaleString()) : "-") +
        '</td><td><button class="ghost" data-revoke="' + esc(r.id) + '">지우기</button></td></tr>').join("") + "</table>";
    $("#apList").querySelectorAll("button[data-revoke]").forEach((b) => (b.onclick = async () => {
      try { await sensitive("POST", "/account/credentials/" + encodeURIComponent(b.dataset.revoke) + "/revoke", {}); await renderApps(); } catch (e) { alertErr(e); }
    }));
  } catch (e) { $("#apList").innerHTML = '<p class="err">' + esc(e.message) + "</p>"; }
}

function alertErr(e) { $("#loginStatus").textContent = ""; $("#whoami").textContent = (state.me ? state.me.email : "") + " — " + e.message; }

async function boot() {
  try {
    state.me = await api("GET", "/account/session");
  } catch (e) {
    state.me = null;
    state.csrf = "";
    $("#login").className = "card";
    $("#app").className = "card hidden";
    return;
  }
  state.csrf = state.me.csrfToken || "";
  $("#login").className = "card hidden";
  $("#app").className = "card";
  $("#whoami").textContent = state.me.email + (state.me.mfaEnrolled ? " · TOTP 등록됨 · 남은 복구 코드 " + state.me.recoveryCodesRemaining : " · TOTP 미등록");
  $("#enroll").className = state.me.mfaEnrolled ? "hidden" : "";
  showSecret();
  await renderApps();
}

$("#signin").onclick = async () => {
  $("#loginStatus").textContent = "";
  try {
    const res = await api("POST", "/account/session/login", {
      email: $("#email").value.trim(), password: $("#password").value, totp: $("#totp").value.trim(), recoveryCode: $("#recovery").value.trim(),
    });
    $("#password").value = ""; $("#totp").value = ""; $("#recovery").value = "";
    if (res.enrollCode) $("#enrollGrant").value = res.enrollCode;
    state.csrf = res.csrfToken;
    await boot();
  } catch (e) { $("#loginStatus").textContent = e.message; }
};
$("#signout").onclick = async () => {
  try { await api("POST", "/account/session/logout"); } catch (e) { /* 이미 끝난 세션이어도 로그인 화면으로 */ }
  state.secret = null;
  await boot();
};
$("#enrollStart").onclick = async () => {
  try {
    const res = await api("POST", "/account/session/mfa/enroll", { enrollCode: $("#enrollGrant").value.trim() });
    $("#enrollSecret").innerHTML = '<div class="secret"><div class="muted">인증 앱에 이 비밀을 넣으십시오</div><div class="value">' + esc(res.secret) + '</div><div class="muted" style="word-break:break-all">' + esc(res.uri) + "</div></div>";
  } catch (e) { alertErr(e); }
};
$("#enrollConfirm").onclick = async () => {
  try {
    const res = await api("POST", "/account/session/mfa/confirm", { code: $("#enrollCode").value.trim() });
    $("#enrollSecret").innerHTML = ""; $("#enrollCode").value = ""; $("#enrollGrant").value = "";
    if (res && res.recoveryCodes) state.secret = { label: "복구 코드 (각각 한 번씩 씁니다)", value: res.recoveryCodes.join("  "), hint: "인증 앱을 잃었을 때 로그인 화면의 복구 코드 칸에 넣습니다. 안전한 곳에 적어 두십시오." };
    await boot();
  } catch (e) { alertErr(e); }
};
$("#apCreate").onclick = async () => {
  try {
    const res = await sensitive("POST", "/account/app-passwords", { label: $("#apLabel").value.trim() });
    if (res && res.__secret) state.secret = res.__secret;
    $("#apLabel").value = "";
    showSecret();
    await renderApps();
  } catch (e) { alertErr(e); }
};
$("#pwChange").onclick = async () => {
  try {
    await sensitive("POST", "/account/password", { currentPassword: $("#pwCurrent").value, newPassword: $("#pwNew").value });
    $("#pwCurrent").value = ""; $("#pwNew").value = "";
    state.secret = null;
    await boot();
  } catch (e) { alertErr(e); }
};
void boot();
</script>
</body>
</html>
`;
