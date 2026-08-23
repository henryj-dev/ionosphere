/**
 * 관리 콘솔 — **무상태 스키마 구동 렌더러.**
 *
 * ★이 화면은 자기가 무엇을 할 수 있는지 모른다. 기동하면 `GET /v1/commands`로 **명령 서술**을
 * 받아 탭·표·입력 폼을 그리고, 사용자가 무언가 하면 `POST /v1/commands/<이름>`으로 되돌려준다.
 * 서버가 명령을 하나 추가하면 화면에 자동으로 생기고, 여기 코드는 바뀌지 않는다.
 *
 * 왜 이렇게 바꿨나(이전 구현이 남긴 교훈):
 *  · 화면이 **상태 인코딩의 자기 사본**을 들고 있다가 스키마와 어긋났다. 0을 "대기", 2를
 *    "비활성"으로 표시했는데 실제로는 0=정지(가역), 2=삭제 드레인(비가역)이었다 — 운영자가
 *    "비활성화했다가 되살리지" 하고 누르면 **되돌릴 수 없는 삭제**였다. 지금은 인코딩도
 *    라벨도 서버가 준다(`/v1/commands`의 `encodings`).
 *  · 탭·컬럼·버튼이 전부 하드코딩이라 API에 기능이 생겨도 화면이 따라오지 않았다. 계정 정지가
 *    자동 집행에는 있는데 사람이 쓸 입구는 없던 것이 그 결과다(콘솔이 "정지를 쓰세요(현재
 *    콘솔에는 정지 버튼이 없습니다)"라고 스스로 적어 두고 있었다).
 *
 * 자기완결(인라인 CSS/JS, 외부 리소스 0 → CSP 안전). 토큰은 런타임 입력, localStorage 보관.
 * ⚠ 이 페이지 자체엔 시크릿이 없다. admin 포트 노출 정책은 조립층 소관이다.
 *
 * 이 파일의 HTML/JS는 TS 템플릿 리터럴 안에 있다 — 내부에서 백틱과 `\${`를 쓰지 말 것
 * (문자열 결합으로 작성). **JS 문자열 안의 큰따옴표를 `\"`로 이스케이프하면 안 된다** —
 * 템플릿 리터럴이 이스케이프를 먼저 풀어 브라우저에는 생 `"`가 나가고 문자열이 조기 종료된다.
 * 작은따옴표로 감쌀 것. `api.test.ts`가 인라인 스크립트를 `new Function`으로 파싱해 이 실수를
 * 잡는다(tsc는 못 본다).
 */

/**
 * 관리 콘솔 HTML 응답에 붙는 보안 헤더 — 페이지 바로 옆에 둔다.
 *
 * 왜(감사 5차 L-12): 이 페이지는 응답 헤더가 `content-type` 하나뿐이었다. 지금은 XSS가 없지만
 * 이 화면은 **root 토큰을 localStorage에 보관**한다 — 장래에 보간 한 군데가 새면 그 대가가
 * 전 테넌트 장악이다. 헤더를 여기 두는 이유는 응집도다: 페이지에 외부 스크립트를 붙이는
 * 사람이 CSP를 같은 파일에서 보게 된다.
 *
 * `connect-src 'self'` — fetch 대상은 같은 오리진의 `/v1/*`뿐. 토큰이 외부로 새 나갈 수 있는
 * 유일한 통로라 여기를 좁히는 것이 실질 방어다.
 */
export const ADMIN_UI_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "content-security-policy": [
    "default-src 'self'",
    "script-src 'unsafe-inline'",
    "style-src 'unsafe-inline'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; "),
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

export const ADMIN_UI_HTML = `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ionosphere 관리 콘솔</title>
<style>
  :root { color-scheme: light dark; --bd: #8883; --acc: #3b82f6; --danger: #dc2626; --ok: #16a34a; }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 system-ui, sans-serif; margin: 0; padding: 1.2rem; max-width: 1100px; margin-inline: auto; }
  h1 { font-size: 1.2rem; margin: 0 0 .8rem; }
  h2 { font-size: 1rem; margin: 1.2rem 0 .4rem; }
  input, button, select, textarea { font: inherit; padding: .4rem .5rem; border: 1px solid var(--bd); border-radius: 6px; background: transparent; color: inherit; }
  textarea { min-width: 22rem; }
  button { cursor: pointer; background: var(--acc); color: #fff; border-color: transparent; }
  button.ghost { background: transparent; color: inherit; border-color: var(--bd); }
  button.danger { background: transparent; color: var(--danger); border-color: var(--danger); }
  button.armed { background: var(--danger); color: #fff; border-color: transparent; font-weight: 600; }
  .row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: flex-end; margin: .3rem 0; }
  .field { display: flex; flex-direction: column; gap: .15rem; }
  .field > span { font-size: 12px; opacity: .7; }
  .field small { font-size: 11px; opacity: .6; max-width: 26rem; }
  .tabs { display: flex; gap: .3rem; flex-wrap: wrap; border-bottom: 1px solid var(--bd); margin-top: 1rem; }
  .tabs button { background: transparent; color: inherit; border: none; border-bottom: 2px solid transparent; border-radius: 0; }
  .tabs button.active { border-bottom-color: var(--acc); font-weight: 600; }
  table { border-collapse: collapse; width: 100%; margin-top: .6rem; }
  th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--bd); font-size: 13px; vertical-align: top; }
  td.act { white-space: nowrap; }
  td.act button { margin-right: .3rem; }
  .muted { opacity: .65; }
  .card { border: 1px solid var(--bd); border-radius: 8px; padding: .8rem; margin-top: .6rem; }
  .hidden { display: none; }
  .err { color: var(--danger); }
  .ok { color: var(--ok); }
  code { background: #8881; padding: .05rem .3rem; border-radius: 4px; }
  .secret { border: 2px solid var(--acc); border-radius: 8px; padding: .8rem; margin: .6rem 0; }
  .secret .value { font: 600 18px/1.4 ui-monospace, monospace; user-select: all; word-break: break-all; }
  .danger-note { color: var(--danger); font-size: 12px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: .6rem; }
  .stat { border: 1px solid var(--bd); border-radius: 8px; padding: .6rem .7rem; }
  .stat .k { font-size: 12px; opacity: .65; }
  .stat .v { font: 600 20px/1.3 system-ui, sans-serif; word-break: break-all; }
  .toast { position: fixed; right: 1rem; bottom: 1rem; max-width: 30rem; padding: .6rem .8rem; border-radius: 8px; border: 1px solid var(--bd); background: Canvas; box-shadow: 0 2px 12px #0003; }
</style>
</head>
<body>
<h1>ionosphere 관리 콘솔</h1>
<div class="card">
  <div class="row">
    <label class="field"><span>Bearer 토큰</span><input id="token" type="password" placeholder="IONOSPHERE_ADMIN_TOKEN 또는 api-key" size="34"></label>
    <label class="field"><span>tenantId (root 전용)</span><input id="tenant" placeholder="선택" size="16"></label>
    <button id="save">저장</button>
    <span id="status" class="muted"></span>
  </div>
</div>

<div class="tabs" id="tabs"></div>
<div id="view"></div>
<div id="toast" class="toast hidden"></div>

<script>
const $ = (s) => document.querySelector(s);
const state = {
  token: localStorage.getItem("ionosphere_admin_token") || "",
  tenant: localStorage.getItem("ionosphere_admin_tenant") || "",
  /** 서버가 준 명령 서술. **화면은 이것 말고 아는 것이 없다.** */
  commands: [],
  /** 상태 정수 → 사람 말. 서버가 준다(화면이 사본을 들면 스키마와 어긋난다 — 파일 머리말). */
  encodings: {},
  /** 그룹(탭)별로 묶은 명령. */
  groups: [],
  /** 방금 발급된 평문 — 화면을 다시 그려도 살아남아야 한다(서버는 해시만 보관). */
  secret: null,
};
$("#token").value = state.token;
$("#tenant").value = state.tenant;
$("#save").onclick = () => {
  state.token = $("#token").value.trim();
  state.tenant = $("#tenant").value.trim();
  localStorage.setItem("ionosphere_admin_token", state.token);
  localStorage.setItem("ionosphere_admin_tenant", state.tenant);
  $("#status").textContent = "저장됨";
  boot();
};

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { authorization: "Bearer " + state.token, ...(body ? { "content-type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) throw new Error((data && data.error) || res.status + " " + res.statusText);
  return data;
}

/** 명령 호출 — GUI가 서버와 나누는 **유일한 대화 방식**이다. */
async function call(name, args) {
  const body = { ...args };
  if (state.tenant) body.tenantId = state.tenant;
  return await api("POST", "/v1/commands/" + encodeURIComponent(name), body);
}

function toast(msg, kind) {
  const el = $("#toast");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  setTimeout(() => { el.className = "toast hidden"; }, 5000);
}

/**
 * 바이트를 사람이 읽는 단위로. 1024 기준(디스크·쿼터는 전부 2진 단위로 잡혀 있다).
 * ★생 숫자를 그대로 두면 12자리 정수 두 개를 눈으로 비교하게 된다 — 쿼터 초과를 놓치는 자리다.
 */
function fmtBytes(n) {
  const v = Number(n) || 0;
  const u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0, x = v;
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return (i === 0 ? String(x) : x.toFixed(x < 10 ? 2 : 1)) + " " + u[i];
}
function fmtTime(ms) { return ms ? new Date(Number(ms)).toLocaleString() : "-"; }

/**
 * 값을 표시용으로 바꾼다. 상태 컬럼이면 **서버가 준 인코딩**으로 이름을 찾는다.
 * 모르는 값은 숨기지 않고 그대로 보여준다 — 조용한 오표시보다 낯선 숫자가 낫다.
 */
function display(value, col) {
  if (value === null || value === undefined || value === "") return "-";
  if (col && col.format === "bytes") return fmtBytes(value);
  if (col && col.format === "time") return fmtTime(value);
  /**
   * ★어느 인코딩인지는 **컬럼 서술이 말해 준다**(col.encoding). 예전엔 컬럼 이름과 지금 보고
   * 있는 탭으로 짐작했는데, 그런 규칙은 표가 하나 늘면 조용히 틀리고 그 결과가 "0=대기" 같은
   * **그럴듯한 오표시**로 나타난다 — 되돌릴 수 없는 삭제를 누르게 만든 그 사고다.
   */
  const enc = col && col.encoding ? state.encodings[col.encoding] : null;
  if (enc) {
    for (const name of Object.keys(enc.values)) {
      if (enc.values[name] === value) return enc.labels[name] || name;
    }
    return String(value); // 모르는 값은 숨기지 않는다(조용한 오표시 금지)
  }
  if (typeof value === "boolean") return value ? "예" : "아니오";
  return String(value);
}

/** 인자 하나의 입력 위젯 — 타입은 서버가 서술한다. */
function inputFor(cmd, a) {
  const id = "arg-" + cmd.name + "-" + a.name;
  let control;
  if (a.type === "enum" && a.choices) {
    control = '<select id="' + esc(id) + '">' +
      (a.required ? "" : '<option value="">(선택 안 함)</option>') +
      a.choices.map((c) => '<option value="' + esc(c.value) + '">' + esc(c.label) + "</option>").join("") +
      "</select>";
  } else if (a.type === "boolean") {
    control = '<select id="' + esc(id) + '"><option value="">아니오</option><option value="true">예</option></select>';
  } else if (a.name === "cert" || a.name === "key") {
    control = '<textarea id="' + esc(id) + '" rows="4" placeholder="' + esc(a.placeholder || "") + '"></textarea>';
  } else {
    const type = a.type === "secret" ? "password" : a.type === "number" ? "number" : "text";
    control = '<input id="' + esc(id) + '" type="' + type + '" placeholder="' + esc(a.placeholder || "") + '">';
  }
  return '<label class="field"><span>' + esc(a.label) + (a.required ? " *" : "") + "</span>" + control +
    (a.help ? "<small>" + esc(a.help) + "</small>" : "") + "</label>";
}

function readArgs(cmd) {
  const out = {};
  for (const a of cmd.args) {
    const el = document.getElementById("arg-" + cmd.name + "-" + a.name);
    if (!el) continue;
    const v = el.value.trim();
    if (v !== "") out[a.name] = v;
  }
  return out;
}

/**
 * 파괴적 동작 2단계 확인 — 첫 클릭은 실행하지 않고 "정말? 다시 클릭"으로 바뀐다.
 *
 * 'confirm()'을 쓰지 않는 이유: 브라우저 모달은 원격 데스크톱·키오스크에서 포커스를 잃거나
 * 억제될 수 있어 "눌렀는데 아무 일도 안 일어남"으로 보인다. 4초 안에 다시 누르지 않으면 원복.
 *
 * ★어떤 버튼에 이걸 붙일지는 **명령이 정한다**('destructive'). 화면이 목록을 들고 있으면
 * 새 파괴적 명령을 추가한 사람이 화면 코드를 잊었을 때 확인 단계가 사라진다.
 */
const ARM_MS = 4000;
function arm(btn, run) {
  let armed = false, timer = null;
  const label = btn.textContent;
  const reset = () => { armed = false; clearTimeout(timer); btn.textContent = label; btn.classList.remove("armed"); };
  btn.onclick = () => {
    if (!armed) {
      armed = true;
      btn.classList.add("armed");
      btn.textContent = "정말? 다시 클릭";
      timer = setTimeout(reset, ARM_MS);
      return;
    }
    reset();
    run();
  };
}

/** 평문 시크릿 강조 블록 — 서버는 해시만 보관하므로 이 화면을 벗어나면 복구 불가. */
function secretBlock(s) {
  return '<div class="secret"><div><strong>' + esc(s.label) + "</strong></div>" +
    '<div class="value">' + esc(s.value) + "</div>" +
    '<div class="danger-note">이 값은 지금 한 번만 표시됩니다. 서버에는 해시만 저장되어 다시 볼 수 없습니다.' +
    (s.hint ? " " + esc(s.hint) : "") + "</div></div>";
}

function activeGroup() {
  const k = decodeURIComponent(location.hash.replace(/^#/, ""));
  return state.groups.some((g) => g.name === k) ? k : (state.groups[0] || {}).name || "";
}

/** 결과 표. 컬럼은 명령의 'fields'가 정한다 — 화면에 컬럼 목록이 없다. */
function tableOf(rows, cmd, rowActions) {
  if (!rows || rows.length === 0) return '<p class="muted">(없음)</p>';
  const cols = cmd.fields && cmd.fields.length > 0
    ? cmd.fields
    : Object.keys(rows[0]).map((k) => ({ key: k, label: k }));
  const head = "<tr>" + cols.map((c) => "<th>" + esc(c.label) + "</th>").join("") +
    (rowActions.length > 0 ? "<th>작업</th>" : "") + "</tr>";
  const body = rows.map((r, i) => {
    const cells = cols.map((c) => "<td>" + esc(display(r[c.key], c)) + "</td>").join("");
    const acts = rowActions.length === 0 ? "" :
      '<td class="act">' + rowActions.map((a) =>
        '<button class="' + (a.spec.destructive ? "danger" : "ghost") + '" data-act="' + esc(a.spec.name) + '" data-row="' + i + '">' +
        esc(a.spec.label) + "</button>").join("") + "</td>";
    return "<tr>" + cells + acts + "</tr>";
  }).join("");
  return "<table>" + head + body + "</table>";
}

/**
 * 이 표의 행에 걸 수 있는 명령들.
 *
 * ★규칙: **같은 그룹의 변경 명령 중 인자가 하나뿐이고 그 인자를 행에서 채울 수 있으면** 행
 * 버튼으로 만든다. 이렇게 하면 'account-suspend' 같은 명령을 추가하는 것만으로 계정 표에
 * 정지 버튼이 생긴다 — 화면 코드를 손대지 않는다.
 */
function rowActionsFor(group, row) {
  if (!row) return [];
  return state.commands
    .filter((c) => c.group === group && !c.readOnly && c.args.length === 1)
    .map((c) => ({ spec: c, arg: c.args[0] }))
    .filter((a) => valueForArg(a.arg, row) !== undefined);
}

/**
 * 행에서 인자 값을 찾는다. 이름이 맞는 컬럼이 있으면 그것, 없으면 흔한 별칭을 본다
 * ('account' ← email/id, 'domain' ← name/id, 'alias' ← address/id).
 */
function valueForArg(arg, row) {
  if (row[arg.name] !== undefined && row[arg.name] !== null) return String(row[arg.name]);
  const alias = { account: ["email", "id"], domain: ["name", "id"], alias: ["address", "id"], email: ["email"], id: ["id"], credentialId: ["id"] }[arg.name];
  if (!alias) return undefined;
  for (const k of alias) if (row[k] !== undefined && row[k] !== null && row[k] !== "") return String(row[k]);
  return undefined;
}

async function renderGroup(group) {
  const view = $("#view");
  const cmds = state.commands.filter((c) => c.group === group);
  const readers = cmds.filter((c) => c.readOnly);
  const writers = cmds.filter((c) => !c.readOnly);

  let html = "";
  if (state.secret) html += secretBlock(state.secret);

  // 인자가 있는 변경 명령은 폼으로. 인자 없는 것도 버튼 하나로 실행할 수 있어야 한다.
  for (const c of writers) {
    html += '<div class="card"><h2>' + esc(c.label) + "</h2>" +
      '<p class="muted">' + esc(c.summary) + "</p>" +
      '<div class="row">' + c.args.map((a) => inputFor(c, a)).join("") +
      '<button class="' + (c.destructive ? "danger" : "") + '" data-run="' + esc(c.name) + '">' + esc(c.label) + "</button></div>" +
      (c.irreversible ? '<p class="danger-note">되돌릴 수 없습니다.</p>' : "") +
      "</div>";
  }

  view.innerHTML = html + '<div id="lists"><p class="muted">불러오는 중…</p></div>';

  // 조회 명령은 결과를 표로. 여러 개면 순서대로 쌓는다.
  let lists = "";
  const rendered = [];
  for (const c of readers) {
    /**
     * ★필수 인자가 있는 조회는 **자동으로 부르지 않는다**(예: 앱 비밀번호 목록은 계정이 필요).
     * 인자 없이 부르면 "필수 인자 누락"이 빨간 글씨로 화면을 채우는데, 그건 오류가 아니라
     * 아직 무엇을 볼지 고르지 않은 상태다. 대신 인자 폼을 그려 사용자가 고르게 한다.
     */
    if (c.args.some((a) => a.required)) {
      lists += "<h2>" + esc(c.label) + '</h2><div class="card"><div class="row">' +
        c.args.map((a) => inputFor(c, a)).join("") +
        '<button data-query="' + esc(c.name) + '">조회</button></div>' +
        '<div id="q-' + esc(c.name) + '"></div></div>';
      continue;
    }
    try {
      const res = await call(c.name, {});
      const rows = Array.isArray(res) ? res : res && res.rows ? res.rows : null;
      if (rows) {
        const acts = rowActionsFor(group, rows[0]);
        lists += '<h2>' + esc(c.label) + "</h2>" + tableOf(rows, c, acts);
        rendered.push({ cmd: c, rows, acts });
      } else if (res && typeof res === "object") {
        // 단일 객체 결과(사용량·TLS 상태)는 카드로.
        lists += '<h2>' + esc(c.label) + '</h2><div class="stats">' +
          Object.keys(res).map((k) => '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v">' +
            esc(typeof res[k] === "object" ? JSON.stringify(res[k]) : display(res[k], { format: /bytes$/i.test(k) ? "bytes" : undefined })) +
            "</div></div>").join("") + "</div>";
      }
    } catch (e) {
      lists += '<h2>' + esc(c.label) + '</h2><p class="err">' + esc(e.message) + "</p>";
    }
  }
  $("#lists").innerHTML = lists || '<p class="muted">(조회할 것이 없습니다)</p>';

  /**
   * 인자가 필요한 조회 — 사용자가 값을 넣고 [조회]를 누르면 그때 부른다.
   * 결과는 그 자리 아래에 표로 그린다(다른 표를 밀어내지 않게).
   */
  $("#lists").querySelectorAll("button[data-query]").forEach((b) => {
    const c = state.commands.find((x) => x.name === b.dataset.query);
    b.onclick = async () => {
      const target = document.getElementById("q-" + c.name);
      try {
        const res = await call(c.name, readArgs(c));
        const rows = Array.isArray(res) ? res : res && res.rows ? res.rows : [];
        target.innerHTML = tableOf(rows, c, []);
      } catch (e) {
        target.innerHTML = '<p class="err">' + esc(e.message) + "</p>";
      }
    };
  });

  // 폼 실행 버튼
  view.querySelectorAll("button[data-run]").forEach((b) => {
    const c = state.commands.find((x) => x.name === b.dataset.run);
    const run = async () => {
      try {
        const res = await call(c.name, readArgs(c));
        state.secret = res && res.__secret ? res.__secret : null;
        toast((c.label) + " 완료", "ok");
        await renderGroup(group);
      } catch (e) {
        toast(e.message, "err");
      }
    };
    if (c.destructive) arm(b, run); else b.onclick = run;
  });

  // 행 버튼 — 어떤 명령을 걸지는 위 rowActionsFor가 정한다.
  $("#lists").querySelectorAll("button[data-act]").forEach((b) => {
    const spec = state.commands.find((x) => x.name === b.dataset.act);
    // 행 인덱스는 표를 그린 순서와 같다. 표가 여러 개면 가장 가까운 표를 찾는다.
    const table = b.closest("table");
    const owner = rendered.find((r) => r.acts.some((a) => a.spec.name === spec.name) && r.rows.length > 0 && table);
    const row = owner ? owner.rows[Number(b.dataset.row)] : null;
    const run = async () => {
      try {
        const arg = spec.args[0];
        const args = {};
        args[arg.name] = valueForArg(arg, row);
        const res = await call(spec.name, args);
        state.secret = res && res.__secret ? res.__secret : null;
        toast(spec.label + " 완료", "ok");
        await renderGroup(group);
      } catch (e) {
        toast(e.message, "err");
      }
    };
    if (spec.destructive) arm(b, run); else b.onclick = run;
  });
}

function renderTabs() {
  const active = activeGroup();
  $("#tabs").innerHTML = state.groups.map((g) =>
    '<button data-g="' + esc(g.name) + '"' + (g.name === active ? ' class="active"' : "") + ">" + esc(g.name) + "</button>",
  ).join("");
  // 해시만 바꾸고 그리기는 hashchange에 맡긴다 — 두 경로가 갈리면 새로고침과 클릭이 달라진다.
  $("#tabs").querySelectorAll("button").forEach((b) => (b.onclick = () => {
    if (b.dataset.g === active) { void renderGroup(active); return; } // 같은 탭 재클릭 = 새로고침
    location.hash = encodeURIComponent(b.dataset.g);
  }));
}

/**
 * 기동 — **명령 서술을 받아 오는 것이 전부다.** 이 요청이 실패하면 화면은 아무것도 그리지
 * 못한다(그리려야 그릴 근거가 없다). 그 사실이 그대로 보이는 것이 옳다.
 */
async function boot() {
  if (!state.token) {
    $("#tabs").innerHTML = "";
    $("#view").innerHTML = '<p class="muted">먼저 Bearer 토큰을 입력하고 저장하세요.</p>';
    return;
  }
  try {
    const meta = await api("GET", "/v1/commands");
    state.commands = meta.commands;
    state.encodings = meta.encodings || {};
    const seen = [];
    for (const c of state.commands) if (!seen.includes(c.group)) seen.push(c.group);
    state.groups = seen.map((name) => ({ name }));
    renderTabs();
    await renderGroup(activeGroup());
  } catch (e) {
    $("#view").innerHTML = '<p class="err">명령 목록을 받지 못했습니다: ' + esc(e.message) + "</p>";
  }
}

addEventListener("hashchange", () => { renderTabs(); void renderGroup(activeGroup()); });
void boot();
</script>
</body>
</html>
`;
