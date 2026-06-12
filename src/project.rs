//! Projects: a saved, per-campaign attack configuration that can be edited from
//! the master web UI. A project holds only the settings that vary between
//! campaigns — the target IPs, the stop window, the DNS padding count, and the
//! JS payload.
//!
//! Deployment/infrastructure settings (listen/bind addresses, DNS TTL,
//! `REBIND_SERVER_IP`, ports, and the delegated `REBIND_HOSTNAME`) are NOT part
//! of a project; they live in the environment / `.env` only. New projects are
//! seeded from the environment, so `.env` provides the defaults (`REBIND_DNS_PAD`
//! seeds the padding count).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

/// A project: the per-campaign settings configurable from the master web UI.
#[derive(Clone, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    /// Target IPs to rebind to (one iframe each), as strings.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Seconds the runner asks `/stop` to keep the standard server offline.
    #[serde(default = "default_stop_seconds")]
    pub stop_seconds: u64,
    /// Extra copies of our server IP to return next to each decoded target in a
    /// DNS A/AAAA answer (see [`crate::dns`]). Biases browsers onto our server
    /// first; `/stop` then pushes them to the target. 0 disables padding.
    #[serde(default = "default_pad")]
    pub pad: usize,
    /// JS payload defining `runPayload(rebind)`.
    #[serde(default)]
    pub payload: String,
    /// HTML document served as the runner page (the page hosting the rebind
    /// iframes). Two placeholders are substituted at render time:
    /// `{{REBIND_SCRIPT}}` (the orchestration `<script>`, always injected — if
    /// absent it is appended before `</body>`) and `{{PROJECT_NAME}}`. Empty
    /// falls back to [`DEFAULT_RUNNER_HTML`].
    #[serde(default)]
    pub runner_html: String,
}

fn default_stop_seconds() -> u64 {
    5
}

fn default_pad() -> usize {
    0
}

/// Placeholder in [`Project::runner_html`] replaced by the orchestration script.
pub const RUNNER_SCRIPT_MARKER: &str = "{{REBIND_SCRIPT}}";

/// Placeholder in [`Project::runner_html`] replaced by the (escaped) project name.
pub const RUNNER_NAME_MARKER: &str = "{{PROJECT_NAME}}";

/// Default runner page. The visible markup here is fully editable per-project;
/// only the `{{REBIND_SCRIPT}}` block (the rebinding logic) is injected by the
/// server. Custom pages may drop the `#frames`/`#log` elements — the injected
/// script creates a hidden frames container if one is missing, so the rebind
/// still runs behind arbitrary decoy content.
pub const DEFAULT_RUNNER_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>rebind :: runner</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 1.5rem; }
  #log { white-space: pre-wrap; font-family: monospace; background:#111; color:#0f0;
          padding:1rem; border-radius:6px; min-height:8rem; }
  iframe { width: 360px; height: 70px; border: 1px solid #ccc; margin: 4px; }
  .frame-label { font-family: monospace; font-size: 12px; color:#555; }
  a { color:#06c; }
</style>
</head>
<body>
  <h1>rebind runner &mdash; project: {{PROJECT_NAME}}</h1>
  <p>One iframe per target. Each loads
     <code>&lt;target_ip&gt;.&lt;random&gt;.&lt;hostname&gt;</code>; the DNS server adds
     this server's IP to the answer (from config), so the browser lands here
     first. The master pings each frame; frames that don't pong are reloaded
     with a fresh random label until they point at this server.</p>
  <div id="frames"></div>
  <h2>Log</h2>
  <div id="log"></div>
{{REBIND_SCRIPT}}
</body>
</html>
"#;

/// Cap on DNS padding, to keep an answer from overflowing a UDP DNS packet.
pub const MAX_PAD: usize = 16;

/// The currently-active project, shared across the web servers.
pub type Active = Arc<RwLock<Project>>;

impl Project {
    /// Build a project seeded from the process environment (the values loaded
    /// from `.env`): `REBIND_TARGETS`, `REBIND_STOP_SECONDS`, and `payload`.
    pub fn default_from_env(name: &str, payload: &str) -> Self {
        let targets = std::env::var("REBIND_TARGETS")
            .unwrap_or_else(|_| "127.0.0.1".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let stop_seconds = std::env::var("REBIND_STOP_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5)
            .min(20);
        let pad = std::env::var("REBIND_DNS_PAD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(default_pad)
            .min(MAX_PAD);
        Project {
            name: name.to_string(),
            targets,
            stop_seconds,
            pad,
            payload: payload.to_string(),
            runner_html: String::new(),
        }
    }

    /// The runner page HTML, falling back to [`DEFAULT_RUNNER_HTML`] when the
    /// project hasn't customized it.
    pub fn runner_html_or_default(&self) -> &str {
        if self.runner_html.trim().is_empty() {
            DEFAULT_RUNNER_HTML
        } else {
            &self.runner_html
        }
    }

    /// Parsed, valid target IPs.
    pub fn target_ips(&self) -> Vec<IpAddr> {
        self.targets
            .iter()
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    }

    /// Stop window, clamped to the 20s server-side cap.
    pub fn stop_seconds_clamped(&self) -> u64 {
        self.stop_seconds.min(20)
    }

    /// DNS padding count, clamped to [`MAX_PAD`].
    pub fn pad_clamped(&self) -> usize {
        self.pad.min(MAX_PAD)
    }
}

/// Directory holding project JSON files (`REBIND_PROJECTS_DIR`, default
/// `./projects`).
pub fn projects_dir() -> PathBuf {
    std::env::var("REBIND_PROJECTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("projects"))
}

/// Reject names that could escape the projects directory or are unwieldy.
fn sanitize(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return None;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        Some(name.to_string())
    } else {
        None
    }
}

fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

/// List saved project names (sorted).
pub fn list() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(projects_dir()) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    out.push(stem.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// Load a project from disk.
pub fn load(name: &str) -> std::io::Result<Project> {
    let name = sanitize(name).ok_or_else(|| err("invalid project name"))?;
    let path = projects_dir().join(format!("{name}.json"));
    let data = std::fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(|e| err(e.to_string()))
}

/// Save a project to disk (creating the projects directory if needed).
pub fn save(project: &Project) -> std::io::Result<()> {
    let name = sanitize(&project.name).ok_or_else(|| err("invalid project name"))?;
    let dir = projects_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{name}.json"));
    let data = serde_json::to_string_pretty(project).map_err(|e| err(e.to_string()))?;
    std::fs::write(path, data)
}

/// Delete a saved project from disk.
pub fn delete(name: &str) -> std::io::Result<()> {
    let name = sanitize(name).ok_or_else(|| err("invalid project name"))?;
    let path = projects_dir().join(format!("{name}.json"));
    std::fs::remove_file(path)
}
