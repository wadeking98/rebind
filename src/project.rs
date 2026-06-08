//! Projects: a saved, per-campaign attack configuration that can be edited from
//! the master web UI. A project holds only the settings that vary between
//! campaigns — the target IPs, the stop window, and the JS payload.
//!
//! Deployment/infrastructure settings (listen/bind addresses, DNS TTL,
//! `REBIND_SERVER_IP`, ports, and the delegated `REBIND_HOSTNAME`) are NOT part
//! of a project; they live in the environment / `.env` only. New projects are
//! seeded from the environment, so `.env` provides the defaults.

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
    /// JS payload defining `runPayload(rebind)`.
    #[serde(default)]
    pub payload: String,
}

fn default_stop_seconds() -> u64 {
    20
}

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
            .unwrap_or(20)
            .min(20);
        Project {
            name: name.to_string(),
            targets,
            stop_seconds,
            payload: payload.to_string(),
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
