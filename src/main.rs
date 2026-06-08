//! rebind — a DNS rebinding test harness for authorized security testing.
//!
//! Three servers run concurrently on the tokio runtime:
//!   1. A DNS nameserver that decodes the requested A/AAAA addresses out of the
//!      queried subdomain (see [`dns`]).
//!   2. A master/orchestrator web server on port 3000 that drives the rebinding
//!      attempt with one iframe per target (see [`web::serve_content`]). It is
//!      protected by HTTP Basic auth backed by SQLite (see [`auth`]); the
//!      standard server below is intentionally left open.
//!   3. A web server on a standard port serving the rebind frame and exposing
//!      `GET /stop` (see [`web::serve_standard`]).
//!
//! Configuration is via environment variables (all optional):
//!   REBIND_DNS_BIND       default 0.0.0.0:53
//!   REBIND_DNS_TTL        default 0
//!   REBIND_CONTENT_BIND   default 0.0.0.0:3000
//!   REBIND_STANDARD_BIND  default 0.0.0.0:80
//!   REBIND_HOSTNAME       default rebind.example.com   (base domain we serve)
//!   REBIND_SERVER_IP      default 127.0.0.1            (our standard server IP)
//!   REBIND_TARGETS        default 127.0.0.1            (comma-separated targets)
//!   REBIND_STOP_SECONDS   default 30                   (offline window on /stop)
//!   REBIND_AUTH_DB        default rebind-auth.db       (master Basic-auth DB)
//!
//! Binding to ports 53 and 80 requires elevated privileges; override the binds
//! to high ports for unprivileged local testing.

mod auth;
mod dns;
mod project;
mod web;

use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use project::Project;
use web::Deploy;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Extract the port from a `host:port` bind string, defaulting on parse error.
fn port_of(bind: &str, default: u16) -> u16 {
    bind.rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    // Load a .env file if present (real environment variables take precedence).
    match dotenvy::dotenv() {
        Ok(path) => eprintln!("loaded environment from {}", path.display()),
        Err(e) if e.not_found() => {}
        Err(e) => eprintln!("warning: failed to load .env: {e}"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rebind=info,info".into()),
        )
        .init();

    let dns_bind = env_or("REBIND_DNS_BIND", "0.0.0.0:53");
    let dns_ttl: u32 = env_or("REBIND_DNS_TTL", "0").parse().unwrap_or(0);
    let content_bind = env_or("REBIND_CONTENT_BIND", "0.0.0.0:3000");
    let standard_bind = env_or("REBIND_STANDARD_BIND", "0.0.0.0:80");

    let standard_port = port_of(&standard_bind, 80);

    // Deployment settings — environment / .env only, not part of any project.
    let hostname = env_or("REBIND_HOSTNAME", "rebind.example.com");
    let server_ip: IpAddr = env_or("REBIND_SERVER_IP", "127.0.0.1")
        .parse()
        .expect("REBIND_SERVER_IP must be a valid IP address");

    // Load the configurable payload (JS defining `runPayload(rebind)`); fall
    // back to the built-in default when no file is set or it can't be read.
    let payload_file = env_or("REBIND_PAYLOAD_FILE", "payload.js");
    let payload_js = match std::fs::read_to_string(&payload_file) {
        Ok(s) => {
            tracing::info!("loaded payload from {payload_file} ({} bytes)", s.len());
            s
        }
        Err(e) => {
            tracing::warn!("payload file '{payload_file}' not loaded ({e}); using built-in default");
            web::DEFAULT_PAYLOAD.to_string()
        }
    };

    // The active project is seeded from the process environment (i.e. the
    // .env values), and shared between the master and standard servers.
    let active = Arc::new(RwLock::new(Project::default_from_env("default", &payload_js)));

    // Initialize the auth database (seeding an admin user on first run). The
    // master web server refuses to start without it, since it would otherwise
    // be served unauthenticated.
    let auth_db = match auth::init() {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("failed to initialize auth database: {e}");
            return;
        }
    };

    let deploy = Deploy {
        hostname: hostname.clone(),
        server_ip,
        standard_port,
    };

    tracing::info!("rebind starting");
    tracing::info!("  dns      -> {dns_bind} (ttl {dns_ttl})");
    tracing::info!("  content  -> {content_bind} (dashboard / ; runner /run)");
    tracing::info!("  standard -> {standard_bind}");
    tracing::info!("  hostname -> {hostname}");
    tracing::info!("  server   -> {server_ip}:{standard_port}");
    tracing::info!("  projects -> {}", project::projects_dir().display());

    let dns_task = tokio::spawn(async move {
        if let Err(e) = dns::serve(&dns_bind, dns_ttl).await {
            tracing::error!("dns fatal: {e}");
            tracing::error!("(port 53 needs privileges; try REBIND_DNS_BIND=0.0.0.0:5353)");
        }
    });

    let content_active = active.clone();
    let content_task = tokio::spawn(async move {
        if let Err(e) =
            web::serve_content(&content_bind, content_active, deploy, payload_js, auth_db).await
        {
            tracing::error!("content fatal: {e}");
        }
    });

    let standard_active = active.clone();
    let standard_task = tokio::spawn(async move {
        if let Err(e) = web::serve_standard(&standard_bind, standard_active).await {
            tracing::error!("standard fatal: {e}");
            tracing::error!("(port 80 needs privileges; try REBIND_STANDARD_BIND=0.0.0.0:8080)");
        }
    });

    let _ = tokio::join!(dns_task, content_task, standard_task);
}
