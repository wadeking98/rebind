//! HTTP Basic authentication for the master/content web server, backed by a
//! SQLite database.
//!
//! On first run the database is created and, if it holds no users, an `admin`
//! account is seeded with a randomly generated password that is printed once to
//! the log so the operator can record it. Passwords are stored as Argon2 PHC
//! strings (salt included), never in the clear.
//!
//! Only the master server (the dashboard / project API on port 3000) is gated.
//! The standard-port server intentionally stays open — it serves the rebind
//! frame to the test target and must be reachable without credentials.

use std::sync::{Arc, Mutex};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

/// Shared handle to the auth database. SQLite connections are `Send` but not
/// `Sync`, so we guard the single connection with a mutex; auth queries are
/// tiny and infrequent (one per request), so contention is a non-issue.
pub type AuthDb = Arc<Mutex<Connection>>;

/// Path to the SQLite auth database (`REBIND_AUTH_DB`, default `rebind-auth.db`).
fn auth_db_path() -> String {
    std::env::var("REBIND_AUTH_DB").unwrap_or_else(|_| "rebind-auth.db".to_string())
}

/// Open (creating if needed) the auth database, ensure the schema exists, and
/// seed an `admin` user with a random password when the database has no users.
pub fn init() -> Result<AuthDb, Box<dyn std::error::Error>> {
    let path = auth_db_path();
    let conn = Connection::open(&path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            username      TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )",
        [],
    )?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
    if count == 0 {
        let password = random_password(24);
        let hash = hash_password(&password)?;
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
            params!["admin", hash],
        )?;
        tracing::warn!("================================================================");
        tracing::warn!("auth database initialized at {path}");
        tracing::warn!("a new admin account was created with a random password:");
        tracing::warn!("    username: admin");
        tracing::warn!("    password: {password}");
        tracing::warn!("record it now — this password is not stored or shown again");
        tracing::warn!("================================================================");
    } else {
        tracing::info!("auth database at {path} ({count} user(s))");
    }

    Ok(Arc::new(Mutex::new(conn)))
}

/// Generate a random alphanumeric password. The character set omits visually
/// ambiguous characters (0/O, 1/l/I) so a copied password is easy to read back.
fn random_password(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let i = (rng.next_u32() as usize) % CHARS.len();
            CHARS[i] as char
        })
        .collect()
}

/// Hash a password with Argon2 and a fresh random salt, returning a PHC string
/// (`$argon2id$...`) that encodes the algorithm, parameters, salt, and hash.
fn hash_password(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| e.to_string())?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?
        .to_string();
    Ok(hash)
}

/// Verify a username/password pair against the stored Argon2 hash. Returns
/// `false` for unknown users, malformed stored hashes, or a wrong password.
fn verify(conn: &Connection, username: &str, password: &str) -> bool {
    let stored: Option<String> = conn
        .query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            params![username],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten();

    match stored {
        Some(hash) => match PasswordHash::new(&hash) {
            Ok(parsed) => Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        },
        None => false,
    }
}

/// Axum middleware enforcing HTTP Basic auth against the database. On success
/// the request proceeds; otherwise it responds `401` with a `WWW-Authenticate`
/// challenge so browsers prompt for credentials.
pub async fn require_auth(State(db): State<AuthDb>, req: Request, next: Next) -> Response {
    if let Some((user, pass)) = basic_credentials(&req) {
        let ok = {
            let conn = db.lock().unwrap();
            verify(&conn, &user, &pass)
        };
        if ok {
            return next.run(req).await;
        }
    }
    unauthorized()
}

/// Decode `Authorization: Basic base64(user:pass)` into its parts, if present.
fn basic_credentials(req: &Request) -> Option<(String, String)> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pass) = creds.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// A `401 Unauthorized` response carrying a Basic-auth challenge.
fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"rebind\"")
        .body(Body::from("authentication required\n"))
        .expect("static 401 response is always valid")
}
