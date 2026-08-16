// The user/session helpers below have no callers yet: this ticket delivers the
// schema and the data access layer only, the login, middleware and user
// management tickets that consume them are still open.
#![allow(dead_code)]

use crate::models::Task;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, Pool, Sqlite};
use std::str::FromStr;
use tracing::info;

/// Default database location, relative to the working directory.
const DEFAULT_DATABASE_URL: &str = "sqlite:data/tasks.db?mode=rwc";

// ---------------------------------------------------------------------------
// Auth models
//
// These live here (and not in `src/models.rs`) because the follow-up tickets
// own that file; move them over once the auth handlers land.
// ---------------------------------------------------------------------------

/// A user account. `password_hash` is expected to be an Argon2id PHC string —
/// this module never hashes or verifies, it only stores what it is given.
///
/// `Debug` is written by hand, not derived. `#[serde(skip_serializing)]` keeps
/// the hash out of JSON responses, but it does nothing for `Debug`: a derived
/// one printed the complete Argon2 PHC string — salt, parameters and digest —
/// so a single `tracing::debug!(?user)` would write an offline-crackable hash
/// into a log file, into every backup of it and into every bug report built
/// from it. Same failure as `LoginOutcome` in `handlers::auth`, one file over.
#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// `admin` or `user`
    pub role: String,
    pub home_path: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for User {
    /// Shows what is useful when debugging an account — who, which role,
    /// whether it is enabled, when it was created and last used — and leaves
    /// out the one field that is crackable: the password hash.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .field("role", &self.role)
            .field("home_path", &self.home_path)
            .field("is_active", &self.is_active)
            .field("created_at", &self.created_at)
            .field("last_login_at", &self.last_login_at)
            .finish()
    }
}

/// A server-side session. `id` is the **hash** of the session token, never the
/// token itself — the plaintext token only ever lives in the client cookie.
///
/// `Debug` is written by hand for the same reason as on [`User`]: `id` is the
/// token digest and therefore the *server-side session key*. It is what every
/// lookup here matches on, so anyone who reads it out of a log can identify —
/// and with `delete_session` destroy — that exact session. Being a hash does
/// not make it printable; it makes it the credential the server compares
/// against.
#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

impl std::fmt::Debug for Session {
    /// Shows whose session it is, how long it runs and where it came from —
    /// enough to follow a session through the logs — but not the session key
    /// itself.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &"<redacted>")
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("user_agent", &self.user_agent)
            .field("ip", &self.ip)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Share model
// ---------------------------------------------------------------------------

/// An anonymous share link for one file or directory.
///
/// `token_hash` is the SHA-256 digest of the link token, never the token
/// itself — exactly like [`Session::id`]. The plaintext token exists once, in
/// the response that creates the share, and is never persisted; see
/// [`crate::handlers::shares::ShareToken`].
///
/// The counting columns are deliberately part of the row and not a separate
/// table: `access_count` together with `max_accesses` is what makes an atomic
/// `UPDATE … WHERE access_count < max_accesses` possible, and that single
/// statement is the only thing that keeps concurrent downloads from running
/// past the limit (see [`consume_share_access`]).
///
/// `Debug` is hand-written for the same reason as on [`User`] and [`Session`]:
/// `token_hash` is the server-side lookup key of the share and `password_hash`
/// is crackable offline. A derived `Debug` would put both into any
/// `tracing::debug!(?share)` line, into every backup of that log and into every
/// bug report built from it.
#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct Share {
    pub id: String,
    /// SHA-256 of the link token, lowercase hex.
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub owner_id: String,
    /// The shared path, frozen at creation time. Re-checked against the
    /// owner's home on every access — freezing it is not a substitute.
    pub path: String,
    pub is_dir: bool,
    /// Optional Argon2id PHC string for a password-protected link.
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    /// `None` = no time limit.
    pub expires_at: Option<DateTime<Utc>>,
    /// `None` = no access limit.
    pub max_accesses: Option<i64>,
    pub access_count: i64,
    pub is_revoked: bool,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for Share {
    /// Shows what identifies and bounds a share — who owns it, what it points
    /// at, when it dies — and redacts the two secrets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("id", &self.id)
            .field("token_hash", &"<redacted>")
            .field("owner_id", &self.owner_id)
            .field("path", &self.path)
            .field("is_dir", &self.is_dir)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("max_accesses", &self.max_accesses)
            .field("access_count", &self.access_count)
            .field("is_revoked", &self.is_revoked)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Share {
    /// Whether the share is usable at `now`, ignoring the owner's account
    /// state (which lives in another table — see [`get_live_share_by_hash`]).
    ///
    /// This is the read-only view of the same conditions
    /// [`consume_share_access`] enforces in SQL. Use it to decide what to
    /// *show*; use `consume_share_access` to decide what to *hand out*.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        !self.is_revoked
            && self.expires_at.is_none_or(|expires| expires > now)
            && self
                .max_accesses
                .is_none_or(|max| self.access_count < max.max(0))
    }
}

// ---------------------------------------------------------------------------
// Setup / migration
// ---------------------------------------------------------------------------

pub async fn init_database() -> Result<Pool<Sqlite>> {
    // Create data directory if it doesn't exist
    tokio::fs::create_dir_all("data").await?;

    let pool = connect(DEFAULT_DATABASE_URL).await?;
    run_migrations(&pool).await?;

    info!("✅ Database initialized successfully");
    Ok(pool)
}

/// Open a pool for `database_url`. Foreign keys are enabled explicitly:
/// SQLite defaults them to *off* per connection, so `ON DELETE CASCADE` would
/// silently do nothing without this.
pub async fn connect(database_url: &str) -> Result<Pool<Sqlite>> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new().connect_with(options).await?;
    Ok(pool)
}

/// Create every table and index this application needs.
///
/// Purely additive and idempotent (`IF NOT EXISTS` throughout), so it runs
/// safely against an existing `data/tasks.db` without touching stored rows.
pub async fn run_migrations(pool: &Pool<Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            source_path TEXT NOT NULL,
            remote_name TEXT NOT NULL,
            remote_path TEXT NOT NULL,
            chunk_size TEXT,
            use_chunking BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            home_path TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            user_agent TEXT,
            ip TEXT
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
        .execute(pool)
        .await?;

    // Anonymous share links. `token_hash` is UNIQUE for two reasons: it is the
    // lookup key of every public request, and the uniqueness constraint is what
    // turns an (astronomically unlikely) token collision into a failed INSERT
    // instead of two shares answering to the same link.
    //
    // `access_count` and `max_accesses` sit in the same row on purpose — that
    // is what makes the limit enforceable in a single atomic
    // `UPDATE … WHERE access_count < max_accesses` (see [`consume_share_access`]).
    // A counter in a side table would need a transaction around two statements.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS shares (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            is_dir INTEGER NOT NULL,
            password_hash TEXT,
            expires_at TEXT,
            max_accesses INTEGER,
            access_count INTEGER NOT NULL DEFAULT 0,
            is_revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_shares_owner_id ON shares(owner_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_shares_expires_at ON shares(expires_at)")
        .execute(pool)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

pub async fn create_task(pool: &Pool<Sqlite>, task: &Task) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO tasks (id, name, source_path, remote_name, remote_path, chunk_size, use_chunking, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    "#,
    )
    .bind(&task.id)
    .bind(&task.name)
    .bind(&task.source_path)
    .bind(&task.remote_name)
    .bind(&task.remote_path)
    .bind(&task.chunk_size)
    .bind(task.use_chunking)
    .bind(task.created_at)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_all_tasks(pool: &Pool<Sqlite>) -> Result<Vec<Task>> {
    let tasks = sqlx::query_as::<_, Task>(
        r#"
        SELECT id, name, source_path, remote_name, remote_path, chunk_size, use_chunking, created_at
        FROM tasks
        ORDER BY created_at DESC
    "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(tasks)
}

pub async fn get_task_by_name(pool: &Pool<Sqlite>, name: &str) -> Result<Option<Task>> {
    let task = sqlx::query_as::<_, Task>(
        r#"
        SELECT id, name, source_path, remote_name, remote_path, chunk_size, use_chunking, created_at
        FROM tasks
        WHERE name = ?
    "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(task)
}

pub async fn delete_task(pool: &Pool<Sqlite>, task_id: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM tasks WHERE id = ?
    "#,
    )
    .bind(task_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn task_name_exists(pool: &Pool<Sqlite>, name: &str) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM tasks WHERE name = ?
    "#,
    )
    .bind(name)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

const USER_COLUMNS: &str =
    "id, username, password_hash, role, home_path, is_active, created_at, last_login_at";

pub async fn create_user(pool: &Pool<Sqlite>, user: &User) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO users (id, username, password_hash, role, home_path, is_active, created_at, last_login_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    "#,
    )
    .bind(&user.id)
    .bind(&user.username)
    .bind(&user.password_hash)
    .bind(&user.role)
    .bind(&user.home_path)
    .bind(user.is_active)
    .bind(user.created_at.to_rfc3339())
    .bind(user.last_login_at.map(|ts| ts.to_rfc3339()))
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_user_by_id(pool: &Pool<Sqlite>, user_id: &str) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?");
    let user = sqlx::query_as::<_, User>(&sql)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

pub async fn get_user_by_username(pool: &Pool<Sqlite>, username: &str) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?");
    let user = sqlx::query_as::<_, User>(&sql)
        .bind(username)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

pub async fn get_all_users(pool: &Pool<Sqlite>) -> Result<Vec<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users ORDER BY username ASC");
    let users = sqlx::query_as::<_, User>(&sql).fetch_all(pool).await?;

    Ok(users)
}

pub async fn username_exists(pool: &Pool<Sqlite>, username: &str) -> Result<bool> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await?;

    Ok(count.0 > 0)
}

/// Number of accounts in total. `0` means the app is not set up yet.
pub async fn count_users(pool: &Pool<Sqlite>) -> Result<i64> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    Ok(count.0)
}

/// Update the mutable profile fields. `password_hash`, `created_at` and
/// `last_login_at` are deliberately not touched here — they have their own
/// functions so a profile edit can never silently reset a password.
pub async fn update_user(pool: &Pool<Sqlite>, user: &User) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE users
        SET username = ?, role = ?, home_path = ?, is_active = ?
        WHERE id = ?
    "#,
    )
    .bind(&user.username)
    .bind(&user.role)
    .bind(&user.home_path)
    .bind(user.is_active)
    .bind(&user.id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn update_user_password(
    pool: &Pool<Sqlite>,
    user_id: &str,
    password_hash: &str,
) -> Result<bool> {
    let result = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(password_hash)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Enable or disable an account. Disabling keeps the row (and everything owned
/// by it) intact; the caller is responsible for dropping the user's sessions.
pub async fn set_user_active(pool: &Pool<Sqlite>, user_id: &str, is_active: bool) -> Result<bool> {
    let result = sqlx::query("UPDATE users SET is_active = ? WHERE id = ?")
        .bind(is_active)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn set_user_last_login(
    pool: &Pool<Sqlite>,
    user_id: &str,
    when: DateTime<Utc>,
) -> Result<bool> {
    let result = sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(when.to_rfc3339())
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete an account. Its sessions go with it via `ON DELETE CASCADE`.
pub async fn delete_user(pool: &Pool<Sqlite>, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

const SESSION_COLUMNS: &str = "id, user_id, created_at, expires_at, user_agent, ip";

pub async fn create_session(pool: &Pool<Sqlite>, session: &Session) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, created_at, expires_at, user_agent, ip)
        VALUES (?, ?, ?, ?, ?, ?)
    "#,
    )
    .bind(&session.id)
    .bind(&session.user_id)
    .bind(session.created_at.to_rfc3339())
    .bind(session.expires_at.to_rfc3339())
    .bind(&session.user_agent)
    .bind(&session.ip)
    .execute(pool)
    .await?;

    Ok(())
}

/// Look a session up by the **hash** of its token. Returns expired sessions
/// too — use [`get_valid_session`] when the expiry matters.
pub async fn get_session_by_hash(pool: &Pool<Sqlite>, token_hash: &str) -> Result<Option<Session>> {
    let sql = format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE id = ?");
    let session = sqlx::query_as::<_, Session>(&sql)
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

    Ok(session)
}

/// Like [`get_session_by_hash`], but only returns sessions that have not
/// expired at `now`.
pub async fn get_valid_session(
    pool: &Pool<Sqlite>,
    token_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<Session>> {
    let sql = format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE id = ? AND expires_at > ?");
    let session = sqlx::query_as::<_, Session>(&sql)
        .bind(token_hash)
        .bind(now.to_rfc3339())
        .fetch_optional(pool)
        .await?;

    Ok(session)
}

/// All sessions of a user, newest first — the "active logins" view.
pub async fn get_sessions_for_user(pool: &Pool<Sqlite>, user_id: &str) -> Result<Vec<Session>> {
    let sql = format!(
        "SELECT {SESSION_COLUMNS} FROM sessions WHERE user_id = ? ORDER BY created_at DESC"
    );
    let sessions = sqlx::query_as::<_, Session>(&sql)
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    Ok(sessions)
}

pub async fn delete_session(pool: &Pool<Sqlite>, token_hash: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Log a user out everywhere. Returns the number of dropped sessions.
pub async fn delete_sessions_for_user(pool: &Pool<Sqlite>, user_id: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Housekeeping: drop everything that expired before `now`.
pub async fn delete_expired_sessions(pool: &Pool<Sqlite>, now: DateTime<Utc>) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now.to_rfc3339())
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// Shares
// ---------------------------------------------------------------------------

const SHARE_COLUMNS: &str = "id, token_hash, owner_id, path, is_dir, password_hash, \
                             expires_at, max_accesses, access_count, is_revoked, created_at";

/// Persist a share. `share.token_hash` must already be the digest — this layer
/// never sees the plaintext token (see `handlers::shares::create_share`).
///
/// The `UNIQUE` constraint on `token_hash` makes a duplicate an error rather
/// than a silent second share on the same link.
pub async fn create_share(pool: &Pool<Sqlite>, share: &Share) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO shares (
            id, token_hash, owner_id, path, is_dir, password_hash,
            expires_at, max_accesses, access_count, is_revoked, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#,
    )
    .bind(&share.id)
    .bind(&share.token_hash)
    .bind(&share.owner_id)
    .bind(&share.path)
    .bind(share.is_dir)
    .bind(&share.password_hash)
    .bind(share.expires_at.map(|ts| ts.to_rfc3339()))
    .bind(share.max_accesses)
    .bind(share.access_count)
    .bind(share.is_revoked)
    .bind(share.created_at.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Look a share up by the **hash** of its token. Returns revoked, expired and
/// exhausted shares too — use [`get_live_share_by_hash`] when that matters, and
/// [`consume_share_access`] when something is actually handed out.
pub async fn get_share_by_hash(pool: &Pool<Sqlite>, token_hash: &str) -> Result<Option<Share>> {
    let sql = format!("SELECT {SHARE_COLUMNS} FROM shares WHERE token_hash = ?");
    let share = sqlx::query_as::<_, Share>(&sql)
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

    Ok(share)
}

pub async fn get_share_by_id(pool: &Pool<Sqlite>, share_id: &str) -> Result<Option<Share>> {
    let sql = format!("SELECT {SHARE_COLUMNS} FROM shares WHERE id = ?");
    let share = sqlx::query_as::<_, Share>(&sql)
        .bind(share_id)
        .fetch_optional(pool)
        .await?;

    Ok(share)
}

/// A share that may still be *shown* at `now`: not revoked, not expired, not
/// exhausted, and owned by an enabled account.
///
/// The owner check is the reason this is a join and not [`Share::is_usable_at`]:
/// disabling a user must take their links down with them, and that state lives
/// in another table. Deleting a user removes the rows outright (`ON DELETE
/// CASCADE`).
///
/// Read-only — it does not count. The public view uses this to render the
/// landing page; the download path uses [`consume_share_access`].
pub async fn get_live_share_by_hash(
    pool: &Pool<Sqlite>,
    token_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<Share>> {
    let sql = format!(
        "SELECT {SHARE_COLUMNS} FROM shares AS s \
         WHERE s.token_hash = ? \
           AND s.is_revoked = 0 \
           AND (s.expires_at IS NULL OR s.expires_at > ?) \
           AND (s.max_accesses IS NULL OR s.access_count < s.max_accesses) \
           AND EXISTS (SELECT 1 FROM users AS u WHERE u.id = s.owner_id AND u.is_active = 1)"
    );
    let share = sqlx::query_as::<_, Share>(&sql)
        .bind(token_hash)
        .bind(now.to_rfc3339())
        .fetch_optional(pool)
        .await?;

    Ok(share)
}

/// Claim one access against the limit, atomically.
///
/// The whole point of this function is the single `UPDATE`: SQLite applies it
/// under a write lock, so N concurrent downloads of a link with
/// `max_accesses = 1` produce exactly one `rows_affected() == 1` and N-1
/// zeroes. A read-then-write (`is_usable_at`, then `SET access_count + 1`)
/// would let all N through — that is the race this exists to close.
///
/// Returns the share **after** the increment when the access was granted, and
/// `None` when the link is unknown, revoked, expired, exhausted or its owner is
/// disabled. Callers must not fall back to a plain lookup on `None`.
///
/// The row comes back through `RETURNING`, out of the same statement that did
/// the increment. Reading it with a second `SELECT` would have been correct for
/// the *decision* but not for the *number*: a competing consumer can land
/// between the two, so the caller would see somebody else's count. With
/// `RETURNING` the returned `access_count` is exactly the value this call
/// claimed — which is what makes a test able to assert "granted the 3rd of 3"
/// rather than only "granted".
pub async fn consume_share_access(
    pool: &Pool<Sqlite>,
    token_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<Share>> {
    let sql = format!(
        "UPDATE shares \
            SET access_count = access_count + 1 \
          WHERE token_hash = ? \
            AND is_revoked = 0 \
            AND (expires_at IS NULL OR expires_at > ?) \
            AND (max_accesses IS NULL OR access_count < max_accesses) \
            AND EXISTS (SELECT 1 FROM users WHERE id = owner_id AND is_active = 1) \
      RETURNING {SHARE_COLUMNS}"
    );

    let share = sqlx::query_as::<_, Share>(&sql)
        .bind(token_hash)
        .bind(now.to_rfc3339())
        .fetch_optional(pool)
        .await?;

    Ok(share)
}

/// The same liveness test as [`get_live_share_by_hash`] — not revoked, not
/// expired, owner enabled — but **without** the access limit, and still without
/// counting.
///
/// This exists for exactly one caller: the continuation of a download that has
/// already been counted. A media player fetches a file in many `Range`
/// requests, and the later ones must keep working after the request that opened
/// the download consumed the last remaining access. Checking them against the
/// limit would break every ranged download of a one-shot link.
///
/// It is therefore **not** an entry point. Reaching it requires proof that an
/// access was already claimed for this download (see
/// `handlers::shares::DownloadGrants`); using it as a general lookup would hand
/// out an exhausted share for free.
pub async fn get_unmetered_share_by_hash(
    pool: &Pool<Sqlite>,
    token_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<Share>> {
    let sql = format!(
        "SELECT {SHARE_COLUMNS} FROM shares AS s \
         WHERE s.token_hash = ? \
           AND s.is_revoked = 0 \
           AND (s.expires_at IS NULL OR s.expires_at > ?) \
           AND EXISTS (SELECT 1 FROM users AS u WHERE u.id = s.owner_id AND u.is_active = 1)"
    );
    let share = sqlx::query_as::<_, Share>(&sql)
        .bind(token_hash)
        .bind(now.to_rfc3339())
        .fetch_optional(pool)
        .await?;

    Ok(share)
}

/// A user's shares, newest first — the "my links" view.
pub async fn get_shares_for_owner(pool: &Pool<Sqlite>, owner_id: &str) -> Result<Vec<Share>> {
    let sql = format!(
        "SELECT {SHARE_COLUMNS} FROM shares WHERE owner_id = ? ORDER BY created_at DESC, id DESC"
    );
    let shares = sqlx::query_as::<_, Share>(&sql)
        .bind(owner_id)
        .fetch_all(pool)
        .await?;

    Ok(shares)
}

pub async fn count_shares_for_owner(pool: &Pool<Sqlite>, owner_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM shares WHERE owner_id = ?")
        .bind(owner_id)
        .fetch_one(pool)
        .await?;

    Ok(count.0)
}

/// Turn a link off without losing the record of it.
///
/// `owner_id` is part of the `WHERE` clause, not checked beforehand: that way a
/// share of a *different* user is indistinguishable from one that does not
/// exist — both return `false` — and there is no window between the check and
/// the write.
pub async fn revoke_share(pool: &Pool<Sqlite>, share_id: &str, owner_id: &str) -> Result<bool> {
    let result = sqlx::query("UPDATE shares SET is_revoked = 1 WHERE id = ? AND owner_id = ?")
        .bind(share_id)
        .bind(owner_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Remove a share for good. Same ownership handling as [`revoke_share`].
pub async fn delete_share(pool: &Pool<Sqlite>, share_id: &str, owner_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM shares WHERE id = ? AND owner_id = ?")
        .bind(share_id)
        .bind(owner_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Housekeeping: drop links whose expiry has passed. Shares without an expiry
/// and merely exhausted ones are left alone — those are only removed by their
/// owner.
pub async fn delete_expired_shares(pool: &Pool<Sqlite>, now: DateTime<Utc>) -> Result<u64> {
    let result = sqlx::query("DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at <= ?")
        .bind(now.to_rfc3339())
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// A pool on a temporary on-disk database (not `:memory:`, so the
    /// migration path is exercised the same way it runs in production).
    async fn temp_pool() -> (Pool<Sqlite>, tempdir::Dir) {
        let dir = tempdir::Dir::new();
        let url = format!("sqlite:{}?mode=rwc", dir.path().join("test.db").display());
        let pool = connect(&url).await.expect("connect");
        run_migrations(&pool).await.expect("migrate");
        (pool, dir)
    }

    /// Minimal throwaway temp directory helper — the crate has no dev
    /// dependency on `tempfile` and adding one would touch `Cargo.toml`.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "rclone-gui-db-test-{}-{}",
                    std::process::id(),
                    uuid::Uuid::new_v4()
                ));
                std::fs::create_dir_all(&path).expect("create temp dir");
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn sample_user(id: &str, username: &str) -> User {
        User {
            id: id.to_string(),
            username: username.to_string(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_string(),
            role: "user".to_string(),
            home_path: format!("/data/home/{username}"),
            is_active: true,
            created_at: Utc::now(),
            last_login_at: None,
        }
    }

    fn sample_session(id: &str, user_id: &str, expires_in: Duration) -> Session {
        Session {
            id: id.to_string(),
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + expires_in,
            user_agent: Some("test-agent".to_string()),
            ip: Some("127.0.0.1".to_string()),
        }
    }

    #[tokio::test]
    async fn creates_and_finds_user() {
        let (pool, _dir) = temp_pool().await;

        let user = sample_user("u1", "alice");
        create_user(&pool, &user).await.expect("create user");

        let by_id = get_user_by_id(&pool, "u1").await.unwrap().expect("by id");
        assert_eq!(by_id.username, "alice");
        assert_eq!(by_id.role, "user");
        assert_eq!(by_id.home_path, "/data/home/alice");
        assert!(by_id.is_active);
        assert!(by_id.last_login_at.is_none());

        let by_name = get_user_by_username(&pool, "alice")
            .await
            .unwrap()
            .expect("by name");
        assert_eq!(by_name.id, "u1");

        assert!(username_exists(&pool, "alice").await.unwrap());
        assert!(!username_exists(&pool, "bob").await.unwrap());
        assert_eq!(count_users(&pool).await.unwrap(), 1);
        assert!(get_user_by_username(&pool, "bob").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn username_is_unique() {
        let (pool, _dir) = temp_pool().await;

        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        assert!(create_user(&pool, &sample_user("u2", "alice"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn updates_deactivates_and_deletes_user() {
        let (pool, _dir) = temp_pool().await;

        let mut user = sample_user("u1", "alice");
        create_user(&pool, &user).await.unwrap();

        user.username = "alice2".to_string();
        user.role = "admin".to_string();
        user.home_path = "/data/home/alice2".to_string();
        assert!(update_user(&pool, &user).await.unwrap());

        let stored = get_user_by_id(&pool, "u1").await.unwrap().unwrap();
        assert_eq!(stored.username, "alice2");
        assert_eq!(stored.role, "admin");
        // the password must survive a profile update untouched
        assert_eq!(stored.password_hash, user.password_hash);

        assert!(update_user_password(&pool, "u1", "$argon2id$new")
            .await
            .unwrap());
        assert_eq!(
            get_user_by_id(&pool, "u1")
                .await
                .unwrap()
                .unwrap()
                .password_hash,
            "$argon2id$new"
        );

        let now = Utc::now();
        assert!(set_user_last_login(&pool, "u1", now).await.unwrap());
        let last = get_user_by_id(&pool, "u1")
            .await
            .unwrap()
            .unwrap()
            .last_login_at
            .expect("last_login_at");
        assert!((last - now).num_seconds().abs() < 2);

        assert!(set_user_active(&pool, "u1", false).await.unwrap());
        assert!(
            !get_user_by_id(&pool, "u1")
                .await
                .unwrap()
                .unwrap()
                .is_active
        );

        assert!(!set_user_active(&pool, "nope", false).await.unwrap());

        assert!(delete_user(&pool, "u1").await.unwrap());
        assert!(get_user_by_id(&pool, "u1").await.unwrap().is_none());
        assert!(!delete_user(&pool, "u1").await.unwrap());
    }

    #[tokio::test]
    async fn session_lifecycle_and_expiry() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();

        let session = sample_session("hash-a", "u1", Duration::hours(1));
        create_session(&pool, &session).await.unwrap();

        let found = get_session_by_hash(&pool, "hash-a")
            .await
            .unwrap()
            .expect("session");
        assert_eq!(found.user_id, "u1");
        assert_eq!(found.user_agent.as_deref(), Some("test-agent"));
        assert_eq!(found.ip.as_deref(), Some("127.0.0.1"));

        assert!(get_valid_session(&pool, "hash-a", Utc::now())
            .await
            .unwrap()
            .is_some());

        // an expired session is still stored, but no longer valid
        create_session(&pool, &sample_session("hash-b", "u1", Duration::hours(-1)))
            .await
            .unwrap();
        assert!(get_session_by_hash(&pool, "hash-b")
            .await
            .unwrap()
            .is_some());
        assert!(get_valid_session(&pool, "hash-b", Utc::now())
            .await
            .unwrap()
            .is_none());

        assert_eq!(get_sessions_for_user(&pool, "u1").await.unwrap().len(), 2);

        assert_eq!(delete_expired_sessions(&pool, Utc::now()).await.unwrap(), 1);
        assert_eq!(get_sessions_for_user(&pool, "u1").await.unwrap().len(), 1);

        assert!(delete_session(&pool, "hash-a").await.unwrap());
        assert!(!delete_session(&pool, "hash-a").await.unwrap());
        assert!(get_sessions_for_user(&pool, "u1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_user_cascades_to_sessions() {
        let (pool, _dir) = temp_pool().await;

        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        create_user(&pool, &sample_user("u2", "bob")).await.unwrap();
        create_session(&pool, &sample_session("s1", "u1", Duration::hours(1)))
            .await
            .unwrap();
        create_session(&pool, &sample_session("s2", "u1", Duration::hours(1)))
            .await
            .unwrap();
        create_session(&pool, &sample_session("s3", "u2", Duration::hours(1)))
            .await
            .unwrap();

        assert!(delete_user(&pool, "u1").await.unwrap());

        assert!(get_session_by_hash(&pool, "s1").await.unwrap().is_none());
        assert!(get_session_by_hash(&pool, "s2").await.unwrap().is_none());
        // the other user's session is untouched
        assert!(get_session_by_hash(&pool, "s3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn foreign_key_rejects_unknown_user() {
        let (pool, _dir) = temp_pool().await;

        // proves PRAGMA foreign_keys is actually ON for pooled connections
        let orphan = sample_session("s1", "ghost", Duration::hours(1));
        assert!(create_session(&pool, &orphan).await.is_err());
    }

    #[tokio::test]
    async fn delete_sessions_for_user_logs_out_everywhere() {
        let (pool, _dir) = temp_pool().await;

        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        create_session(&pool, &sample_session("s1", "u1", Duration::hours(1)))
            .await
            .unwrap();
        create_session(&pool, &sample_session("s2", "u1", Duration::hours(1)))
            .await
            .unwrap();

        assert_eq!(delete_sessions_for_user(&pool, "u1").await.unwrap(), 2);
        assert_eq!(delete_sessions_for_user(&pool, "u1").await.unwrap(), 0);
    }

    /// `Debug` on `User` must not print the password hash — but must still be
    /// worth printing. Both halves matter: an empty `Debug` would pass the
    /// negative check alone.
    #[test]
    fn user_debug_redacts_the_password_hash() {
        let user = sample_user("u1", "alice");
        let rendered = format!("{user:?}");

        // negative: nothing crackable
        assert!(
            !rendered.contains("$argon2"),
            "Argon2 hash leaked into Debug: {rendered}"
        );
        assert!(
            !rendered.contains(&user.password_hash),
            "password hash leaked into Debug: {rendered}"
        );
        assert!(
            !rendered.contains("aGFzaA"),
            "hash digest leaked into Debug: {rendered}"
        );

        // positive: the fields that make the output useful
        assert!(rendered.contains("User"), "{rendered}");
        assert!(rendered.contains("u1"), "{rendered}");
        assert!(rendered.contains("alice"), "{rendered}");
        assert!(
            rendered.contains("role: \"user\""),
            "role missing: {rendered}"
        );
        assert!(rendered.contains("/data/home/alice"), "{rendered}");
        assert!(rendered.contains("is_active"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// `Debug` on `Session` must not print `id` — that is the token digest and
    /// thus the server-side session key.
    #[test]
    fn session_debug_redacts_the_session_key() {
        let session = sample_session("d1e2a3d4beef", "u1", Duration::hours(1));
        let rendered = format!("{session:?}");

        // negative: the session key stays out
        assert!(
            !rendered.contains("d1e2a3d4beef"),
            "session key leaked into Debug: {rendered}"
        );

        // positive: the fields that make the output useful
        assert!(rendered.contains("Session"), "{rendered}");
        assert!(rendered.contains("u1"), "user_id missing: {rendered}");
        assert!(rendered.contains("expires_at"), "{rendered}");
        assert!(rendered.contains("test-agent"), "{rendered}");
        assert!(rendered.contains("127.0.0.1"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// Wrapping the structs must not reopen the hole: a derived `Debug` on a
    /// container delegates to ours, and `Option`/`Vec` do the same.
    #[test]
    fn nested_debug_stays_redacted() {
        let user = sample_user("u1", "alice");
        let sessions = vec![sample_session("cafebabe1234", "u1", Duration::hours(1))];

        let rendered = format!("{:?}", (Some(&user), &sessions));
        assert!(!rendered.contains("$argon2"), "{rendered}");
        assert!(!rendered.contains("cafebabe1234"), "{rendered}");
        assert!(rendered.contains("alice"), "{rendered}");
    }

    /// The migration path: an existing database that only knows `tasks` gets
    /// the auth tables added without losing rows, and re-running is a no-op.
    #[tokio::test]
    async fn migrates_existing_database_without_data_loss() {
        let dir = tempdir::Dir::new();
        let db_path = dir.path().join("legacy.db");
        let url = format!("sqlite:{}?mode=rwc", db_path.display());

        // 1. an "old" database: only the tasks table, with a row in it
        {
            let pool = connect(&url).await.unwrap();
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    source_path TEXT NOT NULL,
                    remote_name TEXT NOT NULL,
                    remote_path TEXT NOT NULL,
                    chunk_size TEXT,
                    use_chunking BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            "#,
            )
            .execute(&pool)
            .await
            .unwrap();

            create_task(
                &pool,
                &Task {
                    id: "t1".to_string(),
                    name: "legacy-task".to_string(),
                    source_path: "/src".to_string(),
                    remote_name: "remote".to_string(),
                    remote_path: "/dst".to_string(),
                    chunk_size: Some("8M".to_string()),
                    use_chunking: true,
                    created_at: Utc::now(),
                },
            )
            .await
            .unwrap();
            pool.close().await;
        }

        // 2. migrate twice — the second run must be a no-op, not an error
        for _ in 0..2 {
            let pool = connect(&url).await.unwrap();
            run_migrations(&pool)
                .await
                .expect("migration is idempotent");
            pool.close().await;
        }

        // 3. old data intact, new tables usable
        let pool = connect(&url).await.unwrap();

        let tasks = get_all_tasks(&pool).await.unwrap();
        assert_eq!(tasks.len(), 1, "existing tasks must survive the migration");
        assert_eq!(tasks[0].name, "legacy-task");
        assert_eq!(tasks[0].chunk_size.as_deref(), Some("8M"));
        assert!(tasks[0].use_chunking);

        assert_eq!(count_users(&pool).await.unwrap(), 0);
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        create_session(&pool, &sample_session("s1", "u1", Duration::hours(1)))
            .await
            .unwrap();
        assert!(get_session_by_hash(&pool, "s1").await.unwrap().is_some());

        // and there is exactly one of each table, no duplicates
        let names: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('tasks', 'users', 'sessions') ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let names: Vec<String> = names.into_iter().map(|row| row.0).collect();
        assert_eq!(names, vec!["sessions", "tasks", "users"]);

        // the shares table came along with the same migration and is usable
        assert_eq!(count_shares_for_owner(&pool, "u1").await.unwrap(), 0);
        create_share(&pool, &sample_share("sh1", "u1"))
            .await
            .unwrap();
        assert!(get_share_by_hash(&pool, "hash-sh1")
            .await
            .unwrap()
            .is_some());
    }

    // -----------------------------------------------------------------------
    // Shares
    // -----------------------------------------------------------------------

    /// A share with no expiry and no access limit. `token_hash` is a stand-in
    /// here — the real digests are produced in `handlers::shares`, which this
    /// layer never sees.
    fn sample_share(id: &str, owner_id: &str) -> Share {
        Share {
            id: id.to_string(),
            token_hash: format!("hash-{id}"),
            owner_id: owner_id.to_string(),
            path: "/data/home/alice/report.pdf".to_string(),
            is_dir: false,
            password_hash: None,
            expires_at: None,
            max_accesses: None,
            access_count: 0,
            is_revoked: false,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn creates_and_finds_share() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();

        let mut share = sample_share("sh1", "u1");
        share.is_dir = true;
        share.max_accesses = Some(5);
        share.expires_at = Some(Utc::now() + Duration::hours(2));
        create_share(&pool, &share).await.unwrap();

        let found = get_share_by_hash(&pool, "hash-sh1")
            .await
            .unwrap()
            .expect("by hash");
        assert_eq!(found.id, "sh1");
        assert_eq!(found.owner_id, "u1");
        assert!(found.is_dir);
        assert_eq!(found.max_accesses, Some(5));
        assert_eq!(found.access_count, 0);
        assert!(!found.is_revoked);
        assert!(found.password_hash.is_none());
        assert!(found.expires_at.is_some());

        assert_eq!(
            get_share_by_id(&pool, "sh1").await.unwrap().unwrap().id,
            "sh1"
        );
        assert!(get_share_by_hash(&pool, "hash-nope")
            .await
            .unwrap()
            .is_none());
        assert_eq!(get_shares_for_owner(&pool, "u1").await.unwrap().len(), 1);
        assert_eq!(count_shares_for_owner(&pool, "u1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn token_hash_is_unique() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();

        create_share(&pool, &sample_share("sh1", "u1"))
            .await
            .unwrap();

        // same digest, different id — must be refused, not silently accepted
        let mut clash = sample_share("sh2", "u1");
        clash.token_hash = "hash-sh1".to_string();
        assert!(create_share(&pool, &clash).await.is_err());

        assert_eq!(count_shares_for_owner(&pool, "u1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn share_foreign_key_rejects_unknown_owner() {
        let (pool, _dir) = temp_pool().await;

        // proves PRAGMA foreign_keys covers the shares table too
        assert!(create_share(&pool, &sample_share("sh1", "ghost"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn deleting_a_user_takes_their_shares_with_them() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        create_user(&pool, &sample_user("u2", "bob")).await.unwrap();

        create_share(&pool, &sample_share("sh1", "u1"))
            .await
            .unwrap();
        create_share(&pool, &sample_share("sh2", "u1"))
            .await
            .unwrap();
        create_share(&pool, &sample_share("sh3", "u2"))
            .await
            .unwrap();

        assert!(delete_user(&pool, "u1").await.unwrap());

        assert!(get_share_by_id(&pool, "sh1").await.unwrap().is_none());
        assert!(get_share_by_id(&pool, "sh2").await.unwrap().is_none());
        // the other user's link is untouched
        assert!(get_share_by_id(&pool, "sh3").await.unwrap().is_some());
    }

    /// The reason `access_count` and `max_accesses` live in the same row: N
    /// concurrent claims against a limit of 3 must grant exactly 3.
    ///
    /// The setup is deliberately hostile to a read-then-write implementation:
    ///
    ///   * `flavor = "multi_thread"` — the claims run on several OS threads, so
    ///     they overlap for real and not just at `await` points of one thread;
    ///   * a [`tokio::sync::Barrier`] releases all of them at the same instant,
    ///     *before* a pool connection is taken (waiting on the barrier while
    ///     holding one would deadlock against the pool's connection limit);
    ///   * more tasks than the pool has connections (default 10), so the claims
    ///     genuinely queue against SQLite's write lock.
    ///
    /// The assertion is on the *returned* counts, not only on how many calls
    /// said yes: a granted access must report 1, 2 and 3 exactly once each. A
    /// lost update would show a repeated number even when the tally happens to
    /// come out right.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn access_counting_is_atomic_under_concurrency() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();

        let mut share = sample_share("sh1", "u1");
        share.max_accesses = Some(3);
        create_share(&pool, &share).await.unwrap();

        const CLAIMS: usize = 24;
        let now = Utc::now();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CLAIMS));

        let mut handles = Vec::new();
        for _ in 0..CLAIMS {
            let pool = pool.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                consume_share_access(&pool, "hash-sh1", now).await
            }));
        }

        let mut granted_counts = Vec::new();
        for handle in handles {
            if let Some(share) = handle.await.expect("join").expect("query") {
                granted_counts.push(share.access_count);
            }
        }
        granted_counts.sort_unstable();

        assert_eq!(
            granted_counts,
            vec![1, 2, 3],
            "the limit was overrun, undershot, or an increment was lost"
        );
        let after = get_share_by_id(&pool, "sh1").await.unwrap().unwrap();
        assert_eq!(
            after.access_count, 3,
            "the counter must match what was granted"
        );
        // and the link is closed for good afterwards
        assert!(consume_share_access(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_none());
    }

    /// The continuation lookup ignores the limit — and nothing else.
    #[tokio::test]
    async fn unmetered_lookup_ignores_only_the_limit() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        let now = Utc::now();

        // exhausted: invisible to the metered lookup, visible to this one
        let mut exhausted = sample_share("sh1", "u1");
        exhausted.max_accesses = Some(1);
        exhausted.access_count = 1;
        create_share(&pool, &exhausted).await.unwrap();
        assert!(get_live_share_by_hash(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_none());
        assert!(get_unmetered_share_by_hash(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_some());

        // expired, revoked and unknown stay invisible to both
        let mut expired = sample_share("sh2", "u1");
        expired.expires_at = Some(now - Duration::minutes(1));
        create_share(&pool, &expired).await.unwrap();
        let mut revoked = sample_share("sh3", "u1");
        revoked.is_revoked = true;
        create_share(&pool, &revoked).await.unwrap();

        for hash in ["hash-sh2", "hash-sh3", "hash-nope"] {
            assert!(
                get_unmetered_share_by_hash(&pool, hash, now)
                    .await
                    .unwrap()
                    .is_none(),
                "{hash} must stay invisible"
            );
        }

        // a disabled owner takes the exhausted one offline as well
        set_user_active(&pool, "u1", false).await.unwrap();
        assert!(get_unmetered_share_by_hash(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_none());

        // reading never counts
        assert_eq!(
            get_share_by_id(&pool, "sh1")
                .await
                .unwrap()
                .unwrap()
                .access_count,
            1
        );
    }

    #[tokio::test]
    async fn consume_respects_limit_expiry_and_revocation() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        let now = Utc::now();

        // unlimited: counts up but never runs out
        create_share(&pool, &sample_share("sh1", "u1"))
            .await
            .unwrap();
        for expected in 1..=3 {
            let granted = consume_share_access(&pool, "hash-sh1", now)
                .await
                .unwrap()
                .expect("unlimited share must always grant");
            assert_eq!(granted.access_count, expected);
        }

        // expired
        let mut expired = sample_share("sh2", "u1");
        expired.expires_at = Some(now - Duration::minutes(1));
        create_share(&pool, &expired).await.unwrap();
        assert!(consume_share_access(&pool, "hash-sh2", now)
            .await
            .unwrap()
            .is_none());
        assert!(get_live_share_by_hash(&pool, "hash-sh2", now)
            .await
            .unwrap()
            .is_none());
        // it is still there, just unusable — and its counter did not move
        assert_eq!(
            get_share_by_id(&pool, "sh2")
                .await
                .unwrap()
                .unwrap()
                .access_count,
            0
        );

        // revoked
        let mut revoked = sample_share("sh3", "u1");
        revoked.is_revoked = true;
        create_share(&pool, &revoked).await.unwrap();
        assert!(consume_share_access(&pool, "hash-sh3", now)
            .await
            .unwrap()
            .is_none());

        // unknown token
        assert!(consume_share_access(&pool, "hash-nope", now)
            .await
            .unwrap()
            .is_none());
    }

    /// Disabling the owner must take their links down; deleting them removes
    /// the rows outright.
    #[tokio::test]
    async fn a_disabled_owner_takes_their_links_offline() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        create_share(&pool, &sample_share("sh1", "u1"))
            .await
            .unwrap();
        let now = Utc::now();

        assert!(get_live_share_by_hash(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_some());

        assert!(set_user_active(&pool, "u1", false).await.unwrap());

        assert!(get_live_share_by_hash(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_none());
        assert!(consume_share_access(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_none());
        // the row itself is untouched, so re-enabling restores the link
        assert!(get_share_by_hash(&pool, "hash-sh1")
            .await
            .unwrap()
            .is_some());
        assert!(set_user_active(&pool, "u1", true).await.unwrap());
        assert!(get_live_share_by_hash(&pool, "hash-sh1", now)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn revoke_and_delete_are_scoped_to_the_owner() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        create_user(&pool, &sample_user("u2", "bob")).await.unwrap();
        create_share(&pool, &sample_share("sh1", "u1"))
            .await
            .unwrap();

        // a stranger cannot touch it, and gets the same answer as for a
        // share that does not exist
        assert!(!revoke_share(&pool, "sh1", "u2").await.unwrap());
        assert!(!delete_share(&pool, "sh1", "u2").await.unwrap());
        assert!(!revoke_share(&pool, "ghost", "u2").await.unwrap());
        assert!(
            !get_share_by_id(&pool, "sh1")
                .await
                .unwrap()
                .unwrap()
                .is_revoked
        );

        assert!(revoke_share(&pool, "sh1", "u1").await.unwrap());
        assert!(
            get_share_by_id(&pool, "sh1")
                .await
                .unwrap()
                .unwrap()
                .is_revoked
        );

        assert!(delete_share(&pool, "sh1", "u1").await.unwrap());
        assert!(get_share_by_id(&pool, "sh1").await.unwrap().is_none());
        assert!(!delete_share(&pool, "sh1", "u1").await.unwrap());
    }

    #[tokio::test]
    async fn expired_shares_are_swept_but_unlimited_ones_are_not() {
        let (pool, _dir) = temp_pool().await;
        create_user(&pool, &sample_user("u1", "alice"))
            .await
            .unwrap();
        let now = Utc::now();

        let mut gone = sample_share("sh1", "u1");
        gone.expires_at = Some(now - Duration::hours(1));
        create_share(&pool, &gone).await.unwrap();

        let mut alive = sample_share("sh2", "u1");
        alive.expires_at = Some(now + Duration::hours(1));
        create_share(&pool, &alive).await.unwrap();

        // exhausted, but without an expiry — housekeeping must leave it alone
        let mut exhausted = sample_share("sh3", "u1");
        exhausted.max_accesses = Some(1);
        exhausted.access_count = 1;
        create_share(&pool, &exhausted).await.unwrap();

        assert_eq!(delete_expired_shares(&pool, now).await.unwrap(), 1);
        assert_eq!(delete_expired_shares(&pool, now).await.unwrap(), 0);

        assert!(get_share_by_id(&pool, "sh1").await.unwrap().is_none());
        assert!(get_share_by_id(&pool, "sh2").await.unwrap().is_some());
        assert!(get_share_by_id(&pool, "sh3").await.unwrap().is_some());
    }

    /// `is_usable_at` is the read-only twin of the SQL in
    /// `consume_share_access`; the two must agree.
    #[test]
    fn is_usable_at_matches_the_sql_conditions() {
        let now = Utc::now();
        let base = sample_share("sh1", "u1");
        assert!(base.is_usable_at(now));

        let mut revoked = base.clone();
        revoked.is_revoked = true;
        assert!(!revoked.is_usable_at(now));

        let mut expired = base.clone();
        expired.expires_at = Some(now - Duration::seconds(1));
        assert!(!expired.is_usable_at(now));

        let mut future = base.clone();
        future.expires_at = Some(now + Duration::seconds(1));
        assert!(future.is_usable_at(now));

        let mut exhausted = base.clone();
        exhausted.max_accesses = Some(2);
        exhausted.access_count = 2;
        assert!(!exhausted.is_usable_at(now));

        let mut left = base.clone();
        left.max_accesses = Some(2);
        left.access_count = 1;
        assert!(left.is_usable_at(now));
    }

    /// Same guarantee as on `User` and `Session`: the lookup key and the
    /// crackable hash must not be printable, but the rest must stay useful.
    #[test]
    fn share_debug_redacts_token_hash_and_password() {
        let mut share = sample_share("sh1", "u1");
        share.token_hash = "deadbeefcafe0000".to_string();
        share.password_hash = Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_string());

        let rendered = format!("{share:?}");

        assert!(!rendered.contains("deadbeefcafe0000"), "{rendered}");
        assert!(!rendered.contains("$argon2"), "{rendered}");
        // still worth printing
        assert!(rendered.contains("sh1"), "{rendered}");
        assert!(rendered.contains("u1"), "{rendered}");
        assert!(rendered.contains("report.pdf"), "{rendered}");
    }

    /// `Serialize` must not carry the secrets into an API response either.
    #[test]
    fn share_serialization_omits_the_secrets() {
        let mut share = sample_share("sh1", "u1");
        share.token_hash = "deadbeefcafe0000".to_string();
        share.password_hash = Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_string());

        let json = serde_json::to_string(&share).expect("serialize");

        assert!(!json.contains("deadbeefcafe0000"), "{json}");
        assert!(!json.contains("$argon2"), "{json}");
        assert!(json.contains("report.pdf"), "{json}");
    }
}
