// Anonymous share links: token generation and the creation of a share row.
//
// This module owns the *secret* half of a share. The database layer
// (`crate::database`) only ever stores a digest; the plaintext token exists in
// exactly one place — the return value of [`create_share`] — and the caller is
// expected to hand it to the user once and drop it.
//
// The HTTP surface (`GET /s/:token`, the create/revoke endpoints) belongs to
// the follow-up tickets; this module deliberately contains no axum handlers, so
// nothing here has a caller yet.
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Sqlite};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::database::{self, Share};

// ---------------------------------------------------------------------------
// Token
//
// Same reasoning as for session tokens in `handlers::auth`, and the same shape,
// because a share link is the identical kind of credential: a bearer secret
// that is worth nothing to guess and everything to leak.
//
// 32 bytes straight from the OS CSPRNG, stored as its SHA-256 digest. Reading
// the database therefore does not yield a working link — which is the point of
// the ticket: an operator, a backup or a leaked dump must not be able to open
// somebody's shared folder.
//
// SHA-256 rather than Argon2 for the same reason as there: the input is 256
// random bits, so there is nothing to slow an attacker down over, and the hash
// runs on every public request. No salt, because there is no precomputation to
// defend against over that input space.
// ---------------------------------------------------------------------------

/// Length of a raw share token in bytes. 32 bytes = 256 bits.
///
/// A share link is handed out anonymously and often lives in a chat log or a
/// mail, so the token is the *only* thing standing between the world and the
/// shared path. It gets the same budget as a session cookie, not less.
pub const SHARE_TOKEN_BYTES: usize = 32;

/// The 32-byte floor is a requirement, not a preference — enforced at compile
/// time so nobody can shrink it in passing.
const _: () = assert!(SHARE_TOKEN_BYTES >= 32);

/// Length of a token in the form that travels in the URL (lowercase hex).
pub const SHARE_TOKEN_HEX_LENGTH: usize = SHARE_TOKEN_BYTES * 2;

/// A raw share-link token.
///
/// Wrapped in a newtype on purpose, mirroring `auth::SessionToken`:
///   * no `Display`, no `Serialize` and a redacting `Debug`, so it cannot reach
///     a `tracing` line or a JSON response by accident;
///   * reading the secret takes the explicit [`ShareToken::expose`], which is
///     greppable in review.
///
/// A derived `Debug` has already written a live token into a log once in this
/// project. That is what this type exists to prevent.
#[derive(Clone)]
pub struct ShareToken(String);

impl ShareToken {
    /// The token in its link form (lowercase hex). Only call this where the
    /// value is genuinely needed — building the one response that shows the
    /// user their new link.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The digest that is stored in `shares.token_hash`.
    pub fn hash(&self) -> String {
        hash_share_token(&self.0)
    }
}

impl std::fmt::Debug for ShareToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the value, not even a prefix of it.
        f.write_str("ShareToken(<redacted>)")
    }
}

/// Draw a fresh share token from the operating system CSPRNG.
///
/// Fails instead of panicking when the entropy source is unavailable: handing
/// out a token from a degraded RNG is the one outcome that would be a security
/// bug, so it has to be an error the caller must handle.
pub fn generate_share_token() -> Result<ShareToken> {
    let mut bytes = [0u8; SHARE_TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow!("failed to draw a share token from the system RNG: {e}"))?;

    Ok(ShareToken(to_hex(&bytes)))
}

/// SHA-256 of a token, lowercase hex. This is what `shares.token_hash` holds.
pub fn hash_share_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    to_hex(&digest)
}

/// Whether `candidate` has the shape of a token this server issues.
///
/// Lets the public route reject junk out of a URL before it costs a database
/// round trip. It says nothing about validity — a well-formed token can still
/// be unknown, revoked or expired.
pub fn is_well_formed_share_token(candidate: &str) -> bool {
    candidate.len() == SHARE_TOKEN_HEX_LENGTH
        && candidate
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Lowercase hex.
///
/// Duplicated from `handlers::auth` rather than shared: that module belongs to
/// another ticket and its helper is private. Worth folding into one place once
/// both are settled.
fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

/// What the caller decides when a share is created. Everything else — id,
/// token, counters, timestamps — is set here, so no caller can invent them.
#[derive(Clone)]
pub struct NewShare {
    pub owner_id: String,
    /// Path as it is stored. It is **not** validated here: canonicalising it
    /// and checking it against the owner's home needs the path resolver and
    /// belongs to the endpoint that accepts it. Freezing a path is not a
    /// substitute for re-checking it on every access.
    pub path: String,
    pub is_dir: bool,
    /// Optional Argon2id PHC string. Hash it with `auth::hash_password` — a
    /// plaintext password must never reach this struct's field.
    pub password_hash: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    /// `None` = unlimited. Values below 1 are rejected: a share nobody may open
    /// is a mistake, not a configuration.
    pub max_accesses: Option<i64>,
}

impl std::fmt::Debug for NewShare {
    /// Hand-written for the same reason as [`Share`]'s: the derived version
    /// printed the whole Argon2id PHC string. A hash is not a password, but it
    /// is the material an offline attack works on, and a log line is exactly
    /// where it must not turn up. Shows everything that identifies the share.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewShare")
            .field("owner_id", &self.owner_id)
            .field("path", &self.path)
            .field("is_dir", &self.is_dir)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("max_accesses", &self.max_accesses)
            .finish()
    }
}

/// Create a share and return it together with its plaintext token.
///
/// The token is returned **once** and never stored; only its digest reaches the
/// database. Show it to the user and drop the [`ShareToken`] — there is no way
/// to recover it afterwards, which is the intended property.
pub async fn create_share(
    pool: &Pool<Sqlite>,
    new_share: NewShare,
    now: DateTime<Utc>,
) -> Result<(Share, ShareToken)> {
    if new_share.owner_id.is_empty() {
        return Err(anyhow!("a share needs an owner"));
    }
    if new_share.path.is_empty() {
        return Err(anyhow!("a share needs a path"));
    }
    if let Some(max) = new_share.max_accesses {
        if max < 1 {
            return Err(anyhow!(
                "max_accesses must be at least 1, got {max} — omit it for an unlimited link"
            ));
        }
    }
    if let Some(expires_at) = new_share.expires_at {
        if expires_at <= now {
            return Err(anyhow!("the expiry of a share must lie in the future"));
        }
    }

    let token = generate_share_token()?;
    let share = Share {
        id: uuid::Uuid::new_v4().to_string(),
        token_hash: token.hash(),
        owner_id: new_share.owner_id,
        path: new_share.path,
        is_dir: new_share.is_dir,
        password_hash: new_share.password_hash,
        expires_at: new_share.expires_at,
        max_accesses: new_share.max_accesses,
        access_count: 0,
        is_revoked: false,
        created_at: now,
    };

    // A failing INSERT (unknown owner, or the practically impossible token
    // collision the UNIQUE index guards against) leaves nothing behind: the
    // token was never handed out.
    database::create_share(pool, &share).await?;

    // The id is not secret; the token is, and is therefore not logged.
    tracing::info!(
        share_id = %share.id,
        owner_id = %share.owner_id,
        is_dir = share.is_dir,
        "created share link"
    );

    Ok((share, token))
}

// ---------------------------------------------------------------------------
// Access
//
// Everything below answers one question: may this request have the content?
//
// Three rules shape it, and they are all rules about *not* being generous:
//
//  1. Only a request that actually hands out content counts. Opening the
//     landing page, a link preview bot, a reload — none of them consume an
//     access, or a stranger could burn a share by knocking on it.
//  2. A denial never says why. Unknown, malformed, revoked, expired, exhausted
//     and "owner disabled" all collapse into [`ShareAccess::Gone`], because a
//     distinguishable answer turns the endpoint into an oracle for probing
//     tokens.
//  3. The claim itself is one SQL statement (`database::consume_share_access`).
//     Nothing here reads the counter and then writes it back.
// ---------------------------------------------------------------------------

/// How long a started download may keep fetching ranges without counting again.
///
/// It is an *idle* timeout, refreshed by every range request, so a slow
/// connection on a big file is never cut off mid-transfer. Five minutes is long
/// enough for a player that pauses and seeks, and short enough that the window
/// is not a second, uncounted share link.
const DOWNLOAD_GRANT_IDLE_SECONDS: i64 = 300;

/// Upper bound on remembered downloads.
///
/// The map is keyed partly by client-supplied data, so its size is an attack
/// surface. When it is full, new grants are simply not recorded: the next range
/// request of that download then counts again. That is the direction a failure
/// has to go — an over-count costs the owner an access, an under-count would
/// cost them the limit.
const MAX_DOWNLOAD_GRANTS: usize = 10_000;

/// Downloads that have already paid for themselves.
///
/// A single video download arrives as many `Range` requests. Counting each one
/// would empty a 3-access link before the first file finished, so the request
/// that *opens* a download claims the access and leaves a grant behind; the
/// range requests that follow it ride on that grant.
///
/// The grant is keyed by the token digest **and** a caller-supplied client key
/// (see [`AccessRequest::client_key`]) — never by the token alone, or one
/// visitor's download would let every other visitor fetch the file for free.
///
/// This is in-memory on purpose: a lost grant (restart, second process) makes
/// the next range request count once more, which is a correct, conservative
/// outcome. Persisting it would buy nothing and would put a second copy of the
/// token digest on disk.
pub struct DownloadGrants {
    idle_ttl: Duration,
    /// `(token_hash, client_key) -> last seen`.
    grants: Mutex<HashMap<(String, String), DateTime<Utc>>>,
}

impl Default for DownloadGrants {
    fn default() -> Self {
        Self::new()
    }
}

impl DownloadGrants {
    pub fn new() -> Self {
        Self::with_idle_ttl(Duration::seconds(DOWNLOAD_GRANT_IDLE_SECONDS))
    }

    /// Mainly for tests, which need to age a grant without waiting.
    pub fn with_idle_ttl(idle_ttl: Duration) -> Self {
        Self {
            idle_ttl,
            grants: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this download is already paid for — and if so, keep it alive.
    ///
    /// Refreshing here rather than in a second call is what makes the timeout
    /// an idle timeout: a transfer that keeps asking keeps its grant.
    fn continues_paid_download(
        &self,
        token_hash: &str,
        client_key: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let mut grants = self.lock();
        let key = (token_hash.to_string(), client_key.to_string());

        match grants.get(&key) {
            Some(last_seen) if now - *last_seen < self.idle_ttl => {
                grants.insert(key, now);
                true
            }
            // Expired: drop it now rather than leave it for the sweep, so a
            // stale entry can never be revived by a clock adjustment.
            Some(_) => {
                grants.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Record that an access was claimed for this download.
    fn open(&self, token_hash: &str, client_key: &str, now: DateTime<Utc>) {
        let mut grants = self.lock();

        // Cheap amortised sweep: only when the map is at its cap, and only over
        // entries that are already dead.
        if grants.len() >= MAX_DOWNLOAD_GRANTS {
            let ttl = self.idle_ttl;
            grants.retain(|_, last_seen| now - *last_seen < ttl);
        }
        if grants.len() >= MAX_DOWNLOAD_GRANTS {
            tracing::warn!(
                "download grant table is full ({MAX_DOWNLOAD_GRANTS} entries) — \
                 ranged downloads will be counted per request until it drains"
            );
            return;
        }

        grants.insert((token_hash.to_string(), client_key.to_string()), now);
    }

    /// Drop everything that has gone idle. Meant for the same housekeeping
    /// timer that sweeps expired sessions.
    pub fn sweep(&self, now: DateTime<Utc>) {
        let ttl = self.idle_ttl;
        self.lock().retain(|_, last_seen| now - *last_seen < ttl);
    }

    /// Number of live-or-not entries. Tests only.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    /// A poisoned lock means some other thread panicked while holding it; the
    /// map is still a perfectly good map, and refusing to serve downloads over
    /// it would be worse than carrying on. Never `unwrap` — this sits in a
    /// request path.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), DateTime<Utc>>> {
        self.grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl std::fmt::Debug for DownloadGrants {
    /// The keys contain token digests. Only the size is printable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadGrants")
            .field("entries", &self.lock().len())
            .field("idle_ttl", &self.idle_ttl)
            .finish()
    }
}

/// One attempt to fetch the content behind a share link.
///
/// `Debug` is hand-written: this struct holds the token *and* the plaintext
/// password, which is precisely the pair that must never appear in a log line.
pub struct AccessRequest<'a> {
    /// The token exactly as it arrived in the URL — unchecked.
    pub token: &'a str,
    /// The password the visitor supplied, if any. Plaintext, never stored.
    pub password: Option<&'a str>,
    /// The raw `Range` header of the request, if it had one. Its *presence* is
    /// what matters here, not the byte offsets: a ranged request is a
    /// continuation candidate, a plain one always starts a new download.
    pub range: Option<&'a str>,
    /// Whatever the route uses to tell one downloader from another (peer
    /// address plus user agent, or a per-download cookie once one exists).
    ///
    /// It only ever narrows a grant, so a wrong or empty value cannot let
    /// somebody else's download through — it can at worst cost an extra count.
    pub client_key: &'a str,
}

impl std::fmt::Debug for AccessRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessRequest")
            .field("token", &"<redacted>")
            .field("password", &self.password.map(|_| "<redacted>"))
            .field("range", &self.range)
            .field("client_key", &self.client_key)
            .finish()
    }
}

/// The verdict on an [`AccessRequest`].
#[derive(Debug)]
pub enum ShareAccess {
    /// Hand out the content. Carries the share **after** the access was
    /// counted, so `access_count` is the number this request claimed.
    Granted(Share),
    /// The link is live but password protected, and no matching password came
    /// with the request. The only outcome besides `Granted` that is
    /// distinguishable from the outside — it has to be, or a protected link
    /// could never be opened — and it costs no access.
    PasswordRequired,
    /// Everything else: unknown, malformed, revoked, expired, exhausted,
    /// owner disabled. One variant on purpose. Answer it with a single status
    /// (HTTP 410) and an identical body, whatever the real reason was.
    Gone,
}

/// Look at a share without touching its counter.
///
/// This is what the public landing page runs on: showing a visitor the file
/// name must not spend one of the owner's accesses, or a reload — or a chat
/// client fetching a preview — would eat the link.
pub async fn peek_share(
    pool: &Pool<Sqlite>,
    token: &str,
    now: DateTime<Utc>,
) -> Result<Option<Share>> {
    if !is_well_formed_share_token(token) {
        return Ok(None);
    }

    database::get_live_share_by_hash(pool, &hash_share_token(token), now).await
}

/// Decide whether the content behind a share link may be handed out, and claim
/// an access if it may.
///
/// Call this **only** where content is actually delivered. It is the one place
/// that consumes; everything that merely renders a page uses [`peek_share`].
///
/// The order of the steps is the security-relevant part:
///
///   1. shape check, then the metered lookup — an exhausted or expired link
///      never reaches the password step, so a protected link cannot be
///      distinguished from an unprotected one after it has run out;
///   2. the password, verified before anything is consumed, so a wrong guess
///      cannot burn an access;
///   3. the atomic claim, which re-checks every condition from step 1 under the
///      write lock. The earlier lookup is a filter, never the decision.
pub async fn authorize_content_access(
    pool: &Pool<Sqlite>,
    grants: &DownloadGrants,
    request: &AccessRequest<'_>,
    now: DateTime<Utc>,
) -> Result<ShareAccess> {
    if !is_well_formed_share_token(request.token) {
        spend_password_time(request.password).await;
        return Ok(ShareAccess::Gone);
    }

    let token_hash = hash_share_token(request.token);

    // A ranged request may be the continuation of a download that already paid.
    let continuing = request.range.is_some()
        && grants.continues_paid_download(&token_hash, request.client_key, now);

    // A continuation is looked up without the limit — the access it rides on
    // was claimed when the download started, and the final chunk of a file must
    // not fail because that claim was the last one. Everything else (revoked,
    // expired, owner disabled) still applies.
    let candidate = if continuing {
        database::get_unmetered_share_by_hash(pool, &token_hash, now).await?
    } else {
        database::get_live_share_by_hash(pool, &token_hash, now).await?
    };

    let Some(candidate) = candidate else {
        // Spend the same Argon2 time an existing protected share would have
        // cost, so the response time does not separate "no such link" from
        // "wrong password". Same trick, and the same reason, as the login.
        spend_password_time(request.password).await;
        return Ok(ShareAccess::Gone);
    };

    if let Some(stored_hash) = candidate.password_hash.clone() {
        let Some(supplied) = request.password else {
            return Ok(ShareAccess::PasswordRequired);
        };
        if !verify_password_off_thread(supplied.to_string(), stored_hash).await {
            // Deliberately not `Gone`: a wrong password is a retryable state,
            // and it must not consume an access either.
            tracing::info!(
                share_id = %candidate.id,
                "share link opened with a wrong password"
            );
            return Ok(ShareAccess::PasswordRequired);
        }
    }

    if continuing {
        // Already counted when the download started.
        return Ok(ShareAccess::Granted(candidate));
    }

    match database::consume_share_access(pool, &token_hash, now).await? {
        Some(share) => {
            grants.open(&token_hash, request.client_key, now);
            tracing::info!(
                share_id = %share.id,
                access_count = share.access_count,
                max_accesses = ?share.max_accesses,
                "share access granted"
            );
            Ok(ShareAccess::Granted(share))
        }
        // Lost the race against a concurrent download, or the link expired
        // between the lookup and the claim. Indistinguishable from the outside,
        // which is correct.
        None => Ok(ShareAccess::Gone),
    }
}

/// Run Argon2 off the async runtime. Verification is CPU- and memory-bound by
/// design; doing it inline would stall every other request on the worker.
async fn verify_password_off_thread(password: String, stored_hash: String) -> bool {
    match tokio::task::spawn_blocking(move || {
        crate::handlers::auth::verify_password(&password, &stored_hash)
    })
    .await
    {
        Ok(verified) => verified,
        Err(e) => {
            // No password material in the message.
            tracing::error!("share password verification task failed: {e}");
            false
        }
    }
}

/// Burn the time a real verification would have taken, when there was nothing
/// to verify against. Does nothing when the request carried no password.
async fn spend_password_time(password: Option<&str>) {
    let Some(password) = password else {
        return;
    };

    let _ =
        verify_password_off_thread(password.to_string(), dummy_password_hash().to_string()).await;
}

/// A stand-in Argon2id hash over a secret nobody knows, so it can never verify.
///
/// Duplicated from `handlers::auth` for the same reason as [`to_hex`]: the
/// original is private and that file belongs to another ticket. Worth folding
/// into one place together with `to_hex` once it is free.
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    DUMMY
        .get_or_init(|| {
            let throwaway =
                generate_share_token().map_or_else(|_| String::new(), |t| t.expose().to_string());
            // On failure the fallback is an unparseable string, which
            // `verify_password` rejects — the outcome is unchanged, only the
            // timing defence is lost.
            crate::handlers::auth::hash_password(&throwaway).unwrap_or_default()
        })
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A pool on a temporary on-disk database, with one user to own shares.
    async fn temp_pool() -> (Pool<Sqlite>, TempDir) {
        let dir = TempDir::new();
        let url = format!("sqlite:{}?mode=rwc", dir.path().join("test.db").display());
        let pool = database::connect(&url).await.expect("connect");
        database::run_migrations(&pool).await.expect("migrate");

        database::create_user(
            &pool,
            &database::User {
                id: "u1".to_string(),
                username: "alice".to_string(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_string(),
                role: "user".to_string(),
                home_path: "/data/home/alice".to_string(),
                is_active: true,
                created_at: Utc::now(),
                last_login_at: None,
            },
        )
        .await
        .expect("create user");

        (pool, dir)
    }

    /// Throwaway temp directory — the crate has no dev dependency on
    /// `tempfile`, and adding one would touch `Cargo.toml`.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rclone-gui-shares-test-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn new_share() -> NewShare {
        NewShare {
            owner_id: "u1".to_string(),
            path: "/data/home/alice/report.pdf".to_string(),
            is_dir: false,
            password_hash: None,
            expires_at: None,
            max_accesses: None,
        }
    }

    #[test]
    fn tokens_are_long_hex_and_never_repeat() {
        let mut seen = HashSet::new();

        for _ in 0..256 {
            let token = generate_share_token().expect("generate");
            let raw = token.expose().to_string();

            assert_eq!(raw.len(), SHARE_TOKEN_HEX_LENGTH, "256 bits in hex");
            assert!(is_well_formed_share_token(&raw), "{raw}");
            assert!(seen.insert(raw), "the same share token came up twice");
        }
    }

    #[test]
    fn hashing_is_stable_and_one_way() {
        let token = generate_share_token().expect("generate");

        assert_eq!(token.hash(), token.hash(), "hashing must be deterministic");
        assert_eq!(token.hash().len(), 64, "SHA-256 in hex");
        assert_ne!(
            token.hash(),
            token.expose(),
            "the digest must not be the token"
        );

        let other = generate_share_token().expect("generate");
        assert_ne!(token.hash(), other.hash());

        // known-answer, so a swapped algorithm cannot pass unnoticed
        assert_eq!(
            hash_share_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn well_formed_rejects_junk() {
        let good = "a".repeat(SHARE_TOKEN_HEX_LENGTH);
        assert!(is_well_formed_share_token(&good));

        assert!(!is_well_formed_share_token(""));
        assert!(!is_well_formed_share_token(&"a".repeat(63)));
        assert!(!is_well_formed_share_token(&"a".repeat(65)));
        // uppercase hex is not what we issue
        assert!(!is_well_formed_share_token(&"A".repeat(64)));
        // right length, not hex
        assert!(!is_well_formed_share_token(&"z".repeat(64)));
        assert!(!is_well_formed_share_token(&"../".repeat(21)));
    }

    /// The whole point of the newtype: a token must not be printable by
    /// accident. Both halves matter — an empty `Debug` would pass the negative
    /// check on its own.
    #[test]
    fn debug_redacts_the_token() {
        let token = generate_share_token().expect("generate");
        let rendered = format!("{token:?}");

        assert!(
            !rendered.contains(token.expose()),
            "share token leaked into Debug: {rendered}"
        );
        // not even a prefix
        assert!(!rendered.contains(&token.expose()[..8]), "{rendered}");
        assert_eq!(rendered, "ShareToken(<redacted>)");
    }

    #[tokio::test]
    async fn creating_a_share_stores_only_the_hash() {
        let (pool, _dir) = temp_pool().await;

        let (share, token) = create_share(&pool, new_share(), Utc::now())
            .await
            .expect("create share");

        assert_eq!(share.token_hash, token.hash());
        assert_ne!(share.token_hash, token.expose());
        assert_eq!(share.access_count, 0);
        assert!(!share.is_revoked);

        // the acceptance criterion, checked against the raw table rather than
        // against our own struct: no column anywhere holds the plaintext
        let rows: Vec<(String, String, String, Option<String>)> =
            sqlx::query_as("SELECT id, token_hash, path, password_hash FROM shares")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rows.len(), 1);
        for row in &rows {
            for cell in [Some(&row.0), Some(&row.1), Some(&row.2), row.3.as_ref()]
                .into_iter()
                .flatten()
            {
                assert!(
                    !cell.contains(token.expose()),
                    "the plaintext token reached the database: {cell}"
                );
            }
        }

        // and it is retrievable by the digest, not by the token
        assert!(database::get_share_by_hash(&pool, token.expose())
            .await
            .unwrap()
            .is_none());
        assert!(database::get_share_by_hash(&pool, &token.hash())
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn two_shares_never_share_a_token() {
        let (pool, _dir) = temp_pool().await;
        let now = Utc::now();

        let mut tokens = HashSet::new();
        let mut hashes = HashSet::new();

        for _ in 0..64 {
            let (share, token) = create_share(&pool, new_share(), now).await.expect("create");
            assert!(tokens.insert(token.expose().to_string()), "token repeated");
            assert!(hashes.insert(share.token_hash.clone()), "hash repeated");
        }

        assert_eq!(
            database::count_shares_for_owner(&pool, "u1").await.unwrap(),
            64
        );
    }

    #[tokio::test]
    async fn rejects_nonsense_input() {
        let (pool, _dir) = temp_pool().await;
        let now = Utc::now();

        let mut no_owner = new_share();
        no_owner.owner_id = String::new();
        assert!(create_share(&pool, no_owner, now).await.is_err());

        let mut no_path = new_share();
        no_path.path = String::new();
        assert!(create_share(&pool, no_path, now).await.is_err());

        let mut zero_limit = new_share();
        zero_limit.max_accesses = Some(0);
        assert!(create_share(&pool, zero_limit, now).await.is_err());

        let mut past = new_share();
        past.expires_at = Some(now - Duration::hours(1));
        assert!(create_share(&pool, past, now).await.is_err());

        // an unknown owner is caught by the foreign key, not by us
        let mut ghost = new_share();
        ghost.owner_id = "nobody".to_string();
        assert!(create_share(&pool, ghost, now).await.is_err());

        assert_eq!(
            database::count_shares_for_owner(&pool, "u1").await.unwrap(),
            0,
            "a rejected share must leave no row behind"
        );
    }

    /// `NewShare` carries an Argon2 hash, never a plaintext password — and its
    /// derived `Debug` must not print the hash either.
    #[tokio::test]
    async fn password_protected_share_stores_the_phc_string() {
        let (pool, _dir) = temp_pool().await;

        let hash = crate::handlers::auth::hash_password("correct horse battery staple")
            .expect("hash password");

        let mut protected = new_share();
        protected.password_hash = Some(hash.clone());

        let (share, _token) = create_share(&pool, protected, Utc::now())
            .await
            .expect("create");

        let stored = database::get_share_by_id(&pool, &share.id)
            .await
            .unwrap()
            .expect("stored");
        assert_eq!(stored.password_hash.as_deref(), Some(hash.as_str()));
        assert!(crate::handlers::auth::verify_password(
            "correct horse battery staple",
            &hash
        ));

        // `Share::Debug` redacts it (the model's own guarantee, checked here
        // because this is the path that fills the field)
        let rendered = format!("{stored:?}");
        assert!(!rendered.contains("$argon2"), "{rendered}");
        assert!(!rendered.contains(&hash), "{rendered}");
    }

    // -----------------------------------------------------------------------
    // Access
    // -----------------------------------------------------------------------

    /// A plain, non-ranged request from one anonymous visitor.
    fn plain<'a>(token: &'a ShareToken) -> AccessRequest<'a> {
        AccessRequest {
            token: token.expose(),
            password: None,
            range: None,
            client_key: "203.0.113.7|curl",
        }
    }

    fn granted(access: &ShareAccess) -> bool {
        matches!(access, ShareAccess::Granted(_))
    }

    async fn stored_count(pool: &Pool<Sqlite>, id: &str) -> i64 {
        database::get_share_by_id(pool, id)
            .await
            .expect("load share")
            .expect("share exists")
            .access_count
    }

    /// The headline criterion: once the limit is reached, nothing gets through
    /// any more — and the counter stops there.
    #[tokio::test]
    async fn access_stops_at_the_limit() {
        let (pool, _dir) = temp_pool().await;
        let grants = DownloadGrants::new();
        let now = Utc::now();

        let mut limited = new_share();
        limited.max_accesses = Some(2);
        let (share, token) = create_share(&pool, limited, now).await.expect("create");

        for expected in 1..=2 {
            let access = authorize_content_access(&pool, &grants, &plain(&token), now)
                .await
                .expect("authorize");
            match access {
                ShareAccess::Granted(s) => assert_eq!(s.access_count, expected),
                other => panic!("access {expected} should have been granted, got {other:?}"),
            }
        }

        for _ in 0..3 {
            let access = authorize_content_access(&pool, &grants, &plain(&token), now)
                .await
                .expect("authorize");
            assert!(!granted(&access), "the limit did not hold: {access:?}");
        }

        assert_eq!(
            stored_count(&pool, &share.id).await,
            2,
            "a rejected attempt must not move the counter"
        );
    }

    /// The criterion this whole ticket exists for. Read-then-write passes the
    /// sequential test above and fails this one.
    ///
    /// It is built to actually race: several OS threads
    /// (`flavor = "multi_thread"`), a barrier so every task reaches the claim
    /// at the same moment, and more tasks than the pool has connections, so
    /// they queue on SQLite's write lock rather than tiptoe past each other.
    /// A limit of 1 is the sharpest case — the last remaining access.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_downloads_cannot_exceed_the_limit() {
        let (pool, _dir) = temp_pool().await;
        let now = Utc::now();

        let mut limited = new_share();
        limited.max_accesses = Some(1);
        let (share, token) = create_share(&pool, limited, now).await.expect("create");

        const ATTEMPTS: usize = 24;
        let grants = std::sync::Arc::new(DownloadGrants::new());
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
        let raw = token.expose().to_string();

        let mut handles = Vec::new();
        for i in 0..ATTEMPTS {
            let pool = pool.clone();
            let grants = grants.clone();
            let barrier = barrier.clone();
            let raw = raw.clone();
            handles.push(tokio::spawn(async move {
                // Distinct client keys: nobody may ride on anybody else's grant.
                let client_key = format!("198.51.100.{i}|player");
                let request = AccessRequest {
                    token: &raw,
                    password: None,
                    range: None,
                    client_key: &client_key,
                };
                barrier.wait().await;
                matches!(
                    authorize_content_access(&pool, &grants, &request, now).await,
                    Ok(ShareAccess::Granted(_))
                )
            }));
        }

        let mut granted_count = 0;
        for handle in handles {
            if handle.await.expect("join") {
                granted_count += 1;
            }
        }

        assert_eq!(
            granted_count, 1,
            "{ATTEMPTS} simultaneous downloads got past a limit of 1"
        );
        assert_eq!(stored_count(&pool, &share.id).await, 1);
    }

    /// A video is fetched in many `Range` requests. All of them together are
    /// one access.
    #[tokio::test]
    async fn a_ranged_download_counts_once() {
        let (pool, _dir) = temp_pool().await;
        let grants = DownloadGrants::with_idle_ttl(Duration::seconds(60));
        let now = Utc::now();

        let mut limited = new_share();
        limited.max_accesses = Some(1);
        let (share, token) = create_share(&pool, limited, now).await.expect("create");

        let ranged = |bytes: &'static str| AccessRequest {
            token: token.expose(),
            password: None,
            range: Some(bytes),
            client_key: "203.0.113.7|player",
        };

        // The request that opens the download pays for it.
        assert!(granted(
            &authorize_content_access(&pool, &grants, &ranged("bytes=0-1023"), now)
                .await
                .expect("authorize")
        ));
        assert_eq!(stored_count(&pool, &share.id).await, 1);

        // Every further chunk — including seeks backwards — rides along, even
        // though the link is now exhausted.
        for range in ["bytes=1024-2047", "bytes=8192-", "bytes=0-1023"] {
            let access = authorize_content_access(
                &pool,
                &grants,
                &AccessRequest {
                    token: token.expose(),
                    password: None,
                    range: Some(range),
                    client_key: "203.0.113.7|player",
                },
                now,
            )
            .await
            .expect("authorize");
            assert!(granted(&access), "range {range} was cut off: {access:?}");
        }
        assert_eq!(
            stored_count(&pool, &share.id).await,
            1,
            "the range requests of one download counted more than once"
        );

        // Somebody else's ranged request is not a continuation — it is a new
        // download, and the link has nothing left.
        let stranger = authorize_content_access(
            &pool,
            &grants,
            &AccessRequest {
                token: token.expose(),
                password: None,
                range: Some("bytes=0-1023"),
                client_key: "192.0.2.99|player",
            },
            now,
        )
        .await
        .expect("authorize");
        assert!(
            !granted(&stranger),
            "a stranger rode on somebody else's download grant: {stranger:?}"
        );

        // And the grant is not a second link: once it goes idle it is gone,
        // and the exhausted share is exhausted again.
        let later = now + Duration::seconds(61);
        let stale = authorize_content_access(&pool, &grants, &ranged("bytes=2048-"), later)
            .await
            .expect("authorize");
        assert!(
            !granted(&stale),
            "an idle grant kept an exhausted link alive: {stale:?}"
        );
        assert_eq!(stored_count(&pool, &share.id).await, 1);
    }

    /// A grant must never outlive a revocation — the download is cut off at the
    /// next chunk, not allowed to run to the end.
    #[tokio::test]
    async fn revoking_stops_a_running_ranged_download() {
        let (pool, _dir) = temp_pool().await;
        let grants = DownloadGrants::new();
        let now = Utc::now();

        let (share, token) = create_share(&pool, new_share(), now).await.expect("create");
        let ranged = AccessRequest {
            token: token.expose(),
            password: None,
            range: Some("bytes=0-1023"),
            client_key: "203.0.113.7|player",
        };

        assert!(granted(
            &authorize_content_access(&pool, &grants, &ranged, now)
                .await
                .expect("authorize")
        ));

        assert!(database::revoke_share(&pool, &share.id, "u1")
            .await
            .expect("revoke"));

        let after = authorize_content_access(&pool, &grants, &ranged, now)
            .await
            .expect("authorize");
        assert!(!granted(&after), "a revoked link kept serving: {after:?}");
    }

    /// Knocking on a protected link must not cost the owner anything.
    #[tokio::test]
    async fn a_wrong_password_costs_no_access() {
        let (pool, _dir) = temp_pool().await;
        let grants = DownloadGrants::new();
        let now = Utc::now();

        let mut protected = new_share();
        protected.max_accesses = Some(1);
        protected.password_hash =
            Some(crate::handlers::auth::hash_password("open sesame").expect("hash"));
        let (share, token) = create_share(&pool, protected, now).await.expect("create");

        // no password at all
        let access = authorize_content_access(&pool, &grants, &plain(&token), now)
            .await
            .expect("authorize");
        assert!(
            matches!(access, ShareAccess::PasswordRequired),
            "{access:?}"
        );

        // wrong password, several times
        for guess in ["", "opensesame", "open sesame "] {
            let access = authorize_content_access(
                &pool,
                &grants,
                &AccessRequest {
                    token: token.expose(),
                    password: Some(guess),
                    range: None,
                    client_key: "203.0.113.7|curl",
                },
                now,
            )
            .await
            .expect("authorize");
            assert!(
                matches!(access, ShareAccess::PasswordRequired),
                "{access:?}"
            );
        }

        assert_eq!(
            stored_count(&pool, &share.id).await,
            0,
            "guessing at the password burned the owner's accesses"
        );

        // the right one still works, exactly once
        let right = AccessRequest {
            token: token.expose(),
            password: Some("open sesame"),
            range: None,
            client_key: "203.0.113.7|curl",
        };
        assert!(granted(
            &authorize_content_access(&pool, &grants, &right, now)
                .await
                .expect("authorize")
        ));
        let again = authorize_content_access(&pool, &grants, &right, now)
            .await
            .expect("authorize");
        assert!(!granted(&again), "{again:?}");
        assert_eq!(stored_count(&pool, &share.id).await, 1);
    }

    /// Time limit and access limit are separate gates; `None` means unlimited
    /// on each of them independently.
    #[tokio::test]
    async fn expiry_and_limit_are_independent() {
        let (pool, _dir) = temp_pool().await;
        let grants = DownloadGrants::new();
        let now = Utc::now();

        // expires, but unlimited accesses
        let mut timed = new_share();
        timed.expires_at = Some(now + Duration::hours(1));
        let (timed_share, timed_token) = create_share(&pool, timed, now).await.expect("create");

        for expected in 1..=5 {
            let access = authorize_content_access(&pool, &grants, &plain(&timed_token), now)
                .await
                .expect("authorize");
            match access {
                ShareAccess::Granted(s) => assert_eq!(s.access_count, expected),
                other => panic!("an unlimited link stopped granting: {other:?}"),
            }
        }

        let after_expiry = now + Duration::hours(2);
        let access = authorize_content_access(&pool, &grants, &plain(&timed_token), after_expiry)
            .await
            .expect("authorize");
        assert!(!granted(&access), "an expired link served: {access:?}");
        assert_eq!(stored_count(&pool, &timed_share.id).await, 5);

        // limited, but never expires
        let mut counted = new_share();
        counted.max_accesses = Some(1);
        let (_, counted_token) = create_share(&pool, counted, now).await.expect("create");

        let far_future = now + Duration::days(3650);
        assert!(
            granted(
                &authorize_content_access(&pool, &grants, &plain(&counted_token), far_future)
                    .await
                    .expect("authorize")
            ),
            "a link without an expiry must still work in ten years"
        );
        assert!(!granted(
            &authorize_content_access(&pool, &grants, &plain(&counted_token), far_future)
                .await
                .expect("authorize")
        ));
    }

    /// The anti-oracle criterion: every kind of failure gives the same answer.
    #[tokio::test]
    async fn every_denial_looks_the_same() {
        let (pool, _dir) = temp_pool().await;
        let grants = DownloadGrants::new();
        let now = Utc::now();

        // exhausted
        let mut exhausted = new_share();
        exhausted.max_accesses = Some(1);
        let (_, exhausted_token) = create_share(&pool, exhausted, now).await.expect("create");
        assert!(granted(
            &authorize_content_access(&pool, &grants, &plain(&exhausted_token), now)
                .await
                .expect("authorize")
        ));

        // expired (created valid, asked for later)
        let mut timed = new_share();
        timed.expires_at = Some(now + Duration::minutes(5));
        let (_, expired_token) = create_share(&pool, timed, now).await.expect("create");

        // revoked
        let (revoked_share, revoked_token) =
            create_share(&pool, new_share(), now).await.expect("create");
        assert!(database::revoke_share(&pool, &revoked_share.id, "u1")
            .await
            .expect("revoke"));

        // owner disabled
        let (_, orphan_token) = create_share(&pool, new_share(), now).await.expect("create");

        // never existed, and outright junk
        let unknown = generate_share_token().expect("generate");

        let later = now + Duration::hours(1);
        crate::database::set_user_active(&pool, "u1", false)
            .await
            .expect("disable owner");

        let cases: Vec<(&str, String)> = vec![
            ("exhausted", exhausted_token.expose().to_string()),
            ("expired", expired_token.expose().to_string()),
            ("revoked", revoked_token.expose().to_string()),
            ("owner disabled", orphan_token.expose().to_string()),
            ("unknown", unknown.expose().to_string()),
            ("malformed", "not-a-token".to_string()),
            ("empty", String::new()),
            ("traversal", "../".repeat(21)),
        ];

        for (label, raw) in cases {
            let request = AccessRequest {
                token: &raw,
                password: None,
                range: None,
                client_key: "203.0.113.7|curl",
            };
            let access = authorize_content_access(&pool, &grants, &request, later)
                .await
                .expect("authorize");
            assert!(
                matches!(access, ShareAccess::Gone),
                "{label} must be indistinguishable from a token that never existed, got {access:?}"
            );
            // and `peek_share` gives nothing away either
            assert!(
                peek_share(&pool, &raw, later)
                    .await
                    .expect("peek")
                    .is_none(),
                "{label} was visible to the landing page"
            );
        }
    }

    /// Looking at the landing page is not an access.
    #[tokio::test]
    async fn peeking_never_counts() {
        let (pool, _dir) = temp_pool().await;
        let now = Utc::now();

        let mut limited = new_share();
        limited.max_accesses = Some(1);
        let (share, token) = create_share(&pool, limited, now).await.expect("create");

        for _ in 0..10 {
            assert!(peek_share(&pool, token.expose(), now)
                .await
                .expect("peek")
                .is_some());
        }
        assert_eq!(
            stored_count(&pool, &share.id).await,
            0,
            "reloading the landing page consumed the link"
        );
    }

    /// The grant table must not grow without bound, and its `Debug` must not
    /// print the token digests it is keyed by.
    #[test]
    fn grants_expire_and_do_not_print_their_keys() {
        let grants = DownloadGrants::with_idle_ttl(Duration::seconds(30));
        let now = Utc::now();

        grants.open("hash-a", "client-1", now);
        grants.open("hash-b", "client-1", now);
        assert_eq!(grants.len(), 2);

        assert!(grants.continues_paid_download("hash-a", "client-1", now + Duration::seconds(29)));
        // wrong client, wrong share
        assert!(!grants.continues_paid_download("hash-a", "client-2", now));
        assert!(!grants.continues_paid_download("hash-c", "client-1", now));

        // idle out
        assert!(!grants.continues_paid_download("hash-b", "client-1", now + Duration::seconds(31)));
        grants.sweep(now + Duration::hours(1));
        assert_eq!(grants.len(), 0);

        grants.open("hash-secret", "client-1", now);
        let rendered = format!("{grants:?}");
        assert!(!rendered.contains("hash-secret"), "{rendered}");
        assert!(!rendered.contains("client-1"), "{rendered}");
    }

    /// `AccessRequest` carries the token and the plaintext password — the one
    /// pair that must never reach a log line.
    #[test]
    fn access_request_debug_redacts_token_and_password() {
        let token = generate_share_token().expect("generate");
        let request = AccessRequest {
            token: token.expose(),
            password: Some("open sesame"),
            range: Some("bytes=0-1023"),
            client_key: "203.0.113.7|curl",
        };

        let rendered = format!("{request:?}");
        assert!(!rendered.contains(token.expose()), "{rendered}");
        assert!(!rendered.contains(&token.expose()[..8]), "{rendered}");
        assert!(!rendered.contains("open sesame"), "{rendered}");
        // the harmless fields stay, or the type would be useless for debugging
        assert!(rendered.contains("bytes=0-1023"), "{rendered}");
    }

    /// `NewShare` carries the same Argon2id PHC string `Share` redacts, and it
    /// is the value an offline attack works on. The derived `Debug` printed it
    /// in full; this is the regression guard for the next field somebody adds.
    #[test]
    fn new_share_debug_redacts_the_password_hash() {
        let phc = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$0000000000000000000000000000000000000000000";
        let mut share = new_share();
        share.password_hash = Some(phc.to_string());

        let rendered = format!("{share:?}");
        assert!(!rendered.contains(phc), "{rendered}");
        assert!(!rendered.contains("argon2id"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // what identifies the share stays readable
        assert!(
            rendered.contains("/data/home/alice/report.pdf"),
            "{rendered}"
        );
    }

    /// A redaction only holds if it survives being nested — `tracing` prints
    /// whole structures, not single fields.
    #[test]
    fn nested_new_share_debug_stays_redacted() {
        let phc = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$0000000000000000000000000000000000000000000";
        let mut share = new_share();
        share.password_hash = Some(phc.to_string());

        assert!(!format!("{:?}", Some(&share)).contains(phc));
        assert!(!format!("{:?}", vec![share]).contains(phc));
    }
}
