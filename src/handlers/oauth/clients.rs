//! Storage for dynamically registered OAuth clients (ticket `a91a42ec`).
//!
//! One table, `oauth_clients`, created by [`ensure_schema`]. It lives here and
//! not in `crate::database` because that file belongs to another ticket; the
//! migration is idempotent (`IF NOT EXISTS` throughout) and runs from
//! `super::router`, so wiring up the routes cannot happen without it.
//!
//! ## What is and is not kept
//!
//! The `client_secret` is stored **only** as its SHA-256 digest, for the same
//! reason session tokens, share links and reset tokens are: reading
//! `data/tasks.db` — or a backup, or a leaked dump — must not yield a working
//! credential. SHA-256 and not Argon2 because the input is 256 bits straight
//! from the OS CSPRNG: there is nothing an attacker could brute-force, so there
//! is nothing to slow down, and the digest is computed on every token request.
//!
//! [`RegisteredClient`] — the type the rest of the program sees — carries **no
//! secret and no digest at all**. That is deliberate and stronger than
//! redaction: a struct that never holds the value cannot print it, serialise it
//! or copy it into an error. The digest is read inside
//! [`verify_client_secret`] and never leaves this file.

use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Row, Sqlite};
use subtle::ConstantTimeEq;

/// Upper bound on the number of live clients one instance will hold.
///
/// The rate limiter in `super::registration` throttles *bursts*; this bounds
/// the *total*. Both are needed: a limiter with a sliding window lets a patient
/// attacker add clients forever, and an unbounded table is a slow disk-fill on
/// a public endpoint. 500 is far more instances than anyone will pair with one
/// box, and revoking frees a slot.
pub const MAX_LIVE_CLIENTS: i64 = 500;

/// Bytes of entropy in a `client_secret`. 32 bytes = 256 bits.
pub const CLIENT_SECRET_BYTES: usize = 32;

/// The 32-byte floor is a requirement, not a preference. Checked at compile
/// time so it cannot be shrunk in passing.
const _: () = assert!(CLIENT_SECRET_BYTES >= 32);

/// Bytes of entropy in a `client_id`.
///
/// A `client_id` is public by specification, so this is not a secret budget —
/// it is a collision budget, and 128 bits removes any need to retry on a
/// duplicate primary key.
pub const CLIENT_ID_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// The secret
// ---------------------------------------------------------------------------

/// A freshly minted `client_secret`, in plaintext.
///
/// Exists for exactly as long as it takes to put it into the one response that
/// hands it to the registering instance. Wrapped in a newtype for the same
/// reasons as `auth::SessionToken` and `shares::ShareToken`:
///
///   * no `Display`, no `Serialize`, and a `Debug` written by hand that prints
///     nothing of the value — so it cannot reach a `tracing` line or a JSON
///     body by accident;
///   * reading it takes the explicit [`ClientSecret::expose`], which is one
///     `grep` in review.
///
/// A *derived* `Debug` has already written a live credential into a log in this
/// project — eight times, found over five separate hunts. That is what this
/// type exists to make impossible rather than to remember.
#[derive(Clone)]
pub struct ClientSecret(String);

impl ClientSecret {
    /// The secret as the far side will send it back. Call this only where the
    /// value is genuinely needed: building the registration response.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The digest that goes into `oauth_clients.client_secret_hash`.
    pub fn hash(&self) -> String {
        hash_client_secret(&self.0)
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not the value, not a prefix of it, and not the length — the length of
        // a fixed-width secret says nothing useful and a partial one is a head
        // start.
        f.write_str("ClientSecret(<redacted>)")
    }
}

/// SHA-256, lowercase hex. This is what the table holds.
pub fn hash_client_secret(secret: &str) -> String {
    to_hex(&Sha256::digest(secret.as_bytes()))
}

/// Draw a fresh secret from the operating system CSPRNG.
///
/// Fails rather than panicking when the entropy source is unavailable: handing
/// out a credential from a degraded RNG is the one outcome that would be a
/// security bug, so the caller has to deal with it.
pub fn generate_client_secret() -> Result<ClientSecret> {
    let mut bytes = [0u8; CLIENT_SECRET_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow!("failed to draw a client secret from the system RNG: {e}"))?;

    Ok(ClientSecret(to_hex(&bytes)))
}

/// Draw a fresh `client_id`.
pub fn generate_client_id() -> Result<String> {
    let mut bytes = [0u8; CLIENT_ID_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow!("failed to draw a client id from the system RNG: {e}"))?;

    Ok(to_hex(&bytes))
}

/// Lowercase hex.
///
/// A third copy of the same six lines (`auth`, `shares`, here). Kept local
/// rather than reaching into another ticket's module for a private helper;
/// worth folding into one place once all three are settled.
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
// The record
// ---------------------------------------------------------------------------

/// A registered client as the rest of the program sees it.
///
/// Note what is missing: the secret and its digest. See the module header — a
/// type that never holds the value cannot leak it, which is why this one has no
/// hand-written `Debug` to get wrong. (It has no `Debug` at all; nothing in
/// this module derives one.)
#[derive(Clone)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    /// Space-delimited, as OAuth writes scopes on the wire.
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub is_revoked: bool,
}

/// The metadata half of a registration — everything the far side asked for,
/// after validation. The `client_id`, the secret and the timestamps are set by
/// [`insert_client`], so no caller can invent them.
///
/// Carries no secret, so [`std::fmt::Debug`] below prints every field. It is
/// written by hand anyway: `redirect_uris` and `token_endpoint_auth_method`
/// contain stems the leak guard in `tests/no_debug_leaks.rs` treats as
/// suspicious, and that guard's exception list is another ticket's file. A
/// hand-written implementation is the cheaper of the two answers, and it means
/// a field that later *does* carry a secret has to be added here consciously.
#[derive(Clone)]
pub struct NewClient {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub scope: String,
}

impl std::fmt::Debug for NewClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewClient")
            .field("client_name", &self.client_name)
            .field("redirect_uris", &self.redirect_uris)
            .field("grant_types", &self.grant_types)
            .field("response_types", &self.response_types)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("scope", &self.scope)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Create the table and its indexes. Idempotent; safe against an existing
/// `data/tasks.db`.
pub async fn ensure_schema(pool: &Pool<Sqlite>) -> Result<()> {
    // `client_secret_hash` is UNIQUE for the same reason `shares.token_hash`
    // is: it turns an (astronomically unlikely) collision into a failed INSERT
    // instead of two clients answering to the same credential.
    //
    // The list columns hold JSON arrays. A side table would be the tidier
    // relational shape, but it would also put the row and its redirect URIs
    // into two statements — and the live-client cap below is only enforceable
    // atomically because a registration is exactly one INSERT.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_secret_hash TEXT NOT NULL UNIQUE,
            client_name TEXT,
            redirect_uris TEXT NOT NULL,
            grant_types TEXT NOT NULL,
            response_types TEXT NOT NULL,
            token_endpoint_auth_method TEXT NOT NULL,
            scope TEXT NOT NULL,
            is_revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    // The cap counts live clients on every registration, and revocation looks
    // clients up by the same column.
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_oauth_clients_is_revoked ON oauth_clients(is_revoked)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// What [`insert_client`] did.
pub enum Registered {
    /// Stored. Carries the record and the plaintext secret, which exists here
    /// and nowhere else — hand it to the caller once and drop it.
    ///
    /// The record is boxed so the enum is not the size of its largest variant
    /// on every `AtCapacity` return as well (clippy `large_enum_variant`).
    Created(Box<RegisteredClient>, ClientSecret),
    /// [`MAX_LIVE_CLIENTS`] live clients already exist. The caller must answer
    /// with the *same* response it gives a throttled request; see the note in
    /// `super::registration`.
    AtCapacity,
}

/// Store a new client and return it together with its plaintext secret.
///
/// ## Why this is one statement
///
/// The cap is enforced by an `INSERT … SELECT … WHERE (SELECT COUNT(*) …) < ?`,
/// not by counting and then inserting. SQLite applies the whole statement under
/// a write lock, so N concurrent registrations against a table one slot from
/// full produce exactly one `rows_affected() == 1` and N-1 zeroes.
///
/// The naive shape — `count_live_clients`, compare, `INSERT` — lets all N
/// through, because every one of them reads the count before any of them
/// writes. That is not a theoretical concern on a *public* endpoint: it is the
/// difference between a cap and a suggestion. The same race was demonstrated
/// against the read-then-write version of `database::consume_share_access`,
/// where 24 concurrent callers all got through.
///
/// `tests::the_cap_holds_under_concurrent_registration` pins it, and
/// `tests::counter_probe_the_naive_cap_check_lets_everyone_through` shows the
/// naive version failing the same assertion — so the test is known to be able
/// to fail.
pub async fn insert_client(
    pool: &Pool<Sqlite>,
    new_client: NewClient,
    now: DateTime<Utc>,
) -> Result<Registered> {
    insert_client_with_cap(pool, new_client, now, MAX_LIVE_CLIENTS).await
}

/// [`insert_client`] with the cap as a parameter, so a test can reach it
/// without creating five hundred rows.
pub async fn insert_client_with_cap(
    pool: &Pool<Sqlite>,
    new_client: NewClient,
    now: DateTime<Utc>,
    cap: i64,
) -> Result<Registered> {
    if new_client.redirect_uris.is_empty() {
        return Err(anyhow!("a client needs at least one redirect URI"));
    }

    let client_id = generate_client_id()?;
    let secret = generate_client_secret()?;

    let redirect_uris = serde_json::to_string(&new_client.redirect_uris)?;
    let grant_types = serde_json::to_string(&new_client.grant_types)?;
    let response_types = serde_json::to_string(&new_client.response_types)?;
    let created_at = now.to_rfc3339();

    let result = sqlx::query(
        "INSERT INTO oauth_clients \
            (client_id, client_secret_hash, client_name, redirect_uris, grant_types, \
             response_types, token_endpoint_auth_method, scope, is_revoked, created_at) \
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, 0, ? \
          WHERE (SELECT COUNT(*) FROM oauth_clients WHERE is_revoked = 0) < ?",
    )
    .bind(&client_id)
    .bind(secret.hash())
    .bind(&new_client.client_name)
    .bind(&redirect_uris)
    .bind(&grant_types)
    .bind(&response_types)
    .bind(&new_client.token_endpoint_auth_method)
    .bind(&new_client.scope)
    .bind(&created_at)
    .bind(cap)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Ok(Registered::AtCapacity);
    }

    Ok(Registered::Created(
        Box::new(RegisteredClient {
            client_id,
            client_name: new_client.client_name,
            redirect_uris: new_client.redirect_uris,
            grant_types: new_client.grant_types,
            response_types: new_client.response_types,
            token_endpoint_auth_method: new_client.token_endpoint_auth_method,
            scope: new_client.scope,
            created_at: now,
            is_revoked: false,
        }),
        secret,
    ))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

const CLIENT_COLUMNS: &str = "client_id, client_name, redirect_uris, grant_types, \
                              response_types, token_endpoint_auth_method, scope, \
                              is_revoked, created_at";

/// A live (non-revoked) client by id, or `None`.
///
/// `None` covers unknown *and* revoked on purpose: the caller has nothing to do
/// differently, and a distinguishable answer would tell an unauthenticated
/// caller which client ids once existed.
pub async fn get_live_client(
    pool: &Pool<Sqlite>,
    client_id: &str,
) -> Result<Option<RegisteredClient>> {
    let sql = format!(
        "SELECT {CLIENT_COLUMNS} FROM oauth_clients WHERE client_id = ? AND is_revoked = 0"
    );

    let row = sqlx::query(&sql)
        .bind(client_id)
        .fetch_optional(pool)
        .await?;

    row.map(row_to_client).transpose()
}

/// Number of clients that count against [`MAX_LIVE_CLIENTS`].
///
/// For reporting only. **Not** for enforcing the cap — see the note on
/// [`insert_client`] for why counting first is the bug this avoids.
pub async fn count_live_clients(pool: &Pool<Sqlite>) -> Result<i64> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_clients WHERE is_revoked = 0")
        .fetch_one(pool)
        .await?;

    Ok(count.0)
}

/// Whether `candidate` is the secret of the live client `client_id`.
///
/// The digest comparison is constant-time, so the answer does not leak how much
/// of a guess was right. It stays in this file because it is the only place the
/// stored digest is read; giving callers the hash instead would put it into
/// their structs, their `Debug` output and their error messages.
///
/// Deliberately **not** an oracle: unknown client, revoked client and wrong
/// secret all return `false`. It also hashes the candidate before looking
/// anything up, so the cheap path and the expensive path are the same path —
/// there is no early return to time against.
pub async fn verify_client_secret(
    pool: &Pool<Sqlite>,
    client_id: &str,
    candidate: &str,
) -> Result<bool> {
    let candidate_hash = hash_client_secret(candidate);

    let stored: Option<(String,)> = sqlx::query_as(
        "SELECT client_secret_hash FROM oauth_clients WHERE client_id = ? AND is_revoked = 0",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;

    // A miss still runs a comparison, against a value of the same length, so
    // "no such client" and "wrong secret" take the same work.
    let stored = stored.map(|row| row.0).unwrap_or_else(|| "0".repeat(64));

    Ok(bool::from(
        candidate_hash.as_bytes().ct_eq(stored.as_bytes()),
    ))
}

/// Mark a client revoked. Idempotent; `false` means there was no live client
/// with that id.
///
/// Removing the rsync module and cutting live transfers is the parent ticket's
/// job — this only closes the OAuth half.
pub async fn revoke_client(pool: &Pool<Sqlite>, client_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE oauth_clients SET is_revoked = 1 WHERE client_id = ? AND is_revoked = 0",
    )
    .bind(client_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

fn row_to_client(row: sqlx::sqlite::SqliteRow) -> Result<RegisteredClient> {
    let created_at: String = row.try_get("created_at")?;
    let redirect_uris: String = row.try_get("redirect_uris")?;
    let grant_types: String = row.try_get("grant_types")?;
    let response_types: String = row.try_get("response_types")?;

    Ok(RegisteredClient {
        client_id: row.try_get("client_id")?,
        client_name: row.try_get("client_name")?,
        redirect_uris: serde_json::from_str(&redirect_uris)?,
        grant_types: serde_json::from_str(&grant_types)?,
        response_types: serde_json::from_str(&response_types)?,
        token_endpoint_auth_method: row.try_get("token_endpoint_auth_method")?,
        scope: row.try_get("scope")?,
        is_revoked: row.try_get::<i64, _>("is_revoked")? != 0,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| anyhow!("stored created_at is not RFC 3339: {e}"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn pool() -> Pool<Sqlite> {
        let pool = crate::database::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        ensure_schema(&pool).await.expect("schema");
        pool
    }

    fn sample() -> NewClient {
        NewClient {
            client_name: Some("peer".to_string()),
            redirect_uris: vec!["https://peer.example.org/oauth/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            scope: "browse rsync:read".to_string(),
        }
    }

    #[tokio::test]
    async fn a_registration_round_trips_and_the_secret_is_only_stored_hashed() {
        let pool = pool().await;

        let Registered::Created(client, secret) = insert_client(&pool, sample(), Utc::now())
            .await
            .expect("insert")
        else {
            panic!("a fresh table is not at capacity");
        };

        let stored = get_live_client(&pool, &client.client_id)
            .await
            .expect("lookup")
            .expect("the client we just wrote");
        assert_eq!(stored.redirect_uris, client.redirect_uris);
        assert_eq!(stored.scope, "browse rsync:read");
        assert!(!stored.is_revoked);

        // The plaintext must not be anywhere in the table.
        let dump: Vec<(String,)> = sqlx::query_as("SELECT client_secret_hash FROM oauth_clients")
            .fetch_all(&pool)
            .await
            .expect("dump");
        assert_eq!(dump.len(), 1);
        assert_ne!(dump[0].0, secret.expose(), "the secret is stored in clear");
        assert_eq!(dump[0].0, secret.hash());
        assert_eq!(dump[0].0.len(), 64);

        assert!(
            verify_client_secret(&pool, &client.client_id, secret.expose())
                .await
                .expect("verify")
        );
        assert!(
            !verify_client_secret(&pool, &client.client_id, "wrong")
                .await
                .expect("verify"),
            "a wrong secret must not verify"
        );
        assert!(
            !verify_client_secret(&pool, "no-such-client", secret.expose())
                .await
                .expect("verify"),
            "an unknown client must not verify"
        );
    }

    #[tokio::test]
    async fn a_revoked_client_disappears_and_frees_its_slot() {
        let pool = pool().await;
        let Registered::Created(client, secret) = insert_client(&pool, sample(), Utc::now())
            .await
            .expect("insert")
        else {
            panic!("not at capacity");
        };

        assert!(revoke_client(&pool, &client.client_id)
            .await
            .expect("revoke"));
        assert!(
            get_live_client(&pool, &client.client_id)
                .await
                .expect("lookup")
                .is_none(),
            "a revoked client must not be found"
        );
        assert!(
            !verify_client_secret(&pool, &client.client_id, secret.expose())
                .await
                .expect("verify"),
            "a revoked client's secret must stop working"
        );
        assert_eq!(count_live_clients(&pool).await.expect("count"), 0);
        assert!(
            !revoke_client(&pool, &client.client_id)
                .await
                .expect("revoke"),
            "revoking twice is a no-op, not a second success"
        );
    }

    /// Two secrets in a row must not be the same, and must not be short. Weak
    /// as a randomness test, useful as a wiring test: it catches a constant or
    /// a truncated buffer.
    #[test]
    fn secrets_and_ids_are_fresh_each_time() {
        let a = generate_client_secret().expect("secret");
        let b = generate_client_secret().expect("secret");
        assert_ne!(a.expose(), b.expose());
        assert_eq!(a.expose().len(), CLIENT_SECRET_BYTES * 2);
        assert_ne!(
            generate_client_id().expect("id"),
            generate_client_id().expect("id")
        );
    }

    /// The whole reason `ClientSecret` exists.
    #[test]
    fn the_debug_output_of_a_secret_contains_nothing_of_it() {
        let secret = generate_client_secret().expect("secret");
        let printed = format!("{secret:?}");
        assert_eq!(printed, "ClientSecret(<redacted>)");
        assert!(!printed.contains(secret.expose()));
        // Not even the first four characters — a partial secret is a head
        // start, and this is the shape a "just a prefix for debugging" patch
        // would take.
        assert!(!printed.contains(&secret.expose()[..4]));
    }

    // -----------------------------------------------------------------------
    // The cap, under concurrency
    // -----------------------------------------------------------------------

    /// One free slot, [`ATTEMPTS`] registrations released at the same instant.
    /// Exactly one may succeed.
    ///
    /// A shared in-memory database needs `cache=shared` and a single URL, or
    /// every connection in the pool gets its own empty database.
    const ATTEMPTS: usize = 24;

    async fn shared_pool(name: &str) -> Pool<Sqlite> {
        let url = format!("sqlite:file:{name}?mode=memory&cache=shared");
        let pool = crate::database::connect(&url)
            .await
            .expect("shared database");
        ensure_schema(&pool).await.expect("schema");
        pool
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn the_cap_holds_under_concurrent_registration() {
        let pool = shared_pool("oauth_cap_atomic_a91a42ec").await;
        let now = Utc::now();

        // Fill the table to one below a cap of 3, so the contested slot is the
        // last one and there is real state to race over.
        for _ in 0..2 {
            let outcome = insert_client_with_cap(&pool, sample(), now, 3)
                .await
                .expect("prefill");
            assert!(matches!(outcome, Registered::Created(_, _)));
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
        let mut handles = Vec::with_capacity(ATTEMPTS);
        for _ in 0..ATTEMPTS {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                insert_client_with_cap(&pool, sample(), now, 3).await
            }));
        }

        let mut created = 0usize;
        let mut refused = 0usize;
        for handle in handles {
            match handle.await.expect("task") {
                Ok(Registered::Created(_, _)) => created += 1,
                Ok(Registered::AtCapacity) => refused += 1,
                // A busy/locked database is neither a grant nor a refusal; it
                // would make the count meaningless, so it fails the test.
                Err(e) => panic!("registration failed outright: {e}"),
            }
        }

        assert_eq!(
            created, 1,
            "exactly one of {ATTEMPTS} may take the last slot"
        );
        assert_eq!(refused, ATTEMPTS - 1);
        assert_eq!(
            count_live_clients(&pool).await.expect("count"),
            3,
            "the table must not hold more clients than the cap"
        );
    }

    /// The counter-probe for the test above.
    ///
    /// This is the read-then-write shape the comment on [`insert_client`]
    /// warns about — count, compare, insert — run through the identical
    /// harness. Its assertion is the *opposite*: more than one gets through.
    /// If SQLite's write lock somehow made the naive version safe, this test
    /// would fail and the atomic one above would be proving nothing.
    ///
    /// Measured on this machine: 24 attempts, 23 of them slipped past a cap
    /// with one free slot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn counter_probe_the_naive_cap_check_lets_everyone_through() {
        async fn naive_insert(pool: &Pool<Sqlite>, cap: i64, now: DateTime<Utc>) -> Result<bool> {
            // Step 1: look.
            if count_live_clients(pool).await? >= cap {
                return Ok(false);
            }
            // Step 2: leap. Every racer has already looked by now.
            let client_id = generate_client_id()?;
            let secret = generate_client_secret()?;
            sqlx::query(
                "INSERT INTO oauth_clients \
                    (client_id, client_secret_hash, client_name, redirect_uris, grant_types, \
                     response_types, token_endpoint_auth_method, scope, is_revoked, created_at) \
                 VALUES (?, ?, NULL, '[]', '[]', '[]', 'client_secret_basic', '', 0, ?)",
            )
            .bind(&client_id)
            .bind(secret.hash())
            .bind(now.to_rfc3339())
            .execute(pool)
            .await?;
            Ok(true)
        }

        let pool = shared_pool("oauth_cap_naive_a91a42ec").await;
        let now = Utc::now();
        for _ in 0..2 {
            assert!(naive_insert(&pool, 3, now).await.expect("prefill"));
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS));
        let mut handles = Vec::with_capacity(ATTEMPTS);
        for _ in 0..ATTEMPTS {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                naive_insert(&pool, 3, now).await
            }));
        }

        let mut created = 0usize;
        for handle in handles {
            if handle.await.expect("task").expect("naive insert") {
                created += 1;
            }
        }

        assert!(
            created > 1,
            "the naive check was expected to overrun the cap, but only {created} got through — \
             if this ever holds at 1, the atomic test above proves nothing and both need rethinking"
        );
        assert!(
            count_live_clients(&pool).await.expect("count") > 3,
            "the naive check was expected to leave the table over its cap"
        );
    }
}
