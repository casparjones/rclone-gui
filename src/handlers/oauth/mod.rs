//! OAuth 2.1 authorization server — the two entry points a *foreign* instance
//! needs before it can do anything else (ticket `a91a42ec`).
//!
//! The user's wish behind this epic, in his own words: "ich möchte etwas
//! stabiles eigenes wo ich nur rclone URL angeben muss und dann kann ich mich
//! über oauth dort anmelden". Two things have to exist for a base URL to be
//! enough:
//!
//!   * **Discovery** (RFC 8414) — `GET /.well-known/oauth-authorization-server`
//!     turns one URL into the full set of endpoints, so nothing has to be typed
//!     twice or guessed.
//!   * **Dynamic Client Registration** (RFC 7591) — `POST /oauth/register`
//!     lets the far side obtain a `client_id`/`client_secret` pair on its own.
//!     Without it, pairing two instances means an operator hand-editing a file
//!     on each of them, which is exactly the `data/peers/<name>.json` stopgap
//!     this epic replaces.
//!
//! **What this module deliberately does not contain:** `/oauth/authorize`,
//! `/oauth/token` and `/oauth/revoke`. Those are tickets `0fa3d2b0` and the
//! rsync-credential half of the parent `8b1f4477`. Discovery *advertises* them,
//! because a metadata document without a `token_endpoint` is not a valid one
//! (RFC 8414 §2 makes it mandatory) — a client that follows the advertisement
//! today gets a 404 from the router, which is the honest answer while the
//! endpoint is unbuilt. Nothing here invents their behaviour.
//!
//! ## Security shape
//!
//! Both endpoints are **public** — that is their whole point — so they carry
//! their own defences instead of the session guard's:
//!
//!   * the registration body is parsed only *after* the rate limiter has
//!     spoken. `Bytes` sits in the handler signature rather than `Json<T>`
//!     because axum runs extractors in argument order: with `Json<T>` first, a
//!     throttled caller would get 422 for a malformed body and 429 for a
//!     well-formed one, and could read the accepted field structure out of the
//!     difference. This exact mistake was found elsewhere in this tree.
//!   * a `client_secret` is stored as its SHA-256 digest only. Reading
//!     `data/tasks.db` does not yield a usable credential — same rule as
//!     sessions, share links and reset tokens.
//!   * the plaintext secret exists in exactly one place, the response that
//!     creates it, and lives in [`clients::ClientSecret`], which has a
//!     hand-written redacting `Debug`, no `Display` and no `Serialize`.
//!   * **no `derive(Debug)` on anything that touches a credential or an
//!     attacker-supplied body.** There is exactly one derived `Debug` in the
//!     module — `registration::Invalid`, whose two fields are `&'static str`
//!     chosen in this file — and it says so at the declaration. Everything
//!     else either has a hand-written implementation
//!     (`clients::ClientSecret`, `clients::NewClient`) or none at all.
//!
//!     Not relying on the guard in `tests/no_debug_leaks.rs` is deliberate: it
//!     matches on names, and half the field names here (`redirect_uris`,
//!     `token_endpoint_auth_method`) are innocent words that happen to contain
//!     a suspicious stem, while a field it *would* wave through could still
//!     carry a token. Its exception list also lives in a file this ticket does
//!     not own, so a trip would have been unfixable from here.
//!
//! ## Nothing here has a caller yet
//!
//! `src/main.rs` belongs to another ticket, so the routes are not registered —
//! see [`router`] and the ticket comment for the two lines that do it. Until
//! then every item in this module tree is unreachable from `main`, hence the
//! module-wide `allow(dead_code)`. **Take it out with the same commit that
//! registers the routes**, or it will start hiding real dead code. The same
//! shape and the same reason as `handlers::shares` when it was written.
#![allow(dead_code)]

pub mod clients;
pub mod metadata;
pub mod registration;

use std::sync::Arc;

use anyhow::Result;
use axum::routing::{get, post};
use axum::Router;
use sqlx::{Pool, Sqlite};

/// Path of the RFC 8414 metadata document.
///
/// Fixed by the specification: the well-known suffix is appended to the issuer,
/// and our issuer has no path component, so this is the whole path. It must be
/// reachable without a session — see the note on [`router`].
pub const DISCOVERY_PATH: &str = "/.well-known/oauth-authorization-server";

/// Path of the RFC 7591 registration endpoint.
pub const REGISTRATION_PATH: &str = "/oauth/register";

/// Path of the authorization endpoint. Built by ticket `0fa3d2b0`; advertised
/// here because the metadata document requires it.
pub const AUTHORIZATION_PATH: &str = "/oauth/authorize";

/// Path of the token endpoint. Built by ticket `0fa3d2b0`.
pub const TOKEN_PATH: &str = "/oauth/token";

/// Path of the revocation endpoint (RFC 7009). Built with the credential half
/// of the parent ticket.
pub const REVOCATION_PATH: &str = "/oauth/revoke";

/// Everything the two handlers share. Cloned per request by axum, so both
/// fields are cheap to clone.
///
/// The limiter sits behind an `Arc` for the same reason `AuthState`'s does: one
/// limiter for the whole process, or it would reset on every request and limit
/// nothing.
#[derive(Clone)]
pub struct OAuthState {
    pub pool: Pool<Sqlite>,
    pub limiter: Arc<registration::RegistrationRateLimiter>,
}

impl OAuthState {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self {
            pool,
            limiter: Arc::new(registration::RegistrationRateLimiter::default()),
        }
    }
}

/// The OAuth routes, ready to `.merge()` into the main router.
///
/// `async` and fallible on purpose: it creates its own table before handing
/// back a router that needs it. Doing it here rather than asking `main.rs` to
/// remember a separate `ensure_schema` call makes it impossible to wire up the
/// routes without the storage they use.
///
/// **Both paths must be added to `handlers::auth_web::is_public_path`.** Merging
/// this router is not enough: the session guard wraps the finished router and
/// refuses anything not on its allowlist, so without that edit discovery and
/// registration answer 401 — which is a failing state that looks like a working
/// one from the outside (a 401 is a valid HTTP response, and a client following
/// a base URL cannot tell it from "not an OAuth server").
pub async fn router(pool: Pool<Sqlite>) -> Result<Router> {
    clients::ensure_schema(&pool).await?;

    Ok(Router::new()
        .route(DISCOVERY_PATH, get(metadata::discovery))
        .route(REGISTRATION_PATH, post(registration::register))
        .with_state(OAuthState::new(pool)))
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

/// Environment variable that fixes the externally reachable base URL.
///
/// Set it. The fallback below works, but it trusts a request header for a value
/// the specification wants pinned.
pub const PUBLIC_BASE_URL_ENV: &str = "RCLONE_GUI_PUBLIC_BASE_URL";

/// The issuer identifier, and the prefix of every advertised endpoint.
///
/// Two sources, in order:
///
///   1. `RCLONE_GUI_PUBLIC_BASE_URL`, validated and with any trailing slash
///      removed. This is the correct way to run it: RFC 8414 §3.3 has the
///      client compare the `issuer` in the document against the URL it derived
///      the request from, so the value has to be stable and not vary with who
///      is asking.
///   2. Otherwise the request's `Host` header, with `X-Forwarded-Proto` (or a
///      loopback-shaped host) deciding the scheme.
///
/// The fallback exists because this application is deployed by people, not by a
/// platform, and refusing to serve discovery until an environment variable is
/// set would make the feature invisible rather than safe. Its weakness is
/// stated plainly: `Host` is attacker-controllable, so an unconfigured
/// instance will happily advertise endpoints on somebody else's hostname. What
/// keeps that from being an authorization bug is that it changes only the
/// *advertisement*: a client that follows RFC 8414 §3.3 rejects a document
/// whose `issuer` does not match where it looked, and every security decision
/// this server makes later is taken against the stored `redirect_uris`, never
/// against a header. It is still worth a warning, which [`issuer_from_env`]
/// emits once per process.
///
/// **Not a decision I made alone:** whether an unconfigured instance should
/// serve discovery at all, or answer 503 until the operator names its public
/// URL, is a policy question. The permissive branch is the one that keeps the
/// acceptance criterion ("a second instance registers with nothing but the
/// URL") testable today; flipping it is a one-line change here.
pub fn issuer(host_header: Option<&str>, forwarded_proto: Option<&str>) -> String {
    if let Some(configured) = issuer_from_env() {
        return configured;
    }

    let host = host_header
        .map(str::trim)
        .filter(|h| is_plausible_host(h))
        .unwrap_or("localhost");

    let scheme = match forwarded_proto.map(str::trim) {
        Some("https") => "https",
        Some("http") => "http",
        // No proxy said anything. A loopback or `.local` host is a developer
        // or a LAN box and is almost certainly plain HTTP; anything else is
        // assumed to be reachable over TLS, because advertising `http://` for
        // a public deployment would be the worse mistake of the two.
        _ if is_local_host(host) => "http",
        _ => "https",
    };

    format!("{scheme}://{host}")
}

/// The configured base URL, or `None`.
///
/// Rejects anything that is not a plain absolute `http`/`https` origin: a
/// query, a fragment or embedded credentials in an issuer identifier are
/// forbidden by RFC 8414 §2, and a path would silently break the well-known
/// suffix. A bad value is a startup mistake, so it is warned about loudly
/// rather than quietly half-honoured.
fn issuer_from_env() -> Option<String> {
    let raw = std::env::var(PUBLIC_BASE_URL_ENV).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let trimmed = raw.trim_end_matches('/');
    match validate_issuer(trimmed) {
        Ok(()) => Some(trimmed.to_string()),
        Err(why) => {
            warn_once(&format!(
                "{PUBLIC_BASE_URL_ENV} is set but unusable ({why}); \
                 falling back to the Host header for the OAuth issuer"
            ));
            None
        }
    }
}

/// What an issuer identifier is allowed to look like.
fn validate_issuer(value: &str) -> Result<(), &'static str> {
    let rest = match value.split_once("://") {
        Some(("http", rest)) | Some(("https", rest)) => rest,
        _ => return Err("must start with http:// or https://"),
    };
    if rest.is_empty() {
        return Err("no host");
    }
    if rest.contains('?') || rest.contains('#') {
        return Err("must not carry a query or a fragment");
    }
    if rest.contains('@') {
        return Err("must not carry credentials");
    }
    if rest.contains('/') {
        return Err("must be an origin without a path — the well-known suffix is appended to it");
    }
    if !is_plausible_host(rest) {
        return Err("host contains characters that do not belong in one");
    }
    Ok(())
}

/// A cheap sanity filter on a host value that is about to be pasted into URLs
/// we hand out. Not a parser — its only job is to keep control characters,
/// whitespace and injected path or scheme separators out of the document.
fn is_plausible_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        })
}

/// Whether a host is one this machine talks to itself on, or a LAN name.
fn is_local_host(host: &str) -> bool {
    let bare = host.rsplit_once(':').map_or(host, |(h, _)| h);
    let bare = bare.trim_start_matches('[').trim_end_matches(']');

    bare == "localhost"
        || bare == "::1"
        || bare.starts_with("127.")
        || bare.ends_with(".localhost")
        || bare.ends_with(".local")
}

/// Emit a warning at most once per process, keyed by nothing — the two callers
/// each have exactly one thing to say. Keeps a misconfigured instance from
/// filling the log with the same line on every discovery request.
fn warn_once(message: &str) {
    static SAID: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SAID.set(()).is_ok() {
        tracing::warn!("{message}");
    }
}

/// The `Host` header, as a borrowed string, if it is one at all.
pub fn host_header(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
}

/// The `X-Forwarded-Proto` header's first value, if present.
pub fn forwarded_proto(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `std::env` is process-wide; these tests set the same variable, so they
    /// take a lock rather than racing each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var(PUBLIC_BASE_URL_ENV).ok();
        match value {
            Some(v) => std::env::set_var(PUBLIC_BASE_URL_ENV, v),
            None => std::env::remove_var(PUBLIC_BASE_URL_ENV),
        }
        let out = body();
        match previous {
            Some(v) => std::env::set_var(PUBLIC_BASE_URL_ENV, v),
            None => std::env::remove_var(PUBLIC_BASE_URL_ENV),
        }
        out
    }

    #[test]
    fn the_configured_base_url_wins_over_the_host_header() {
        with_env(Some("https://backup.example.org"), || {
            assert_eq!(
                issuer(Some("attacker.example.com"), Some("http")),
                "https://backup.example.org"
            );
        });
    }

    #[test]
    fn a_trailing_slash_is_removed_so_endpoints_do_not_get_a_double_one() {
        with_env(Some("https://backup.example.org/"), || {
            assert_eq!(issuer(None, None), "https://backup.example.org");
        });
    }

    #[test]
    fn an_unusable_configured_value_falls_back_instead_of_being_half_honoured() {
        for bad in [
            "backup.example.org",               // no scheme
            "https://backup.example.org/oauth", // path
            "https://user:pw@backup.example.org",
            "https://backup.example.org?x=1",
            "https://",
            "ftp://backup.example.org",
        ] {
            with_env(Some(bad), || {
                assert_eq!(
                    issuer(Some("host.example"), Some("https")),
                    "https://host.example",
                    "{bad} must not be used as an issuer"
                );
            });
        }
    }

    #[test]
    fn without_configuration_the_host_header_and_forwarded_proto_decide() {
        with_env(None, || {
            assert_eq!(
                issuer(Some("gui.example.org"), Some("https")),
                "https://gui.example.org"
            );
            assert_eq!(
                issuer(Some("gui.example.org"), Some("http")),
                "http://gui.example.org"
            );
            // Several proxies in a chain: the first value is the client-facing
            // one.
            assert_eq!(
                issuer(Some("gui.example.org"), Some("https, http")),
                "https://gui.example.org"
            );
        });
    }

    #[test]
    fn a_loopback_host_without_a_proxy_header_is_assumed_to_be_plain_http() {
        with_env(None, || {
            assert_eq!(
                issuer(Some("127.0.0.1:8080"), None),
                "http://127.0.0.1:8080"
            );
            assert_eq!(
                issuer(Some("localhost:9000"), None),
                "http://localhost:9000"
            );
            assert_eq!(issuer(Some("[::1]:9000"), None), "http://[::1]:9000");
            assert_eq!(issuer(Some("nas.local"), None), "http://nas.local");
            // Anything else gets https, because advertising http for a public
            // deployment is the worse of the two mistakes.
            assert_eq!(
                issuer(Some("gui.example.org"), None),
                "https://gui.example.org"
            );
        });
    }

    /// A `Host` header is attacker-controllable, and it is pasted straight into
    /// the URLs of the document we hand out. Anything that could end the host
    /// and start a path — or smuggle in a newline — must not survive.
    #[test]
    fn a_junk_host_header_cannot_inject_into_the_advertised_urls() {
        with_env(None, || {
            for junk in [
                "evil.example/../../etc",
                "evil.example/oauth",
                "evil example",
                "evil.example\nX-Injected: 1",
                "user:pw@evil.example",
                "",
                "   ",
            ] {
                let value = issuer(Some(junk), Some("https"));
                assert_eq!(
                    value, "https://localhost",
                    "{junk:?} must be refused, got {value}"
                );
            }
        });
    }

    /// The guard for the test above: if `is_plausible_host` were removed, the
    /// junk *would* reach the document. Shown here so the assertion above is
    /// known to be able to fail.
    #[test]
    fn counter_probe_the_junk_host_filter_is_what_rejects_them() {
        assert!(!is_plausible_host("evil.example/oauth"));
        assert!(!is_plausible_host("evil.example\nX-Injected: 1"));
        assert!(!is_plausible_host("user:pw@evil.example"));
        // ...and a real host still passes, so the filter is not simply "no".
        assert!(is_plausible_host("gui.example.org:8443"));
        assert!(is_plausible_host("[::1]:9000"));
    }
}

/// End-to-end tests through the real router.
///
/// `main.rs` belongs to another ticket, so the routes are not registered in the
/// running server yet. These drive [`router`] directly with `tower`'s
/// `oneshot`, which is the same code path a request takes — real extractors,
/// real status codes, real JSON — and is the closest honest proof of "a second
/// instance registers successfully" that can be given without that file.
///
/// **What it does not prove:** that the session guard lets these two paths
/// through. That needs the `is_public_path` entries listed in the ticket
/// comment, and until they exist a live server answers 401 here. Not tested,
/// stated.
#[cfg(test)]
mod router_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    // `tower::ServiceExt::oneshot` would be tidier, but `tower` is in this
    // tree without its `util` feature and `Cargo.toml` belongs to another
    // ticket. `tower::Service::call` needs no feature and is the same code
    // path; `Router::poll_ready` is unconditionally ready, which is why it is
    // sound to skip here.
    use tower::Service;

    async fn call(app: &Router, request: Request<Body>) -> axum::response::Response {
        let mut app = app.clone();
        app.call(request).await.expect("the router is infallible")
    }

    async fn app() -> Router {
        let pool = crate::database::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        // `router` runs the migration itself; this asserts that.
        router(pool).await.expect("router")
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("JSON body")
    }

    fn post_register(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(REGISTRATION_PATH)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    #[tokio::test]
    async fn discovery_answers_a_document_a_client_can_follow() {
        let response = call(
            &app().await,
            Request::builder()
                .uri(DISCOVERY_PATH)
                .header("host", "gui.example.org")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=3600")
        );

        let doc = body_json(response).await;
        assert_eq!(doc["issuer"], "https://gui.example.org");
        assert_eq!(
            doc["registration_endpoint"],
            "https://gui.example.org/oauth/register"
        );
        assert_eq!(doc["code_challenge_methods_supported"][0], "S256");
    }

    /// The acceptance criterion: a second instance registers with nothing but
    /// the base URL, and the credential it gets back actually works.
    #[tokio::test]
    async fn a_second_instance_registers_and_the_credential_it_gets_back_works() {
        let pool = crate::database::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        let app = router(pool.clone()).await.expect("router");

        let response = call(
            &app,
            post_register(
                r#"{"client_name":"peer-b",
                    "redirect_uris":["https://peer-b.example.org/oauth/callback"],
                    "grant_types":["authorization_code","refresh_token"],
                    "scope":"browse rsync:write"}"#,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = body_json(response).await;

        let client_id = body["client_id"].as_str().expect("client_id");
        let secret = body["client_secret"].as_str().expect("client_secret");
        assert_eq!(client_id.len(), clients::CLIENT_ID_BYTES * 2);
        assert_eq!(secret.len(), clients::CLIENT_SECRET_BYTES * 2);
        assert_eq!(body["client_secret_expires_at"], 0);
        assert!(body["client_id_issued_at"].as_i64().unwrap_or(0) > 0);
        assert_eq!(body["scope"], "browse rsync:write");
        assert_eq!(
            body["redirect_uris"][0],
            "https://peer-b.example.org/oauth/callback"
        );

        // The credential is usable, and it is not what is on disk.
        assert!(
            clients::verify_client_secret(&pool, client_id, secret)
                .await
                .expect("verify"),
            "the secret handed out must authenticate the client"
        );
        let stored: Vec<(String,)> = sqlx::query_as("SELECT client_secret_hash FROM oauth_clients")
            .fetch_all(&pool)
            .await
            .expect("dump");
        assert_eq!(stored.len(), 1);
        assert_ne!(
            stored[0].0, secret,
            "the secret must not be stored in clear"
        );
    }

    #[tokio::test]
    async fn a_bad_redirect_uri_is_refused_with_the_rfc_error_code() {
        let response = call(
            &app().await,
            post_register(r#"{"redirect_uris":["http://peer-b.example.org/cb"]}"#),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(response).await["error"], "invalid_redirect_uri");
    }

    /// Mass registration is bounded, and the bound is reached by the limiter
    /// before the database is touched at all.
    #[tokio::test]
    async fn mass_registration_is_refused_after_the_limit() {
        let state = OAuthState::new(
            crate::database::connect("sqlite::memory:")
                .await
                .expect("in-memory database"),
        );
        clients::ensure_schema(&state.pool).await.expect("schema");
        let app = Router::new()
            .route(
                REGISTRATION_PATH,
                axum::routing::post(registration::register),
            )
            .with_state(state.clone());

        let mut created = 0usize;
        let mut refused = 0usize;
        // One client key, so its own bucket is what bites first.
        for _ in 0..registration::RATE_PER_CLIENT + 5 {
            let request = Request::builder()
                .method("POST")
                .uri(REGISTRATION_PATH)
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.7")
                .body(Body::from(
                    r#"{"redirect_uris":["https://peer-b.example.org/cb"]}"#,
                ))
                .expect("request");
            let response = call(&app, request).await;
            match response.status() {
                StatusCode::CREATED => created += 1,
                StatusCode::TOO_MANY_REQUESTS => {
                    assert!(
                        response
                            .headers()
                            .contains_key(axum::http::header::RETRY_AFTER),
                        "a 429 must say when to come back"
                    );
                    refused += 1;
                }
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(created, registration::RATE_PER_CLIENT);
        assert_eq!(refused, 5);
        assert_eq!(
            clients::count_live_clients(&state.pool)
                .await
                .expect("count"),
            registration::RATE_PER_CLIENT as i64,
            "a refused registration must not have reached the table"
        );
    }

    /// The axum extractor-order trap, as a property of the finished route.
    ///
    /// A throttled caller must get the *same* answer for an empty body, for
    /// junk, and for perfectly valid JSON. If the body were parsed first — the
    /// `Json<T>` signature — the three would be 400, 400 and 429, and the
    /// difference tells an unauthenticated prober which fields are accepted.
    /// That is exactly the bug found on a protected endpoint in this tree.
    #[tokio::test]
    async fn a_throttled_caller_cannot_read_the_field_structure_off_the_status() {
        let state = OAuthState::new(
            crate::database::connect("sqlite::memory:")
                .await
                .expect("in-memory database"),
        );
        clients::ensure_schema(&state.pool).await.expect("schema");
        let app = Router::new()
            .route(
                REGISTRATION_PATH,
                axum::routing::post(registration::register),
            )
            .with_state(state);

        // Burn the caller's bucket.
        for _ in 0..registration::RATE_PER_CLIENT {
            let _ = call(
                &app,
                Request::builder()
                    .method("POST")
                    .uri(REGISTRATION_PATH)
                    .header("x-forwarded-for", "203.0.113.9")
                    .body(Body::from(
                        r#"{"redirect_uris":["https://peer-b.example.org/cb"]}"#,
                    ))
                    .expect("request"),
            )
            .await;
        }

        let mut answers = Vec::new();
        for body in [
            "",
            "not json at all",
            "{}",
            r#"{"redirect_uris":["https://peer-b.example.org/cb"]}"#,
        ] {
            let response = call(
                &app,
                Request::builder()
                    .method("POST")
                    .uri(REGISTRATION_PATH)
                    .header("x-forwarded-for", "203.0.113.9")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await;
            let status = response.status();
            answers.push((status, body_json(response).await));
        }

        for (status, json) in &answers {
            assert_eq!(*status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(*status, answers[0].0);
            assert_eq!(*json, answers[0].1, "the bodies must be identical too");
        }
    }

    /// A body over the size limit is refused, and refusing it costs no parse.
    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let filler = "a".repeat(registration::MAX_BODY_BYTES);
        let response = call(
            &app().await,
            post_register(&format!(
                r#"{{"client_name":"{filler}","redirect_uris":["https://p.example/cb"]}}"#
            )),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await["error"],
            "invalid_client_metadata"
        );
    }
}
