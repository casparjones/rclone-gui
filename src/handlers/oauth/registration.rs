//! Dynamic Client Registration (RFC 7591) — `POST /oauth/register`.
//!
//! This is the endpoint that removes the hand-written
//! `data/peers/<remote_name>.json`. A second rclone-gui instance posts what it
//! is and where it wants to be redirected, and gets back a `client_id` and a
//! `client_secret` it can immediately use in the authorization-code flow. No
//! operator on either side has to copy an identifier around.
//!
//! ## It is open, so it is bounded
//!
//! The acceptance criterion says a second instance registers "ohne manuelle
//! Vorarbeit", so registration cannot require an initial access token — there
//! would be nothing to carry it. That makes this the only unauthenticated
//! *write* endpoint in the application, and it gets three independent bounds:
//!
//!   1. a **sliding-window rate limit** ([`RegistrationRateLimiter`]), global
//!      and per claimed client, checked *before* anything else;
//!   2. a **body size limit** ([`MAX_BODY_BYTES`]), so a refused request costs
//!      a length check and not a parse;
//!   3. a **hard cap on stored clients** (`clients::MAX_LIVE_CLIENTS`),
//!      enforced inside the `INSERT`, because a sliding window bounds the rate
//!      and not the total.
//!
//! **Deliberately not invented:** RFC 7591 §3 allows a server to demand an
//! initial access token, and a one-shot pairing code issued in the UI would be
//! the natural fit for this application. That is a product decision about how
//! pairing is *started*, it is not in this ticket's criteria, and inventing a
//! code format here would mean rebuilding it later. Reported to the
//! orchestrator instead.
//!
//! ## Why `Bytes` and not `Json<RegistrationRequest>`
//!
//! Because the rate limiter has to speak first. With `Json<T>` in the
//! signature, axum deserialises the body before the handler body runs at all,
//! so a throttled caller would get 422 for junk and 429 for well-formed JSON —
//! and could read the accepted field structure out of the difference, while
//! also making every refused request pay for a parse. The same mistake was
//! found on a protected endpoint in this tree, where an unauthorised caller got
//! 422 on an empty body and 403 on a valid one.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::clients::{self, NewClient, Registered};
use super::metadata::{
    SUPPORTED_AUTH_METHODS, SUPPORTED_GRANT_TYPES, SUPPORTED_RESPONSE_TYPES, SUPPORTED_SCOPES,
};
use super::OAuthState;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Largest registration body that will be read.
///
/// A legitimate one is a few hundred bytes. 4 KiB leaves room for a long client
/// name and several redirect URIs and still means a flood costs a comparison.
pub const MAX_BODY_BYTES: usize = 4 * 1024;

/// Sliding window for the rate limit.
pub const RATE_WINDOW: Duration = Duration::from_secs(600);

/// Registrations per client key within the window.
///
/// Pairing is a once-per-peer act. Five allows for a retried request and a
/// mistyped redirect URI; it allows nothing else.
pub const RATE_PER_CLIENT: usize = 5;

/// Registrations across the whole process within the window.
///
/// This is the limit that actually bites, and for the same reason as the reset
/// endpoint's: the per-client key comes from `X-Forwarded-For`, which anyone
/// who reaches the port directly can set to anything. The per-client bucket
/// helps behind a trusted proxy; the global one holds regardless.
pub const RATE_GLOBAL: usize = 30;

/// Longest `client_name` accepted. It ends up on a consent page, and an
/// unbounded attacker-chosen string does not belong there.
pub const MAX_CLIENT_NAME_CHARS: usize = 128;

/// Most redirect URIs one client may register.
pub const MAX_REDIRECT_URIS: usize = 5;

/// Longest single redirect URI.
pub const MAX_REDIRECT_URI_CHARS: usize = 512;

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Sliding-window limiter for the public registration endpoint.
///
/// In-process and in-memory on purpose, exactly like
/// `auth_web::ResetRateLimiter`: it protects this process's disk and CPU, and a
/// restart clearing it is not a security problem — the hard cap on stored
/// clients survives the restart, which is the bound that matters.
#[derive(Default)]
pub struct RegistrationRateLimiter {
    inner: std::sync::Mutex<RateState>,
}

#[derive(Default)]
struct RateState {
    per_client: HashMap<String, Vec<Instant>>,
    global: Vec<Instant>,
}

impl RegistrationRateLimiter {
    /// Record an attempt and say whether it may proceed.
    ///
    /// Both the pruning and the two comparisons happen while the mutex is
    /// held. That is not incidental: check-then-record with the lock released
    /// in between is precisely the shape that lets N concurrent callers all
    /// read a count below the limit and all record afterwards.
    /// `tests::the_global_cap_holds_under_concurrent_requests` pins it and
    /// `tests::counter_probe_a_check_then_record_limiter_overruns` shows the
    /// broken shape failing the same assertion.
    ///
    /// A refused attempt is **not** recorded, so a client hammering the
    /// endpoint cannot extend its own lockout indefinitely — it stays refused
    /// until the window slides.
    pub fn allow(&self, client_key: &str, now: Instant) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            // A poisoned mutex means another thread panicked holding it.
            // Refusing is the safe direction on a public write endpoint.
            tracing::error!("registration rate limiter mutex is poisoned, refusing the attempt");
            return false;
        };

        let cutoff = now.checked_sub(RATE_WINDOW).unwrap_or(now);
        state.global.retain(|seen| *seen > cutoff);
        state.per_client.retain(|_, seen| {
            seen.retain(|when| *when > cutoff);
            !seen.is_empty()
        });

        if state.global.len() >= RATE_GLOBAL {
            return false;
        }
        let bucket = state.per_client.entry(client_key.to_string()).or_default();
        if bucket.len() >= RATE_PER_CLIENT {
            return false;
        }

        bucket.push(now);
        state.global.push(now);
        true
    }
}

/// What a request claims to be, for the rate limiter only.
///
/// Never used for a security decision beyond throttling — see [`RATE_GLOBAL`].
fn client_key(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .unwrap_or("unknown")
        .to_string()
}

// ---------------------------------------------------------------------------
// Request and response
// ---------------------------------------------------------------------------

/// The client metadata a registration may carry.
///
/// Every field is optional and unknown members are ignored, both because
/// RFC 7591 §2 says a server must ignore metadata it does not understand, and
/// because rejecting them would break against any client that sends a field we
/// have not heard of.
///
/// No `Debug`: three of these field names contain a stem the leak guard treats
/// as suspicious, and a registration body is attacker-supplied text that has no
/// business in a log line.
#[derive(Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Space-delimited, as OAuth writes scopes on the wire.
    #[serde(default)]
    pub scope: Option<String>,
}

/// The RFC 7591 §3.2.1 success body.
///
/// `client_secret` is the plaintext, and this is the **only** place it is ever
/// written down. It is a `String` here rather than a `ClientSecret` because the
/// value has to be serialised, which is exactly what that newtype refuses to
/// allow — the conversion happens in one visible line in [`register`], via
/// `expose()`.
///
/// No `Debug`, for the obvious reason.
#[derive(Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
    /// Seconds since the epoch, as RFC 7591 specifies for this field.
    pub client_id_issued_at: i64,
    /// `0` means "does not expire". Rotation of the *rsync* secret is a
    /// separate mechanism in the parent ticket; the client credential itself is
    /// ended by revocation, not by a clock.
    pub client_secret_expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub scope: String,
}

/// The RFC 7591 §3.2.2 error body. Also used for the throttled answer, which
/// has no code of its own in that document.
#[derive(Serialize)]
struct RegistrationError {
    error: &'static str,
    error_description: &'static str,
}

/// 400 with an RFC 7591 error code.
///
/// The description is a fixed string, never an echo of the input: reflecting
/// attacker-supplied text into a response body is how a JSON endpoint turns
/// into a phishing surface, and it tells a prober nothing it did not already
/// send.
fn reject(error: &'static str, description: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(RegistrationError {
            error,
            error_description: description,
        }),
    )
        .into_response()
}

/// The one answer for "not now".
///
/// Used for **both** the rate limit and the hard client cap, byte for byte.
/// Distinguishing them would tell an unauthenticated caller how many clients
/// this instance already holds and whether it is near its ceiling; there is
/// nothing a legitimate peer would do differently, so there is nothing to gain
/// by saying which bound it hit.
fn too_many() -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(RegistrationError {
            error: "temporarily_unavailable",
            error_description: "registration is rate limited; retry later",
        }),
    )
        .into_response();

    response.headers_mut().insert(
        header::RETRY_AFTER,
        header::HeaderValue::from_static("600"),
    );

    response
}

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

/// `POST /oauth/register`.
///
/// Order of operations, and every step is there because the one before it must
/// not be skippable:
///
///   1. rate limit — **before** the body is looked at, so a refusal costs
///      nothing and cannot be starved by malformed input;
///   2. size;
///   3. parse;
///   4. validate;
///   5. store, with the cap inside the `INSERT`.
///
/// No database access happens before step 5, which is what makes the throttled
/// path structurally cheap and structurally uniform — there is no lookup to
/// time against.
pub async fn register(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.limiter.allow(&client_key(&headers), Instant::now()) {
        tracing::warn!("client registration refused: rate limit");
        return too_many();
    }

    if body.len() > MAX_BODY_BYTES {
        return reject(
            "invalid_client_metadata",
            "registration body is too large",
        );
    }

    let request: RegistrationRequest = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            // The parser's message quotes the input. Not echoed.
            return reject(
                "invalid_client_metadata",
                "body must be a JSON object of client metadata",
            );
        }
    };

    let new_client = match validate(request) {
        Ok(validated) => validated,
        Err(e) => return reject(e.error, e.description),
    };

    let now = chrono::Utc::now();
    match clients::insert_client(&state.pool, new_client, now).await {
        Ok(Registered::Created(client, secret)) => {
            // The one line where the plaintext leaves its newtype.
            tracing::info!(
                client_id = %client.client_id,
                "registered a new OAuth client via DCR"
            );
            (
                StatusCode::CREATED,
                Json(RegistrationResponse {
                    client_id: client.client_id,
                    client_secret: secret.expose().to_string(),
                    client_id_issued_at: client.created_at.timestamp(),
                    client_secret_expires_at: 0,
                    client_name: client.client_name,
                    redirect_uris: client.redirect_uris,
                    grant_types: client.grant_types,
                    response_types: client.response_types,
                    token_endpoint_auth_method: client.token_endpoint_auth_method,
                    scope: client.scope,
                }),
            )
                .into_response()
        }
        Ok(Registered::AtCapacity) => {
            tracing::warn!(
                "client registration refused: {} live clients is the cap",
                clients::MAX_LIVE_CLIENTS
            );
            too_many()
        }
        Err(e) => {
            // The message may name a column or a file path; it stays in the
            // log and does not go out on a public endpoint.
            tracing::error!("storing a registered client failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegistrationError {
                    error: "temporarily_unavailable",
                    error_description: "the registration could not be stored",
                }),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// An RFC 7591 §3.2.2 rejection: a registered error code and a fixed
/// description.
///
/// `Debug` is derived, and that is safe here for a reason worth stating: both
/// fields are `&'static str` chosen in this file. Nothing attacker-supplied can
/// reach them — `tests::no_error_description_reflects_attacker_input` is the
/// assertion that keeps it that way.
#[derive(Debug)]
pub struct Invalid {
    pub error: &'static str,
    pub description: &'static str,
}

fn invalid_uri(description: &'static str) -> Invalid {
    Invalid {
        error: "invalid_redirect_uri",
        description,
    }
}

fn invalid_metadata(description: &'static str) -> Invalid {
    Invalid {
        error: "invalid_client_metadata",
        description,
    }
}

/// Turn a request into the record we are willing to store, or say why not.
///
/// Defaults follow RFC 7591 §2: `authorization_code`, `code`,
/// `client_secret_basic`. The scope default is ours — `browse` is the one that
/// cannot move or delete data, so a client that says nothing gets the harmless
/// one and has to ask for the rest.
pub fn validate(request: RegistrationRequest) -> Result<NewClient, Invalid> {
    // --- redirect URIs -----------------------------------------------------
    let redirect_uris = request.redirect_uris.unwrap_or_default();
    if redirect_uris.is_empty() {
        return Err(invalid_uri(
            "at least one redirect_uri is required for the authorization_code grant",
        ));
    }
    if redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid_uri("too many redirect_uris"));
    }
    for uri in &redirect_uris {
        check_redirect_uri(uri)?;
    }
    // Duplicates are not an error worth a round trip, but they should not be
    // stored — the authorization endpoint compares against this list.
    let mut deduped: Vec<String> = Vec::with_capacity(redirect_uris.len());
    for uri in redirect_uris {
        if !deduped.contains(&uri) {
            deduped.push(uri);
        }
    }
    let redirect_uris = deduped;

    // --- grant and response types -----------------------------------------
    let grant_types = request
        .grant_types
        .filter(|g| !g.is_empty())
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    for grant in &grant_types {
        if !SUPPORTED_GRANT_TYPES.contains(&grant.as_str()) {
            // Named codes exist for exactly this in RFC 7591 §3.2.2.
            return Err(Invalid {
                error: "invalid_client_metadata",
                description: "unsupported grant_type; this server issues \
                              authorization_code and refresh_token only",
            });
        }
    }
    if grant_types.iter().any(|g| g == "refresh_token")
        && !grant_types.iter().any(|g| g == "authorization_code")
    {
        // RFC 7591 §2: refresh_token is meaningless without the grant that
        // produces the refresh token in the first place.
        return Err(invalid_metadata(
            "refresh_token requires authorization_code as well",
        ));
    }

    let response_types = request
        .response_types
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| vec!["code".to_string()]);
    for response_type in &response_types {
        if !SUPPORTED_RESPONSE_TYPES.contains(&response_type.as_str()) {
            return Err(invalid_metadata(
                "unsupported response_type; this server issues code only",
            ));
        }
    }

    // --- client authentication --------------------------------------------
    let token_endpoint_auth_method = request
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".to_string());
    if !SUPPORTED_AUTH_METHODS.contains(&token_endpoint_auth_method.as_str()) {
        return Err(invalid_metadata(
            "unsupported token_endpoint_auth_method; both peers are servers, \
             so a client secret is required",
        ));
    }

    // --- scope -------------------------------------------------------------
    let requested_scope = request.scope.unwrap_or_default();
    let mut scopes: Vec<&str> = Vec::new();
    for scope in requested_scope.split_whitespace() {
        if !SUPPORTED_SCOPES.contains(&scope) {
            return Err(Invalid {
                error: "invalid_client_metadata",
                description: "unknown scope requested",
            });
        }
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        scopes.push("browse");
    }
    let scope = scopes.join(" ");

    // --- name --------------------------------------------------------------
    let client_name = match request.client_name {
        None => None,
        Some(name) => {
            let name = name.trim().to_string();
            if name.is_empty() {
                None
            } else if name.chars().count() > MAX_CLIENT_NAME_CHARS {
                return Err(invalid_metadata("client_name is too long"));
            } else if name.chars().any(|c| c.is_control()) {
                // It is shown on a consent page later. Escaping is that page's
                // job; control characters have no legitimate use here and are
                // cheaper to refuse than to reason about.
                return Err(invalid_metadata(
                    "client_name must not contain control characters",
                ));
            } else {
                Some(name)
            }
        }
    };

    Ok(NewClient {
        client_name,
        redirect_uris,
        grant_types,
        response_types,
        token_endpoint_auth_method,
        scope,
    })
}

/// What a redirect URI must look like to be stored.
///
/// This list is the security boundary of the whole flow: the authorization
/// endpoint will send an authorization code to whatever is in it, so anything
/// accepted here is a place codes can go.
///
///   * absolute, with a scheme we know. `https` always; `http` **only** for a
///     loopback host, per RFC 8252 §7.3 and OAuth 2.1 — that is the case of a
///     peer being set up on the same machine, and it is the only one where
///     plaintext is not a code-interception bug.
///   * no fragment. RFC 6749 §3.1.2 forbids one, and a fragment is not sent to
///     the server anyway, so one here means the client misunderstands the flow.
///   * no userinfo. Credentials in a redirect target are both a leak and a
///     spoofing aid (`https://real.example@evil.example`).
///   * no wildcard, no whitespace, no control characters, no backslash — the
///     characters that make two parsers disagree about which host a URL names.
fn check_redirect_uri(uri: &str) -> Result<(), Invalid> {
    if uri.is_empty() || uri.chars().count() > MAX_REDIRECT_URI_CHARS {
        return Err(invalid_uri("redirect_uri is empty or too long"));
    }
    if uri
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '*')
    {
        return Err(invalid_uri(
            "redirect_uri must not contain whitespace, control characters, \
             a backslash or a wildcard",
        ));
    }
    if uri.contains('#') {
        return Err(invalid_uri("redirect_uri must not carry a fragment"));
    }

    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| invalid_uri("redirect_uri must be an absolute http or https URL"))?;
    if !matches!(scheme, "http" | "https") {
        return Err(invalid_uri(
            "redirect_uri must use https, or http on a loopback host",
        ));
    }

    // Authority = everything up to the first `/`, `?`. It is checked before the
    // path, because `@` in a path is legal and `@` in an authority is userinfo.
    let authority_end = rest
        .find(['/', '?'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(invalid_uri("redirect_uri has no host"));
    }
    if authority.contains('@') {
        return Err(invalid_uri("redirect_uri must not carry credentials"));
    }

    if scheme == "http" && !is_loopback_authority(authority) {
        return Err(invalid_uri(
            "http is only accepted for a loopback redirect_uri; use https",
        ));
    }

    Ok(())
}

/// Whether an authority names this machine.
///
/// The literals from RFC 8252 §7.3, plus `localhost`. That RFC prefers the
/// literal IP because `localhost` depends on a resolver, but a peer being set
/// up by hand on the same box will be typed as `localhost` by a person, and
/// refusing it would send them to plain `http` on a name we *do* accept, which
/// is worse. Note that `127.` covers the whole loopback /8.
fn is_loopback_authority(authority: &str) -> bool {
    // Strip the port. Split from the right so an IPv6 literal's colons survive.
    let host = match authority.rsplit_once(':') {
        // `[::1]:8080` — the part before the last colon still ends in `]`.
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');

    host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1" || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn request() -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: Some(vec!["https://peer.example.org/cb".to_string()]),
            client_name: Some("Peer".to_string()),
            grant_types: None,
            response_types: None,
            token_endpoint_auth_method: None,
            scope: None,
        }
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    #[test]
    fn a_minimal_registration_gets_the_rfc_defaults() {
        let validated = validate(request()).expect("valid");
        assert_eq!(validated.grant_types, vec!["authorization_code"]);
        assert_eq!(validated.response_types, vec!["code"]);
        assert_eq!(validated.token_endpoint_auth_method, "client_secret_basic");
        // Ours, not the RFC's: the scope that cannot move or delete anything.
        assert_eq!(validated.scope, "browse");
    }

    #[test]
    fn a_registration_without_a_redirect_uri_is_refused() {
        for uris in [None, Some(vec![])] {
            let mut req = request();
            req.redirect_uris = uris;
            let err = validate(req).expect_err("must be refused");
            assert_eq!(err.error, "invalid_redirect_uri");
        }
    }

    /// The security boundary of the whole flow. Each entry is a place an
    /// authorization code must never be sent.
    #[test]
    fn a_redirect_uri_that_could_take_a_code_elsewhere_is_refused() {
        let bad = [
            "http://peer.example.org/cb",       // plaintext to a remote host
            "peer.example.org/cb",              // not absolute
            "/cb",                              // relative
            "ftp://peer.example.org/cb",        // unknown scheme
            "javascript://x/%0aalert(1)",       // not http(s)
            "data:text/html,<script>",          // not http(s)
            "https://peer.example.org/cb#frag", // fragment
            "https://user:pw@peer.example.org/cb", // userinfo
            "https://real.example@evil.example/cb", // spoofing shape
            "https://*.example.org/cb",         // wildcard
            "https://peer.example.org/c b",     // whitespace
            "https://peer.example.org\\@evil.example/cb", // backslash confusion
            "https://",                         // no host
            "https:///cb",                      // no host
        ];
        for uri in bad {
            let mut req = request();
            req.redirect_uris = Some(vec![uri.to_string()]);
            let err = validate(req).expect_err(&format!("{uri} must be refused"));
            assert_eq!(err.error, "invalid_redirect_uri", "for {uri}");
        }
        // A CR/LF smuggling attempt, spelled out separately so the array above
        // stays readable.
        let mut req = request();
        req.redirect_uris = Some(vec!["https://peer.example.org/cb\r\nX: 1".to_string()]);
        assert_eq!(
            validate(req).expect_err("CRLF must be refused").error,
            "invalid_redirect_uri"
        );
    }

    /// The counter-probe: the shapes above are refused *because of the checks*,
    /// not because everything is refused. These must pass.
    #[test]
    fn the_shapes_a_real_peer_uses_are_accepted() {
        let good = [
            "https://peer.example.org/oauth/callback",
            "https://peer.example.org:8443/oauth/callback?instance=b",
            "http://127.0.0.1:8080/oauth/callback",
            "http://127.0.0.53/cb",
            "http://localhost:9000/cb",
            "http://[::1]:9000/cb",
        ];
        for uri in good {
            let mut req = request();
            req.redirect_uris = Some(vec![uri.to_string()]);
            assert!(
                validate(req).is_ok(),
                "{uri} is a legitimate redirect target and must be accepted"
            );
        }
    }

    #[test]
    fn too_many_redirect_uris_are_refused_and_duplicates_are_collapsed() {
        let mut req = request();
        req.redirect_uris = Some(
            (0..MAX_REDIRECT_URIS + 1)
                .map(|n| format!("https://peer.example.org/cb{n}"))
                .collect(),
        );
        assert_eq!(
            validate(req).expect_err("too many").error,
            "invalid_redirect_uri"
        );

        let mut req = request();
        req.redirect_uris = Some(vec![
            "https://peer.example.org/cb".to_string(),
            "https://peer.example.org/cb".to_string(),
        ]);
        assert_eq!(validate(req).expect("valid").redirect_uris.len(), 1);
    }

    #[test]
    fn the_grants_oauth_21_removed_are_refused() {
        for grant in [
            "implicit",
            "password",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        ] {
            let mut req = request();
            req.grant_types = Some(vec![grant.to_string()]);
            let err = validate(req).expect_err(&format!("{grant} must be refused"));
            assert_eq!(err.error, "invalid_client_metadata");
        }

        let mut req = request();
        req.response_types = Some(vec!["token".to_string()]);
        assert_eq!(
            validate(req).expect_err("implicit response type").error,
            "invalid_client_metadata"
        );
    }

    #[test]
    fn refresh_token_without_authorization_code_is_refused() {
        let mut req = request();
        req.grant_types = Some(vec!["refresh_token".to_string()]);
        assert_eq!(
            validate(req).expect_err("refresh alone").error,
            "invalid_client_metadata"
        );

        let mut req = request();
        req.grant_types = Some(vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]);
        assert!(validate(req).is_ok(), "both together is the normal case");
    }

    #[test]
    fn a_public_client_cannot_register() {
        let mut req = request();
        req.token_endpoint_auth_method = Some("none".to_string());
        assert_eq!(
            validate(req).expect_err("none").error,
            "invalid_client_metadata"
        );

        for method in ["client_secret_basic", "client_secret_post"] {
            let mut req = request();
            req.token_endpoint_auth_method = Some(method.to_string());
            assert!(validate(req).is_ok(), "{method} must be accepted");
        }
    }

    #[test]
    fn only_known_scopes_are_accepted_and_they_are_deduplicated() {
        let mut req = request();
        req.scope = Some("rsync:read browse rsync:read".to_string());
        assert_eq!(validate(req).expect("valid").scope, "rsync:read browse");

        for bad in ["admin", "rsync:*", "browse rsync:everything", "*"] {
            let mut req = request();
            req.scope = Some(bad.to_string());
            assert_eq!(
                validate(req).expect_err(bad).error,
                "invalid_client_metadata",
                "scope {bad} must be refused"
            );
        }
    }

    #[test]
    fn a_client_name_is_bounded_and_free_of_control_characters() {
        let mut req = request();
        req.client_name = Some("a".repeat(MAX_CLIENT_NAME_CHARS + 1));
        assert_eq!(
            validate(req).expect_err("too long").error,
            "invalid_client_metadata"
        );

        let mut req = request();
        req.client_name = Some("Peer\u{0}\u{1b}[2J".to_string());
        assert_eq!(
            validate(req).expect_err("control chars").error,
            "invalid_client_metadata"
        );

        // Blank collapses to absent rather than to an empty display name.
        let mut req = request();
        req.client_name = Some("   ".to_string());
        assert!(validate(req).expect("valid").client_name.is_none());
    }

    /// RFC 7591 §2: metadata the server does not understand is ignored, not
    /// rejected. A client sending a field from a newer draft must still be able
    /// to pair.
    #[test]
    fn unknown_metadata_members_are_ignored() {
        let body = br#"{
            "redirect_uris": ["https://peer.example.org/cb"],
            "software_id": "rclone-gui",
            "jwks_uri": "https://peer.example.org/jwks",
            "some_future_field": {"nested": [1, 2, 3]}
        }"#;
        let parsed: RegistrationRequest = serde_json::from_slice(body).expect("parse");
        assert!(validate(parsed).is_ok());
    }

    // -----------------------------------------------------------------------
    // Rate limiter
    // -----------------------------------------------------------------------

    #[test]
    fn the_per_client_bucket_stops_one_caller_and_the_global_one_stops_the_rest() {
        let limiter = RegistrationRateLimiter::default();
        let now = Instant::now();

        for n in 0..RATE_PER_CLIENT {
            assert!(limiter.allow("a", now), "attempt {n} from a must pass");
        }
        assert!(!limiter.allow("a", now), "a is over its own limit");
        // Another caller is unaffected — a per-client limit that locked out
        // everyone would be a denial-of-service lever for one attacker.
        assert!(limiter.allow("b", now));

        // Fill the global bucket with distinct callers.
        let mut key = 0;
        while limiter.allow(&format!("k{key}"), now) {
            key += 1;
            assert!(key < RATE_GLOBAL * 4, "the global cap never bit");
        }
        assert!(
            !limiter.allow("brand-new", now),
            "past the global cap nobody passes, whatever they claim to be"
        );

        // The window slides.
        let later = now + RATE_WINDOW + Duration::from_secs(1);
        assert!(limiter.allow("a", later));
    }

    /// A refused attempt must not count, or a client hammering the endpoint
    /// would keep pushing its own release further away.
    #[test]
    fn a_refused_attempt_does_not_extend_the_lockout() {
        let limiter = RegistrationRateLimiter::default();
        let start = Instant::now();
        for _ in 0..RATE_PER_CLIENT {
            assert!(limiter.allow("a", start));
        }
        // Hammer well into the window.
        for step in 1..100 {
            assert!(!limiter.allow("a", start + Duration::from_secs(step)));
        }
        // The window is measured from the last *accepted* attempt.
        let released = start + RATE_WINDOW + Duration::from_secs(1);
        assert!(
            limiter.allow("a", released),
            "the lockout must end one window after the last accepted attempt"
        );
    }

    const RACERS: usize = 64;

    /// The global cap must hold when every request arrives at once.
    ///
    /// `std::thread` rather than tasks: the limiter is synchronous and the
    /// contention that matters is between OS threads on the mutex.
    #[test]
    fn the_global_cap_holds_under_concurrent_requests() {
        let limiter = Arc::new(RegistrationRateLimiter::default());
        let barrier = Arc::new(std::sync::Barrier::new(RACERS));
        let now = Instant::now();

        let mut handles = Vec::with_capacity(RACERS);
        for n in 0..RACERS {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // A distinct key each, so the per-client bucket never bites
                // and the global cap is the only thing under test.
                limiter.allow(&format!("racer-{n}"), now)
            }));
        }

        let allowed = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .filter(|passed| *passed)
            .count();

        assert_eq!(
            allowed, RATE_GLOBAL,
            "exactly the global cap may pass, not {allowed} of {RACERS}"
        );
    }

    /// The counter-probe for the test above.
    ///
    /// A limiter that reads the count, releases the lock, then records — the
    /// shape a refactor produces when someone splits `allow` into `check` and
    /// `record`. Run through the identical harness, it must overrun the cap. If
    /// it did not, the test above would be proving nothing.
    ///
    /// Measured on this machine: **64 of 64** racers past a cap of 30, against
    /// exactly 30 for the real limiter.
    #[test]
    fn counter_probe_a_check_then_record_limiter_overruns() {
        #[derive(Default)]
        struct Naive {
            seen: std::sync::Mutex<Vec<Instant>>,
        }
        impl Naive {
            fn allow(&self, now: Instant) -> bool {
                // Step 1: look, and let go of the lock.
                {
                    let Ok(seen) = self.seen.lock() else {
                        return false;
                    };
                    if seen.len() >= RATE_GLOBAL {
                        return false;
                    }
                }
                // The window every racer slips through. A bare `yield_now`
                // was measured at 31 of 64 — an overrun, but only just, and
                // close enough to the cap to be flaky. A few milliseconds is
                // the same bug held open long enough to be counted reliably.
                std::thread::sleep(Duration::from_millis(5));
                // Step 2: record.
                let Ok(mut seen) = self.seen.lock() else {
                    return false;
                };
                seen.push(now);
                true
            }
        }

        let limiter = Arc::new(Naive::default());
        let barrier = Arc::new(std::sync::Barrier::new(RACERS));
        let now = Instant::now();

        let mut handles = Vec::with_capacity(RACERS);
        for _ in 0..RACERS {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                limiter.allow(now)
            }));
        }

        let allowed = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .filter(|passed| *passed)
            .count();

        assert!(
            allowed > RATE_GLOBAL,
            "the check-then-record limiter was expected to overrun the cap of {RATE_GLOBAL}, \
             but only {allowed} of {RACERS} passed — if this ever holds, the test above proves \
             nothing and both need rethinking"
        );
    }

    // -----------------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------------

    /// The throttled answer must not say *which* bound was hit — the rate limit
    /// and the client cap both use it, and a difference would report how full
    /// this instance is.
    #[test]
    fn the_throttled_answer_is_one_fixed_response() {
        let a = too_many();
        let b = too_many();
        assert_eq!(a.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(a.status(), b.status());
        assert_eq!(
            a.headers().get(header::RETRY_AFTER),
            b.headers().get(header::RETRY_AFTER)
        );
        assert!(a.headers().get(header::RETRY_AFTER).is_some());
    }

    /// No error description may echo the input back.
    #[test]
    fn no_error_description_reflects_attacker_input() {
        let needle = "MARKER-a91a42ec";
        let mut req = request();
        req.redirect_uris = Some(vec![format!("gopher://{needle}.example/cb")]);
        let err = validate(req).expect_err("bad scheme");
        assert!(
            !err.description.contains(needle),
            "the description echoed the input: {}",
            err.description
        );

        let mut req = request();
        req.scope = Some(needle.to_string());
        let err = validate(req).expect_err("bad scope");
        assert!(!err.description.contains(needle));

        let mut req = request();
        req.client_name = Some(needle.to_string());
        req.grant_types = Some(vec![needle.to_string()]);
        let err = validate(req).expect_err("bad grant");
        assert!(!err.description.contains(needle));
    }
}
