// The web side of authentication: the session guard, the login page, the login
// and logout routes.
//
// `handlers::auth` holds the primitives (hashing, tokens, cookie building,
// `login`/`logout`/`authenticate_session`); this module is the only place that
// wires them into axum. Nothing here re-implements a security decision — it
// decides *where* the guard applies and *what an unauthenticated request sees*.
//
// The guard is a single layer around the whole router, not a per-handler check.
// That is the point of the ticket: a handler someone adds next month is
// protected because it was added to a router that is already wrapped, not
// because its author remembered an extractor.

use std::sync::Arc;

use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Extension, Form, Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

use crate::database::{Session, User};
use crate::handlers::auth::{self, session_token_from_cookie_header, LoginError, SessionConfig};
use crate::models::ApiResponse;

/// Path of the login page. Also the redirect target for unauthenticated page
/// requests.
pub const LOGIN_PATH: &str = "/login";

/// Everything the guard and the login routes need. Cloned per request by axum's
/// state machinery, so both fields are cheap to clone (`Pool` is an `Arc`
/// inside, the config sits behind one).
///
/// Deliberately no `Debug`: it carries no secret today, but a struct that grows
/// a token or a hash later must not print it by accident. If you add `Debug`
/// here, write it by hand and redact — same rule as `User`, `Session` and
/// `LoginOutcome`.
#[derive(Clone)]
pub struct AuthState {
    pub pool: Pool<Sqlite>,
    pub config: Arc<SessionConfig>,
}

impl AuthState {
    pub fn new(pool: Pool<Sqlite>, config: SessionConfig) -> Self {
        Self {
            pool,
            config: Arc::new(config),
        }
    }
}

/// The authenticated caller, put into the request extensions by the guard.
///
/// Handlers take it as `Extension<CurrentUser>`. Its presence is proof that the
/// guard ran and let the request through — the extension is never inserted on
/// any other path.
///
/// `Debug` may be derived here: both fields have hand-written `Debug`
/// implementations that redact the password hash and the session key. A field
/// added later that carries a token or a cookie string would break that, so
/// check before extending this struct.
#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub user: User,
    pub session: Session,
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

/// Paths reachable without a session.
///
/// This is an **allowlist**, and it is the only exception to a default-deny
/// rule: everything the guard is not explicitly told to let through needs a
/// valid session, including paths that match no route at all. Adding a route
/// therefore protects it; opening one up takes a deliberate edit here.
///
/// The three entries and why each has to be here:
///   * the login page and the form it posts to — otherwise nobody could ever
///     obtain a session,
///   * `/static/**` — the login page is server-rendered and standalone, but the
///     application shell loads its stylesheet and its JS modules from here
///     *after* login; serving them only to sessions would be one more thing to
///     get wrong, and they contain no user data,
///   * `/favicon.ico` — requested by the browser on the login page itself; a
///     401 there is noise, not protection.
fn is_public_path(path: &str) -> bool {
    matches!(path, LOGIN_PATH | "/api/auth/login" | "/favicon.ico")
        || path == "/static"
        || path.starts_with("/static/")
}

/// Whether an unauthenticated request should be answered with 401 JSON rather
/// than a redirect to the login page.
///
/// Everything under `/api/` is a programmatic caller: `fetch` follows a 302
/// silently and would hand the frontend the login *page* as if it were a JSON
/// answer, which surfaces as a parse error somewhere far from the cause. A 401
/// says what happened.
fn wants_json(path: &str) -> bool {
    path.starts_with("/api/")
}

/// The session guard.
///
/// Applied once, around the finished router (see `src/main.rs`), so it sees
/// every request — matched routes, the static service and unmatched paths
/// alike.
pub async fn require_session(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    if is_public_path(&path) {
        return next.run(req).await;
    }

    let token = req
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| session_token_from_cookie_header(header, &state.config.cookie_name));

    let Some(token) = token else {
        return reject(&state, &path, req.uri(), false);
    };

    match auth::authenticate_session(&state.pool, &token).await {
        Ok(Some((session, user))) => {
            req.extensions_mut().insert(CurrentUser { user, session });
            next.run(req).await
        }
        // Expired, unknown or belonging to a disabled account. The cookie is
        // cleared on the way out so the browser stops sending a token that will
        // never work again.
        Ok(None) => reject(&state, &path, req.uri(), true),
        Err(e) => {
            // A database failure is not "logged out". Answering 401 here would
            // make every client drop its session over a transient error.
            tracing::error!("session lookup failed: {e}");
            error_response(
                &path,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session could not be verified",
            )
        }
    }
}

/// Turn away a request without a usable session.
fn reject(state: &AuthState, path: &str, uri: &axum::http::Uri, clear_cookie: bool) -> Response {
    let mut response = if wants_json(path) {
        error_response(path, StatusCode::UNAUTHORIZED, "Authentication required")
    } else {
        // 303 rather than 302: the browser must switch to GET for the login
        // page even if the original request was a POST.
        let target = format!("{LOGIN_PATH}?next={}", percent_encode(&path_and_query(uri)));
        (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, target)],
            Html(redirect_body()),
        )
            .into_response()
    };

    if clear_cookie {
        if let Ok(value) = state.config.build_clearing_cookie().parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }

    response
}

/// One error shape for API callers, one for browsers.
fn error_response(path: &str, status: StatusCode, message: &str) -> Response {
    if wants_json(path) {
        (
            status,
            Json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some(message.to_string()),
            }),
        )
            .into_response()
    } else {
        (
            status,
            Html(page(message, &format!("<p>{}</p>", escape_html(message)))),
        )
            .into_response()
    }
}

fn redirect_body() -> String {
    page(
        "Redirecting",
        &format!("<p>Please <a href=\"{LOGIN_PATH}\">sign in</a> to continue.</p>"),
    )
}

// ---------------------------------------------------------------------------
// Login page
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginPageQuery {
    /// Where to go after a successful login.
    pub next: Option<String>,
    /// Set by the login handlers when they bounce back to the form.
    pub error: Option<String>,
}

/// `GET /login` — the sign-in form.
///
/// Rendered here in Rust rather than in `static/`: the login page must work
/// before any session exists and must not depend on the application shell, its
/// CDN stylesheets or its JS modules. It is plain HTML with a plain form, so it
/// also works with JavaScript switched off.
pub async fn login_page(Query(query): Query<LoginPageQuery>) -> Html<String> {
    let next = sanitize_next(query.next.as_deref());
    let error = query.error.as_deref().map(message_for_error_code);

    let error_block = match error {
        Some(text) => format!(
            "<p class=\"error\" role=\"alert\">{}</p>",
            escape_html(text)
        ),
        None => String::new(),
    };

    Html(page(
        "Sign in",
        &format!(
            r#"<h1>rclone GUI</h1>
    {error_block}
    <form method="post" action="{LOGIN_PATH}">
      <input type="hidden" name="next" value="{next}">
      <label for="username">User name</label>
      <input id="username" name="username" type="text" autocomplete="username" autofocus required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>"#,
            next = escape_html(&next),
        ),
    ))
}

/// The self-contained page frame. No external stylesheet, no script, no CDN.
fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>{title} · rclone GUI</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font-family: system-ui, sans-serif; margin: 0; min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
            background: #f3f4f6; color: #111827; }}
    main {{ background: #fff; padding: 2rem; border-radius: .75rem; width: min(22rem, 92vw);
            box-shadow: 0 1px 3px rgba(0,0,0,.15); }}
    h1 {{ font-size: 1.25rem; margin: 0 0 1rem; }}
    label {{ display: block; font-size: .8rem; margin: .75rem 0 .25rem; }}
    input {{ width: 100%; box-sizing: border-box; padding: .5rem; border: 1px solid #d1d5db;
             border-radius: .375rem; font: inherit; }}
    button {{ margin-top: 1.25rem; width: 100%; padding: .55rem; border: 0; border-radius: .375rem;
              background: #2563eb; color: #fff; font: inherit; cursor: pointer; }}
    .error {{ background: #fee2e2; color: #991b1b; padding: .5rem .75rem; border-radius: .375rem;
              font-size: .85rem; margin: 0 0 .5rem; }}
    @media (prefers-color-scheme: dark) {{
      body {{ background: #111827; color: #f9fafb; }}
      main {{ background: #1f2937; box-shadow: none; }}
      input {{ background: #111827; color: inherit; border-color: #374151; }}
    }}
  </style>
</head>
<body>
  <main>
{body}
  </main>
</body>
</html>"#,
        title = escape_html(title),
    )
}

// ---------------------------------------------------------------------------
// Login / logout routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub next: Option<String>,
}

// No `Debug` on the request types: both carry a plaintext password, and a
// derived `Debug` is exactly how such a value reaches a log.

#[derive(Deserialize)]
pub struct LoginJson {
    pub username: String,
    pub password: String,
}

/// What a caller may know about itself. Never the hash, never the token.
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: String,
    pub home_path: String,
    pub session_expires_at: chrono::DateTime<chrono::Utc>,
}

/// `POST /login` — the browser form. Answers with a redirect either way.
pub async fn login_form_submit(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let next = sanitize_next(form.next.as_deref());

    match do_login(&state, &headers, &form.username, &form.password).await {
        Ok(set_cookie) => match set_cookie.parse::<axum::http::HeaderValue>() {
            Ok(cookie) => (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, next)],
                [(header::SET_COOKIE, cookie)],
            )
                .into_response(),
            Err(e) => {
                tracing::error!("could not build the session cookie header: {e}");
                error_response(
                    "/login",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Login failed, please try again",
                )
            }
        },
        Err(error) => {
            let target = format!(
                "{LOGIN_PATH}?next={}&error={}",
                percent_encode(&next),
                error_code(&error)
            );
            (StatusCode::SEE_OTHER, [(header::LOCATION, target)]).into_response()
        }
    }
}

/// `POST /api/auth/login` — the JSON route, for the frontend modules.
pub async fn login_json_submit(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Json(body): Json<LoginJson>,
) -> Response {
    match do_login(&state, &headers, &body.username, &body.password).await {
        Ok(set_cookie) => match set_cookie.parse::<axum::http::HeaderValue>() {
            Ok(cookie) => (
                [(header::SET_COOKIE, cookie)],
                Json(ApiResponse::success("ok".to_string())),
            )
                .into_response(),
            Err(e) => {
                tracing::error!("could not build the session cookie header: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some("Login failed, please try again".to_string()),
                    }),
                )
                    .into_response()
            }
        },
        Err(error) => {
            // 401 for bad credentials and for a disabled account alike; the
            // message differs, the status does not.
            let status = match error {
                LoginError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::UNAUTHORIZED,
            };
            (
                status,
                Json(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(error.to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// The shared half of both login routes. Returns the `Set-Cookie` value.
async fn do_login(
    state: &AuthState,
    headers: &HeaderMap,
    username: &str,
    password: &str,
) -> std::result::Result<String, LoginError> {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());

    let outcome = match auth::login(
        &state.pool,
        &state.config,
        username,
        password,
        user_agent,
        ip,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            // The cause of an internal failure is for the operator. The client
            // only ever gets `LoginError`'s `Display`, which says nothing about
            // the database or about whether the account exists.
            if let LoginError::Internal(ref cause) = error {
                tracing::error!("login failed internally: {cause:#}");
            }
            return Err(error);
        }
    };

    // Only the identity is logged. `outcome` as a whole is never logged, not
    // even at debug level: its `Debug` redacts, but the habit of printing it is
    // what the redaction exists to survive, not to invite.
    tracing::info!(user_id = %outcome.user.id, "session opened");

    Ok(outcome.set_cookie)
}

/// `GET /logout` and `POST /logout` — invalidate the session server-side and
/// send the browser back to the login page.
///
/// Behind the guard, so it always has a session; the token is read from the
/// cookie again because the session row is keyed by its hash.
pub async fn logout_page(State(state): State<AuthState>, headers: HeaderMap) -> Response {
    destroy_session(&state, &headers).await;

    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, LOGIN_PATH)],
        Html(redirect_body()),
    )
        .into_response();
    if let Ok(value) = state.config.build_clearing_cookie().parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// `POST /api/auth/logout` — same thing for the frontend modules.
pub async fn logout_json(State(state): State<AuthState>, headers: HeaderMap) -> Response {
    destroy_session(&state, &headers).await;

    let mut response = Json(ApiResponse::success("ok".to_string())).into_response();
    if let Ok(value) = state.config.build_clearing_cookie().parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

async fn destroy_session(state: &AuthState, headers: &HeaderMap) {
    let Some(token) = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| session_token_from_cookie_header(header, &state.config.cookie_name))
    else {
        return;
    };

    // Deleting the row is what makes the logout real: a captured cookie must
    // stop working, and clearing it in the browser does not achieve that.
    if let Err(e) = auth::logout(&state.pool, &token).await {
        tracing::warn!("could not delete the session on logout: {e}");
    }
}

/// `GET /api/auth/me` — who the caller is. Behind the guard, so the extension
/// is always present.
pub async fn me(Extension(current): Extension<CurrentUser>) -> Json<ApiResponse<UserInfo>> {
    Json(ApiResponse::success(UserInfo {
        id: current.user.id,
        username: current.user.username,
        role: current.user.role,
        home_path: current.user.home_path,
        session_expires_at: current.session.expires_at,
    }))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn error_code(error: &LoginError) -> &'static str {
    match error {
        LoginError::InvalidCredentials => "credentials",
        LoginError::AccountDisabled => "disabled",
        LoginError::Internal(_) => "internal",
    }
}

/// The message shown on the login page. Driven by a code in the query string
/// rather than by a message, so nothing a client sends is ever rendered back.
fn message_for_error_code(code: &str) -> &'static str {
    match code {
        "disabled" => "This account is disabled.",
        "internal" => "Login failed, please try again.",
        _ => "Invalid user name or password.",
    }
}

/// Keep a redirect target inside this application.
///
/// Only a single-slash absolute path survives. `//evil.example`, `https://…`
/// and a backslash-prefixed variant (which some browsers normalise to `//`) all
/// fall back to `/`, so the login page cannot be turned into an open redirect.
fn sanitize_next(next: Option<&str>) -> String {
    let candidate = next.unwrap_or("/").trim();

    let acceptable = candidate.starts_with('/')
        && !candidate.starts_with("//")
        && !candidate.starts_with("/\\")
        && !candidate.contains(['\r', '\n'])
        && candidate != LOGIN_PATH;

    if acceptable {
        candidate.to_string()
    } else {
        "/".to_string()
    }
}

fn path_and_query(uri: &axum::http::Uri) -> String {
    uri.path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

/// Percent-encode a value for use inside a query string. Hand-written for the
/// same reason the cookie parser is: it is a handful of bytes and the tree has
/// no encoder in it.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Escape the five characters that matter inside HTML text and attributes.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_login_and_static_are_public() {
        for path in [
            LOGIN_PATH,
            "/api/auth/login",
            "/favicon.ico",
            "/static",
            "/static/js/main.js",
        ] {
            assert!(is_public_path(path), "{path} should be public");
        }
    }

    #[test]
    fn everything_else_needs_a_session() {
        // Every route registered in main.rs, plus paths that match no route at
        // all — the guard must not let an unmatched path through either.
        for path in [
            "/",
            "/api/configs",
            "/api/configs/foo",
            "/api/configs/foo/edit",
            "/api/configs/persist",
            "/api/files/local",
            "/api/files/remote",
            "/api/download/file",
            "/api/download/zip",
            "/api/thumb",
            "/api/preview/info",
            "/api/preview/text",
            "/api/preview/image",
            "/api/sync",
            "/api/sync-log/abc",
            "/api/sync-delete/abc",
            "/api/sync/abc/log",
            "/api/sync/abc",
            "/api/tasks",
            "/api/tasks/abc",
            "/api/tasks/start",
            "/api/rsyncd/status",
            "/api/auth/me",
            "/api/auth/logout",
            "/logout",
            "/a-route-that-does-not-exist-yet",
        ] {
            assert!(!is_public_path(path), "{path} must require a session");
        }
    }

    #[test]
    fn a_path_that_only_starts_like_static_is_not_public() {
        assert!(!is_public_path("/staticky"));
        assert!(!is_public_path("/api/static"));
        assert!(!is_public_path("/login/../api/tasks"));
    }

    #[test]
    fn api_paths_get_json_the_rest_get_a_redirect() {
        assert!(wants_json("/api/tasks"));
        assert!(!wants_json("/"));
        assert!(!wants_json("/logout"));
    }

    #[test]
    fn next_stays_inside_the_application() {
        assert_eq!(sanitize_next(Some("/api/tasks")), "/api/tasks");
        assert_eq!(sanitize_next(Some("/")), "/");
        assert_eq!(sanitize_next(None), "/");
        // Open-redirect attempts and a self-referencing target.
        assert_eq!(sanitize_next(Some("//evil.example/")), "/");
        assert_eq!(sanitize_next(Some("/\\evil.example/")), "/");
        assert_eq!(sanitize_next(Some("https://evil.example/")), "/");
        assert_eq!(sanitize_next(Some("evil.example")), "/");
        assert_eq!(sanitize_next(Some(LOGIN_PATH)), "/");
        assert_eq!(sanitize_next(Some("/x\r\nSet-Cookie: a=b")), "/");
    }

    #[test]
    fn the_login_page_escapes_what_it_reflects() {
        let html = page("t", &escape_html("<script>window.__FLAG__=1</script>"));
        assert!(!html.contains("<script>window"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn percent_encoding_keeps_paths_readable_and_escapes_the_rest() {
        assert_eq!(percent_encode("/api/tasks"), "/api/tasks");
        assert_eq!(percent_encode("/a b?c=d&e"), "/a%20b%3Fc%3Dd%26e");
    }
}
