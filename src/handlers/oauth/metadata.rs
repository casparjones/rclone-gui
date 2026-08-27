//! The RFC 8414 authorization server metadata document.
//!
//! `GET /.well-known/oauth-authorization-server`. This is the whole reason a
//! user can paste one URL and be done: everything else in the pairing flow is
//! discovered from here.
//!
//! The document is **public and contains no secret** — that is what it is for.
//! It is also completely static apart from the issuer prefix, so it is
//! recomputed per request rather than cached in process; a handful of string
//! concatenations is cheaper than the invalidation logic a cache would need
//! when `Host` decides the prefix.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use super::{OAuthState, AUTHORIZATION_PATH, REGISTRATION_PATH, REVOCATION_PATH, TOKEN_PATH};

/// The scopes this server issues, in the order the parent ticket lists them.
///
/// `browse` lists folders; the three `rsync:*` scopes are read (pull), write
/// (push) and delete-in-target. Deleting is its own scope on purpose: it is the
/// one that can destroy data, and a peer that only ever pulls should not be
/// able to ask for it by accident.
pub const SUPPORTED_SCOPES: &[&str] = &["browse", "rsync:read", "rsync:write", "rsync:delete"];

/// The grant types this server will support.
///
/// `authorization_code` and `refresh_token`, and nothing else — OAuth 2.1
/// removes the implicit and the resource-owner-password grants, and the parent
/// ticket says so explicitly. Advertising them is how a client learns not to
/// try.
pub const SUPPORTED_GRANT_TYPES: &[&str] = &["authorization_code", "refresh_token"];

/// The response types this server will support. `code` only.
pub const SUPPORTED_RESPONSE_TYPES: &[&str] = &["code"];

/// How a client may authenticate at the token endpoint.
///
/// Both are the same credential over TLS; `basic` is the one RFC 6749 says a
/// server must accept, `post` is the one many clients actually send. `none`
/// (public client) is deliberately absent: both sides of this pairing are
/// servers, so there is no reason to allow a client without a secret.
pub const SUPPORTED_AUTH_METHODS: &[&str] = &["client_secret_basic", "client_secret_post"];

/// PKCE challenge methods. `S256` only.
///
/// `plain` is forbidden by OAuth 2.1 for anything but a client that cannot do
/// SHA-256, which does not exist here. Listing one value is also how a client
/// is told that PKCE is not optional.
pub const SUPPORTED_CODE_CHALLENGE_METHODS: &[&str] = &["S256"];

/// The metadata document.
///
/// Field names are fixed by RFC 8414 §2 and are what a foreign client reads, so
/// they are spelled exactly as the registry spells them. `issuer`,
/// `authorization_endpoint`, `token_endpoint` and `response_types_supported`
/// are the mandatory four; the rest are the ones that save a client from
/// guessing.
///
/// No `Debug`: several field names here contain a stem the leak guard treats as
/// suspicious (`token_endpoint_auth_methods_supported`, `registration_endpoint`
/// via `uri`-adjacent naming), and nothing in this module needs a derived one.
#[derive(Serialize, Clone)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub revocation_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

/// Build the document for one issuer.
///
/// Split out from the handler so it can be asserted on directly, without a
/// router and without a database.
pub fn metadata_for(issuer: &str) -> AuthorizationServerMetadata {
    let endpoint = |path: &str| format!("{issuer}{path}");
    let list = |values: &[&str]| values.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    AuthorizationServerMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: endpoint(AUTHORIZATION_PATH),
        token_endpoint: endpoint(TOKEN_PATH),
        registration_endpoint: endpoint(REGISTRATION_PATH),
        revocation_endpoint: endpoint(REVOCATION_PATH),
        scopes_supported: list(SUPPORTED_SCOPES),
        response_types_supported: list(SUPPORTED_RESPONSE_TYPES),
        response_modes_supported: vec!["query".to_string()],
        grant_types_supported: list(SUPPORTED_GRANT_TYPES),
        token_endpoint_auth_methods_supported: list(SUPPORTED_AUTH_METHODS),
        // The same credential authenticates a revocation (RFC 7009 §2.1).
        revocation_endpoint_auth_methods_supported: list(SUPPORTED_AUTH_METHODS),
        code_challenge_methods_supported: list(SUPPORTED_CODE_CHALLENGE_METHODS),
    }
}

/// `GET /.well-known/oauth-authorization-server`.
///
/// Takes the state it does not use (`_state`) rather than none, so it can share
/// the router's state type with the registration handler. No database access:
/// the document depends on nothing that is stored, which is also why it cannot
/// fail.
pub async fn discovery(State(_state): State<OAuthState>, headers: HeaderMap) -> Response {
    let issuer = super::issuer(
        super::host_header(&headers),
        super::forwarded_proto(&headers),
    );

    let mut response = (StatusCode::OK, Json(metadata_for(&issuer))).into_response();

    // Public, unauthenticated and near-static. An hour keeps a chatty client
    // from asking on every operation without making a hostname change take a
    // day to propagate.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mandatory_field_is_present_and_absolute() {
        let doc = metadata_for("https://backup.example.org");
        let json = serde_json::to_value(&doc).expect("serialise");

        // RFC 8414 §2: these four are REQUIRED.
        for required in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "response_types_supported",
        ] {
            assert!(
                json.get(required).is_some(),
                "{required} is required by RFC 8414 and missing"
            );
        }

        // Every endpoint the far side is meant to call has to be a complete
        // URL, not a path — a client that only has our base URL cannot resolve
        // a relative one against the well-known path correctly.
        for field in [
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
            "revocation_endpoint",
        ] {
            let value = json[field].as_str().unwrap_or_default();
            assert!(
                value.starts_with("https://backup.example.org/"),
                "{field} must be absolute and under the issuer, got {value:?}"
            );
        }

        assert_eq!(json["issuer"], "https://backup.example.org");
        assert_eq!(
            json["token_endpoint"],
            "https://backup.example.org/oauth/token"
        );
        assert_eq!(
            json["registration_endpoint"],
            "https://backup.example.org/oauth/register"
        );
    }

    /// The endpoint paths in the document must be the paths the router actually
    /// serves. Two string constants drifting apart would produce a document
    /// that looks valid and points nowhere.
    #[test]
    fn the_advertised_paths_are_the_routers_paths() {
        let doc = metadata_for("https://x.example");
        assert_eq!(
            doc.registration_endpoint,
            format!("https://x.example{}", super::super::REGISTRATION_PATH)
        );
        assert_eq!(
            doc.authorization_endpoint,
            format!("https://x.example{}", super::super::AUTHORIZATION_PATH)
        );
        assert_eq!(
            super::super::DISCOVERY_PATH,
            "/.well-known/oauth-authorization-server"
        );
    }

    /// OAuth 2.1 forbids the implicit and password grants and PKCE `plain`.
    /// Advertising any of them would invite a client to use them.
    #[test]
    fn nothing_that_oauth_21_removed_is_advertised() {
        let doc = metadata_for("https://x.example");
        for forbidden in ["implicit", "password", "token"] {
            assert!(
                !doc.grant_types_supported.iter().any(|g| g == forbidden),
                "{forbidden} must not be an advertised grant type"
            );
            assert!(
                !doc.response_types_supported.iter().any(|r| r == forbidden),
                "{forbidden} must not be an advertised response type"
            );
        }
        assert_eq!(
            doc.code_challenge_methods_supported,
            vec!["S256".to_string()]
        );
        assert!(
            !doc.token_endpoint_auth_methods_supported
                .iter()
                .any(|m| m == "none"),
            "both peers are servers; a public client has no place here"
        );
    }

    #[test]
    fn the_four_scopes_of_the_parent_ticket_are_advertised() {
        let doc = metadata_for("https://x.example");
        assert_eq!(
            doc.scopes_supported,
            vec!["browse", "rsync:read", "rsync:write", "rsync:delete"]
        );
    }

    /// A metadata document is read by other people's code and is served to
    /// anyone. If it ever grows a field carrying a credential, this is the test
    /// that should have been here.
    ///
    /// A plain substring search does **not** work and the first version of this
    /// test failed on the real document: `token_endpoint_auth_methods_supported`
    /// legitimately contains the string `client_secret_basic`. So the check is
    /// structural — no *key* may be a credential name, and no *value* may look
    /// like one of this server's secrets or ids (64 or 32 hex characters).
    #[test]
    fn the_document_carries_nothing_secret() {
        let doc = serde_json::to_value(metadata_for("https://x.example")).expect("serialise");
        let object = doc.as_object().expect("the document is a JSON object");

        for key in object.keys() {
            assert!(
                !matches!(
                    key.as_str(),
                    "client_secret" | "client_id" | "password" | "client_secret_hash"
                ),
                "the public metadata document must not carry a {key:?} member"
            );
        }

        fn looks_like_a_credential(value: &str) -> bool {
            matches!(value.len(), 32 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
        }

        let mut strings: Vec<&str> = Vec::new();
        for value in object.values() {
            match value {
                serde_json::Value::String(s) => strings.push(s),
                serde_json::Value::Array(items) => {
                    strings.extend(items.iter().filter_map(|i| i.as_str()));
                }
                _ => {}
            }
        }
        assert!(!strings.is_empty(), "the walk found nothing to check");
        for value in &strings {
            assert!(
                !looks_like_a_credential(value),
                "{value:?} has the shape of a client id or secret"
            );
        }

        // The counter-probe: the check above is able to fire.
        assert!(looks_like_a_credential(&"a1b2c3d4".repeat(8)));
        assert!(looks_like_a_credential(&"0".repeat(32)));
        assert!(!looks_like_a_credential("https://x.example/oauth/token"));
    }
}
