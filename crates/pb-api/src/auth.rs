//! Request authentication: token extraction, record resolution and the
//! `RequireSuperuserAuth` guard.
//!
//! Mirrors `apis/middlewares.go` + `core.FindAuthRecordByToken`: the token is
//! parsed *unverified* first to learn which collection/record it belongs to, and
//! only then is the signature checked against `tokenKey + token secret`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use pb_core::collections::Collection;
use pb_core::records::Record;
use pb_core::tokens;
use rusqlite::Connection;

use crate::error::ApiError;

/// Everything a handler needs about the authenticated record.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub record: Record,
    pub collection: Collection,
}

impl AuthContext {
    pub fn is_superuser(&self) -> bool {
        self.collection.name == pb_core::superusers::COLLECTION_NAME_SUPERUSERS
    }
}

/// A small pool of SQLite connections so that concurrent requests are not
/// serialized on a single `Mutex<Connection>` (the main latency bottleneck
/// versus the Go oracle, which uses `database/sql`'s connection pool).
#[derive(Clone)]
pub struct Db {
    path: std::sync::Arc<PathBuf>,
    pool: Arc<Mutex<Vec<Connection>>>,
}

impl Db {
    pub fn open(path: &Path, size: usize) -> anyhow::Result<Self> {
        // A fresh pool means a fresh process-level view of `_collections`;
        // drop anything cached for a database path that was reopened.
        pb_core::collections::Collection::invalidate_cache();
        let mut conns = Vec::with_capacity(size.max(1));
        for _ in 0..size.max(1) {
            conns.push(pb_core::db::open(path)?);
        }
        Ok(Self {
            path: std::sync::Arc::from(path.to_path_buf()),
            pool: Arc::new(Mutex::new(conns)),
        })
    }

    /// Check out one connection. The connection is returned to the pool when
    /// the guard is dropped.
    pub fn lock(&self) -> Result<PooledConn, ()> {
        let mut guard = self.pool.lock().map_err(|_| ())?;
        let conn = if let Some(c) = guard.pop() {
            c
        } else {
            drop(guard);
            // Pool exhausted: open a fresh connection on demand.
            pb_core::db::open(&self.path).map_err(|_| ())?
        };
        Ok(PooledConn {
            pool: self.pool.clone(),
            conn: Some(conn),
        })
    }
}

pub struct PooledConn {
    pool: Arc<Mutex<Vec<Connection>>>,
    conn: Option<Connection>,
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if let Ok(mut guard) = self.pool.lock() {
                guard.push(conn);
            }
        }
    }
}

impl std::ops::Deref for PooledConn {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("pooled connection present")
    }
}

impl std::ops::DerefMut for PooledConn {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("pooled connection present")
    }
}

/// `getAuthTokenFromRequest`: the raw header, with an optional `Bearer ` prefix.
pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    if raw.is_empty() {
        return None;
    }
    if raw.len() > 7 && raw[..7].eq_ignore_ascii_case("Bearer ") {
        return Some(raw[7..].to_string());
    }
    Some(raw.to_string())
}

/// Resolve the auth record for a request, if any.
///
/// Invalid, expired or unknown tokens are silently ignored here — exactly like
/// the `loadAuthToken` middleware, which leaves `e.Auth` nil so that individual
/// handlers can decide how to respond. The global `rejectUnknownToken`
/// middleware (see [`reject_unknown_token`]) is what turns such tokens into a
/// `401` for routes that don't perform their own auth check.
pub fn load_auth(db: &Db, headers: &HeaderMap) -> Option<AuthContext> {
    let token = token_from_headers(headers)?;
    let conn = db.lock().ok()?;
    find_auth_record(&conn, &token, &[tokens::TYPE_AUTH]).ok()
}

/// `FindAuthRecordByToken`.
pub fn find_auth_record(
    conn: &Connection,
    token: &str,
    valid_types: &[&str],
) -> anyhow::Result<AuthContext> {
    let claims = tokens::parse_unverified(token)?;

    if claims.id.is_empty() || claims.collection_id.is_empty() || claims.kind.is_empty() {
        anyhow::bail!("missing or invalid token claims");
    }
    if !valid_types.is_empty() && !valid_types.contains(&claims.kind.as_str()) {
        anyhow::bail!("invalid token type");
    }

    let collection = Collection::find(conn, &claims.collection_id)?
        .ok_or_else(|| anyhow::anyhow!("collection not found"))?;
    if !collection.is_auth() {
        anyhow::bail!("the token is not associated to an auth collection record");
    }

    let record = Record::find_by_id(conn, &collection, &claims.id)?
        .ok_or_else(|| anyhow::anyhow!("record not found"))?;

    let secret = match claims.kind.as_str() {
        tokens::TYPE_AUTH => collection.token_secret("authToken"),
        tokens::TYPE_FILE => collection.token_secret("fileToken"),
        tokens::TYPE_VERIFICATION => collection.token_secret("verificationToken"),
        tokens::TYPE_PASSWORD_RESET => collection.token_secret("passwordResetToken"),
        tokens::TYPE_EMAIL_CHANGE => collection.token_secret("emailChangeToken"),
        other => anyhow::bail!("unknown token type {other}"),
    }
    .ok_or_else(|| anyhow::anyhow!("missing signing key"))?;

    let key = tokens::signing_key(record.token_key(), secret);
    tokens::parse_jwt(token, &key)?;

    Ok(AuthContext {
        record,
        collection,
    })
}

/// `rejectUnknownToken`: routes whose own middleware already rejects a missing
/// or invalid token with `"The request requires valid record authorization
/// token."` must keep that message.
///
/// Every other route (public endpoints, record CRUD, realtime, static files,
/// unknown paths, ...) gets the generic global error instead. The oracle binds
/// `rejectUnknownToken` with priority `9999`, i.e. *after* the route-specific
/// auth middlewares, which is why the message differs per route.
fn route_has_own_auth(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;

    let is = |m: &Method| method == m;

    if path == "/api/settings" {
        return is(&Method::GET) || is(&Method::PATCH);
    }
    if path == "/api/settings/test/email"
        || path == "/api/settings/test/s3"
        || path == "/api/settings/apple/generate-client-secret"
    {
        return is(&Method::POST);
    }

    if path == "/api/backups" {
        return is(&Method::GET) || is(&Method::POST);
    }
    if path == "/api/backups/upload" {
        return is(&Method::POST);
    }

    if path == "/api/sql" {
        return is(&Method::POST);
    }
    if path == "/api/files/token" {
        return is(&Method::POST);
    }

    if path == "/api/logs" {
        return is(&Method::GET) || is(&Method::DELETE);
    }
    if path == "/api/logs/stats" {
        return is(&Method::GET);
    }

    let rest = match path.strip_prefix("/api/backups/") {
        Some(rest) if !rest.is_empty() => Some(rest),
        _ => None,
    };
    if let Some(rest) = rest {
        let mut segments = rest.split('/');
        let key = segments.next().unwrap_or("");
        match (segments.next(), segments.next()) {
            (None, None) if !key.is_empty() => return is(&Method::DELETE),
            (Some("restore"), None) if !key.is_empty() => return is(&Method::POST),
            _ => {}
        }
    }

    if path == "/api/crons" {
        return is(&Method::GET);
    }
    if let Some(rest) = path.strip_prefix("/api/crons/") {
        if !rest.is_empty() && !rest.contains('/') {
            return is(&Method::POST);
        }
    }

    if let Some(rest) = path.strip_prefix("/api/logs/") {
        if !rest.is_empty() && !rest.contains('/') {
            return is(&Method::GET);
        }
    }

    let Some(rest) = path.strip_prefix("/api/collections") else {
        return false;
    };
    if rest.is_empty() {
        return is(&Method::GET) || is(&Method::POST);
    }
    let Some(rest) = rest.strip_prefix('/') else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let segments: Vec<&str> = rest.split('/').collect();

    // `/api/collections/meta/*`
    if segments.first() == Some(&"meta") {
        return match (segments.get(1).copied(), segments.len()) {
            (Some("scaffolds"), 2) => is(&Method::GET),
            (Some("oauth2-providers"), 2) => is(&Method::GET),
            (Some("dry-run-view"), 2) => is(&Method::POST),
            _ => false,
        };
    }
    if segments.len() == 1 && segments[0] == "import" {
        return is(&Method::PUT);
    }
    if segments.len() == 1 {
        return is(&Method::GET) || is(&Method::PATCH) || is(&Method::DELETE);
    }
    if segments.len() == 2 && segments[1] == "truncate" {
        return is(&Method::DELETE);
    }
    // `record_auth.go` binds `RequireSameCollectionContextAuth` on these two
    // handlers, so their own 401 message wins over the global rejection.
    if segments.len() == 2
        && (segments[1] == "auth-refresh" || segments[1] == "request-email-change")
    {
        return is(&Method::POST);
    }
    if segments.len() == 3 && segments[1] == "impersonate" {
        return is(&Method::POST);
    }

    false
}

/// Global `rejectUnknownToken` middleware.
///
/// A request that carries an `Authorization` value but no resolvable auth
/// record is rejected with `401 {"data":{},"message":"Missing or invalid
/// authentication.","status":401}`. An empty header behaves like no header.
/// CORS preflight and the `/_` -> `/_/` redirect are handled before this
/// middleware by the oracle as well.
pub async fn reject_unknown_token(
    axum::extract::State(db): axum::extract::State<Db>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::Method;
    use axum::response::IntoResponse;

    if request.method() == Method::OPTIONS || request.uri().path() == "/_" {
        return next.run(request).await;
    }

    let Some(token) = token_from_headers(request.headers()) else {
        return next.run(request).await;
    };
    if route_has_own_auth(request.method(), request.uri().path()) {
        return next.run(request).await;
    }

    let valid = {
        let Ok(conn) = db.lock() else {
            return next.run(request).await;
        };
        find_auth_record(&conn, &token, &[tokens::TYPE_AUTH]).is_ok()
    };
    if valid {
        return next.run(request).await;
    }

    ApiError::unauthorized("Missing or invalid authentication.")
        .with_raw_data(serde_json::json!("unknown authorization token"))
        .into_response()
}

/// `RequireSuperuserAuth`.
pub fn require_superuser(db: &Db, headers: &HeaderMap) -> Result<AuthContext, ApiError> {
    let auth = load_auth(db, headers).ok_or_else(|| {
        ApiError::unauthorized("The request requires valid record authorization token.")
    })?;
    if !auth.is_superuser() {
        return Err(ApiError::forbidden(
            "The authorized record is not allowed to perform this action.",
        ));
    }
    Ok(auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use axum::response::IntoResponse;

    fn own(method: Method, path: &str) -> bool {
        route_has_own_auth(&method, path)
    }

    #[test]
    fn routes_with_their_own_auth_keep_the_specific_message() {
        for (method, path) in [
            (Method::GET, "/api/settings"),
            (Method::PATCH, "/api/settings"),
            (Method::POST, "/api/settings/test/email"),
            (Method::POST, "/api/settings/test/s3"),
            (Method::POST, "/api/settings/apple/generate-client-secret"),
            (Method::GET, "/api/collections"),
            (Method::POST, "/api/collections"),
            (Method::PUT, "/api/collections/import"),
            (Method::GET, "/api/collections/meta/scaffolds"),
            (Method::POST, "/api/collections/meta/dry-run-view"),
            (Method::GET, "/api/collections/meta/oauth2-providers"),
            (Method::GET, "/api/collections/users"),
            (Method::PATCH, "/api/collections/users"),
            (Method::DELETE, "/api/collections/users"),
            (Method::DELETE, "/api/collections/users/truncate"),
            (Method::POST, "/api/collections/users/auth-refresh"),
            (Method::POST, "/api/collections/users/request-email-change"),
            (Method::POST, "/api/collections/users/impersonate/abc"),
            (Method::GET, "/api/backups"),
            (Method::POST, "/api/backups"),
            (Method::POST, "/api/backups/upload"),
            (Method::DELETE, "/api/backups/key"),
            (Method::POST, "/api/backups/key/restore"),
            (Method::GET, "/api/logs"),
            (Method::DELETE, "/api/logs"),
            (Method::GET, "/api/logs/stats"),
            (Method::GET, "/api/logs/abc"),
            (Method::GET, "/api/crons"),
            (Method::POST, "/api/crons/__pbDBOptimize__"),
            (Method::POST, "/api/sql"),
            (Method::POST, "/api/files/token"),
        ] {
            assert!(own(method.clone(), path), "{method} {path} must keep its own auth");
        }
    }

    #[test]
    fn public_routes_use_the_global_unknown_token_error() {
        for (method, path) in [
            (Method::GET, "/api/health"),
            (Method::GET, "/api/backups/key"),
            (Method::GET, "/api/files/users/rec/file.png"),
            (Method::GET, "/api/collections/users/records"),
            (Method::POST, "/api/collections/users/records"),
            (Method::GET, "/api/collections/users/records/abc"),
            (Method::GET, "/api/collections/users/auth-methods"),
            (Method::POST, "/api/collections/users/auth-with-password"),
            (Method::POST, "/api/batch"),
            (Method::GET, "/api/realtime"),
            (Method::POST, "/api/realtime"),
            (Method::GET, "/api/oauth2-redirect"),
            (Method::GET, "/api/does-not-exist"),
            (Method::GET, "/_/"),
            (Method::GET, "/"),
        ] {
            assert!(!own(method.clone(), path), "{method} {path} must use the global error");
        }
    }

    #[tokio::test]
    async fn unknown_token_error_has_the_oracle_shape() {
        let response = ApiError::unauthorized("Missing or invalid authentication.")
            .with_raw_data(serde_json::json!("unknown authorization token"))
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "data": {},
                "message": "Missing or invalid authentication.",
                "status": 401,
            })
        );
    }
}
