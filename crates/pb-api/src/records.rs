//! Record auth endpoints.
//!
//! M2a covers what the admin UI needs to log in: `auth-with-password`,
//! `auth-refresh` and `auth-methods`. OTP, OAuth2, MFA and the email flows are
//! later milestones.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::Json;
use pb_core::collections::Collection;
use pb_core::records::Record;
use pb_core::tokens::{self, RecordClaims};
use serde_json::{json, Map, Value};

use crate::auth::{load_auth, AuthContext, Db};
use crate::error::{validation_length, validation_required, ApiError};

/// `findAuthCollection`: 404 when the collection is missing or not an auth one.
fn find_auth_collection(conn: &rusqlite::Connection, id_or_name: &str) -> Result<Collection, ApiError> {
    Collection::find(conn, id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?
        .filter(Collection::is_auth)
        .ok_or_else(|| ApiError::not_found("Missing or invalid collection context."))
}

/// Reject non-JSON bodies the way `e.BindBody` does.
fn require_json(headers: &HeaderMap) -> Result<(), ApiError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.is_empty() {
        // An empty body is fine: validation reports the missing fields.
        return Ok(());
    }

    let lower = content_type.to_ascii_lowercase();
    if lower.starts_with("application/json") || lower.starts_with("text/plain") {
        return Ok(());
    }
    Err(ApiError::bad_request("Unsupported Content-Type."))
}

fn parse_json_body(body: &Bytes) -> Result<Map<String, Value>, ApiError> {
    if body.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(ApiError::body_load()),
    }
}

/// `validation.Length(1, 255)` + `validation.Required` for a string field.
fn validate_required_string(value: Option<&Value>, errors: &mut Map<String, Value>, name: &str) {
    let text = value.and_then(Value::as_str).unwrap_or("");
    if text.is_empty() {
        errors.insert(name.into(), validation_required());
    } else if text.chars().count() > 255 {
        errors.insert(name.into(), validation_length(1, 255));
    }
}

/// `GET /api/collections/{collection}/auth-methods`
pub async fn methods(
    State(db): State<Db>,
    Path(id_or_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    let password_auth = collection
        .options
        .get("passwordAuth")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let password_enabled = password_auth
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let identity_fields: Vec<Value> = if password_enabled {
        password_auth
            .get("identityFields")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    } else {
        vec![]
    };

    let otp = collection.options.get("otp").cloned().unwrap_or_else(|| json!({}));
    let mfa = collection.options.get("mfa").cloned().unwrap_or_else(|| json!({}));
    let otp_enabled = otp.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let mfa_enabled = mfa.get("enabled").and_then(Value::as_bool).unwrap_or(false);

    let has_email = identity_fields
        .iter()
        .any(|f| f.as_str() == Some("email"));
    let has_username = identity_fields
        .iter()
        .any(|f| f.as_str() == Some("username"));

    Ok(Json(json!({
        "password": {
            "identityFields": identity_fields,
            "enabled": password_enabled,
        },
        "oauth2": {"providers": [], "enabled": false},
        "mfa": {
            "enabled": mfa_enabled,
            "duration": if mfa_enabled {
                mfa.get("duration").and_then(Value::as_i64).unwrap_or(0)
            } else { 0 },
        },
        "otp": {
            "enabled": otp_enabled,
            "duration": if otp_enabled {
                otp.get("duration").and_then(Value::as_i64).unwrap_or(0)
            } else { 0 },
        },
        "authProviders": [],
        "usernamePassword": password_enabled && has_username,
        "emailPassword": password_enabled && has_email,
    })))
}

/// `POST /api/collections/{collection}/auth-with-password`
pub async fn with_password(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    let password_auth = collection
        .options
        .get("passwordAuth")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !password_auth
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ApiError::forbidden(
            "The collection is not configured to allow password authentication.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;

    let identity = form.get("identity").and_then(Value::as_str).unwrap_or("");
    let password = form.get("password").and_then(Value::as_str).unwrap_or("");
    let identity_field = form.get("identityField").and_then(Value::as_str);

    let mut errors = Map::new();
    validate_required_string(form.get("identity"), &mut errors, "identity");
    validate_required_string(form.get("password"), &mut errors, "password");
    if let Some(field) = identity_field {
        let allowed: Vec<&str> = password_auth
            .get("identityFields")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if field.is_empty() || field.chars().count() > 255 {
            errors.insert("identityField".into(), validation_length(1, 255));
        } else if !allowed.contains(&field) {
            errors.insert(
                "identityField".into(),
                json!({"code": "validation_in", "message": "Must be one of the following: email."}),
            );
        }
    }
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    // `findRecordByIdentityField` over the collection's identity fields, with
    // email lookup prioritized (as the oracle does).
    let mut identity_fields: Vec<String> = password_auth
        .get("identityFields")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    identity_fields.sort_by_key(|f| if f == "email" { 0 } else { 1 });

    let mut found: Option<Record> = None;
    for field in &identity_fields {
        let candidate = match field.as_str() {
            "email" => Record::find_by_email(&conn, &collection, identity),
            other => find_by_column(&conn, &collection, other, identity),
        }
        .map_err(|e| ApiError::internal(format!("failed to load record: {e}")))?;
        if candidate.is_some() {
            found = candidate;
            break;
        }
    }

    let Some(record) = found else {
        return Err(ApiError::bad_request("Failed to authenticate."));
    };
    if !record.validate_password(password) {
        return Err(ApiError::bad_request("Failed to authenticate."));
    }

    // `authRule`: "" allows everyone, null denies authentication entirely.
    match collection.options.get("authRule") {
        Some(Value::String(_)) | None => {}
        _ => {
            return Err(ApiError::forbidden(
                "The request doesn't satisfy the collection requirements to authenticate.",
            ))
        }
    }

    let token = auth_token(&collection, &record, true)?;
    Ok(Json(json!({
        "record": record.to_api_json(),
        "token": token,
    })))
}

/// `POST /api/collections/{collection}/auth-refresh`
pub async fn refresh(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Resolve the auth record first: `load_auth` takes the DB lock itself.
    let auth: AuthContext = load_auth(&db, &headers).ok_or_else(|| {
        ApiError::unauthorized("The request requires valid record authorization token.")
    })?;

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;

    let path_collection = Collection::find(&conn, &id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?;
    match &path_collection {
        Some(c) if c.id == auth.collection.id => {}
        _ => {
            return Err(ApiError::forbidden(format!(
                "The request requires auth record from {} collection.",
                auth.collection.name
            )))
        }
    }

    // Only tokens that explicitly allow refresh are renewed; the rest are
    // returned unchanged (e.g. impersonate tokens).
    let token = match tokens::parse_unverified(
        &crate::auth::token_from_headers(&headers).unwrap_or_default(),
    ) {
        Ok(claims) if claims.refreshable.unwrap_or(false) => {
            auth_token(&auth.collection, &auth.record, true)?
        }
        _ => crate::auth::token_from_headers(&headers).unwrap_or_default(),
    };

    Ok(Json(json!({
        "record": auth.record.to_api_json(),
        "token": token,
    })))
}

fn auth_token(
    collection: &Collection,
    record: &Record,
    refreshable: bool,
) -> Result<String, ApiError> {
    let secret = collection
        .token_secret("authToken")
        .ok_or_else(|| ApiError::internal("Failed to create auth token."))?;
    let key = tokens::signing_key(record.token_key(), secret);
    let duration = collection.token_duration("authToken");
    tokens::new_jwt(
        &RecordClaims::auth(record.id(), &collection.id, refreshable),
        &key,
        duration,
    )
    .map_err(|e| ApiError::internal(format!("Failed to create auth token: {e}")))
}

fn find_by_column(
    conn: &rusqlite::Connection,
    collection: &Collection,
    column: &str,
    value: &str,
) -> anyhow::Result<Option<Record>> {
    let sql = format!(
        "SELECT * FROM {} WHERE {} = ?1 LIMIT 1",
        pb_core::records::quote_ident(&collection.name),
        pb_core::records::quote_ident(column)
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([value])?;
    match rows.next()? {
        Some(row) => Ok(Some(Record::from_row(collection, row)?)),
        None => Ok(None),
    }
}

/// Used by the router to keep `HeaderValue` in scope for future auth schemes.
#[allow(dead_code)]
fn bearer(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {value}")).ok()
}
