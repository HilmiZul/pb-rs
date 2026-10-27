//! Record auth endpoints.
//!
//! M2a covers what the admin UI needs to log in: `auth-with-password`,
//! `auth-refresh` and `auth-methods`. OTP, OAuth2, MFA and the email flows are
//! later milestones.

use axum::body::Bytes;
use std::sync::OnceLock;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::Json;
use pb_core::collections::Collection;
use pb_core::records::Record;
use pb_core::search;
use pb_core::tokens::{self, RecordClaims};
use serde_json::{json, Map, Value};

use crate::auth::{load_auth, AuthContext, Db};
use crate::error::{validation_length, validation_required, ApiError};

pub static DATA_DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
pub static AUX_DB: OnceLock<std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>> = OnceLock::new();

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

/// `POST /api/collections/{collection}/request-otp`
pub async fn file_token(
    State(db): State<Db>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let auth = crate::auth::load_auth(&db, &headers)
        .ok_or_else(|| ApiError::unauthorized("Missing auth context."))?;
    let file_token = pb_core::tokens::new_jwt(
        &pb_core::tokens::RecordClaims {
            kind: pb_core::tokens::TYPE_FILE.into(),
            id: auth.record.id().to_string(),
            collection_id: auth.collection.id.clone(),
            refreshable: None,
            email: None,
            new_email: None,
            exp: 0,
        },
        &pb_core::tokens::signing_key(auth.record.token_key(), auth.collection.token_secret("fileToken").unwrap_or("")),
        auth.collection.token_duration("fileToken"),
    )
    .map_err(|e| ApiError::internal(format!("Failed to generate file token: {e}")))?;
    Ok(Json(json!({"token": file_token})))
}

pub async fn file_download(
    State(db): State<Db>,
    headers: HeaderMap,
    Path((collection_name, record_id, filename)): Path<(String, String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::response::Response, ApiError> {
    use axum::http::header;
    let conn = db.lock().map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = Collection::find(&conn, &collection_name)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found."))?;
    let record = Record::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found."))?;
    drop(conn);

    let storage_root = DATA_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("pb_data"))
        .join("storage");
    let file_path = storage_root
        .join(&collection.id)
        .join(&record_id)
        .join(&filename);

    let thumb_size = params.get("thumb").cloned().unwrap_or_default();

    let mut served_path = file_path.clone();
    let mut served_name = filename.clone();

    if !thumb_size.is_empty() {
        // check if image content type
        let is_image = filename.ends_with(".png")
            || filename.ends_with(".jpg")
            || filename.ends_with(".jpeg")
            || filename.ends_with(".gif")
            || filename.ends_with(".webp");
        if is_image {
            let thumb_dir = storage_root
                .join(&collection.id)
                .join(&record_id)
                .join(format!("thumbs_{}", filename));
            let thumb_path = thumb_dir.join(format!("{}_{}", thumb_size, filename));
            if !thumb_path.exists() {
                // generate
                let img = image::open(&file_path).ok();
                if let Some(img) = img {
                    // parse size
                    let size_str = thumb_size.trim_end_matches(['t', 'b', 'f']);
                    let parts: Vec<&str> = size_str.split('x').collect();
                    if parts.len() == 2 {
                        let w: u32 = parts[0].parse().unwrap_or(0);
                        let h: u32 = parts[1].parse().unwrap_or(0);
                        if w > 0 && h > 0 {
                            let thumb = img.thumbnail(w, h);
                            std::fs::create_dir_all(&thumb_dir).ok();
                            let _ = thumb.save(&thumb_path);
                        }
                    }
                }
            }
            if thumb_path.exists() {
                served_path = thumb_path;
                served_name = format!("{}_{}", thumb_size, filename);
            }
        }
    }

    let data = std::fs::read(&served_path)
        .map_err(|_| ApiError::not_found("The requested resource wasn't found."))?;

    let content_type = if served_name.ends_with(".png") {
        "image/png"
    } else if served_name.ends_with(".jpg") || served_name.ends_with(".jpeg") {
        "image/jpeg"
    } else if served_name.ends_with(".gif") {
        "image/gif"
    } else if served_name.ends_with(".webp") {
        "image/webp"
    } else {
        "application/octet-stream"
    };

    let resp = axum::response::Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, content_type)
        .body(axum::body::Body::from(data))
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(resp)
}

pub async fn request_otp(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    let otp_config = collection
        .options
        .get("otp")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !otp_config
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ApiError::forbidden(
            "The collection is not configured to allow OTP authentication.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let email = form.get("email").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    validate_required_string(form.get("email"), &mut errors, "email");
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    // find the auth record by email (ignore not found)
    let record = Record::find_by_email(&conn, &collection, email)
        .map_err(|e| ApiError::internal(format!("failed to load record: {e}")))?;

    // enumeration protection: missing record still returns 200 with a dummy id
    let Some(record) = record else {
        return Ok(Json(json!({"otpId": pb_core::ids::default_random_id()})));
    };

    let length = otp_config
        .get("length")
        .and_then(Value::as_i64)
        .unwrap_or(6) as usize;
    let password = pb_core::ids::random_string_with_alphabet(length, "1234567890");

    // hash the password via the _otps collection's password field (cost 10)
    let otps_collection = Collection::find(&conn, "_otps")
        .map_err(|e| ApiError::internal(format!("failed to load otps collection: {e}")))?
        .ok_or_else(|| ApiError::internal("missing _otps collection"))?;

    let hash = pb_core::record_upsert::hash_password(&password, 10);

    // insert OTP row
    conn.execute(
        "INSERT INTO _otps (collectionRef, recordRef, password, sentTo, created, updated)
         VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%d %H:%M:%fZ','now'), strftime('%Y-%m-%d %H:%M:%fZ','now'))",
        rusqlite::params![collection.id, record.id(), hash, ""],
    )
    .map_err(|e| ApiError::internal(format!("failed to create otp: {e}")))?;

    let otp_id: String = conn
        .query_row(
            "SELECT id FROM _otps WHERE rowid = last_insert_rowid()",
            [],
            |r| r.get(0),
        )
        .map_err(|e| ApiError::internal(format!("failed to read otp id: {e}")))?;

    // email sending stubbed (fire-and-forget no-op)
    let _ = (otps_collection, email, password);

    Ok(Json(json!({"otpId": otp_id})))
}

/// `POST /api/collections/{collection}/auth-with-otp`
pub async fn auth_with_otp(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    let otp_config = collection
        .options
        .get("otp")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !otp_config
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ApiError::forbidden(
            "The collection is not configured to allow OTP authentication.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let otp_id = form.get("otpId").and_then(Value::as_str).unwrap_or("");
    let password = form.get("password").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    validate_required_string(form.get("otpId"), &mut errors, "otpId");
    if let Some(p) = form.get("password").and_then(Value::as_str) {
        if p.is_empty() {
            errors.insert("password".into(), validation_required());
        } else if p.chars().count() > 71 {
            errors.insert("password".into(), validation_length(1, 71));
        }
    } else {
        errors.insert("password".into(), validation_required());
    }
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    let otps_collection = Collection::find(&conn, "_otps")
        .map_err(|e| ApiError::internal(format!("failed to load otps collection: {e}")))?
        .ok_or_else(|| ApiError::internal("missing _otps collection"))?;

    let otp_record = Record::find_by_id(&conn, &otps_collection, otp_id)
        .map_err(|e| ApiError::internal(format!("failed to load otp: {e}")))?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired OTP"))?;

    let otp_collection_ref = otp_record
        .to_api_json()
        .get("collectionRef")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if otp_collection_ref != collection.id {
        return Err(ApiError::bad_request("Invalid or expired OTP"));
    }

    // expiry check
    let duration = otp_config.get("duration").and_then(Value::as_i64).unwrap_or(0);
    let expired: i64 = conn
        .query_row(
            "SELECT CASE WHEN datetime(created, '+' || ?2 || ' seconds') < datetime('now') THEN 1 ELSE 0 END FROM _otps WHERE id = ?1",
            rusqlite::params![otp_id, duration],
            |r| r.get(0),
        )
        .unwrap_or(1);
    if expired == 1 {
        return Err(ApiError::bad_request("Invalid or expired OTP"));
    }

    let record_id = otp_record
        .to_api_json()
        .get("recordRef")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let record = Record::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(format!("failed to load record: {e}")))?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired OTP"))?;

    if !otp_record.validate_password(password) {
        return Err(ApiError::bad_request("Invalid or expired OTP"));
    }

    // delete the OTP
    conn.execute("DELETE FROM _otps WHERE id = ?1", [otp_id])
        .map_err(|e| ApiError::internal(format!("failed to delete otp: {e}")))?;

    // verified state update (only if sentTo matches email); sentTo is "" here so skip

    let mfa_id_req = form.get("mfaId").and_then(Value::as_str).unwrap_or("").to_string();
    match check_mfa(&conn, &collection, &record, "otp", &mfa_id_req)? {
        Some(mfa_id) => {
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, "", json!({"mfaId": mfa_id})));
        }
        None => {}
    }

    let token = auth_token(&collection, &record, true)?;
    Ok(Json(json!({
        "record": record.to_api_json(),
        "token": token,
    })))
}

pub async fn request_password_reset(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
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
        return Err(ApiError::bad_request(
            "The collection is not configured to allow password authentication.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let email = form.get("email").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    validate_required_string(form.get("email"), &mut errors, "email");
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    let record = Record::find_by_email(&conn, &collection, email)
        .map_err(|e| ApiError::internal(format!("failed to load record: {e}")))?;

    if record.is_none() {
        return Ok(StatusCode::NO_CONTENT);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn confirm_password_reset(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let token = form.get("token").and_then(Value::as_str).unwrap_or("");
    let password = form.get("password").and_then(Value::as_str).unwrap_or("");
    let password_confirm = form.get("passwordConfirm").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    if token.is_empty() {
        errors.insert("token".into(), validation_required());
    }
    if password.is_empty() {
        errors.insert("password".into(), validation_required());
    } else if password.chars().count() > 255 {
        errors.insert("password".into(), validation_length(1, 255));
    }
    if password_confirm.is_empty() {
        errors.insert("passwordConfirm".into(), validation_required());
    } else if password_confirm != password {
        errors.insert(
            "passwordConfirm".into(),
            json!({"code": "validation_values_mismatch", "message": "The values do not match."}),
        );
    }
    let mut token_record: Option<pb_core::records::Record> = None;
    if !token.is_empty() {
        match pb_core::records::Record::find_auth_record_by_token(&conn, token, &["passwordReset"]) {
            Ok(Some(r)) => {
                if r.collection.id != collection.id {
                    errors.insert(
                        "token".into(),
                        json!({"code": "validation_token_collection_mismatch", "message": "The provided token is for different auth collection."}),
                    );
                } else {
                    token_record = Some(r);
                }
            }
            _ => {
                errors.insert(
                    "token".into(),
                    json!({"code": "validation_invalid_token", "message": "Invalid or expired token."}),
                );
            }
        }
    }
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    let record = token_record
        .ok_or_else(|| ApiError::bad_request("Invalid or expired password reset token."))?;
    let hash = pb_core::record_upsert::hash_password(password, 10);

    let mut new_verified = record.to_api_json().get("verified").and_then(Value::as_bool).unwrap_or(false);
    if !new_verified {
        if let Ok(claims) = pb_core::tokens::parse_unverified(token) {
            if let Some(email_claim) = claims.email {
    let rec_email = record.to_api_json();
    let rec_email = rec_email.get("email").and_then(Value::as_str).unwrap_or("");
    if rec_email == email_claim {
                    new_verified = true;
                }
            }
        }
    }

    conn.execute(
        &format!(
            "UPDATE {} SET password = ?1, verified = ?2 WHERE id = ?3",
            pb_core::records::quote_ident(&collection.name)
        ),
        rusqlite::params![hash, new_verified as i64, record.id()],
    )
    .map_err(|e| ApiError::internal(format!("failed to update password: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn request_verification(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    if collection.name == "_superusers" {
        return Err(ApiError::bad_request(
            "All superusers are verified by default.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let email = form.get("email").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    validate_required_string(form.get("email"), &mut errors, "email");
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    let record = Record::find_by_email(&conn, &collection, email)
        .map_err(|e| ApiError::internal(format!("failed to load record: {e}")))?;

    if record.is_none() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let record = record.unwrap();
    if record.to_api_json().get("verified").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(StatusCode::NO_CONTENT);
    }

    // email sending stubbed (no-op)
    Ok(StatusCode::NO_CONTENT)
}

pub async fn confirm_verification(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    if collection.name == "_superusers" {
        return Err(ApiError::bad_request(
            "All superusers are verified by default.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let token = form.get("token").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    if token.is_empty() {
        errors.insert("token".into(), validation_required());
    } else {
        // checkToken logic
        let claims = pb_core::tokens::parse_unverified(token).ok();
        let email_claim = claims.as_ref().and_then(|c| c.email.clone()).unwrap_or_default();
        if email_claim.is_empty() {
            errors.insert(
                "token".into(),
                json!({"code": "validation_invalid_token_claims", "message": "Missing email token claim."}),
            );
        } else {
            match pb_core::records::Record::find_auth_record_by_token(&conn, token, &["verification"]) {
                Ok(Some(r)) => {
                    if r.collection.id != collection.id {
                        errors.insert(
                            "token".into(),
                            json!({"code": "validation_token_collection_mismatch", "message": "The provided token is for different auth collection."}),
                        );
                    } else {
                        let rec_json = r.to_api_json();
                        let rec_email = rec_json.get("email").and_then(Value::as_str).unwrap_or("");
                        if rec_email != email_claim {
                            errors.insert(
                                "token".into(),
                                json!({"code": "validation_token_email_mismatch", "message": "The record email doesn't match with the requested token claims."}),
                            );
                        }
                    }
                }
                _ => {
                    errors.insert(
                        "token".into(),
                        json!({"code": "validation_invalid_token", "message": "Invalid or expired token."}),
                    );
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    let record = pb_core::records::Record::find_auth_record_by_token(&conn, token, &["verification"])
        .map_err(|_| ApiError::bad_request("Invalid or expired verification token."))?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired verification token."))?;

    let was_verified = record.to_api_json().get("verified").and_then(Value::as_bool).unwrap_or(false);

    if !was_verified {
        let hash = record.to_api_json().get("password").and_then(Value::as_str).unwrap_or("").to_string();
        // set verified=true; password unchanged (unless password auth disabled, then random password)
        let password_auth_enabled = collection
            .options
            .get("passwordAuth")
            .and_then(|o| o.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let new_password = if !password_auth_enabled {
            pb_core::record_upsert::hash_password(&pb_core::ids::random_string(30), 10)
        } else {
            hash
        };
        conn.execute(
            &format!(
                "UPDATE {} SET verified = 1, password = ?1 WHERE id = ?2",
                pb_core::records::quote_ident(&collection.name)
            ),
            rusqlite::params![new_password, record.id()],
        )
        .map_err(|e| ApiError::internal(format!("failed to update record: {e}")))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn request_email_change(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let auth: crate::auth::AuthContext = crate::auth::load_auth(&db, &headers)
        .ok_or_else(|| ApiError::unauthorized("The request requires valid record authorization token."))?;

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    if collection.name == "_superusers" {
        return Err(ApiError::bad_request(
            "All superusers can change their emails directly.",
        ));
    }
    if auth.collection.id != collection.id {
        return Err(ApiError::forbidden(format!(
            "The request requires auth record from {} collection.",
            collection.name
        )));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let new_email = form.get("newEmail").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    validate_required_string(form.get("newEmail"), &mut errors, "newEmail");
    // email validation basic
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    // email sending stubbed (no-op)
    let _ = new_email;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn confirm_email_change(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    if collection.name == "_superusers" {
        return Err(ApiError::bad_request(
            "All superusers can change their emails directly.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let token = form.get("token").and_then(Value::as_str).unwrap_or("");
    let password = form.get("password").and_then(Value::as_str).unwrap_or("");

    let mut errors = Map::new();
    if token.is_empty() {
        errors.insert("token".into(), validation_required());
    }
    if password.is_empty() {
        errors.insert("password".into(), validation_required());
    }
    if !errors.is_empty() {
        return Err(ApiError::validation(Value::Object(errors)));
    }

    // parse token
    let claims = pb_core::tokens::parse_unverified(token).ok();
    let new_email = claims.as_ref().and_then(|c| c.new_email.clone()).unwrap_or_default();
    if new_email.is_empty() {
        errors.insert(
            "token".into(),
            json!({"code": "validation_invalid_token_payload", "message": "Invalid token payload - newEmail must be set."}),
        );
        return Err(ApiError::validation(Value::Object(errors)));
    }

    let record = pb_core::records::Record::find_auth_record_by_token(&conn, token, &["emailChange"])
        .map_err(|_| ApiError::bad_request("Invalid or expired token."))?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired token."))?;

    if record.collection.id != collection.id {
        errors.insert(
            "token".into(),
            json!({"code": "validation_token_collection_mismatch", "message": "The provided token is for different auth collection."}),
        );
        return Err(ApiError::validation(Value::Object(errors)));
    }

    // check password
    if !record.validate_password(password) {
        errors.insert(
            "password".into(),
            json!({"code": "validation_invalid_password", "message": "Missing or invalid auth record password."}),
        );
        return Err(ApiError::validation(Value::Object(errors)));
    }

    // check if new email already used
    if Record::find_by_email(&conn, &collection, &new_email)
        .map_err(|e| ApiError::internal(format!("failed to load record: {e}")))?
        .is_some()
    {
        errors.insert(
            "token".into(),
            json!({"code": "validation_invalid_token_email", "message": "The new email address is invalid."}),
        );
        return Err(ApiError::validation(Value::Object(errors)));
    }

    // update record
    let hash_check = record.to_api_json().get("password").and_then(Value::as_str).unwrap_or("").to_string();
    let _ = hash_check;
    conn.execute(
        &format!(
            "UPDATE {} SET email = ?1, verified = 1 WHERE id = ?2",
            pb_core::records::quote_ident(&collection.name)
        ),
        rusqlite::params![new_email, record.id()],
    )
    .map_err(|e| ApiError::internal(format!("failed to update record: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn auth_with_oauth2(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_auth_collection(&conn, &id_or_name)?;

    let oauth2_config = collection
        .options
        .get("oauth2")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !oauth2_config
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ApiError::forbidden(
            "The collection is not configured to allow OAuth2 authentication.",
        ));
    }

    require_json(&headers)?;
    let form = parse_json_body(&body)?;
    let provider_name = form.get("provider").and_then(Value::as_str).unwrap_or("");
    let code = form.get("code").and_then(Value::as_str).unwrap_or("");
    let code_verifier = form.get("codeVerifier").and_then(Value::as_str).unwrap_or("");
    let redirect_url = form
        .get("redirectURL")
        .or_else(|| form.get("redirectUrl"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if provider_name.is_empty() || code.is_empty() {
        let mut errors = Map::new();
        if provider_name.is_empty() {
            errors.insert("provider".into(), validation_required());
        }
        if code.is_empty() {
            errors.insert("code".into(), validation_required());
        }
        return Err(ApiError::validation(Value::Object(errors)));
    }

    let providers = oauth2_config
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let provider_config = providers
        .iter()
        .find(|p| p.get("name").and_then(Value::as_str) == Some(provider_name))
        .cloned()
        .ok_or_else(|| ApiError::internal("Missing or invalid provider config."))?;

    let client_id = provider_config.get("clientId").and_then(Value::as_str).unwrap_or("");
    let client_secret = provider_config.get("clientSecret").and_then(Value::as_str).unwrap_or("");
    let token_url = provider_config.get("tokenURL").and_then(Value::as_str).unwrap_or("");
    let user_info_url = provider_config.get("userInfoURL").and_then(Value::as_str).unwrap_or("");

    let body_str = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
        urlencoding::encode(code),
        urlencoding::encode(&redirect_url),
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret)
    );
    let body_str = if !code_verifier.is_empty() {
        format!("{}&code_verifier={}", body_str, urlencoding::encode(code_verifier))
    } else {
        body_str
    };

    let mut resp = ureq::post(token_url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(&body_str)
        .map_err(|e| ApiError::bad_request(format!("Failed to fetch OAuth2 token: {e}")))?;
    let token_text = resp.body_mut().read_to_string().map_err(|e| ApiError::bad_request(format!("Failed to fetch OAuth2 token: {e}")))?;
    let token_json: Value = serde_json::from_str(&token_text)
        .map_err(|e| ApiError::bad_request(format!("Failed to fetch OAuth2 token: {e}")))?;
    let access_token = token_json
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if access_token.is_empty() {
        return Err(ApiError::bad_request("Failed to fetch OAuth2 token."));
    }

    let mut user_resp = ureq::get(user_info_url)
        .header("Authorization", &format!("Bearer {}", access_token))
        .call()
        .map_err(|e| ApiError::bad_request(format!("Failed to fetch OAuth2 user: {e}")))?;
    let user_text = user_resp.body_mut().read_to_string().map_err(|e| ApiError::bad_request(format!("Failed to fetch OAuth2 user: {e}")))?;
    let user_json: Value = serde_json::from_str(&user_text)
        .map_err(|e| ApiError::bad_request(format!("Failed to fetch OAuth2 user: {e}")))?;

    let provider_user_id = user_json
        .get("id")
        .or_else(|| user_json.get("sub"))
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default();
    let email = user_json.get("email").and_then(Value::as_str).unwrap_or("").to_string();
    let name = user_json
        .get("name")
        .or_else(|| user_json.get("login"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut record_ref: Option<String> = None;
    let ext_sql = "SELECT recordRef FROM _externalAuths WHERE collectionRef = ?1 AND provider = ?2 AND providerId = ?3 LIMIT 1";
    if let Ok(rr) = conn.query_row(
        ext_sql,
        rusqlite::params![collection.id, provider_name, provider_user_id],
        |r| r.get::<_, String>(0),
    ) {
        record_ref = Some(rr);
    }

    let mut auth_record: Option<Record> = None;
    if let Some(rr) = &record_ref {
        auth_record = Record::find_by_id(&conn, &collection, rr)
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    if auth_record.is_none() {
        if let Some(auth) = crate::auth::load_auth(&db, &headers) {
            if auth.collection.id == collection.id {
                auth_record = Some(auth.record);
            }
        }
    }

    if auth_record.is_none() && !email.is_empty() {
        auth_record = Record::find_by_email(&conn, &collection, &email)
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    let is_new = auth_record.is_none();

    if auth_record.is_none() {
        let id = pb_core::ids::default_random_id();
        let mut cols = vec!["id".to_string()];
        let mut placeholders = vec!["?1".to_string()];
        let mut params: Vec<Value> = vec![Value::String(id.clone())];

        let create_data = form.get("createData").cloned().unwrap_or(Value::Null);
        let mut fields = Map::new();
        if let Some(obj) = create_data.as_object() {
            for (k, v) in obj {
                fields.insert(k.clone(), v.clone());
            }
        }
        if !email.is_empty() {
            fields.insert("email".into(), Value::String(email.clone()));
        }
        if !name.is_empty() {
            for key in ["name", "username"] {
                if collection.field_list().items().iter().any(|f| pb_core::fields::field_name(f) == key) {
                    fields.entry(key.to_string()).or_insert(Value::String(name.clone()));
                }
            }
        }

        for (k, v) in &fields {
            cols.push(k.clone());
            placeholders.push(format!("?{}", params.len() + 1));
            params.push(v.clone());
        }
        if collection.field_list().items().iter().any(|f| pb_core::fields::field_name(f) == "tokenKey") {
            cols.push("tokenKey".into());
            placeholders.push(format!("?{}", params.len() + 1));
            params.push(Value::String(pb_core::ids::random_string(50)));
        }
        if collection.field_list().items().iter().any(|f| pb_core::fields::field_name(f) == "verified") {
            cols.push("verified".into());
            placeholders.push(format!("?{}", params.len() + 1));
            params.push(Value::Bool(true));
        }

        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            pb_core::records::quote_ident(&collection.name),
            cols.iter().map(|c| pb_core::records::quote_ident(c)).collect::<Vec<_>>().join(", "),
            placeholders.join(", ")
        );
        let sql_params: Vec<rusqlite::types::Value> = params.iter().map(json_to_sqlite).collect();
        conn.execute(&sql, rusqlite::params_from_iter(sql_params))
            .map_err(|e| ApiError::internal(format!("failed to create record: {e}")))?;

        auth_record = Record::find_by_id(&conn, &collection, &id)
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    let auth_record = auth_record.ok_or_else(|| ApiError::internal("failed to resolve auth record"))?;

    if is_new {
        let ext_id = pb_core::ids::default_random_id();
        conn.execute(
            "INSERT INTO _externalAuths (id, collectionRef, recordRef, provider, providerId, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%d %H:%M:%fZ','now'), strftime('%Y-%m-%d %H:%M:%fZ','now'))",
            rusqlite::params![ext_id, collection.id, auth_record.id(), provider_name, provider_user_id],
        )
        .map_err(|e| ApiError::internal(format!("failed to create external auth: {e}")))?;
    }

    let mut meta = Map::new();
    meta.insert("isNew".into(), Value::Bool(is_new));
    if let Some(obj) = user_json.as_object() {
        for (k, v) in obj {
            meta.insert(k.clone(), v.clone());
        }
    }

    let token = auth_token(&collection, &auth_record, true)?;
    Ok(Json(json!({
        "record": auth_record.to_api_json(),
        "token": token,
        "meta": meta,
    })))
}


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
    let mfa_id_req = form.get("mfaId").and_then(Value::as_str).unwrap_or("").to_string();

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

    // MFA check
    match check_mfa(&conn, &collection, &record, "password", &mfa_id_req)? {
        Some(mfa_id) => {
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, "", json!({"mfaId": mfa_id})));
        }
        None => {}
    }
    // MFA requires 401 status; adjust by returning unauthorized with body
    let _ = ();

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

// ---------------------------------------------------------------------------
// Records CRUD
// ---------------------------------------------------------------------------

use std::collections::HashMap;

use axum::extract::Query;
use pb_core::record_upsert::{AccessLevel, RecordModel, SubmitError, Visibility};
use pb_core::validation::errors_to_value;

const NOT_FOUND_MESSAGE: &str = "The requested resource wasn't found.";
const GENERIC_BAD_REQUEST: &str = "Something went wrong while processing your request.";

/// The per-request data that API rules and `@request.*` filters resolve
/// against (`core.RequestInfo`).
#[derive(Clone, Debug)]
struct RequestInfo {
    auth: Option<AuthContext>,
    body: Map<String, Value>,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    method: String,
    context: String,
}

impl RequestInfo {
    fn new(
        auth: Option<AuthContext>,
        body: Map<String, Value>,
        query: HashMap<String, String>,
        headers: &HeaderMap,
        method: &str,
    ) -> Self {
        let mut normalized_headers = HashMap::new();
        for (key, value) in headers {
            if let Ok(text) = value.to_str() {
                normalized_headers
                    .entry(go_snakecase(key.as_str()))
                    .or_insert_with(|| text.to_string());
            }
        }
        Self {
            auth,
            body,
            query,
            headers: normalized_headers,
            method: method.to_string(),
            context: "default".to_string(),
        }
    }

    fn is_superuser(&self) -> bool {
        self.auth.as_ref().map(|a| a.is_superuser()).unwrap_or(false)
    }

    fn auth_record(&self) -> Option<&Record> {
        self.auth.as_ref().map(|a| &a.record)
    }

    fn search_data(&self) -> search::RequestData {
        search::RequestData {
            body: self.body.clone(),
            query: self.query.clone(),
            headers: self.headers.clone(),
            method: self.method.clone(),
            context: self.context.clone(),
        }
    }
}

/// `inflector.Snakecase` (used to normalize `@request.headers.*` keys).
fn go_snakecase(input: &str) -> String {
    fn flush(word: &mut String, out: &mut String) {
        if word.is_empty() {
            return;
        }
        if !out.is_empty() {
            out.push('_');
        }
        let chars: Vec<char> = word.chars().collect();
        for (i, ch) in chars.iter().enumerate() {
            if ch.is_uppercase() && i > 0 && !chars[i - 1].is_uppercase() {
                out.push('_');
            }
            out.push(*ch);
        }
        word.clear();
    }

    let mut out = String::new();
    let mut word = String::new();
    for ch in input.chars() {
        if ch.is_alphanumeric() {
            word.push(ch);
        } else {
            flush(&mut word, &mut out);
        }
    }
    flush(&mut word, &mut out);
    out.to_lowercase()
}

/// Everything the filter SQL builder needs: allowed field names, relation
/// targets of the base collection, and metadata for `@collection.*` references.
struct FilterContext {
    allowed: Vec<String>,
    relations: HashMap<String, search::RelationInfo>,
    collections: HashMap<String, search::CollectionInfo>,
    types: search::RequestFieldTypes,
}

fn filter_context(
    conn: &rusqlite::Connection,
    collection: &Collection,
    include_hidden: bool,
) -> FilterContext {
    let fields = collection.field_list();
    let allowed: Vec<String> = fields
        .items()
        .iter()
        .filter(|f| include_hidden || !pb_core::fields::field_bool(f, "hidden"))
        .map(|f| pb_core::fields::field_name(f).to_string())
        .chain(std::iter::once("id".to_string()))
        .collect();

    let numbers: std::collections::HashSet<String> = fields
        .items()
        .iter()
        .filter(|f| pb_core::fields::field_type(f) == "number")
        .map(|f| pb_core::fields::field_name(f).to_string())
        .collect();

    let all = Collection::load_all(conn).unwrap_or_default();
    let by_id: HashMap<&str, &Collection> = all.iter().map(|c| (c.id.as_str(), c)).collect();

    let relations_for = |c: &Collection| {
        let mut relations: HashMap<String, search::RelationInfo> = HashMap::new();
        for f in c.field_list().items() {
            if pb_core::fields::field_type(f) == "relation" {
                let coll_id = pb_core::fields::field_str(f, "collectionId");
                if let Some(target) = by_id.get(coll_id) {
                    relations.insert(
                        pb_core::fields::field_name(f).to_string(),
                        search::RelationInfo {
                            table: target.name.clone(),
                            multiple: pb_core::fields::is_multiple(f),
                        },
                    );
                }
            }
        }
        relations
    };

    let mut collections: HashMap<String, search::CollectionInfo> = HashMap::new();
    for c in &all {
        let info = search::CollectionInfo {
            table: c.name.clone(),
            fields: c
                .field_list()
                .items()
                .iter()
                .map(|f| pb_core::fields::field_name(f).to_string())
                .collect(),
            relations: relations_for(c),
        };
        collections.insert(c.name.clone(), info.clone());
        collections.insert(c.id.clone(), info);
    }

    FilterContext {
        allowed,
        relations: relations_for(collection),
        collections,
        types: search::RequestFieldTypes { numbers },
    }
}

/// Parse + build a filter expression (list filters and API rules).
fn build_filter_sql_raw(
    ctx: &FilterContext,
    filter: &str,
    request: &RequestInfo,
) -> Result<search::SqlFilter, search::ParseError> {
    let expr = search::parse(filter)?;
    let expr = search::resolve_request_fields(&expr, &request.search_data(), &ctx.types)?;
    search::build_sql_full(
        &expr,
        &ctx.allowed,
        request.auth_record(),
        &ctx.relations,
        &ctx.collections,
    )
}

fn generic_bad_request() -> ApiError {
    ApiError::bad_request(GENERIC_BAD_REQUEST)
}

/// `findCollection`: 404 when the collection is missing.
fn find_collection(conn: &rusqlite::Connection, id_or_name: &str) -> Result<Collection, ApiError> {
    Collection::find(conn, id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?
        .ok_or_else(|| ApiError::not_found("Missing collection context."))
}

/// `e.BindBody` for the JSON content type.
fn bind_body(headers: &HeaderMap, body: &Bytes) -> Result<Map<String, Value>, ApiError> {
    if body.is_empty() {
        return Ok(Map::new());
    }
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.starts_with("application/json") {
        match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(map)) => Ok(map),
            // `json.Unmarshal` into a nil map accepts `null`.
            Ok(Value::Null) => Ok(Map::new()),
            _ => Err(generic_bad_request()),
        }
    } else {
        Err(ApiError::bad_request("Unsupported Content-Type."))
    }
}

/// `strconv.Atoi` for a query parameter.
fn parse_int_param(
    query: &HashMap<String, String>,
    key: &str,
) -> Result<Option<i64>, ApiError> {
    match query.get(key) {
        Some(raw) if !raw.is_empty() => raw
            .parse::<i64>()
            .map(Some)
            .map_err(|_| generic_bad_request()),
        _ => Ok(None),
    }
}

/// `strconv.ParseBool`.
fn go_parse_bool(raw: &str) -> Option<bool> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn parse_bool_param(
    query: &HashMap<String, String>,
    key: &str,
) -> Result<Option<bool>, ApiError> {
    match query.get(key) {
        Some(raw) if !raw.is_empty() => {
            go_parse_bool(raw).map(Some).ok_or_else(generic_bad_request)
        }
        _ => Ok(None),
    }
}

/// `checkForSuperuserOnlyRuleFields`: guests/users can't use rule-only macros
/// in their client-side filter/sort.
fn check_superuser_only_fields(request: &RequestInfo) -> Result<(), ApiError> {
    if request.query.is_empty() || request.is_superuser() {
        return Ok(());
    }
    for param in ["filter", "sort"] {
        let Some(value) = request.query.get(param) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        for field in ["@collection.", "@request."] {
            if value.contains(field) {
                return Err(ApiError::forbidden(format!(
                    "Only superusers can filter by {field}"
                )));
            }
        }
    }
    Ok(())
}

/// `RecordDataFromRequest`: resolve modifiers and drop hidden fields for
/// non-superusers (the auth `password` field is the exception).
fn record_data_from_request(
    record: &RecordModel,
    request: &RequestInfo,
    is_superuser: bool,
) -> Map<String, Value> {
    let mut result = record.replace_modifiers(&request.body);
    if !is_superuser {
        let collection = &record.collection;
        let is_auth = collection.is_auth();
        for field in collection.field_list().items() {
            if !pb_core::fields::field_bool(field, "hidden") {
                continue;
            }
            let name = pb_core::fields::field_name(field);
            if is_auth && name == "password" {
                continue;
            }
            result.remove(name);
        }
    }
    result
}

/// `Record.Get` values for a rule evaluation, including hidden fields.
fn record_rule_matches(
    conn: &rusqlite::Connection,
    collection: &Collection,
    rule: &str,
    record_id: &str,
    request: &RequestInfo,
    ctx: &FilterContext,
) -> Result<bool, ApiError> {
    let sf = build_filter_sql_raw(ctx, rule, request)
        .map_err(|_| ApiError::not_found(NOT_FOUND_MESSAGE))?;
    let sql = format!(
        "SELECT 1 FROM {} WHERE {} = ? AND ({})",
        quote_table(&collection.name),
        pb_core::records::quote_ident("id"),
        sf.sql
    );
    let mut params: Vec<rusqlite::types::Value> =
        vec![rusqlite::types::Value::Text(record_id.to_string())];
    params.extend(sf.params.iter().map(json_to_sqlite));
    Ok(conn
        .query_row(&sql, rusqlite::params_from_iter(params), |_| Ok(()))
        .is_ok())
}

/// Evaluate a rule against in-memory record data (create rule / dummy record).
fn rule_matches_data(
    conn: &rusqlite::Connection,
    rule: &str,
    data: &Map<String, Value>,
    request: &RequestInfo,
    ctx: &FilterContext,
) -> Result<bool, search::ParseError> {
    let built = search::build_rule_sql(
        rule,
        data,
        request.auth_record(),
        &request.search_data(),
        &ctx.types,
    )?;
    let Some((sql, params)) = built else {
        return Ok(true);
    };
    let full = format!("SELECT 1 WHERE ({sql})");
    let values: Vec<rusqlite::types::Value> = params.iter().map(json_to_sqlite).collect();
    Ok(conn
        .query_row(&full, rusqlite::params_from_iter(values), |_| Ok(()))
        .is_ok())
}

/// `hasAuthManageAccess` for the create flow (dummy record data).
fn has_auth_manage_access_data(
    conn: &rusqlite::Connection,
    collection: &Collection,
    data: &Map<String, Value>,
    request: &RequestInfo,
    ctx: &FilterContext,
) -> bool {
    if !collection.is_auth() {
        return false;
    }
    let Some(rule) = collection.manage_rule() else {
        return false;
    };
    if rule.is_empty() || request.auth.is_none() {
        return false;
    }
    rule_matches_data(conn, rule, data, request, ctx).unwrap_or(false)
}

/// `hasAuthManageAccess` for the update flow (stored record row).
fn has_auth_manage_access_record(
    conn: &rusqlite::Connection,
    collection: &Collection,
    record_id: &str,
    request: &RequestInfo,
    ctx: &FilterContext,
) -> bool {
    if !collection.is_auth() {
        return false;
    }
    let Some(rule) = collection.manage_rule() else {
        return false;
    };
    if rule.is_empty() || request.auth.is_none() {
        return false;
    }
    record_rule_matches(conn, collection, rule, record_id, request, ctx).unwrap_or(false)
}

/// `autoResolveRecordsFlags` + `PublicExport` visibility for one record.
fn visibility_for_record(
    conn: &rusqlite::Connection,
    collection: &Collection,
    record: &RecordModel,
    request: &RequestInfo,
    ctx: &FilterContext,
) -> Visibility {
    let mut visibility = Visibility::default();

    if request.is_superuser() {
        visibility.ignore_email_visibility = true;
        for field in collection.field_list().items() {
            visibility.unhide(pb_core::fields::field_name(field));
        }
        return visibility;
    }

    if !collection.is_auth() {
        return visibility;
    }

    if let Some(auth) = &request.auth {
        if auth.record.id() == record.id() {
            visibility.ignore_email_visibility = true;
        }
    }

    if collection
        .manage_rule()
        .map(|rule| !rule.is_empty())
        .unwrap_or(false)
        && request.auth.is_some()
        && record_rule_matches(
            conn,
            collection,
            collection.manage_rule().unwrap_or_default(),
            record.id(),
            request,
            ctx,
        )
        .unwrap_or(false)
    {
        visibility.ignore_email_visibility = true;
    }

    visibility
}

/// `EnrichRecord` for a single saved record.
fn enrich_record(
    conn: &rusqlite::Connection,
    collection: &Collection,
    record: &RecordModel,
    request: &RequestInfo,
) -> Value {
    let ctx = filter_context(conn, collection, true);
    let visibility = visibility_for_record(conn, collection, record, request, &ctx);
    let mut json = record.to_api_json_with(&visibility);
    let expand = request.query.get("expand").cloned().unwrap_or_default();
    if !expand.trim().is_empty() {
        let tree = build_expand_tree(&expand);
        expand_record(conn, collection, &mut json, &tree, request);
    }
    json
}

/// `GET /api/collections/{collection}/records`
pub async fn list(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;
    let request = RequestInfo::new(auth, Map::new(), query, &headers, "GET");

    if !request.is_superuser() && collection.list_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }
    check_superuser_only_fields(&request)?;

    let page = parse_int_param(&request.query, "page")?.unwrap_or(1).max(1);
    let per_page = match parse_int_param(&request.query, "perPage")? {
        Some(value) if value <= 0 => 30,
        Some(value) => value.min(500),
        None => 30,
    };
    let skip_total = parse_bool_param(&request.query, "skipTotal")?.unwrap_or(false);

    let sort = request.query.get("sort").cloned().unwrap_or_default();
    let order_clause = build_order(&conn, &collection, &sort)?;

    // Filter + collection list rule.
    let mut clauses: Vec<String> = Vec::new();
    let mut filter_params: Vec<Value> = Vec::new();

    if !request.is_superuser() {
        if let Some(rule) = &collection.list_rule {
            if !rule.is_empty() {
                let ctx = filter_context(&conn, &collection, true);
                let sf =
                    build_filter_sql_raw(&ctx, rule, &request).map_err(|_| generic_bad_request())?;
                clauses.push(sf.sql);
                filter_params.extend(sf.params);
            }
        }
    }
    if let Some(filter) = request.query.get("filter") {
        if !filter.trim().is_empty() {
            let ctx = filter_context(&conn, &collection, request.is_superuser());
            let sf =
                build_filter_sql_raw(&ctx, filter, &request).map_err(|_| generic_bad_request())?;
            clauses.push(format!("({})", sf.sql));
            filter_params.extend(sf.params);
        }
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let total: i64 = if skip_total {
        -1
    } else {
        let total_sql = if where_clause.is_empty() {
            format!("SELECT count(*) FROM {}", quote_table(&collection.name))
        } else {
            format!(
                "SELECT count(*) FROM {} {}",
                quote_table(&collection.name),
                where_clause
            )
        };
        let params: Vec<rusqlite::types::Value> =
            filter_params.iter().map(json_to_sqlite).collect();
        conn.query_row(&total_sql, rusqlite::params_from_iter(params), |r| r.get(0))
            .map_err(|e| ApiError::internal(format!("count failed: {e}")))?
    };

    let total_pages = if skip_total {
        -1
    } else {
        ((total as f64) / (per_page as f64)).ceil() as i64
    };

    let sql = format!(
        "SELECT * FROM {} {} {} LIMIT ? OFFSET ?",
        quote_table(&collection.name),
        where_clause,
        order_clause
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ApiError::internal(format!("prepare failed: {e}")))?;
    let mut all_params: Vec<rusqlite::types::Value> =
        filter_params.iter().map(json_to_sqlite).collect();
    all_params.push(rusqlite::types::Value::Integer(per_page));
    all_params.push(rusqlite::types::Value::Integer(per_page * (page - 1)));
    let mut rows = stmt
        .query(rusqlite::params_from_iter(all_params))
        .map_err(|e| ApiError::internal(format!("query failed: {e}")))?;

    let ctx = filter_context(&conn, &collection, true);
    let expand = request.query.get("expand").cloned().unwrap_or_default();
    let tree = build_expand_tree(&expand);
    let mut records = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| ApiError::internal(format!("row failed: {e}")))?
    {
        let record = RecordModel::from_row(&collection, row)
            .map_err(|e| ApiError::internal(format!("from_row failed: {e}")))?;
        let visibility = visibility_for_record(&conn, &collection, &record, &request, &ctx);
        let mut json = record.to_api_json_with(&visibility);
        if !tree.is_empty() {
            expand_record(&conn, &collection, &mut json, &tree, &request);
        }
        records.push(json);
    }
    drop(rows);
    drop(stmt);

    project_fields(
        &mut records,
        request.query.get("fields").map(String::as_str).unwrap_or(""),
    );

    let mut out = Map::new();
    out.insert("items".into(), Value::Array(records));
    out.insert("page".into(), Value::Number(page.into()));
    out.insert("perPage".into(), Value::Number(per_page.into()));
    out.insert("totalItems".into(), Value::Number(total.into()));
    out.insert("totalPages".into(), Value::Number(total_pages.into()));
    Ok(Json(Value::Object(out)))
}

/// Build a tree of expand paths (`author.mentor` -> {author: [mentor]}).
fn build_expand_tree(expand: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut tree: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for e in expand.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let parts: Vec<&str> = e.split('.').collect();
        let top = parts[0].to_string();
        let rest = if parts.len() > 1 {
            parts[1..].join(".")
        } else {
            String::new()
        };
        tree.entry(top.clone()).or_default();
        if !rest.is_empty() {
            tree.get_mut(&top).unwrap().push(rest);
        }
    }
    tree
}

/// Whether the current request may expand (view) the given related record.
fn can_view_expanded(
    conn: &rusqlite::Connection,
    collection: &Collection,
    record: &RecordModel,
    request: &RequestInfo,
    ctx: &FilterContext,
) -> bool {
    if request.is_superuser() {
        return true;
    }
    match collection.view_rule.as_deref() {
        None => false,
        Some("") => true,
        Some(rule) => record_rule_matches(conn, collection, rule, record.id(), request, ctx)
            .unwrap_or(false),
    }
}

fn expand_record(
    conn: &rusqlite::Connection,
    collection: &Collection,
    rec: &mut Value,
    tree: &std::collections::BTreeMap<String, Vec<String>>,
    request: &RequestInfo,
) {
    let mut expand_obj = Map::new();
    let Some(obj) = rec.as_object_mut() else {
        return;
    };
    for (field_name, nested) in tree {
        let rel_field = {
            let fl = collection.field_list();
            fl.items()
                .iter()
                .find(|f| {
                    pb_core::fields::field_name(f) == field_name
                        && pb_core::fields::field_type(f) == "relation"
                })
                .cloned()
        };
        let Some(rel_field) = rel_field else {
            continue;
        };
        let coll_id = pb_core::fields::field_str(&rel_field, "collectionId");
        let Ok(Some(rel_coll)) = Collection::find(conn, coll_id) else {
            continue;
        };
        let is_multiple = pb_core::fields::is_multiple(&rel_field);
        let val = obj.get(field_name).cloned().unwrap_or(Value::Null);
        let child_tree = build_expand_tree(&nested.join(","));
        let rel_ctx = filter_context(conn, &rel_coll, true);

        let resolve = |rid: &str, expand_obj: &mut Map<String, Value>| {
            let Ok(Some(rel)) = RecordModel::find_by_id(conn, &rel_coll, rid) else {
                return;
            };
            if !can_view_expanded(conn, &rel_coll, &rel, request, &rel_ctx) {
                return;
            }
            let visibility = visibility_for_record(conn, &rel_coll, &rel, request, &rel_ctx);
            let mut rv = rel.to_api_json_with(&visibility);
            if !child_tree.is_empty() {
                expand_record(conn, &rel_coll, &mut rv, &child_tree, request);
            }
            match expand_obj.get_mut(field_name) {
                Some(Value::Array(items)) => items.push(rv),
                Some(slot) => *slot = rv,
                None => {
                    if is_multiple {
                        expand_obj.insert(field_name.clone(), Value::Array(vec![rv]));
                    } else {
                        expand_obj.insert(field_name.clone(), rv);
                    }
                }
            }
        };

        if is_multiple {
            let ids: Vec<String> = val
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            for rid in &ids {
                resolve(rid, &mut expand_obj);
            }
        } else if let Some(rid) = val.as_str() {
            if !rid.is_empty() {
                resolve(rid, &mut expand_obj);
            }
        }
    }
    // The oracle always includes `expand` (even as `{}`) when expansion was
    // requested for the record.
    obj.insert("expand".into(), Value::Object(expand_obj));
}

/// `fields` projection (`picker.Pick`): keep exactly the requested keys.
fn project_fields(records: &mut Vec<Value>, fields: &str) {
    if fields.trim().is_empty() {
        return;
    }
    let parsed: Vec<String> = fields
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    for rec in records.iter_mut() {
        pick_value(rec, &parsed);
    }
}

fn pick_value(value: &mut Value, fields: &[String]) {
    match value {
        Value::Object(map) => {
            let mut keep = Map::new();
            for (key, mut item) in std::mem::take(map) {
                let mut nested: Vec<String> = Vec::new();
                let mut exact = false;
                for field in fields {
                    if field == "*" || field == &key {
                        exact = true;
                        break;
                    }
                    if let Some(rest) = field
                        .strip_prefix(&format!("{key}."))
                        .or_else(|| field.strip_prefix(&format!("{key}[")))
                    {
                        nested.push(rest.to_string());
                    }
                }
                if exact {
                    keep.insert(key, item);
                } else if !nested.is_empty() {
                    pick_value(&mut item, &nested);
                    keep.insert(key, item);
                }
            }
            *map = keep;
        }
        Value::Array(items) => {
            for item in items {
                pick_value(item, fields);
            }
        }
        _ => {}
    }
}

fn quote_table(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// `search.Provider` sort parsing: `-field`, `@rowid`, `@random` and simple
/// relation paths (`author.name`).
fn build_order(
    conn: &rusqlite::Connection,
    collection: &Collection,
    sort: &str,
) -> Result<String, ApiError> {
    if sort.is_empty() {
        return Ok(String::new());
    }
    let mut parts = Vec::new();
    for token in sort.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (desc, field) = if let Some(rest) = token.strip_prefix('-') {
            (true, rest)
        } else {
            (false, token)
        };
        let expr = match field {
            "@rowid" => "_rowid_".to_string(),
            "@random" => "RANDOM()".to_string(),
            other => {
                if let Some((head, sub)) = other.split_once('.') {
                    let fields = collection.field_list();
                    let rel = fields.items().iter().find(|f| {
                        pb_core::fields::field_name(f) == head
                            && pb_core::fields::field_type(f) == "relation"
                    });
                    let Some(rel) = rel else {
                        return Err(generic_bad_request());
                    };
                    let coll_id = pb_core::fields::field_str(rel, "collectionId");
                    let Some(target) = Collection::find(conn, coll_id)
                        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
                    else {
                        return Err(generic_bad_request());
                    };
                    let exists = target
                        .field_list()
                        .items()
                        .iter()
                        .any(|f| pb_core::fields::field_name(f) == sub)
                        || sub == "id";
                    if !exists {
                        return Err(generic_bad_request());
                    }
                    format!(
                        "(SELECT {} FROM {} WHERE {} = {})",
                        pb_core::records::quote_ident(sub),
                        quote_table(&target.name),
                        pb_core::records::quote_ident("id"),
                        pb_core::records::quote_ident(head)
                    )
                } else {
                    let exists = collection
                        .field_list()
                        .items()
                        .iter()
                        .any(|f| pb_core::fields::field_name(f) == other);
                    if !exists {
                        return Err(generic_bad_request());
                    }
                    pb_core::records::quote_ident(other)
                }
            }
        };
        let dir = if desc { "DESC" } else { "ASC" };
        parts.push(format!("{expr} {dir}"));
    }
    if parts.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("ORDER BY {}", parts.join(", ")))
    }
}

/// `GET /api/collections/{collection}/records/{id}`
pub async fn view(
    State(db): State<Db>,
    headers: HeaderMap,
    Path((id_or_name, record_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;
    let request = RequestInfo::new(auth, Map::new(), query, &headers, "GET");

    if !request.is_superuser() && collection.view_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let record = RecordModel::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
        .ok_or_else(|| ApiError::not_found(NOT_FOUND_MESSAGE))?;

    if !request.is_superuser() {
        if let Some(rule) = collection.view_rule.as_deref() {
            if !rule.is_empty() {
                let ctx = filter_context(&conn, &collection, true);
                if !record_rule_matches(&conn, &collection, rule, &record_id, &request, &ctx)? {
                    return Err(ApiError::not_found(NOT_FOUND_MESSAGE));
                }
            }
        }
    }

    let mut records = vec![enrich_record(&conn, &collection, &record, &request)];
    project_fields(
        &mut records,
        request.query.get("fields").map(String::as_str).unwrap_or(""),
    );
    Ok(Json(records.pop().unwrap_or(Value::Null)))
}

/// `POST /api/collections/{collection}/records`
pub async fn create(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if collection.is_view() {
        return Err(ApiError::bad_request("Unsupported collection type."));
    }

    let request = RequestInfo::new(auth, Map::new(), query, &headers, "POST");
    let is_superuser = request.is_superuser();
    if !is_superuser && collection.create_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let body = bind_body(&headers, &body)?;
    let mut request = RequestInfo { body, ..request };

    let mut record = RecordModel::new(&collection);
    if is_superuser {
        record.grant_access(AccessLevel::Superuser);
    }
    let data = record_data_from_request(&record, &request, is_superuser);
    request.body = data.clone();
    record.load(&data);

    if !is_superuser {
        if let Some(rule) = collection.create_rule.as_deref() {
            let ctx = filter_context(&conn, &collection, true);

            let mut dummy = record.clone_model();
            if dummy.id().is_empty() {
                dummy.set_id(format!("__temp_id__{}{}", "__pb_create__", random_string(6)));
            }
            dummy.set_verified(false);
            let dummy_data = dummy.to_rule_data();

            if !rule.is_empty()
                && !rule_matches_data(&conn, rule, &dummy_data, &request, &ctx)
                    .map_err(|_| ApiError::bad_request("Failed to create record."))?
            {
                return Err(ApiError::bad_request("Failed to create record."));
            }

            if !record.has_manage_access()
                && has_auth_manage_access_data(&conn, &collection, &dummy_data, &request, &ctx)
            {
                record.grant_access(AccessLevel::Manager);
            }
        }
    }

    match record.submit(&conn) {
        Ok(()) => {}
        Err(SubmitError::Validation(errors)) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Failed to create record.",
                errors_to_value(&errors),
            ));
        }
        Err(SubmitError::Raw(_)) => {
            return Err(ApiError::bad_request("Failed to create record."));
        }
    }

    broadcast_record(&conn, &collection, &record, "create");

    let mut records = vec![enrich_record(&conn, &collection, &record, &request)];
    project_fields(
        &mut records,
        request.query.get("fields").map(String::as_str).unwrap_or(""),
    );
    Ok(Json(records.pop().unwrap_or(Value::Null)))
}

/// `PATCH /api/collections/{collection}/records/{id}`
pub async fn update(
    State(db): State<Db>,
    headers: HeaderMap,
    Path((id_or_name, record_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if collection.is_view() {
        return Err(ApiError::bad_request("Unsupported collection type."));
    }

    let request = RequestInfo::new(auth, Map::new(), query, &headers, "PATCH");
    let is_superuser = request.is_superuser();
    if !is_superuser && collection.update_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let mut record = RecordModel::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
        .ok_or_else(|| ApiError::not_found(NOT_FOUND_MESSAGE))?;

    let body = bind_body(&headers, &body)?;
    let mut request = RequestInfo { body, ..request };

    // Modifiers are resolved against the eager-fetched stored record.
    let data = record_data_from_request(&record, &request, is_superuser);
    request.body = data.clone();

    if !is_superuser {
        if let Some(rule) = collection.update_rule.as_deref() {
            if !rule.is_empty() {
                let ctx = filter_context(&conn, &collection, true);
                if !record_rule_matches(&conn, &collection, rule, &record_id, &request, &ctx)? {
                    return Err(ApiError::not_found(NOT_FOUND_MESSAGE));
                }
            }
        }
    }

    if is_superuser {
        record.grant_access(AccessLevel::Superuser);
    }
    record.load(&data);

    if !record.has_manage_access() {
        let ctx = filter_context(&conn, &collection, true);
        if has_auth_manage_access_record(&conn, &collection, &record_id, &request, &ctx) {
            record.grant_access(AccessLevel::Manager);
        }
    }

    match record.submit(&conn) {
        Ok(()) => {}
        Err(SubmitError::Validation(errors)) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Failed to update record.",
                errors_to_value(&errors),
            ));
        }
        Err(SubmitError::Raw(_)) => {
            return Err(ApiError::bad_request("Failed to update record."));
        }
    }

    broadcast_record(&conn, &collection, &record, "update");

    let mut records = vec![enrich_record(&conn, &collection, &record, &request)];
    project_fields(
        &mut records,
        request.query.get("fields").map(String::as_str).unwrap_or(""),
    );
    Ok(Json(records.pop().unwrap_or(Value::Null)))
}

/// `DELETE /api/collections/{collection}/records/{id}`
pub async fn delete(
    State(db): State<Db>,
    headers: HeaderMap,
    Path((id_or_name, record_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = load_auth(&db, &headers);
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if collection.is_view() {
        return Err(ApiError::bad_request("Unsupported collection type."));
    }

    let request = RequestInfo::new(auth, Map::new(), HashMap::new(), &headers, "DELETE");
    if !request.is_superuser() && collection.delete_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let Some(record) = RecordModel::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
    else {
        return Err(ApiError::not_found(NOT_FOUND_MESSAGE));
    };

    if !request.is_superuser() {
        if let Some(rule) = collection.delete_rule.as_deref() {
            if !rule.is_empty() {
                let ctx = filter_context(&conn, &collection, true);
                if !record_rule_matches(&conn, &collection, rule, &record_id, &request, &ctx)? {
                    return Err(ApiError::not_found(NOT_FOUND_MESSAGE));
                }
            }
        }
    }

    let sql = format!(
        "DELETE FROM {} WHERE {} = ?1",
        quote_table(&collection.name),
        pb_core::records::quote_ident("id")
    );
    conn.execute(&sql, [&record_id])
        .map_err(|_| {
            ApiError::bad_request(
                "Failed to delete record. Make sure that the record is not part of a required relation reference.",
            )
        })?;
    broadcast_record(&conn, &collection, &record, "delete");
    Ok(StatusCode::NO_CONTENT)
}

fn json_to_sqlite(value: &Value) -> rusqlite::types::Value {
    match value {
        Value::Null => rusqlite::types::Value::Null,
        Value::Bool(b) => rusqlite::types::Value::Integer(if *b { 1 } else { 0 }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rusqlite::types::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                rusqlite::types::Value::Real(f)
            } else {
                rusqlite::types::Value::Text(n.to_string())
            }
        }
        Value::String(s) => rusqlite::types::Value::Text(s.clone()),
        Value::Array(_) | Value::Object(_) => {
            rusqlite::types::Value::Text(serde_json::to_string(value).unwrap_or_default())
        }
    }
}

/// `security.PseudorandomString(6)` (`[A-Za-z0-9]`).
fn random_string(length: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

fn check_mfa(
    conn: &rusqlite::Connection,
    collection: &Collection,
    auth_record: &Record,
    current_method: &str,
    requested_mfa_id: &str,
) -> Result<Option<String>, ApiError> {
    let mfa_config = collection
        .options
        .get("mfa")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !mfa_config.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(None);
    }
    let mfas_collection = Collection::find(conn, "_mfas")
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::internal("missing _mfas collection"))?;
    let duration = mfa_config.get("duration").and_then(Value::as_i64).unwrap_or(0);

    if requested_mfa_id.is_empty() {
        let mfa_id = pb_core::ids::default_random_id();
        conn.execute(
            "INSERT INTO _mfas (id, collectionRef, recordRef, method, created, updated) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%d %H:%M:%fZ','now'), strftime('%Y-%m-%d %H:%M:%fZ','now'))",
            rusqlite::params![mfa_id, collection.id, auth_record.id(), current_method],
        )
        .map_err(|e| ApiError::internal(e.to_string()))?;
        let _ = mfas_collection;
        let _ = duration;
        return Ok(Some(mfa_id));
    }

    let mfa = Record::find_by_id(conn, &mfas_collection, requested_mfa_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some(mfa) = mfa else {
        return Err(ApiError::bad_request("Invalid or expired MFA session."));
    };
    let mfa_json = mfa.to_api_json();
    let mfa_collection_ref = mfa_json.get("collectionRef").and_then(Value::as_str).unwrap_or("");
    let mfa_record_ref = mfa_json.get("recordRef").and_then(Value::as_str).unwrap_or("");
    let mfa_method = mfa_json.get("method").and_then(Value::as_str).unwrap_or("");
    if mfa_collection_ref != collection.id || mfa_record_ref != auth_record.id() {
        return Err(ApiError::bad_request("Invalid MFA session."));
    }
    let expired: i64 = conn
        .query_row(
            "SELECT CASE WHEN datetime(created, '+' || ?2 || ' seconds') < datetime('now') THEN 1 ELSE 0 END FROM _mfas WHERE id = ?1",
            rusqlite::params![requested_mfa_id, duration],
            |r| r.get(0),
        )
        .unwrap_or(1);
    if expired == 1 {
        conn.execute("DELETE FROM _mfas WHERE id = ?1", [requested_mfa_id]).ok();
        return Err(ApiError::bad_request("Invalid or expired MFA session."));
    }
    if mfa_method == current_method {
        return Err(ApiError::bad_request("A different authentication method is required."));
    }
    conn.execute("DELETE FROM _mfas WHERE id = ?1", [requested_mfa_id]).ok();
    Ok(None)
}

pub async fn logs_list(
    State(db): State<Db>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    crate::auth::require_superuser(&db, &headers)?;
    let aux = AUX_DB
        .get()
        .cloned()
        .ok_or_else(|| ApiError::internal("aux db not available"))?;
    let conn = aux.lock().map_err(|_| ApiError::internal("aux lock poisoned"))?;

    let page: i64 = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let per_page: i64 = params.get("perPage").and_then(|s| s.parse().ok()).unwrap_or(30).clamp(1, 500);
    let offset = (page - 1) * per_page;

    let total: i64 = conn
        .query_row("SELECT count(*) FROM _logs", [], |r| r.get(0))
        .unwrap_or(0);

    let mut stmt = conn
        .prepare("SELECT id, level, message, data, created FROM _logs ORDER BY created DESC LIMIT ?1 OFFSET ?2")
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let rows = stmt
        .query_map(rusqlite::params![per_page, offset], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "level": r.get::<_, i64>(1)?,
                "message": r.get::<_, String>(2)?,
                "data": serde_json::from_str::<Value>(&r.get::<_, String>(3)?).unwrap_or(Value::Object(Map::new())),
                "created": r.get::<_, String>(4)?,
            }))
        })
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(|e| ApiError::internal(e.to_string()))?);
    }

    let total_pages = if total == 0 { 0 } else { (total + per_page - 1) / per_page };
    Ok(Json(json!({
        "items": items,
        "page": page,
        "perPage": per_page,
        "totalItems": total,
        "totalPages": total_pages,
    })))
}

pub async fn logs_view(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    crate::auth::require_superuser(&db, &headers)?;
    let aux = AUX_DB
        .get()
        .cloned()
        .ok_or_else(|| ApiError::internal("aux db not available"))?;
    let conn = aux.lock().map_err(|_| ApiError::internal("aux lock poisoned"))?;
    let mut stmt = conn
        .prepare("SELECT id, level, message, data, created FROM _logs WHERE id = ?1")
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let row = stmt
        .query_row([id], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "level": r.get::<_, i64>(1)?,
                "message": r.get::<_, String>(2)?,
                "data": serde_json::from_str::<Value>(&r.get::<_, String>(3)?).unwrap_or(Value::Object(Map::new())),
                "created": r.get::<_, String>(4)?,
            }))
        })
        .map_err(|_| ApiError::not_found("The requested resource wasn't found."))?;
    Ok(Json(row))
}

pub async fn logs_stats(
    State(db): State<Db>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    crate::auth::require_superuser(&db, &headers)?;
    let aux = AUX_DB
        .get()
        .cloned()
        .ok_or_else(|| ApiError::internal("aux db not available"))?;
    let conn = aux.lock().map_err(|_| ApiError::internal("aux lock poisoned"))?;
    // simple stats: count by level
    let mut stmt = conn
        .prepare("SELECT level, count(*) FROM _logs GROUP BY level")
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut by_level = Map::new();
    let mut total = 0i64;
    for row in rows {
        let (level, count) = row.map_err(|e| ApiError::internal(e.to_string()))?;
        by_level.insert(level.to_string(), json!(count));
        total += count;
    }
    Ok(Json(json!({
        "total": total,
        "byLevel": by_level,
    })))
}

pub async fn logs_truncate(
    State(db): State<Db>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    crate::auth::require_superuser(&db, &headers)?;
    let aux = AUX_DB
        .get()
        .cloned()
        .ok_or_else(|| ApiError::internal("aux db not available"))?;
    let conn = aux.lock().map_err(|_| ApiError::internal("aux lock poisoned"))?;
    conn.execute("DELETE FROM _logs", [])
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

struct RealtimeGuard(String);

impl Drop for RealtimeGuard {
    fn drop(&mut self) {
        crate::realtime::broker().unregister(&self.0);
    }
}

pub async fn realtime_connect(
    State(_db): State<Db>,
    headers: HeaderMap,
) -> axum::response::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, axum::BoxError>>,
> {
    use futures_util::stream;
    use std::time::Duration;

    let client_id = pb_core::ids::default_random_id();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let rx = crate::realtime::broker().register(&client_id, &ip);
    let connect_data = format!(r#"{{"clientId":"{client_id}"}}"#);
    let guard = RealtimeGuard(client_id);

    let stream = stream::unfold((Some(rx), guard, false), move |(rx_opt, guard, sent)| {
        let connect_data = connect_data.clone();
        async move {
            if !sent {
                let ev = axum::response::sse::Event::default()
                    .event("PB_CONNECT")
                    .data(connect_data);
                return Some((Ok(ev), (rx_opt, guard, true)));
            }
            let mut rx = rx_opt?;
            match tokio::time::timeout(Duration::from_secs(30), rx.recv()).await {
                Ok(Some(msg)) => {
                    let ev = axum::response::sse::Event::default()
                        .event(msg.name)
                        .data(msg.data);
                    Some((Ok(ev), (Some(rx), guard, true)))
                }
                Ok(None) => None,
                Err(_) => {
                    let ev = axum::response::sse::Event::default().comment("ping");
                    Some((Ok(ev), (Some(rx), guard, true)))
                }
            }
        }
    });
    axum::response::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

pub async fn realtime_subscribe(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    require_json(&headers)?;
    let form = parse_json_body(&body)?;

    let client_id = form.get("clientId").and_then(Value::as_str).unwrap_or("");
    if client_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "",
            json!({"clientId": validation_required()}),
        ));
    }
    if client_id.chars().count() > 255 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "",
            json!({"clientId": validation_length(1, 255)}),
        ));
    }

    let mut subscriptions: Vec<String> = Vec::new();
    if let Some(raw) = form.get("subscriptions") {
        match raw {
            Value::Array(items) => {
                for item in items {
                    let Some(text) = item.as_str() else {
                        return Err(ApiError::new(
                            StatusCode::BAD_REQUEST,
                            "",
                            json!({"subscriptions": {"code": "validation_invalid_type", "message": "Invalid value."}}),
                        ));
                    };
                    subscriptions.push(text.to_string());
                }
            }
            Value::Null => {}
            _ => {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "",
                    json!({"subscriptions": {"code": "validation_invalid_type", "message": "Invalid value."}}),
                ));
            }
        }
    }
    if subscriptions.len() > 1000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "",
            json!({"subscriptions": validation_length(0, 1000)}),
        ));
    }
    if subscriptions.iter().any(|s| s.chars().count() > 2500) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "",
            json!({"subscriptions": validation_length(0, 2500)}),
        ));
    }

    let broker = crate::realtime::broker();
    let Some((_stored_ip, stored_auth)) = broker.client_state(client_id) else {
        return Err(ApiError::not_found("Missing or invalid client id."));
    };

    let current_auth = load_auth(&db, &headers)
        .map(|auth| (auth.collection.id.clone(), auth.record.id().to_string()));

    // Only guest -> auth upgrades are allowed; any other auth change is forbidden.
    if let Some(existing) = &stored_auth {
        if current_auth.as_ref() != Some(existing) {
            return Err(ApiError::forbidden(
                "The current and the previous request authorization don't match.",
            ));
        }
    }

    broker.set_subscriptions(client_id, subscriptions, current_auth);
    Ok(StatusCode::NO_CONTENT)
}

/// Broadcasts a record change to every subscribed realtime client, applying
/// the collection view/list API rule and the per-subscription `filter`.
fn broadcast_record(
    conn: &rusqlite::Connection,
    collection: &Collection,
    record: &pb_core::record_upsert::RecordModel,
    action: &str,
) {
    let clients = crate::realtime::broker().snapshot();
    if clients.is_empty() {
        return;
    }

    let record_id = record.id().to_string();
    let record_data = record.to_rule_data();

    for client in clients {
        let auth = match &client.auth {
            Some((collection_id, record_id)) => Collection::find(conn, collection_id)
                .ok()
                .flatten()
                .and_then(|auth_collection| {
                    Record::find_by_id(conn, &auth_collection, record_id)
                        .ok()
                        .flatten()
                        .map(|rec| AuthContext {
                            record: rec,
                            collection: auth_collection,
                        })
                }),
            None => None,
        };
        let is_superuser = auth.as_ref().map(|a| a.is_superuser()).unwrap_or(false);

        for topic in &client.subscriptions {
            let Some(specific) = crate::realtime::topic_matches(
                topic,
                &collection.id,
                &collection.name,
                &record_id,
            ) else {
                continue;
            };

            let rule = if specific {
                collection.view_rule.as_deref()
            } else {
                collection.list_rule.as_deref()
            };

            let allowed = if is_superuser {
                true
            } else {
                match rule {
                    None => false,
                    Some("") => true,
                    Some(rule) => {
                        let request = RequestInfo {
                            auth: auth.clone(),
                            body: Map::new(),
                            query: HashMap::new(),
                            headers: HashMap::new(),
                            method: "GET".to_string(),
                            context: "realtime".to_string(),
                        };
                        let ctx = filter_context(conn, collection, is_superuser);
                        rule_matches_data(conn, rule, &record_data, &request, &ctx).unwrap_or(false)
                    }
                }
            };
            if !allowed {
                continue;
            }

            let mut payload = json!({
                "action": action,
                "record": record.to_api_json(),
            });
            // Optional `fields` projection from the subscription options.
            if let Some(options) = topic.split_once("options=").map(|(_, v)| v) {
                if let Ok(Value::Object(opts)) = serde_json::from_str::<Value>(
                    &urlencoding::decode(options).unwrap_or_else(|_| options.into()),
                ) {
                    if let Some(fields) = opts
                        .get("query")
                        .and_then(|q| q.get("fields"))
                        .and_then(Value::as_str)
                    {
                        let mut records = vec![payload["record"].clone()];
                        project_fields(&mut records, fields);
                        payload["record"] = records.pop().unwrap_or(Value::Null);
                    }
                }
            }

            let _ = client.sender.send(crate::realtime::Event {
                name: crate::realtime::subscription_topic(topic).to_string(),
                data: payload.to_string(),
            });
        }
    }
}
