//! Record auth endpoints.
//!
//! M2a covers what the admin UI needs to log in: `auth-with-password`,
//! `auth-refresh` and `auth-methods`. OTP, OAuth2, MFA and the email flows are
//! later milestones.

use axum::body::Bytes;
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

    let token = auth_token(&collection, &record, true)?;
    Ok(Json(json!({
        "record": record.to_api_json(),
        "token": token,
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

    if RecordModel::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
        .is_none()
    {
        return Err(ApiError::not_found(NOT_FOUND_MESSAGE));
    }

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
