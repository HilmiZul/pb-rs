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

// ---------------------------------------------------------------------------
// Records CRUD (basic: list/view/create/update/delete, no filter/expand yet)
// ---------------------------------------------------------------------------

use axum::extract::Query;
use axum::http::StatusCode;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct RecordsListParams {
    pub page: Option<String>,
    #[serde(rename = "perPage")]
    pub per_page: Option<String>,
    pub sort: Option<String>,
    pub filter: Option<String>,
    #[serde(rename = "skipTotal")]
    pub skip_total: Option<String>,
    pub expand: Option<String>,
    pub fields: Option<String>,
}

fn parse_page(raw: Option<&str>) -> i64 {
    raw.and_then(|s| s.trim().parse().ok()).unwrap_or(1).max(1)
}

fn parse_per_page(raw: Option<&str>) -> i64 {
    raw.and_then(|s| s.trim().parse().ok())
        .unwrap_or(30)
        .clamp(1, 500)
}

fn find_collection(conn: &rusqlite::Connection, id_or_name: &str) -> Result<Collection, ApiError> {
    Collection::find(conn, id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?
        .ok_or_else(|| ApiError::not_found("Missing collection context."))
}

/// `GET /api/collections/{collection}/records`
pub async fn list(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    Query(params): Query<RecordsListParams>,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let is_superuser = auth.as_ref().map(|a| a.is_superuser()).unwrap_or(false);

    let conn = db.lock().map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if !is_superuser && collection.list_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let page = parse_page(params.page.as_deref());
    let per_page = parse_per_page(params.per_page.as_deref());
    let offset = (page - 1) * per_page;

    let sort = params.sort.clone().unwrap_or_default();
    let order_clause = build_order(&collection, &sort);

    // Filter
    let filter = params.filter.clone().unwrap_or_default();

    // Apply collection list rule for non-superusers.
    let mut rule_filter = String::new();
    let mut rule_params: Vec<serde_json::Value> = Vec::new();
    if !is_superuser {
        if let Some(rule) = &collection.list_rule {
            if !rule.is_empty() {
                let allowed: Vec<String> = collection
                    .field_list()
                    .items()
                    .iter()
                    .map(|f| pb_core::fields::field_name(f).to_string())
                    .chain(std::iter::once("id".to_string()))
                    .collect();
                if let Ok(expr) = search::parse(rule) {
                    if let Ok(sf) = search::build_sql_with_auth(&expr, &allowed, auth.as_ref().map(|a| &a.record)) {
                        rule_filter = sf.sql;
                        rule_params = sf.params;
                    }
                }
            }
        }
    }

    let (where_clause, filter_params) = if filter.trim().is_empty() && rule_filter.is_empty() {
        (String::new(), Vec::new())
    } else if filter.trim().is_empty() {
        // only rule filter
        (format!("WHERE {}", rule_filter), rule_params)
    } else if rule_filter.is_empty() {
        // only user filter
        let allowed: Vec<String> = collection
            .field_list()
            .items()
            .iter()
            .map(|f| pb_core::fields::field_name(f).to_string())
            .chain(std::iter::once("id".to_string()))
            .collect();
        let expr = search::parse(&filter).map_err(|e| ApiError::bad_request(format!("invalid filter: {e}")))?;
        let auth_record = auth.as_ref().map(|a| a.record.clone());
        // Build relation field -> table name map for traversal.
        let mut relations: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for f in collection.field_list().items() {
            if pb_core::fields::field_type(f) == "relation" {
                let coll_id = pb_core::fields::field_str(f, "collectionId");
                if let Ok(Some(c)) = Collection::find(&conn, coll_id) {
                    relations.insert(pb_core::fields::field_name(f).to_string(), c.name.clone());
                }
            }
        }
        let sf = search::build_sql_with_auth_and_relations(&expr, &allowed, auth_record.as_ref(), &relations)
            .map_err(|e| ApiError::bad_request(format!("invalid filter: {e}")))?;
        (format!("WHERE {}", sf.sql), sf.params)
    } else {
        // both
        let allowed: Vec<String> = collection
            .field_list()
            .items()
            .iter()
            .map(|f| pb_core::fields::field_name(f).to_string())
            .chain(std::iter::once("id".to_string()))
            .collect();
        let expr = search::parse(&filter).map_err(|e| ApiError::bad_request(format!("invalid filter: {e}")))?;
        let auth_record = auth.as_ref().map(|a| a.record.clone());
        // Build relation field -> table name map for traversal.
        let mut relations: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for f in collection.field_list().items() {
            if pb_core::fields::field_type(f) == "relation" {
                let coll_id = pb_core::fields::field_str(f, "collectionId");
                if let Ok(Some(c)) = Collection::find(&conn, coll_id) {
                    relations.insert(pb_core::fields::field_name(f).to_string(), c.name.clone());
                }
            }
        }
        let sf = search::build_sql_with_auth_and_relations(&expr, &allowed, auth_record.as_ref(), &relations)
            .map_err(|e| ApiError::bad_request(format!("invalid filter: {e}")))?;
        (format!("WHERE {} AND ({})", rule_filter, sf.sql), [rule_params, sf.params].concat())
    };

    let total_sql = if where_clause.is_empty() {
        format!("SELECT count(*) FROM {}", quote_table(&collection.name))
    } else {
        format!("SELECT count(*) FROM {} {}", quote_table(&collection.name), where_clause)
    };
    let total: i64 = if filter_params.is_empty() {
        conn.query_row(&total_sql, [], |r| r.get(0))
    } else {
        let params: Vec<rusqlite::types::Value> = filter_params.iter().map(json_to_sqlite).collect();
        conn.query_row(&total_sql, rusqlite::params_from_iter(params), |r| r.get(0))
    }
    .map_err(|e| ApiError::internal(format!("count failed: {e}")))?;

    let sql = if where_clause.is_empty() {
        format!("SELECT * FROM {} {} LIMIT ? OFFSET ?", quote_table(&collection.name), order_clause)
    } else {
        format!("SELECT * FROM {} {} {} LIMIT ? OFFSET ?", quote_table(&collection.name), where_clause, order_clause)
    };

    let mut stmt = conn.prepare(&sql).map_err(|e| ApiError::internal(format!("prepare failed: {e}")))?;
    // Combine filter params + pagination params
    let mut all_params: Vec<rusqlite::types::Value> = filter_params.iter().map(json_to_sqlite).collect();
    all_params.push(rusqlite::types::Value::Integer(per_page));
    all_params.push(rusqlite::types::Value::Integer(offset));
    let mut rows = stmt.query(rusqlite::params_from_iter(all_params)).map_err(|e| ApiError::internal(format!("query failed: {e}")))?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|e| ApiError::internal(format!("row failed: {e}")))? {
        let rec = Record::from_row(&collection, row).map_err(|e| ApiError::internal(format!("from_row failed: {e}")))?;
        records.push(rec.to_api_json());
    }

    // Expand: supports single and nested levels (author.posts.comments).
    let expand_param = params.expand.clone().unwrap_or_default();
    if !expand_param.is_empty() {
        let expands: Vec<&str> = expand_param.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        // Build a tree: top-level field -> list of nested expand paths.
        let mut tree: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
        for e in &expands {
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

        fn expand_record(
            conn: &rusqlite::Connection,
            collection: &Collection,
            rec: &mut Value,
            tree: &std::collections::BTreeMap<String, Vec<String>>,
        ) {
            let mut expand_obj = Map::new();
            if let Some(obj) = rec.as_object_mut() {
                for (field_name, nested) in tree {
                    let rel_field = {
                        let fl = collection.field_list();
                        fl.items().iter().find(|f| {
                            pb_core::fields::field_name(f) == field_name
                                && pb_core::fields::field_type(f) == "relation"
                        }).cloned()
                    };
                    let rel_field = match rel_field {
                        Some(f) => f,
                        None => continue,
                    };
                    let coll_id = pb_core::fields::field_str(&rel_field, "collectionId");
                    let rel_coll = match Collection::find(conn, coll_id) {
                        Ok(Some(c)) => c,
                        _ => continue,
                    };
                    let is_multiple = pb_core::fields::is_multiple(&rel_field);
                    let val = obj.get(field_name).cloned().unwrap_or(Value::Null);

                    // Build nested tree for children.
                    let mut child_tree: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
                    for n in nested {
                        let parts: Vec<&str> = n.split('.').collect();
                        let top = parts[0].to_string();
                        let rest = if parts.len() > 1 { parts[1..].join(".") } else { String::new() };
                        child_tree.entry(top.clone()).or_default();
                        if !rest.is_empty() {
                            child_tree.get_mut(&top).unwrap().push(rest);
                        }
                    }

                    if is_multiple {
                        let ids: Vec<String> = val.as_array()
                            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                            .unwrap_or_default();
                        let mut rels = Vec::new();
                        for rid in &ids {
                            if let Ok(Some(mut r)) = Record::find_by_id(conn, &rel_coll, rid) {
                                let mut rv = r.to_api_json();
                                if !child_tree.is_empty() {
                                    expand_record(conn, &rel_coll, &mut rv, &child_tree);
                                }
                                rels.push(rv);
                            }
                        }
                        expand_obj.insert(field_name.clone(), Value::Array(rels));
                    } else if let Some(rid) = val.as_str() {
                        if !rid.is_empty() {
                            if let Ok(Some(mut r)) = Record::find_by_id(conn, &rel_coll, rid) {
                                let mut rv = r.to_api_json();
                                if !child_tree.is_empty() {
                                    expand_record(conn, &rel_coll, &mut rv, &child_tree);
                                }
                                expand_obj.insert(field_name.clone(), rv);
                            }
                        }
                    }
                }
                if !expand_obj.is_empty() {
                    obj.insert("expand".into(), Value::Object(expand_obj));
                }
            }
        }

        let mut expanded: Vec<Value> = Vec::with_capacity(records.len());
        for rec in &records {
            let mut rec = rec.clone();
            expand_record(&conn, &collection, &mut rec, &tree);
            expanded.push(rec);
        }
        records = expanded;
    }

    let total_pages = if per_page > 0 {
        (total + per_page - 1) / per_page
    } else {
        1
    };

    let skip_total = params
        .skip_total
        .as_deref()
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut out = Map::new();
    out.insert("page".into(), Value::Number(page.into()));
    out.insert("perPage".into(), Value::Number(per_page.into()));
    if !skip_total {
        out.insert("totalItems".into(), Value::Number(total.into()));
        out.insert("totalPages".into(), Value::Number(total_pages.into()));
    }
    // Fields projection.
    let fields_param = params.fields.clone().unwrap_or_default();
    if !fields_param.is_empty() {
        let wanted: Vec<&str> = fields_param.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let mut projected: Vec<Value> = Vec::with_capacity(records.len());
        for rec in &records {
            let mut obj = Map::new();
            if let Some(r) = rec.as_object() {
                // always include these
                for k in ["collectionId", "collectionName", "id", "expand"] {
                    if let Some(v) = r.get(k) {
                        obj.insert(k.to_string(), v.clone());
                    }
                }
                for w in &wanted {
                    if let Some(v) = r.get(*w) {
                        obj.insert(w.to_string(), v.clone());
                    }
                }
            }
            projected.push(Value::Object(obj));
        }
        records = projected;
    }

    out.insert("items".into(), Value::Array(records));
    Ok(Json(Value::Object(out)))
}

fn quote_table(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn build_order(collection: &Collection, sort: &str) -> String {
    if sort.is_empty() {
        return String::new();
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
        let col = match field {
            "@rowid" => "_rowid_".to_string(),
            "@created" | "@updated" | "@random" => field.trim_start_matches('@').to_string(),
            other => other.to_string(),
        };
        // validate column exists
        let exists = collection.field_list().items().iter().any(|f| {
            pb_core::fields::field_name(f) == col
        }) || col == "_rowid_" || col == "id" || col == "created" || col == "updated";
        if !exists {
            continue;
        }
        let dir = if desc { "DESC" } else { "ASC" };
        parts.push(format!("{} {}", quote_table(&col), dir));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("ORDER BY {}", parts.join(", "))
    }
}

/// `GET /api/collections/{collection}/records/{id}`
pub async fn view(
    State(db): State<Db>,
    headers: HeaderMap,
    Path((id_or_name, record_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let is_superuser = auth.as_ref().map(|a| a.is_superuser()).unwrap_or(false);

    let conn = db.lock().map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if !is_superuser && collection.view_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let record = Record::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found."))?;

    // View rule evaluation for non-superusers.
    if !is_superuser {
        if let Some(rule) = &collection.view_rule {
            if !rule.is_empty() {
                let data_map: serde_json::Map<String, serde_json::Value> = record.data.iter().map(|(k,v)|(k.clone(),v.clone())).collect();
                if !rule_passes(&conn, rule, &data_map, auth.as_ref().map(|a| &a.record)) {
                    return Err(ApiError::not_found("The requested resource wasn't found."));
                }
            }
        }
    }

    Ok(Json(record.to_api_json()))
}


fn rule_passes(
    conn: &rusqlite::Connection,
    rule: &str,
    record_data: &serde_json::Map<String, serde_json::Value>,
    auth: Option<&pb_core::records::Record>,
) -> bool {
    if rule.is_empty() {
        return true;
    }
    match pb_core::search::build_rule_sql(rule, record_data, auth) {
        Some((sql, params)) => {
            let full = format!("SELECT 1 WHERE {}", sql);
            let sqlite_params: Vec<rusqlite::types::Value> = params.iter().map(json_to_sqlite).collect();
            conn.query_row(&full, rusqlite::params_from_iter(sqlite_params), |_| Ok(())).is_ok()
        }
        None => true,
    }
}

/// `POST /api/collections/{collection}/records`
pub async fn create(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let is_superuser = auth.as_ref().map(|a| a.is_superuser()).unwrap_or(false);

    let mut conn = db.lock().map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if !is_superuser && collection.update_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let payload: Map<String, Value> = if body.is_empty() {
        Map::new()
    } else {
        match serde_json::from_slice(&body) {
            Ok(Value::Object(m)) => m,
            _ => return Err(ApiError::bad_request("Failed to load the submitted data due to invalid formatting.")),
        }
    };

    // Build column list from collection fields + id
    let fields = collection.field_list();
    let mut columns: Vec<String> = Vec::new();
    let mut placeholders: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();

    // id
    let id = payload.get("id").and_then(Value::as_str).map(String::from).unwrap_or_else(|| {
        // `r` + 14 hex chars (matches `DEFAULT ('r'||lower(hex(randomblob(7))))`).
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut out = String::from("r");
        for _ in 0..14 {
            out.push_str(&format!("{:x}", rng.gen_range(0..16u8)));
        }
        out
    });

    // Rule evaluation for non-superusers.
    if !is_superuser {
        if let Some(rule) = &collection.create_rule {
            if !rule.is_empty() {
                let mut data = payload.clone();
                data.insert("id".into(), Value::String(id.clone()));
                let data_map: serde_json::Map<String, serde_json::Value> = data.iter().map(|(k,v)|(k.clone(),v.clone())).collect();
                if !rule_passes(&conn, rule, &data_map, auth.as_ref().map(|a| &a.record)) {
                    return Err(ApiError::bad_request("Failed to create record."));
                }
            }
        }
    }

    columns.push("id".into());
    placeholders.push("?".into());
    values.push(Value::String(id.clone()));

    for field in fields.items() {
        let name = pb_core::fields::field_name(field).to_string();
        if name == "id" {
            continue;
        }
        let mut val = payload.get(&name).cloned().unwrap_or(Value::Null);
        // Go's JSON binder turns `null`/missing into the field zero value.
        if val.is_null() {
            val = field_default(field);
        }
        // Convert JSON to storage form
        let stored = json_to_column(&val, pb_core::fields::field_type(field));
        columns.push(name);
        placeholders.push("?".into());
        values.push(stored);
    }

    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        quote_table(&collection.name),
        columns.iter().map(|c| format!("\"{}\"", c.replace('"', "\"\""))).collect::<Vec<_>>().join(", "),
        placeholders.join(", ")
    );

    let params: Vec<rusqlite::types::Value> = values.iter().map(json_to_sqlite).collect();
    conn.execute(&sql, rusqlite::params_from_iter(params))
        .map_err(|e| ApiError::bad_request(format!("Failed to create record. Raw error: \n{e}")))?;

    let record = Record::find_by_id(&conn, &collection, &id)
        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
        .ok_or_else(|| ApiError::internal("created record is missing"))?;
    Ok(Json(record.to_api_json()))
}

fn field_default(field: &Value) -> Value {
    match pb_core::fields::field_type(field) {
        "number" => json!(0),
        "bool" => json!(false),
        "json" => Value::Null,
        "geoPoint" => json!({"lon": 0, "lat": 0}),
        "select" | "file" | "relation" if pb_core::fields::is_multiple(field) => json!([]),
        _ => json!(""),
    }
}

fn json_to_column(value: &Value, field_type: &str) -> Value {
    match field_type {
        "bool" => value.clone(),
        "number" => value.clone(),
        "json" => value.clone(),
        _ => value.clone(),
    }
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

/// `PATCH /api/collections/{collection}/records/{id}`
pub async fn update(
    State(db): State<Db>,
    headers: HeaderMap,
    Path((id_or_name, record_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let auth = load_auth(&db, &headers);
    let is_superuser = auth.as_ref().map(|a| a.is_superuser()).unwrap_or(false);

    let mut conn = db.lock().map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if !is_superuser && collection.update_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }

    let payload: Map<String, Value> = if body.is_empty() {
        Map::new()
    } else {
        match serde_json::from_slice(&body) {
            Ok(Value::Object(m)) => m,
            _ => return Err(ApiError::bad_request("Failed to load the submitted data due to invalid formatting.")),
        }
    };

    // Build SET clause
    let fields = collection.field_list();
    let mut sets = Vec::new();
    // Rule evaluation for non-superusers.
    if !is_superuser {
        if let Some(rule) = &collection.update_rule {
            if !rule.is_empty() {
                // Build updated record data.
                let existing = Record::find_by_id(&conn, &collection, &record_id)
                    .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
                    .ok_or_else(|| ApiError::not_found("The requested resource wasn't found."))?;
                let mut data = existing.data.clone();
                for (k, v) in &payload {
                    data.insert(k.clone(), v.clone());
                }
                let data_map: serde_json::Map<String, serde_json::Value> = data.iter().map(|(k,v)|(k.clone(),v.clone())).collect();
                if !rule_passes(&conn, rule, &data_map, auth.as_ref().map(|a| &a.record)) {
                    return Err(ApiError::bad_request("Failed to update record."));
                }
            }
        }
    }

    let mut values: Vec<Value> = Vec::new();
    for (key, val) in &payload {
        if key == "id" || key == "collectionId" || key == "collectionName" {
            continue;
        }
        // check field exists
        let field_type = fields.items().iter().find(|f| pb_core::fields::field_name(f) == key).map(|f| pb_core::fields::field_type(f).to_string());
        let ft = match field_type {
            Some(t) => t,
            None => continue,
        };
        sets.push(format!("{} = ?", quote_table(key)));
        values.push(json_to_column(val, &ft));
    }
    if sets.is_empty() {
        let record = Record::find_by_id(&conn, &collection, &record_id)
            .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
            .ok_or_else(|| ApiError::not_found("The requested resource wasn't found."))?;
        return Ok(Json(record.to_api_json()));
    }
    values.push(Value::String(record_id.clone()));
    let sql = format!(
        "UPDATE {} SET {} WHERE id = ?",
        quote_table(&collection.name),
        sets.join(", ")
    );
    let params: Vec<rusqlite::types::Value> = values.iter().map(json_to_sqlite).collect();
    conn.execute(&sql, rusqlite::params_from_iter(params))
        .map_err(|e| ApiError::bad_request(format!("Failed to update record. Raw error: \n{e}")))?;

    let record = Record::find_by_id(&conn, &collection, &record_id)
        .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found."))?;

    // View rule evaluation for non-superusers.
    if !is_superuser {
        if let Some(rule) = &collection.view_rule {
            if !rule.is_empty() {
                let data_map: serde_json::Map<String, serde_json::Value> = record.data.iter().map(|(k,v)|(k.clone(),v.clone())).collect();
                if !rule_passes(&conn, rule, &data_map, auth.as_ref().map(|a| &a.record)) {
                    return Err(ApiError::not_found("The requested resource wasn't found."));
                }
            }
        }
    }

    Ok(Json(record.to_api_json()))
}

/// `DELETE /api/collections/{collection}/records/{id}`
pub async fn delete(
    State(db): State<Db>,
    headers: HeaderMap,
    Path((id_or_name, record_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = load_auth(&db, &headers);
    let is_superuser = auth.as_ref().map(|a| a.is_superuser()).unwrap_or(false);

    let conn = db.lock().map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = find_collection(&conn, &id_or_name)?;

    if !is_superuser && collection.delete_rule.is_none() {
        return Err(ApiError::forbidden("Only superusers can perform this action."));
    }
    if !is_superuser {
        if let Some(rule) = &collection.delete_rule {
            if !rule.is_empty() {
                let existing = Record::find_by_id(&conn, &collection, &record_id)
                    .map_err(|e| ApiError::internal(format!("find failed: {e}")))?
                    .ok_or_else(|| ApiError::not_found("The requested resource wasn't found."))?;
                let data_map: serde_json::Map<String, serde_json::Value> = existing.data.iter().map(|(k,v)|(k.clone(),v.clone())).collect();
                if !rule_passes(&conn, rule, &data_map, auth.as_ref().map(|a| &a.record)) {
                    return Err(ApiError::bad_request("Failed to delete record."));
                }
            }
        }
    }

    let sql = format!("DELETE FROM {} WHERE id = ?1", quote_table(&collection.name));
    conn.execute(&sql, [&record_id])
        .map_err(|e| ApiError::bad_request(format!("Failed to delete record. Raw error: \n{e}")))?;
    Ok(StatusCode::NO_CONTENT)
}
