//! Settings endpoints (read-only in M2a).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::Value;

use crate::auth::{require_superuser, Db};
use crate::error::ApiError;

/// `GET /api/settings`
pub async fn list(State(db): State<Db>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let settings = pb_core::settings::api_json(&conn)
        .map_err(|e| ApiError::internal(format!("failed to load settings: {e}")))?;
    Ok(Json(settings))
}
