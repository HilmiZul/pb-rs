//! Settings endpoints.
//!
//! `GET /api/settings` serves the masked settings (`Settings.MarshalJSON`);
//! `PATCH /api/settings` binds the submitted JSON onto a clone of the current
//! settings, validates and persists it (`apis/settings.go: settingsSet`).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use pb_core::settings::{self, Settings};
use serde_json::Value;

use crate::auth::{require_superuser, Db};
use crate::error::ApiError;

/// `GET /api/settings`
pub async fn list(State(db): State<Db>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let settings = settings::api_json(&conn)
        .map_err(|e| ApiError::internal(format!("failed to load settings: {e}")))?;
    Ok(Json(settings))
}

/// `e.BadRequestError("An error occurred while loading the submitted data.", err)`
fn load_error() -> ApiError {
    ApiError::bad_request("An error occurred while loading the submitted data.")
}

/// `PATCH /api/settings`
pub async fn set(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;

    let patch = bind_body(&headers, &body)?;

    // A JSON `null` body nils the target pointer in Go and the save panics;
    // the router recovers it as a generic 500.
    if patch.as_ref().is_some_and(Value::is_null) {
        return Err(ApiError::internal(
            "Something went wrong while processing your request.",
        ));
    }

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;

    let settings = match &patch {
        // A type mismatch while binding is a load error, not an internal one.
        Some(patch) => settings::load_with_patch(&conn, patch).map_err(|_| load_error())?,
        None => settings::load(&conn).map_err(|e| {
            ApiError::internal(format!("failed to load settings: {e}"))
        })?,
    };

    let errors = settings::validate(&settings);
    if !errors.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "An error occurred while saving the new settings.",
            settings::errors_to_value(&errors),
        )
        .with_raw_data(pb_core::validation::errors_to_log_value(&errors)));
    }

    // The save hook normalizes nothing else; persist as-is.
    settings::save(&conn, &settings)
        .map_err(|e| ApiError::internal(format!("failed to save settings: {e}")))?;

    // `OnSettingsReload` destroys the rate limiter store.
    crate::rate_limit::reset();

    let saved: Settings = settings::load(&conn)
        .map_err(|e| ApiError::internal(format!("failed to reload settings: {e}")))?;
    Ok(Json(saved.to_api_json()))
}

/// `router.Event.BindBody` for the settings endpoint.
///
/// Returns `None` when the request carries no bindable data: an empty body, or
/// a form-encoded body (PocketBase binds those through form tags, which the
/// admin UI never uses for settings).
fn bind_body(headers: &HeaderMap, body: &[u8]) -> Result<Option<Value>, ApiError> {
    crate::body::bind_json(headers, body).map_err(|_| load_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderValue};

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
        headers
    }

    #[test]
    fn binds_json_and_ignores_trailing_bytes() {
        let json = headers("application/json");
        let value = bind_body(&json, br#"{"meta":{"appName":"X"}}"#)
            .unwrap()
            .unwrap();
        assert_eq!(value["meta"]["appName"], "X");
        // Go decodes the first value and ignores the rest.
        assert!(bind_body(&json, br#"{"meta":{}} trailing"#).is_ok());
    }

    #[test]
    fn empty_body_is_a_no_op() {
        assert_eq!(bind_body(&headers("application/json"), b"").unwrap(), None);
    }

    #[test]
    fn form_bodies_are_accepted_as_a_no_op() {
        assert_eq!(
            bind_body(&headers("application/x-www-form-urlencoded"), b"meta.appName=X").unwrap(),
            None
        );
    }

    #[test]
    fn unsupported_content_types_fail_to_bind() {
        assert!(bind_body(&headers("text/plain"), br#"{"meta":{}}"#).is_err());
    }

    #[test]
    fn invalid_json_fails_to_bind() {
        assert!(bind_body(&headers("application/json"), b"{").is_err());
    }
}
