//! The PocketBase error envelope.
//!
//! Every error response is `{"data":{...},"message":"...","status":N}`. The
//! `message` strings are part of the contract (`docs/COMPATIBILITY.md` rule 3),
//! so they are copied from the oracle's recordings, not invented.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub data: Value,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>, data: Value) -> Self {
        Self {
            status,
            message: message.into(),
            data,
        }
    }

    /// `router.NewBadRequestError` with an explicit message.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message, json!({}))
    }

    /// `router.NewNotFoundError` with an explicit message.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message, json!({}))
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message, json!({}))
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message, json!({}))
    }

    /// A request body validation failure: `data` holds one entry per field.
    pub fn validation(data: Value) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "An error occurred while validating the submitted data.",
            data,
        )
    }

    /// `e.BadRequestError("An error occurred while loading the submitted data.", err)`
    pub fn body_load() -> Self {
        Self::bad_request("An error occurred while loading the submitted data.")
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            message,
            json!({}),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "data": self.data,
            "message": self.message,
            "status": self.status.as_u16(),
        });
        (self.status, Json(body)).into_response()
    }
}

/// A single validation failure in PocketBase's `{code,message}` shape.
pub fn validation_required() -> Value {
    json!({"code": "validation_required", "message": "Cannot be blank."})
}

/// `validation_length_out_of_range`, sentenized like `inflector.Sentenize`.
pub fn validation_length(min: usize, max: usize) -> Value {
    json!({
        "code": "validation_length_out_of_range",
        "message": format!("The length must be between {min} and {max}."),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_messages_match_the_oracle_wording() {
        assert_eq!(validation_required()["message"], "Cannot be blank.");
        assert_eq!(
            validation_length(1, 255)["message"],
            "The length must be between 1 and 255."
        );
    }
}
