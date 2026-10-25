//! HTTP surface. M1 exposes `/api/health`, the JSON 404 envelope and the
//! embedded admin UI. Every response shape here is copied from a recorded
//! oracle response (`harness` goldens), not from documentation.

use std::path::PathBuf;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::Value;
use tower_http::services::{ServeDir, ServeFile};

/// Re-exported so the CLI can run the server without a direct axum dependency.
pub use axum;

/// `GET /api/health` — `{"message":"API is healthy.","code":200,"data":{}}`
#[derive(Serialize)]
struct HealthResponse {
    message: &'static str,
    code: u16,
    data: Value,
}

/// PocketBase's error envelope: `{"data":{},"message":"...","status":N}`
#[derive(Serialize)]
struct ErrorResponse {
    data: Value,
    message: String,
    status: u16,
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        message: "API is healthy.",
        code: 200,
        data: Value::Object(Default::default()),
    })
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            data: Value::Object(Default::default()),
            message: "File not found.".to_string(),
            status: 404,
        }),
    )
}

/// Build the router.
///
/// `ui_dir` is the mirrored admin UI directory (`ui/_`); when present it is
/// served under `/_/` with SPA fallback, exactly like the embedded FS.
pub fn router(ui_dir: Option<PathBuf>) -> Router {
    let mut app = Router::new().route("/api/health", get(health));

    if let Some(dir) = ui_dir {
        let index = dir.join("index.html");
        let service = ServeDir::new(&dir).fallback(ServeFile::new(index));
        app = app.nest_service("/_", service);
    }

    app.fallback(not_found)
}
