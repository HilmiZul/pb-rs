//! HTTP surface. Every response shape here is copied from a recorded oracle
//! response (`harness` goldens), not from documentation.

use std::path::PathBuf;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;
use tower_http::services::{ServeDir, ServeFile};

/// Re-exported so the CLI can run the server without a direct axum dependency.
pub use axum;

pub mod auth;
pub mod body;
pub mod collections;
pub mod error;
pub mod records;
pub mod settings;

use auth::Db;

/// `GET /api/health` — `{"message":"API is healthy.","code":200,"data":{}}`
#[derive(Serialize)]
struct HealthResponse {
    message: &'static str,
    code: u16,
    data: Value,
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
        Json(serde_json::json!({
            "data": {},
            "message": "File not found.",
            "status": 404,
        })),
    )
}

/// Build the router.
///
/// `ui_dir` is the mirrored admin UI directory (`ui/_`); when present it is
/// served under `/_/` with SPA fallback, exactly like the embedded FS.
pub fn router(conn: Connection, ui_dir: Option<PathBuf>, data_dir: Option<PathBuf>) -> Router {
    if let Some(dir) = data_dir {
        let _ = records::DATA_DIR.set(dir);
    }
    let api = Router::new()
        .route("/health", get(health))
        .route("/settings", get(settings::list).patch(settings::set))
        .route(
            "/collections",
            get(collections::list).post(collections::create),
        )
        .route("/collections/import", axum::routing::put(collections::import))
        // Static `meta` routes must be declared before the `:collection`
        // wildcard; matchit prefers static segments regardless of order, but
        // keeping them together documents the relationship.
        .route("/collections/meta/scaffolds", get(collections::scaffolds))
        .route(
            "/collections/meta/dry-run-view",
            axum::routing::post(collections::dry_run_view),
        )
        .route(
            "/collections/meta/oauth2-providers",
            get(collections::oauth2_providers),
        )
        .route(
            "/collections/:collection",
            get(collections::view)
                .patch(collections::update)
                .delete(collections::delete),
        )
        .route(
            "/collections/:collection/truncate",
            delete(collections::truncate),
        )
        .route(
            "/collections/:collection/records",
            get(records::list).post(records::create),
        )
        .route(
            "/collections/:collection/records/:id",
            get(records::view).patch(records::update).delete(records::delete),
        )
        .route("/collections/:collection/auth-methods", get(records::methods))
        .route(
            "/collections/:collection/auth-with-password",
            post(records::with_password),
        )
        .route(
            "/collections/:collection/request-otp",
            post(records::request_otp),
        )
        .route(
            "/collections/:collection/auth-with-otp",
            post(records::auth_with_otp),
        )
        .route(
            "/collections/:collection/auth-with-oauth2",
            post(records::auth_with_oauth2),
        )
        .route(
            "/collections/:collection/request-password-reset",
            post(records::request_password_reset),
        )
        .route(
            "/collections/:collection/confirm-password-reset",
            post(records::confirm_password_reset),
        )
        .route(
            "/collections/:collection/request-verification",
            post(records::request_verification),
        )
        .route(
            "/collections/:collection/confirm-verification",
            post(records::confirm_verification),
        )
        .route(
            "/collections/:collection/request-email-change",
            post(records::request_email_change),
        )
        .route(
            "/collections/:collection/confirm-email-change",
            post(records::confirm_email_change),
        )
        .route(
            "/collections/:collection/auth-refresh",
            post(records::refresh),
        )
        .route("/files/token", post(records::file_token))
        .route(
            "/files/:collection/:recordId/:filename",
            get(records::file_download),
        );

    let mut app = Router::new().nest("/api", api);

    if let Some(dir) = ui_dir {
        let index = dir.join("index.html");
        let service = ServeDir::new(&dir).fallback(ServeFile::new(index));
        app = app.nest_service("/_", service);
    }

    let db: Db = std::sync::Arc::new(std::sync::Mutex::new(conn));
    app.with_state(db).fallback(not_found)
}
