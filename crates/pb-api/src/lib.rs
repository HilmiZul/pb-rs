//! HTTP surface. Every response shape here is copied from a recorded oracle
//! response (`harness` goldens), not from documentation.

use std::path::PathBuf;

use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;
use tower_http::services::{ServeDir, ServeFile};

/// Re-exported so the CLI can run the server without a direct axum dependency.
pub use axum;

pub mod activity;
pub mod auth;
pub mod backups;
pub mod batch;
pub mod crons;
pub mod body;
pub mod collections;
pub mod error;
pub mod rate_limit;
pub mod realtime;
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

/// PocketBase's router has no method-specific 405: unmatched requests fall
/// through to its catch-all. `examples/base` additionally registers a
/// `GET /{path...}` static handler, so GET/HEAD misses report `File not found.`
/// while every other method reports the generic 404.
async fn not_found(method: axum::http::Method) -> error::ApiError {
    if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
        error::ApiError::not_found("File not found.")
    } else {
        error::ApiError::not_found("The requested resource wasn't found.")
    }
}

/// Build the router.
///
/// `ui_dir` is the mirrored admin UI directory (`ui/_`); when present it is
/// served under `/_/` with SPA fallback, exactly like the embedded FS.
pub fn router(conn: Connection, ui_dir: Option<PathBuf>, data_dir: Option<PathBuf>, aux_conn: Option<Connection>) -> Router {
    if let Some(dir) = data_dir {
        let _ = records::DATA_DIR.set(dir);
    }
    if let Some(ac) = aux_conn {
        let _ = records::AUX_DB.set(std::sync::Arc::new(std::sync::Mutex::new(ac)));
    }
    let db: Db = std::sync::Arc::new(std::sync::Mutex::new(conn));
    // `OnServe`: start the cron ticker once the server is about to run.
    crons::start_scheduler(db.clone());
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
        )
        .route("/logs", get(records::logs_list).delete(records::logs_truncate))
        .route("/logs/stats", get(records::logs_stats))
        .route("/logs/:id", get(records::logs_view))
        .route("/realtime", get(records::realtime_connect).post(records::realtime_subscribe))
        .route("/batch", post(batch::batch_transaction))
        .route("/backups", get(backups::list).post(backups::create))
        .route("/backups/upload", post(backups::upload))
        .route(
            "/backups/:key",
            get(backups::download).delete(backups::delete),
        )
        .route("/backups/:key/restore", post(backups::restore))
        .route("/crons", get(crons::list))
        .route("/crons/:id", post(crons::run));

    // PocketBase's router has no method-specific 405: an unmatched
    // method+path combination falls through to the 404 handler.
    let api = api.method_not_allowed_fallback(not_found);

    let mut app = Router::new().nest("/api", api);

    if let Some(dir) = ui_dir {
        let index = dir.join("index.html");
        let service = ServeDir::new(&dir).fallback(ServeFile::new(index));
        app = app.nest_service("/_", service);
    }

    // The oracle binds the activity logger on the root router, so unmatched
    // `/api/*` paths and the static UI are logged too.
    app.fallback(not_found)
        // Layer order: the last layer added is the outermost. The activity
        // logger wraps everything (so 429s are logged), the global limiter runs
        // before the collection-scoped one, mirroring the oracle priorities.
        .layer(axum::middleware::from_fn_with_state(
            db.clone(),
            rate_limit::collection_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            db.clone(),
            rate_limit::global_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            db.clone(),
            activity::activity_logger,
        ))
        .with_state(db)
}
