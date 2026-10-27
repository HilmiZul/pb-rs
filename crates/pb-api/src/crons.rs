//! `/api/crons` — list and manually run the built-in cron jobs.
//!
//! The scheduler itself is not implemented yet; the jobs and their
//! expressions match the oracle so the admin UI shows the same list, and
//! `POST /api/crons/{id}` executes the same cleanup work on demand.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use pb_core::collections::Collection;
use serde_json::{json, Value};

use crate::auth::{require_superuser, Db};
use crate::error::ApiError;

struct Job {
    id: &'static str,
    expression: &'static str,
}

const JOBS: &[Job] = &[
    Job {
        id: "__pbDBOptimize__",
        expression: "0 0 * * *",
    },
    Job {
        id: "__pbMFACleanup__",
        expression: "0 * * * *",
    },
    Job {
        id: "__pbOTPCleanup__",
        expression: "0 * * * *",
    },
    Job {
        id: "__pbLogsCleanup__",
        expression: "0 */6 * * *",
    },
];

fn job_list(conn: &rusqlite::Connection) -> Vec<Value> {
    let mut jobs: Vec<Value> = JOBS
        .iter()
        .map(|job| json!({"id": job.id, "expression": job.expression}))
        .collect();
    if let Ok(settings) = pb_core::settings::load(conn) {
        if !settings.backups.cron.is_empty() {
            jobs.push(json!({
                "id": "__pbAutoBackup__",
                "expression": settings.backups.cron,
            }));
        }
        if settings.rate_limits.enabled {
            jobs.push(json!({
                "id": "__pbRateLimitersCleanup__",
                "expression": "2 * * * *",
            }));
        }
    }
    jobs
}

pub async fn list(
    State(db): State<Db>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    Ok(Json(Value::Array(job_list(&conn))))
}

fn delete_expired(
    conn: &rusqlite::Connection,
    collection_name: &str,
    options_key: &str,
) -> Result<(), String> {
    let collections = Collection::load_all(conn).map_err(|e| e.to_string())?;
    for collection in collections.iter().filter(|c| c.is_auth()) {
        let duration = collection
            .options
            .get(options_key)
            .and_then(|v| v.get("duration"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        conn.execute(
            &format!(
                "DELETE FROM {collection_name} WHERE collectionRef = ?1 AND created < strftime('%Y-%m-%d %H:%M:%fZ','now','-{duration} seconds')"
            ),
            [&collection.id],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn cleanup_logs(conn: &rusqlite::Connection) -> Result<(), String> {
    let Some(aux) = crate::records::AUX_DB.get() else {
        return Ok(());
    };
    let aux = aux.lock().map_err(|_| "aux lock poisoned".to_string())?;
    let max_days = {
        let settings = pb_core::settings::load(conn).map_err(|e| e.to_string())?;
        settings.logs.max_days
    };
    aux.execute(
        "DELETE FROM _logs WHERE created < strftime('%Y-%m-%d %H:%M:%fZ','now', ?1)",
        [format!("-{max_days} days")],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn run(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;

    let known = {
        let conn = db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        job_list(&conn)
            .iter()
            .any(|job| job["id"].as_str() == Some(id.as_str()))
    };
    if !known {
        return Err(ApiError::not_found("Missing or invalid cron job."));
    }

    let db = db.clone();
    std::thread::spawn(move || {
        let result: Result<(), String> = (|| {
            let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
            match id.as_str() {
                "__pbDBOptimize__" => {
                    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                    if let Some(aux) = crate::records::AUX_DB.get() {
                        if let Ok(aux) = aux.lock() {
                            let _ = aux.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                        }
                    }
                    let _ = conn.execute_batch("PRAGMA optimize");
                }
                "__pbMFACleanup__" => delete_expired(&conn, "_mfas", "mfa")?,
                "__pbOTPCleanup__" => delete_expired(&conn, "_otps", "otp")?,
                "__pbLogsCleanup__" => cleanup_logs(&conn)?,
                "__pbAutoBackup__" => {
                    let settings =
                        pb_core::settings::load(&conn).map_err(|e| e.to_string())?;
                    let app_name = {
                        let mut out = String::new();
                        let mut word = String::new();
                        let flush = |word: &mut String, out: &mut String| {
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
                        };
                        for ch in settings.meta.app_name.chars() {
                            if ch.is_alphanumeric() {
                                word.push(ch);
                            } else {
                                flush(&mut word, &mut out);
                            }
                        }
                        flush(&mut word, &mut out);
                        out.to_lowercase()
                    };
                    let app_name = if app_name.len() > 50 {
                        &app_name[..50]
                    } else {
                        &app_name
                    };
                    let timestamp: String = conn
                        .query_row("SELECT strftime('%Y%m%d%H%M%S','now')", [], |r| r.get(0))
                        .map_err(|e| e.to_string())?;
                    let name = format!("@auto_pb_backup_{app_name}_{timestamp}.zip");
                    drop(conn);
                    crate::backups::create_backup_now(&db, &name)?;

                    let max_keep = settings.backups.cron_max_keep;
                    if max_keep > 0 {
                        crate::backups::prune_auto_backups(max_keep as usize);
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(err) = result {
            eprintln!("cron job {id} failed: {err}");
        }
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Unused helper kept for symmetry with the query-string based endpoints.
#[allow(dead_code)]
fn _unused(_: HashMap<String, String>) {}
