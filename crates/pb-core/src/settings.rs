//! Application settings: the `settings` row of `_params`.
//!
//! The API shape is the stored JSON with one twist: `settingsList` serves a
//! clone whose SMTP password is hidden (`Settings.Clone` sets `hidePassword`,
//! and the field is then serialized with `omitempty`). Everything else is
//! passed through verbatim, including key order.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;

pub const PARAM_ID: &str = "settings";

/// Load the raw stored settings JSON.
pub fn load_raw(conn: &Connection) -> Result<Value> {
    // `_params.value` is a BLOB in an oracle-created database (Go binds
    // `types.JSONRaw`); accept TEXT too so hand-edited databases still load.
    let raw: Option<rusqlite::types::Value> = conn
        .query_row("SELECT value FROM _params WHERE id = ?1", [PARAM_ID], |row| {
            row.get(0)
        })
        .optional()?;

    let bytes = match raw {
        Some(rusqlite::types::Value::Blob(bytes)) => bytes,
        Some(rusqlite::types::Value::Text(text)) => text.into_bytes(),
        Some(rusqlite::types::Value::Null) | None => {
            return Ok(Value::Object(Default::default()))
        }
        Some(other) => anyhow::bail!("unexpected _params.value storage class: {other:?}"),
    };

    serde_json::from_slice(&bytes).context("parse stored settings")
}

/// Persist settings, keeping the oracle's BLOB storage class.
pub fn save_raw(conn: &Connection, settings: &Value) -> Result<()> {
    let json = serde_json::to_vec(settings).context("serialize settings")?;
    conn.execute(
        "INSERT INTO _params (id, value) VALUES (?1, ?2)
         ON CONFLICT(id) DO UPDATE SET value = excluded.value,
                                       updated = strftime('%Y-%m-%d %H:%M:%fZ', 'now')",
        rusqlite::params![PARAM_ID, json],
    )
    .context("save settings")?;
    Ok(())
}

/// The JSON served by `GET /api/settings`.
pub fn api_json(conn: &Connection) -> Result<Value> {
    let mut settings = load_raw(conn)?;
    hide_smtp_password(&mut settings);
    Ok(settings)
}

/// `SMTPConfig.MarshalJSON` with `hidePassword`: an empty password is dropped,
/// a non-empty one is still serialized.
fn hide_smtp_password(settings: &mut Value) {
    let Some(smtp) = settings.get_mut("smtp").and_then(Value::as_object_mut) else {
        return;
    };
    if smtp
        .get("password")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(false)
    {
        smtp.remove("password");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{migrations, seed};

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrations::migrate_data(&conn).unwrap();
        seed::seed(&conn).unwrap();
        conn
    }

    #[test]
    fn api_json_hides_an_empty_smtp_password() {
        let conn = fresh();
        let json = api_json(&conn).unwrap();
        assert!(json["smtp"].get("password").is_none());
        assert_eq!(json["meta"]["appName"], "Acme");
    }

    #[test]
    fn api_json_keeps_a_non_empty_smtp_password() {
        let conn = fresh();
        let mut raw = load_raw(&conn).unwrap();
        raw["smtp"]["password"] = Value::String("hunter2".into());
        save_raw(&conn, &raw).unwrap();
        let json = api_json(&conn).unwrap();
        assert_eq!(json["smtp"]["password"], "hunter2");
    }
}
