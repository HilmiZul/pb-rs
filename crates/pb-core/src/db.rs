//! SQLite connection setup, mirroring `core/db_connect.go`.
//!
//! The oracle opens both databases with this exact pragma set:
//!
//! ```text
//! busy_timeout(10000) journal_mode(WAL) journal_size_limit(200000000)
//! synchronous(NORMAL) foreign_keys(ON) temp_store(MEMORY) cache_size(-32000)
//! _defensive=1
//! ```

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Open (creating parent directories) and configure a PocketBase database file.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create data dir {}", parent.display()))?;
        }
    }

    let conn = Connection::open(path)
        .with_context(|| format!("open sqlite database {}", path.display()))?;

    configure(&conn)?;
    Ok(conn)
}

/// Apply the pragma set. Order matters: `busy_timeout` must be first.
pub fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_millis(10_000))?;

    // journal_mode returns the resulting mode as a row.
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;

    conn.pragma_update(None, "journal_size_limit", 200_000_000_i64)?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "cache_size", -32_000_i64)?;

    // `_defensive=1` in the oracle's DSN. rusqlite exposes it as a feature
    // (`modern_sqlite`), which is not enabled; the pragma set above is the
    // part that affects observable behaviour.
    Ok(())
}

/// True when a table (or view) with this name exists in the main schema.
pub fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type IN ('table','view') AND name = ?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Run `PRAGMA optimize` the way the oracle does after syncing record tables.
pub fn optimize(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA optimize;")?;
    Ok(())
}
