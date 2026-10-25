//! Superuser bootstrap, mirroring `apis/installer.go` + `core/record_model_superusers.go`.
//!
//! On every `serve`, the oracle checks whether any superuser other than the
//! installer placeholder exists. If none does, it creates
//! `__pbinstaller@example.com` with a random password and a random `tokenKey`,
//! then hands a short-lived auth token to the installer UI. The record itself is
//! deleted as soon as a real superuser is created.
//!
//! Replicating the row matters for drop-in behaviour: without it, a port-created
//! install looks like "a superuser already exists" to the oracle and the
//! installer flow would be skipped.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::ids;

/// `core.DefaultInstallerEmail`
pub const DEFAULT_INSTALLER_EMAIL: &str = "__pbinstaller@example.com";

/// `core.CollectionNameSuperusers`
pub const COLLECTION_NAME_SUPERUSERS: &str = "_superusers";

/// bcrypt cost used by the oracle (`$2a$10$`).
const BCRYPT_COST: u32 = 10;
/// `SetRandomPassword` uses `security.RandomString(30)`.
const RANDOM_PASSWORD_LENGTH: usize = 30;
/// The `tokenKey` field autogenerates `[a-zA-Z0-9]{50}`.
const TOKEN_KEY_LENGTH: usize = 50;

/// `needInstallerSuperuser`: true when every existing superuser is the
/// installer placeholder (or there are none at all).
pub fn needs_installer_superuser(conn: &Connection) -> Result<bool> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM _superusers WHERE email <> ?1",
        [DEFAULT_INSTALLER_EMAIL],
        |row| row.get(0),
    )?;
    Ok(total == 0)
}

/// `findOrCreateInstallerSuperuser`. Returns `true` when a row was inserted.
pub fn ensure_installer_superuser(conn: &Connection) -> Result<bool> {
    if !needs_installer_superuser(conn)? {
        return Ok(false);
    }

    let existing: i64 = conn.query_row(
        "SELECT count(*) FROM _superusers WHERE email = ?1",
        [DEFAULT_INSTALLER_EMAIL],
        |row| row.get(0),
    )?;
    if existing > 0 {
        return Ok(false);
    }

    let password = ids::random_string(RANDOM_PASSWORD_LENGTH);
    let hash = bcrypt::hash_with_result(password, BCRYPT_COST)
        .context("hash installer password")?
        // The oracle's hashes are `$2a$` (Go's x/crypto/bcrypt); the crate
        // defaults to `$2b$`. Both verify in Go, but matching the prefix keeps
        // at-rest dumps comparable.
        .format_for_version(bcrypt::Version::TwoA);

    conn.execute(
        "INSERT INTO _superusers
            (id, email, emailVisibility, password, tokenKey, verified, created, updated)
         VALUES (?1, ?2, 0, ?3, ?4, 1,
                 strftime('%Y-%m-%d %H:%M:%fZ', 'now'),
                 strftime('%Y-%m-%d %H:%M:%fZ', 'now'))",
        rusqlite::params![
            ids::default_random_id(),
            DEFAULT_INSTALLER_EMAIL,
            hash,
            ids::random_string(TOKEN_KEY_LENGTH),
        ],
    )
    .context("create installer superuser")?;

    Ok(true)
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
    fn creates_the_installer_row_once() {
        let conn = fresh();
        assert!(ensure_installer_superuser(&conn).unwrap());
        assert!(!ensure_installer_superuser(&conn).unwrap());

        let (email, verified, hash): (String, i64, String) = conn
            .query_row(
                "SELECT email, verified, password FROM _superusers",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(email, DEFAULT_INSTALLER_EMAIL);
        assert_eq!(verified, 1);
        assert!(hash.starts_with("$2a$10$"), "unexpected hash: {hash}");
    }

    #[test]
    fn skips_when_a_real_superuser_exists() {
        let conn = fresh();
        conn.execute(
            "INSERT INTO _superusers (id, email, password, tokenKey, verified)
             VALUES ('abc123456789012', 'admin@example.com', '', 'k', 1)",
            [],
        )
        .unwrap();
        assert!(!ensure_installer_superuser(&conn).unwrap());
        let count: i64 = conn
            .query_row("SELECT count(*) FROM _superusers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
