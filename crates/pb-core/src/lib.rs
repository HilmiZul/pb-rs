//! Core of the PocketBase-compatible Rust server.
//!
//! Everything here is driven by facts extracted from the reference binary
//! (v0.40.6, commit 9d281cca) and verified by the differential harness.

pub mod db;
pub mod ids;
pub mod migrations;
pub mod seed;
pub mod superusers;

/// API version reported to clients. Must match the oracle, because the admin UI
/// and SDKs gate features on it.
pub const VERSION: &str = "0.40.6";

/// The PocketBase data directory layout (relative to `--dir`).
pub const DATA_DB: &str = "data.db";
pub const AUX_DB: &str = "auxiliary.db";
pub const TYPES_DTS: &str = "types.d.ts";

/// Generated JSVM typings written into the data directory on startup, exactly
/// as the oracle does.
pub const TYPES_DTS_CONTENT: &str = include_str!("../assets/types.d.ts");
