//! PocketBase-compatible CLI.
//!
//! Flag names, defaults and subcommand names mirror the cobra definitions of the
//! reference binary (v0.42.3). `serve` and `--version` are functional in M1;
//! `superuser`, `migrate` and `update` are declared so scripts fail loudly
//! instead of hitting an unknown-command path.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "pocketbase",
    version = "version 0.42.3",
    about = "pocketbase CLI",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(flatten)]
    global: Global,

    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Args, Clone)]
struct Global {
    /// enable/disable auto migrations
    #[arg(long, global = true, default_value_t = true, action = ArgAction::Set)]
    automigrate: bool,

    /// enable dev mode, aka. printing logs and sql statements to the console
    #[arg(long, global = true)]
    dev: bool,

    /// the PocketBase data directory
    #[arg(long, global = true, default_value = "pb_data")]
    dir: PathBuf,

    /// the env variable whose value of 32 characters will be used as encryption key for the app settings
    #[arg(long = "encryptionEnv", global = true)]
    encryption_env: Option<String>,

    /// the directory with the JS app hooks
    #[arg(long = "hooksDir", global = true)]
    hooks_dir: Option<PathBuf>,

    /// the total prewarm goja.Runtime instances for the JS app hooks execution
    #[arg(long = "hooksPool", global = true, default_value_t = 15)]
    hooks_pool: u32,

    /// auto restart the app on pb_hooks file change; it has no effect on Windows
    #[arg(long = "hooksWatch", global = true, default_value_t = true, action = ArgAction::Set)]
    hooks_watch: bool,

    /// fallback the request to index.html on missing static path
    #[arg(long = "indexFallback", global = true, default_value_t = true, action = ArgAction::Set)]
    index_fallback: bool,

    /// the directory with the user defined migrations
    #[arg(long = "migrationsDir", global = true)]
    migrations_dir: Option<PathBuf>,

    /// the directory to serve static files
    #[arg(long = "publicDir", global = true, default_value = "pb_public")]
    public_dir: PathBuf,

    /// the default SELECT queries timeout in seconds
    #[arg(long = "queryTimeout", global = true, default_value_t = 30)]
    query_timeout: u32,
}

#[derive(Subcommand)]
enum Command {
    /// Starts the web server (default to 127.0.0.1:8090 if no domain is specified)
    Serve(ServeArgs),

    /// Manage superusers
    Superuser {
        #[command(subcommand)]
        cmd: Option<SuperuserCommand>,
    },

    /// Executes app DB migration scripts
    Migrate {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Automatically updates the current app executable with the latest available version
    Update,
}

#[derive(Args)]
struct ServeArgs {
    /// domain(s) to serve on
    domains: Vec<String>,

    /// TCP address to listen for the HTTP server
    #[arg(long)]
    http: Option<String>,

    /// TCP address to listen for the HTTPS server
    #[arg(long)]
    https: Option<String>,

    /// CORS allowed domain origins list
    #[arg(long, value_delimiter = ',')]
    origins: Option<Vec<String>>,
}

#[derive(Subcommand)]
enum SuperuserCommand {
    /// Creates a new superuser
    Create {
        email: String,
        password: String,
    },
    /// Changes the password of a single superuser
    Update {
        email: String,
        password: String,
    },
    /// Creates, or updates if email exists, a single superuser
    Upsert {
        email: String,
        password: String,
    },
    /// Deletes an existing superuser
    Delete { email: String },
    /// Creates a new OTP for the specified superuser
    Otp { email: String },
    /// Updates the superuser IPs whitelist setting
    Ips {
        #[arg(trailing_var_arg = true)]
        ips: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Some(Command::Serve(args)) => serve(cli.global, args),
        Some(Command::Superuser { cmd }) => superuser(cli.global, cmd),
        Some(Command::Migrate { args }) => migrate(cli.global, args),
        Some(Command::Update) => bail!("update: not implemented yet (M5)"),
        None => {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

fn serve(global: Global, args: ServeArgs) -> Result<()> {
    init_tracing(&global);

    if args.https.is_some() {
        bail!("TLS serving is not implemented yet; use --http");
    }

    let data_db = bootstrap(&global.dir)?;
    if pb_core::superusers::ensure_installer_superuser(&data_db)? {
        tracing::info!("created the installer superuser");
    }

    let hooks_dir = global.hooks_dir.clone().unwrap_or_else(|| {
        global
            .dir
            .parent()
            .map(|parent| parent.join("pb_hooks"))
            .unwrap_or_else(|| PathBuf::from("pb_hooks"))
    });
    if pb_js::has_hooks(&hooks_dir) {
        let engine = pb_js::HookEngine::load_with_data_dir(&hooks_dir, &global.dir)
            .with_context(|| format!("load JS hooks from {}", hooks_dir.display()))?;
        pb_api::install_hook_engine(std::sync::Arc::new(engine));
    }

    let addr = resolve_addr(&args)?;
    let ui_dir = resolve_ui_dir();

    // PocketBase's install flow: when no real superuser exists, mint a
    // short-lived auth token for the installer placeholder, print (and open)
    // the `/_/#/pbinstall/<token>` URL, and redirect the UI there automatically.
    let mut install_token: Option<String> = None;
    if pb_core::superusers::needs_installer_superuser(&data_db).unwrap_or(false) {
        if let Ok(Some(col)) =
            pb_core::collections::Collection::find(&data_db, pb_core::superusers::COLLECTION_NAME_SUPERUSERS)
        {
            if let Ok(Some(rec)) =
                pb_core::records::Record::find_by_email(&data_db, &col, pb_core::superusers::DEFAULT_INSTALLER_EMAIL)
            {
                let secret = col.token_secret("authToken").unwrap_or("");
                let key = pb_core::tokens::signing_key(rec.token_key(), secret);
                let claims = pb_core::tokens::RecordClaims::auth(rec.id(), &col.id, false);
                if let Ok(token) = pb_core::tokens::new_jwt(&claims, &key, 30 * 60) {
                    let base_url = format!("http://{}", addr);
                    let url = format!("{}/_/#/pbinstall/{}", base_url.trim_end_matches('/'), token);
                    println!();
                    println!("(!) Launch the URL below in the browser if it hasn't been open already to create your first superuser account:");
                    println!("{}", url);
                    println!(
                        "(you can also create your first superuser by running: {} superuser upsert EMAIL PASS)",
                        std::env::current_exe()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|_| "pocketbase".to_string())
                    );
                    println!();
                    open_in_browser(&url);
                    install_token = Some(token);
                }
            }
        }
    }

    // tracing::info!(%addr, ui = ?ui_dir, "starting server");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(64)
        .enable_all()
        .build()?;

    let data_pool = pb_api::auth::Db::open(&global.dir.join(pb_core::DATA_DB), 32)
        .context("open data db pool")?;
    let aux_pool = pb_api::auth::Db::open(&global.dir.join(pb_core::AUX_DB), 8)
        .context("open aux db pool")?;

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .with_context(|| format!("bind {addr}"))?;
        // println!("Server started at http://{addr}");
        println!("REST API: http://{addr}/api");
        println!("UI: http://{addr}/_");
        let app = pb_api::router(data_pool, ui_dir, Some(global.dir.clone()), Some(aux_pool), args.origins.clone(), install_token)
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        pb_api::axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("http server")?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/// Open (and if needed create) the data directory's databases, applying
/// migrations and seeding. Shared by `serve` and `superuser`.
fn bootstrap(data_dir: &Path) -> Result<pb_core::rusqlite::Connection> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("create data dir {}", data_dir.display()))?;
    // `LocalTempDirName` is deleted on every app bootstrap.
    let _ = std::fs::remove_dir_all(data_dir.join(".pb_temp_to_delete"));

    let data_db = pb_core::db::open(&data_dir.join(pb_core::DATA_DB))?;
    let recorded = pb_core::migrations::migrate_data(&data_db)?;
    if recorded > 0 {
        tracing::info!(migrations = recorded, "applied migrations");
    }
    pb_core::seed::seed(&data_db)?;

    let aux_db = pb_core::db::open(&data_dir.join(pb_core::AUX_DB))?;
    pb_core::migrations::migrate_aux(&aux_db)?;

    write_types_dts(data_dir)?;
    pb_core::db::optimize(&data_db)?;

    Ok(data_db)
}

fn superuser(global: Global, cmd: Option<SuperuserCommand>) -> Result<()> {
    let Some(cmd) = cmd else {
        bail!("superuser: missing subcommand (create, update, upsert, delete, otp, ips)");
    };

    let conn = bootstrap(&global.dir)?;

    match cmd {
        SuperuserCommand::Upsert { email, password } => {
            check_email(&email, "missing or invalid email address")?;
            pb_core::superusers::upsert(&conn, &email, &password)
                .context("failed to upsert superuser account")?;
            println!("Successfully saved superuser {:?}!", email.to_lowercase());
        }
        SuperuserCommand::Create { email, password } => {
            check_email(&email, "missing or invalid email address")?;
            pb_core::superusers::create(&conn, &email, &password)
                .context("failed to create new superuser account")?;
            println!(
                "Successfully created new superuser {:?}!",
                email.to_lowercase()
            );
        }
        SuperuserCommand::Update { email, password } => {
            check_email(&email, "missing or invalid email address")?;
            pb_core::superusers::update_password(&conn, &email, &password)
                .with_context(|| format!("failed to change superuser {email:?} password"))?;
            println!(
                "Successfully changed superuser {:?} password!",
                email.to_lowercase()
            );
        }
        SuperuserCommand::Delete { email } => {
            check_email(&email, "invalid or missing email address")?;
            if pb_core::superusers::delete(&conn, &email)? {
                println!("Successfully deleted superuser {:?}!", email.to_lowercase());
            } else {
                println!("superuser {email:?} is missing or already deleted");
            }
        }
        SuperuserCommand::Otp { email } => {
            check_email(&email, "invalid or missing email address")?;
            let superuser = pb_core::superusers::find(&conn, &email)?
                .with_context(|| format!("superuser with email {email:?} doesn't exist"))?;
            let collection = pb_core::collections::Collection::find(&conn, "_superusers")?
                .context("missing _superusers collection")?;
            let otp_cfg = collection
                .options
                .get("otp")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let enabled = otp_cfg
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !enabled {
                bail!("OTP auth is not enabled for the _superusers collection");
            }
            let length = otp_cfg
                .get("length")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(6) as usize;
            let duration = otp_cfg
                .get("duration")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let pass = pb_core::ids::random_string_with_alphabet(length, "1234567890");
            let hash = pb_core::record_upsert::hash_password(&pass, 10);
            conn.execute(
                "INSERT INTO _otps (collectionRef, recordRef, password, sentTo, created, updated)
                 VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%d %H:%M:%fZ','now'), strftime('%Y-%m-%d %H:%M:%fZ','now'))",
                rusqlite::params![collection.id, superuser.id(), hash, ""],
            )
            .context("failed to create OTP")?;
            let otp_id: String = conn
                .query_row(
                    "SELECT id FROM _otps WHERE rowid = last_insert_rowid()",
                    [],
                    |r| r.get(0),
                )
                .context("failed to read otp id")?;
            println!("Successfully created OTP for superuser {:?}:", email.to_lowercase());
            println!("├─ Id:    {}", otp_id);
            println!("├─ Pass:  {}", pass);
            println!("└─ Valid: {}s\n", duration);
        }
        SuperuserCommand::Ips { ips } => {
            let mut settings = pb_core::settings::load(&conn).context("load settings")?;
            settings.superuser_ips = ips.clone();
            pb_core::settings::save(&conn, &settings).context("save settings")?;
            if ips.is_empty() {
                println!("Successfully cleared SuperuserIPs setting!");
            } else {
                println!("Successfully updated SuperuserIPs setting:");
                for (i, ip) in ips.iter().enumerate() {
                    if i + 1 == ips.len() {
                        println!("└─ {}", ip);
                    } else {
                        println!("├─ {}", ip);
                    }
                }
            }
        }
    }

    Ok(())
}

const MIGRATION_TEMPLATE: &str = r#"migrate((app) => {
  // add up queries...
}, (app) => {
  // add down queries...
})
"#;

fn migrate(global: Global, args: Vec<String>) -> Result<()> {
    let _conn = bootstrap(&global.dir)?;
    let sub = args.first().map(String::as_str).unwrap_or("up");
    match sub {
        "up" | "" => {
            println!("No new migrations to apply.");
        }
        "create" => {
            let name = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| "new_migration".to_string());
            let dir = global
                .migrations_dir
                .clone()
                .unwrap_or_else(|| {
                    global
                        .dir
                        .parent()
                        .map(|p| p.join("pb_migrations"))
                        .unwrap_or_else(|| global.dir.join("pb_migrations"))
                });
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("create migrations dir {}", dir.display()))?;
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let path = dir.join(format!("{}_{}.js", ts, name));
            std::fs::write(&path, MIGRATION_TEMPLATE)
                .with_context(|| format!("write {}", path.display()))?;
            println!("Created new migration file: {}", path.display());
        }
        "collections" => {
            bail!("migrate collections: not implemented yet");
        }
        "down" => {
            bail!("migrate down: not implemented yet");
        }
        "history-sync" => {
            bail!("migrate history-sync: not implemented yet");
        }
        other => {
            bail!("unknown migrate command: {}", other);
        }
    }
    Ok(())
}

fn check_email(email: &str, message: &str) -> Result<()> {
    if !pb_core::superusers::is_valid_email(email) {
        bail!("{message}");
    }
    Ok(())
}

fn init_tracing(global: &Global) {
    let default = if global.dev { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn write_types_dts(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(pb_core::TYPES_DTS);
    if path.exists() {
        return Ok(());
    }
    std::fs::write(&path, pb_core::TYPES_DTS_CONTENT)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// `--http` wins; otherwise a single domain argument means 0.0.0.0:80,
/// otherwise the cobra default 127.0.0.1:8090.
fn resolve_addr(args: &ServeArgs) -> Result<String> {
    if let Some(http) = &args.http {
        return Ok(normalize_addr(http));
    }
    if !args.domains.is_empty() {
        return Ok("0.0.0.0:80".to_string());
    }
    Ok("127.0.0.1:8090".to_string())
}

/// Accept both `127.0.0.1:8090` and bare `127.0.0.1` (cobra's behaviour: the
/// default port is appended).
fn normalize_addr(value: &str) -> String {
    if value.contains(':') {
        value.to_string()
    } else {
        format!("{value}:8090")
    }
}

/// Embedded copy of the admin UI (`ui/_`), compiled into the binary so a
/// single executable works even when the `ui/_` directory is not present on
/// disk (e.g. a release binary moved out of its archive).
const EMBEDDED_UI: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../ui/_");

/// Prefer the mirrored UI next to the executable, then the working directory.
/// Fall back to the copy embedded in the binary.
fn resolve_ui_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("ui/_"));
            candidates.push(dir.join("../../ui/_"));
        }
    }
    candidates.push(PathBuf::from("ui/_"));
    if let Some(found) = candidates.into_iter().find(|p| p.is_dir()) {
        return Some(found);
    }

    // No on-disk UI: extract the embedded copy to a per-process temp dir.
    let dest = std::env::temp_dir().join(format!("pocketbase-ui-{}", std::process::id()));
    if !dest.exists() {
        if let Err(err) = std::fs::create_dir_all(&dest) {
            tracing::warn!(?err, "could not create temp UI dir");
            return None;
        }
        if let Err(err) = EMBEDDED_UI.extract(&dest) {
            tracing::warn!(?err, "could not extract embedded UI");
            return None;
        }
    }
    let ui = dest.join("ui/_");
    // include_dir extracts the contents of `ui/_` directly into `dest`? Check:
    // include_dir!(".../ui/_") embeds the directory itself, and extract()
    // recreates its contents under dest. The ServeDir expects `ui/_` layout,
    // so if `dest/index.html` exists, point at dest.
    if dest.join("index.html").is_file() {
        Some(dest)
    } else if ui.is_dir() {
        Some(ui)
    } else {
        None
    }
}

/// Best-effort attempt to open the installer URL in the default browser.
fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = url;
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
