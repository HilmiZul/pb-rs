//! PocketBase-compatible CLI.
//!
//! Flag names, defaults and subcommand names mirror the cobra definitions of the
//! reference binary (v0.40.6). `serve` and `--version` are functional in M1;
//! `superuser`, `migrate` and `update` are declared so scripts fail loudly
//! instead of hitting an unknown-command path.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "pocketbase",
    version = "version 0.40.6",
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
    Migrate,

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
    /// Lists the IPs the specified superuser has logged in from
    Ips { email: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Some(Command::Serve(args)) => serve(cli.global, args),
        Some(Command::Superuser { cmd }) => superuser(cli.global, cmd),
        Some(Command::Migrate) => bail!("migrate: not implemented yet (M1.1)"),
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

    let addr = resolve_addr(&args)?;
    let ui_dir = resolve_ui_dir();

    tracing::info!(%addr, ui = ?ui_dir, "starting server");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .with_context(|| format!("bind {addr}"))?;
        println!("Server started at http://{addr}");
        pb_api::axum::serve(listener, pb_api::router(data_db, ui_dir))
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
        SuperuserCommand::Otp { .. } => bail!("superuser otp: not implemented yet (M4)"),
        SuperuserCommand::Ips { .. } => bail!("superuser ips: not implemented yet (M4)"),
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

/// Prefer the mirrored UI next to the executable, then the working directory.
fn resolve_ui_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("ui/_"));
            candidates.push(dir.join("../../ui/_"));
        }
    }
    candidates.push(PathBuf::from("ui/_"));
    candidates.into_iter().find(|p| p.is_dir())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
