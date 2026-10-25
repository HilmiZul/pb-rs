//! Differential compatibility harness for the PocketBase -> Rust port.
//!
//! The original Go binary is the oracle. This tool records its observable
//! behaviour for a scenario, then replays the same scenario against the Rust
//! implementation and reports every difference.
//!
//! Subcommands:
//!   record  run a scenario against a live base URL, write normalized golden files
//!   diff    compare two recordings and fail on any normalized difference
//!
//! Volatile values (ids, timestamps, JWTs, secrets) are normalized on both
//! sides so only semantic differences surface.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(about = "PocketBase compatibility harness (oracle vs port)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Record a scenario against a running server.
    Record {
        #[arg(long)]
        base: String,
        #[arg(long, default_value = "harness/scenarios/basic.json")]
        scenario: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare two recordings.
    Diff {
        #[arg(long)]
        a: PathBuf,
        #[arg(long)]
        b: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    #[serde(default)]
    requests: Vec<Request>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct Request {
    name: String,
    method: String,
    path: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Recorded {
    request: Request,
    status: u16,
    content_type: String,
    body: String,
}

fn normalize(input: &str) -> String {
    // PocketBase record ids: 15 lowercase alphanumeric characters.
    let ids = Regex::new(r"\b[a-z0-9]{15}\b").unwrap();
    // RFC3339-ish timestamps, with or without fractional seconds.
    let ts = Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?").unwrap();
    // JWTs.
    let jwt = Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
    // 43-char base64url secrets (auth token keys, settings secrets).
    let secret = Regex::new(r"\b[A-Za-z0-9_-]{43}\b").unwrap();

    let out = ids.replace_all(input, "<id>");
    let out = ts.replace_all(&out, "<ts>");
    let out = jwt.replace_all(&out, "<jwt>");
    secret.replace_all(&out, "<secret>").to_string()
}

fn record(base: &str, scenario_path: &Path, out: &Path) -> Result<()> {
    let raw = fs::read_to_string(scenario_path)
        .with_context(|| format!("read scenario {}", scenario_path.display()))?;
    let scenario: Scenario = serde_json::from_str(&raw)?;

    let dir = out.join(&scenario.name);
    fs::create_dir_all(&dir)?;

    for req in &scenario.requests {
        let url = format!("{}{}", base.trim_end_matches('/'), req.path);
        let mut call = ureq::request(&req.method, &url);
        for (k, v) in &req.headers {
            call = call.set(k, v);
        }
        let result = match &req.body {
            Some(b) => call.send_string(b),
            None => call.call(),
        };

        let (status, content_type, body) = match result {
            Ok(resp) => {
                let ct = resp.header("content-type").unwrap_or("").to_string();
                (resp.status(), ct, resp.into_string().unwrap_or_default())
            }
            Err(ureq::Error::Status(code, resp)) => {
                let ct = resp.header("content-type").unwrap_or("").to_string();
                (code, ct, resp.into_string().unwrap_or_default())
            }
            Err(e) => {
                anyhow::bail!("transport error for {} {}: {e}", req.method, req.path);
            }
        };

        let recorded = Recorded {
            request: req.clone(),
            status,
            content_type: content_type.split(';').next().unwrap_or("").trim().to_string(),
            body: normalize(&body),
        };
        let file = dir.join(format!("{}.json", sanitize(&req.name)));
        fs::write(&file, serde_json::to_string_pretty(&recorded)?)?;
        println!("{:>6} {} -> {}", status, req.path, file.display());
    }
    Ok(())
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn diff(a: &Path, b: &Path) -> Result<()> {
    let mut mismatches = 0usize;
    let mut compared = 0usize;

    for entry in fs::read_dir(a)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let dir_a = entry.path();
        let dir_b = b.join(&name);
        if !dir_b.is_dir() {
            println!("MISSING in B: {}", dir_a.display());
            mismatches += 1;
            continue;
        }
        for file in fs::read_dir(&dir_a)? {
            let file = file?;
            let rel = file.file_name();
            let fa = file.path();
            let fb = dir_b.join(&rel);
            if !fb.exists() {
                println!("MISSING in B: {}", fb.display());
                mismatches += 1;
                continue;
            }
            compared += 1;
            let ra: Recorded = serde_json::from_str(&fs::read_to_string(&fa)?)?;
            let rb: Recorded = serde_json::from_str(&fs::read_to_string(&fb)?)?;

            if ra.status != rb.status {
                println!("STATUS {}: {} != {}", rel.to_string_lossy(), ra.status, rb.status);
                mismatches += 1;
            }
            if ra.content_type != rb.content_type {
                println!(
                    "CONTENT-TYPE {}: {} != {}",
                    rel.to_string_lossy(),
                    ra.content_type,
                    rb.content_type
                );
                mismatches += 1;
            }
            if ra.body != rb.body {
                println!("BODY {}", rel.to_string_lossy());
                print_body_diff(&ra.body, &rb.body);
                mismatches += 1;
            }
        }
    }

    println!("compared {compared} responses, {mismatches} mismatch(es)");
    if mismatches > 0 {
        anyhow::bail!("compatibility mismatch");
    }
    Ok(())
}

fn print_body_diff(a: &str, b: &str) {
    let pa: Option<serde_json::Value> = serde_json::from_str(a).ok();
    let pb: Option<serde_json::Value> = serde_json::from_str(b).ok();
    match (pa, pb) {
        (Some(va), Some(vb)) => {
            let sa = serde_json::to_string_pretty(&va).unwrap_or_default();
            let sb = serde_json::to_string_pretty(&vb).unwrap_or_default();
            for (i, (la, lb)) in sa.lines().zip(sb.lines()).enumerate() {
                if la != lb {
                    println!("  line {}: -{la}", i + 1);
                    println!("  line {}: +{lb}", i + 1);
                }
            }
        }
        _ => {
            println!("  A: {a}");
            println!("  B: {b}");
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Record { base, scenario, out } => record(&base, &scenario, &out),
        Cmd::Diff { a, b } => diff(&a, &b),
    }
}
