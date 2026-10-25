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
//! sides so only semantic differences surface. JSON bodies are compared
//! semantically: key order is not part of the contract (see
//! `docs/COMPATIBILITY.md`), values and array order are.

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
    /// Extract values from the JSON response for use in later requests.
    /// Key = variable name, value = dot-separated path (e.g. `token`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    save: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Recorded {
    request: Request,
    status: u16,
    content_type: String,
    body: String,
}

/// Replace volatile values with placeholders.
///
/// Order matters: longer, more specific patterns first, so that e.g. a JWT is
/// not partially rewritten by the id rule.
fn normalize(input: &str) -> String {
    // JWTs (`header.payload.signature`).
    let jwt = Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
    // Per-install secrets and token keys: 50 alphanumerics.
    let secret = Regex::new(r"\b[A-Za-z0-9]{50}\b").unwrap();
    // `collectionScaffolds` regenerates a 10-char id per request and embeds it
    // in the default index names. Only scaffold indexes have an empty table
    // name, so anchoring on `ON `` ` keeps real collection indexes untouched.
    let scaffold_index = Regex::new(r"idx_[A-Za-z0-9]+_[a-z0-9]{10}` ON ``").unwrap();
    // PocketBase record ids: 15 lowercase alphanumerics.
    let ids = Regex::new(r"\b[a-z0-9]{15}\b").unwrap();
    // RFC3339-ish timestamps, with or without fractional seconds.
    let ts = Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?").unwrap();

    let out = jwt.replace_all(input, "<jwt>");
    let out = secret.replace_all(&out, "<secret>");
    let out = scaffold_index.replace_all(&out, "idx_<random>` ON ``");
    let out = ids.replace_all(&out, "<id>");
    ts.replace_all(&out, "<ts>").to_string()
}

fn substitute(value: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = value.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

/// Resolve a dot-separated path inside a JSON value (`token`, `record.id`).
fn lookup<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn record(base: &str, scenario_path: &Path, out: &Path) -> Result<()> {
    let raw = fs::read_to_string(scenario_path)
        .with_context(|| format!("read scenario {}", scenario_path.display()))?;
    let scenario: Scenario = serde_json::from_str(&raw)?;

    let dir = out.join(&scenario.name);
    fs::create_dir_all(&dir)?;

    let mut vars: BTreeMap<String, String> = BTreeMap::new();

    for req in &scenario.requests {
        let path = substitute(&req.path, &vars);
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let mut call = ureq::request(&req.method, &url);
        for (k, v) in &req.headers {
            call = call.set(k, &substitute(v, &vars));
        }
        let body = req.body.as_ref().map(|b| substitute(b, &vars));
        // PocketBase only accepts JSON bodies; ureq would otherwise send
        // `text/plain` and the oracle answers "Unsupported Content-Type."
        if body.is_some()
            && !req
                .headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case("content-type"))
        {
            call = call.set("content-type", "application/json");
        }
        let result = match &body {
            Some(b) => call.send_string(b),
            None => call.call(),
        };

        let (status, content_type, raw_body) = match result {
            Ok(resp) => {
                let ct = resp.header("content-type").unwrap_or("").to_string();
                (resp.status(), ct, resp.into_string().unwrap_or_default())
            }
            Err(ureq::Error::Status(code, resp)) => {
                let ct = resp.header("content-type").unwrap_or("").to_string();
                (code, ct, resp.into_string().unwrap_or_default())
            }
            Err(e) => {
                anyhow::bail!("transport error for {} {}: {e}", req.method, path);
            }
        };

        if !req.save.is_empty() {
            let parsed: serde_json::Value = serde_json::from_str(&raw_body)
                .with_context(|| format!("save: response of {} is not JSON", req.name))?;
            for (var, pointer) in &req.save {
                let found = lookup(&parsed, pointer)
                    .with_context(|| format!("save: no `{pointer}` in response of {}", req.name))?;
                let text = match found {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                vars.insert(var.clone(), text);
            }
        }

        let recorded = Recorded {
            request: Request {
                path,
                body,
                ..req.clone()
            },
            status,
            content_type: content_type.split(';').next().unwrap_or("").trim().to_string(),
            body: normalize(&raw_body),
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

    let mut dirs: Vec<_> = fs::read_dir(a)?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect();
    dirs.sort_by_key(|e| e.file_name());

    for entry in dirs {
        let name = entry.file_name();
        let dir_a = entry.path();
        let dir_b = b.join(&name);
        if !dir_b.is_dir() {
            println!("MISSING in B: {}", dir_a.display());
            mismatches += 1;
            continue;
        }
        let mut files: Vec<_> = fs::read_dir(&dir_a)?.filter_map(Result::ok).collect();
        files.sort_by_key(|e| e.file_name());
        for file in files {
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
            if !body_eq(&ra.body, &rb.body) {
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

/// JSON bodies are compared semantically; anything else byte for byte.
fn body_eq(a: &str, b: &str) -> bool {
    match (
        serde_json::from_str::<serde_json::Value>(a),
        serde_json::from_str::<serde_json::Value>(b),
    ) {
        (Ok(va), Ok(vb)) => va == vb,
        _ => a == b,
    }
}

fn print_body_diff(a: &str, b: &str) {
    let pa: Option<serde_json::Value> = serde_json::from_str(a).ok();
    let pb: Option<serde_json::Value> = serde_json::from_str(b).ok();
    match (pa, pb) {
        (Some(va), Some(vb)) => {
            let sa = serde_json::to_string_pretty(&va).unwrap_or_default();
            let sb = serde_json::to_string_pretty(&vb).unwrap_or_default();
            let la: Vec<_> = sa.lines().collect();
            let lb: Vec<_> = sb.lines().collect();
            for i in 0..la.len().max(lb.len()) {
                let x = la.get(i).copied().unwrap_or("<absent>");
                let y = lb.get(i).copied().unwrap_or("<absent>");
                if x != y {
                    println!("  line {:>3}: -{x}", i + 1);
                    println!("  line {:>3}: +{y}", i + 1);
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
