use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use env_ghost::fs::Mode;
use env_ghost::policy::Policy;
use env_ghost::{audit, caller, daemon, doctor};

#[derive(Parser)]
#[command(
    name = "env-ghost",
    version,
    about = "Caller-aware secrets filesystem for Linux"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mount over a file and log every access. Everyone gets the real contents.
    Watch {
        file: PathBuf,
        /// Policy used only to log what guard would have served.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Don't echo events to stderr.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Mount over a file and serve each caller the view its policy allows.
    Guard {
        file: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show recent access events.
    Log {
        /// Keep printing new events.
        #[arg(short, long)]
        follow: bool,
        /// Number of past events to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Print raw JSON lines.
        #[arg(long)]
        json: bool,
    },
    /// Check what this host supports.
    Doctor,
    /// Show how a running process would be identified and what it would get.
    Explain {
        pid: i32,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Put the original file back after the daemon died.
    Restore {
        file: PathBuf,
        /// Overwrite even if the file no longer holds the stub.
        #[arg(long)]
        force: bool,
    },
    #[command(name = "__watchdog", hide = true)]
    Watchdog { file: PathBuf },
}

fn default_policy_path() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d).join("env-ghost/policy.toml"));
    }
    std::env::var_os("HOME")
        .filter(|d| !d.is_empty())
        .map(|h| PathBuf::from(h).join(".config/env-ghost/policy.toml"))
}

/// Explicit --policy must exist. The default location may be missing, which
/// means builtins only and everyone else redacted; we say so.
fn load_policy(explicit: Option<&Path>) -> Result<(Policy, String)> {
    if let Some(p) = explicit {
        let pol = Policy::load(p)?;
        let desc = format!("{}, {} rules", p.display(), pol.rule_count());
        return Ok((pol, desc));
    }
    match default_policy_path() {
        Some(p) if p.exists() => {
            let pol = Policy::load(&p)?;
            let desc = format!("{}, {} rules", p.display(), pol.rule_count());
            Ok((pol, desc))
        }
        Some(p) => Ok((
            Policy::default(),
            format!("none at {}, every caller gets redacted", p.display()),
        )),
        None => Ok((
            Policy::default(),
            "none (HOME unset), every caller gets redacted".into(),
        )),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("env-ghost: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    match cli.cmd {
        Cmd::Watch {
            file,
            policy,
            quiet,
        } => {
            let (policy, policy_desc) = load_policy(policy.as_deref())?;
            daemon::run(
                &file,
                daemon::Options {
                    mode: Mode::Watch,
                    policy,
                    policy_desc,
                    quiet,
                },
            )?;
        }
        Cmd::Guard {
            file,
            policy,
            quiet,
        } => {
            let (policy, policy_desc) = load_policy(policy.as_deref())?;
            daemon::run(
                &file,
                daemon::Options {
                    mode: Mode::Guard,
                    policy,
                    policy_desc,
                    quiet,
                },
            )?;
        }
        Cmd::Log {
            follow,
            lines,
            json,
        } => audit::tail(lines, follow, json)?,
        Cmd::Doctor => return Ok(doctor::run()),
        Cmd::Explain { pid, policy } => {
            let (policy, desc) = load_policy(policy.as_deref())?;
            let c = caller::resolve(pid as u32)
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("resolving pid {pid}"))?;
            let d = policy.decide(&c);
            println!("{}", serde_json::to_string_pretty(&c)?);
            println!("policy: {desc}");
            println!("view: {} (rule: {})", d.view.as_str(), d.rule);
        }
        Cmd::Restore { file, force } => daemon::restore(&file, force)?,
        Cmd::Watchdog { file } => daemon::watchdog_main(&file)?,
    }
    Ok(true)
}
