use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::caller::{Caller, Identity};
use crate::policy::{Decision, View};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Event {
    pub ts: String,
    pub event: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub served: Option<View>,
    /// What the policy said. In watch mode this is what guard would serve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<Caller>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opener: Option<Identity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Event {
    pub fn new(event: &str, file: &str) -> Event {
        Event {
            ts: humantime::format_rfc3339_millis(SystemTime::now()).to_string(),
            event: event.to_string(),
            file: file.to_string(),
            ..Default::default()
        }
    }

    pub fn note(mut self, note: impl Into<String>) -> Event {
        self.note = Some(note.into());
        self
    }
}

pub fn state_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d).join("env-ghost"));
    }
    match std::env::var_os("HOME").filter(|d| !d.is_empty()) {
        Some(h) => Ok(PathBuf::from(h).join(".local/state/env-ghost")),
        None => bail!("neither XDG_STATE_HOME nor HOME is set; can't place the event log"),
    }
}

pub fn runtime_dir() -> Result<PathBuf> {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(d) => Ok(PathBuf::from(d).join("env-ghost")),
        None => Ok(state_dir()?.join("run")),
    }
}

pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

pub fn log_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("events.jsonl"))
}

pub struct Audit {
    file: Mutex<File>,
    echo: bool,
}

impl Audit {
    pub fn open(echo: bool) -> Result<Audit> {
        let path = log_path()?;
        ensure_private_dir(path.parent().unwrap())?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        Ok(Audit {
            file: Mutex::new(file),
            echo,
        })
    }

    pub fn record(&self, ev: &Event) {
        let mut line = match serde_json::to_string(ev) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("env-ghost: can't encode event: {e}");
                return;
            }
        };
        if self.echo {
            eprintln!("{}", render(ev));
        }
        line.push('\n');
        // One write per line so O_APPEND keeps lines whole across processes.
        let mut f = self.file.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = f.write_all(line.as_bytes()) {
            eprintln!("env-ghost: event log write failed: {e}");
        }
    }
}

/// One line for humans. cmdline and comm are shown in quotes because the
/// process chose them.
pub fn render(ev: &Event) -> String {
    let time = ev
        .ts
        .get(11..23)
        .map(str::to_string)
        .unwrap_or_else(|| ev.ts.clone());
    let mut s = format!("{time} ");
    match ev.event.as_str() {
        "access" => {
            let op = ev.op.as_deref().unwrap_or("?");
            let served = ev.served.map_or("-", View::as_str);
            s.push_str(&format!("{op:<7} {served:<8}"));
        }
        other => s.push_str(&format!("{other:<16}")),
    }
    if let Some(c) = &ev.caller {
        let exe = sanitize(c.proc.exe.as_deref().unwrap_or("?"));
        s.push_str(&format!(
            " {} {exe} \"{}\"",
            c.identity.tgid,
            truncate(&sanitize(&c.proc.cmdline_untrusted.join(" ")), 60)
        ));
        let chain: Vec<String> = c
            .ancestry
            .iter()
            .map(|a| format!("{}:{}", short_name(a), a.pid))
            .collect();
        if !chain.is_empty() {
            s.push_str(&format!(" < {}", chain.join(" < ")));
        }
        match &c.session_root {
            Some(r) if r.verified => s.push_str(&format!(" [{}]", r.kind.as_str())),
            Some(r) => s.push_str(&format!(" [{}, unverified]", r.kind.as_str())),
            None if c.reached_init => s.push_str(" [no session root]"),
            None => {}
        }
    }
    if let Some(d) = &ev.decision {
        if ev.mode.as_deref() == Some("watch") {
            s.push_str(&format!(" would={} rule={}", d.view.as_str(), d.rule));
        } else {
            s.push_str(&format!(" rule={}", d.rule));
        }
    }
    if let Some(o) = &ev.opener {
        s.push_str(&format!(" opener={}", o.tgid));
    }
    if let Some(n) = &ev.note {
        s.push_str(&format!(" ({})", sanitize(n)));
    }
    s.push_str(&format!(" {}", sanitize(&ev.file)));
    s
}

/// Callers choose their argv, comm and even exe path, and the log may be read
/// in a terminal. Escape anything that could move the cursor or set colors.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn short_name(p: &crate::caller::ProcInfo) -> String {
    p.exe
        .as_deref()
        .and_then(|e| e.rsplit('/').next())
        .map(sanitize)
        .unwrap_or_else(|| format!("\"{}\"", sanitize(&p.comm_untrusted)))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push_str("...");
        t
    }
}

pub fn tail(lines: usize, follow: bool, json: bool) -> Result<()> {
    let path = log_path()?;
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !follow {
                println!("no events yet ({})", path.display());
                return Ok(());
            }
            loop {
                std::thread::sleep(Duration::from_millis(300));
                if let Ok(f) = File::open(&path) {
                    break f;
                }
            }
        }
        Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
    };
    let mut reader = BufReader::new(file);
    let mut all = Vec::new();
    let mut buf = String::new();
    while reader.read_line(&mut buf)? > 0 {
        all.push(std::mem::take(&mut buf));
    }
    let start = all.len().saturating_sub(lines);
    for l in &all[start..] {
        print_line(l, json);
    }
    if !follow {
        return Ok(());
    }
    let mut pos = reader.stream_position()?;
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len < pos {
            // Truncated or replaced; start over from the top.
            pos = 0;
        }
        reader.seek(SeekFrom::Start(pos))?;
        // Only consume complete lines so a write in progress isn't split.
        loop {
            buf.clear();
            let n = reader.read_line(&mut buf)?;
            if n == 0 || !buf.ends_with('\n') {
                break;
            }
            pos += n as u64;
            print_line(&buf, json);
        }
    }
}

fn print_line(line: &str, json: bool) {
    let line = line.trim_end();
    if line.is_empty() {
        return;
    }
    if json {
        println!("{line}");
        return;
    }
    match serde_json::from_str::<Event>(line) {
        Ok(ev) => println!("{}", render(&ev)),
        Err(_) => println!("unparsable: {}", sanitize(line)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_characters() {
        assert_eq!(sanitize("a\x1b[2Jb\nc\u{9b}"), "a\\x1b[2Jb\\x0ac\\x9b");
    }
}
