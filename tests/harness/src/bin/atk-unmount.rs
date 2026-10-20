//! Remove the mount with fusermount3 as the same user and read what's under
//! it. The plaintext was never moved, so in unprivileged mode this is
//! expected to be a bypass.
//!
//! usage: atk-unmount <file> <secret>

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use env_ghost_harness::{Verdict, args, describe, has, mounted, report};

fn main() {
    let a = args();
    let (file, secret) = (&a[1], &a[2]);
    let out = Command::new("fusermount3").args(["-u", file]).output();
    let how = match out {
        Ok(o) if o.status.success() => "fusermount3 -u succeeded".to_string(),
        Ok(o) => format!(
            "fusermount3 -u failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("fusermount3 not runnable: {e}"),
    };
    if mounted(Path::new(file)) {
        report(
            "fusermount-u",
            Verdict::Held,
            "fusermount3 -u as the same user, then read",
            &format!("{how}; still mounted"),
        );
        return;
    }
    // Give the daemon a moment to notice and exit.
    std::thread::sleep(Duration::from_millis(500));
    let under = fs::read(file).unwrap_or_default();
    report(
        "fusermount-u",
        if has(&under, secret) {
            Verdict::Bypassed
        } else {
            Verdict::Held
        },
        "fusermount3 -u as the same user, then read",
        &format!(
            "{how}; file now reads as {}. the plaintext sits under the mount in this mode",
            describe(&under, secret)
        ),
    );
}
