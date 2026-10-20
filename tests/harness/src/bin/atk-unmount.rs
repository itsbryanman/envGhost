//! Remove the mount with fusermount3 as the same user, read what's under it,
//! then ask the watchdog to put the original back and read again.
//!
//! usage: atk-unmount <file> <secret> <env-ghost>

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use env_ghost_harness::{Verdict, args, describe, has, mounted, report};

fn main() {
    let a = args();
    let (file, secret, env_ghost) = (&a[1], &a[2], &a[3]);
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
        report(
            "fusermount-u-restore",
            Verdict::NotApplicable,
            "fusermount3 -u, then env-ghost restore, then read",
            "mount could not be removed",
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
            "{how}; file now reads as {}. protection is gone until restarted",
            describe(&under, secret)
        ),
    );

    let r = Command::new(env_ghost)
        .args(["restore", file])
        .output()
        .unwrap();
    let after = fs::read(file).unwrap_or_default();
    report(
        "fusermount-u-restore",
        if has(&after, secret) {
            Verdict::Bypassed
        } else {
            Verdict::Held
        },
        "fusermount3 -u, then env-ghost restore, then read",
        &format!(
            "restore {}; file reads as {}. restore has no way to tell the user from an attacker",
            if r.status.success() {
                "succeeded"
            } else {
                "failed"
            },
            describe(&after, secret)
        ),
    );
}
