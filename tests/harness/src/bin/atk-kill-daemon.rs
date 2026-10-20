//! SIGKILL the daemon while reading in a loop. Same UID can always do this.
//! The watchdog detaches the dead mount and the plain file underneath comes
//! back, so in unprivileged mode this is expected to be a bypass. The note
//! records whether the path got stuck on ENOTCONN, which it must not.
//!
//! usage: atk-kill-daemon <file> <secret> <daemon-pid>

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use env_ghost_harness::{Verdict, args, has, mounted, report};

fn main() {
    let a = args();
    let (file, secret) = (&a[1], &a[2]);
    let daemon: i32 = a[3].parse().unwrap();
    let start = Instant::now();
    let mut killed_at = None;
    let (mut gap_errors, mut leaked, mut other) = (0u64, 0u64, 0u64);
    let mut last_gap = None;
    while start.elapsed() < Duration::from_secs(3) {
        if killed_at.is_none() && start.elapsed() > Duration::from_millis(300) {
            unsafe { libc::kill(daemon, libc::SIGKILL) };
            killed_at = Some(Instant::now());
        }
        match fs::read(file) {
            Ok(b) if has(&b, secret) => leaked += 1,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOTCONN) | Some(libc::ECONNABORTED)
                ) =>
            {
                gap_errors += 1;
                last_gap = Some(Instant::now());
            }
            Err(_) => other += 1,
        }
    }
    let gap = match (killed_at, last_gap) {
        (Some(k), Some(l)) => format!("{:.1} ms", (l - k).as_secs_f64() * 1000.0),
        _ => "none observed".into(),
    };
    let still_mounted = mounted(Path::new(file));
    let v = if leaked > 0 {
        Verdict::Bypassed
    } else {
        Verdict::Held
    };
    report(
        "sigkill-daemon",
        v,
        "SIGKILL the daemon during a read loop, keep reading",
        &format!(
            "{gap_errors} reads failed with ENOTCONN/ECONNABORTED, last one {gap} after the kill; \
             then {leaked} reads returned the plain file underneath; {other} other errors; \
             still mounted: {still_mounted}"
        ),
    );
}
