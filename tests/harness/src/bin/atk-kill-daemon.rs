//! SIGKILL the daemon while reading in a loop. Same UID can always do this.
//! Held means: no secret comes out, and the path ends up as the stub rather
//! than stuck on ENOTCONN.
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
    let (mut gap_errors, mut stub, mut leaked, mut other) = (0u64, 0u64, 0u64, 0u64);
    let mut last_gap = None;
    while start.elapsed() < Duration::from_secs(3) {
        if killed_at.is_none() && start.elapsed() > Duration::from_millis(300) {
            unsafe { libc::kill(daemon, libc::SIGKILL) };
            killed_at = Some(Instant::now());
        }
        match fs::read(file) {
            Ok(b) if has(&b, secret) => leaked += 1,
            Ok(b) if b.starts_with(b"# env-ghost is not running") => stub += 1,
            Ok(_) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTCONN) | Some(libc::ECONNABORTED)) => {
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
    let ends_on_stub = fs::read(file)
        .map(|b| b.starts_with(b"# env-ghost is not running"))
        .unwrap_or(false);
    let v = if leaked == 0 && ends_on_stub && !still_mounted {
        Verdict::Held
    } else {
        Verdict::Bypassed
    };
    report(
        "sigkill-daemon",
        v,
        "SIGKILL the daemon during a read loop",
        &format!(
            "{gap_errors} reads failed with ENOTCONN/ECONNABORTED, last one {gap} after the kill; \
             then {stub} stub reads, {leaked} with the secret, {other} other errors; \
             ends on stub: {ends_on_stub}"
        ),
    );
}
