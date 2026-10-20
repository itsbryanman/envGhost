//! Skip the file and go after processes that already hold the plaintext:
//! the env-ghost daemon, a trusted process that read the file, and a child
//! that got the secret through its environment.
//!
//! usage: atk-proc-peek <secret> <daemon-pid> <trusted-pid> <trusted-child-pid>

use std::fs;
use std::io::{Read, Seek, SeekFrom};

use env_ghost_harness::{Verdict, args, has, ptrace_scope, report};

fn scan_mem(pid: &str, secret: &str) -> Result<bool, String> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| format!("maps: {e}"))?;
    let mut mem = fs::File::open(format!("/proc/{pid}/mem")).map_err(|e| format!("mem: {e}"))?;
    let mut readable_any = false;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !perms.starts_with('r') {
            continue;
        }
        let (lo, hi) = range.split_once('-').unwrap();
        let lo = u64::from_str_radix(lo, 16).unwrap();
        let hi = u64::from_str_radix(hi, 16).unwrap();
        if hi - lo > 256 << 20 {
            continue;
        }
        let mut buf = vec![0u8; (hi - lo) as usize];
        if mem.seek(SeekFrom::Start(lo)).is_err() {
            continue;
        }
        if mem.read_exact(&mut buf).is_ok() {
            readable_any = true;
            if has(&buf, secret) {
                return Ok(true);
            }
        }
    }
    if readable_any {
        Ok(false)
    } else {
        Err("no region readable".into())
    }
}

fn main() {
    let a = args();
    let (secret, daemon, trusted, child) = (&a[1], &a[2], &a[3], &a[4]);
    let scope = ptrace_scope();

    match scan_mem(daemon, secret) {
        Ok(true) => report(
            "proc-mem-daemon",
            Verdict::Bypassed,
            "read /proc/<pid>/mem of the env-ghost daemon",
            &format!("secret found in daemon memory (ptrace_scope={scope})"),
        ),
        Ok(false) => report(
            "proc-mem-daemon",
            Verdict::Held,
            "read /proc/<pid>/mem of the env-ghost daemon",
            "memory readable but secret not found",
        ),
        Err(e) => report(
            "proc-mem-daemon",
            Verdict::Held,
            "read /proc/<pid>/mem of the env-ghost daemon",
            &format!("{e}; daemon is non-dumpable (ptrace_scope={scope})"),
        ),
    }

    match scan_mem(trusted, secret) {
        Ok(true) => report(
            "proc-mem-trusted",
            Verdict::Bypassed,
            "read /proc/<pid>/mem of a trusted process that read the file",
            &format!("secret found (ptrace_scope={scope}); out of scope for a file-level control"),
        ),
        Ok(false) => report(
            "proc-mem-trusted",
            Verdict::Held,
            "read /proc/<pid>/mem of a trusted process that read the file",
            &format!("memory readable, secret not found (ptrace_scope={scope})"),
        ),
        Err(e) => report(
            "proc-mem-trusted",
            Verdict::Held,
            "read /proc/<pid>/mem of a trusted process that read the file",
            &format!("{e} (ptrace_scope={scope})"),
        ),
    }

    match fs::read(format!("/proc/{child}/environ")) {
        Ok(env) => report(
            "proc-environ-child",
            if has(&env, secret) {
                Verdict::Bypassed
            } else {
                Verdict::Held
            },
            "read /proc/<pid>/environ of a child the trusted process launched with the secret",
            "environ needs only PTRACE_MODE_READ, which yama does not restrict",
        ),
        Err(e) => report(
            "proc-environ-child",
            Verdict::Held,
            "read /proc/<pid>/environ of a child the trusted process launched with the secret",
            &format!("{e}"),
        ),
    }
}
