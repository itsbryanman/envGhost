//! Get a trusted process to open the file and hand over the fd with
//! SCM_RIGHTS, then read through it.
//!
//! usage: atk-fd-pass <file> <secret> <eg-trusted> <events.jsonl> <workdir>

use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixListener;
use std::process::Command;

use env_ghost_harness::{Verdict, args, describe, has, recv_fd, report};

fn main() {
    let a = args();
    let (file, secret, trusted, log, work) = (&a[1], &a[2], &a[3], &a[4], &a[5]);
    let sock = format!("{work}/fd.sock");
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap();
    let mut helper = Command::new(trusted)
        .args(["send-fd", file, &sock])
        .spawn()
        .unwrap();
    let (mut conn, _) = listener.accept().unwrap();
    let fd = recv_fd(conn.as_raw_fd()).unwrap();
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    let mut got = Vec::new();
    let read = f.read_to_end(&mut got);
    let _ = conn.write_all(b"k");
    let _ = helper.wait();

    let logged = fs::read_to_string(log)
        .map(|l| l.contains("\"fd_passing\""))
        .unwrap_or(false);
    let note = format!(
        "read through passed fd got {}; fd_passing event {}",
        match &read {
            Ok(_) => describe(&got, secret),
            Err(e) => {
                let _ = e;
                "an error"
            }
        },
        if logged { "logged" } else { "not logged" }
    );
    let v = if has(&got, secret) {
        Verdict::Bypassed
    } else {
        Verdict::Held
    };
    report(
        "fd-passing",
        v,
        "trusted process opens the file and passes the fd over SCM_RIGHTS",
        &note,
    );
}
