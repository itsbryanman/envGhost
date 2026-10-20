//! Look like a trusted program by name: argv and comm say node / npm or the
//! trusted helper, the executable is this binary. Then read.
//! A second attack skips the disguise and just runs the trusted executable.
//!
//! usage: atk-spoof <file> <secret> <eg-trusted>

use std::fs;
use std::os::unix::process::CommandExt;
use std::process::Command;

use env_ghost_harness::{Verdict, args, describe, has, report};

fn main() {
    let a = args();
    if std::env::var("EG_STAGE").as_deref() == Ok("spoofed") {
        let (file, secret) = (&a[a.len() - 2], &a[a.len() - 1]);
        let name = std::env::var("EG_COMM").unwrap();
        let mut comm = [0u8; 16];
        comm[..name.len().min(15)].copy_from_slice(&name.as_bytes()[..name.len().min(15)]);
        unsafe { libc::prctl(libc::PR_SET_NAME, comm.as_ptr()) };
        let got = fs::read(file).unwrap_or_default();
        println!("{}", if has(&got, secret) { "real" } else { describe(&got, secret) });
        return;
    }

    let (file, secret, trusted) = (&a[1], &a[2], &a[3]);
    let me = std::env::current_exe().unwrap();
    let disguises: [(&str, &[&str], &str); 3] = [
        ("node", &["/usr/lib/node_modules/npm/bin/npm-cli.js", "run", "dev"], "node"),
        ("npm", &["start"], "npm"),
        (trusted.as_str(), &["read"], "eg-trusted"),
    ];
    let mut results = Vec::new();
    let mut leaked = false;
    for (argv0, rest, comm) in disguises {
        let out = Command::new(&me)
            .arg0(argv0)
            .args(rest)
            .args([file, secret])
            .env("EG_STAGE", "spoofed")
            .env("EG_COMM", comm)
            .output()
            .unwrap();
        let what = String::from_utf8_lossy(&out.stdout).trim().to_string();
        leaked |= what == "real";
        results.push(format!("as {comm}: {what}"));
    }
    report(
        "spoof-argv-comm",
        if leaked { Verdict::Bypassed } else { Verdict::Held },
        "forge argv[0] and comm as node, npm, and the trusted helper",
        &results.join(", "),
    );

    let out = Command::new(trusted).args(["read", file]).output().unwrap();
    report(
        "trusted-exe-gadget",
        if has(&out.stdout, secret) {
            Verdict::Bypassed
        } else {
            Verdict::Held
        },
        "run the trusted executable itself and have it print the file",
        &format!(
            "got {}; exe-based trust can't see what the trusted program is asked to do",
            describe(&out.stdout, secret)
        ),
    );
}
