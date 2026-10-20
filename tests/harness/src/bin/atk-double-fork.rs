//! Pretend to be an npm postinstall script, double-fork so the payload is
//! reparented away from npm, then read.
//!
//! usage: atk-double-fork <file> <secret> env-intact|env-scrubbed

use std::fs;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

use env_ghost_harness::{Verdict, args, describe, has, report};

fn main() {
    let a = args();
    let stage = std::env::var("EG_STAGE").unwrap_or_default();
    let (file, secret, variant) = (&a[a.len() - 3], &a[a.len() - 2], &a[a.len() - 1]);
    let me = std::env::current_exe().unwrap();
    let id = format!("double-fork-{variant}");
    let attack = match variant.as_str() {
        "env-intact" => "npm postinstall double-forks, then reads",
        _ => "npm postinstall double-forks, clears its environment, then reads",
    };

    match stage.as_str() {
        "" => {
            // The npm process. argv says npm install; that's all npm itself
            // looks like from the outside.
            let st = Command::new(&me)
                .arg0("npm")
                .args(["install", file, secret, variant])
                .env("EG_STAGE", "npm")
                .status()
                .unwrap();
            assert!(st.success());
        }
        "npm" => {
            // npm runs lifecycle scripts with npm_lifecycle_event set.
            let st = Command::new(&me)
                .arg0("node")
                .args(["postinstall.js", file, secret, variant])
                .env("EG_STAGE", "script")
                .env("npm_lifecycle_event", "postinstall")
                .status()
                .unwrap();
            assert!(st.success());
        }
        "script" => {
            let before = fs::read(file).unwrap_or_default();
            let parent = unsafe { libc::getpid() };
            match unsafe { libc::fork() } {
                0 => {
                    if unsafe { libc::fork() } != 0 {
                        unsafe { libc::_exit(0) };
                    }
                    // Grandchild: wait until the middle process is gone and
                    // we've been reparented.
                    let mid = unsafe { libc::getppid() };
                    for _ in 0..200 {
                        if unsafe { libc::getppid() } != mid {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let new_parent = unsafe { libc::getppid() };
                    let parent_comm = fs::read_to_string(format!("/proc/{new_parent}/comm"))
                        .unwrap_or_default();
                    let note_base = format!(
                        "before fork: {}; reparented to pid {new_parent} ({})",
                        describe(&before, secret),
                        parent_comm.trim()
                    );
                    if variant == "env-scrubbed" {
                        let err = Command::new(&me)
                            .arg0("payload")
                            .args([file.as_str(), secret, variant])
                            .env_clear()
                            .env("EG_STAGE", "payload")
                            .env("EG_NOTE", &note_base)
                            .env(
                                "EG_POLICY_NOTE",
                                std::env::var("EG_POLICY_NOTE").unwrap_or_default(),
                            )
                            .exec();
                        panic!("exec: {err}");
                    }
                    finish(&id, attack, file, secret, &note_base);
                    unsafe { libc::_exit(0) };
                }
                _ => {
                    let _ = parent;
                    let mut st = 0;
                    unsafe { libc::wait(&mut st) };
                }
            }
        }
        "payload" => {
            let note = std::env::var("EG_NOTE").unwrap_or_default();
            finish(&id, attack, file, secret, &note);
        }
        _ => unreachable!(),
    }
}

fn finish(id: &str, attack: &str, file: &str, secret: &str, note: &str) {
    let after = fs::read(file).unwrap_or_default();
    let v = if has(&after, secret) {
        Verdict::Bypassed
    } else {
        Verdict::Held
    };
    let policy = std::env::var("EG_POLICY_NOTE").unwrap_or_default();
    report(
        id,
        v,
        attack,
        &format!("{policy}{note}; after: {}", describe(&after, secret)),
    );
}
