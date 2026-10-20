//! Probe what mmap does on a direct I/O FUSE file, and whether a private
//! mapping can pick up pages a trusted process faulted in.
//!
//! usage: atk-mmap <file> <secret> <eg-trusted>

use std::fs;
use std::path::Path;
use std::process::Command;

use env_ghost_harness::{Mapping, Verdict, args, describe, has, report};

fn main() {
    let a = args();
    let (file, secret, trusted) = (&a[1], &a[2], &a[3]);
    let path = Path::new(file);
    let len = fs::metadata(path).unwrap().len() as usize;

    let shared = match Mapping::shared(path, len) {
        Ok(m) => format!(
            "MAP_SHARED mapped and read as {}",
            describe(&m.bytes(), secret)
        ),
        Err(e) => format!("MAP_SHARED fails: {e}"),
    };

    let mine = match Mapping::private(path, len) {
        Ok(m) => m,
        Err(e) => {
            report(
                "mmap-private",
                Verdict::NotApplicable,
                "keep a MAP_PRIVATE mapping while a trusted process maps the file",
                &format!("{shared}; MAP_PRIVATE fails: {e}"),
            );
            return;
        }
    };
    let first = describe(&mine.bytes(), secret);

    let t = Command::new(trusted)
        .args(["mmap-read", file])
        .output()
        .unwrap();
    let trusted_saw = describe(&t.stdout, secret);

    // Touch our existing mapping again. If the trusted process's mmap
    // invalidated our pages and refilled the cache with its own view, the
    // refault hands that view to us.
    let again = mine.bytes();
    let fresh = Mapping::private(path, len)
        .map(|m| describe(&m.bytes(), secret))
        .unwrap_or("error");

    report(
        "mmap-private",
        if has(&again, secret) {
            Verdict::Bypassed
        } else {
            Verdict::Held
        },
        "keep a MAP_PRIVATE mapping while a trusted process maps the file",
        &format!(
            "{shared}; own mapping first read {first}; trusted mapping read {trusted_saw}; \
             own mapping re-read {}; a fresh mapping reads {fresh}",
            describe(&again, secret)
        ),
    );
}
