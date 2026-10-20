//! These tests mount real FUSE files. They need /dev/fuse and either root or
//! a setuid fusermount3. Set ENV_GHOST_SKIP_FUSE_TESTS=1 to skip them on
//! machines without FUSE; they fail otherwise, so a missing FUSE is never
//! mistaken for a pass.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const SECRET: &str = "sk_test_fake0000notarealkey";

fn fuse_ok() -> bool {
    if std::env::var_os("ENV_GHOST_SKIP_FUSE_TESTS").is_some_and(|v| v == "1") {
        eprintln!("skipping: ENV_GHOST_SKIP_FUSE_TESTS=1");
        return false;
    }
    assert!(
        Path::new("/dev/fuse").exists(),
        "/dev/fuse missing; set ENV_GHOST_SKIP_FUSE_TESTS=1 to skip"
    );
    true
}

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(format!(
            "/tmp/egt-{}-{}-{name}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        Scratch { dir }
    }

    fn env_file(&self, contents: &[u8]) -> PathBuf {
        let p = self.dir.join(".env");
        fs::write(&p, contents).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn mounted(path: &Path) -> bool {
    let info = fs::read_to_string("/proc/self/mountinfo").unwrap();
    let p = path.to_string_lossy();
    info.lines()
        .any(|l| l.split(' ').nth(4) == Some(&*p) && l.contains(" env-ghost "))
}

struct Daemon {
    child: Child,
    path: PathBuf,
}

impl Daemon {
    fn start(s: &Scratch, mode: &str, file: &Path, policy: Option<&str>) -> Daemon {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_env-ghost"));
        cmd.arg(mode).arg("-q").arg(file);
        if let Some(p) = policy {
            let pp = s.dir.join("policy.toml");
            fs::write(&pp, p).unwrap();
            cmd.arg("--policy").arg(pp);
        }
        let child = cmd
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("XDG_STATE_HOME", s.dir.join("state"))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let d = Daemon {
            child,
            path: file.to_path_buf(),
        };
        let t = Instant::now();
        while !mounted(file) {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "mount never appeared"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        d
    }

    fn stop(mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let status = self.child.wait().unwrap();
        assert!(status.success(), "daemon exited with {status}");
        assert!(!mounted(&self.path));
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
            let _ = self.child.wait();
        }
    }
}

/// Run a reader with a clean environment. Inherited agent markers such as
/// CLAUDECODE would trip the builtin rules and redact everything.
fn read_with(exe: &str, args: &[&str], file: &Path) -> String {
    let out = Command::new(exe)
        .args(args)
        .arg(file)
        .env_clear()
        .output()
        .unwrap();
    assert!(out.status.success(), "{exe} failed: {:?}", out);
    String::from_utf8(out.stdout).unwrap()
}

fn canon(p: &str) -> String {
    fs::canonicalize(p).unwrap().to_string_lossy().into_owned()
}

fn sample() -> Vec<u8> {
    format!("# keys\nSTRIPE_KEY={SECRET}\nPORT=5432\n").into_bytes()
}

/// Not a real test. When EG_HELPER_FILE is set this binary acts as a reader
/// for the caching test: open, report, wait for a go line, read, print.
#[test]
fn helper_reader() {
    let Some(file) = std::env::var_os("EG_HELPER_FILE") else {
        return;
    };
    use std::io::{BufRead, Write};
    let mut f = fs::File::open(file).unwrap();
    println!("EG_OPENED");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    println!(
        "EG_DATA:{}",
        String::from_utf8_lossy(&buf).replace('\n', "|")
    );
}

struct Reader {
    child: Child,
    out: std::io::BufReader<std::process::ChildStdout>,
}

impl Reader {
    /// Spawn a copy of this test binary as a reader holding `file` open.
    fn open(exe: &Path, file: &Path) -> Reader {
        use std::io::BufRead;
        let mut child = Command::new(exe)
            .args([
                "--exact",
                "helper_reader",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("EG_HELPER_FILE", file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(out.read_line(&mut line).unwrap() > 0, "reader died");
            // libtest prints "test helper_reader ... " before our output.
            if line.contains("EG_OPENED") {
                break;
            }
        }
        Reader { child, out }
    }

    fn read(mut self) -> String {
        use std::io::{BufRead, Write};
        self.child.stdin.take().unwrap().write_all(b"go\n").unwrap();
        let mut line = String::new();
        loop {
            line.clear();
            assert!(self.out.read_line(&mut line).unwrap() > 0, "reader died");
            if let Some(i) = line.find("EG_DATA:") {
                let d = line[i + 8..].trim_end().to_string();
                self.child.wait().unwrap();
                return d;
            }
        }
    }
}

#[test]
fn two_callers_get_different_views_back_to_back() {
    if !fuse_ok() {
        return;
    }
    let s = Scratch::new("views");
    let file = s.env_file(&sample());
    // Two copies of this binary: same code, different exe paths, so the
    // policy can tell them apart.
    let me = std::env::current_exe().unwrap();
    let trusted = s.dir.join("trusted-reader");
    let untrusted = s.dir.join("untrusted-reader");
    fs::copy(&me, &trusted).unwrap();
    fs::copy(&me, &untrusted).unwrap();
    // Builtins off: when this suite runs under an AI agent or from an npm
    // script, every reader would be redacted by lineage and the test would
    // prove nothing about caching.
    let policy = format!(
        "[defaults]\ndisable_builtin = [\"ai-agent\", \"package-install\"]\n\
         [[rule]]\nview = \"real\"\nexe = \"{}\"\n",
        trusted.display()
    );
    let d = Daemon::start(&s, "guard", &file, Some(&policy));
    // FUSE drops the page cache on open unless FOPEN_KEEP_CACHE is set, so
    // the leak needs both readers to hold the file open before either reads.
    // Then the second read would come from pages the first one pulled in.
    for round in 0..10 {
        let a = Reader::open(&trusted, &file);
        let b = Reader::open(&untrusted, &file);
        let (real, red) = if round % 2 == 0 {
            let real = a.read();
            (real, b.read())
        } else {
            let red = b.read();
            (a.read(), red)
        };
        assert!(
            real.contains(SECRET),
            "round {round}: trusted reader got {real}"
        );
        assert!(
            !red.contains(SECRET),
            "round {round}: untrusted reader got the secret"
        );
        assert!(
            red.contains("STRIPE_KEY=sk_test_xxxx"),
            "round {round}: {red}"
        );
        assert_eq!(real.len(), red.len());
    }
    d.stop();
}

#[test]
fn st_size_is_identical_across_views() {
    if !fuse_ok() {
        return;
    }
    let s = Scratch::new("size");
    let original = sample();
    let file = s.env_file(&original);
    let d = Daemon::start(&s, "guard", &file, None);
    let meta = fs::metadata(&file).unwrap();
    assert_eq!(meta.len(), original.len() as u64);
    let stat = read_with(&canon("/usr/bin/stat"), &["-c", "%s"], &file);
    assert_eq!(stat.trim(), original.len().to_string());
    let red = read_with(&canon("/usr/bin/cat"), &[], &file);
    assert_eq!(red.len(), original.len());
    assert_eq!(meta.mode() & 0o222, 0, "write bits should be dropped");
    d.stop();
}

#[test]
fn watch_serves_real_and_leaves_file_untouched() {
    if !fuse_ok() {
        return;
    }
    let s = Scratch::new("watch");
    let mut original = sample();
    original.extend_from_slice(b"WEIRD=\xff\x00\r\nNO_NEWLINE=1");
    let file = s.env_file(&original);
    let d = Daemon::start(&s, "watch", &file, None);
    let mut got = Vec::new();
    fs::File::open(&file)
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, original);
    d.stop();
    assert_eq!(fs::read(&file).unwrap(), original);
    let log = fs::read_to_string(s.dir.join("state/env-ghost/events.jsonl")).unwrap();
    assert!(log.contains("\"op\":\"read\""));
    assert!(log.contains("\"cmdline_untrusted\""));
    assert!(!log.contains(SECRET), "secret leaked into the event log");
}

#[test]
fn writes_fail_cleanly() {
    if !fuse_ok() {
        return;
    }
    let s = Scratch::new("write");
    let file = s.env_file(&sample());
    let d = Daemon::start(&s, "guard", &file, None);
    let err = fs::OpenOptions::new().append(true).open(&file).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EROFS));
    let tmp = s.dir.join("tmp");
    fs::write(&tmp, b"X=1\n").unwrap();
    // Editors save with rename over the target. The kernel refuses that over
    // a mount point.
    let err = fs::rename(&tmp, &file).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EBUSY));
    d.stop();
    let log = fs::read_to_string(s.dir.join("state/env-ghost/events.jsonl")).unwrap();
    assert!(log.contains("write_denied"));
    assert_eq!(fs::read(&file).unwrap(), sample());
}

#[test]
fn sigkill_during_read_loop_brings_original_back() {
    if !fuse_ok() {
        return;
    }
    let s = Scratch::new("kill");
    let original = sample();
    let file = s.env_file(&original);
    let d = Daemon::start(&s, "guard", &file, None);
    let pid = d.child.id() as i32;

    let reader_file = file.clone();
    let reader = std::thread::spawn(move || {
        let (mut failed, mut redacted, mut plain) = (0, 0, 0);
        let mut last_fail: Option<Instant> = None;
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(3) {
            match fs::read(&reader_file) {
                Ok(b) if b.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()) => plain += 1,
                Ok(_) => redacted += 1,
                // In-flight requests are aborted with ECONNABORTED; new ones
                // on the dead connection get ENOTCONN until the detach lands.
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ENOTCONN) | Some(libc::ECONNABORTED)
                    ) =>
                {
                    failed += 1;
                    last_fail = Some(Instant::now());
                }
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        (failed, redacted, plain, last_fail)
    });
    std::thread::sleep(Duration::from_millis(300));
    let killed = Instant::now();
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let (failed, redacted, plain, last_fail) = reader.join().unwrap();
    eprintln!(
        "redacted reads {redacted}, failed reads {failed} (last {:?} after kill), plain reads after {plain}",
        last_fail.map(|l| l - killed)
    );
    assert!(plain > 0, "path never came back");
    assert!(!mounted(&file));
    // The original was never touched, so it's exactly what we started with.
    assert_eq!(fs::read(&file).unwrap(), original);
    drop(d);
}
