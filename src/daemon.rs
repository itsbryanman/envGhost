use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};

use crate::audit::{self, Audit, Event};
use crate::fs::{GhostFs, Mode, Views};
use crate::policy::Policy;

const MAX_FILE: u64 = 1 << 20;

static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

pub struct Options {
    pub mode: Mode,
    pub policy: Policy,
    pub policy_desc: String,
    pub quiet: bool,
}

/// Mount over `path` and serve it until a signal arrives. The file on disk is
/// never modified: the mount covers it, and when the mount goes away for any
/// reason the original is what's there.
pub fn run(path: &Path, opts: Options) -> Result<()> {
    let path = fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
    let meta = fs::metadata(&path)?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if is_ghost_mount(&path) {
        bail!("{} is already mounted by env-ghost", path.display());
    }
    if meta.len() > MAX_FILE {
        bail!("{} is larger than {} bytes", path.display(), MAX_FILE);
    }
    let original = fs::read(&path)?;

    set_non_dumpable()?;
    let audit = Arc::new(Audit::open(!opts.quiet)?);
    let path_str = path.to_string_lossy().into_owned();

    eprintln!("env-ghost: same-UID isolation is not a security boundary");
    eprintln!(
        "env-ghost: the plaintext stays on disk under the mount; any process of this user can unmount it"
    );

    // Block the signals we handle before any thread exists, so they all
    // inherit the mask and only the sigwait thread ever sees them.
    let sigs = block_signals();

    let mut watchdog = spawn_watchdog(&path)?;

    let views = Views::build(original);
    let fs = GhostFs::new(
        opts.mode,
        path_str.clone(),
        views,
        &meta,
        opts.policy,
        audit.clone(),
    );
    let mut config = fuser::Config::default();
    config.mount_options = vec![
        fuser::MountOption::FSName("env-ghost".into()),
        fuser::MountOption::Subtype("env-ghost".into()),
        fuser::MountOption::NoSuid,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoExec,
    ];
    let session = match fuser::Session::new(fs, &path, &config) {
        Ok(s) => s,
        Err(e) => {
            watchdog.clean();
            return Err(e).with_context(|| format!("mounting over {}", path.display()));
        }
    };

    match opts.mode {
        Mode::Watch => eprintln!(
            "env-ghost: watching {} (audit only, every caller gets the real file)",
            path.display()
        ),
        Mode::Guard => eprintln!(
            "env-ghost: guarding {} (policy: {})",
            path.display(),
            opts.policy_desc
        ),
    }
    eprintln!("env-ghost: events: {}", audit::log_path()?.display());
    audit.record(&Event::new("start", &path_str).note(format!(
        "mode {}, pid {}",
        match opts.mode {
            Mode::Watch => "watch",
            Mode::Guard => "guard",
        },
        std::process::id()
    )));

    {
        let path = path.clone();
        let audit = audit.clone();
        std::thread::spawn(move || {
            loop {
                let sig = wait_signal(&sigs);
                SHUTTING_DOWN.store(true, Ordering::SeqCst);
                match lazy_unmount(&path) {
                    Ok(()) => {
                        audit.record(
                            &Event::new("stop", &path.to_string_lossy())
                                .note(format!("signal {sig}")),
                        );
                        watchdog.clean();
                        std::process::exit(0);
                    }
                    Err(e) => {
                        // Exiting now would leave a dead mount behind. Keep
                        // serving and let the user try again.
                        SHUTTING_DOWN.store(false, Ordering::SeqCst);
                        eprintln!("env-ghost: shutdown failed, still running: {e:#}");
                    }
                }
            }
        });
    }

    let res = session.run();
    if SHUTTING_DOWN.load(Ordering::SeqCst) {
        loop {
            std::thread::park();
        }
    }
    let note = match res {
        Ok(()) => "unmounted by something other than env-ghost".to_string(),
        Err(e) => format!("fuse session ended: {e}"),
    };
    audit.record(&Event::new("external_unmount", &path_str).note(note.clone()));
    eprintln!(
        "env-ghost: {note}; {} is the plain file again",
        path.display()
    );
    std::process::exit(3);
}

fn set_non_dumpable() -> Result<()> {
    // Makes /proc/<pid>/mem, environ and ptrace attach root-only for this
    // process. The plaintext lives here, so this matters more than anywhere.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        bail!(
            "prctl(PR_SET_DUMPABLE): {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn block_signals() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

fn wait_signal(set: &libc::sigset_t) -> i32 {
    let mut sig = 0;
    unsafe { libc::sigwait(set, &mut sig) };
    sig
}

/// MNT_DETACH: the path is released at once even if a reader holds the file
/// open. That reader keeps its fd; new opens see the file underneath.
pub fn lazy_unmount(path: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINVAL) {
                bail!("umount2 {}: {e}", path.display());
            }
        }
        return Ok(());
    }
    // Unprivileged users can't call umount2; fusermount3 is setuid and checks
    // that the mount belongs to us.
    let out = Command::new("fusermount3")
        .args(["-u", "-z", "--"])
        .arg(path)
        .output()
        .context("running fusermount3")?;
    if !out.status.success() && is_ghost_mount(path) {
        bail!(
            "fusermount3 -u -z {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn is_ghost_mount(path: &Path) -> bool {
    let Ok(info) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = path.to_string_lossy();
    info.lines().any(|l| {
        let mut halves = l.splitn(2, " - ");
        let left: Vec<&str> = halves.next().unwrap_or("").split(' ').collect();
        let right: Vec<&str> = halves.next().unwrap_or("").split(' ').collect();
        let mnt = left.get(4).map(|m| unescape_mountinfo(m));
        let fstype = right.first().copied().unwrap_or("");
        let source = right.get(1).copied().unwrap_or("");
        mnt.as_deref() == Some(&*want) && fstype.starts_with("fuse") && source == "env-ghost"
    })
}

fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() && b[i + 1..i + 4].iter().all(|c| c.is_ascii_digit()) {
            let v = u8::from_str_radix(&s[i + 1..i + 4], 8).unwrap_or(b'?');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub struct Watchdog {
    stdin: Option<std::process::ChildStdin>,
    child: std::process::Child,
}

impl Watchdog {
    /// Tell the watchdog we exited on purpose, then wait for it.
    fn clean(&mut self) {
        if let Some(mut s) = self.stdin.take() {
            let _ = s.write_all(b"C");
        }
        let _ = self.child.wait();
    }
}

fn spawn_watchdog(path: &Path) -> Result<Watchdog> {
    let exe = std::env::current_exe().context("locating own executable")?;
    let mut cmd = Command::new(exe);
    cmd.arg("__watchdog")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    unsafe {
        cmd.pre_exec(|| {
            // Own session: a Ctrl-C or SIGHUP aimed at the daemon's terminal
            // must not take the watchdog down with it.
            libc::setsid();
            // The signal mask survives exec, and the daemon has SIGTERM
            // blocked for its sigwait thread.
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("starting watchdog")?;
    let stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut ack = [0u8; 1];
    if stdout.read_exact(&mut ack).is_err() || &ack != b"R" {
        let _ = child.wait();
        bail!("watchdog failed to start; not mounting without crash recovery");
    }
    Ok(Watchdog {
        stdin: Some(stdin),
        child,
    })
}

/// The watchdog does nothing until the daemon's end of the pipe closes. If
/// that happens without the daemon saying goodbye, the daemon died, and the
/// kernel answers every access to the dead mount with ENOTCONN. Detaching it
/// puts the original file back in view.
pub fn watchdog_main(path: &Path) -> Result<()> {
    set_non_dumpable()?;
    let mut stdin = std::io::stdin().lock();
    std::io::stdout().write_all(b"R")?;
    std::io::stdout().flush()?;

    let mut msg = [0u8; 1];
    let n = stdin.read(&mut msg).unwrap_or(0);
    if n == 1 && &msg == b"C" {
        return Ok(());
    }
    if !is_ghost_mount(path) {
        return Ok(());
    }
    let res = lazy_unmount(path);
    let path_str = path.to_string_lossy().into_owned();
    let note = match &res {
        Ok(()) => "daemon died; mount detached".to_string(),
        Err(e) => format!("daemon died; detach failed: {e:#}"),
    };
    if let Ok(audit) = Audit::open(false) {
        audit.record(&Event::new("watchdog", &path_str).note(note.clone()));
    }
    eprintln!("env-ghost: {note}: {}", path.display());
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_escapes() {
        assert_eq!(unescape_mountinfo("/home/a\\040b/.env"), "/home/a b/.env");
        assert_eq!(unescape_mountinfo("/x/dir\\040"), "/x/dir ");
        assert_eq!(unescape_mountinfo("/x\\04"), "/x\\04");
    }
}
