use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};

use crate::audit::{self, Audit, Event};
use crate::fs::{GhostFs, Mode, Views};
use crate::policy::Policy;

pub const STUB_PREFIX: &str = "# env-ghost is not running";
const MAX_FILE: u64 = 1 << 20;

pub fn stub_for(path: &Path) -> String {
    format!(
        "{STUB_PREFIX}. if it crashed, run: env-ghost restore {}\n",
        path.display()
    )
}

static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

pub struct Options {
    pub mode: Mode,
    pub policy: Policy,
    pub policy_desc: String,
    pub quiet: bool,
}

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
    if original.starts_with(STUB_PREFIX.as_bytes()) {
        bail!(
            "{} holds an env-ghost stub, so the real contents aren't here. \
             try: env-ghost restore {}",
            path.display(),
            path.display()
        );
    }

    set_non_dumpable()?;
    let audit = Arc::new(Audit::open(!opts.quiet)?);
    let path_str = path.to_string_lossy().into_owned();

    eprintln!("env-ghost: same-UID isolation is not a security boundary");

    // Block the signals we handle before any thread exists, so they all
    // inherit the mask and only the sigwait thread ever sees them.
    let sigs = block_signals();

    let mut watchdog = spawn_watchdog(&path, &original)?;

    write_in_place(&path, stub_for(&path).as_bytes())
        .with_context(|| format!("writing stub to {}", path.display()))?;

    let views = Views::build(original.clone());
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
            let restored = write_in_place(&path, &original);
            watchdog.clean();
            restored.context("mount failed and restoring the original also failed")?;
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
            let sig = wait_signal(&sigs);
            SHUTTING_DOWN.store(true, Ordering::SeqCst);
            let code = match shutdown(&path, &original, &audit, sig) {
                Ok(()) => {
                    watchdog.clean();
                    0
                }
                Err(e) => {
                    // Leave the watchdog holding the bytes so restore works.
                    eprintln!("env-ghost: {e:#}");
                    1
                }
            };
            std::process::exit(code);
        });
    }

    let res = session.run();
    if SHUTTING_DOWN.load(Ordering::SeqCst) {
        loop {
            std::thread::park();
        }
    }
    // Someone else unmounted us. Don't put the secrets back on disk: whoever
    // did that would just read them. The watchdog keeps a copy for restore.
    let note = match res {
        Ok(()) => "unmounted by something other than env-ghost".to_string(),
        Err(e) => format!("fuse session ended: {e}"),
    };
    audit.record(&Event::new("external_unmount", &path_str).note(note.clone()));
    eprintln!(
        "env-ghost: {note}; {} now shows the stub. env-ghost restore {} puts the original back",
        path.display(),
        path.display()
    );
    std::process::exit(3);
}

fn shutdown(path: &Path, original: &[u8], audit: &Audit, sig: i32) -> Result<()> {
    lazy_unmount(path)?;
    write_in_place(path, original).context("restoring original contents")?;
    let back = fs::read(path)?;
    if back != original {
        bail!("restored file does not match the original");
    }
    let path_str = path.to_string_lossy();
    audit.record(&Event::new("stop", &path_str).note(format!("signal {sig}, original restored")));
    eprintln!("env-ghost: restored {}", path.display());
    Ok(())
}

fn write_in_place(path: &Path, bytes: &[u8]) -> Result<()> {
    // Same inode, so ownership, mode and hard links survive.
    let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn set_non_dumpable() -> Result<()> {
    // Makes /proc/<pid>/mem, environ and ptrace attach root-only for this
    // process. The plaintext lives here, so this matters more than anywhere.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        bail!("prctl(PR_SET_DUMPABLE): {}", std::io::Error::last_os_error());
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
        if b[i] == b'\\' && i + 3 < b.len() + 0 && b[i + 1..i + 4].iter().all(|c| c.is_ascii_digit())
        {
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

fn spawn_watchdog(path: &Path, original: &[u8]) -> Result<Watchdog> {
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
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("starting watchdog")?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    stdin.write_all(&(original.len() as u64).to_le_bytes())?;
    stdin.write_all(original)?;
    stdin.flush()?;
    let mut ack = [0u8; 1];
    if stdout.read_exact(&mut ack).is_err() {
        let _ = child.wait();
        bail!("watchdog failed to start (see above); not mounting without crash recovery");
    }
    if &ack != b"R" {
        bail!("watchdog sent unexpected ack");
    }
    Ok(Watchdog {
        stdin: Some(stdin),
        child,
    })
}

fn socket_path(path: &Path) -> Result<PathBuf> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    Ok(audit::runtime_dir()?.join(format!("restore-{:016x}.sock", h.finish())))
}

/// The watchdog. It holds a copy of the original bytes and does nothing
/// until the daemon's end of the pipe closes. If that happens without the
/// daemon saying goodbye, the daemon died: detach the mount so the path stops
/// returning ENOTCONN, then wait for `env-ghost restore`.
pub fn watchdog_main(path: &Path) -> Result<()> {
    set_non_dumpable()?;
    let mut stdin = std::io::stdin().lock();
    let mut len = [0u8; 8];
    stdin.read_exact(&mut len)?;
    let mut original = vec![0u8; u64::from_le_bytes(len) as usize];
    stdin.read_exact(&mut original)?;

    // Bind now, not after a crash. If restore can't work, the daemon must
    // find out before it replaces the file with the stub.
    let sock = socket_path(path)?;
    audit::ensure_private_dir(sock.parent().unwrap())?;
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)
        .with_context(|| format!("binding restore socket {}", sock.display()))?;

    std::io::stdout().write_all(b"R")?;
    std::io::stdout().flush()?;

    let mut msg = [0u8; 1];
    let n = stdin.read(&mut msg).unwrap_or(0);
    if n == 1 && &msg == b"C" {
        let _ = fs::remove_file(&sock);
        return Ok(());
    }

    let detached = if is_ghost_mount(path) {
        lazy_unmount(path).map(|_| true)
    } else {
        Ok(false)
    };
    let path_str = path.to_string_lossy().into_owned();
    if let Ok(audit) = Audit::open(false) {
        let note = match &detached {
            Ok(true) => "daemon died; mount detached, stub exposed".to_string(),
            Ok(false) => "daemon gone and not mounted; holding original for restore".to_string(),
            Err(e) => format!("daemon died; detach failed: {e:#}"),
        };
        audit.record(&Event::new("watchdog", &path_str).note(note));
    }
    match &detached {
        Ok(_) => eprintln!(
            "env-ghost: daemon for {} is gone; the path shows the stub. run: env-ghost restore {}",
            path.display(),
            path.display()
        ),
        Err(e) => eprintln!("env-ghost: daemon for {} died and detach failed: {e:#}", path.display()),
    }

    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { continue };
        let mut req = String::new();
        let _ = (&mut conn).take(64).read_to_string(&mut req);
        let force = req.trim() == "restore --force";
        let current = fs::read(path).unwrap_or_default();
        if !force && !current.starts_with(STUB_PREFIX.as_bytes()) {
            let _ = conn.write_all(
                b"refused: the file no longer holds the env-ghost stub. use --force to overwrite\n",
            );
            continue;
        }
        if is_ghost_mount(path) {
            let _ = conn.write_all(b"refused: still mounted\n");
            continue;
        }
        match write_in_place(path, &original) {
            Ok(()) => {
                let _ = conn.write_all(b"restored\n");
                let _ = fs::remove_file(&sock);
                if let Ok(audit) = Audit::open(false) {
                    audit.record(&Event::new("restore", &path_str).note("original restored by request"));
                }
                return Ok(());
            }
            Err(e) => {
                let _ = conn.write_all(format!("failed: {e:#}\n").as_bytes());
            }
        }
    }
    Ok(())
}

pub fn restore(path: &Path, force: bool) -> Result<()> {
    let path = fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
    if is_ghost_mount(&path) {
        bail!("{} is mounted; env-ghost is still running", path.display());
    }
    let sock = socket_path(&path)?;
    let mut conn = match UnixStream::connect(&sock) {
        Ok(c) => c,
        Err(_) => {
            bail!(
                "no watchdog is holding {}. if the daemon was stopped cleanly the file \
                 is already restored; if the machine rebooted, the copy is gone",
                path.display()
            );
        }
    };
    let req: &[u8] = if force { b"restore --force" } else { b"restore" };
    conn.write_all(req)?;
    conn.shutdown(std::net::Shutdown::Write)?;
    let mut resp = String::new();
    conn.read_to_string(&mut resp)?;
    let resp = resp.trim();
    if resp == "restored" {
        println!("restored {}", path.display());
        Ok(())
    } else {
        bail!("{resp}")
    }
}
