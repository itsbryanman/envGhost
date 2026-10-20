use std::fs;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

use serde::{Deserialize, Serialize};

const MAX_ANCESTRY: usize = 64;

/// A process pinned by TGID plus start time. PIDs get reused; the pair does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identity {
    pub tgid: i32,
    pub start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub start_time: u64,
    pub ppid: i32,
    pub exe: Option<String>,
    /// From /proc/<pid>/comm. Any process can set this to anything.
    pub comm_untrusted: String,
    /// From /proc/<pid>/cmdline. Any process can rewrite its own argv.
    pub cmdline_untrusted: Vec<String>,
    pub cgroup: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionKind {
    Sshd,
    Tmux,
    VscodeServer,
    SystemdUser,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionKind::Sshd => "sshd",
            SessionKind::Tmux => "tmux",
            SessionKind::VscodeServer => "vscode-server",
            SessionKind::SystemdUser => "systemd-user",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRoot {
    pub kind: SessionKind,
    pub pid: i32,
    /// The root's executable is owned by root and not writable by anyone else.
    /// A user can drop a binary named tmux in ~/bin; it can't do this.
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caller {
    /// The thread ID FUSE reported. Kept for the log; decisions use the TGID.
    pub tid: i32,
    pub identity: Identity,
    pub proc: ProcInfo,
    /// Parents from nearest to farthest, ending at the session root or pid 1.
    pub ancestry: Vec<ProcInfo>,
    pub session_root: Option<SessionRoot>,
    /// The caller's cgroup accepts processes from this user. systemd delegates
    /// user@UID.service to the user, so a process there could have moved
    /// itself in. Session scopes stay root-owned.
    pub cgroup_user_movable: bool,
    /// Walk hit pid 1 without passing a session root. Common for daemons and
    /// anything started via nohup or setsid, so this is a fact, not a verdict.
    pub reached_init: bool,
    /// Variables from the caller's initial environment that the built-in rules
    /// look at. Attacker-controlled, so only ever used to restrict.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub env_hints: Vec<String>,
}

#[derive(Debug)]
pub enum ResolveError {
    Kernel,
    Gone,
    Raced,
    Io(io::Error),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Kernel => write!(f, "request has no caller pid"),
            ResolveError::Gone => write!(f, "caller exited before it could be identified"),
            ResolveError::Raced => write!(f, "caller pid changed identity during lookup"),
            ResolveError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for ResolveError {
    fn from(e: io::Error) -> Self {
        if e.raw_os_error() == Some(libc::ESRCH) || e.kind() == io::ErrorKind::NotFound {
            ResolveError::Gone
        } else {
            ResolveError::Io(e)
        }
    }
}

const ENV_HINT_VARS: &[&str] = &[
    "npm_lifecycle_event",
    "PIP_BUILD_TRACKER",
    "OUT_DIR",
    "CARGO_MANIFEST_DIR",
    "CLAUDECODE",
    "AI_AGENT",
    "GEMINI_CLI",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
];

/// Resolve the thread ID from a FUSE request header into a pinned caller.
pub fn resolve(tid: u32) -> Result<Caller, ResolveError> {
    if tid == 0 {
        return Err(ResolveError::Kernel);
    }
    let tid = tid as i32;
    // FUSE hands us the calling thread, not the process. /proc/<tid> resolves
    // for any thread even though readdir on /proc only lists group leaders.
    let tgid = read_tgid(tid)?;

    let pidfd = pidfd_open(tgid)?;
    let proc = read_proc(tgid)?;

    let mut ancestry: Vec<ProcInfo> = Vec::new();
    let mut session_root = session_root_of(&proc);
    let mut reached_init = false;
    let mut ppid = proc.ppid;
    let mut child_start = proc.start_time;
    while session_root.is_none() && ancestry.len() < MAX_ANCESTRY {
        if ppid <= 1 {
            reached_init = ppid == 1;
            break;
        }
        let Ok(parent) = read_proc(ppid) else { break };
        // A parent can't be younger than its child. If it is, the real parent
        // exited and the pid now belongs to an unrelated process.
        if parent.start_time > child_start {
            break;
        }
        child_start = parent.start_time;
        let next = parent.ppid;
        session_root = session_root_of(&parent);
        ancestry.push(parent);
        ppid = next;
    }

    let env_hints = read_env_hints(tgid);
    let cgroup_user_movable = proc.cgroup.as_deref().is_none_or(cgroup_user_movable);

    // Everything above was read by pid. If the process exited and the pid was
    // recycled while we were reading, the start time changes or the pidfd
    // reports exit. Either way the data may describe someone else.
    let start_again = read_start_time(tgid)?;
    if start_again != proc.start_time || pidfd_exited(&pidfd) {
        return Err(ResolveError::Raced);
    }
    // The requesting thread is blocked in our syscall and can only disappear
    // if it was killed. If it did, its tid may now be in another process.
    if read_tgid(tid).ok() != Some(tgid) {
        return Err(ResolveError::Raced);
    }

    Ok(Caller {
        tid,
        identity: Identity {
            tgid,
            start_time: proc.start_time,
        },
        proc,
        ancestry,
        session_root,
        cgroup_user_movable,
        reached_init,
        env_hints,
    })
}

fn read_tgid(tid: i32) -> Result<i32, ResolveError> {
    let status = fs::read_to_string(format!("/proc/{tid}/status"))?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or(ResolveError::Gone)
}

fn pidfd_open(pid: i32) -> Result<OwnedFd, ResolveError> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn pidfd_exited(fd: &OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    // A pidfd becomes readable once the process has exited.
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    n != 0
}

pub struct Stat {
    pub comm: String,
    pub ppid: i32,
    pub start_time: u64,
}

/// Parse /proc/<pid>/stat. comm sits in parens and may itself contain spaces
/// and ')', so fields are counted from the last ')'.
pub fn parse_stat(raw: &str) -> Option<Stat> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    let comm = raw.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = raw.get(close + 1..)?.split_whitespace().collect();
    // rest[0] is field 3 (state); ppid is field 4, starttime field 22.
    let ppid = rest.get(1)?.parse().ok()?;
    let start_time = rest.get(19)?.parse().ok()?;
    Some(Stat {
        comm,
        ppid,
        start_time,
    })
}

fn read_stat(pid: i32) -> io::Result<Stat> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_stat(&raw).ok_or_else(|| io::Error::other(format!("unparsable /proc/{pid}/stat")))
}

fn read_start_time(pid: i32) -> io::Result<u64> {
    Ok(read_stat(pid)?.start_time)
}

pub fn read_proc(pid: i32) -> io::Result<ProcInfo> {
    let stat = read_stat(pid)?;
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default();
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|s| parse_cgroup_v2(&s));
    Ok(ProcInfo {
        pid,
        start_time: stat.start_time,
        ppid: stat.ppid,
        exe,
        comm_untrusted: stat.comm,
        cmdline_untrusted: cmdline,
        cgroup,
    })
}

pub fn parse_cgroup_v2(raw: &str) -> Option<String> {
    raw.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.to_string())
}

fn cgroup_user_movable(cgroup: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(format!("/sys/fs/cgroup{cgroup}/cgroup.procs")) {
        Ok(m) => m.uid() != 0 || m.mode() & 0o022 != 0,
        Err(_) => true,
    }
}

fn read_env_hints(pid: i32) -> Vec<String> {
    // Needs ptrace read access. Same UID and dumpable is enough; yama does
    // not gate PTRACE_MODE_READ.
    let Ok(raw) = fs::read(format!("/proc/{pid}/environ")) else {
        return Vec::new();
    };
    raw.split(|b| *b == 0)
        .filter_map(|kv| {
            let kv = String::from_utf8_lossy(kv);
            let (k, v) = kv.split_once('=')?;
            ENV_HINT_VARS
                .contains(&k)
                .then(|| format!("{k}={}", v.chars().take(128).collect::<String>()))
        })
        .collect()
}

fn exe_name(p: &ProcInfo) -> Option<&str> {
    let exe = p.exe.as_deref()?;
    let exe = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    Path::new(exe).file_name()?.to_str()
}

/// Session roots are where we stop walking. These programs reparent or detach
/// their children on purpose, so anything above them says nothing about the
/// caller. Only verified roots end the walk; an unverified match is recorded
/// but the walk continues so a fake tmux can't hide its own parents.
fn session_root_of(p: &ProcInfo) -> Option<SessionRoot> {
    let kind = session_kind(p)?;
    let verified = exe_root_owned(p.pid);
    if !verified && kind != SessionKind::VscodeServer {
        return None;
    }
    Some(SessionRoot {
        kind,
        pid: p.pid,
        verified,
    })
}

fn session_kind(p: &ProcInfo) -> Option<SessionKind> {
    let exe = p.exe.as_deref()?;
    match exe_name(p)? {
        "sshd" | "sshd-session" => return Some(SessionKind::Sshd),
        "tmux" => return Some(SessionKind::Tmux),
        // pid 1 is also systemd; only the per-user manager counts.
        "systemd" if p.pid != 1 && p.cmdline_untrusted.iter().any(|a| a == "--user") => {
            return Some(SessionKind::SystemdUser);
        }
        _ => {}
    }
    // vscode-server lives in the user's home, so it can never be verified.
    if exe.contains("/.vscode-server/") || exe.contains("/.vscode-server-insiders/") {
        return Some(SessionKind::VscodeServer);
    }
    None
}

/// stat through /proc/<pid>/exe reaches the inode actually mapped, even if
/// the path was replaced after exec.
pub fn exe_root_owned(pid: i32) -> bool {
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(format!("/proc/{pid}/exe")) {
        Ok(m) => m.uid() == 0 && m.mode() & 0o022 == 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_hostile_comm() {
        let raw = "4242 (evil) 1 2 (x) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
        let s = parse_stat(raw).unwrap();
        assert_eq!(s.comm, "evil) 1 2 (x");
        assert_eq!(s.ppid, 17);
        assert_eq!(s.start_time, 987654);
    }

    #[test]
    fn cgroup_v2_line() {
        let raw = "0::/user.slice/user-1000.slice/session-3.scope\n";
        assert_eq!(
            parse_cgroup_v2(raw).as_deref(),
            Some("/user.slice/user-1000.slice/session-3.scope")
        );
        assert_eq!(parse_cgroup_v2("12:pids:/foo\n"), None);
    }

    #[test]
    fn resolves_self_from_thread() {
        let tid = unsafe { libc::gettid() };
        let handle = std::thread::spawn(|| unsafe { libc::gettid() });
        let other_tid = handle.join().unwrap();
        let me = resolve(tid as u32).unwrap();
        assert_eq!(me.identity.tgid, std::process::id() as i32);
        // The thread has exited by now, so it may or may not resolve, but it
        // must never resolve to a different process.
        if let Ok(c) = resolve(other_tid as u32) {
            assert_eq!(c.identity.tgid, std::process::id() as i32);
        }
    }

    #[test]
    fn live_thread_maps_to_tgid() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            tx.send(unsafe { libc::gettid() }).unwrap();
            done_rx.recv().unwrap();
        });
        let tid = rx.recv().unwrap();
        assert_ne!(tid, std::process::id() as i32);
        let c = resolve(tid as u32).unwrap();
        assert_eq!(c.identity.tgid, std::process::id() as i32);
        assert_eq!(c.tid, tid);
        done_tx.send(()).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn kernel_request_has_no_caller() {
        assert!(matches!(resolve(0), Err(ResolveError::Kernel)));
    }
}
