use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Ok,
    Warn,
    No,
}

struct Line {
    name: &'static str,
    status: Status,
    detail: String,
}

/// Probe the host and print what works. Returns false if watch and guard
/// can't run here.
pub fn run() -> bool {
    let mut lines = Vec::new();
    let mut blockers = Vec::new();

    let euid = unsafe { libc::geteuid() };
    let kernel = kernel_release();

    let fuse = probe_fuse(euid);
    if fuse.status == Status::No {
        blockers.push("fuse");
    }
    lines.push(fuse);

    let pidfd = probe_pidfd(&kernel);
    if pidfd.status == Status::No {
        blockers.push("pidfd");
    }
    lines.push(pidfd);

    lines.push(probe_cgroup());
    lines.push(probe_yama());
    lines.push(probe_userns());
    lines.push(probe_landlock());
    lines.push(probe_bpf(euid));
    if euid == 0 {
        lines.push(Line {
            name: "user",
            status: Status::Warn,
            detail: "running as root; mounts will only be readable by root's processes".into(),
        });
    }

    let container = detect_container();
    if let Some(c) = &container {
        lines.push(Line {
            name: "container",
            status: Status::Warn,
            detail: c.clone(),
        });
    }

    for l in &lines {
        let s = match l.status {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::No => "no",
        };
        println!("{:<10} {:<5} {}", l.name, s, l.detail);
    }
    println!();
    println!("kernel     {kernel}");
    if blockers.is_empty() {
        println!("watch and guard can run here (unprivileged mode: same-UID processes are not isolated)");
        true
    } else {
        println!("watch and guard can't run here: missing {}", blockers.join(", "));
        if container.is_some() {
            println!(
                "in docker, these run args would provide what's missing: \
                 --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined"
            );
        }
        false
    }
}

fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn probe_fuse(euid: u32) -> Line {
    let dev = Path::new("/dev/fuse");
    let meta = match fs::metadata(dev) {
        Ok(m) => m,
        Err(_) => {
            return Line {
                name: "fuse",
                status: Status::No,
                detail: "/dev/fuse does not exist".into(),
            };
        }
    };
    if !meta.file_type().is_char_device() {
        return Line {
            name: "fuse",
            status: Status::No,
            detail: "/dev/fuse is not a character device".into(),
        };
    }
    if let Err(e) = fs::OpenOptions::new().read(true).write(true).open(dev) {
        return Line {
            name: "fuse",
            status: Status::No,
            detail: format!("can't open /dev/fuse: {e}"),
        };
    }
    if euid == 0 {
        return Line {
            name: "fuse",
            status: Status::Ok,
            detail: "/dev/fuse opens read-write; root mounts directly".into(),
        };
    }
    match find_in_path("fusermount3") {
        Some(p) => {
            let m = fs::metadata(&p).ok();
            let setuid = m.as_ref().is_some_and(|m| m.permissions().mode() & 0o4000 != 0 && m.uid() == 0);
            if setuid {
                Line {
                    name: "fuse",
                    status: Status::Ok,
                    detail: format!("/dev/fuse opens read-write, {} is setuid root", p.display()),
                }
            } else {
                Line {
                    name: "fuse",
                    status: Status::No,
                    detail: format!("{} is not setuid root, so unprivileged mounts fail", p.display()),
                }
            }
        }
        None => Line {
            name: "fuse",
            status: Status::No,
            detail: "fusermount3 not found in PATH (install the fuse3 package)".into(),
        },
    }
}

fn find_in_path(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

fn probe_pidfd(kernel: &str) -> Line {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Line {
            name: "pidfd",
            status: Status::No,
            detail: format!("pidfd_open failed: {e} (needs Linux 5.3+, kernel is {kernel})"),
        };
    }
    unsafe { libc::close(fd as i32) };
    Line {
        name: "pidfd",
        status: Status::Ok,
        detail: "pidfd_open works; callers are pinned against pid reuse".into(),
    }
}

fn probe_cgroup() -> Line {
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut st) } == 0;
    // CGROUP2_SUPER_MAGIC
    if !ok || st.f_type as u64 != 0x6367_7270 {
        return Line {
            name: "cgroup",
            status: Status::No,
            detail: "/sys/fs/cgroup is not cgroup v2; cgroup matchers will never match".into(),
        };
    }
    let own = fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| crate::caller::parse_cgroup_v2(&s))
        .unwrap_or_default();
    let dir = format!("/sys/fs/cgroup{own}");
    let writable = access_w(&format!("{dir}/cgroup.procs"));
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let ro_mount = unsafe { libc::statvfs(c"/sys/fs/cgroup".as_ptr(), &mut vfs) } == 0
        && vfs.f_flag & libc::ST_RDONLY != 0;
    let detail = format!(
        "v2, own cgroup {own}, {} (not used yet)",
        if ro_mount {
            "mounted read-only"
        } else if writable {
            "writable"
        } else {
            "not writable"
        }
    );
    Line {
        name: "cgroup",
        status: Status::Ok,
        detail,
    }
}

fn access_w(p: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(p) else {
        return false;
    };
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

fn probe_yama() -> Line {
    match fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(v) => {
            let v = v.trim();
            let (status, what) = match v {
                "0" => (
                    Status::Warn,
                    "any same-uid process can read another's memory (/proc/<pid>/mem, ptrace)",
                ),
                "1" => (Status::Ok, "only ancestors can ptrace or read /proc/<pid>/mem"),
                "2" => (Status::Ok, "only CAP_SYS_PTRACE can ptrace"),
                "3" => (Status::Ok, "ptrace disabled"),
                _ => (Status::Warn, "unknown value"),
            };
            Line {
                name: "ptrace",
                status,
                detail: format!(
                    "yama ptrace_scope={v}: {what}. /proc/<pid>/environ stays readable either way"
                ),
            }
        }
        Err(_) => Line {
            name: "ptrace",
            status: Status::Warn,
            detail: "yama not present; same-uid processes can read each other's memory".into(),
        },
    }
}

fn probe_userns() -> Line {
    // Ask the kernel instead of reading sysctls: Debian, Ubuntu's apparmor
    // restriction and max_user_namespaces all gate this differently.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        unsafe { libc::_exit(if r == 0 { 0 } else { 1 }) };
    }
    let mut status = 0;
    if pid > 0 {
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }
    let works = pid > 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    Line {
        name: "userns",
        status: if works { Status::Ok } else { Status::No },
        detail: if works {
            "unprivileged user namespaces work (not used yet)".into()
        } else {
            "unprivileged user namespaces are blocked (not used yet)".into()
        },
    }
}

fn probe_landlock() -> Line {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi > 0 {
        Line {
            name: "landlock",
            status: Status::Ok,
            detail: format!("ABI v{abi} (not used yet)"),
        }
    } else {
        let e = std::io::Error::last_os_error();
        Line {
            name: "landlock",
            status: Status::No,
            detail: format!("unavailable: {e} (not used yet)"),
        }
    }
}

fn probe_bpf(euid: u32) -> Line {
    let unpriv = fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into());
    let lsm = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let bpf_lsm = lsm.split(',').any(|m| m.trim() == "bpf");
    let btf = Path::new("/sys/kernel/btf/vmlinux").exists();
    let usable = euid == 0 || unpriv == "0";
    Line {
        name: "bpf",
        status: if usable && bpf_lsm && btf {
            Status::Ok
        } else {
            Status::No
        },
        detail: format!(
            "unprivileged_bpf_disabled={unpriv}, bpf lsm {}, btf {}, {} (not used yet)",
            if bpf_lsm { "active" } else { "inactive" },
            if btf { "present" } else { "missing" },
            if usable {
                "loadable by this user"
            } else {
                "needs root or CAP_BPF"
            }
        ),
    }
}

fn detect_container() -> Option<String> {
    if Path::new("/.dockerenv").exists() {
        return Some("running inside docker".into());
    }
    if Path::new("/run/.containerenv").exists() {
        return Some("running inside podman".into());
    }
    let cg = fs::read_to_string("/proc/1/cgroup").unwrap_or_default();
    if cg.contains("docker") || cg.contains("kubepods") || cg.contains("containerd") {
        return Some("pid 1 is in a container cgroup".into());
    }
    None
}
