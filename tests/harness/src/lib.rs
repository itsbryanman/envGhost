//! Shared bits for the attack programs. Each attack prints one or more
//! RESULT lines; tests/harness/run.sh collects them.

use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::path::Path;

pub enum Verdict {
    Held,
    Bypassed,
    NotApplicable,
}

/// One tab-separated line: id, verdict, attack, note.
pub fn report(id: &str, verdict: Verdict, attack: &str, note: &str) {
    let v = match verdict {
        Verdict::Held => "HELD",
        Verdict::Bypassed => "BYPASSED",
        Verdict::NotApplicable => "N/A",
    };
    let note = note.replace(['\t', '\n'], " ");
    println!("RESULT\t{id}\t{v}\t{attack}\t{note}");
}

pub fn has(hay: &[u8], needle: &str) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

pub fn describe(bytes: &[u8], secret: &str) -> &'static str {
    if has(bytes, secret) {
        "real"
    } else {
        "not real"
    }
}

pub fn args() -> Vec<String> {
    std::env::args().collect()
}

pub fn ptrace_scope() -> String {
    fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "absent".into())
}

pub fn mounted(path: &Path) -> bool {
    let info = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let p = path.to_string_lossy();
    info.lines()
        .any(|l| l.split(' ').nth(4) == Some(&*p) && l.contains(" env-ghost "))
}

/// Send one fd over a connected unix socket with SCM_RIGHTS.
pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    unsafe {
        let mut byte = [b'F'];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut RawFd, fd);
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
    unsafe {
        let mut byte = [0u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space;
        if libc::recvmsg(sock, &mut msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::other("no fd received"));
        }
        Ok(std::ptr::read_unaligned(
            libc::CMSG_DATA(cmsg) as *const RawFd
        ))
    }
}

/// Map a file MAP_PRIVATE and copy out `len` bytes.
pub struct Mapping {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Mapping {
    pub fn private(path: &Path, len: usize) -> io::Result<Mapping> {
        Self::map(path, len, libc::MAP_PRIVATE)
    }

    pub fn shared(path: &Path, len: usize) -> io::Result<Mapping> {
        Self::map(path, len, libc::MAP_SHARED)
    }

    fn map(path: &Path, len: usize, flags: i32) -> io::Result<Mapping> {
        use std::os::fd::AsRawFd;
        let f = fs::File::open(path)?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                flags,
                f.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Mapping { ptr, len })
    }

    pub fn bytes(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len).to_vec() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}
