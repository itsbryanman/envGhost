use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, INodeNo, LockOwner,
    OpenAccMode, OpenFlags, ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite,
    Request, TimeOrNow, WriteFlags,
};

use crate::audit::{Audit, Event};
use crate::caller::{self, Caller, Identity, ResolveError};
use crate::policy::{Decision, Policy, View};
use crate::redact;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Audit only: everyone gets the real bytes.
    Watch,
    /// Serve whatever the policy decides.
    Guard,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Watch => "watch",
            Mode::Guard => "guard",
        }
    }
}

const WRITE_HINT: &str = "writes are not supported yet; stop env-ghost, edit the file, start it again";

pub struct Views {
    pub real: Vec<u8>,
    pub redacted: Vec<u8>,
    pub canary: Vec<u8>,
}

impl Views {
    pub fn build(real: Vec<u8>) -> Views {
        let redacted = redact::redact(&real);
        let canary = redact::canary(&real);
        // st_size is shared by every caller, so every view must be the same
        // length or the size itself tells a reader which view it got.
        assert_eq!(redacted.len(), real.len());
        assert_eq!(canary.len(), real.len());
        Views {
            real,
            redacted,
            canary,
        }
    }

    fn get(&self, v: View) -> &[u8] {
        match v {
            View::Real => &self.real,
            View::Redacted => &self.redacted,
            View::Canary => &self.canary,
        }
    }
}

struct Handle {
    opener: Option<Identity>,
    view: View,
}

pub struct GhostFs {
    mode: Mode,
    path: String,
    views: Views,
    attr: FileAttr,
    policy: Policy,
    handles: Mutex<HashMap<u64, Handle>>,
    next_fh: AtomicU64,
    audit: Arc<Audit>,
}

impl GhostFs {
    pub fn new(
        mode: Mode,
        path: String,
        views: Views,
        meta: &std::fs::Metadata,
        policy: Policy,
        audit: Arc<Audit>,
    ) -> GhostFs {
        use std::os::unix::fs::MetadataExt;
        let size = views.real.len() as u64;
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let attr = FileAttr {
            ino: INodeNo::ROOT,
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind: FileType::RegularFile,
            // Drop write bits so editors notice before trying.
            perm: (meta.mode() & 0o7555) as u16,
            nlink: 1,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: 0,
            flags: 0,
            blksize: 4096,
        };
        GhostFs {
            mode,
            path,
            views,
            attr,
            policy,
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            audit,
        }
    }

    fn event(&self, kind: &str) -> Event {
        let mut ev = Event::new(kind, &self.path);
        ev.mode = Some(self.mode.as_str().into());
        ev
    }

    /// Resolve the caller and ask the policy. A caller we can't pin gets the
    /// policy's default, never the real view.
    fn evaluate(&self, req: &Request, op: &str) -> (Option<Caller>, Decision) {
        match caller::resolve(req.pid()) {
            Ok(c) => {
                let d = self.policy.decide(&c);
                (Some(c), d)
            }
            Err(e) => {
                let note = match e {
                    ResolveError::Kernel => "no caller pid",
                    ResolveError::Gone => "caller exited before lookup",
                    ResolveError::Raced => "pid changed identity during lookup",
                    ResolveError::Io(_) => "caller lookup failed",
                };
                if !matches!(e, ResolveError::Kernel) {
                    self.audit.record(
                        &self
                            .event("resolve_failed")
                            .note(format!("{op}: {note}: tid {}: {e}", req.pid())),
                    );
                }
                let d = Decision {
                    view: self.policy.decide_unidentified(),
                    rule: "unidentified".into(),
                };
                (None, d)
            }
        }
    }

    fn served(&self, d: &Decision) -> View {
        match self.mode {
            Mode::Watch => View::Real,
            Mode::Guard => d.view,
        }
    }

    fn deny_write(&self, req: &Request, op: &str) {
        let (c, _) = self.evaluate(req, op);
        let mut ev = self.event("write_denied").note(WRITE_HINT);
        ev.op = Some(op.into());
        ev.caller = c;
        self.audit.record(&ev);
    }
}

// Zero TTLs: the kernel must ask us on every lookup and stat. A cached attr
// is harmless today since every view has the same size, but a cached entry
// would let the kernel skip us entirely.
const TTL: Duration = Duration::ZERO;

impl Filesystem for GhostFs {
    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &std::ffi::OsStr, reply: ReplyEntry) {
        // The mount root is the file itself; there is nothing to look up.
        reply.error(Errno::ENOTDIR);
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        let (c, d) = self.evaluate(req, "getattr");
        let mut ev = self.event("access");
        ev.op = Some("getattr".into());
        ev.caller = c;
        ev.decision = Some(d);
        self.audit.record(&ev);
        reply.attr(&TTL, &self.attr);
    }

    fn setattr(
        &self,
        req: &Request,
        _ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        self.deny_write(req, "setattr");
        reply.error(Errno::EROFS);
    }

    fn open(&self, req: &Request, _ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if flags.acc_mode() != OpenAccMode::O_RDONLY || flags.0 & libc::O_TRUNC != 0 {
            self.deny_write(req, "open");
            reply.error(Errno::EROFS);
            return;
        }
        let (c, d) = self.evaluate(req, "open");
        let view = self.served(&d);
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().unwrap().insert(
            fh,
            Handle {
                opener: c.as_ref().map(|c| c.identity),
                view,
            },
        );
        let mut ev = self.event("access");
        ev.op = Some("open".into());
        ev.served = Some(view);
        ev.caller = c;
        ev.decision = Some(d);
        self.audit.record(&ev);
        // Direct I/O keeps reads out of the page cache. Without it the kernel
        // answers the next reader from whatever view the last one pulled in.
        reply.opened(FileHandle(fh), FopenFlags::FOPEN_DIRECT_IO);
    }

    fn read(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let (c, d) = self.evaluate(req, "read");
        let (opener, open_view) = match self.handles.lock().unwrap().get(&fh.0) {
            Some(h) => (h.opener, Some(h.view)),
            None => (None, None),
        };
        // Policy is checked again on every read: the fd may have moved to
        // another process. Serve the stricter of what the opener got and
        // what this reader gets.
        let mut view = self.served(&d);
        if let Some(v) = open_view {
            view = view.max(v);
        }
        let reader = c.as_ref().map(|c| c.identity);
        let passed = opener.is_some() && reader.is_some() && opener != reader;
        if passed {
            let mut ev = self.event("fd_passing");
            ev.op = Some("read".into());
            ev.served = Some(view);
            ev.caller = c.clone();
            ev.opener = opener;
            ev.decision = Some(d.clone());
            self.audit.record(&ev.note("reader is not the process that opened the file"));
        }
        let data = self.views.get(view);
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(size as usize).min(data.len());
        if !passed {
            let mut ev = self.event("access");
            ev.op = Some("read".into());
            ev.served = Some(view);
            ev.caller = c;
            ev.decision = Some(d);
            self.audit.record(&ev);
        }
        reply.data(&data[start..end]);
    }

    fn write(
        &self,
        req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        self.deny_write(req, "write");
        reply.error(Errno::EROFS);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.handles.lock().unwrap().remove(&fh.0);
        reply.ok();
    }
}
