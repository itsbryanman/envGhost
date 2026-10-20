# Design

Decisions made for M0 (watch) and M1 (guard), and why. Where a claim is about
kernel behavior, it says whether it was measured, and on which kernel.
Measurements below are from Linux 6.12.101 (Debian 13, x86_64).

## Shape

One binary, `env-ghost`, with subcommands. `watch` and `guard` run the same
daemon; watch serves the real bytes to everyone and logs what guard would
have served.

The daemon reads the target file into memory and mounts a single-file FUSE
filesystem over the file's own path. The mount root is a regular file, so
`stat`, `lseek`, `pread` and concurrent readers behave as they do on any
file. The file on disk is never written. When the mount goes away, for any
reason, the original is what's left at the path.

Modules:

- `caller`: turn a FUSE request into a pinned process identity and lineage.
- `policy`: decide a view from a `Caller` snapshot. No FUSE or filesystem
  state. This is the part meant to move into a separate privileged process
  later, which is why it takes plain data in and returns plain data out.
- `redact`: build the redacted and canary views.
- `fs`: the FUSE filesystem.
- `daemon`: mount lifecycle, signals, watchdog.
- `audit`: JSON lines event log and the readable `log` view.

## FUSE crate: fuser

[fuser](https://github.com/cberner/fuser) 0.18. Reasons:

- Pure Rust implementation of the FUSE protocol; no libfuse at build or run
  time. Unprivileged mounts go through the system's setuid `fusermount3`,
  the same helper libfuse uses.
- Low-level API: we see the request header (uid, gid, pid) and choose open
  flags per open. Both are required here. Path-based wrappers hide them.
- Maintained, widely depended on, MIT licensed.

Considered: `fuse3` (async, tokio; more machinery than one file needs),
`polyfuse` (less active), direct libfuse bindings (C dependency for no gain).

## Kernel caching is off

The kernel normally caches file pages and attributes for FUSE files. With
per-caller views that is a leak: reader B gets the pages reader A pulled in.

- Every open replies with `FOPEN_DIRECT_IO`, so `read()` goes to the daemon
  every time and never touches the page cache.
- Attribute and entry TTLs are zero.
- `FOPEN_KEEP_CACHE` is never set.

Measured: `tests/fuse.rs::two_callers_get_different_views_back_to_back`
holds both readers' files open before either reads, then reads in
alternating order. With `FOPEN_DIRECT_IO` removed, round 0 fails: the
untrusted reader gets the real secret. With it, all rounds pass.

Also measured: a test that only opens and reads sequentially does not catch
this, because FUSE invalidates the page cache on every open when
`FOPEN_KEEP_CACHE` is unset. The leak needs overlapping opens.

All views are the same length, so the single `st_size` the kernel reports is
correct for everyone and says nothing about which view a caller will get.

## mmap

Measured with `tests/harness/src/bin/atk-mmap.rs` on 6.12:

- `MAP_SHARED` on a direct I/O file fails with `ENODEV`. We don't negotiate
  `FUSE_DIRECT_IO_ALLOW_MMAP`.
- `MAP_PRIVATE` succeeds and is served through the page cache, not direct
  I/O. Each new mapping first invalidates cached pages, so a fresh mapping
  faults in the view of whoever faults first.
- The hole: an untrusted process keeps a private mapping open. A trusted
  process then maps the file, which drops the cached pages (and the
  untrusted mapping's pages with them) and faults in the real view. When
  the untrusted process touches its old mapping again, it refaults from the
  page cache and gets the real view. No FUSE read happens for that refault,
  so the daemon never sees it.

The harness records this as BYPASSED. It needs a trusted tool that mmaps the
file while the attacker holds its mapping. Which common tools mmap small
files has not been surveyed. Not fixed in M1.

## Caller identity

FUSE puts the calling thread's ID in the request header, not the process ID.
`/proc/<tid>/status` gives the thread group ID. Decisions use the TGID.

PIDs are recycled, so a PID read at one moment can name a different process
a moment later. Resolution goes:

1. tid to tgid via `/proc/<tid>/status`.
2. `pidfd_open(tgid)`. The pidfd refers to that exact process from here on.
3. Read `/proc/<tgid>/stat` for start time and parent, then exe, cmdline,
   cgroup and the ancestry walk.
4. Read the start time again, poll the pidfd for exit, and check the tid
   still maps to the same tgid. Any mismatch fails resolution.

A caller that can't be resolved gets the policy's default view (never real)
and an event is logged. The identity stored on a file handle is
`{tgid, start_time}`.

Remaining window: between the kernel queuing the request and step 2, the
caller could be killed and its PID reused. The caller is blocked in our
syscall, so this needs a SIGKILL and a PID wrap within that window.

## Untrusted fields

`cmdline` and `comm` are set by the process. They are logged with
`_untrusted` in the field name and quoted in the readable log. The policy
loader rejects any rule that grants `real` using only weak matchers
(`cmdline`, `ancestor_cmdline`, `session_root = "vscode-server"`). Weak
matchers can be used freely to restrict.

`exe` comes from `/proc/<pid>/exe`, which the kernel sets at exec. It says
which binary is running, not what that binary was asked to do. Trusting an
interpreter like `node` by exe trusts every script it runs.

## Policy on open and on every read

`open` resolves the caller, decides a view, and stores the opener identity
and view on the handle. `read` resolves the reader again and decides again.
The served view is the stricter of the two (`real < redacted < canary`). If
the reader is not the opener, the fd was inherited or passed, and an
`fd_passing` event is logged with both identities.

## Lineage

The ancestry walk follows `PPid` from the caller until a session root or
pid 1, at most 64 steps. Each parent must have started no later than its
child; otherwise the real parent exited and the PID was reused, and the walk
stops.

Session roots: `sshd`/`sshd-session`, the tmux server, `systemd --user`, and
vscode-server. These reparent or detach their children on purpose, so
nothing above them tells us about the caller. Reaching pid 1 without a root
is logged as a fact, not a verdict: nohup, setsid, and daemons do it all the
time.

A root only ends the walk if its executable is owned by root and not
group- or world-writable (checked through `/proc/<pid>/exe`). Otherwise a
user could drop a binary named `tmux` in `~/bin` to hide its own parents.
vscode-server always lives in a user-writable path, so it is recorded but
treated as a weak matcher.

`PPid` walking does not survive a double fork. cgroup membership does, so
`cgroup` is a matcher. But systemd delegates `user@UID.service` to the user,
who can move their own processes between cgroups there. A cgroup match
counts toward granting `real` only when the caller's cgroup is not
user-writable (its `cgroup.procs` is root-owned, as session scopes are).

The npm builtin also checks `npm_lifecycle_event` in the caller's initial
environment. That survives a plain double fork but not a deliberate
`env -i`. The harness shows both.

## Crash safety

If a FUSE daemon dies, the mount stays and every access returns `ENOTCONN`.
A separate watchdog process prevents that:

- The daemon starts `env-ghost __watchdog <path>` before mounting, connected
  by a pipe. The watchdog calls `setsid()` so terminal signals aimed at the
  daemon don't reach it, and clears the blocked-signal mask it would
  otherwise inherit.
- The watchdog blocks reading the pipe. On a clean exit the daemon unmounts
  and sends one byte; the watchdog exits. If the pipe closes without that
  byte, the daemon died. The watchdog lazy-unmounts (`umount2(MNT_DETACH)`
  as root, `fusermount3 -u -z` otherwise) and the original file is visible
  again.
- If the watchdog can't start, the daemon refuses to mount.
- If unmount fails during a clean shutdown, the daemon keeps serving instead
  of exiting into a dead mount.

Measured (SIGKILL during a tight read loop): reads in flight when the daemon
dies fail with `ECONNABORTED`; reads that arrive before the detach lands
fail with `ENOTCONN`. The window was about 0.7 ms as root and about 1.1 ms
unprivileged, where the detach goes through `fusermount3`. After that every
read returns the original file. A process that held the file open across
the crash keeps a dead fd.

Why not fusermount3's `auto_unmount`: it requires `allow_other` or
`allow_root`, which need `user_allow_other` in `/etc/fuse.conf` and widen
access to other users. It also gives no hook to log the event.

The watchdog is a same-UID process. Anything running as the user can kill
it, or unmount the file directly with `fusermount3 -u`. Either way the
plaintext underneath is exposed. In M0/M1 the plaintext stays on disk
because there is nowhere safer to keep it yet; see M2.

## Writes

Not supported in M0/M1. Opens for writing, `O_TRUNC`, `write` and `setattr`
return `EROFS` and log a `write_denied` event with a hint. The reported mode
drops write bits so editors warn up front. Editors that save by writing a
temp file and renaming it over the target get `EBUSY` from the kernel,
since a mount point can't be replaced (measured in `writes_fail_cleanly`).

## Redaction

Both views keep the file layout byte for byte except value bytes. Keys,
`=`, quotes, whitespace, `export`, line endings and known token prefixes
(`sk_live_`, `ghp_`, `AKIA` and others) stay. A prefix is kept only if the
value is longer than the prefix.

Dotenv has no single grammar, so the parser masks the union of what
different parsers would treat as values:

- Comment bodies are masked. People comment out old keys.
- Unquoted values run to end of line; docker env files have no inline
  comments.
- Anything after a closing quote is masked.
- A lone CR, or an unparsed line with an unclosed quote, means parsers
  disagree about every following line, so everything after it is masked.

Redacted values become `x` (or `0` for all-digit values). Canary values are
random from an alphabet chosen by the real value's character class, so an
AKIA key stays upper-case alphanumeric.

## Daemon hardening

Daemon and watchdog call `prctl(PR_SET_DUMPABLE, 0)`, which makes their
`/proc/<pid>/mem`, `environ` and ptrace access root-only. The harness shows
the daemon's memory unreadable even with `ptrace_scope=0`. Same-UID code can
still kill the daemon.
