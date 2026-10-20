# Threat model

env-ghost limits how far a credential file spreads and trips a wire when
something reads it. It is not malware-proof. This page covers M0/M1, which
run unprivileged as the user.

## Who it is for

Code that runs as you but that you didn't really mean to hand your secrets
to: package install scripts, AI coding agents, and tools that read every
file in a project directory.

## What it stops

These get the redacted view instead of the real file, provided the policy
doesn't trust them:

- Callers matched by the builtin rules: npm, pnpm, yarn, bun and npx
  installs and their lifecycle scripts, pip and uv installs, cargo build
  scripts and rustc (proc macros), and known AI agent CLIs.
- Any caller no rule names. Unknown callers get redacted by default.
- A process that receives an fd from a trusted one: reads are checked again
  per reader, and the stricter view wins.
- A process that forges its argv or comm to look like a trusted program.
  Rules that grant the real file must match on something the caller can't
  set itself.
- Reading the env-ghost daemon's memory through `/proc/<pid>/mem`. The
  daemon is non-dumpable.

## What it detects

Every getattr, open and read is logged with the caller's TGID, start time,
exe, cmdline (marked untrusted), cgroup and ancestry. Also logged: fd
passing between processes, write attempts, callers that couldn't be
identified, and an unmount env-ghost didn't start.

## What it doesn't touch

- **The plaintext on disk.** In M0/M1 the real file stays where it was,
  under the mount. Any process running as you can unmount it with
  `fusermount3 -u`, or kill the daemon, and read the file. The harness
  records both as bypassed.
- **Other paths to the same file.** The mount covers one path. Hard links
  (env-ghost warns at start when there are any), bind mounts made earlier,
  and other mount namespaces reach the inode directly.
- **Same-UID attackers in general.** Without a privileged daemon, anything
  running as you can also kill env-ghost, edit its policy, or read the
  memory of trusted processes when `ptrace_scope` is 0.
- **Code running inside an authorized process.** If you trust `node` by
  exe, every script node runs is trusted. A trusted binary can be run
  directly and told to print the file.
- **Child environment inheritance.** Once a trusted process puts secrets in
  a child's environment, any same-UID process can read
  `/proc/<pid>/environ`. Yama does not restrict that.
- **Deliberate lineage evasion.** A payload that double-forks and clears its
  environment loses the signals the install rules rely on. Whether that
  gets it the real file depends on what else your policy trusts.
- **Shared page cache through mmap.** A process holding a private mapping
  can pick up pages a trusted process faulted in. See design.md.
- **Raw private key files** such as `~/.ssh/id_ed25519`. Not handled.
- **Other users and root.** The mount is only accessible to the mounting
  user. Root can read the file underneath at any time.

## Assumptions

- Linux with cgroup v2 and a setuid `fusermount3`, or root.
- The policy file and the env-ghost binary are not writable by the code
  you're defending against. Same-UID code can write both today.
