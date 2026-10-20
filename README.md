# env-ghost

Caller-aware secrets filesystem for Linux.

[![CI](https://img.shields.io/github/actions/workflow/status/itsbryanman/envGhost/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/itsbryanman/envGhost/actions/workflows/ci.yml?query=branch%3Amain)
[![License](https://img.shields.io/github/license/itsbryanman/envGhost?style=flat-square)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue?style=flat-square)](Cargo.toml)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/itsbryanman/envGhost?style=flat-square&label=openssf%20scorecard)](https://securityscorecards.dev/viewer/?uri=github.com/itsbryanman/envGhost)
[![Platform](https://img.shields.io/badge/platform-Linux-informational?style=flat-square)](docs/design.md)
[![FUSE](https://img.shields.io/badge/FUSE-3-informational?style=flat-square)](docs/design.md)
[![Tested kernels](https://img.shields.io/badge/tested%20on-Linux%206.12%20%7C%206.17-informational?style=flat-square)](docs/harness-results.md)
[![Code size](https://img.shields.io/github/languages/code-size/itsbryanman/envGhost?style=flat-square)](https://github.com/itsbryanman/envGhost)
[![Top language](https://img.shields.io/github/languages/top/itsbryanman/envGhost?style=flat-square)](https://github.com/itsbryanman/envGhost)
[![Last commit](https://img.shields.io/github/last-commit/itsbryanman/envGhost?style=flat-square)](https://github.com/itsbryanman/envGhost/commits/main)
[![Commit activity](https://img.shields.io/github/commit-activity/m/itsbryanman/envGhost?style=flat-square)](https://github.com/itsbryanman/envGhost/commits/main)
[![Open issues](https://img.shields.io/github/issues/itsbryanman/envGhost?style=flat-square)](https://github.com/itsbryanman/envGhost/issues)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/itsbryanman/envGhost/pulls)
[![Stars](https://img.shields.io/github/stars/itsbryanman/envGhost?style=flat-square)](https://github.com/itsbryanman/envGhost/stargazers)

![demo](docs/demo.gif)

Status: early. Unprivileged mode only. Expect breakage.

Your `.env` sits in plaintext where every install script and agent can read
it, and the tools that try to fix that hand the secret to whoever asks.

env-ghost mounts FUSE over a single credential file. Every access is tied to
the calling process, and each read gets the real file, a redacted copy with
the same keys, prefixes and byte lengths, or a canary. Package install
scripts and AI agent CLIs get the redacted copy by default. It limits blast
radius and leaves a trail. It does not stop malware, and in this version
anything running as your user can unmount it.

## Build

```sh
cargo build --release
./target/release/env-ghost doctor
```

Needs Linux, cgroup v2, `/dev/fuse` and `fusermount3` (package `fuse3`).

## Watch mode

```sh
env-ghost watch .env      # audit only, everyone gets the real file
env-ghost log -f          # in another terminal
cat .env                  # shows up in the log
```

`env-ghost guard .env` serves views by [policy](docs/policy.md).

## What the log looks like

From the run in the GIF. `cat` is trusted by the policy; the second `cat`
runs under a stub `npm install` (shown as `dash`, its real exe) and hits the
install rule.

```
13:42:58.104 start            (mode guard, pid 3723593) /tmp/egdemo/.env
13:42:59.891 open    real     3723673 /usr/bin/cat "cat .env" < bash:3723583 < tmux:3723582 [tmux] rule=cat /tmp/egdemo/.env
13:42:59.892 getattr -        3723673 /usr/bin/cat "cat .env" < bash:3723583 < tmux:3723582 [tmux] rule=cat /tmp/egdemo/.env
13:42:59.892 read    real     3723673 /usr/bin/cat "cat .env" < bash:3723583 < tmux:3723582 [tmux] rule=cat /tmp/egdemo/.env
13:42:59.892 read    real     3723673 /usr/bin/cat "cat .env" < bash:3723583 < tmux:3723582 [tmux] rule=cat /tmp/egdemo/.env
13:43:03.994 open    redacted 3723699 /usr/bin/cat "cat .env" < dash:3723698 < bash:3723583 < tmux:3723582 [tmux] rule=builtin:package-install /tmp/egdemo/.env
13:43:03.994 getattr -        3723699 /usr/bin/cat "cat .env" < dash:3723698 < bash:3723583 < tmux:3723582 [tmux] rule=builtin:package-install /tmp/egdemo/.env
13:43:03.994 read    redacted 3723699 /usr/bin/cat "cat .env" < dash:3723698 < bash:3723583 < tmux:3723582 [tmux] rule=builtin:package-install /tmp/egdemo/.env
13:43:03.994 read    redacted 3723699 /usr/bin/cat "cat .env" < dash:3723698 < bash:3723583 < tmux:3723582 [tmux] rule=builtin:package-install /tmp/egdemo/.env
13:43:06.806 stop             (signal 15) /tmp/egdemo/.env
```

`env-ghost log --json` gives the same events with full caller detail.

## Compared to

| | Per-caller views | Real file semantics | Secrets in `/proc/<pid>/environ` |
|---|---|---|---|
| Plaintext `.env` | no | yes | only if the app passes them to children |
| [1Password local `.env`](https://www.1password.dev/environments/local-env-file) | no, any process can read it once unlocked | no, it's a named pipe; concurrent readers may fail | no |
| [`op run`](https://www.1password.dev/cli/secrets-environment-variables) / [`doppler run`](https://docs.doppler.com/docs/cli) | no | no file, env vars only | yes |
| env-ghost | yes | yes, read-only | no |

## Harness results

Last run: Debian 13, kernel 6.12, unprivileged, ptrace_scope=0. Full notes
in [docs/harness-results.md](docs/harness-results.md).

| Attack | Result | Note |
|---|---|---|
| npm postinstall double-forks, then reads | HELD | npm_lifecycle_event survives the double fork |
| npm postinstall double-forks, clears its environment, then reads | BYPASSED | no lineage or env left to mark it as an install; cgroup rule trusts it |
| trusted process opens the file and passes the fd over SCM_RIGHTS | HELD | reader is checked again; gets redacted, event logged |
| forge argv[0] and comm as node, npm, and the trusted helper | HELD | argv and comm don't grant access; exe does |
| run the trusted executable itself and have it print the file | BYPASSED | trusting an exe trusts whatever it's told to do |
| keep a MAP_PRIVATE mapping while a trusted process maps the file | BYPASSED | private mapping refaults from page cache a trusted mmap filled; never reaches env-ghost |
| read /proc/&lt;pid>/mem of the env-ghost daemon | HELD | daemon is non-dumpable |
| read /proc/&lt;pid>/mem of a trusted process that read the file | BYPASSED | same-UID memory read works at ptrace_scope=0 |
| read /proc/&lt;pid>/environ of a child the trusted process launched with the secret | BYPASSED | environ is readable by any same-UID process |
| SIGKILL the daemon during a read loop, keep reading | BYPASSED | watchdog detaches the dead mount; plaintext underneath |
| fusermount3 -u as the same user, then read | BYPASSED | same user can unmount; plaintext underneath |

## More

- [Threat model](docs/threat-model.md)
- [Design](docs/design.md)

## License

Apache-2.0
