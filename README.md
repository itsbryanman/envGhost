# env-ghost

Caller-aware secrets filesystem for Linux.

[![CI](https://github.com/itsbryanman/env-ghost/actions/workflows/ci.yml/badge.svg)](https://github.com/itsbryanman/env-ghost/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/itsbryanman/env-ghost)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](Cargo.toml)
[![Release](https://img.shields.io/github/v/release/itsbryanman/env-ghost)](https://github.com/itsbryanman/env-ghost/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/itsbryanman/env-ghost/badge)](https://securityscorecards.dev/viewer/?uri=github.com/itsbryanman/env-ghost)
[![Platform](https://img.shields.io/badge/platform-Linux-informational)](docs/design.md)
[![FUSE](https://img.shields.io/badge/FUSE-3-informational)](docs/design.md)
[![Kernel](https://img.shields.io/badge/kernel-5.3%2B-informational)](docs/design.md)
[![Code size](https://img.shields.io/github/languages/code-size/itsbryanman/env-ghost)](https://github.com/itsbryanman/env-ghost)
[![Top language](https://img.shields.io/github/languages/top/itsbryanman/env-ghost)](https://github.com/itsbryanman/env-ghost)
[![Last commit](https://img.shields.io/github/last-commit/itsbryanman/env-ghost)](https://github.com/itsbryanman/env-ghost/commits/main)
[![Commit activity](https://img.shields.io/github/commit-activity/m/itsbryanman/env-ghost)](https://github.com/itsbryanman/env-ghost/commits/main)
[![Open issues](https://img.shields.io/github/issues/itsbryanman/env-ghost)](https://github.com/itsbryanman/env-ghost/issues)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/itsbryanman/env-ghost/pulls)
[![Stars](https://img.shields.io/github/stars/itsbryanman/env-ghost)](https://github.com/itsbryanman/env-ghost/stargazers)

env-ghost mounts FUSE over a single credential file, starting with `.env`.
Every access is tied to the calling process, and each read gets the real
file, a redacted copy with the same keys, prefixes and byte lengths, or a
canary. Package install scripts and AI agent CLIs get the redacted copy by
default. It limits blast radius and leaves a trail. It does not stop
malware, and in this version anything running as your user can unmount it.

![demo](docs/demo.gif)

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

## More

- [Threat model](docs/threat-model.md)
- [Harness results](docs/harness-results.md)
- [Design](docs/design.md)

## License

Apache-2.0
