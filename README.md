# env-ghost

Caller-aware secrets filesystem for Linux.

[![CI](https://github.com/itsbryanman/envGhost/actions/workflows/ci.yml/badge.svg)](https://github.com/itsbryanman/envGhost/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/itsbryanman/envGhost)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](Cargo.toml)
[![Release](https://img.shields.io/github/v/release/itsbryanman/envGhost)](https://github.com/itsbryanman/envGhost/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/itsbryanman/envGhost/badge)](https://securityscorecards.dev/viewer/?uri=github.com/itsbryanman/envGhost)
[![Platform](https://img.shields.io/badge/platform-Linux-informational)](docs/design.md)
[![FUSE](https://img.shields.io/badge/FUSE-3-informational)](docs/design.md)
[![Tested kernel](https://img.shields.io/badge/tested%20on-Linux%206.12-informational)](docs/harness-results.md)
[![Code size](https://img.shields.io/github/languages/code-size/itsbryanman/envGhost)](https://github.com/itsbryanman/envGhost)
[![Top language](https://img.shields.io/github/languages/top/itsbryanman/envGhost)](https://github.com/itsbryanman/envGhost)
[![Last commit](https://img.shields.io/github/last-commit/itsbryanman/envGhost)](https://github.com/itsbryanman/envGhost/commits/main)
[![Commit activity](https://img.shields.io/github/commit-activity/m/itsbryanman/envGhost)](https://github.com/itsbryanman/envGhost/commits/main)
[![Open issues](https://img.shields.io/github/issues/itsbryanman/envGhost)](https://github.com/itsbryanman/envGhost/issues)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/itsbryanman/envGhost/pulls)
[![Stars](https://img.shields.io/github/stars/itsbryanman/envGhost)](https://github.com/itsbryanman/envGhost/stargazers)

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
