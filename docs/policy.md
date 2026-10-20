# Policy file

Default location: `$XDG_CONFIG_HOME/env-ghost/policy.toml`, falling back to
`~/.config/env-ghost/policy.toml`. Override with `--policy`. With no file,
the builtin rules apply and everyone else gets the redacted view.

```toml
[defaults]
unknown = "redacted"          # or "canary"; "real" is refused
disable_builtin = []          # "package-install", "ai-agent"

[[rule]]
name = "dev server"
view = "real"
exe = "/usr/bin/node"
cgroup = "/user.slice/user-1000.slice/session-*.scope"

[[rule]]
name = "anything that looks like curl"
view = "canary"
cmdline = "*curl*"
```

Rules are checked in order and the first match wins. Every matcher in a rule
must match. Patterns are shell globs; `*` also matches `/`.

| Matcher | Checks | Strength |
|---|---|---|
| `exe` | `/proc/<pid>/exe` of the caller | strong |
| `ancestor_exe` | exe of any process in the ancestry | strong |
| `cgroup` | caller's cgroup v2 path | strong only if the cgroup is root-owned |
| `session_root` | `sshd`, `tmux`, `systemd-user`, `vscode-server` | strong, except `vscode-server` |
| `cmdline` | caller's argv joined by spaces | weak |
| `ancestor_cmdline` | argv of any ancestor | weak |

A rule with `view = "real"` must include a strong matcher, and at match time
at least one strong matcher has to be one the caller couldn't arrange. A
cgroup under `user@UID.service` doesn't count, since the user can move
processes into it.

Builtin rules run after yours and can only make a view stricter. They match
package installs (npm, pnpm, yarn, bun, npx, pip, uv, poetry, pipx, cargo
build scripts, rustc) and AI agent CLIs (by exe or argv name, and by
environment markers such as `CLAUDECODE`). They use argv and environment,
which the caller controls, so they catch the ordinary case and nothing
deliberate.

`env-ghost explain <pid>` shows how a running process is identified and
which rule it hits.
