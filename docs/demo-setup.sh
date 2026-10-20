#!/bin/sh
# Builds the scratch directory docs/demo.tape records in. Secret values are fake.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
d=/tmp/egdemo
cargo build --quiet --release --manifest-path "$root/Cargo.toml"
rm -rf "$d"
mkdir -p "$d/bin" "$d/state" "$d/cfg/env-ghost"
cat > "$d/.env" <<'EOF'
STRIPE_KEY=sk_test_FAKE4eC39HqLyjWDarjtT1
GITHUB_TOKEN=ghp_FAKEFAKEFAKE0000000
DATABASE_URL=postgres://app:hunter2@db:5432/app
EOF
cat > "$d/cfg/env-ghost/policy.toml" <<'EOF'
[[rule]]
name = "cat"
view = "real"
exe = "/usr/bin/cat"
EOF
cat > "$d/bin/npm" <<'EOF'
#!/bin/sh
# stand-in for npm: runs a "postinstall" that reads .env
cat .env
EOF
chmod +x "$d/bin/npm"
cat > "$d/tmux.conf" <<'EOF'
set -g status off
set -g default-command "env PS1='$ ' bash --norc --noprofile"
set -g pane-border-style fg=colour240
set -g pane-active-border-style fg=colour240
EOF
# tmux daemonizes, so the shells it starts have no link back to whatever
# launched vhs, and env -i keeps agent variables out.
cat > "$d/start.sh" <<EOF
#!/bin/sh
cd $d
exec env -i HOME=$d TERM=xterm-256color PS1='\$ ' \\
  PATH=$d/bin:$root/target/release:/usr/bin:/bin \\
  XDG_STATE_HOME=$d/state XDG_CONFIG_HOME=$d/cfg \\
  tmux -L egdemo -f $d/tmux.conf new-session \; \\
  split-window -v -b -l 40% "printf '\\\$ env-ghost log -f | grep open\\n'; env-ghost log -f -n 0 | grep --line-buffered ' open '" \; \\
  select-pane -D
EOF
chmod +x "$d/start.sh"
