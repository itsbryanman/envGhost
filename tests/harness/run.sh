#!/usr/bin/env bash
# Run every attack against a live env-ghost and collect RESULT lines.
#
#   tests/harness/run.sh [results.tsv]
#
# Runs unprivileged. If started as root it drops to $HARNESS_USER (default
# nobody) for the daemon and the attacks, since root bypasses most of what
# is being tested.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
out=${1:-$root/target/harness-results.tsv}

cargo build --quiet --release --workspace --manifest-path "$root/Cargo.toml"
bin=$root/target/release

work=$(mktemp -d /tmp/egh.XXXXXX)
chmod 755 "$work"
mkdir -p "$work/state" "$work/cfg"

run_as=()
if [ "$(id -u)" = 0 ]; then
    user=${HARNESS_USER:-nobody}
    run_as=(setpriv --reuid="$user" --regid="$(id -g "$user")" --clear-groups)
fi

# Clean environment for everything we launch: inherited agent or npm
# variables would change which builtin rules fire. Kept as an array rather
# than a function so a backgrounded command's $! is the real pid.
as_user=("${run_as[@]}" env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$work"
    XDG_STATE_HOME="$work/state" XDG_CONFIG_HOME="$work/cfg")
as_user() { "${as_user[@]}" "$@"; }

secret="sk_test_$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
file=$work/.env
original="# harness
STRIPE_KEY=$secret
PORT=5432
"

# Written as the test user. When the harness runs as root, the work dir
# belongs to that user, and root writing into it could be redirected.
reset_file() {
    as_user sh -c 'printf "%s" "$1" > "$2"' _ "$original" "$file"
}

cgroup=$(as_user cat /proc/self/cgroup | sed -n 's/^0:://p')

# The ai-agent builtin is off so results don't depend on whether the harness
# was started from inside an agent session. package-install stays on.
base_policy="[defaults]
disable_builtin = [\"ai-agent\"]

[[rule]]
name = \"trusted helper\"
view = \"real\"
exe = \"$bin/eg-trusted\"

[[rule]]
name = \"node\"
view = \"real\"
exe = \"/usr/bin/node\"
"
cgroup_policy="$base_policy
[[rule]]
name = \"whole session\"
view = \"real\"
cgroup = \"$cgroup\"
"
printf '%s' "$base_policy" > "$work/base.toml"
printf '%s' "$cgroup_policy" > "$work/cgroup.toml"
# Root-written files exist before the directory changes hands.
[ ${#run_as[@]} -eq 0 ] || chown -R "$user" "$work"

: > "$out.raw"

mounted() {
    awk -v p="$file" '$5 == p && / env-ghost / { found = 1 } END { exit !found }' /proc/self/mountinfo
}

daemon_pid=
start_daemon() {
    reset_file
    "${as_user[@]}" "$bin/env-ghost" guard -q --policy "$1" "$file" 2>>"$work/daemon.log" &
    daemon_pid=$!
    for _ in $(seq 100); do
        mounted && return 0
        sleep 0.05
    done
    echo "daemon did not mount; see $work/daemon.log" >&2
    exit 1
}

stop_daemon() {
    if kill -0 "$daemon_pid" 2>/dev/null; then
        kill -TERM "$daemon_pid"
        wait "$daemon_pid" || true
    fi
    if mounted; then
        echo "still mounted after stop" >&2
        exit 1
    fi
    # env-ghost never writes to the file; whatever happened, it must be
    # exactly what we put there.
    if [ "$(cat "$file")" != "$(printf '%s' "$original")" ]; then
        echo "file changed under the mount" >&2
        exit 1
    fi
}

attack() {
    as_user "$@" | grep '^RESULT' >> "$out.raw" || true
}

# Double-fork only matters against a policy that would otherwise trust the
# payload, so this round trusts the whole session cgroup.
start_daemon "$work/cgroup.toml"
pnote="EG_POLICY_NOTE=policy trusts the session cgroup; "
attack "$pnote" "$bin/atk-double-fork" "$file" "$secret" env-intact
attack "$pnote" "$bin/atk-double-fork" "$file" "$secret" env-scrubbed
stop_daemon

start_daemon "$work/base.toml"
attack "$bin/atk-fd-pass" "$file" "$secret" "$bin/eg-trusted" "$work/state/env-ghost/events.jsonl" "$work"
attack "$bin/atk-spoof" "$file" "$secret" "$bin/eg-trusted"
attack "$bin/atk-mmap" "$file" "$secret" "$bin/eg-trusted"

# A trusted process that read the real file and passed it to a child's env.
holder_out=$work/holder.out
"${as_user[@]}" "$bin/eg-trusted" hold "$file" > "$holder_out" &
holder=$!
for _ in $(seq 100); do [ -s "$holder_out" ] && break; sleep 0.05; done
read -r holder_pid child_pid < "$holder_out"
attack "$bin/atk-proc-peek" "$secret" "$daemon_pid" "$holder_pid" "$child_pid"
kill "$holder_pid" "$child_pid" 2>/dev/null || true
wait "$holder" 2>/dev/null || true

attack "$bin/atk-kill-daemon" "$file" "$secret" "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
stop_daemon

start_daemon "$work/base.toml"
attack "$bin/atk-unmount" "$file" "$secret"
wait "$daemon_pid" 2>/dev/null || true
stop_daemon

{
    printf 'kernel\t%s\n' "$(uname -r)"
    printf 'ptrace_scope\t%s\n' "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)"
    printf 'user\t%s\n' "$(as_user id -un)"
    printf 'mode\tunprivileged\n'
    printf 'commit\t%s\n' "$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    printf 'date\t%s\n' "$(date -u +%Y-%m-%d)"
    cat "$out.raw"
} > "$out"
rm -f "$out.raw"
rm -rf "$work"
echo "$out"
