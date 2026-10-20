#!/usr/bin/env bash
# Find out whether this runner can actually mount env-ghost, by doing it.
# Prints available=yes|no for $GITHUB_OUTPUT and never fails the job itself.
set -u

bin=${1:?usage: fuse-probe.sh path/to/env-ghost}
dir=$(mktemp -d /tmp/egp.XXXXXX)
mkdir -p "$dir/state" "$dir/run"
printf 'A=1\n' > "$dir/.env"

ok=no
if [ ! -c /dev/fuse ]; then
    echo "::warning::/dev/fuse is missing on this runner"
else
    env -i PATH="$PATH" XDG_STATE_HOME="$dir/state" XDG_RUNTIME_DIR="$dir/run" \
        "$bin" watch -q "$dir/.env" 2>"$dir/err" &
    pid=$!
    for _ in $(seq 100); do
        if awk -v p="$dir/.env" '$5 == p { f = 1 } END { exit !f }' /proc/self/mountinfo; then
            ok=yes
            break
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.05
    done
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    if [ "$ok" = no ]; then
        echo "::warning::env-ghost could not mount on this runner: $(tr '\n' ' ' < "$dir/err")"
    fi
fi
rm -rf "$dir"
echo "available=$ok"
