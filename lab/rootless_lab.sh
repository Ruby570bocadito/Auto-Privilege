#!/usr/bin/env bash
# =============================================================================
# Auto-Privilege — Rootless Demo Lab
#
# Runs Auto-Privilege against a FAKE vulnerable system built inside a user
# namespace (unshare -r -m). Nothing here touches your real system:
#   - /etc is bind-mounted from a temp dir with a writable passwd/shadow/cron
#   - /usr/bin is bind-mounted from a temp copy seeded with SUID python3/find
#   - the SUID bits only grant the namespace's mapped root, never yours
#
# Usage:
#   lab/rootless_lab.sh                     # scan + enumerate (read-only)
#   lab/rootless_lab.sh --exploit --risk=medium
#   lab/rootless_lab.sh --json
#   lab/rootless_lab.sh --seeds             # list the staged vulnerabilities
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN=/tmp/autoprivilege

# --seeds: print exactly what the lab stages (the bait list below mirrors the
# cp/chmod lines 1:1) and exit before building anything — the list is also
# linked from the README so the demo's fake vulnerabilities are documented,
# not folklore. Works even on hosts without unshare (pure documentation).
if [ "${1:-}" = "--seeds" ]; then
    cat <<'EOF'
[lab] staged vulnerabilities (all FAKE, inside the namespace only):
  1. /usr/bin seeded with SUID python3 + find          -> GTFOBins shell techniques
  2. /etc/cron.d/backup: writable root cron job        -> cron injection
  3. /etc/passwd: writable copy                        -> root user injection
  4. /etc/shadow: owned copy (readable + writable)     -> root hash extraction
  5. /etc/systemd/system/vuln.service: writable unit   -> systemd hijack
  6. /usr/local/bin/writable: world-writable PATH dir  -> binary planting bait
The SUID bits only grant the namespace's mapped root — never your real user.
EOF
    exit 0
fi

command -v unshare >/dev/null || { echo "unshare not available"; exit 1; }

echo "[lab] building binary..." >&2
( cd "$PROJECT_DIR" && go build -o "$BIN" ./cmd/autoprivilege )

echo "[lab] staging fake vulnerable system..." >&2
STAGE=$(mktemp -d /tmp/ap-lab.XXXXXX)
mkdir -p "$STAGE/etc/cron.d" "$STAGE/etc/systemd/system" "$STAGE/bin" "$STAGE/local"

# /etc seed: real passwd (names resolve), readable shadow, writable cron job.
cp /etc/passwd "$STAGE/etc/passwd" 2>/dev/null || echo "root:x:0:0:root:/root:/bin/bash" > "$STAGE/etc/passwd"
if [ -r /etc/shadow ]; then
    cp /etc/shadow "$STAGE/etc/shadow"
else
    echo 'root:$6$tF1j0uS9$H.Crm5un0QQmAY9ltTkGqlguo2orTktVKsqwB.yLP6AiLkguG.hVGksJL1lGWpy8qDHkrA1j.xrkN65b0whaq.:19000:0:99999:7:::' > "$STAGE/etc/shadow"
fi
printf '* * * * * root /usr/local/bin/backup.sh\n' > "$STAGE/etc/cron.d/backup"
printf '[Unit]\nDescription=Vuln Service\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n' > "$STAGE/etc/systemd/system/vuln.service"

# /usr/bin seed: full copy with SUID on python3 + find (vulnerability 1).
cp -a /usr/bin/. "$STAGE/bin/"
chmod u+s "$STAGE/bin/python3" 2>/dev/null || true
chmod u+s "$STAGE/bin/find" 2>/dev/null || true

# /usr/local/bin seed: world-writable (writable PATH dir).
mkdir -p "$STAGE/local/writable"
chmod 777 "$STAGE/local/writable"

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

# unshare(1) detaches the controlling terminal, so remember the real tty
# path now and reconnect the tool's stdin to it inside the namespace.
TTY_PATH="$(tty)" 2>/dev/null || TTY_PATH=""

echo "[lab] entering user namespace (mapped root, no real privileges)..." >&2
export OUTER_TTY="${TTY_PATH:-/dev/null}"
unshare -r -m bash -s "$BIN" "$@" <<EOF
set -euo pipefail
BIN=\$1; shift

mount --make-rprivate /
mount --bind "$STAGE/etc" /etc
mount --bind "$STAGE/bin" /usr/bin
mount --bind "$STAGE/local" /usr/local/bin

export PATH=/usr/local/bin:/usr/bin:/bin
export USER=root HOME=/root
cd /tmp

# --shell: interactive shell inside the lab (manual technique demos).
# The script comes from a heredoc, so pull the interactive shell's input
# straight from the remembered tty device.
if [ "\${1:-}" = "--shell" ]; then
    export HOME=/tmp
    if [ "$OUTER_TTY" = "/dev/null" ]; then
        echo "[lab] --shell needs a terminal" >&2
        exit 1
    fi
    exec bash --noprofile --norc -i < "$OUTER_TTY"
fi

if [ "$OUTER_TTY" = "/dev/null" ]; then
    exec "\$BIN" "\$@"
fi
exec "\$BIN" "\$@" < "$OUTER_TTY"
EOF
