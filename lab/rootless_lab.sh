#!/usr/bin/env bash
# =============================================================================
# Auto-Privilege — Rootless Demo Lab (v2.0)
#
# Runs Auto-Privilege as an UNPRIVILEGED user against a fake vulnerable
# system built inside nested user namespaces. Nothing here touches your
# real system:
#
#   level 1: unshare -r -m        → mapped root + private mount namespace:
#                                    /etc, /usr/bin, /usr/local/bin, /opt and
#                                    /home/labuser are bind-mounted from a
#                                    temp stage seeded with vulnerabilities
#   level 2: unshare -U + uid_map → the scanner runs as uid 1000 (the lab
#                                    user), the honest privesc perspective —
#                                    v2.0's root guards (audit FP-1) mean a
#                                    mapped-root run would correctly see
#                                    nothing, so the lab drops privileges
#                                    before scanning
#
# All seeded SUID/caps bits only grant the namespace's mapped ids — never
# your real user, never the real host.
#
# Usage:
#   lab/rootless_lab.sh                     # scan + enumerate (read-only)
#   lab/rootless_lab.sh --json              # machine-readable
#   lab/rootless_lab.sh --min-risk low      # show informational leads too
#   lab/rootless_lab.sh --exploit --risk=medium
#   lab/rootless_lab.sh --seeds             # list the staged vulnerabilities
#   lab/rootless_lab.sh --shell             # interactive shell inside the lab
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN=/tmp/autoprivilege

# --seeds: print exactly what the lab stages (the bait list below mirrors
# the staging code 1:1) and exit before building anything — the list is also
# linked from the README so the demo's fake vulnerabilities are documented,
# not folklore. Works even on hosts without unshare (pure documentation).
if [ "${1:-}" = "--seeds" ]; then
    cat <<'EOF'
[lab] staged vulnerabilities (all FAKE, inside the namespace only):
  1. /etc/passwd 0666 (writable)                     → inject a root user
  2. /etc/shadow 0644 (readable)                     → crack the root hash
  3. /etc/cron.d/backup 0666 (writable root cron)    → cron injection
  4. /etc/cron.d/cleanup (locked) → /opt/scripts/cleanup.sh 0777
                                                     → root cron references
                                                       a user-writable script
  5. /etc/systemd/system/vuln.service 0666           → systemd hijack
  6. /etc/environment puts /tmp (world-writable, foreign owner) on PATH
                                                     → binary planting
  7. /etc/exports: /shared *(rw,no_root_squash)      → NFS root takeover
  8. /opt/custom/db.conf + .env with live-looking credentials
                                                     → readable secrets
  9. /home/labuser/.bash_history: mysql -p"..."      → password in history
 10. /home/labuser/.ssh/id_rsa 0644                  → private key exposure
 11. /usr/bin/python3.10 with file cap_setuid        → in-process setuid(0)
EOF
    exit 0
fi

command -v unshare >/dev/null || { echo "unshare not available"; exit 1; }

echo "[lab] building binary..." >&2
( cd "$PROJECT_DIR" && go build -o "$BIN" ./cmd/autoprivilege )

echo "[lab] staging fake vulnerable system..." >&2
STAGE=$(mktemp -d /tmp/ap-lab.XXXXXX)
mkdir -p "$STAGE/etc/cron.d" "$STAGE/etc/systemd/system" \
         "$STAGE/opt/scripts" "$STAGE/opt/custom" \
         "$STAGE/local/writable" "$STAGE/home/labuser/.ssh" \
         "$STAGE/bin"

# --- /etc seed: resolvable names, writable passwd, readable shadow --------
cp /etc/passwd "$STAGE/etc/passwd" 2>/dev/null || echo "root:x:0:0:root:/root:/bin/bash" > "$STAGE/etc/passwd"
# one uid, one name: drop any real account squatting on uid 1000 so the lab
# user resolves cleanly inside the namespace.
sed -i '/^[^:]*:[^:]*:1000:/d' "$STAGE/etc/passwd"
echo 'labuser:x:1000:1000:Lab User:/tmp/labhome:/bin/bash' >> "$STAGE/etc/passwd"
chmod 666 "$STAGE/etc/passwd"                                    # seed 1
if [ -r /etc/shadow ]; then
    cp /etc/shadow "$STAGE/etc/shadow"
else
    echo 'root:$6$tF1j0uS9$H.Crm5un0QQmAY9ltTkGqlguo2orTktVKsqwB.yLP6AiLkguG.hVGksJL1lGWpy8qDHkrA1j.xrkN65b0whaq.:19000:0:99999:7:::' > "$STAGE/etc/shadow"
fi
chmod 644 "$STAGE/etc/shadow"                                    # seed 2

# --- cron seed: writable schedule + locked schedule with writable payload -
printf '* * * * * root /usr/local/bin/backup.sh\n' > "$STAGE/etc/cron.d/backup"
chmod 666 "$STAGE/etc/cron.d/backup"                             # seed 3
printf '* * * * * root /opt/scripts/cleanup.sh >/dev/null 2>&1\n' > "$STAGE/etc/cron.d/cleanup"
chmod 444 "$STAGE/etc/cron.d/cleanup"
printf '#!/bin/bash\necho cleanup\n' > "$STAGE/opt/scripts/cleanup.sh"
chmod 777 "$STAGE/opt/scripts/cleanup.sh"                        # seed 4

# --- systemd seed ----------------------------------------------------------
printf '[Unit]\nDescription=Vuln Service\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n' > "$STAGE/etc/systemd/system/vuln.service"
chmod 666 "$STAGE/etc/systemd/system/vuln.service"               # seed 5

# --- PATH seed: writable dir reachable through /etc/environment (FN-5) ----
chmod 777 "$STAGE/local/writable"
# /tmp on PATH is the classic planting bait: world-writable, sticky, owned
# by a uid the lab user is not (real root reads as unmapped inside the ns).
printf 'PATH="/tmp:/usr/local/bin:/usr/bin:/bin"\n' > "$STAGE/etc/environment"  # seed 6

# --- NFS seed --------------------------------------------------------------
printf '/shared *(rw,no_root_squash)\n' > "$STAGE/etc/exports"   # seed 7

# --- credential seeds ------------------------------------------------------
printf 'DB_HOST=db.internal\nDB_PASSWORD=SuperSecret123!\n' > "$STAGE/opt/custom/db.conf"
printf 'API_KEY=sk-1234567890abcdef\nJWT_SECRET=prod-jwt-not-a-drill\n' > "$STAGE/opt/custom/.env"
chmod 644 "$STAGE/opt/custom/db.conf" "$STAGE/opt/custom/.env"   # seed 8
printf 'mysql -u root -p"RootPass123!"\nssh deploy@10.0.0.5\n' > "$STAGE/home/labuser/.bash_history"  # seed 9
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBmYWtlbGFiIGtleSBub3QgYSByZWFsIHNlY3JldC4uLi4K\n-----END OPENSSH PRIVATE KEY-----\n' > "$STAGE/home/labuser/.ssh/id_rsa"
chmod 644 "$STAGE/home/labuser/.ssh/id_rsa"                      # seed 10
chown -R "$(id -u):$(id -g)" "$STAGE/home" 2>/dev/null || true

# --- /usr/bin seed: clean copy + file capability (seed 11) -----------------
cp -a /usr/bin/. "$STAGE/bin/" 2>/dev/null || true
# (the file capability is granted inside the namespace below — setcap as
# the real unprivileged user would silently fail)

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

echo "[lab] entering user namespace (mounts as mapped root, scan drops to uid 1000)..." >&2

unshare -r -m bash -s "$STAGE" "$BIN" "$@" <<'OUTER'
set -euo pipefail
STAGE="$1"; BIN="$2"; shift 2

mount --make-rprivate /
mount --bind "$STAGE/etc" /etc
mount --bind "$STAGE/bin" /usr/bin
mount --bind "$STAGE/local" /usr/local/bin
mount --bind "$STAGE/opt" /opt
mkdir -p /tmp/labhome
mount --bind "$STAGE/home/labuser" /tmp/labhome

# seed 11: file capability on a staged interpreter — needs CAP_SETFCAP, so
# it runs here, as the namespace's mapped root.
SETCAP=$(command -v setcap || echo /usr/sbin/setcap)
if [ -x "$SETCAP" ]; then
    for c in python3.13 python3.12 python3.11 python3.10 python3 perl perl5 node; do
        if [ -e "/usr/bin/$c" ]; then
            "$SETCAP" cap_setuid+ep "/usr/bin/$c" 2>/dev/null || true
            break
        fi
    done
fi

F=$(mktemp -u /tmp/aplab.XXXXXX)

# The child script: fresh user namespace, wait for the parent to install
# our identity, then drop to the unprivileged lab user (uid 1000) and run
# the tool (or an interactive shell with --shell). F and BIN are baked in
# at write time; "$@" carries the tool arguments through untouched.
INNER=$(mktemp /tmp/apinner.XXXXXX)
cat > "$INNER" <<EOF
#!/usr/bin/env bash
F="$F"
BIN="$BIN"
echo \$\$ > "\$F.pid"
for i in \$(seq 400); do [ -e "\$F.go" ] && break; sleep 0.05; done
if [ "\${1:-}" = "--shell" ]; then
  exec setpriv --reuid=1000 --regid=1000 --keep-groups \
    env HOME=/tmp/labhome USER=labuser LOGNAME=labuser \
    PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin SHELL=/bin/bash \
    bash --noprofile --norc -i
fi
exec setpriv --reuid=1000 --regid=1000 --keep-groups \
  env HOME=/tmp/labhome USER=labuser LOGNAME=labuser \
  PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin \
  "\$BIN" "\$@"
EOF
chmod +x "$INNER"

unshare -U bash "$INNER" "$@" &
CHILD=$!
for i in $(seq 200); do [ -f "$F.pid" ] && break; sleep 0.05; done
CH=$(cat "$F.pid" 2>/dev/null || { echo "[lab] sync failed" >&2; exit 1; })
# The privileged side installs the lab user's identity in the child
# namespace — the newuidmap pattern, without needing the setuid helper.
echo deny > "/proc/$CH/setgroups" 2>/dev/null || true
echo "1000 0 1" > "/proc/$CH/uid_map"
echo "1000 0 1" > "/proc/$CH/gid_map"
touch "$F.go"
# wait on the PID explicitly: a bare `wait` swallows the child's exit code,
# and the lab must propagate the tool's gate exits (0/1/3) faithfully.
wait "$CHILD"
rc=$?
rm -f "$F.pid" "$F.go" "$INNER"
exit $rc
OUTER
