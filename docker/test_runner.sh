#!/usr/bin/env bash
# =============================================================================
# Auto-Privilege — Docker Integration Test Runner (v2.0)
#
# Builds the binary, runs unit tests, then exercises the tool inside the
# docker compose lab (vulnerable / clean / edgecases) and — this is the
# v2.0 part — ASSERTS the results:
#
#   vulnerable: every one of the 10 seeded flaws must be detected
#   clean:      ZERO exploitable findings, score >= 90, no FPs
#   edgecases:  all 8 seeded edge cases must be detected
#   gates:      --fail-on / --min-score behavior verified end-to-end
#
# Usage:  ./docker/test_runner.sh
# Env:     AUTOPRIV_SUBNET  compose subnet override (default 172.28.0.0/16 —
#          auto-bumped to 172.30.0.0/16 when the default is already taken)
# Requires: go, docker compose, docker running, python3
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$PROJECT_DIR/autoprivilege"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_DIR/test-results}"
SUBNET="${AUTOPRIV_SUBNET:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES+1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
FAILURES=0

mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------
# 1. Build + unit tests
# ---------------------------------------------------------------
log "Building binary..."
( cd "$PROJECT_DIR" && go build -o "$BIN" ./cmd/autoprivilege ) || { fail "build"; exit 1; }
pass "binary built: $BIN"

log "Running unit tests..."
if go -C "$PROJECT_DIR" test -count=1 ./... ; then
    pass "unit tests"
else
    fail "unit tests"
fi

# ---------------------------------------------------------------
# 2. Network conflict handling (dj-lab fix): 172.28.0.0/16 collides
#    with pre-existing compose networks — pick a free one.
# ---------------------------------------------------------------
if [ -z "$SUBNET" ]; then
    SUBNET="172.28.0.0/16"
    if docker network ls --format '{{.Name}}' | grep -q . 2>/dev/null; then
        # any existing network already using 172.28.x?
        USED=$(docker network inspect $(docker network ls --format '{{.Name}}') \
               --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null | grep '^172\.28\.' || true)
        if [ -n "$USED" ]; then
            warn "default subnet 172.28.0.0/16 already in use ($USED) — switching to 172.30.0.0/16"
            SUBNET="172.30.0.0/16"
        fi
    fi
fi
export AUTOPRIV_SUBNET="$SUBNET"
log "Lab subnet: $SUBNET"

log "Building docker images (this takes a while the first time)..."
( cd "$SCRIPT_DIR" && docker compose build ) || { fail "docker build"; exit 1; }
pass "images built"

log "Starting lab network..."
( cd "$SCRIPT_DIR" && docker compose up -d ) || { fail "docker up"; exit 1; }
pass "containers up"
sleep 3

# ---------------------------------------------------------------
# Helpers for assertion-based checks
# ---------------------------------------------------------------
scan_json() {  # container -> json on stdout
    docker exec "$1" /usr/local/bin/autoprivilege --json 2>/dev/null
}

count_exploitable() {  # json on stdin -> number of exploitable findings
    python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(-1); raise SystemExit
print(sum(1 for f in d.get("findings", []) if f.get("exploitable")))
'
}

get_score() {  # json on stdin -> score int
    python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
    print(d["summary"]["score"])
except Exception:
    print(-1)
'
}

json_has_target() {  # json-file, source, target-substring
    python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
for f in d.get("findings", []):
    if f.get("source") == sys.argv[2] and sys.argv[3] in f.get("target", ""):
        raise SystemExit(0)
raise SystemExit(1)
' "$1" "$2" "$3"
}

json_has_desc() {  # json-file, description-substring
    python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
for f in d.get("findings", []):
    if sys.argv[2].lower() in f.get("description", "").lower():
        raise SystemExit(0)
raise SystemExit(1)
' "$1" "$2"
}

# ---------------------------------------------------------------
# 3. Vulnerable system — ALL 10 seeded flaws must be detected
# ---------------------------------------------------------------
log "=== vulnerable: scan + assertions (10 seeded flaws) ==="
docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege 2>&1 | tee "$RESULTS_DIR/vulnerable_scan.log"
scan_json autoprivilege-vulnerable > "$RESULTS_DIR/vulnerable.json" || fail "vulnerable json"

# V1: SUID binaries (find, vim, python3, bash are the seeded ones)
for bin in find vim python3 bash; do
    if json_has_target "$RESULTS_DIR/vulnerable.json" SUID "/usr/bin/$bin"; then
        pass "V1: SUID $bin detected"
    else
        fail "V1: SUID $bin NOT detected"
    fi
done
# V2: sudo NOPASSWD find (free rule)
if json_has_target "$RESULTS_DIR/vulnerable.json" SUDO "/usr/bin/find"; then
    pass "V2: NOPASSWD sudo find detected"
else
    fail "V2: NOPASSWD sudo find NOT detected"
fi
# V3: writable cron file + referenced writable script
if json_has_target "$RESULTS_DIR/vulnerable.json" CRON "/etc/cron.d/backup"; then
    pass "V3: writable /etc/cron.d/backup detected"
else
    fail "V3: writable /etc/cron.d/backup NOT detected"
fi
# V4: writable /etc/passwd
if json_has_target "$RESULTS_DIR/vulnerable.json" FILE "/etc/passwd"; then
    pass "V4: writable /etc/passwd detected"
else
    fail "V4: writable /etc/passwd NOT detected"
fi
# V5: readable /etc/shadow
if json_has_target "$RESULTS_DIR/vulnerable.json" FILE "/etc/shadow"; then
    pass "V5: readable /etc/shadow detected"
else
    fail "V5: readable /etc/shadow NOT detected"
fi
# V6: writable PATH dir from /etc/environment (FN-5 fix reads it directly)
if json_has_target "$RESULTS_DIR/vulnerable.json" PATH "/opt/custom/bin"; then
    pass "V6: PATH dir /opt/custom/bin (from /etc/environment) detected"
else
    fail "V6: PATH dir /opt/custom/bin NOT detected"
fi
# V7: writable systemd service
if json_has_target "$RESULTS_DIR/vulnerable.json" SERVICE "vuln.service"; then
    pass "V7: writable systemd service detected"
else
    fail "V7: writable systemd service NOT detected"
fi
# V8: readable SSH private key
if json_has_target "$RESULTS_DIR/vulnerable.json" CRED "id_rsa"; then
    pass "V8: SSH private key detected"
else
    fail "V8: SSH private key NOT detected"
fi
# V9: credentials in /opt/custom (FN-5 fix: custom config sweep)
N9=0
json_has_desc "$RESULTS_DIR/vulnerable.json" "/opt/custom/db.conf" && N9=1
json_has_desc "$RESULTS_DIR/vulnerable.json" "/opt/custom/.env" && N9=$((N9+1))
if [ "$N9" -ge 1 ]; then
    pass "V9: credentials in /opt/custom configs detected ($N9 files)"
else
    fail "V9: /opt/custom credentials NOT detected"
fi
# V10: docker group membership
if json_has_target "$RESULTS_DIR/vulnerable.json" DOCKER "testuser"; then
    pass "V10: docker group membership detected"
else
    fail "V10: docker group membership NOT detected"
fi

# ---------------------------------------------------------------
# 4. Clean system — ZERO exploitable findings, high score
# ---------------------------------------------------------------
log "=== clean: scan + FP assertions ==="
docker exec autoprivilege-clean /usr/local/bin/autoprivilege 2>&1 | tee "$RESULTS_DIR/clean_scan.log"
scan_json autoprivilege-clean > "$RESULTS_DIR/clean.json" || fail "clean json"

CLEAN_EXPLOITABLE=$(count_exploitable < "$RESULTS_DIR/clean.json")
CLEAN_SCORE=$(get_score < "$RESULTS_DIR/clean.json")
if [ "$CLEAN_EXPLOITABLE" = "0" ]; then
    pass "clean: 0 exploitable findings (no false positives)"
else
    fail "clean: $CLEAN_EXPLOITABLE exploitable finding(s) on a clean system (FALSE POSITIVES)"
    python3 -c '
import json
d = json.load(open("'"$RESULTS_DIR"'/clean.json"))
for f in d.get("findings", []):
    if f.get("exploitable"):
        print("  FP:", f.get("source"), f.get("target"), "-", f.get("description", "")[:80])
'
fi
if [ "$CLEAN_SCORE" -ge 90 ]; then
    pass "clean: score $CLEAN_SCORE >= 90"
else
    fail "clean: score $CLEAN_SCORE < 90 (INC-2 regression)"
fi
if grep -q "Writable /etc/passwd" "$RESULTS_DIR/clean_scan.log"; then
    fail "clean: must not report writable /etc/passwd (FP)"
else
    pass "clean: no writable-passwd false positive"
fi

# ---------------------------------------------------------------
# 5. Edge cases — all 8 seeded cases must be handled
# ---------------------------------------------------------------
log "=== edgecases: scan + assertions (8 cases) ==="
docker exec autoprivilege-edgecases /usr/local/bin/autoprivilege 2>&1 | tee "$RESULTS_DIR/edgecases_scan.log"
scan_json autoprivilege-edgecases > "$RESULTS_DIR/edgecases.json" || fail "edgecases json"

# E1: renamed SUID copy of find (FN-2 content-hash detection)
if json_has_desc "$RESULTS_DIR/edgecases.json" "byte-identical copy of find"; then
    pass "E1: renamed SUID custom-find detected (content hash)"
else
    fail "E1: renamed SUID custom-find NOT detected (FN-2 regression)"
fi
# E2: restricted sudo rule — informational, never a free technique (FP-8)
if json_has_desc "$RESULTS_DIR/edgecases.json" "Restricted NOPASSWD sudo"; then
    if json_has_target "$RESULTS_DIR/edgecases.json" SUDO "/usr/bin/tar" && \
       python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
print(sum(1 for f in d["findings"] if f["source"]=="SUDO" and f.get("exploitable")))
' "$RESULTS_DIR/edgecases.json" | grep -q '^0$'; then
        pass "E2: restricted sudo rule reported as informational (FP-8 fixed)"
    else
        fail "E2: restricted sudo rule reported as exploitable (FP-8 regression)"
    fi
else
    fail "E2: restricted sudo rule NOT reported at all"
fi
# E3: cron referencing writable script (FN-3)
if json_has_target "$RESULTS_DIR/edgecases.json" CRON "/opt/scripts/cleanup.sh"; then
    pass "E3: root cron -> writable script detected (FN-3 fixed)"
else
    fail "E3: root cron -> writable script NOT detected (FN-3 regression)"
fi
# E4: SUID bash copy (renamed shell)
if json_has_desc "$RESULTS_DIR/edgecases.json" "byte-identical copy of bash"; then
    pass "E4: SUID root-shell (bash copy) detected (FN-2 fixed)"
else
    fail "E4: SUID root-shell NOT detected (FN-2 regression)"
fi
# E5: file capability cap_setuid (FN-1 tolerant getcap parser)
if json_has_target "$RESULTS_DIR/edgecases.json" CAPS "cap_setuid"; then
    pass "E5: cap_setuid on python3.10 detected (tolerant getcap parser)"
else
    fail "E5: cap_setuid NOT detected (FN-1 regression)"
fi
# E6: NFS rw + no_root_squash
if json_has_target "$RESULTS_DIR/edgecases.json" NFS "/shared"; then
    pass "E6: NFS rw+no_root_squash detected"
else
    fail "E6: NFS rw+no_root_squash NOT detected"
fi
# E7: writable /etc/passwd via 666
if json_has_target "$RESULTS_DIR/edgecases.json" FILE "/etc/passwd"; then
    pass "E7: writable /etc/passwd (666) detected"
else
    fail "E7: writable /etc/passwd NOT detected"
fi
# E8: password in bash history (context-aware matcher)
if json_has_target "$RESULTS_DIR/edgecases.json" CRED ".bash_history"; then
    pass "E8: mysql -p\"...\" in history detected (context-aware matcher)"
else
    fail "E8: password in history NOT detected (FN-5 regression)"
fi

# ---------------------------------------------------------------
# 6. CI gates end-to-end
# ---------------------------------------------------------------
log "=== gates: --fail-on / --min-score end-to-end ==="
docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege --quiet --fail-on high >/dev/null 2>&1
CODE=$?
if [ $CODE -eq 3 ]; then pass "vulnerable --fail-on high trips (exit 3)"; else fail "vulnerable --fail-on high exit=$CODE (want 3)"; fi

docker exec autoprivilege-clean /usr/local/bin/autoprivilege --quiet --fail-on high >/dev/null 2>&1
CODE=$?
if [ $CODE -eq 0 ]; then pass "clean --fail-on high passes (exit 0)"; else fail "clean --fail-on high exit=$CODE (want 0 — FP-driven gate trip)"; fi

docker exec autoprivilege-clean /usr/local/bin/autoprivilege --quiet --min-score 90 >/dev/null 2>&1
CODE=$?
if [ $CODE -eq 0 ]; then pass "clean --min-score 90 passes (exit 0, score $CLEAN_SCORE)"; else fail "clean --min-score 90 exit=$CODE (want 0 — INC-2 regression)"; fi

# ---------------------------------------------------------------
# 7. CLI flags smoke tests
# ---------------------------------------------------------------
log "=== CLI flags ==="
docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege --help > "$RESULTS_DIR/help.log" 2>&1 && pass "--help"
for risk in safe low medium high danger; do
    docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege "--risk=$risk" > /dev/null 2>&1 \
        && pass "--risk=$risk" || fail "--risk=$risk"
done
docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege --quiet > /dev/null 2>&1
CODE=$?
if [ $CODE -eq 0 ] || [ $CODE -eq 1 ]; then pass "--quiet exit code $CODE"; else fail "--quiet exit code $CODE"; fi

# ---------------------------------------------------------------
# 8. Teardown + summary
# ---------------------------------------------------------------
log "Stopping lab..."
( cd "$SCRIPT_DIR" && docker compose down -v )

echo ""
echo "============================================"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}  ALL CHECKS PASSED${NC}"
else
    echo -e "${RED}  $FAILURES CHECK(S) FAILED${NC}"
fi
echo "  Logs saved to: $RESULTS_DIR/"
echo "============================================"
exit "$FAILURES"
