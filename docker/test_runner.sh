#!/usr/bin/env bash
# =============================================================================
# Auto-Privilege — Docker Test Runner
#
# Builds the binary, runs unit tests, then exercises the tool inside the
# docker compose lab (vulnerable / clean / edgecases) and checks CLI flags.
#
# Usage:  ./docker/test_runner.sh
# Requires: go, docker compose, docker running
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$PROJECT_DIR/autoprivilege"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_DIR/test-results}"

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
# 2. Build the lab images
# ---------------------------------------------------------------
log "Building docker images (this takes a while the first time)..."
( cd "$SCRIPT_DIR" && docker compose build ) || { fail "docker build"; exit 1; }
pass "images built"

log "Starting lab network..."
( cd "$SCRIPT_DIR" && docker compose up -d ) || { fail "docker up"; exit 1; }
pass "containers up"
sleep 3

# ---------------------------------------------------------------
# 3. Vulnerable system
# ---------------------------------------------------------------
log "=== vulnerable: scan ==="
if docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege 2>&1 | tee "$RESULTS_DIR/vulnerable_scan.log"; then
    pass "scan ran"
else
    fail "scan"
fi

log "=== vulnerable: suid vector ==="
docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege --vector=suid 2>&1 | tee "$RESULTS_DIR/vulnerable_suid.log"

log "=== vulnerable: json output is valid JSON ==="
if docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege --json 2>/dev/null | python3 -m json.tool > "$RESULTS_DIR/vulnerable.json"; then
    pass "json valid"
else
    fail "json invalid"
fi

log "=== vulnerable: dry-run plan ==="
docker exec autoprivilege-vulnerable /usr/local/bin/autoprivilege --exploit --dry-run --risk=danger 2>&1 | tee "$RESULTS_DIR/vulnerable_dryrun.log"

# ---------------------------------------------------------------
# 4. Clean system — must NOT find exploitable passwd/shadow issues
# ---------------------------------------------------------------
log "=== clean: scan ==="
docker exec autoprivilege-clean /usr/local/bin/autoprivilege 2>&1 | tee "$RESULTS_DIR/clean_scan.log"
if grep -q "Writable /etc/passwd" "$RESULTS_DIR/clean_scan.log"; then
    fail "clean system must not report writable /etc/passwd (false positive)"
else
    pass "no passwd false positive on clean system"
fi

# ---------------------------------------------------------------
# 5. Edge cases
# ---------------------------------------------------------------
log "=== edgecases: scan + per-vector runs ==="
docker exec autoprivilege-edgecases /usr/local/bin/autoprivilege 2>&1 | tee "$RESULTS_DIR/edgecases_scan.log"
for vector in suid sudo cron passwd; do
    docker exec autoprivilege-edgecases /usr/local/bin/autoprivilege "--vector=$vector" 2>&1 | tee -a "$RESULTS_DIR/edgecases_vectors.log"
done

# ---------------------------------------------------------------
# 6. CLI flags smoke tests
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
# 7. Teardown + summary
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
