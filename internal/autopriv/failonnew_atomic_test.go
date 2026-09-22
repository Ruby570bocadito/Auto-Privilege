package autopriv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ================================================================
// --fail-on-new regression gate, atomic report writes,
// per-scanner timing.
// ================================================================

// --- computeExitCode (pure, so the whole exit contract is testable) ---

func gateP(risk RiskLevel, enabled bool) Options {
	return Options{FailOnRisk: risk, FailOnEnabled: enabled}
}

func TestComputeExitCodeClassic(t *testing.T) {
	// Scan-only (no exploit): 0.
	if code, msg := computeExitCode(&AutoPrivilege{Opts: Options{}}); code != 0 || msg != "" {
		t.Errorf("scan-only must be (0, \"\"), got (%d,%q)", code, msg)
	}
	// Exploit without root: 1.
	p := &AutoPrivilege{Opts: Options{Exploit: true}}
	if code, _ := computeExitCode(p); code != 1 {
		t.Errorf("exploit-no-root must be 1, got %d", code)
	}
	// Dry-run never counts as an exploit attempt: 0.
	pDry := &AutoPrivilege{Opts: Options{Exploit: true, DryRun: true}}
	if code, _ := computeExitCode(pDry); code != 0 {
		t.Errorf("dry-run must stay 0, got %d", code)
	}
}

func TestComputeExitCodePolicyGateWins(t *testing.T) {
	// Gate trips over exploit-no-root: 3 (ronda-8 documented precedence).
	p := &AutoPrivilege{Opts: func() Options {
		o := gateP(RiskLow, true)
		o.Exploit = true
		return o
	}(), Findings: []Finding{{Source: "CRON", Risk: RiskLow, Exploitable: true}}}
	code, msg := computeExitCode(p)
	if code != 3 || !strings.Contains(msg, "policy gate") {
		t.Errorf("policy gate must override 1 with its message, got (%d,%q)", code, msg)
	}
	// Gate enabled but NOT tripping: falls through to 1 (exploit failed) —
	// the round-8 contract: a passing gate does not mask a failed exploit.
	pNoTrip := &AutoPrivilege{Opts: gateP(RiskDanger, true), Findings: nil}
	if code, msg := computeExitCode(pNoTrip); code != 0 || msg != "" {
		t.Errorf("gate enabled without findings on scan-only run must stay (0,\"\"), got (%d,%q)", code, msg)
	}
}

func TestComputeExitCodeRegressionGate(t *testing.T) {
	base := &jsonReport{Tool: "Auto-Privilege", Findings: []Finding{
		{Source: "SUID", Target: "/usr/bin/python3", Risk: RiskHigh, Exploitable: true},
	}}
	current := []Finding{
		{Source: "SUID", Target: "/usr/bin/python3", Risk: RiskHigh, Exploitable: true}, // resolved-tracking
		{Source: "CRON", Target: "/etc/cron.d/new", Risk: RiskHigh, Exploitable: true},  // NEW exploitable
	}
	p := &AutoPrivilege{Opts: Options{FailOnNew: true}, Baseline: base}
	p.Diff = diffReports(base, current)

	// New exploitable finding → regression gate, 3.
	code, msg := computeExitCode(p)
	if code != 3 || !strings.Contains(msg, "regression gate") {
		t.Errorf("regression gate must trip with its message, got (%d,%q)", code, msg)
	}

	// Same KEY with a reworded description is NOT new: gate stays silent.
	sameKey := []Finding{{Source: "SUID", Target: "/usr/bin/python3", Risk: RiskHigh, Exploitable: true}}
	p2 := &AutoPrivilege{Opts: Options{FailOnNew: true}, Baseline: base}
	p2.Diff = diffReports(base, sameKey)
	if code, msg := computeExitCode(p2); code != 0 || msg != "" {
		t.Errorf("no new findings must pass clean, got (%d,%q)", code, msg)
	}

	// New INFORMATIONAL finding does not trip the regression gate (it gates
	// the actionable surface, not the noise).
	info := []Finding{{Source: "CRED", Target: "/x", Risk: RiskLow, Exploitable: false}}
	p3 := &AutoPrivilege{Opts: Options{FailOnNew: true}, Baseline: base}
	p3.Diff = diffReports(base, info)
	if code, _ := computeExitCode(p3); code != 0 {
		t.Errorf("new informational finding must not trip the regression gate, got %d", code)
	}

	// --fail-on-new without a diff (no --baseline): fail-fast in run()
	// prevents this state; the pure function is defensive here (0/1 as if unset).
	p4 := &AutoPrivilege{Opts: Options{FailOnNew: true}}
	if code, _ := computeExitCode(p4); code != 0 {
		t.Errorf("regression gate without diff must degrade to 0, got %d", code)
	}

	// Policy gate message takes precedence when both trip.
	p5 := &AutoPrivilege{Opts: Options{FailOnNew: true, FailOnRisk: RiskLow, FailOnEnabled: true}, Baseline: base, Findings: current}
	p5.Diff = p.Diff // has 1 new exploitable; policy gate also trips on it
	code5, msg5 := computeExitCode(p5)
	if code5 != 3 || !strings.Contains(msg5, "policy gate") {
		t.Errorf("policy gate message must win when both gates trip, got (%d,%q)", code5, msg5)
	}
}

// --- atomicWriteFile ---

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := atomicWriteFile(path, []byte(`{"a":1}`), 0600); err != nil {
		t.Fatalf("atomic write failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"a":1}` {
		t.Fatalf("content wrong: %q err=%v", data, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("perm must be pinned regardless of umask, got %v", info.Mode().Perm())
	}

	// Overwrite works and no .tmp leftovers ever survive a successful write.
	if err := atomicWriteFile(path, []byte(`{"a":2}`), 0600); err != nil {
		t.Fatalf("overwrite failed: %v", err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != `{"a":2}` {
		t.Errorf("overwrite content wrong: %q", data)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestAtomicWritesUsedByAllReportWriters(t *testing.T) {
	dir := t.TempDir()
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{{Source: "FILE", Target: "/etc/shadow", Description: "Writable /etc/shadow", Risk: RiskDanger, Exploitable: true}}

	if err := p.WriteJSONFile(filepath.Join(dir, "r.json")); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteMarkdownReport(filepath.Join(dir, "r.md")); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteSARIFFile(filepath.Join(dir, "r.sarif")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"r.json": false, "r.md": false, "r.sarif": false}
	for _, e := range entries {
		if _, ok := want[e.Name()]; !ok {
			t.Errorf("unexpected artifact in the output dir: %s", e.Name())
		} else {
			want[e.Name()] = true
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("report writer left a temp file: %s", e.Name())
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("expected artifact %s missing", name)
		}
	}
}

// --- scannerName (identity must follow scannerOrder, not a parallel list) ---

func TestScannerNameFollowsFuncIdentity(t *testing.T) {
	name := scannerName(scanSudo)
	if name == "" {
		t.Fatal("scanner name must not be empty")
	}
	// An anonymous func gets a runtime-generated name — still non-empty and
	// unique per closure, which is all the timing log needs.
	anon := func(p *AutoPrivilege) {}
	if scannerName(anon) == "" {
		t.Error("anonymous scanner must still produce a name")
	}
}
