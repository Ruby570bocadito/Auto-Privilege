package autopriv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ================================================================
// --explain playbook, --ignore filter, --sarif-stdout,
// loader-path and init.d extensions.
// ================================================================

// --- explain DB integrity ---

func TestExplainDBCoversAllSources(t *testing.T) {
	for _, s := range validSources {
		e, ok := explainDB[s]
		if !ok {
			t.Errorf("source %q has NO playbook entry — --explain and the markdown plan would skip it", s)
			continue
		}
		if strings.TrimSpace(e.What) == "" {
			t.Errorf("source %q has an empty What", s)
		}
		if len(e.Harden) == 0 {
			t.Errorf("source %q has no hardening steps", s)
		}
		for _, step := range e.Harden {
			if strings.TrimSpace(step) == "" {
				t.Errorf("source %q has a blank hardening step", s)
			}
		}
	}
	// And the DB carries no orphan entries outside the canonical vocabulary.
	if len(explainDB) != len(validSources) {
		t.Errorf("explainDB has %d entries for %d valid sources — vocabulary drift", len(explainDB), len(validSources))
	}
}

func TestPrintExplainUnknownSource(t *testing.T) {
	err := printExplain("BOGUS")
	if err == nil {
		t.Fatal("unknown source must be an error, got nil")
	}
	if !strings.Contains(err.Error(), "BOGUS") || !strings.Contains(err.Error(), "all") {
		t.Errorf("error must name the source and the all alias, got %v", err)
	}
	if err := printExplain("cron"); err != nil {
		t.Errorf("case-insensitive source lookup failed: %v", err)
	}
	if err := printExplain("all"); err != nil {
		t.Errorf("all alias must be accepted: %v", err)
	}
}

func TestHardeningPlanFromFindings(t *testing.T) {
	findings := []Finding{
		{Source: "CRON", Target: "/etc/cron.d/x"},
		{Source: "CRON", Target: "/etc/cron.d/y"}, // dedup by source
		{Source: "CRED", Target: "/home/u/.bash_history"},
		{Source: "SUID", Target: "/usr/bin/python3"},
	}
	plan := hardeningPlan(findings)
	if !strings.Contains(plan, "## Hardening plan") {
		t.Fatal("plan section missing")
	}
	// First-appearance order: CRON before CRED before SUID.
	iCRON := strings.Index(plan, "### CRON")
	iCRED := strings.Index(plan, "### CRED")
	iSUID := strings.Index(plan, "### SUID")
	if iCRON < 0 || iCRED < 0 || iSUID < 0 {
		t.Fatalf("plan must carry one section per detected source, got:\n%s", plan)
	}
	if !(iCRON < iCRED && iCRED < iSUID) {
		t.Errorf("sections must follow first-appearance order, got CRON@%d CRED@%d SUID@%d", iCRON, iCRED, iSUID)
	}
	if strings.Count(plan, "### CRON") != 1 {
		t.Errorf("duplicate source findings must dedup to one section")
	}

	// Empty findings → no section at all (not an empty heading).
	if got := hardeningPlan(nil); got != "" {
		t.Errorf("no findings must produce no plan, got %q", got)
	}
}

// --- --ignore ---

func TestParseIgnore(t *testing.T) {
	names, err := parseIgnore("cred, container ,CRED")
	if err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	if len(names) != 2 || names[0] != "CRED" || names[1] != "CONTAINER" {
		t.Errorf("parse must uppercase, trim and dedup, got %v", names)
	}
	if _, err := parseIgnore("bogus"); err == nil {
		t.Error("unknown source must be an error")
	}
	if _, err := parseIgnore("  "); err == nil {
		t.Error("empty list must be an error")
	}
}

func TestFilterIgnored(t *testing.T) {
	findings := []Finding{
		{Source: "CRED", Target: "/x"},
		{Source: "SUID", Target: "/usr/bin/python3"},
		{Source: "CRED", Target: "/y"},
		{Source: "CRON", Target: "/etc/cron.d/j"},
	}
	got := filterIgnored(findings, []string{"CRED"})
	if len(got) != 2 {
		t.Fatalf("CRED findings must be filtered, got %v", got)
	}
	if got[0].Source != "SUID" || got[1].Source != "CRON" {
		t.Errorf("survivors keep order, got %v", got)
	}
	if same := filterIgnored(findings, nil); len(same) != 4 {
		t.Errorf("no ignore list must be a no-op, got %d", len(same))
	}
	// Filtering EVERYTHING is legal: an operator may silence a whole scan.
	if none := filterIgnored(findings, []string{"CRED", "SUID", "CRON"}); len(none) != 0 {
		t.Errorf("ignoring every source must yield zero findings, got %v", none)
	}
}

// TestIgnoreIntegrationScoreGate pins the composed semantics: the ignore
// filter runs ONCE after the scan, so score and policy gate measure the
// SAME filtered reality the reports show — no hidden findings inflating
// either metric.
func TestIgnoreIntegrationScoreGate(t *testing.T) {
	findings := []Finding{
		{Source: "CRED", Target: "/x", Risk: RiskHigh, Exploitable: true},
		{Source: "SUID", Target: "/usr/bin/python3", Risk: RiskHigh, Exploitable: true},
	}
	filtered := filterIgnored(findings, []string{"CRED"})
	p := &AutoPrivilege{Opts: Options{FailOnRisk: RiskHigh, FailOnEnabled: true}, Findings: filtered}
	if s := buildSummary(p).Score; s != 100-10 {
		t.Errorf("score must recompute over the filtered set (only SUID's penalty), got %d", s)
	}
	if n := policyGateCount(p); n != 1 {
		t.Errorf("gate must count only surviving findings, got %d", n)
	}
}

// --- scanLoaderPath (ld.so.conf / ld.so.conf.d) ---

func TestScanLoaderPathWritable(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "ld.so.conf")
	confD := filepath.Join(dir, "ld.so.conf.d")
	if err := os.WriteFile(conf, []byte("include /etc/ld.so.conf.d/*.conf\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(confD, 0777); err != nil {
		t.Fatal(err)
	}

	p := &AutoPrivilege{Opts: Options{}}
	scanLoaderPath(p, conf, confD)
	if len(p.Findings) != 2 {
		t.Fatalf("writable conf + confD must yield 2 findings, got %v", p.Findings)
	}
	for _, f := range p.Findings {
		if f.Source != "PRELOAD" || f.Risk != RiskHigh || !f.Exploitable {
			t.Errorf("loader-path findings must be PRELOAD/HIGH/exploitable, got %+v", f)
		}
		if !strings.Contains(strings.ToLower(f.Description), "writable") {
			t.Errorf("description must announce writability (enumerator gates on it, case-insensitive): %q", f.Description)
		}
	}

	// Missing paths stay silent.
	p2 := &AutoPrivilege{Opts: Options{}}
	scanLoaderPath(p2, filepath.Join(dir, "missing"), filepath.Join(dir, "missing-d"))
	if len(p2.Findings) != 0 {
		t.Errorf("missing loader paths must stay silent, got %v", p2.Findings)
	}
}

func TestEnumeratePreloadLibraryPathVector(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{{Source: "PRELOAD", Target: preloadPaths.confD,
		Description: "Writable /etc/ld.so.conf.d — drop a .conf adding an attacker library dir (absorbed by the next ldconfig)",
		Risk:        RiskHigh, Exploitable: true}}
	enumerateAll(p)
	if len(p.Vectors) != 1 {
		t.Fatalf("writable confD must yield exactly one vector, got %+v", p.Vectors)
	}
	v := p.Vectors[0]
	if v.Category != "preload" || v.Exploit != nil {
		t.Errorf("library-path vector must be manual preload, got %+v", v)
	}
	if !strings.Contains(v.Command, "ldconfig") {
		t.Errorf("command must name the ldconfig absorption step, got %q", v.Command)
	}

	// The preload file itself keeps its classic technique — no cross-wiring.
	p2 := &AutoPrivilege{Opts: Options{}}
	p2.Findings = []Finding{{Source: "PRELOAD", Target: "/etc/ld.so.preload",
		Description: "2 ld.so.preload entries — file writable, entries injectable",
		Risk:        RiskHigh, Exploitable: true}}
	enumerateAll(p2)
	if len(p2.Vectors) != 1 || !strings.Contains(p2.Vectors[0].Command, "ld.so.preload") {
		t.Errorf("ld.so.preload vector must keep its own technique, got %+v", p2.Vectors)
	}
}

// --- scanServices init.d extension ---

func TestScanServicesInitD(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	initD := filepath.Join(dir, "init.d")
	if err := os.Mkdir(initD, 0755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(initD, "vulnservice") // no extension: init.d naming
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0666); err != nil {
		t.Fatal(err)
	}
	// A subdirectory must not match (regular files only).
	if err := os.Mkdir(filepath.Join(initD, "subdir"), 0777); err != nil {
		t.Fatal(err)
	}

	p := &AutoPrivilege{Opts: Options{}}
	scanServicesWithPaths(p, filepath.Join(dir, "no-systemd-here"), initD)
	if len(p.Findings) != 1 {
		t.Fatalf("writable init.d script must yield exactly one finding, got %v", p.Findings)
	}
	f := p.Findings[0]
	if f.Source != "SERVICE" || f.Target != script || f.Risk != RiskHigh || !f.Exploitable {
		t.Errorf("init.d finding wrong: %+v", f)
	}
	if !strings.Contains(f.Description, "init.d") {
		t.Errorf("description must name init.d, got %q", f.Description)
	}
}
