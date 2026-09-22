package autopriv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- parseFailOn ---

func TestParseFailOnFlag(t *testing.T) {
	cases := []struct {
		in      string
		enabled bool
		level   RiskLevel
		wantErr bool
	}{
		{"", false, RiskSafe, false},
		{"low", true, RiskLow, false},
		{"medium", true, RiskMedium, false},
		{"high", true, RiskHigh, false},
		{"danger", true, RiskDanger, false},
		{"HIGH", true, RiskHigh, false}, // case-insensitive like --risk
		{"safe", false, RiskSafe, true}, // confusing alias: rejected on purpose
		{"junk", false, RiskSafe, true},
	}
	for _, c := range cases {
		lvl, enabled, err := parseFailOn(c.in)
		if c.wantErr && err == nil {
			t.Errorf("parseFailOn(%q): want error, got none", c.in)
			continue
		}
		if !c.wantErr && err != nil {
			t.Errorf("parseFailOn(%q): unexpected error %v", c.in, err)
			continue
		}
		if !c.wantErr && (enabled != c.enabled || lvl != c.level) {
			t.Errorf("parseFailOn(%q) = (%v, %v), want (%v, %v)", c.in, lvl, enabled, c.level, c.enabled)
		}
	}
}

// --- policyGateCount ---

func TestPolicyGateCountsExploitableAtOrAbove(t *testing.T) {
	findings := []Finding{
		{Source: "SUID", Target: "/a", Risk: RiskHigh, Exploitable: true},
		{Source: "CRED", Target: "/b", Risk: RiskMedium, Exploitable: true},
		{Source: "PATH", Target: "/c", Risk: RiskLow, Exploitable: true},
		{Source: "FILE", Target: "/d", Risk: RiskHigh, Exploitable: false}, // not actionable
	}
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = findings

	if got := policyGateCount(p); got != 0 {
		t.Fatalf("disabled gate must count 0, got %d", got)
	}

	p.Opts.FailOnEnabled = true
	p.Opts.FailOnRisk = RiskMedium
	if got := policyGateCount(p); got != 2 {
		t.Errorf("threshold medium: want 2 (high+medium, low excluded, non-exploitable excluded), got %d", got)
	}

	p.Opts.FailOnRisk = RiskLow
	if got := policyGateCount(p); got != 3 {
		t.Errorf("threshold low: want 3, got %d", got)
	}

	p.Opts.FailOnRisk = RiskDanger
	if got := policyGateCount(p); got != 0 {
		t.Errorf("threshold danger: want 0, got %d", got)
	}
}

// --- diffReports ---

func TestDiffReportsClassifiesNewAndResolved(t *testing.T) {
	before := &jsonReport{
		Tool:      "Auto-Privilege",
		Timestamp: time.Now().UTC(),
		Findings: []Finding{
			{Source: "SUID", Target: "/usr/bin/old", Exploitable: true},
			{Source: "SUDO", Target: "ALL", Exploitable: true},
			{Source: "FILE", Target: "/etc/shadow", Exploitable: false},
		},
	}
	current := []Finding{
		{Source: "SUDO", Target: "ALL", Exploitable: true},                 // kept
		{Source: "CRED", Target: "/home/u/.ssh/id_rsa", Exploitable: true}, // NEW
		{Source: "CRED", Target: "/home/u/.ssh/id_rsa", Exploitable: true}, // duplicate: no double count
		{Source: "FILE", Target: "/etc/shadow", Exploitable: false},        // kept (same key)
		{Source: "FILE", Target: "/etc/shadow", Exploitable: false},        // duplicate
	}

	d := diffReports(before, current)
	if d.BaselineDate != before.Timestamp {
		t.Errorf("BaselineDate must carry the baseline timestamp")
	}
	if len(d.New) != 1 || d.New[0].Target != "/home/u/.ssh/id_rsa" {
		t.Errorf("New = %v, want only the new CRED finding", d.New)
	}
	if d.NewExploitable != 1 {
		t.Errorf("NewExploitable = %d, want 1", d.NewExploitable)
	}
	if len(d.Resolved) != 1 || d.Resolved[0].Source != "SUID" {
		t.Errorf("Resolved = %v, want only the removed SUID finding", d.Resolved)
	}

	// Key isolation: same Target under a different Source is BOTH new and
	// resolved, never "the same issue".
	before2 := &jsonReport{Tool: "Auto-Privilege", Findings: []Finding{{Source: "FILE", Target: "/t"}}}
	current2 := []Finding{{Source: "CRED", Target: "/t", Exploitable: true}}
	d2 := diffReports(before2, current2)
	if len(d2.New) != 1 || len(d2.Resolved) != 1 {
		t.Errorf("same target under different source must be new AND resolved, got new=%d resolved=%d", len(d2.New), len(d2.Resolved))
	}
}

func TestDiffReportsEmptySlicesNotNull(t *testing.T) {
	before := &jsonReport{Tool: "Auto-Privilege"}
	d := diffReports(before, nil)
	if d.New == nil || d.Resolved == nil {
		t.Fatalf("New/Resolved must be [] not nil: %v %v", d.New, d.Resolved)
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "null") {
		t.Errorf("diff JSON must never contain null: %s", data)
	}
}

// --- loadBaseline ---

func TestLoadBaselineValidation(t *testing.T) {
	dir := t.TempDir()

	valid, _ := json.Marshal(jsonReport{Tool: "Auto-Privilege", Version: "1.5.0"})
	validPath := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(validPath, valid, 0600); err != nil {
		t.Fatal(err)
	}
	wrongToolPath := filepath.Join(dir, "wrong.json")
	if err := os.WriteFile(wrongToolPath, []byte(`{"tool":"something-else"}`), 0600); err != nil {
		t.Fatal(err)
	}
	junkPath := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(junkPath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	if rep, err := loadBaseline(validPath); err != nil || rep == nil || rep.Tool != "Auto-Privilege" {
		t.Errorf("valid baseline must load, got rep=%v err=%v", rep, err)
	}
	if _, err := loadBaseline(wrongToolPath); err == nil || !strings.Contains(err.Error(), "not an Auto-Privilege report") {
		t.Errorf("wrong tool must be rejected with a clear error, got %v", err)
	}
	if _, err := loadBaseline(junkPath); err == nil {
		t.Errorf("junk must be rejected")
	}
	if _, err := loadBaseline(filepath.Join(dir, "missing.json")); err == nil {
		t.Errorf("missing file must be rejected")
	}
}

// --- markdownDiff + buildReport integration ---

func TestMarkdownDiffSection(t *testing.T) {
	d := &ReportDiff{
		BaselinePath:   "/tmp/base.json",
		BaselineDate:   time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC),
		New:            []Finding{{Source: "SUDOERS", Target: "/etc/sudoers", Risk: RiskHigh, Description: "Writable /etc/sudoers"}},
		NewExploitable: 1,
		Resolved:       []Finding{{Source: "SUID", Target: "/old"}},
	}
	out := markdownDiff(d)
	for _, want := range []string{"## Diff vs baseline", "/tmp/base.json", "New findings | 1 (1 exploitable)", "Resolved findings | 1", "SUDOERS", "/etc/sudoers"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown diff missing %q in:\n%s", want, out)
		}
	}

	empty := markdownDiff(&ReportDiff{BaselinePath: "/tmp/base.json", New: []Finding{}, Resolved: []Finding{}})
	if !strings.Contains(empty, "No new findings") {
		t.Errorf("empty diff must state the surface did not grow, got:\n%s", empty)
	}
}

func TestBuildReportEmbedsDiffOnlyWhenPresent(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{{Source: "SUID", Target: "/x", Exploitable: true}}

	// Without baseline: no diff key in the JSON at all.
	rep := buildReport(p)
	if rep.Diff != nil {
		t.Fatalf("diff must be nil without baseline")
	}
	data, _ := marshalJSON(rep)
	if strings.Contains(string(data), "\"diff\"") {
		t.Errorf("JSON without baseline must not carry a diff key: %s", data)
	}

	// With baseline: diff embedded and shaped.
	p.Baseline = &jsonReport{Tool: "Auto-Privilege", Timestamp: time.Now().UTC()}
	p.Diff = diffReports(p.Baseline, p.Findings)
	p.Diff.BaselinePath = p.Opts.Baseline
	rep = buildReport(p)
	if rep.Diff == nil {
		t.Fatalf("diff must be embedded when a baseline diff was computed")
	}
	data, _ = marshalJSON(rep)
	for _, want := range []string{"\"diff\"", "\"new\"", "\"resolved\"", "\"new_exploitable\""} {
		if !strings.Contains(string(data), want) {
			t.Errorf("diff JSON missing %s in:\n%s", want, data)
		}
	}
}
