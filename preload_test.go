package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The writable-branch assertions require a non-root euid: root can write
// everything, so the distinction the scanner is testing would collapse.
func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("writable checks short-circuit for euid 0 — run as a regular user")
	}
}

// --- countPreloadEntries ---

func TestCountPreloadEntries(t *testing.T) {
	cases := []struct {
		content string
		want    int
	}{
		{"", 0},
		{"\n\n   \n\t\n", 0}, // blank lines are not entries (glibc ignores them)
		{"/tmp/evil.so\n", 1},
		{"/tmp/a.so\n/tmp/b.so\n", 2},
		{"  /tmp/spaced.so  \n\n/tmp/b.so\n", 2}, // whitespace trimmed, blanks skipped
	}
	for _, c := range cases {
		if got := countPreloadEntries(c.content); got != c.want {
			t.Errorf("countPreloadEntries(%q) = %d, want %d", c.content, got, c.want)
		}
	}
}

// --- scanPreloadPaths (synthetic tree, same mechanism as production paths) ---

func TestScanPreloadPathsFindings(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	preload := filepath.Join(dir, "ld.so.preload")
	sudoers := filepath.Join(dir, "sudoers")
	sudoersDir := filepath.Join(dir, "sudoers.d")

	// Writable preload with entries → PRELOAD, HIGH, exploitable.
	if err := os.WriteFile(preload, []byte("/tmp/a.so\n/tmp/b.so\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sudoersDir, 0777); err != nil {
		t.Fatal(err)
	}

	p := &AutoPrivilege{Opts: Options{}}
	scanPreloadPaths(p, preload, sudoers, sudoersDir)

	var preloadFinding, sudoersDirFinding *Finding
	for i := range p.Findings {
		switch p.Findings[i].Source {
		case "PRELOAD":
			f := p.Findings[i]
			preloadFinding = &f
		case "SUDOERS":
			if p.Findings[i].Target == sudoersDir {
				f := p.Findings[i]
				sudoersDirFinding = &f
			}
		}
	}
	if preloadFinding == nil {
		t.Fatalf("writable non-empty preload must yield a PRELOAD finding, got %v", p.Findings)
	}
	if preloadFinding.Risk != RiskHigh || !preloadFinding.Exploitable {
		t.Errorf("writable preload must be HIGH/exploitable, got %v/%v", preloadFinding.Risk, preloadFinding.Exploitable)
	}
	if !strings.Contains(preloadFinding.Description, "writable") {
		t.Errorf("description must announce writability (the enumerator gates on it): %q", preloadFinding.Description)
	}
	if strings.Contains(preloadFinding.Description, "/tmp/a.so") {
		t.Errorf("content must never leak into the finding: %q", preloadFinding.Description)
	}
	if sudoersDirFinding == nil {
		t.Errorf("writable sudoers.d directory must yield a SUDOERS finding, got %v", p.Findings)
	}
}

func TestScanPreloadPathsHonestAbsence(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	preload := filepath.Join(dir, "ld.so.preload")
	sudoers := filepath.Join(dir, "sudoers")
	sudoersDir := filepath.Join(dir, "sudoers.d")

	// Readable but NOT writable preload with entries → informational only.
	if err := os.WriteFile(preload, []byte("/root/evil.so\n"), 0444); err != nil {
		t.Fatal(err)
	}

	p := &AutoPrivilege{Opts: Options{}}
	scanPreloadPaths(p, preload, sudoers, sudoersDir)

	for _, f := range p.Findings {
		if f.Source == "PRELOAD" {
			if f.Risk != RiskLow || f.Exploitable {
				t.Errorf("non-writable preload must be LOW/not exploitable, got %v/%v", f.Risk, f.Exploitable)
			}
		}
		if f.Source == "SUDOERS" {
			t.Errorf("missing sudoers targets must stay silent, got %v", f)
		}
	}

	// Empty preload → nothing at all; missing paths → nothing at all.
	if err := os.Remove(preload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(preload, []byte("\n \n"), 0666); err != nil {
		t.Fatal(err)
	}
	p2 := &AutoPrivilege{Opts: Options{}}
	scanPreloadPaths(p2, preload, sudoers, sudoersDir)
	if len(p2.Findings) != 0 {
		t.Errorf("empty preload + missing sudoers must produce zero findings, got %v", p2.Findings)
	}
}

func TestScanPreloadPathsWritableSudoersFile(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	sudoers := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoers, []byte("root ALL=(ALL) ALL\n"), 0666); err != nil {
		t.Fatal(err)
	}

	p := &AutoPrivilege{Opts: Options{}}
	scanPreloadPaths(p, filepath.Join(dir, "missing-preload"), sudoers, filepath.Join(dir, "missing-dir"))

	found := false
	for _, f := range p.Findings {
		if f.Source == "SUDOERS" && f.Target == sudoers {
			found = true
			if f.Risk != RiskHigh || !f.Exploitable {
				t.Errorf("writable /etc/sudoers must be HIGH/exploitable, got %v/%v", f.Risk, f.Exploitable)
			}
		}
	}
	if !found {
		t.Errorf("writable sudoers file must yield a SUDOERS finding, got %v", p.Findings)
	}
}

// --- sudoersRulePresent + exploitSudoersWrite ---

func TestSudoersRulePresent(t *testing.T) {
	cases := []struct {
		content string
		want    bool
	}{
		{"", false},
		{"root ALL=(ALL) ALL\n", false},
		{"%admin ALL=(ALL) ALL\n", false},
		{"ALL ALL=(ALL) NOPASSWD: ALL\n", true},
		{"ALL ALL=(ALL) NOPASSWD:ALL\n", true},
		{"user ALL=(ALL) NOPASSWD: /usr/bin/less\n", false}, // scoped rule is not the wildcard
	}
	for _, c := range cases {
		if got := sudoersRulePresent(c.content); got != c.want {
			t.Errorf("sudoersRulePresent(%q) = %v, want %v", c.content, got, c.want)
		}
	}
}

func TestExploitSudoersWriteIdempotentAndNewlineSafe(t *testing.T) {
	dir := t.TempDir()
	sudoers := filepath.Join(dir, "sudoers")
	// No trailing newline: a naive append would concatenate onto the last
	// line and produce a sudoers syntax error that bricks sudo for everyone.
	if err := os.WriteFile(sudoers, []byte("root ALL=(ALL) ALL"), 0666); err != nil {
		t.Fatal(err)
	}

	r1 := exploitSudoersWrite(sudoers, Options{})
	if r1 == nil || !r1.Success {
		t.Fatalf("first write must succeed, got %+v", r1)
	}
	data, _ := os.ReadFile(sudoers)
	content := string(data)
	if got := strings.Count(content, "NOPASSWD"); got != 1 {
		t.Fatalf("rule must appear exactly once after first write, got %d in %q", got, content)
	}
	if !strings.HasPrefix(content, "root ALL=(ALL) ALL\n") {
		t.Errorf("missing trailing newline must be compensated before appending, got %q", content)
	}
	if !strings.HasSuffix(content, "NOPASSWD: ALL\n") {
		t.Errorf("rule must end with a newline, got %q", content)
	}

	// Second run: idempotent, no duplicate rule.
	r2 := exploitSudoersWrite(sudoers, Options{})
	if r2 == nil || !r2.Success {
		t.Fatalf("second run must succeed, got %+v", r2)
	}
	data, _ = os.ReadFile(sudoers)
	if got := strings.Count(string(data), "NOPASSWD"); got != 1 {
		t.Errorf("second run must not duplicate the rule, got %d occurrences", got)
	}

	// Unreadable path → honest error, no panic.
	if r := exploitSudoersWrite(filepath.Join(dir, "missing"), Options{}); r.Success || r.Error == "" {
		t.Errorf("missing sudoers must fail with an error, got %+v", r)
	}
}

// --- enumeration wiring for the two new sources ---

func TestEnumeratePreloadGatesOnWritable(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{{Source: "PRELOAD", Target: "/etc/ld.so.preload",
		Description: "2 ld.so.preload entries loaded with euid 0 into every SUID binary — file writable, entries injectable",
		Risk:        RiskHigh, Exploitable: true}}
	enumerateAll(p)
	if len(p.Vectors) != 1 || p.Vectors[0].Category != "preload" || p.Vectors[0].Exploit != nil {
		t.Fatalf("writable PRELOAD must yield exactly one manual preload vector, got %+v", p.Vectors)
	}

	// Informational-only finding (not writable): nothing to hand over.
	p2 := &AutoPrivilege{Opts: Options{}}
	p2.Findings = []Finding{{Source: "PRELOAD", Target: "/etc/ld.so.preload",
		Description: "2 ld.so.preload entries loaded with euid 0 into every SUID binary",
		Risk:        RiskLow, Exploitable: false}}
	enumerateAll(p2)
	if len(p2.Vectors) != 0 {
		t.Errorf("non-writable PRELOAD must not yield vectors, got %+v", p2.Vectors)
	}
}

func TestEnumerateSudoersAutoAndManual(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{
		{Source: "SUDOERS", Target: "/etc/sudoers", Risk: RiskHigh, Exploitable: true},
		{Source: "SUDOERS", Target: "/etc/sudoers.d", Risk: RiskHigh, Exploitable: true},
	}
	enumerateAll(p)
	if len(p.Vectors) != 2 {
		t.Fatalf("both SUDOERS findings must yield vectors, got %+v", p.Vectors)
	}
	var auto, manual int
	for _, v := range p.Vectors {
		if v.Category != "sudoers" {
			t.Errorf("category must be sudoers, got %q", v.Category)
		}
		if v.Exploit != nil {
			auto++
		} else {
			manual++
		}
	}
	if auto != 1 || manual != 1 {
		t.Errorf("want 1 auto (writable /etc/sudoers) + 1 manual (sudoers.d dir), got %d auto + %d manual", auto, manual)
	}
	if !strings.Contains(p.Vectors[0].Command, "NOPASSWD: ALL") {
		t.Errorf("displayed command must show the exact rule")
	}
}
