package autopriv

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ================================================================
// --html report, --fail-on-new [risk], --list-vectors
// ================================================================

// --- Bloque 1: HTML report ---------------------------------------------

// TestHTMLReportEscapesDynamicContent is the security test for the fifth
// output format: finding targets and descriptions come from filesystem
// paths and file CONTENT, so a credential file whose text contains markup
// must render as text, never as tags.
func TestHTMLReportEscapesDynamicContent(t *testing.T) {
	dir := t.TempDir()
	p := &AutoPrivilege{Opts: Options{}, Started: time.Now()}
	p.Findings = []Finding{
		{Source: "CRED", Target: `/tmp/x/<script>alert("xss")</script>`,
			Description: `<img src=x onerror=alert(1)> & "quotes"`, Risk: RiskHigh, Exploitable: true},
	}
	p.Vectors = []Vector{
		{Name: "suid-<b>bold</b>", Risk: RiskMedium, Target: "&&", Category: "suid",
			Command: "echo '<script>shell()</script>'"},
	}
	path := filepath.Join(dir, "audit.html")
	if err := p.WriteHTMLReport(path); err != nil {
		t.Fatalf("WriteHTMLReport: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, raw := range []string{"<script>alert", "<img src=x", "<b>bold</b>"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw markup leaked into HTML report: %q", raw)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert", "&lt;img src=x", "&lt;b&gt;bold&lt;/b&gt;", "&amp; &#34;quotes&#34;"} {
		if !strings.Contains(out, want) {
			t.Errorf("escaped form missing: %q", want)
		}
	}
}

// TestHTMLReportStructureAndPerms checks the contract that matters for the
// "attach it to the engagement doc" use case: a full self-contained page
// (doctype, inline CSS, zero external resources), the same numbers as the
// JSON summary, the hardening plan for detected sources, and 0600 perms
// with no .tmp leftovers (atomic write).
func TestHTMLReportStructureAndPerms(t *testing.T) {
	dir := t.TempDir()
	p := &AutoPrivilege{Opts: Options{}, Started: time.Now()}
	p.Findings = []Finding{
		{Source: "SUID", Target: "/usr/bin/python3", Description: "SUID python3", Risk: RiskHigh, Exploitable: true},
		{Source: "CRON", Target: "/etc/cron.d/job", Description: "writable cron", Risk: RiskMedium, Exploitable: true},
	}
	p.Vectors = []Vector{{Name: "suid-python3", Risk: RiskHigh, Target: "/usr/bin/python3",
		Command: "/usr/bin/python3 -c 'import os; os.setuid(0)'", Category: "gtfobins"}}
	path := filepath.Join(dir, "audit.html")
	if err := p.WriteHTMLReport(path); err != nil {
		t.Fatalf("WriteHTMLReport: %v", err)
	}
	assertPinned0600(t, path, "HTML report")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp leftover: %s", e.Name())
		}
	}
	data, _ := os.ReadFile(path)
	out := string(data)
	for _, want := range []string{
		"<!DOCTYPE html>", "<style>", "http://", "https://", // inline CSS, no external fetches
		"Hardening plan", "SUID", "CRON", "Exploit vectors", "suid-python3",
		"Hardening score", "/usr/bin/python3",
	} {
		if want == "http://" || want == "https://" {
			if strings.Contains(out, want) {
				t.Errorf("external resource reference found (%q) — report must be self-contained", want)
			}
			continue
		}
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	// Empty-safe: zero findings must not emit a Hardening plan section.
	empty := &AutoPrivilege{Opts: Options{}, Started: time.Now()}
	path2 := filepath.Join(dir, "empty.html")
	if err := empty.WriteHTMLReport(path2); err != nil {
		t.Fatalf("WriteHTMLReport(empty): %v", err)
	}
	data2, _ := os.ReadFile(path2)
	if strings.Contains(string(data2), "Hardening plan") {
		t.Error("empty scan must not render a Hardening plan section")
	}
}

// TestHTMLReportDiffSection pins the baseline rendering: new findings listed
// with their badges, the honest "predates scoring" rendering preserved.
func TestHTMLReportDiffSection(t *testing.T) {
	dir := t.TempDir()
	before := jsonReport{Summary: jsonSummary{Score: 0}}
	p := &AutoPrivilege{Opts: Options{}, Started: time.Now()}
	p.Diff = &ReportDiff{
		BaselinePath:   filepath.Join(dir, "base.json"),
		BaselineDate:   time.Now(),
		New:            []Finding{{Source: "CRED", Target: "/home/u/.bash_history", Description: "secrets", Risk: RiskHigh, Exploitable: true}},
		NewExploitable: 1,
		SummaryBefore:  before.Summary,
		ScoreAfter:     85,
	}
	path := filepath.Join(dir, "diff.html")
	if err := p.WriteHTMLReport(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	out := string(data)
	if !strings.Contains(out, "Diff vs baseline") || !strings.Contains(out, "baseline predates scoring") {
		t.Error("diff section or honest score rendering missing")
	}
	if !strings.Contains(out, "/home/u/.bash_history") {
		t.Error("new finding missing from diff table")
	}
}

// --- Bloque 2: --fail-on-new con umbral ---------------------------------

// TestFailOnNewThresholdGate: --fail-on-new=high ignores a new MEDIUM
// exploitable regression (the pipeline keeps hardening; the verdict falls
// through to the classic code) and trips on a new DANGER one, with the
// "at/above HIGH" message.
func TestFailOnNewThresholdGate(t *testing.T) {
	mk := func(newF Finding) *AutoPrivilege {
		return &AutoPrivilege{
			Opts: Options{FailOnNew: true, FailOnNewRisk: RiskHigh},
			Diff: &ReportDiff{New: []Finding{newF}, NewExploitable: 1},
		}
	}
	medium := mk(Finding{Source: "SUID", Risk: RiskMedium, Exploitable: true})
	code, msg := computeExitCode(medium)
	if code != 0 || msg != "" {
		t.Errorf("medium regression with high threshold: got (%d, %q), want (0, \"\")", code, msg)
	}
	danger := mk(Finding{Source: "SUID", Risk: RiskDanger, Exploitable: true})
	code, msg = computeExitCode(danger)
	if code != 3 {
		t.Errorf("danger regression with high threshold: got %d, want 3", code)
	}
	if !strings.Contains(msg, "at/above HIGH") {
		t.Errorf("threshold message missing: %q", msg)
	}
}

// TestFailOnNewBareBehaviorPreserved: the round-11 contract — bare
// --fail-on-new trips on ANY new exploitable finding regardless of risk,
// and never on informational findings.
func TestFailOnNewBareBehaviorPreserved(t *testing.T) {
	low := &AutoPrivilege{
		Opts: Options{FailOnNew: true, FailOnNewRisk: RiskSafe},
		Diff: &ReportDiff{New: []Finding{{Source: "SUID", Risk: RiskLow, Exploitable: true}}, NewExploitable: 1},
	}
	if code, _ := computeExitCode(low); code != 3 {
		t.Errorf("bare gate must trip on a LOW regression, got %d", code)
	}
	info := &AutoPrivilege{
		Opts: Options{FailOnNew: true, FailOnNewRisk: RiskSafe},
		Diff: &ReportDiff{New: []Finding{{Source: "NOTE", Risk: RiskMedium, Exploitable: false}}, NewExploitable: 0},
	}
	if code, _ := computeExitCode(info); code != 0 {
		t.Errorf("informational finding must not trip the gate, got %d", code)
	}
}

// TestFailOnNewFlagParsing exercises the custom flag.Value: bare sets the
// any-risk default, =danger maps to RiskDanger, typos fail at parse time,
// and String() round-trips for flag defaults printing.
func TestFailOnNewFlagParsing(t *testing.T) {
	var opts Options
	f := failOnNewFlag{&opts}
	if err := f.Set(""); err != nil {
		t.Fatalf("bare Set: %v", err)
	}
	if !opts.FailOnNew || opts.FailOnNewRisk != RiskSafe {
		t.Errorf("bare Set state: %v / %v", opts.FailOnNew, opts.FailOnNewRisk)
	}
	if err := f.Set("high"); err != nil {
		t.Fatalf("Set(high): %v", err)
	}
	if opts.FailOnNewRisk != RiskHigh {
		t.Errorf("Set(high) risk = %v", opts.FailOnNewRisk)
	}
	if got := f.String(); got != "high" {
		t.Errorf("String() = %q, want high", got)
	}
	if err := f.Set("bogus"); err == nil {
		t.Error("invalid threshold must fail at parse time")
	} else if !strings.Contains(err.Error(), "invalid --fail-on-new threshold") {
		t.Errorf("wrong error text: %v", err)
	}
	var nilOpts *Options
	if s := (failOnNewFlag{nilOpts}).String(); s != "" {
		t.Errorf("nil-safe String() = %q, want empty", s)
	}
}

// --- Bloque 3: --list-vectors -------------------------------------------

// TestVectorCatalogCoversValidVectors pins the catalog to validVectors in
// BOTH directions: a new vector cannot ship undocumented, and a removed
// vector cannot leave a ghost entry behind.
func TestVectorCatalogCoversValidVectors(t *testing.T) {
	if len(vectorCatalogOrder) != len(validVectors) {
		t.Errorf("catalog order has %d entries, validVectors has %d", len(vectorCatalogOrder), len(validVectors))
	}
	seen := map[string]bool{}
	for _, name := range vectorCatalogOrder {
		if seen[name] {
			t.Errorf("duplicated catalog entry: %s", name)
		}
		seen[name] = true
		doc, ok := vectorCatalog[name]
		if !ok {
			t.Errorf("vector %q missing from vectorCatalog", name)
			continue
		}
		if len(strings.TrimSpace(doc.Desc)) < 30 {
			t.Errorf("vector %q catalog description too thin: %q", name, doc.Desc)
		}
		if !validVectors[name] {
			t.Errorf("catalog entry %q is not a valid vector (ghost entry)", name)
		}
	}
	for name := range validVectors {
		if !seen[name] {
			t.Errorf("valid vector %q missing from vectorCatalogOrder", name)
		}
	}
}

// TestPrintVectorListOutput runs the printer and verifies every vector name
// reaches the output (the discoverability promise of the flag).
func TestPrintVectorListOutput(t *testing.T) {
	out := captureStdout(t, func() { printVectorList() })
	for name := range validVectors {
		if !strings.Contains(out, name) {
			t.Errorf("--list-vectors output missing vector %q", name)
		}
	}
	if !strings.Contains(out, "read-only") {
		t.Error("catalog must state the read-only promise")
	}
}

// --- Higiene: paridad flags ↔ usage -------------------------------------

// TestFlagUsageParity turns the manual parity check of every round into a
// test: every registered flag must appear in usage() and every --flag in
// the usage text must be registered (hygiene: strip [risk] decorations and
// example lines before comparing).
func TestFlagUsageParity(t *testing.T) {
	// Hermetic FlagSet built through registerFlags — the same single
	// source of truth run() uses, without the testing framework's -test.*
	// noise and without depending on process-global flag state.
	fs := flag.NewFlagSet("parity", flag.ContinueOnError)
	registerFlags(fs, new(Options), new(string), new(bool))
	registered := map[string]bool{}
	fs.VisitAll(func(fl *flag.Flag) { registered[fl.Name] = true })

	usageOut := captureStderr(t, usage)
	re := regexp.MustCompile(`--[a-z][a-z0-9-]*`)
	inUsage := map[string]bool{}
	for _, m := range re.FindAllString(usageOut, -1) {
		name := strings.TrimPrefix(m, "--")
		// Example lines may mention flag VALUES that are not flags; only
		// names registered in flag* are counted from the Options section,
		// so keep every plausible name and let the two-way diff below be
		// the judge.
		inUsage[name] = true
	}
	for name := range registered {
		if !inUsage[name] {
			t.Errorf("flag -%s registered but missing from usage()", name)
		}
	}
	for name := range inUsage {
		// "help" is served by the flag package itself (the -h/--help
		// default that prints flag.Usage) — intentionally not registered.
		if name == "help" {
			continue
		}
		if !registered[name] {
			t.Errorf("usage() mentions --%s but no such flag is registered", name)
		}
	}
}
