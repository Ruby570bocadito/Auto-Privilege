package autopriv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- sarifLevel ---

func TestSarifLevelMapping(t *testing.T) {
	cases := []struct {
		risk RiskLevel
		want string
	}{
		{RiskDanger, "error"},
		{RiskHigh, "error"},
		{RiskMedium, "warning"},
		{RiskLow, "note"},
		{RiskSafe, "note"},
	}
	for _, c := range cases {
		if got := sarifLevel(c.risk); got != c.want {
			t.Errorf("sarifLevel(%v) = %q, want %q", c.risk, got, c.want)
		}
	}
}

// --- sarifTargetURI ---

func TestSarifTargetURI(t *testing.T) {
	// Absolute paths become file:// URIs.
	uri, ok := sarifTargetURI("/etc/passwd")
	if !ok || uri != "file:///etc/passwd" {
		t.Errorf("sarifTargetURI(/etc/passwd) = %q,%v", uri, ok)
	}
	// Spaces are percent-encoded by the URL encoder, not left raw.
	uri, ok = sarifTargetURI("/tmp/space dir/x")
	if !ok || !strings.Contains(uri, "%20") {
		t.Errorf("URI must percent-encode spaces, got %q", uri)
	}
	// Non-path targets have no location — suppressed, never fabricated.
	for _, target := range []string{"ALL", "self", "CVE-2021-4034", "cap_setuid", "0x00000000", ""} {
		if _, ok := sarifTargetURI(target); ok {
			t.Errorf("sarifTargetURI(%q) must be suppressed", target)
		}
	}
}

// --- buildSARIF shape ---

func TestBuildSARIFShape(t *testing.T) {
	findings := []Finding{
		{Source: "FILE", Target: "/etc/shadow", Description: "Writable /etc/shadow", Risk: RiskDanger, Exploitable: true},
		{Source: "FILE", Target: "/etc/passwd", Description: "Writable /etc/passwd", Risk: RiskHigh, Exploitable: true},
		{Source: "SUDO", Target: "ALL", Description: "Full sudo access", Risk: RiskHigh, Exploitable: true},
		{Source: "CONTAINER", Target: "self", Description: "Running inside a container", Risk: RiskMedium, Exploitable: false},
	}
	log := buildSARIF(findings)

	if log.Version != "2.1.0" {
		t.Errorf("SARIF version must be 2.1.0, got %q", log.Version)
	}
	if !strings.Contains(log.Schema, "sarif-2.1.0.json") {
		t.Errorf("$schema must pin SARIF 2.1.0, got %q", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("exactly one run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Auto-Privilege" || run.Tool.Driver.Version != Version {
		t.Errorf("driver identity wrong: %+v", run.Tool.Driver)
	}
	if len(run.Results) != len(findings) {
		t.Fatalf("one result per finding, got %d want %d", len(run.Results), len(findings))
	}

	// Rules: deduped per source, first-appearance order (FILE before SUDO
	// before CONTAINER — never map iteration).
	wantRules := []string{"FILE", "SUDO", "CONTAINER"}
	if len(run.Tool.Driver.Rules) != len(wantRules) {
		t.Fatalf("rules must be deduped per source, got %+v", run.Tool.Driver.Rules)
	}
	for i, r := range run.Tool.Driver.Rules {
		if r.ID != wantRules[i] {
			t.Errorf("rule[%d].ID = %q, want %q (first-appearance order)", i, r.ID, wantRules[i])
		}
		if r.ShortDescription.Text == "" {
			t.Errorf("rule %q must carry a human shortDescription", r.ID)
		}
	}

	// Results: level mapping + location presence.
	if run.Results[0].Level != "error" || run.Results[2].Level != "error" {
		t.Errorf("DANGER/HIGH must map to error")
	}
	if run.Results[3].Level != "warning" {
		t.Errorf("MEDIUM must map to warning, got %q", run.Results[3].Level)
	}
	if len(run.Results[0].Locations) != 1 || run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "file:///etc/shadow" {
		t.Errorf("path target must produce a file:// location, got %+v", run.Results[0].Locations)
	}
	if len(run.Results[2].Locations) != 0 {
		t.Errorf("non-path target (ALL) must have no location, got %+v", run.Results[2].Locations)
	}
	if !strings.Contains(run.Results[2].Message.Text, "(target: ALL)") {
		t.Errorf("non-path target must be embedded in the message, got %q", run.Results[2].Message.Text)
	}
	if !strings.Contains(run.Results[3].Message.Text, "(target: self)") {
		t.Errorf("non-path target 'self' must be embedded in the message, got %q", run.Results[3].Message.Text)
	}
}

func TestBuildSARIFEmptyFindings(t *testing.T) {
	log := buildSARIF(nil)
	if log.Runs[0].Results == nil {
		t.Errorf("results must be [] not null for a clean host")
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("rules must be [] not null for a clean host")
	}
}

// --- WriteSARIFFile ---

func TestWriteSARIFFile(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{
		{Source: "FILE", Target: "/etc/shadow", Description: "Writable /etc/shadow", Risk: RiskDanger, Exploitable: true},
	}
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := p.WriteSARIFFile(path); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	assertPinned0600(t, path, "SARIF report")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("written file must be valid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Errorf("round-tripped log shape wrong: %+v", log)
	}
}
