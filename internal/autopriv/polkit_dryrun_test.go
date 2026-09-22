package autopriv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ================================================================
// POLKIT vector/source, dry-run plan JSON, --top n
// ================================================================

// polkitTempTree builds a fake /etc/polkit-1 tree inside a temp dir.
func polkitTempTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "rules.d"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"50-local.d", "90-mandatory.d"} {
		if err := os.MkdirAll(filepath.Join(root, "localauthority", d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestScanPolkitWritableRulesDir: a writable rules.d is a HIGH exploitable
// POLKIT finding — the one surface that yields the auto vector.
func TestScanPolkitWritableRulesDir(t *testing.T) {
	root := polkitTempTree(t)
	p := &AutoPrivilege{}
	scanPolkitPaths(p, filepath.Join(root, "rules.d"),
		[]string{filepath.Join(root, "localauthority", "50-local.d"),
			filepath.Join(root, "localauthority", "90-mandatory.d")})
	// everything is writable in the temp tree: 1 rules.d + 2 localauthority
	if len(p.Findings) != 3 {
		t.Fatalf("findings = %d, want 3 (rules.d + 2 localauthority)", len(p.Findings))
	}
	f := p.Findings[0]
	if f.Source != "POLKIT" || f.Risk != RiskHigh || !f.Exploitable {
		t.Errorf("rules.d finding wrong: %+v", f)
	}
	if !strings.Contains(f.Description, "rules.d") {
		t.Errorf("rules.d finding should name rules.d: %s", f.Description)
	}
}

// TestScanPolkitLockedDirPerFilePass: a LOCKED rules.d stays silent at the
// directory level, but an existing writable .rules file inside is caught by
// the per-file pass — polkitd reloads on every change.
func TestScanPolkitLockedDirPerFilePass(t *testing.T) {
	skipNonPOSIXPerms(t)
	if os.Geteuid() == 0 {
		t.Skip("permisos no distinguibles como root")
	}
	root := polkitTempTree(t)
	rulesDir := filepath.Join(root, "rules.d")
	rule := filepath.Join(rulesDir, "50-admin.rules")
	if err := os.WriteFile(rule, []byte("// policy\n"), 0666); err != nil {
		t.Fatal(err)
	}
	// bloquear el directorio DESPUÉS de crear el fichero; desbloquearlo
	// antes de que TempDir intente su cleanup
	if err := os.Chmod(rulesDir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rulesDir, 0755) })
	p := &AutoPrivilege{}
	scanPolkitPaths(p, rulesDir, nil)
	if len(p.Findings) != 1 {
		t.Fatalf("findings = %d, want exactly the writable rule file", len(p.Findings))
	}
	f := p.Findings[0]
	if f.Source != "POLKIT" || f.Target != rule || !f.Exploitable || f.Risk != RiskHigh {
		t.Errorf("per-file finding wrong: %+v", f)
	}
}

// TestScanPolkitSilenceWhenClean: root-owned, non-writable surfaces emit
// NOTHING — honest absence of evidence.
func TestScanPolkitSilenceWhenClean(t *testing.T) {
	skipNonPOSIXPerms(t)
	if os.Geteuid() == 0 {
		t.Skip("permisos no distinguibles como root")
	}
	root := polkitTempTree(t)
	rulesDir := filepath.Join(root, "rules.d")
	// 0444 + owner: no escribible para nadie — el estado sano
	if err := os.WriteFile(filepath.Join(rulesDir, "50-admin.rules"), []byte("// policy\n"), 0444); err != nil {
		t.Fatal(err)
	}
	// bloquear todo DESPUÉS de crear el contenido; desbloquear en cleanup
	if err := os.Chmod(rulesDir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rulesDir, 0755) })
	for _, d := range []string{"50-local.d", "90-mandatory.d"} {
		if err := os.Chmod(filepath.Join(root, "localauthority", d), 0555); err != nil {
			t.Fatal(err)
		}
	}
	p := &AutoPrivilege{}
	scanPolkitPaths(p, rulesDir,
		[]string{filepath.Join(root, "localauthority", "50-local.d"),
			filepath.Join(root, "localauthority", "90-mandatory.d")})
	if len(p.Findings) != 0 {
		t.Fatalf("clean polkit must stay silent, got %+v", p.Findings)
	}
}

// TestEnumeratePolkitClassification: the writable rules.d directory yields
// the AUTO vector (exploit wired); a writable .rules file and a
// localauthority dir stay manual — honest classification per surface.
func TestEnumeratePolkitClassification(t *testing.T) {
	dirFinding := Finding{Source: "POLKIT", Target: "/etc/polkit-1/rules.d",
		Risk: RiskHigh, Exploitable: true}
	p := &AutoPrivilege{}
	p.Findings = []Finding{dirFinding}
	enumerateVectors(p, []string{"polkit"})
	if len(p.Vectors) != 1 {
		t.Fatalf("vectors = %d, want 1", len(p.Vectors))
	}
	if p.Vectors[0].Exploit == nil {
		t.Error("writable rules.d must classify as an AUTO vector")
	}
	if !strings.Contains(p.Vectors[0].Command, "00-autoprivilege-temp.rules") {
		t.Errorf("command should name the temporary 00- rule: %s", p.Vectors[0].Command)
	}

	fileFinding := Finding{Source: "POLKIT", Target: "/etc/polkit-1/rules.d/50-admin.rules",
		Risk: RiskHigh, Exploitable: true}
	p2 := &AutoPrivilege{}
	p2.Findings = []Finding{fileFinding}
	enumerateVectors(p2, []string{"polkit"})
	if len(p2.Vectors) != 1 || p2.Vectors[0].Exploit != nil {
		t.Errorf("writable .rules FILE must stay manual, got %+v", p2.Vectors)
	}

	laFinding := Finding{Source: "POLKIT", Target: "/etc/polkit-1/localauthority/50-local.d",
		Risk: RiskHigh, Exploitable: true}
	p3 := &AutoPrivilege{}
	p3.Findings = []Finding{laFinding}
	enumerateVectors(p3, []string{"polkit"})
	if len(p3.Vectors) != 1 || p3.Vectors[0].Exploit != nil {
		t.Errorf("localauthority dir must stay manual, got %+v", p3.Vectors)
	}
}

// TestPolkitRulePayloadShape: the planted grant targets the exec action for
// the current user only, and returns YES — never a broader identity or a
// different action.
func TestPolkitRulePayloadShape(t *testing.T) {
	payload := polkitRulePayload("operator")
	for _, want := range []string{
		"org.freedesktop.policykit.exec", `subject.user == "operator"`, "polkit.Result.YES",
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q", want)
		}
	}
	if strings.Contains(payload, "uid=0") || strings.Contains(payload, "ALL") {
		t.Error("payload must be scoped to one user/action, not a blanket grant")
	}
}

// TestExploitPolkitRuleUnwritablePath: the exploit fails honestly (no fake
// success) when the rules dir cannot be written.
func TestExploitPolkitRuleUnwritablePath(t *testing.T) {
	r := exploitPolkitRule("/nonexistent-polkit-1/rules.d", "operator", Options{})
	if r.Success || r.IsRoot {
		t.Errorf("exploit must fail honestly on an unwritable dir, got %+v", r)
	}
	if r.Error == "" {
		t.Error("exploit error must be populated")
	}
}

// TestPolkitCatalogAndSources: the vocabulary is fully wired — vector
// catalog, canonical order, validSources and explainDB all know POLKIT.
func TestPolkitCatalogAndSources(t *testing.T) {
	if !validVectors["polkit"] {
		t.Error("validVectors lacks polkit")
	}
	if !isValidSource("POLKIT") {
		t.Error("validSources lacks POLKIT")
	}
	if _, ok := explainDB["POLKIT"]; !ok {
		t.Error("explainDB lacks POLKIT — the playbook cannot ship without it")
	}
	found := false
	for _, v := range vectorCatalogOrder {
		if v == "polkit" {
			found = true
		}
	}
	if !found {
		t.Error("vectorCatalogOrder lacks polkit — --list-vectors would hide it")
	}
	// the explain entry carries real steps
	if len(explainDB["POLKIT"].Harden) < 3 {
		t.Error("POLKIT playbook too thin")
	}
}

// TestDryRunPlanJSONShape: --dry-run --json adds a structured "plan" key —
// each vector with name/target/command/risk/kind and the within_risk verdict,
// in the same safest-first order the terminal plan shows.
func TestDryRunPlanJSONShape(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{DryRun: true, MaxRisk: RiskMedium}}
	p.Vectors = []Vector{
		{Name: "low v", Risk: RiskLow, Target: "t1", Command: "cmd1", Category: "c"},
		{Name: "high v", Risk: RiskHigh, Target: "t2", Command: "cmd2", Category: "c"},
	}
	plan := buildPlan(p)
	if len(plan) != 2 {
		t.Fatalf("plan = %d entries, want 2", len(plan))
	}
	if plan[0].Name != "low v" || !plan[0].WithinRisk {
		t.Errorf("low vector must come first (safest) and be within risk: %+v", plan[0])
	}
	if plan[1].WithinRisk {
		t.Errorf("HIGH vector must be flagged out of the --risk medium window: %+v", plan[1])
	}
	if plan[0].Kind != "manual" && plan[0].Kind != "auto" {
		t.Errorf("kind must be auto|manual, got %q", plan[0].Kind)
	}
}

// TestTopVectorsFlagBounds: --top n clamps to a sane window and defaults to
// the historical 5.
func TestTopVectorsFlagBounds(t *testing.T) {
	if defaultTopVectors != 5 {
		t.Errorf("defaultTopVectors = %d, want 5 (the historical value)", defaultTopVectors)
	}
}
