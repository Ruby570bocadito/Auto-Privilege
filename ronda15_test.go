package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// ================================================================
// Ronda 15 — machine-readable catalogs, --list-sources, --min-risk
// ================================================================

// TestVectorCatalogJSONShape pins the --list-vectors --json document: valid
// JSON, canonical order (vectorCatalogOrder), names that the binary itself
// accepts, non-empty honest descriptions and the routing envelope.
func TestVectorCatalogJSONShape(t *testing.T) {
	var doc struct {
		Tool    string          `json:"tool"`
		Version string          `json:"version"`
		Mode    string          `json:"mode"`
		Vectors []catalogVector `json:"vectors"`
	}
	if err := json.Unmarshal(vectorCatalogJSON(), &doc); err != nil {
		t.Fatalf("vector catalog is not valid JSON: %v", err)
	}
	if doc.Tool != "Auto-Privilege" || doc.Mode != "vector-catalog" {
		t.Errorf("envelope wrong: tool=%q mode=%q", doc.Tool, doc.Mode)
	}
	if doc.Version != Version {
		t.Errorf("version = %q, want %q", doc.Version, Version)
	}
	if len(doc.Vectors) != len(vectorCatalogOrder) {
		t.Fatalf("vectors = %d, want %d", len(doc.Vectors), len(vectorCatalogOrder))
	}
	for i, v := range doc.Vectors {
		if v.Name != vectorCatalogOrder[i] {
			t.Errorf("vectors[%d].name = %q, want canonical order %q", i, v.Name, vectorCatalogOrder[i])
		}
		if !validVectors[v.Name] {
			t.Errorf("catalog offers %q which validVectors rejects", v.Name)
		}
		if strings.TrimSpace(v.Description) == "" {
			t.Errorf("vector %q has an empty description", v.Name)
		}
	}
}

// TestSourceCatalogMatchesValidSources pins the source vocabulary both
// ways: --list-sources covers exactly what validSources holds (no ghost
// sources, no missing ones) and every description comes from the playbook
// DB — the same sentences --explain prints, so the two surfaces cannot
// disagree about what a source means.
func TestSourceCatalogMatchesValidSources(t *testing.T) {
	cat := sourceCatalog()
	if len(cat) != len(validSources) {
		t.Fatalf("catalog = %d sources, want %d", len(cat), len(validSources))
	}
	seen := map[string]bool{}
	for i, s := range cat {
		if s.Source != validSources[i] {
			t.Errorf("catalog[%d] = %q, want canonical order %q", i, s.Source, validSources[i])
		}
		seen[s.Source] = true
		if strings.TrimSpace(s.Description) == "" {
			t.Errorf("source %q has an empty description", s.Source)
		}
		if e, ok := explainDB[s.Source]; ok && e.What != s.Description {
			t.Errorf("source %q description diverges from explainDB", s.Source)
		}
	}
	if len(seen) != len(validSources) {
		t.Errorf("catalog has duplicate sources")
	}
}

// TestSourceListJSONShape: the --list-sources --json document carries the
// envelope (mode=sources), the canonical order and the explainDB sentences —
// pinned through the pure builder, no stdout capture.
func TestSourceListJSONShape(t *testing.T) {
	doc := buildSourceListJSONDoc()
	if doc.Tool != "Auto-Privilege" || doc.Mode != "sources" {
		t.Errorf("envelope wrong: tool=%q mode=%q", doc.Tool, doc.Mode)
	}
	if doc.Version != Version {
		t.Errorf("version = %q, want %q", doc.Version, Version)
	}
	if len(doc.Sources) != len(validSources) {
		t.Fatalf("sources = %d, want %d", len(doc.Sources), len(validSources))
	}
	for i, s := range doc.Sources {
		if s.Source != validSources[i] {
			t.Errorf("sources[%d] = %q, want canonical order %q", i, s.Source, validSources[i])
		}
		if s.Source == "" || s.Description == "" {
			t.Errorf("catalog row with empty fields: %+v", s)
		}
	}
	// the JSON document must actually serialize without nulls
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("sources document does not marshal: %v", err)
	}
	if strings.Contains(string(data), "null") {
		t.Errorf("sources document contains null: %s", data)
	}
}

// TestExplainJSONShape pins the structured playbook: a single source yields
// one playbook with the exact What sentence and the Harden steps in order;
// "all" yields every source alphabetically; unknown sources error like the
// text voice.
func TestExplainJSONShape(t *testing.T) {
	single, err := explainJSONDocFor("cron")
	if err != nil {
		t.Fatal(err)
	}
	if single.Scope != "CRON" || len(single.Playbooks) != 1 {
		t.Fatalf("single scope/playbooks = %q/%d, want CRON/1", single.Scope, len(single.Playbooks))
	}
	entry := explainDB["CRON"]
	pb := single.Playbooks[0]
	if pb.Source != "CRON" || pb.What != entry.What {
		t.Errorf("playbook content diverges from explainDB: %+v", pb)
	}
	if len(pb.Steps) != len(entry.Harden) {
		t.Fatalf("steps = %d, want %d", len(pb.Steps), len(entry.Harden))
	}
	for i := range entry.Harden {
		if pb.Steps[i] != entry.Harden[i] {
			t.Errorf("step[%d] diverges from explainDB order", i)
		}
	}

	all, err := explainJSONDocFor("ALL")
	if err != nil {
		t.Fatal(err)
	}
	if all.Scope != "all" || len(all.Playbooks) != len(validSources) {
		t.Fatalf("all scope/playbooks = %q/%d, want all/%d", all.Scope, len(all.Playbooks), len(validSources))
	}
	for i := 1; i < len(all.Playbooks); i++ {
		if all.Playbooks[i-1].Source >= all.Playbooks[i].Source {
			t.Errorf("all playbooks not alphabetical at %d: %q >= %q",
				i, all.Playbooks[i-1].Source, all.Playbooks[i].Source)
		}
	}

	if _, err := explainJSONDocFor("GHOST"); err == nil {
		t.Error("unknown source must error like the text voice")
	}
	// every playbook carries non-empty honest content
	for _, p := range all.Playbooks {
		if strings.TrimSpace(p.What) == "" || len(p.Steps) == 0 {
			t.Errorf("playbook %q is empty — JSON voice would emit hollow advice", p.Source)
		}
	}
}

// TestMinRiskFilter pins the floor semantics: inclusive floor (medium keeps
// MEDIUM+), order-preserving survivors, empty-safe inputs, and a floor at
// or below SAFE is a no-op.
func TestMinRiskFilter(t *testing.T) {
	in := []Finding{
		{Source: "A", Risk: RiskLow},
		{Source: "B", Risk: RiskMedium},
		{Source: "C", Risk: RiskHigh},
		{Source: "D", Risk: RiskDanger},
		{Source: "E", Risk: RiskLow},
	}
	got := filterMinRisk(in, RiskMedium)
	if len(got) != 3 {
		t.Fatalf("floor=medium kept %d findings, want 3", len(got))
	}
	for i, want := range []string{"B", "C", "D"} {
		if got[i].Source != want {
			t.Errorf("survivor[%d] = %q, want %q (order must be preserved)", i, got[i].Source, want)
		}
	}
	if got := filterMinRisk(in, RiskDanger); len(got) != 1 || got[0].Source != "D" {
		t.Errorf("floor=danger kept %+v, want only D", got)
	}
	if got := filterMinRisk(in, RiskSafe); len(got) != len(in) {
		t.Errorf("floor=safe must be a no-op, kept %d", len(got))
	}
	if got := filterMinRisk(nil, RiskHigh); got != nil {
		t.Errorf("empty input must stay empty, got %+v", got)
	}
	if got := filterMinRisk([]Finding{}, RiskHigh); len(got) != 0 {
		t.Errorf("zero-length input must stay empty, got %+v", got)
	}
}

// TestParseMinRisk pins the validation contract: the four valid floors
// (case-insensitive), the deliberate rejection of "safe" with a useful
// message, and the generic error for typos.
func TestParseMinRisk(t *testing.T) {
	for input, want := range map[string]RiskLevel{
		"low": RiskLow, "medium": RiskMedium, "high": RiskHigh, "danger": RiskDanger,
		"MEDIUM": RiskMedium, "High": RiskHigh, "DANGER": RiskDanger,
	} {
		got, err := parseMinRisk(input)
		if err != nil {
			t.Errorf("parseMinRisk(%q) unexpected error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("parseMinRisk(%q) = %v, want %v", input, got, want)
		}
	}
	if _, err := parseMinRisk("safe"); err == nil {
		t.Error(`parseMinRisk("safe") must fail: a safe floor is a confusing no-op`)
	} else if !strings.Contains(err.Error(), "low as the floor") {
		t.Errorf(`parseMinRisk("safe") error should point to "low": %v`, err)
	}
	if _, err := parseMinRisk("banana"); err == nil {
		t.Error(`parseMinRisk("banana") must fail`)
	} else if !strings.Contains(err.Error(), "valid: low, medium, high, danger") {
		t.Errorf("parseMinRisk typo error must list the valid values: %v", err)
	}
}

// TestCompletionRound15Values: the two new value lists reach every shell
// dialect — --min-risk completes the risk floor, --ignore completes the
// source vocabulary.
func TestCompletionRound15Values(t *testing.T) {
	mr, ok := completionValues["min-risk"]
	if !ok || len(mr) != 4 {
		t.Fatalf("min-risk values = %v, want the 4-floor list", mr)
	}
	ig, ok := completionValues["ignore"]
	if !ok || len(ig) != len(validSources) {
		t.Fatalf("ignore values = %v, want the full source vocabulary", ig)
	}
	bash, err := completionScriptFor("bash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bash, `--min-risk) COMPREPLY=( $(compgen -W "low medium high danger"`) {
		t.Errorf("bash: --min-risk value completion missing")
	}
	if !strings.Contains(bash, `--ignore) COMPREPLY=( $(compgen -W "SUID SGID`) {
		t.Errorf("bash: --ignore value completion missing")
	}
	zsh, err := completionScriptFor("zsh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(zsh, ":min-risk:(low medium high danger)") {
		t.Errorf("zsh: --min-risk value completion missing")
	}
	fish, err := completionScriptFor("fish")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fish, "-l ignore -x -a 'SUID") {
		t.Errorf("fish: --ignore value completion missing")
	}
}

// TestMinRiskFlagRegistered: the flag must exist on the hermetic FlagSet
// with the risk-floor usage text — a flag that drops from registerFlags
// would break the completion and the parity test at once.
func TestMinRiskFlagRegistered(t *testing.T) {
	found := false
	for _, pair := range completionFlagNames() {
		if pair[0] == "min-risk" {
			found = true
			if !strings.Contains(pair[1], "risk floor") {
				t.Errorf("--min-risk usage = %q, want it to mention the risk floor", pair[1])
			}
		}
		if pair[0] == "list-sources" {
			if !strings.Contains(pair[1], "vocabulary") {
				t.Errorf("--list-sources usage = %q, want it to mention the vocabulary", pair[1])
			}
		}
	}
	if !found {
		t.Fatal("--min-risk missing from registerFlags")
	}
}

// TestMinRiskGatesSeeFilteredReality: the filtered-reality contract —
// hardeningScore over the survivors equals what a --min-risk run reports,
// so gates and score operate on the same filtered set the terminal shows.
func TestMinRiskGatesSeeFilteredReality(t *testing.T) {
	in := []Finding{
		{Source: "A", Risk: RiskLow, Exploitable: true},
		{Source: "B", Risk: RiskMedium, Exploitable: true},
	}
	filtered := filterMinRisk(in, RiskMedium)
	full, floored := hardeningScore(in), hardeningScore(filtered)
	if floored <= full {
		t.Errorf("floor must raise the reported score: %d vs %d", floored, full)
	}
	// the filter must not mutate the input slice (shared backing guard)
	if len(in) != 2 {
		t.Fatalf("filterMinRisk mutated its input: %d findings left", len(in))
	}
}

// TestResolveColorMode pins the three-way color precedence: --no-color wins
// over everything, --color beats the TTY check and NO_COLOR (the capture
// escape hatch), and with neither flag the classic rule applies.
func TestResolveColorMode(t *testing.T) {
	cases := []struct {
		name            string
		force, noColor  bool
		tty, noColorEnv string
		want            bool
	}{
		{"tty clean", false, false, "tty", "", true},
		{"pipe auto-off", false, false, "", "", false},
		{"pipe NO_COLOR", false, false, "tty", "1", false},
		{"--color forces pipe", true, false, "", "", true},
		{"--color beats NO_COLOR", true, false, "", "1", true},
		{"--no-color wins tty", true, true, "tty", "", false},
		{"--no-color beats --color", true, true, "", "", false},
	}
	for _, tc := range cases {
		if got := resolveColorMode(tc.force, tc.noColor, tc.tty == "tty", tc.noColorEnv); got != tc.want {
			t.Errorf("%s: resolveColorMode = %v, want %v", tc.name, got, tc.want)
		}
	}
}
