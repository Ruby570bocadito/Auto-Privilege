package main

import (
	"strings"
	"testing"
)

// --- hardeningScore / findingPenalty ---

func TestHardeningScoreEmpty(t *testing.T) {
	if got := hardeningScore(nil); got != 100 {
		t.Errorf("clean host must score 100, got %d", got)
	}
	if got := hardeningScore([]Finding{}); got != 100 {
		t.Errorf("empty findings must score 100, got %d", got)
	}
}

func TestFindingPenaltyWeights(t *testing.T) {
	cases := []struct {
		f    Finding
		want int
	}{
		{Finding{Risk: RiskSafe, Exploitable: true}, 0},   // SAFE is never a hit
		{Finding{Risk: RiskLow, Exploitable: true}, 3},    // 2 * 1.5
		{Finding{Risk: RiskLow, Exploitable: false}, 2},   //
		{Finding{Risk: RiskMedium, Exploitable: true}, 6}, // 4 * 1.5
		{Finding{Risk: RiskMedium, Exploitable: false}, 4},
		{Finding{Risk: RiskHigh, Exploitable: true}, 10}, // 7 * 1.5 = 10.5 → 10
		{Finding{Risk: RiskHigh, Exploitable: false}, 7},
		{Finding{Risk: RiskDanger, Exploitable: true}, 15}, // 10 * 1.5
		{Finding{Risk: RiskDanger, Exploitable: false}, 10},
	}
	for _, c := range cases {
		if got := findingPenalty(c.f); got != c.want {
			t.Errorf("findingPenalty(%v risk=%v expl=%v) = %d, want %d",
				c.f.Source, c.f.Risk, c.f.Exploitable, got, c.want)
		}
	}
}

func TestHardeningScoreDeterministicAndClamped(t *testing.T) {
	findings := []Finding{
		{Source: "A", Risk: RiskHigh, Exploitable: true},
		{Source: "B", Risk: RiskMedium, Exploitable: false},
		{Source: "C", Risk: RiskLow, Exploitable: true},
	}
	want := 100 - 10 - 4 - 3 // 83
	if got := hardeningScore(findings); got != want {
		t.Errorf("hardeningScore = %d, want %d", got, want)
	}
	// Determinism: the same findings always produce the same score.
	for i := 0; i < 5; i++ {
		if got := hardeningScore(findings); got != want {
			t.Fatalf("score must be deterministic, run %d gave %d", i, got)
		}
	}
	// Clamp: 8 DANGER exploitable = 120 penalty → floor at 0, never negative.
	if got := hardeningScore([]Finding{
		{Risk: RiskDanger, Exploitable: true}, {Risk: RiskDanger, Exploitable: true},
		{Risk: RiskDanger, Exploitable: true}, {Risk: RiskDanger, Exploitable: true},
		{Risk: RiskDanger, Exploitable: true}, {Risk: RiskDanger, Exploitable: true},
		{Risk: RiskDanger, Exploitable: true}, {Risk: RiskDanger, Exploitable: true},
	}); got != 0 {
		t.Errorf("catastrophic host must clamp to 0, got %d", got)
	}
}

// --- score integration: JSON summary + markdown + diff ---

func TestBuildSummaryIncludesScore(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{
		{Source: "FILE", Target: "/etc/shadow", Risk: RiskDanger, Exploitable: true},
		{Source: "CRED", Target: "/x", Risk: RiskLow, Exploitable: false},
	}
	s := buildSummary(p)
	if want := 100 - 15 - 2; s.Score != want {
		t.Errorf("summary.Score = %d, want %d", s.Score, want)
	}
}

func TestMarkdownSummaryScoreRow(t *testing.T) {
	s := jsonSummary{Findings: 2, Exploitable: 1, Score: 85, Risks: map[string]int{"HIGH": 1}}
	out := markdownSummary(s)
	if !strings.Contains(out, "| Hardening score | 85/100 |") {
		t.Errorf("markdown summary must carry the score row, got:\n%s", out)
	}
}

func TestMarkdownDiffScoreTrajectory(t *testing.T) {
	// Baseline WITH score → "before → after" rendering.
	d := &ReportDiff{
		New: []Finding{}, Resolved: []Finding{},
		ScoreAfter:    83,
		SummaryBefore: jsonSummary{Score: 91, Risks: map[string]int{}},
	}
	out := markdownDiff(d)
	if !strings.Contains(out, "| Score | 91 → 83/100 |") {
		t.Errorf("markdown diff must render the score trajectory, got:\n%s", out)
	}
	// Baseline PREDATING the metric (score 0) → honest "unknown" rendering,
	// never a fabricated 0 → X regression.
	d2 := &ReportDiff{New: []Finding{}, Resolved: []Finding{}, ScoreAfter: 83,
		SummaryBefore: jsonSummary{Risks: map[string]int{}}}
	out2 := markdownDiff(d2)
	if !strings.Contains(out2, "83/100 (baseline predates scoring)") {
		t.Errorf("pre-metric baseline must render unknown-baseline score, got:\n%s", out2)
	}
	if strings.Contains(out2, "0 → 83") {
		t.Errorf("pre-metric baseline must not fabricate a 0→X trajectory, got:\n%s", out2)
	}
}

func TestDiffReportsComputesScoreAfter(t *testing.T) {
	before := &jsonReport{Tool: "Auto-Privilege", Findings: []Finding{
		{Source: "FILE", Target: "/etc/shadow", Risk: RiskDanger, Exploitable: true},
	}}
	current := []Finding{
		{Source: "CRED", Target: "/x", Risk: RiskLow, Exploitable: false},
	}
	d := diffReports(before, current)
	if want := 100 - 2; d.ScoreAfter != want {
		t.Errorf("diff.ScoreAfter = %d, want %d", d.ScoreAfter, want)
	}
}
