package autopriv

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ================================================================
// Baseline diff + policy gate (--baseline / --fail-on)
// ================================================================

// ReportDiff is the baseline-comparison block embedded in the JSON report
// (key "diff") and the markdown report when --baseline points at a previous
// --json/--output document. New findings are the actionable surface ("what
// grew since the last audit"); Resolved is the hardening payoff.
type ReportDiff struct {
	BaselinePath   string      `json:"baseline_path"`
	BaselineDate   time.Time   `json:"baseline_date"`
	New            []Finding   `json:"new"`
	Resolved       []Finding   `json:"resolved"`
	NewExploitable int         `json:"new_exploitable"`
	ScoreAfter     int         `json:"score_after"`
	SummaryBefore  jsonSummary `json:"summary_before"`
}

// loadBaseline reads and validates a previous Auto-Privilege JSON report.
// The tool check ("tool" == "Auto-Privilege") keeps an arbitrary JSON file
// (jq output, CI metadata…) from being silently diffed against itself.
func loadBaseline(path string) (*jsonReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep jsonReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("%s is not a valid Auto-Privilege JSON report: %v", path, err)
	}
	if rep.Tool != "Auto-Privilege" {
		return nil, fmt.Errorf("%s is not an Auto-Privilege report (tool=%q)", path, rep.Tool)
	}
	return &rep, nil
}

// findingKey identifies a finding across runs: same source AND target means
// "the same issue", even if the description text was reworded between tool
// versions. Source alone is not enough (SUDO fires per rule), target alone
// neither (/etc/shadow has a readable and a writable finding).
func findingKey(f Finding) string {
	return f.Source + "\x00" + f.Target
}

// diffReports classifies the current findings against a baseline report:
// NEW = present now, absent before; RESOLVED = present before, absent now.
// NewExploitable counts new findings that are directly actionable — the
// number a hardening gate cares about. Keys are deduplicated within each
// side so duplicate findings never double-count. New/Resolved are never nil
// (they render as [] in JSON, not null).
func diffReports(before *jsonReport, current []Finding) *ReportDiff {
	prev := map[string]bool{}
	for _, f := range before.Findings {
		prev[findingKey(f)] = true
	}
	d := &ReportDiff{
		BaselineDate:  before.Timestamp,
		New:           []Finding{},
		Resolved:      []Finding{},
		ScoreAfter:    hardeningScore(current),
		SummaryBefore: before.Summary,
	}
	// Mirror buildSummary's convention: Risks never renders as null.
	if d.SummaryBefore.Risks == nil {
		d.SummaryBefore.Risks = map[string]int{}
	}
	seen := map[string]bool{}
	for _, f := range current {
		k := findingKey(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		if !prev[k] {
			d.New = append(d.New, f)
			if f.Exploitable {
				d.NewExploitable++
			}
		}
	}
	for _, f := range before.Findings {
		k := findingKey(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		d.Resolved = append(d.Resolved, f)
	}
	return d
}

// parseFailOn validates the --fail-on value: empty disables the gate, a risk
// name sets the threshold. "safe" is rejected on purpose: every finding has
// risk >= SAFE, so it would just be a confusing alias for low.
func parseFailOn(s string) (RiskLevel, bool, error) {
	if s == "" {
		return RiskSafe, false, nil
	}
	switch strings.ToLower(s) {
	case "low":
		return RiskLow, true, nil
	case "medium":
		return RiskMedium, true, nil
	case "high":
		return RiskHigh, true, nil
	case "danger":
		return RiskDanger, true, nil
	case "safe":
		return RiskSafe, false, errors.New(`invalid --fail-on "safe": use low to fail on any actionable finding`)
	}
	return RiskSafe, false, fmt.Errorf("invalid --fail-on %q (valid: low, medium, high, danger)", s)
}

// policyGateCount returns how many exploitable findings sit at or above the
// configured --fail-on threshold (0 when the gate is disabled).
func policyGateCount(p *AutoPrivilege) int {
	if !p.Opts.FailOnEnabled {
		return 0
	}
	n := 0
	for _, f := range p.Findings {
		if f.Exploitable && f.Risk >= p.Opts.FailOnRisk {
			n++
		}
	}
	return n
}
