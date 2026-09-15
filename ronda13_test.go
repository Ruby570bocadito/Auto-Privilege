package main

import (
	"strings"
	"testing"
)

// ================================================================
// Ronda 13 — --min-score, --completion, v1.8.0
// ================================================================

// TestMinScoreGate: the posture gate trips when the score lands below the
// floor (exit 3 with the score-gate message), stays silent when the score
// clears it, and is disabled at 0 (the zero-value contract).
func TestMinScoreGate(t *testing.T) {
	// penalty: exploitable MEDIUM (4*3/2 = 6) + informational HIGH (7) = 13 → score 87
	findings := []Finding{
		{Source: "SUID", Risk: RiskMedium, Exploitable: true},
		{Source: "NOTE", Risk: RiskHigh, Exploitable: false},
	}
	mk := func(min int) *AutoPrivilege {
		return &AutoPrivilege{Opts: Options{MinScore: min}, Findings: findings}
	}
	if code, msg := computeExitCode(mk(90)); code != 3 || !strings.Contains(msg, "score gate: hardening score 87 < 90") {
		t.Errorf("score below floor: got (%d, %q)", code, msg)
	}
	if code, _ := computeExitCode(mk(88)); code != 3 {
		t.Errorf("score just below floor must trip, got %d", code)
	}
	if code, msg := computeExitCode(mk(87)); code != 0 || msg != "" {
		t.Errorf("score exactly at floor must NOT trip (gate is score < floor): got (%d, %q)", code, msg)
	}
	if code, msg := computeExitCode(mk(86)); code != 0 || msg != "" {
		t.Errorf("score above floor: got (%d, %q), want (0, \"\")", code, msg)
	}
	if code, _ := computeExitCode(mk(0)); code != 0 {
		t.Errorf("min-score 0 must disable the gate, got %d", code)
	}
}

// TestMinScorePrecedence: the posture gate has the LOWEST message
// precedence — a policy or regression verdict names its finding, which
// beats the generic "score too low" (all three exit 3 anyway).
func TestMinScorePrecedence(t *testing.T) {
	p := &AutoPrivilege{
		Opts: Options{
			MinScore:      100, // would trip: any finding drops the score below 100
			FailOn:        "high",
			FailOnEnabled: true,
			FailOnRisk:    RiskHigh,
		},
		Findings: []Finding{{Source: "SUID", Risk: RiskHigh, Exploitable: true}},
	}
	code, msg := computeExitCode(p)
	if code != 3 || !strings.Contains(msg, "policy gate") {
		t.Errorf("policy gate must win the message: got (%d, %q)", code, msg)
	}
	p2 := &AutoPrivilege{
		Opts: Options{MinScore: 100, FailOnNew: true, FailOnNewRisk: RiskSafe},
		Diff: &ReportDiff{New: []Finding{{Source: "CRED", Risk: RiskHigh, Exploitable: true}}, NewExploitable: 1},
	}
	code, msg = computeExitCode(p2)
	if code != 3 || !strings.Contains(msg, "regression gate") {
		t.Errorf("regression gate must win over score gate: got (%d, %q)", code, msg)
	}
}

// TestMinScoreIgnoresRootedClassic: the gate never masks the classic 0/1
// verdict when it passes — a gate in green falls through (round-8 contract).
func TestMinScoreIgnoresClassic(t *testing.T) {
	// Exploit attempted, no root → classic 1; gate trips above → 3 wins.
	trips := &AutoPrivilege{
		Opts:     Options{Exploit: true, MinScore: 100},
		Findings: []Finding{{Source: "SUID", Risk: RiskLow, Exploitable: true}},
	}
	if code, _ := computeExitCode(trips); code != 3 {
		t.Errorf("trip must beat classic 1, got %d", code)
	}
	// Same run with the gate disabled → classic 1 preserved.
	off := &AutoPrivilege{
		Opts:     Options{Exploit: true, MinScore: 0},
		Findings: []Finding{{Source: "SUID", Risk: RiskLow, Exploitable: true}},
	}
	if code, _ := computeExitCode(off); code != 1 {
		t.Errorf("gate off must fall through to classic 1, got %d", code)
	}
}

// TestCompletionCoversAllFlags: the generated scripts offer EVERY registered
// flag (plus help) — the generation reads the same registerFlags source the
// binary uses, so a new flag lands in the completion automatically.
func TestCompletionCoversAllFlags(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		out := captureStdout(t, func() {
			if err := printCompletion(shell); err != nil {
				t.Errorf("printCompletion(%s): %v", shell, err)
			}
		})
		if len(out) == 0 {
			t.Errorf("completion %s: empty script", shell)
		}
	}
}

// TestCompletionScriptShape pins one structural line per shell and verifies
// every flag name reaches each script (raw name for fish's -l, --name for
// bash/zsh).
func TestCompletionScriptShape(t *testing.T) {
	shells := map[string]func(out string) bool{
		"bash": func(out string) bool {
			return strings.Contains(out, "complete -F _autoprivilege_completions autoprivilege")
		},
		"zsh": func(out string) bool {
			return strings.Contains(out, "#compdef autoprivilege")
		},
		"fish": func(out string) bool {
			return strings.Contains(out, "complete -c autoprivilege")
		},
	}
	for shell, shape := range shells {
		out := captureStdout(t, func() { _ = printCompletion(shell) })
		if !shape(out) {
			t.Errorf("completion %s: structural line missing", shell)
		}
		for _, f := range completionFlagNames() {
			needle := "--" + f[0]
			if shell == "fish" {
				needle = "-l " + f[0]
			}
			if !strings.Contains(out, needle) {
				t.Errorf("completion %s: flag %q missing", shell, f[0])
			}
		}
	}
}

// TestCompletionUnknownShell: an unsupported shell is a caller error (exit 2
// upstream) with the valid options in the message — never a silent bash
// script for a fish user.
func TestCompletionUnknownShell(t *testing.T) {
	err := printCompletion("powershell")
	if err == nil || !strings.Contains(err.Error(), "bash, zsh, fish") {
		t.Errorf("unknown shell: got %v, want error naming the valid shells", err)
	}
	// case-insensitive
	if err := printCompletion("BASH"); err != nil {
		t.Errorf("case-insensitive shell: %v", err)
	}
}

// TestVersionPinnedTo180: the round-13 decision — the three-round feature
// backlog ships as v1.8.0. Pinning it here so a revert is deliberate.
func TestVersionPinnedTo180(t *testing.T) {
	if Version != "1.8.0" {
		t.Errorf("Version = %q, want 1.8.0", Version)
	}
}
