package autopriv

// ================================================================
// Hardening score (--score is implicit: the metric always ships)
// ================================================================

// hardeningScore distills the findings into a single 0–100 posture number
// so the "did hardening work?" question has a one-glance answer: --baseline
// says what changed, the score says how much it matters. The formula is
// deliberately simple and fully deterministic (same findings → same score,
// always): a clean host scores 100, every finding subtracts a penalty
// weighted by risk.
//
// v2.0 rebalance (audit INC-2): the old table charged informational
// findings 2/4/7/10 — a pristine container with seventeen distribution-
// baseline SUID binaries and one container-context note bled to 62/100 and
// --min-score 90 failed on a clean system. Exploitability is now the
// dominant axis: an exploitable finding costs what it always cost, an
// informational lead costs about a third of it (they are investigation
// leads — version heuristics, context notes, verify-first items — not open
// doors).
//
// The exact per-finding penalties:
//
//	risk    | exploitable | informational
//	--------+-------------+---------------
//	LOW     |      3      |       1
//	MEDIUM  |      6      |       2
//	HIGH    |     10      |       3
//	DANGER  |     15      |       5
//
// The score is clamped at 0: a catastrophically misconfigured host can
// never render as negative (and old baselines predating the metric simply
// carry score 0 — the diff renderer says "unknown" instead of "0→X").
func hardeningScore(findings []Finding) int {
	score := 100
	for _, f := range findings {
		score -= findingPenalty(f)
	}
	if score < 0 {
		return 0
	}
	return score
}

func findingPenalty(f Finding) int {
	var base int
	switch f.Risk {
	case RiskLow:
		base = 1
	case RiskMedium:
		base = 2
	case RiskHigh:
		base = 3
	case RiskDanger:
		base = 5
	default:
		// RiskSafe is not a posture hit: nothing to subtract.
		return 0
	}
	if f.Exploitable {
		// Integer math stays deterministic on every platform; the exact
		// weights are documented in the table above.
		switch f.Risk {
		case RiskLow:
			return 3
		case RiskMedium:
			return 6
		case RiskHigh:
			return 10
		case RiskDanger:
			return 15
		}
	}
	return base
}
