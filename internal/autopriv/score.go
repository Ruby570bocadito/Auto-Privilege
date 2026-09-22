package autopriv

// ================================================================
// Hardening score (--score is implicit: the metric always ships)
// ================================================================

// hardeningScore distills the findings into a single 0–100 posture number
// so the "did hardening work?" question has a one-glance answer: --baseline
// says what changed, the score says how much it matters. The formula is
// deliberately simple and fully deterministic (same findings → same score,
// always): a clean host scores 100, every finding subtracts a penalty
// weighted by risk, with a 1.5x multiplier for exploitable findings — the
// directly actionable surface a hardening gate cares about — and
// informational findings cost a third of their exploitable weight (they
// are investigation leads, not open doors).
//
// The exact per-finding penalties:
//
//	risk    | exploitable | informational
//	--------+-------------+---------------
//	LOW     |      3      |       2
//	MEDIUM  |      6      |       4
//	HIGH    |     10      |       7
//	DANGER  |     15      |      10
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
		base = 2
	case RiskMedium:
		base = 4
	case RiskHigh:
		base = 7
	case RiskDanger:
		base = 10
	default:
		// RiskSafe is not a posture hit: nothing to subtract.
		return 0
	}
	if f.Exploitable {
		// 1.5x, rounded down — integer math stays deterministic on every
		// platform and the exact weights are documented in the table above.
		return base * 3 / 2
	}
	return base
}
