package autopriv

import (
	"testing"
	"time"
)

// syntheticOrder builds a deterministic scanner set: each scanner appends
// findings tagged with its own source so the merged order is unambiguous.
func syntheticOrder() []func(*AutoPrivilege) {
	return []func(*AutoPrivilege){
		func(p *AutoPrivilege) {
			addFinding(p, "AAA", "a1", "first", RiskLow, true)
			addFinding(p, "AAA", "a2", "second", RiskMedium, false)
		},
		func(p *AutoPrivilege) {
			addFinding(p, "BBB", "b1", "third", RiskHigh, true)
		},
		func(p *AutoPrivilege) {
			addFinding(p, "CCC", "c1", "fourth", RiskLow, false)
			addFinding(p, "CCC", "c2", "fifth", RiskLow, false)
		},
		func(p *AutoPrivilege) {
			addFinding(p, "DDD", "d1", "sixth", RiskMedium, true)
		},
	}
}

func findingsEqual(a, b []Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestScanAllParallelDeterministic pins THE parallel contract: the merged
// findings are byte-identical to the sequential run, in scannerOrder —
// whatever the goroutines' completion order was. Everything downstream
// (diff keys, markdown tables, jq pipelines) depends on this stability.
func TestScanAllParallelDeterministic(t *testing.T) {
	orig := scannerOrder
	defer func() { scannerOrder = orig }()

	seq := &AutoPrivilege{Opts: Options{}}
	scannerOrder = syntheticOrder()
	scanAll(seq) // Parallel=false → sequential path

	scannerOrder = syntheticOrder()
	par := &AutoPrivilege{Opts: Options{Parallel: true}}
	scanAll(par)

	if !findingsEqual(seq.Findings, par.Findings) {
		t.Fatalf("parallel findings must be byte-identical to sequential:\nseq=%v\npar=%v",
			seq.Findings, par.Findings)
	}
	if len(par.Findings) != 6 {
		t.Errorf("all findings must survive the merge, got %d", len(par.Findings))
	}
	if par.Findings[0].Source != "AAA" || par.Findings[2].Source != "BBB" ||
		par.Findings[5].Source != "DDD" {
		t.Errorf("merge must follow scannerOrder, got %v", par.Findings)
	}
}

// TestScanAllParallelOutOfOrderCompletion forces the LATER scanners to
// finish first (long sleeps in the first two): a merge that appends in
// completion order instead of index order would produce BBB/AAA — exactly
// the contamination this guard exists to catch.
func TestScanAllParallelOutOfOrderCompletion(t *testing.T) {
	orig := scannerOrder
	defer func() { scannerOrder = orig }()

	scannerOrder = []func(*AutoPrivilege){
		func(p *AutoPrivilege) {
			time.Sleep(120 * time.Millisecond)
			addFinding(p, "SLOW1", "s1", "must be first", RiskLow, true)
		},
		func(p *AutoPrivilege) {
			time.Sleep(60 * time.Millisecond)
			addFinding(p, "SLOW2", "s2", "must be second", RiskLow, true)
		},
		func(p *AutoPrivilege) {
			addFinding(p, "FAST", "f1", "finishes first, reports last", RiskLow, true)
		},
	}

	p := &AutoPrivilege{Opts: Options{Parallel: true}}
	scanAll(p)

	if len(p.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(p.Findings))
	}
	for i, want := range []string{"SLOW1", "SLOW2", "FAST"} {
		if p.Findings[i].Source != want {
			t.Errorf("merged[%d].Source = %q, want %q — merge must follow scannerOrder, not completion order",
				i, p.Findings[i].Source, want)
		}
	}
}

// TestScanAllStealthForcesSequential documents the deliberate interaction:
// --stealth exists to pace host-visible probes, so it wins over --parallel
// (and both together stay correct).
func TestScanAllStealthForcesSequential(t *testing.T) {
	orig := scannerOrder
	defer func() { scannerOrder = orig }()

	seq := &AutoPrivilege{Opts: Options{Stealth: true}}
	scannerOrder = syntheticOrder()
	scanAll(seq)

	scannerOrder = syntheticOrder()
	both := &AutoPrivilege{Opts: Options{Stealth: true, Parallel: true}}
	scanAll(both)

	if !findingsEqual(seq.Findings, both.Findings) {
		t.Errorf("stealth+parallel must behave exactly like stealth-sequential:\n%v\n%v",
			seq.Findings, both.Findings)
	}
}
