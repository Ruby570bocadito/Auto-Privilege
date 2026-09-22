package autopriv

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// jsonSummary is the at-a-glance counts block of the machine-readable report.
// It lives under the "summary" key of the --json output — the shape both
// READMEs document for `jq '.summary'`. Score is the hardening posture
// (0–100, see score.go) — always present so jq consumers can chart it.
type jsonSummary struct {
	Findings    int            `json:"findings"`
	Exploitable int            `json:"exploitable"`
	Score       int            `json:"score"`
	Vectors     int            `json:"vectors"`
	Auto        int            `json:"auto"`
	Manual      int            `json:"manual"`
	Risks       map[string]int `json:"risks"`
	Rooted      bool           `json:"rooted"`
}

// buildSummary aggregates findings and vectors into a jsonSummary. Risk
// buckets with zero hits are omitted so the JSON matches the terminal
// summary; Risks is never nil so it renders as {} instead of null.
func buildSummary(p *AutoPrivilege) jsonSummary {
	s := jsonSummary{
		Findings: len(p.Findings),
		Score:    hardeningScore(p.Findings),
		Vectors:  len(p.Vectors),
		Rooted:   p.Rooted || isRoot(),
		Risks:    map[string]int{},
	}
	for _, f := range p.Findings {
		if f.Exploitable {
			s.Exploitable++
		}
		s.Risks[f.Risk.String()]++
	}
	for _, v := range p.Vectors {
		if v.Exploit == nil {
			s.Manual++
		} else {
			s.Auto++
		}
	}
	return s
}

// jsonReport is the enriched machine-readable report printed by --json.
// Diff is nil (and omitted from the JSON) unless --baseline was given.
type jsonReport struct {
	Tool       string      `json:"tool"`
	Version    string      `json:"version"`
	Host       string      `json:"host"`
	User       string      `json:"user"`
	GOOS       string      `json:"goos"`
	GOArch     string      `json:"goarch"`
	Timestamp  time.Time   `json:"timestamp"`
	DurationMS int64       `json:"duration_ms"`
	Rooted     bool        `json:"rooted"`
	Summary    jsonSummary `json:"summary"`
	Diff       *ReportDiff `json:"diff,omitempty"`
	// Plan is filled only on --dry-run runs: the structured execution plan
	// (what --exploit WOULD run, safest first, with the within-risk verdict).
	// Omitted otherwise -- a non-dry run reports what DID happen.
	Plan     []planEntry `json:"plan,omitempty"`
	Findings []Finding   `json:"findings"`
	Vectors  []Vector    `json:"vectors"`
}

// planEntry is one row of the --dry-run --json plan: the same execution
// plan the terminal shows (safest first), structured so CI can preview what
// an --exploit run WOULD do without running it. Kind is auto|manual;
// WithinRisk mirrors the [skip] verdict of the terminal plan.
type planEntry struct {
	Name       string `json:"name"`
	Risk       string `json:"risk"`
	Target     string `json:"target"`
	Command    string `json:"command"`
	Kind       string `json:"kind"`
	WithinRisk bool   `json:"within_risk"`
}

// buildPlan renders the execution plan (pure -- the JSON printer and the
// terminal printer share the sortedVectors order, so the two voices can
// never disagree about what would run).
func buildPlan(p *AutoPrivilege) []planEntry {
	out := []planEntry{}
	for _, v := range sortedVectors(p.Vectors) {
		kind := "auto"
		if v.Exploit == nil {
			kind = "manual"
		}
		out = append(out, planEntry{
			Name: v.Name, Risk: v.Risk.String(), Target: v.Target,
			Command: v.Command, Kind: kind, WithinRisk: v.Risk <= p.Opts.MaxRisk,
		})
	}
	return out
}

func buildReport(p *AutoPrivilege) jsonReport {
	vectors := make([]Vector, len(p.Vectors))
	copy(vectors, p.Vectors)
	findings := p.Findings
	if findings == nil {
		findings = []Finding{}
	}
	return jsonReport{
		Tool:       "Auto-Privilege",
		Version:    Version,
		Host:       hostname(),
		User:       currentUsername(),
		GOOS:       runtime.GOOS,
		GOArch:     runtime.GOARCH,
		Timestamp:  time.Now().UTC(),
		DurationMS: time.Since(p.Started).Milliseconds(),
		Rooted:     p.Rooted || isRoot(),
		Summary:    buildSummary(p),
		Diff:       p.Diff,
		Plan:       planOrNil(p),
		Findings:   findings,
		Vectors:    vectors,
	}
}

// planOrNil keeps the plan key out of the JSON unless --dry-run asked for
// it -- a non-dry run reports what DID happen, not what would have.
func planOrNil(p *AutoPrivilege) []planEntry {
	if !p.Opts.DryRun {
		return nil
	}
	return buildPlan(p)
}

// ExportJSON prints the enriched machine-readable report to stdout.
func (p *AutoPrivilege) ExportJSON() error {
	data, err := marshalJSON(buildReport(p))
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// atomicWriteFile persists data via temp-file + rename in the destination
// directory: a crash (or an OOM kill mid-scan in CI) can never leave a
// TRUNCATED report behind — the artifact a --fail-on/--fail-on-new gate or
// a --baseline diff reads next run. Rename within the same filesystem is
// atomic on POSIX, so readers see either the old file or the complete new
// one, never a half-written document.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// The temp file inherited a umask-affected mode; pin the requested one
	// before the rename (0600 for reports is a security property, not a
	// courtesy).
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ensureOutputDir creates the parent directory of a report path (0700) so
// `--html out/report.html` does not die at write time because out/ was
// never created — a failure AFTER a full scan is the worst moment to learn
// the directory was missing. Called fail-fast in run() for every report
// path, before any scan work. The 0700 mode keeps the created directory as
// private as the 0600 reports that land inside it; an existing directory is
// left untouched (MkdirAll is a no-op on existing dirs, regardless of mode
// — we do not chmod other people's directories behind their back).
// A non-directory file in the way is an error, not a silent overwrite.
func ensureOutputDir(path string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return nil
}

// WriteJSONFile saves the exact document --json prints, without depending on
// shell redirection (the backlog use case: cron jobs and CI pipelines that
// cannot pipe safely). Perms 0600: the report lists escalation paths and
// credentials-adjacent targets, so it must never be group/world readable.
func (p *AutoPrivilege) WriteJSONFile(path string) error {
	data, err := marshalJSON(buildReport(p))
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0600)
}

// WriteMarkdownReport saves a human-readable evidence report with every
// finding, every vector and the exact commands an operator can run by hand.
func (p *AutoPrivilege) WriteMarkdownReport(path string) error {
	rep := buildReport(p)
	rooted := rep.Rooted

	out := "# Auto-Privilege Report\n\n"
	out += fmt.Sprintf("- **Tool:** Auto-Privilege v%s\n", rep.Version)
	out += fmt.Sprintf("- **Host:** %s  \n", rep.Host)
	out += fmt.Sprintf("- **User:** %s\n", rep.User)
	out += fmt.Sprintf("- **Date:** %s\n", rep.Timestamp.Format(time.RFC3339))
	out += fmt.Sprintf("- **Duration:** %d ms\n", rep.DurationMS)
	out += fmt.Sprintf("- **Root obtained:** %v\n", rooted)
	out += markdownSummary(rep.Summary)
	if rep.Diff != nil {
		out += markdownDiff(rep.Diff)
	}

	out += "\n## Findings\n\n"
	out += "| Source | Risk | Target | Description |\n|---|---|---|---|\n"
	for _, f := range rep.Findings {
		out += fmt.Sprintf("| %s | %s | `%s` | %s |\n",
			f.Source, f.Risk.String(), escapeMD(f.Target), escapeMD(f.Description))
	}
	if len(rep.Findings) == 0 {
		out += "| — | — | — | no findings |\n"
	}
	// The remediation playbook embedded in the evidence report: one
	// section per detected source (same knowledge --explain serves).
	// Empty-safe: no findings → no section.
	out += hardeningPlan(rep.Findings)

	out += "\n## Exploit vectors\n\n"
	for _, v := range rep.Vectors {
		kind := "auto"
		if v.Exploit == nil {
			kind = "manual"
		}
		out += fmt.Sprintf("### %s — %s (%s, %s)\n\n", v.Name, v.Risk.String(), v.Category, kind)
		out += fmt.Sprintf("- **Target:** `%s`\n", escapeMD(v.Target))
		out += fmt.Sprintf("- **Command:**\n\n```bash\n%s\n```\n\n", v.Command)
	}

	return atomicWriteFile(path, []byte(out), 0600)
}

// markdownSummary renders the at-a-glance counts block of the markdown
// report, mirroring the "summary" object the --json output carries: an
// engagement appendix printed with --report is self-sufficient (totals at a
// glance) instead of forcing the operator to re-run with --json or count
// table rows by hand. Risk buckets are sorted alphabetically so the same
// scan always renders identically.
func markdownSummary(s jsonSummary) string {
	keys := make([]string, 0, len(s.Risks))
	for k := range s.Risks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	risks := make([]string, 0, len(keys))
	for _, k := range keys {
		risks = append(risks, fmt.Sprintf("%s %d", k, s.Risks[k]))
	}
	riskLine := "—"
	if len(risks) > 0 {
		riskLine = strings.Join(risks, " · ")
	}

	out := "\n## Summary\n\n"
	out += "| Metric | Value |\n|---|---|\n"
	out += fmt.Sprintf("| Findings | %d (%d exploitable) |\n", s.Findings, s.Exploitable)
	out += fmt.Sprintf("| Hardening score | %d/100 |\n", s.Score)
	out += fmt.Sprintf("| Vectors | %d (%d auto · %d manual) |\n", s.Vectors, s.Auto, s.Manual)
	out += fmt.Sprintf("| Risks | %s |\n", riskLine)
	out += fmt.Sprintf("| Root obtained | %v |\n", s.Rooted)
	return out
}

// markdownDiff renders the baseline-comparison section of the markdown
// report. Only NEW findings are listed row by row — they are the actionable
// surface; resolved ones are summarized by count. The same scan always
// renders identically: rows follow the current findings order (deterministic
// by scannerOrder), never map iteration.
func markdownDiff(d *ReportDiff) string {
	out := "\n## Diff vs baseline\n\n"
	out += fmt.Sprintf("- **Baseline:** `%s`  \n", escapeMD(d.BaselinePath))
	out += fmt.Sprintf("- **Baseline date:** %s\n", d.BaselineDate.Format(time.RFC3339))
	out += "\n| Metric | Value |\n|---|---|\n"
	out += fmt.Sprintf("| New findings | %d (%d exploitable) |\n", len(d.New), d.NewExploitable)
	out += fmt.Sprintf("| Resolved findings | %d |\n", len(d.Resolved))
	// Baselines predating the metric carry score 0 — "unknown" renders
	// honestly instead of a fabricated 100→X regression.
	if d.SummaryBefore.Score > 0 {
		out += fmt.Sprintf("| Score | %d → %d/100 |\n", d.SummaryBefore.Score, d.ScoreAfter)
	} else {
		out += fmt.Sprintf("| Score | %d/100 (baseline predates scoring) |\n", d.ScoreAfter)
	}
	out += "\n### New findings\n\n"
	if len(d.New) == 0 {
		out += "No new findings — the measured surface did not grow since the baseline.\n"
		return out
	}
	out += "| Source | Risk | Target | Description |\n|---|---|---|---|\n"
	for _, f := range d.New {
		out += fmt.Sprintf("| %s | %s | `%s` | %s |\n",
			f.Source, f.Risk.String(), escapeMD(f.Target), escapeMD(f.Description))
	}
	return out
}

// escapeMD keeps pipes and backticks from breaking the markdown tables.
func escapeMD(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '|' || c == '`' {
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	return string(out)
}
