package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// jsonSummary is the at-a-glance counts block of the machine-readable report.
// It lives under the "summary" key of the --json output — the shape both
// READMEs document for `jq '.summary'`.
type jsonSummary struct {
	Findings    int            `json:"findings"`
	Exploitable int            `json:"exploitable"`
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
	Findings   []Finding   `json:"findings"`
	Vectors    []Vector    `json:"vectors"`
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
		Findings:   findings,
		Vectors:    vectors,
	}
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

// WriteJSONFile saves the exact document --json prints, without depending on
// shell redirection (the backlog use case: cron jobs and CI pipelines that
// cannot pipe safely). Perms 0600: the report lists escalation paths and
// credentials-adjacent targets, so it must never be group/world readable.
func (p *AutoPrivilege) WriteJSONFile(path string) error {
	data, err := marshalJSON(buildReport(p))
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
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

	return os.WriteFile(path, []byte(out), 0600)
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
