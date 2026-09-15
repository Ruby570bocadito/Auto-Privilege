package main

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// ================================================================
// HTML report (--html) — the fifth output format
// ================================================================
//
// The four existing formats each serve one consumer: the terminal serves
// the operator on the box, --json serves machines, --report (markdown)
// serves evidence appendices and --sarif serves code-scanning dashboards.
// What none of them serves is the "attach it to the engagement doc and
// email it" moment: a self-contained page a non-technical stakeholder can
// open in any browser, with the posture at a glance and every remediation
// step one click away.
//
// Design rules, in priority order:
//
//  1. Every dynamic string goes through htmlEscape — finding targets and
//     descriptions come from filesystem paths and file CONTENT, so a
//     credential file whose contents include "<script>" must never render
//     as markup (tested: TestHTMLReportEscapesDynamicContent).
//  2. Zero external resources: one HTML document, CSS inline, no fonts,
//     no JS, no images — it works from file:// on an air-gapped laptop,
//     the same promise the embedded GTFOBins db makes.
//  3. Same numbers as every other consumer: it renders buildReport(p),
//     the exact document --json prints, so summary cards, the diff section
//     and the findings table can never disagree with the JSON export.
//  4. Persisted with the same atomic write + 0600 as every other report —
//     it lists escalation paths, so it must never be group/world readable.

// htmlEsc escapes a dynamic string for safe interpolation into HTML text
// content and attribute values (html.EscapeString covers < > & ' ").
func htmlEsc(s string) string {
	return html.EscapeString(s)
}

// htmlRiskClass maps a risk level to its CSS badge class — one place, so
// the palette stays consistent across summary cards, table badges and the
// risk distribution bar.
func htmlRiskClass(r RiskLevel) string {
	switch r {
	case RiskDanger:
		return "danger"
	case RiskHigh:
		return "high"
	case RiskMedium:
		return "medium"
	case RiskLow:
		return "low"
	}
	return "info"
}

// htmlStatusClass picks the posture color for the score card: green when
// the surface is small, amber mid-range, red when the host is wide open.
func htmlStatusClass(score int) string {
	switch {
	case score >= 80:
		return "ok"
	case score >= 50:
		return "warn"
	}
	return "bad"
}

const htmlCSS = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #f3f4f6; color: #111827; line-height: 1.55; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
  header.top { border-bottom: 3px solid #111827; padding-bottom: 14px; margin-bottom: 24px; }
  header.top h1 { margin: 0; font-size: 26px; letter-spacing: .5px; }
  header.top .sub { color: #6b7280; font-size: 14px; margin-top: 4px; }
  .meta { display: flex; flex-wrap: wrap; gap: 18px; font-size: 13px; color: #374151; margin-top: 10px; }
  .meta b { color: #111827; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0 28px; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 16px; }
  .card .num { font-size: 28px; font-weight: 700; }
  .card .lbl { font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; margin-top: 2px; }
  .ok   { color: #15803d; }
  .warn { color: #b45309; }
  .bad  { color: #b91c1c; }
  h2 { font-size: 19px; margin: 34px 0 10px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; font-size: 14px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
  th { background: #111827; color: #f9fafb; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
  tr:last-child td { border-bottom: none; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background: #eef2f7; border-radius: 4px; padding: 1px 5px; font-size: 13px; word-break: break-all; }
  pre.cmd { background: #0d1117; color: #e6edf3; padding: 10px 14px; border-radius: 8px;
            overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
  .badge { display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: .05em;
           padding: 2px 9px; border-radius: 999px; text-transform: uppercase; }
  .badge.danger { background: #fee2e2; color: #b91c1c; }
  .badge.high   { background: #ffedd5; color: #c2410c; }
  .badge.medium { background: #fef9c3; color: #a16207; }
  .badge.low    { background: #dbeafe; color: #1d4ed8; }
  .badge.info   { background: #f1f5f9; color: #475569; }
  .riskbar { display: flex; height: 12px; border-radius: 6px; overflow: hidden; background: #e5e7eb; margin: 6px 0 2px; }
  .riskbar span { display: block; height: 100%; }
  .riskbar .danger { background: #dc2626; } .riskbar .high { background: #ea580c; }
  .riskbar .medium { background: #ca8a04; } .riskbar .low { background: #2563eb; }
  .riskbar .info { background: #94a3b8; }
  details { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px 16px; margin: 10px 0; }
  summary { cursor: pointer; font-weight: 600; }
  details ul { margin: 8px 0 4px; padding-left: 22px; }
  details li { margin: 4px 0; }
  .muted { color: #6b7280; }
  footer.top { margin-top: 44px; font-size: 12px; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 12px; }
`

// hardeningSources returns the unique finding sources that have a playbook
// entry, in first-appearance order — the shared core of the markdown
// "## Hardening plan" (report.go) and the HTML <details> plan below.
// Deterministic by construction (findings follow scannerOrder), empty-safe.
func hardeningSources(findings []Finding) []string {
	seen := map[string]bool{}
	var order []string
	for _, f := range findings {
		if seen[f.Source] {
			continue
		}
		if _, ok := explainDB[f.Source]; !ok {
			continue
		}
		seen[f.Source] = true
		order = append(order, f.Source)
	}
	return order
}

// htmlSummary renders the summary cards + the risk distribution bar.
func htmlSummary(s jsonSummary) string {
	class := htmlStatusClass(s.Score)
	// Fixed render order (danger → safe) keeps the bar stable across runs;
	// zero-count buckets render no segment at all. The keys match the
	// RiskLevel.String() buckets buildSummary writes — "SAFE" for
	// informational findings, not "INFO".
	order := []struct{ key, cls string }{
		{"DANGER", "danger"}, {"HIGH", "high"}, {"MEDIUM", "medium"},
		{"LOW", "low"}, {"SAFE", "info"},
	}
	var bar strings.Builder
	for _, o := range order {
		n := s.Risks[o.key]
		if n <= 0 {
			continue
		}
		bar.WriteString(fmt.Sprintf(`<span class="%s" style="width:%d%%"></span>`, o.cls, n*100/maxInt(s.Findings, 1)))
	}
	rooted := "NO"
	rootClass := "warn"
	if s.Rooted {
		rooted, rootClass = "YES", "bad"
	}
	return fmt.Sprintf(`
<div class="cards">
  <div class="card"><div class="num">%d</div><div class="lbl">Findings</div></div>
  <div class="card"><div class="num">%d</div><div class="lbl">Exploitable</div></div>
  <div class="card"><div class="num %s">%d<span class="muted" style="font-size:14px">/100</span></div><div class="lbl">Hardening score</div></div>
  <div class="card"><div class="num">%d</div><div class="lbl">Vectors (%d auto · %d manual)</div></div>
  <div class="card"><div class="num %s">%s</div><div class="lbl">Root obtained</div></div>
</div>
<div class="riskbar">%s</div>
<div class="muted" style="font-size:12px">Risk distribution: %s</div>`,
		s.Findings, s.Exploitable, class, s.Score, s.Vectors, s.Auto, s.Manual,
		rootClass, rooted, bar.String(), htmlRiskLine(s.Risks))
}

func htmlRiskLine(risks map[string]int) string {
	keys := make([]string, 0, len(risks))
	for k := range risks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, risks[k]))
	}
	return htmlEsc(strings.Join(parts, " · "))
}

// htmlDiff renders the baseline-comparison section, mirroring the markdown
// renderer: new findings listed row by row, resolved ones as a count, and
// the honest "baseline predates scoring" rendering when the metric is absent.
func htmlDiff(d *ReportDiff) string {
	var b strings.Builder
	b.WriteString("\n<h2>Diff vs baseline</h2>\n")
	b.WriteString(fmt.Sprintf("<p>Baseline <code>%s</code> · taken %s</p>\n",
		htmlEsc(d.BaselinePath), d.BaselineDate.Format(time.RFC3339)))
	scoreCell := fmt.Sprintf("%d → %d/100", d.SummaryBefore.Score, d.ScoreAfter)
	if d.SummaryBefore.Score <= 0 {
		scoreCell = fmt.Sprintf("%d/100 <span class=\"muted\">(baseline predates scoring)</span>", d.ScoreAfter)
	}
	b.WriteString(fmt.Sprintf("<p><b>%d</b> new findings (<b>%d</b> exploitable) · <b>%d</b> resolved · score %s</p>\n",
		len(d.New), d.NewExploitable, len(d.Resolved), scoreCell))
	if len(d.New) == 0 {
		b.WriteString("<p class=\"muted\">No new findings — the measured surface did not grow since the baseline.</p>\n")
		return b.String()
	}
	b.WriteString(htmlFindingsTable(d.New))
	return b.String()
}

// htmlFindingsTable is the shared findings renderer (main table and the
// diff's new-findings table) — one markup, one escape path.
func htmlFindingsTable(findings []Finding) string {
	var b strings.Builder
	b.WriteString("<table>\n<tr><th>Source</th><th>Risk</th><th>Target</th><th>Description</th></tr>\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("<tr><td><b>%s</b></td><td><span class=\"badge %s\">%s</span></td><td><code>%s</code></td><td>%s</td></tr>\n",
			htmlEsc(f.Source), htmlRiskClass(f.Risk), htmlEsc(f.Risk.String()),
			htmlEsc(f.Target), htmlEsc(f.Description)))
	}
	if len(findings) == 0 {
		b.WriteString("<tr><td colspan=\"4\" class=\"muted\">no findings</td></tr>\n")
	}
	b.WriteString("</table>\n")
	return b.String()
}

// htmlHardening renders the remediation playbook as <details> blocks — one
// per detected source, same knowledge --explain serves, collapsed by default
// so the page stays scannable. Empty-safe: no findings → no section.
func htmlHardening(findings []Finding) string {
	order := hardeningSources(findings)
	if len(order) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n<h2>Hardening plan</h2>\n")
	b.WriteString("<p class=\"muted\">One playbook per detected source, steps safest first. Rotate any secret surfaced by CRED findings before anything else.</p>\n")
	for _, s := range order {
		e := explainDB[s]
		b.WriteString(fmt.Sprintf("<details><summary>%s <span class=\"muted\">— %s</span></summary>\n<ul>\n",
			htmlEsc(s), htmlEsc(e.What)))
		for _, step := range e.Harden {
			b.WriteString(fmt.Sprintf("<li>%s</li>\n", htmlEsc(step)))
		}
		b.WriteString("</ul>\n</details>\n")
	}
	return b.String()
}

// htmlVectors renders the exploit vectors with the exact command each one
// would run — the manual-reproduction promise, now in the shareable format.
func htmlVectors(vectors []Vector) string {
	var b strings.Builder
	b.WriteString("\n<h2>Exploit vectors</h2>\n")
	if len(vectors) == 0 {
		b.WriteString("<p class=\"muted\">no vectors enumerated</p>\n")
		return b.String()
	}
	for _, v := range vectors {
		kind := "auto"
		if v.Exploit == nil {
			kind = "manual"
		}
		b.WriteString(fmt.Sprintf("<details><summary>%s <span class=\"badge %s\">%s</span> <span class=\"muted\">[%s · %s]</span></summary>\n",
			htmlEsc(v.Name), htmlRiskClass(v.Risk), htmlEsc(v.Risk.String()),
			htmlEsc(v.Category), kind))
		b.WriteString(fmt.Sprintf("<p><b>Target:</b> <code>%s</code></p>\n", htmlEsc(v.Target)))
		b.WriteString(fmt.Sprintf("<pre class=\"cmd\">%s</pre>\n</details>\n", htmlEsc(v.Command)))
	}
	return b.String()
}

// maxInt keeps the risk-bar percentage math safe when Findings is 0.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// WriteHTMLReport saves the self-contained HTML evidence page (0600, atomic
// write). Every dynamic value flows through htmlEsc — see the design rules
// at the top of this file.
func (p *AutoPrivilege) WriteHTMLReport(path string) error {
	rep := buildReport(p)

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString(fmt.Sprintf("<title>Auto-Privilege Report — %s</title>\n", htmlEsc(rep.Host)))
	b.WriteString("<style>" + htmlCSS + "</style>\n</head>\n<body>\n<div class=\"wrap\">\n")

	b.WriteString(fmt.Sprintf(
		"<header class=\"top\">\n<h1>AUTOPRIV — Privilege Escalation Report</h1>\n"+
			"<div class=\"sub\">Auto-Privilege v%s · automated Linux privilege escalation audit</div>\n"+
			"<div class=\"meta\"><span><b>Host:</b> %s</span><span><b>User:</b> %s</span>"+
			"<span><b>Date:</b> %s</span><span><b>Duration:</b> %d ms</span></div>\n</header>\n",
		htmlEsc(rep.Version), htmlEsc(rep.Host), htmlEsc(rep.User),
		rep.Timestamp.Format(time.RFC3339), rep.DurationMS))

	b.WriteString("\n<h2>Summary</h2>\n")
	b.WriteString(htmlSummary(rep.Summary))

	if rep.Diff != nil {
		b.WriteString(htmlDiff(rep.Diff))
	}

	b.WriteString("\n<h2>Findings</h2>\n")
	b.WriteString(htmlFindingsTable(rep.Findings))
	b.WriteString(htmlHardening(rep.Findings))
	b.WriteString(htmlVectors(rep.Vectors))

	b.WriteString(fmt.Sprintf(
		"\n<footer class=\"top\">Generated by Auto-Privilege v%s on %s · "+
			"authorized testing only — labs, CTFs and systems you own.</footer>\n",
		htmlEsc(rep.Version), rep.Timestamp.Format(time.RFC3339)))
	b.WriteString("</div>\n</body>\n</html>\n")

	return atomicWriteFile(path, []byte(b.String()), 0600)
}
