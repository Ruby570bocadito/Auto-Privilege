package autopriv

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// bannerArt spells AUTOPRIV in ANSI Shadow. Correctness is enforced by
// TestBannerArtSpellsAutoPriv, which round-trip decodes every rune column
// against the glyph table, so a typo in the art fails CI.
var bannerArt = []string{
	" █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ██████╗ ██╗██╗   ██╗",
	"██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗██║██║   ██║",
	"███████║██║   ██║   ██║   ██║   ██║██████╔╝██████╔╝██║██║   ██║",
	"██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝",
	"██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ██║  ██║██║ ╚████╔╝ ",
	"╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ",
}

// bannerColor applies a cyan→green 256-color ramp per line.
func bannerColor(i int) string {
	ramp := []string{
		"\x1b[38;5;51m", // cyan
		"\x1b[38;5;50m",
		"\x1b[38;5;49m",
		"\x1b[38;5;48m",
		"\x1b[38;5;47m",
		"\x1b[38;5;46m", // green
	}
	if i < 0 || i >= len(ramp) {
		return AnsiCyan
	}
	return ramp[i]
}

func printBanner(opts Options) {
	if opts.JSON || opts.Quiet {
		return
	}
	for i, line := range bannerArt {
		fmt.Println(colorize(line, bannerColor(i)))
	}
	fmt.Println()
	fmt.Printf("  %s  %s\n",
		colorize("Automated Linux + Windows Privilege Escalation Suite", AnsiBold),
		colorize("v"+Version, AnsiGrey))
	fmt.Println(colorize("  scan → enumerate → auto-root (linux) · enumerate (windows)  ·  zero deps  ·  single binary", AnsiGrey))
	fmt.Println(colorize("  authorized testing only — labs, CTFs and systems you own", AnsiGrey))
	fmt.Println()
}

func usage() {
	out := `  AUTOPRIV v` + Version + ` — automated linux + windows privilege escalation

  Usage: autoprivilege [options]

  Modes:
    (default)                 scan + enumerate (read-only, no changes)
    --exploit                 auto-exploit found vectors, safest first
    --dry-run                 scan + enumerate, show what would run
    --list-gtfo               print the embedded GTFOBins database
    --explain src             hardening playbook for a finding source (or all)
    --list-vectors            print the supported vector catalog
    --list-sources            print the finding-source vocabulary (--ignore/--explain)
    --completion shell        print a shell completion script: bash, zsh or fish
    --update-gtfobins         refresh GTFOBins db from upstream (persisted)

  Targeting:
    --vector list             comma-separated: suid,sgid,sudo,cron,passwd,shadow,
                              docker,container,caps,nfs,path,service,kernel,cred,
                              preload,sudoers,group,hooks,polkit + the Windows
                              set: winpriv,winreg,winservice,winauto,wintask,
                              wincred,winpath — or all
    --risk level              max auto-exploit risk: safe|low|medium|high|danger
    --one-shot                stop after the first successful exploit
    --lhost ip                reverse-shell listener host (auto-detected)
    --lport port              reverse-shell listener port (default 4444)

  Output:
    --json                    machine-readable report on stdout
    --output file             write the JSON report to a file (0600)
    --report file             also write a markdown evidence report
    --html file               write a self-contained HTML report (0600)
    --sarif file              SARIF 2.1.0 report for code-scanning dashboards
    --sarif-stdout            print the SARIF log to stdout (not with --json)
    --baseline file           diff findings against a previous --json/--output report
    --quiet                   no output; exit code 0 = root, 1 = no root
    --no-color                disable ANSI colors (auto-off when piped)
    --color                   force ANSI colors even when piped (captures, demos)
    --verbose                 debug logging on stderr
    --log fmt                 log format: text|json (stderr)

  Misc:
    --ignore list             exclude finding sources entirely: e.g. CRED,CONTAINER
    --min-risk level          hide findings below this risk floor:
                              low|medium|high|danger — the floor applies
                              everywhere (terminal, JSON, reports, gates)
    --parallel                run scanners concurrently (same results, faster)
    --stealth                 jitter between scanners and exploits
    --top n                   show the top n vectors after a failed exploit
                              run (default 5, max 50)
    --scan-timeout dur        timeout for scan-time external commands (default 5s)
    --fail-on risk            exit 3 when exploitable findings >= risk
                              (low|medium|high|danger) — CI hardening gate
    --fail-on-new [risk]      exit 3 when NEW exploitable findings appear vs
                              --baseline — regression gate (requires it);
                              optional threshold: --fail-on-new=low|medium|high|danger
    --min-score n             exit 3 when the hardening score lands below the
                              floor (1-100) — posture gate; 0 disables it
    --rooteame path           load .ko module if root is obtained (lab only)
    --version                 print version
    -h, --help                this help

  Examples:
    autoprivilege                          read-only audit of this machine
    autoprivilege --parallel               same audit, scanners concurrent
    autoprivilege --exploit --risk=low     only the safest auto-exploits
    autoprivilege --vector=suid,sudo       focus two specific vectors
    autoprivilege --json > report.json     CI-friendly output
    autoprivilege --report audit.md        markdown evidence report
    autoprivilege --html audit.html       shareable HTML page for stakeholders
    autoprivilege --sarif audit.sarif      GitHub code-scanning upload
    autoprivilege --quiet --sarif-stdout | sarif-viewer   pipe the log
    autoprivilege --explain cron           how to close the CRON findings
    autoprivilege --ignore CRED,CONTAINER  CI scan without the noisy sources
    autoprivilege --min-risk medium       same scan, only MEDIUM+ findings
    autoprivilege --list-sources          what --ignore/--explain accept
    autoprivilege --list-vectors --json   vector catalog, machine-readable
    autoprivilege --explain cron --json   hardening playbook, structured
    autoprivilege --output base.json       snapshot, then harden, then:
    autoprivilege --baseline base.json     show new/resolved findings
    autoprivilege --quiet --fail-on high   gate: exit 3 on exploitable high
    autoprivilege --baseline base.json --fail-on-new   CI: fail only on regressions
    autoprivilege --baseline base.json --fail-on-new=high   only HIGH+ regressions
    autoprivilege --quiet --min-score 70    gate: exit 3 while score < 70
    autoprivilege --completion bash >> ~/.bashrc   shell completion
    lab/rootless_lab.sh --exploit          safe rootless demo lab
`
	fmt.Fprintln(os.Stderr, colorize(out, AnsiGrey))
}

// printDryRunPlan shows the exact execution plan (safest first) without
// running anything — useful in labs where the operator is already root.
func printDryRunPlan(p *AutoPrivilege) {
	if p.Opts.JSON || p.Opts.Quiet {
		return
	}
	fmt.Println(colorize("\n  [3/3] Dry-run — execution plan (safest first):", AnsiYellow))
	for _, v := range sortedVectors(p.Vectors) {
		if v.Risk > p.Opts.MaxRisk {
			fmt.Printf("  %s %s (risk %s > max %s)\n",
				colorize("[skip]", AnsiGrey), v.Name, v.Risk.String(), p.Opts.MaxRisk.String())
			continue
		}
		kind := colorize("[auto]", AnsiGreen)
		if v.Exploit == nil {
			kind = colorize("[manual]", AnsiCyan)
		}
		fmt.Printf("  %s %s\n    %s %s\n", kind, v.Name, colorize("$", AnsiGrey), colorize(v.Command, AnsiGrey))
	}
}

// printDiffSummary renders the terminal block of the baseline comparison:
// counts first, then every NEW finding with the same risk tags as the main
// findings list (reusing p.Print keeps colors/quiet behavior consistent).
// Resolved findings are counted, not listed — the payoff is a number, the
// action is in the news.
func printDiffSummary(p *AutoPrivilege) {
	if p.Opts.JSON || p.Opts.Quiet || p.Diff == nil {
		return
	}
	fmt.Println(colorize("  ── Diff vs baseline ─────────────────────", AnsiCyan))
	fmt.Printf("   %-10s %d  (%s %d)\n", "new", len(p.Diff.New), "exploitable", p.Diff.NewExploitable)
	fmt.Printf("   %-10s %d\n", "resolved", len(p.Diff.Resolved))
	// Score trajectory across the baseline. Baselines written before the
	// metric existed carry score 0 — "unknown" is the honest rendering
	// there, a fabricated 0→X would read as a catastrophic regression.
	if p.Diff.SummaryBefore.Score > 0 {
		fmt.Printf("   %-10s %d → %d\n", "score", p.Diff.SummaryBefore.Score, p.Diff.ScoreAfter)
	} else {
		fmt.Printf("   %-10s %d (%s)\n", "score", p.Diff.ScoreAfter, "baseline predates scoring")
	}
	for _, f := range p.Diff.New {
		p.Print(f)
	}
	fmt.Println()
}

// printTopVectors shows the strongest manual options instead of nothing.
func printTopVectors(p *AutoPrivilege, n int) {
	sorted := sortedVectors(p.Vectors)
	count := 0
	for _, v := range sorted {
		if count >= n {
			break
		}
		p.PrintVector(v)
		count++
	}
	if len(p.Vectors) == 0 {
		fmt.Println(colorize("    (none found)", AnsiGrey))
	}
}

// printGTFOList dumps the embedded GTFOBins database grouped by category.
// The sgid section lists entries that exist ONLY in sgidLookup — the shells
// shared with the suid list are listed once, in their home section.
func printGTFOList() {
	suid, sudo, sgidOnly := []string{}, []string{}, []string{}
	for bin := range gtfoLookup {
		if gtfoCategory[bin] == "suid-shell" {
			suid = append(suid, bin)
		} else {
			sudo = append(sudo, bin)
		}
	}
	for bin := range sgidLookup {
		if _, shared := gtfoLookup[bin]; !shared {
			sgidOnly = append(sgidOnly, bin)
		}
	}
	sort.Strings(suid)
	sort.Strings(sudo)
	sort.Strings(sgidOnly)

	fmt.Printf("  %s (%d entries + %d sgid)\n\n", colorize("── GTFOBins database ──", AnsiCyan), len(gtfoLookup), len(sgidLookup))
	fmt.Printf("  %s (%d)\n", colorize("suid shell", AnsiGreen), len(suid))
	fmt.Printf("    %s\n\n", wrapCols(suid, ", "))
	fmt.Printf("  %s (%d)\n", colorize("sudo", AnsiBlue), len(sudo))
	fmt.Printf("    %s\n\n", wrapCols(sudo, ", "))
	if len(sgidOnly) > 0 {
		fmt.Printf("  %s (%d)\n", colorize("sgid", AnsiYellow), len(sgidOnly))
		fmt.Printf("    %s\n\n", wrapCols(sgidOnly, ", "))
	}
	fmt.Println(colorize("  embedded in the binary — works air-gapped; --update-gtfobins refreshes it", AnsiGrey))
}

// wrapCols renders a comma-joined list wrapped at ~76 columns.
func wrapCols(items []string, sep string) string {
	const width = 76
	var b strings.Builder
	line := 0
	for i, it := range items {
		w := len(it)
		if i > 0 {
			w += len(sep)
		}
		if line > 0 && line+w > width {
			b.WriteString("\n    ")
			line = 0
		}
		if i > 0 && line > 0 {
			b.WriteString(sep)
		}
		b.WriteString(it)
		line += w
	}
	return b.String()
}

// printVectorList dumps the vector catalog — what --vector accepts and what
// each name actually inspects. Documentation mode like --list-gtfo: honest
// one-liners, no advice that outscopes the scanner. Order comes from
// vectorCatalogOrder (pinned to validVectors by test).
func printVectorList() {
	fmt.Printf("  %s (%d vectors — all read-only)\n\n", colorize("── Vector catalog ──", AnsiCyan), len(vectorCatalogOrder))
	for _, name := range vectorCatalogOrder {
		doc, ok := vectorCatalog[name]
		if !ok {
			// Defensive: the test pins the catalog to validVectors, but the
			// printer must stay honest if the maps ever diverge.
			fmt.Printf("  %-10s %s\n", colorize(name, AnsiBold), colorize("(no catalog entry — report it)", AnsiYellow))
			continue
		}
		fmt.Printf("  %-10s %s\n", colorize(name, AnsiBold), doc.Desc)
	}
	fmt.Println()
	fmt.Println(colorize("  usage: --vector <name[,name2,…]>  ·  all expands to every vector", AnsiGrey))
}

// printSummary renders the end-of-run summary block.
func printSummary(p *AutoPrivilege, elapsed time.Duration) {
	if p.Opts.JSON || p.Opts.Quiet {
		return
	}
	byRisk := map[RiskLevel]int{}
	exploitable := 0
	for _, f := range p.Findings {
		byRisk[f.Risk]++
		if f.Exploitable {
			exploitable++
		}
	}
	auto, manual := 0, 0
	for _, v := range p.Vectors {
		if v.Exploit == nil {
			manual++
		} else {
			auto++
		}
	}

	riskLine := ""
	for r := RiskSafe; r <= RiskDanger; r++ {
		if byRisk[r] > 0 {
			riskLine += fmt.Sprintf("%s %d  ", colorize(r.String(), r.Color()), byRisk[r])
		}
	}
	if riskLine == "" {
		riskLine = colorize("none", AnsiGrey)
	}

	rooted := colorize("NO", AnsiYellow)
	if p.Rooted || isRoot() {
		rooted = colorize("YES", AnsiGreen+AnsiBold)
	}

	fmt.Println()
	fmt.Println(colorize("  ── Summary ─────────────────────────────", AnsiCyan))
	fmt.Printf("   %-10s %d  (%s %d)\n", "findings", len(p.Findings), "exploitable", exploitable)
	fmt.Printf("   %-10s %d/100\n", "score", hardeningScore(p.Findings))
	fmt.Printf("   %-10s %d  (%s %d · %s %d)\n", "vectors", len(p.Vectors), "auto", auto, "manual", manual)
	fmt.Printf("   %-10s %s\n", "risks", strings.TrimRight(riskLine, " "))
	fmt.Printf("   %-10s %s\n", "rooted", rooted)
	if isRoot() {
		// FP-1 contract: escalation scanners are skipped for root by
		// design — say so instead of letting a near-empty root scan read
		// as "pristine host".
		fmt.Println(colorize("   note       running as root — escalation checks skipped by design; rerun as an unprivileged user for the attack surface", AnsiGrey))
	}
	fmt.Printf("   %-10s %s\n", "time", elapsed.Round(100*time.Millisecond))
	if p.Opts.Report != "" {
		fmt.Printf("   %-10s %s\n", "report", p.Opts.Report)
	}
	if p.Opts.HTML != "" {
		fmt.Printf("   %-10s %s\n", "html", p.Opts.HTML)
	}
	if p.Opts.Output != "" {
		fmt.Printf("   %-10s %s\n", "json", p.Opts.Output)
	}
}
