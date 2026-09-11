package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// bannerArt spells AUTO-PRIV in ANSI Shadow (verified by unit test + generator
// script round-trip decode: scripts/gen_ap_banner.py).
var bannerArt = []string{
	" █████╗ ██╗   ██╗████████╗ ██████╗ █████╗██████╗ ██████╗ ██╗██╗   ██╗",
	"██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗╚════╝██╔══██╗██╔══██╗██║██║   ██║",
	"███████║██║   ██║   ██║   ██║   ██║      ██████╔╝██████╔╝██║██║   ██║",
	"██╔══██║██║   ██║   ██║   ██║   ██║      ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝",
	"██║  ██║╚██████╔╝   ██║   ╚██████╔╝      ██║     ██║  ██║██║ ╚████╔╝ ",
	"╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ",
}

// bannerColor applies a cyan→green 256-color ramp per line.
func bannerColor(i int) string {
	ramp := []string{"\033[38;5;51m", "\033[38;5;50m", "\033[38;5;48m", "\033[38;5;47m", "\033[38;5;46m", "\033[38;5;46m"}
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
		colorize("Automated Linux Privilege Escalation Suite", AnsiBold),
		colorize("v"+Version, AnsiGrey))
	fmt.Println(colorize("  scan → enumerate → auto-root  ·  zero deps  ·  single binary", AnsiGrey))
	fmt.Println(colorize("  authorized testing only — labs, CTFs and systems you own", AnsiGrey))
	fmt.Println()
}

func usage() {
	out := `  AUTO-PRIV v` + Version + ` — automated linux privilege escalation

  Usage: autoprivilege [options]

  Modes:
    (default)                 scan + enumerate (read-only, no changes)
    --exploit                 auto-exploit found vectors, safest first
    --dry-run                 scan + enumerate, show what would run
    --list-gtfo               print the embedded GTFOBins database
    --update-gtfobins         refresh GTFOBins db from upstream (persisted)

  Targeting:
    --vector list             comma-separated: suid,sudo,cron,passwd,shadow,
                              docker,caps,nfs,path,service,kernel,cred
    --risk level              max auto-exploit risk: safe|low|medium|high|danger
    --one-shot                stop after the first successful exploit
    --lhost ip                reverse-shell listener host (auto-detected)
    --lport port              reverse-shell listener port (default 4444)

  Output:
    --json                    machine-readable report on stdout
    --report file             also write a markdown evidence report
    --quiet                   no output; exit code 0 = root, 1 = no root
    --no-color                disable ANSI colors (auto-off when piped)
    --verbose                 debug logging on stderr
    --log fmt                 log format: text|json (stderr)

  Misc:
    --stealth                 jitter between scanners and exploits
    --rooteame path           load .ko module if root is obtained (lab only)
    --version                 print version
    -h, --help                this help

  Examples:
    autoprivilege                          read-only audit of this machine
    autoprivilege --exploit --risk=low     only the safest auto-exploits
    autoprivilege --vector=suid,sudo       focus two specific vectors
    autoprivilege --json > report.json     CI-friendly output
    autoprivilege --report audit.md        markdown evidence report
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
func printGTFOList() {
	suid, sudo := []string{}, []string{}
	for bin := range gtfoLookup {
		if gtfoCategory[bin] == "suid-shell" {
			suid = append(suid, bin)
		} else {
			sudo = append(sudo, bin)
		}
	}
	sort.Strings(suid)
	sort.Strings(sudo)

	fmt.Printf("  %s (%d entries)\n\n", colorize("── GTFOBins database ──", AnsiCyan), len(gtfoLookup))
	fmt.Printf("  %s (%d)\n", colorize("suid shell", AnsiGreen), len(suid))
	fmt.Printf("    %s\n\n", wrapCols(suid, ", "))
	fmt.Printf("  %s (%d)\n", colorize("sudo", AnsiBlue), len(sudo))
	fmt.Printf("    %s\n\n", wrapCols(sudo, ", "))
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
	fmt.Printf("   %-10s %d  (%s %d · %s %d)\n", "vectors", len(p.Vectors), "auto", auto, "manual", manual)
	fmt.Printf("   %-10s %s\n", "risks", strings.TrimRight(riskLine, " "))
	fmt.Printf("   %-10s %s\n", "rooted", rooted)
	fmt.Printf("   %-10s %s\n", "time", elapsed.Round(100*time.Millisecond))
	if p.Opts.Report != "" {
		fmt.Printf("   %-10s %s\n", "report", p.Opts.Report)
	}
}
