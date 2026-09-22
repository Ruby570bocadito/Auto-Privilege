package autopriv

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Run is the whole CLI pipeline: flag parsing, scan, enumeration and (when
// asked) exploitation. It lives in the library so every exit-code contract
// (0 root/scan-only, 1 exploit without root, 2 usage error, 3 CI gates)
// stays next to the logic that produces it — the cmd/ wrapper is a
// one-liner and can never drift.
func Run() {
	p := run()

	// FASE 1: Scan
	if !p.Opts.Quiet && !p.Opts.JSON {
		fmt.Println(colorize("  [1/3] Scanning system...", AnsiCyan))
	}
	scanAll(p)

	// --ignore and --min-risk apply ONCE, right after the scan: every
	// downstream consumer (terminal, JSON, markdown, SARIF, score,
	// policy gate, baseline diff, enumeration) sees the same filtered
	// reality. The source exclusion runs first, then the risk floor.
	if len(p.Opts.IgnoreSources) > 0 {
		p.Findings = filterIgnored(p.Findings, p.Opts.IgnoreSources)
	}
	if p.Opts.MinRiskLevel > RiskSafe {
		p.Findings = filterMinRisk(p.Findings, p.Opts.MinRiskLevel)
	}

	// FASE 2: Enumerate
	if !p.Opts.Quiet && !p.Opts.JSON {
		fmt.Println(colorize("\n  [2/3] Enumerating vectors...", AnsiCyan))
	}
	if p.Opts.Vector != "" {
		names, err := parseVectorList(p.Opts.Vector)
		if err != nil {
			// unreachable: validated in run(), kept as a guard
			fmt.Fprintf(os.Stderr, "  [-] %v\n", err)
			os.Exit(2)
		}
		enumerateVectors(p, names)
	} else {
		enumerateAll(p)
	}

	// Print findings
	if !p.Opts.JSON && !p.Opts.Quiet {
		fmt.Println(colorize("\n  ── Findings ──", AnsiCyan))
		shown := 0
		for _, f := range p.Findings {
			if f.Exploitable {
				p.Print(f)
				shown++
			}
		}
		if shown == 0 {
			// INC-3: the victory message must be earned. "system looks
			// clean" over eighteen informational findings was a lie of
			// emphasis — now the count is spelled out with the commands
			// that surface the retained leads.
			if len(p.Findings) == 0 {
				fmt.Println(colorize("    (no findings — system looks clean)", AnsiGrey))
			} else {
				fmt.Println(colorize(fmt.Sprintf("    (no exploitable findings — %d informational note(s) retained; inspect with --min-risk low or --json)", len(p.Findings)), AnsiGrey))
			}
		}
	}

	// Baseline diff: computed once here so the terminal block, the JSON
	// export and the markdown report all share the same numbers.
	if p.Baseline != nil {
		p.Diff = diffReports(p.Baseline, p.Findings)
		p.Diff.BaselinePath = p.Opts.Baseline
		printDiffSummary(p)
	}

	// FASE 3: Exploit (or show the plan)
	// --dry-run shows the execution plan on its own: the usage text and
	// both READMEs promise "scan + enumerate, show what would run", but
	// the old condition required --exploit --dry-run together, so a lone
	// --dry-run silently skipped the plan.
	if p.Opts.DryRun {
		printDryRunPlan(p)
		logDryRun(p.Opts)
	} else if p.Opts.Exploit {
		if isRoot() {
			if !p.Opts.Quiet && !p.Opts.JSON {
				fmt.Println(colorize("\n  [!] Already running as root — nothing to escalate", AnsiYellow))
				fmt.Println(colorize("  [!] Tip: --dry-run shows the execution plan", AnsiGrey))
			}
			if p.Opts.Rooteame != "" {
				tryRooteame(p)
			}
		} else {
			if !p.Opts.Quiet && !p.Opts.JSON {
				fmt.Println(colorize("\n  [3/3] Exploiting... (max risk: "+p.Opts.MaxRisk.String()+")", AnsiCyan))
			}
			exploitAll(p)
		}
	}

	// No root obtained: show the strongest manual options instead of nothing.
	if !p.Rooted && !isRoot() && p.Opts.Exploit && !p.Opts.Quiet && !p.Opts.JSON {
		fmt.Println(colorize("\n  [*] No root obtained. Top vectors:", AnsiYellow))
		printTopVectors(p, p.Opts.topVectorsN())
	}

	if p.Opts.Report != "" {
		if err := p.WriteMarkdownReport(p.Opts.Report); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] report write failed: %v\n", err)
		} else if !p.Opts.Quiet && !p.Opts.JSON {
			fmt.Println(colorize("  [+] Markdown report written: "+p.Opts.Report, AnsiGreen))
		}
	}

	if p.Opts.HTML != "" {
		if err := p.WriteHTMLReport(p.Opts.HTML); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] html write failed: %v\n", err)
		} else if !p.Opts.Quiet && !p.Opts.JSON {
			fmt.Println(colorize("  [+] HTML report written: "+p.Opts.HTML, AnsiGreen))
		}
	}

	if p.Opts.JSON {
		if err := p.ExportJSON(); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] json export failed: %v\n", err)
		}
	}

	if p.Opts.Output != "" {
		if err := p.WriteJSONFile(p.Opts.Output); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] output write failed: %v\n", err)
		} else if !p.Opts.Quiet && !p.Opts.JSON {
			fmt.Println(colorize("  [+] JSON report written: "+p.Opts.Output, AnsiGreen))
		}
	}

	if p.Opts.Sarif != "" {
		if err := p.WriteSARIFFile(p.Opts.Sarif); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] sarif write failed: %v\n", err)
		} else if !p.Opts.Quiet && !p.Opts.JSON {
			fmt.Println(colorize("  [+] SARIF report written: "+p.Opts.Sarif, AnsiGreen))
		}
	}

	// --sarif-stdout hands the log to the pipeline directly — printed
	// even in --quiet (the operator explicitly asked for stdout output,
	// same contract as --json).
	if p.Opts.SarifStdout {
		if err := p.ExportSARIF(); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] sarif export failed: %v\n", err)
		}
	}

	// Elapsed is measured HERE, not right after run(): the old code
	// captured it before the scan even started, so the printed summary
	// always showed ~0s on a scan that really took seconds (the JSON was
	// already correct — it measures at export time).
	printSummary(p, time.Since(p.Started))

	// Exit codes (documented): 0 = root or scan-only run, 1 = exploit ran
	// without root, 2 = usage error, 3 = --fail-on policy gate or
	// --fail-on-new regression gate tripped. Both gates are evaluated
	// last and win: a CI job must fail (3) even when an exploit attempt
	// also failed (1) — all reports above are already written either way.
	exitCode, gateMsg := computeExitCode(p)
	if exitCode != 0 {
		if gateMsg != "" {
			if p.Opts.JSON || p.Opts.Quiet {
				fmt.Fprint(os.Stderr, gateMsg)
			} else {
				fmt.Print(gateMsg)
			}
		}
		os.Exit(exitCode)
	}
}

// failOnNewFlag implements flag.Value for --fail-on-new: a bool-style flag
// that ALSO accepts an optional risk threshold via --fail-on-new=<risk>.
// IsBoolFlag() true makes bare --fail-on-new parse (Set("")) instead of
// swallowing the next argument; --fail-on-new=high lands in Set("high").
// Invalid thresholds fail fast at parse time — a misconfigured CI gate must
// never scan for minutes before discovering its typo (same contract as
// --fail-on).
type failOnNewFlag struct{ opts *Options }

func (f failOnNewFlag) String() string {
	if f.opts == nil || !f.opts.FailOnNew {
		return ""
	}
	if f.opts.FailOnNewRisk <= RiskSafe {
		return "true"
	}
	return strings.ToLower(f.opts.FailOnNewRisk.String())
}

func (f failOnNewFlag) IsBoolFlag() bool { return true }

func (f failOnNewFlag) Set(s string) error {
	if s == "" || s == "true" {
		f.opts.FailOnNew = true
		f.opts.FailOnNewRisk = RiskSafe
		return nil
	}
	if !validMaxRisk(s) {
		return fmt.Errorf("invalid --fail-on-new threshold %q (valid: low, medium, high, danger)", s)
	}
	f.opts.FailOnNew = true
	f.opts.FailOnNewRisk = parseMaxRisk(s)
	return nil
}

// computeExitCode distills the end-of-run decision into (code, message).
// Pure function over the final run state — testable without spawning the
// binary. Documented semantics preserved bit for bit: 1 for exploit-without-
// root, and BOTH gates (policy + regression) override to 3 when they trip,
// winning over 1 — a CI job must fail even when an exploit also failed.
// When the gates are set but do NOT trip, the verdict falls through to the
// classic 0/1 (round-8 contract: gate pass does not mask a failed exploit).
// The policy gate takes message precedence over the regression gate when
// both trip — both exit 3 anyway. The regression gate honors the optional
// --fail-on-new=<risk> threshold: only new exploitable findings at/above it
// count (bare = any new exploitable, the round-11 behavior). The posture
// gate (--min-score) is evaluated LAST: it trips when the hardening score
// lands below the floor, with the lowest message precedence of the three
// gates — a risk/regression verdict names its finding, which beats a
// generic "score too low" for the operator reading the CI log.
func computeExitCode(p *AutoPrivilege) (int, string) {
	code := 0
	if p.Opts.Exploit && !p.Opts.DryRun && !p.Rooted && !isRoot() {
		code = 1
	}
	if n := policyGateCount(p); n > 0 {
		return 3, fmt.Sprintf("  [!] policy gate: %d exploitable finding(s) at/above %s — exit 3\n",
			n, p.Opts.FailOnRisk.String())
	}
	if p.Opts.FailOnNew && p.Diff != nil {
		// Threshold semantics: bare --fail-on-new (FailOnNewRisk ==
		// RiskSafe) counts every new exploitable finding; an explicit
		// --fail-on-new=<risk> counts only findings at/above it.
		// Informational findings never trip the gate — it watches the
		// actionable surface, not the noise (round-11 contract).
		n := 0
		for _, f := range p.Diff.New {
			if f.Exploitable && f.Risk >= p.Opts.FailOnNewRisk {
				n++
			}
		}
		if n > 0 {
			thr := ""
			if p.Opts.FailOnNewRisk > RiskSafe {
				thr = fmt.Sprintf(" at/above %s", p.Opts.FailOnNewRisk.String())
			}
			return 3, fmt.Sprintf("  [!] regression gate: %d new exploitable finding(s)%s since baseline — exit 3\n",
				n, thr)
		}
	}
	if p.Opts.MinScore > 0 {
		if score := hardeningScore(p.Findings); score < p.Opts.MinScore {
			return 3, fmt.Sprintf("  [!] score gate: hardening score %d < %d — exit 3\n",
				score, p.Opts.MinScore)
		}
	}
	return code, ""
}

// registerFlags declares every CLI flag on fs, writing into opts (risk and
// showVersion stay outside Options because run() post-processes them).
// Single source of truth for the CLI surface: TestFlagUsageParity builds a
// private FlagSet through this same function, so the usage-text comparison
// is hermetic (never polluted by the testing framework's own -test.* flags)
// and a new flag cannot ship without surfacing in usage() — and vice versa.
func registerFlags(fs *flag.FlagSet, opts *Options, risk *string, showVersion *bool) {
	fs.BoolVar(&opts.Exploit, "exploit", false, "Auto-exploit found vectors")
	fs.StringVar(risk, "risk", "safe", "Max risk: safe, low, medium, high, danger")
	fs.StringVar(&opts.Vector, "vector", "", "Comma-separated vectors: suid,sgid,sudo,cron,passwd,shadow,docker,container,caps,nfs,path,service,kernel,cred,preload,sudoers,group,hooks,polkit,winpriv,winreg,winservice,winauto,wintask,wincred,winpath")
	fs.BoolVar(&opts.JSON, "json", false, "JSON output")
	fs.BoolVar(&opts.Quiet, "quiet", false, "Quiet mode (exit code only)")
	fs.StringVar(&opts.Rooteame, "rooteame", "", "Path to rootkit.ko to load on root (lab only)")
	fs.BoolVar(&opts.Stealth, "stealth", false, "Add jitter between scanners and exploits")
	fs.BoolVar(&opts.OneShot, "one-shot", false, "Stop after first successful exploit")
	fs.StringVar(&opts.LHost, "lhost", "", "Listener host for reverse shells")
	fs.StringVar(&opts.LPort, "lport", "4444", "Listener port for reverse shells")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Scan and enumerate only, no exploitation")
	fs.StringVar(&opts.LogFormat, "log", "text", "Log format: text, json")
	fs.BoolVar(&opts.UpdateGTFO, "update-gtfobins", false, "Update and persist the GTFOBins database")
	fs.BoolVar(&opts.NoColor, "no-color", false, "Disable ANSI colors (auto-off when piped)")
	fs.BoolVar(&opts.ForceColor, "color", false, "Force ANSI colors even when piped (for captures and demos)")
	fs.BoolVar(&opts.Verbose, "verbose", false, "Verbose logging on stderr")
	fs.BoolVar(&opts.ListGTFO, "list-gtfo", false, "Print the embedded GTFOBins database and exit")
	fs.StringVar(&opts.Report, "report", "", "Write a markdown report to this path")
	fs.StringVar(&opts.Output, "output", "", "Write the JSON report to this file (0600)")
	fs.StringVar(&opts.Baseline, "baseline", "", "Diff findings against a previous --json/--output report")
	fs.StringVar(&opts.FailOn, "fail-on", "", "Exit 3 if any exploitable finding at/above this risk: low, medium, high, danger")
	// --fail-on-new is a bool-style flag with an OPTIONAL value: bare
	// --fail-on-new trips on any new exploitable finding,
	// --fail-on-new=high raises the bar to regressions at/above high.
	// Implemented as a custom flag.Value with IsBoolFlag() so both
	// spellings parse natively (Set("") for bare, Set(v) for =v).
	fs.Var(failOnNewFlag{opts}, "fail-on-new", "Exit 3 if NEW exploitable findings appear vs --baseline (requires it); optional threshold: --fail-on-new=low|medium|high|danger")
	fs.StringVar(&opts.HTML, "html", "", "Write a self-contained HTML report to this path (0600)")
	fs.BoolVar(&opts.ListVectors, "list-vectors", false, "Print the supported vector catalog and exit")
	fs.StringVar(&opts.Sarif, "sarif", "", "Write a SARIF 2.1.0 report for code-scanning dashboards (GitHub/GitLab)")
	fs.BoolVar(&opts.SarifStdout, "sarif-stdout", false, "Print the SARIF log to stdout (exclusive with --json)")
	fs.BoolVar(&opts.Parallel, "parallel", false, "Run scanners concurrently (results identical to sequential)")
	fs.StringVar(&opts.Explain, "explain", "", "Print the hardening playbook for a source (or all) and exit: e.g. cron")
	fs.StringVar(&opts.Ignore, "ignore", "", "Comma-separated finding sources to exclude entirely: e.g. CRED,CONTAINER")
	fs.DurationVar(&opts.ScanTimeout, "scan-timeout", 5*time.Second, "Timeout for external commands during scan (e.g. 10s, 2m)")
	fs.BoolVar(showVersion, "version", false, "Print version and exit")
	fs.StringVar(&opts.Completion, "completion", "", "Print a shell completion script and exit: bash, zsh or fish")
	fs.IntVar(&opts.MinScore, "min-score", 0, "Exit 3 when the hardening score lands below this floor (1-100); 0 disables the gate")
	fs.IntVar(&opts.TopN, "top", defaultTopVectors, "Show the top N vectors after a failed exploit run (1-50)")
	fs.BoolVar(&opts.ListSources, "list-sources", false, "Print the finding-source vocabulary (for --ignore/--explain) and exit")
	fs.StringVar(&opts.MinRisk, "min-risk", "", "Hide findings below this risk floor: low, medium, high, danger")
}

func run() *AutoPrivilege {
	var opts Options
	var risk string
	var showVersion bool
	var baseline *jsonReport

	registerFlags(flag.CommandLine, &opts, &risk, &showVersion)

	flag.Usage = usage
	flag.Parse()

	// Fail fast on a bad --vector before wasting a full scan.
	if opts.Vector != "" {
		if _, err := parseVectorList(opts.Vector); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] %v\n", err)
			os.Exit(2)
		}
	}

	// Fail fast on a bad --fail-on / unreadable --baseline too: both are
	// usage errors, and a CI gate must never scan for minutes before
	// discovering its configuration was wrong.
	if opts.FailOn != "" {
		lvl, enabled, err := parseFailOn(opts.FailOn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [-] %v\n", err)
			os.Exit(2)
		}
		opts.FailOnRisk = lvl
		opts.FailOnEnabled = enabled
	}
	if opts.Baseline != "" {
		b, err := loadBaseline(opts.Baseline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [-] baseline: %v\n", err)
			os.Exit(2)
		}
		baseline = b
	}
	if opts.FailOnNew && opts.Baseline == "" {
		fmt.Fprintln(os.Stderr, "  [-] --fail-on-new requires --baseline: the regression gate compares against a previous report")
		os.Exit(2)
	}
	if opts.Ignore != "" {
		names, err := parseIgnore(opts.Ignore)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [-] %v\n", err)
			os.Exit(2)
		}
		opts.IgnoreSources = names
	}
	// The risk floor validates fail-fast — same contract as --fail-on:
	// a typo must cost an exit 2, never a full scan that hides nothing.
	if opts.MinRisk != "" {
		lvl, err := parseMinRisk(opts.MinRisk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [-] %v\n", err)
			os.Exit(2)
		}
		opts.MinRiskLevel = lvl
	}
	if opts.SarifStdout && opts.JSON {
		fmt.Fprintln(os.Stderr, "  [-] --sarif-stdout and --json both write a document to stdout — pick one")
		os.Exit(2)
	}

	// Report output directories are created (0700) BEFORE the scan: a
	// missing parent is a two-second fix now, and a fatal surprise
	// after a full scan later. Fail-fast, same contract as the rest of
	// the flag validation.
	for _, out := range []struct{ flag, path string }{
		{"--output", opts.Output}, {"--report", opts.Report},
		{"--html", opts.HTML}, {"--sarif", opts.Sarif},
	} {
		if err := ensureOutputDir(out.path); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] %s: %v\n", out.flag, err)
			os.Exit(2)
		}
	}

	// Colors: --no-color wins, then --color, then the classic rule
	// (TTY && !NO_COLOR). Three-way precedence pinned by test.
	setColorMode(resolveColorMode(opts.ForceColor, opts.NoColor, isTerminal(os.Stdout), os.Getenv("NO_COLOR")))

	// Windows legacy consoles need ENABLE_VIRTUAL_TERMINAL_PROCESSING
	// before any ANSI sequence renders (no-op on every other platform).
	enableANSISupport()

	if showVersion {
		fmt.Printf("Auto-Privilege v%s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if opts.ListGTFO {
		printGTFOList()
		os.Exit(0)
	}

	// The vector catalog is a documentation mode like --list-gtfo:
	// print what --vector accepts (with what each vector actually
	// scans) and exit without scanning — same fail-fast contract.
	// --json switches the voice: same catalog, machine-readable.
	if opts.ListVectors {
		if opts.JSON {
			printVectorListJSON()
		} else {
			printVectorList()
		}
		os.Exit(0)
	}

	// The finding-source vocabulary is a documentation mode too: what
	// --ignore and --explain accept, discoverable without provoking a
	// validation error. --json emits the same list machine-readable.
	if opts.ListSources {
		if opts.JSON {
			printSourceListJSON()
		} else {
			printSourceList()
		}
		os.Exit(0)
	}

	// Shell completion is a documentation mode too: print the script
	// for the requested shell and exit. Unknown shells fail fast
	// (exit 2) — dumping bash syntax into a fish config helps nobody.
	if opts.Completion != "" {
		if err := printCompletion(opts.Completion); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	// The hardening playbook is a documentation mode: print and exit
	// without scanning — same fail-fast contract as --list-gtfo.
	// --json switches the voice: the same playbook, structured.
	if opts.Explain != "" {
		var err error
		if opts.JSON {
			err = printExplainJSON(opts.Explain)
		} else {
			err = printExplain(opts.Explain)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [-] %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	if !validMaxRisk(risk) {
		fmt.Fprintf(os.Stderr, "  [-] invalid --risk %q (valid: safe, low, medium, high, danger)\n", risk)
		os.Exit(2)
	}
	opts.MaxRisk = parseMaxRisk(risk)

	// The posture gate validates its floor up front — same fail-fast
	// contract as --fail-on: a CI gate must never scan for minutes
	// before discovering its configuration was wrong.
	if opts.MinScore < 0 || opts.MinScore > 100 {
		fmt.Fprintf(os.Stderr, "  [-] invalid --min-score %d (must be 0-100; 0 disables the gate)\n", opts.MinScore)
		os.Exit(2)
	}

	// --top bounds its window fail-fast — same contract as --min-score:
	// a typo must exit 2, never silently reshape the end-of-run summary.
	// (run() always sees the flag default or an explicit value, so a zero
	// here IS an explicit --top 0 — direct Options constructions never pass
	// through run() and fall back to the default via topVectorsN().)
	if opts.TopN < 1 || opts.TopN > 50 {
		fmt.Fprintf(os.Stderr, "  [-] invalid --top %d (must be 1-50)\n", opts.TopN)
		os.Exit(2)
	}

	if opts.ScanTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "  [-] invalid --scan-timeout %q (must be a positive duration, e.g. 10s)\n", opts.ScanTimeout)
		os.Exit(2)
	}

	if opts.Quiet {
		opts.Exploit = true
	}
	// Windows (v1.9): auto-exploitation is Linux-only. The honest contract:
	// --quiet keeps its "exit code only" meaning (scan-only here — exit 1
	// is defined as "exploit ran without root", and nothing ran), and an
	// explicit --exploit says so on stderr instead of pretending.
	if runtime.GOOS == "windows" && opts.Exploit {
		if !opts.Quiet {
			fmt.Fprintln(os.Stderr, "  [!] --exploit is Linux-only in this version — running the read-only Windows enumeration instead")
		}
		opts.Exploit = false
	}
	if opts.LHost == "" {
		opts.LHost = detectLocalIP()
	}

	p := &AutoPrivilege{Opts: opts, Baseline: baseline, Started: time.Now()}

	printBanner(opts)

	if !opts.Quiet && !opts.JSON {
		fmt.Printf("  %s %-10s  %s %-8d  %s %s\n\n",
			colorize("USER:", AnsiGrey), amIRoot(),
			colorize("PID:", AnsiGrey), os.Getpid(),
			colorize("Host:", AnsiGrey), hostname())
	}

	if opts.UpdateGTFO {
		if err := updateGTFOBins(opts); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] GTFOBins update failed: %v\n", err)
			os.Exit(1)
		}
		if !opts.Exploit && opts.Vector == "" {
			os.Exit(0)
		}
	}

	return p
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown"
	}
	return h
}

func detectLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
