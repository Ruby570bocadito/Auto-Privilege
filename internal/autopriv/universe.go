package autopriv

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"
)

const Version = "2.0.0"

type RiskLevel int

const (
	RiskSafe RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskDanger
)

func (r RiskLevel) String() string {
	switch r {
	case RiskSafe:
		return "SAFE"
	case RiskLow:
		return "LOW"
	case RiskMedium:
		return "MEDIUM"
	case RiskHigh:
		return "HIGH"
	case RiskDanger:
		return "DANGER"
	}
	return "???"
}

func (r RiskLevel) Color() string {
	switch r {
	case RiskSafe:
		return AnsiGreen
	case RiskLow:
		return AnsiBlue
	case RiskMedium:
		return AnsiYellow
	case RiskHigh:
		return AnsiOrange
	case RiskDanger:
		return AnsiRed
	}
	return ""
}

type Finding struct {
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
	Risk        RiskLevel `json:"risk"`
	Exploitable bool      `json:"exploitable"`
}

type Vector struct {
	Name     string                `json:"name"`
	Risk     RiskLevel             `json:"risk"`
	Target   string                `json:"target"`
	Command  string                `json:"command"`
	Category string                `json:"category"`
	Exploit  func() *ExploitResult `json:"-"`
	Meta     map[string]string     `json:"meta,omitempty"`
}

type ExploitResult struct {
	Success bool   `json:"success"`
	Vector  string `json:"vector"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
	IsRoot  bool   `json:"is_root"`
}

type Options struct {
	Exploit     bool
	MaxRisk     RiskLevel
	Vector      string
	JSON        bool
	Quiet       bool
	Rooteame    string
	Stealth     bool
	OneShot     bool
	LHost       string
	LPort       string
	DryRun      bool
	LogFormat   string
	UpdateGTFO  bool
	NoColor     bool
	Verbose     bool
	ListGTFO    bool
	Report      string
	Output      string
	ScanTimeout time.Duration
	Baseline    string
	FailOn      string
	// FailOnRisk/FailOnEnabled are filled by run() from FailOn; tests and
	// library use may set them directly.
	FailOnRisk    RiskLevel
	FailOnEnabled bool
	// FailOnNew enables the regression gate: exit 3 when the baseline diff
	// shows new exploitable findings. Requires --baseline (enforced
	// fail-fast in run()). FailOnNewRisk is the optional threshold set via
	// --fail-on-new=<risk>: bare --fail-on-new leaves it at RiskSafe (any
	// exploitable regression trips), --fail-on-new=high trips only for new
	// exploitable findings at/above high.
	FailOnNew     bool
	FailOnNewRisk RiskLevel
	// Sarif is the --sarif output path (empty = no SARIF export).
	Sarif string
	// SarifStdout prints the SARIF log to stdout instead of a file
	// (mutually exclusive with --json, enforced fail-fast in run()).
	SarifStdout bool
	// Parallel runs the scanners concurrently; the merged findings keep
	// the exact scannerOrder sequence, so results are byte-identical to a
	// sequential run (tested). Stealth forces sequential regardless.
	Parallel bool
	// Explain prints the hardening playbook (a source name or "all") and
	// exits — no scan is performed.
	Explain string
	// Ignore holds the raw --ignore value; IgnoreSources its parsed form
	// (filled by run(), fail-fast on unknown names).
	Ignore        string
	IgnoreSources []string
	// HTML is the --html output path (empty = no HTML export).
	HTML string
	// ListVectors prints the supported vector catalog and exits — a
	// documentation mode like --list-gtfo, so scripts can discover what
	// --vector accepts without parsing the usage text.
	ListVectors bool
	// MinScore is the --min-score posture gate: when > 0, exit 3 if the
	// hardening score lands below it. 0 (the default) disables the gate —
	// a gate configured to "0" means "no floor", which can never trip
	// because the score is clamped at 0, so the zero value is both the
	// disabled state and a harmless no-op.
	MinScore int
	// Completion is the --completion shell name (bash, zsh or fish): print
	// a completion script covering every registered flag and exit — a
	// documentation mode like --list-vectors.
	Completion string
	// ListSources prints the finding-source vocabulary (what --ignore and
	// --explain accept) and exits — a documentation mode like
	// --list-vectors. JSON emits the same list machine-readable.
	ListSources bool
	// MinRisk holds the raw --min-risk value; MinRiskLevel its parsed form
	// (filled by run(), fail-fast on invalid values; empty string leaves
	// MinRiskLevel at RiskSafe = the floor is disabled). Findings below
	// the floor are dropped ONCE right after the scan — the same filtered
	// reality contract --ignore established.
	MinRisk      string
	MinRiskLevel RiskLevel
	// TopN is the --top value: how many "Top vectors" to print after a
	// failed exploit run (the historical default is 5). The flag validates
	// 1-50 fail-fast; direct constructions with a non-positive value fall
	// back to the default through topVectorsN().
	TopN int
	// ForceColor (--color) keeps ANSI colors on even when stdout is not a
	// terminal — the capture/demo escape hatch: pipes into ansi2html,
	// silicon or a recorder keep the exact terminal look. --no-color wins
	// over --color when both are given; NO_COLOR is respected only when
	// neither flag is present.
	ForceColor bool
}

// defaultTopVectors is the historical size of the end-of-run "Top vectors"
// list — kept as a named constant so the test can pin the default.
const defaultTopVectors = 5

// topVectorsN resolves the effective --top value: the flag when sane, the
// historical default otherwise (direct constructions, tests, library use).
func (o Options) topVectorsN() int {
	if o.TopN >= 1 && o.TopN <= 50 {
		return o.TopN
	}
	return defaultTopVectors
}

// scanCmdTimeout returns the timeout applied to external commands run by the
// scanners (sudo -l, uname, groups, crontab -l, …). It defaults to 5s when
// Options was built without going through flag parsing (tests, library use),
// so a zero value can never disable the timeout guard entirely.
func (o Options) scanCmdTimeout() time.Duration {
	if o.ScanTimeout > 0 {
		return o.ScanTimeout
	}
	return 5 * time.Second
}

type AutoPrivilege struct {
	Opts        Options
	Findings    []Finding
	Vectors     []Vector
	Rooted      bool
	LastSuccess bool
	Started     time.Time
	// Baseline holds the parsed previous report when --baseline was given;
	// Diff is its computed comparison (nil without --baseline).
	Baseline *jsonReport
	Diff     *ReportDiff
}

// ================================================================
// ANSI colors
// ================================================================
const (
	AnsiReset  = "\033[0m"
	AnsiRed    = "\033[31m"
	AnsiGreen  = "\033[32m"
	AnsiYellow = "\033[33m"
	AnsiBlue   = "\033[34m"
	AnsiOrange = "\033[38;5;208m"
	AnsiBold   = "\033[1m"
	AnsiCyan   = "\033[36m"
	AnsiGrey   = "\033[90m"
)

// colorsEnabled is toggled once at startup: colors auto-disable when stdout
// is not a terminal, when --no-color is passed, or when NO_COLOR is set.
// --color forces them back on for captures and demos.
var colorsEnabled = true

func setColorMode(enabled bool) { colorsEnabled = enabled }

// resolveColorMode distills the color decision into a pure function:
// --no-color wins over --color, --color beats the TTY check and NO_COLOR,
// and with neither flag the classic rule applies (TTY and no NO_COLOR).
func resolveColorMode(force, noColor, tty bool, noColorEnv string) bool {
	if noColor {
		return false
	}
	if force {
		return true
	}
	return tty && noColorEnv == ""
}

// isTerminal moved to the platform layer: TCGETS is a Linux ioctl,
// GetConsoleMode the Windows answer, and a char-device heuristic the
// fallback for the remaining Unixes.

func colorize(text, color string) string {
	if text == "" {
		return ""
	}
	if !colorsEnabled {
		return text
	}
	return color + text + AnsiReset
}

func (p *AutoPrivilege) Print(finding Finding) {
	// --quiet means NO output (the contract behind "exit code only"): the old
	// partial check let exploitable findings leak to the terminal.
	if p.Opts.JSON || p.Opts.Quiet {
		return
	}

	tag := "[+]"
	color := AnsiGreen
	switch finding.Risk {
	case RiskHigh:
		tag = "[!]"
		color = AnsiOrange
	case RiskDanger:
		tag = "[*]"
		color = AnsiRed
	case RiskMedium:
		tag = "[~]"
		color = AnsiYellow
	case RiskLow:
		tag = "[.]"
		color = AnsiBlue
	}

	fmt.Printf("  %s %s → %s",
		colorize(tag, color),
		colorize(finding.Source, AnsiBold),
		finding.Description)
	if finding.Target != "" {
		fmt.Printf(" (%s)", finding.Target)
	}
	fmt.Println()
}

func (p *AutoPrivilege) PrintVector(v Vector) {
	if p.Opts.JSON {
		return
	}
	fmt.Printf("  %s %-14s %s %s\n",
		colorize("[>]", v.Risk.Color()),
		colorize("["+v.Category+"]", AnsiGrey),
		colorize(v.Name, AnsiBold),
		colorize(v.Target, AnsiGrey))
}

func (p *AutoPrivilege) PrintExploit(r *ExploitResult) {
	if p.Opts.JSON {
		return
	}
	if r.Success && r.IsRoot {
		fmt.Printf("\n  %s\n\n", colorize("[!] ROOT OBTAINED", AnsiRed+AnsiBold))
		fmt.Printf("  %s %s\n", colorize("Vector:", AnsiBold), r.Vector)
		if r.Output != "" {
			fmt.Printf("  %s %s\n", colorize("Output:", AnsiBold), r.Output)
		}
	} else if r.Success {
		fmt.Printf("  %s %s → executed\n", colorize("[+]", AnsiGreen), r.Vector)
	} else if r.Error != "" {
		fmt.Printf("  %s %s → %s\n", colorize("[-]", AnsiRed), r.Vector, r.Error)
	}
}

// ExportJSON prints the machine-readable report. Moved to report.go.
//
// isRoot, isTerminal and every other syscall-shaped question live in the
// platform layer (platform_linux.go / platform_windows.go /
// platform_other.go) — this file stays pure Go.

// currentUsername resolves the real username (env vars lie under su/sudo).
func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("LOGNAME")
}

func amIRoot() string {
	if isRoot() {
		return colorize("ROOT", AnsiRed+AnsiBold)
	}
	return colorize(currentUsername(), AnsiGreen)
}

func parseMaxRisk(s string) RiskLevel {
	switch strings.ToLower(s) {
	case "safe":
		return RiskSafe
	case "low":
		return RiskLow
	case "medium":
		return RiskMedium
	case "high":
		return RiskHigh
	case "danger", "all":
		return RiskDanger
	default:
		return RiskSafe
	}
}

// validMaxRisks is used by flag validation to reject typos early.
func validMaxRisk(s string) bool {
	switch strings.ToLower(s) {
	case "safe", "low", "medium", "high", "danger", "all":
		return true
	}
	return false
}

// marshalJSON is a small helper that never ignores marshal errors silently.
func marshalJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
