package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const Version = "1.5.0"

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
var colorsEnabled = true

func setColorMode(enabled bool) { colorsEnabled = enabled }

// isTerminal reports whether f is a real terminal (TTY). A plain char-device
// check is not enough — /dev/null also matches — so we ask the kernel with
// TCGETS, which only succeeds on actual ttys.
func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&termios)),
		0, 0, 0,
	)
	return errno == 0
}

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

func isRoot() bool {
	return os.Geteuid() == 0
}

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
