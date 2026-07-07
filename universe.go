package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

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
	Source      string   `json:"source"`
	Target      string   `json:"target"`
	Description string   `json:"description"`
	Risk        RiskLevel `json:"risk"`
	Exploitable bool     `json:"exploitable"`
}

type Vector struct {
	Name     string                 `json:"name"`
	Risk     RiskLevel              `json:"risk"`
	Target   string                 `json:"target"`
	Command  string                 `json:"command"`
	Category string                 `json:"category"`
	Exploit  func() *ExploitResult `json:"-"`
	Meta     map[string]string     `json:"meta,omitempty"`
}

type ExploitResult struct {
	Success   bool   `json:"success"`
	Vector    string `json:"vector"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	IsRoot    bool   `json:"is_root"`
}

type Options struct {
	Exploit      bool
	MaxRisk      RiskLevel
	Vector       string
	JSON         bool
	Quiet        bool
	Rooteame     string
	Stealth      bool
	OneShot      bool
	LHost        string
	LPort        string
	DryRun       bool
	LogFormat    string
	UpdateGTFO   bool
}

type AutoPrivilege struct {
	Opts     Options
	Findings []Finding
	Vectors  []Vector
	Rooted   bool
}

// ================================================================
// Ansi colors
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

func colorize(text, color string) string {
	if text == "" {
		return ""
	}
	return color + text + AnsiReset
}

func printBanner() {
	fmt.Print(colorize(`
 ╔══════════════════════════════════════════╗
 ║     autoprivilege — Linux PrivEsc AutoPwn    ║
 ║     ruby570bocadito (c) 2026            ║
 ╚══════════════════════════════════════════╝
`+"\n", AnsiCyan))
}

func (p *AutoPrivilege) Print(finding Finding) {
	if p.Opts.JSON {
		return
	}
	if p.Opts.Quiet && !finding.Exploitable {
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

func (p *AutoPrivilege) ExportJSON() error {
	type Report struct {
		Findings []Finding `json:"findings"`
		Vectors  []Vector  `json:"vectors"`
		Rooted   bool      `json:"rooted"`
	}
	r := Report{
		Findings: p.Findings,
		Vectors:  p.Vectors,
		Rooted:   p.Rooted,
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
	return nil
}

func isRoot() bool {
	return os.Geteuid() == 0
}

func amIRoot() string {
	if isRoot() {
		return colorize("ROOT", AnsiRed+AnsiBold)
	}
	return colorize(os.Getenv("USER"), AnsiGreen)
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
