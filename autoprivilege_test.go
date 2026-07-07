package main

import (
	"strings"
	"testing"
)

func TestGTFOBinsLookup(t *testing.T) {
	tests := []struct {
		bin     string
		hasCmd  bool
		isShell bool
	}{
		{"python3", true, true},
		{"perl", true, true},
		{"find", true, false},
		{"vim", true, false},
		{"awk", true, false},
		{"nonexistent", false, false},
		{"nmap", true, false},
		{"tar", true, false},
		{"docker", true, false},
		{"bash", true, true},
		{"zsh", true, true},
	}

	for _, tt := range tests {
		cmd, ok := getCommand(tt.bin)
		if ok != tt.hasCmd {
			t.Errorf("%s: hasCmd=%v, want %v", tt.bin, ok, tt.hasCmd)
		}
		if ok && cmd == "" {
			t.Errorf("%s: has cmd but it's empty", tt.bin)
		}
		shell := isSuidShellBin(tt.bin)
		if shell != tt.isShell {
			t.Errorf("%s: isShell=%v, want %v", tt.bin, shell, tt.isShell)
		}
	}
}

func TestRiskLevels(t *testing.T) {
	if RiskSafe.String() != "SAFE" {
		t.Errorf("safe=%s", RiskSafe.String())
	}
	if RiskDanger.String() != "DANGER" {
		t.Errorf("danger=%s", RiskDanger.String())
	}
	if parseMaxRisk("safe") != RiskSafe {
		t.Error("parse safe")
	}
	if parseMaxRisk("all") != RiskDanger {
		t.Error("parse all")
	}
}

func TestExtractBinName(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/python3":    "python3",
		"/usr/local/bin/find": "find",
		"/bin/bash":           "bash",
		"socat":               "socat",
	}
	for path, want := range cases {
		got := extractBinName(path)
		if got != want {
			t.Errorf("extractBinName(%s)=%s, want %s", path, got, want)
		}
	}
}

func TestColorOutput(t *testing.T) {
	// Ensure colorize doesn't panic
	s := colorize("test", AnsiRed)
	if !strings.HasPrefix(s, AnsiRed) {
		t.Error("colorize missing prefix")
	}
	if !strings.HasSuffix(s, AnsiReset) {
		t.Error("colorize missing reset")
	}
	// Empty string
	if colorize("", AnsiRed) != "" {
		t.Error("colorize empty should be empty")
	}
}

func TestFindingPrint(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	f := Finding{Source: "SUID", Target: "/usr/bin/python3",
		Description: "test", Risk: RiskHigh, Exploitable: true}
	// Should not panic
	p.Print(f)
}

func TestVectorPrint(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	v := Vector{Name: "test", Category: "suid", Target: "/bin/sh",
		Risk: RiskHigh}
	p.PrintVector(v)
}

func TestResultPrint(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	r := &ExploitResult{Success: true, IsRoot: true, Vector: "test"}
	p.PrintExploit(r)
	r2 := &ExploitResult{Success: false, Error: "failed"}
	p.PrintExploit(r2)
}

func TestAmIRoot(t *testing.T) {
	s := amIRoot()
	if s == "" {
		t.Error("amIRoot returned empty")
	}
}

func TestJSONExport(t *testing.T) {
	p := &AutoPrivilege{
		Opts: Options{JSON: false},
		Findings: []Finding{{Source: "test", Description: "test"}},
	}
	// Should not panic
	p.ExportJSON()
}
