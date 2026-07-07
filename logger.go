package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

func (l LogLevel) String() string {
	switch l {
	case LogDebug:
		return "DEBUG"
	case LogInfo:
		return "INFO"
	case LogWarn:
		return "WARN"
	case LogError:
		return "ERROR"
	}
	return "UNKNOWN"
}

type LogEntry struct {
	Time    string `json:"timestamp"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Module  string `json:"module,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

func log(level LogLevel, module, msg, detail string, opts Options) {
	if opts.Quiet && level < LogWarn {
		return
	}

	entry := LogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Level:   level.String(),
		Message: msg,
		Module:  module,
		Detail:  detail,
	}

	if opts.LogFormat == "json" {
		data, _ := json.Marshal(entry)
		fmt.Fprintln(os.Stderr, string(data))
	} else {
		color := ""
		switch level {
		case LogInfo:
			color = AnsiCyan
		case LogWarn:
			color = AnsiYellow
		case LogError:
			color = AnsiRed
		case LogDebug:
			color = AnsiGrey
		}
		prefix := fmt.Sprintf("  [%s] [%s]", entry.Level, entry.Module)
		if color != "" {
			prefix = colorize(prefix, color)
		}
		fmt.Fprintf(os.Stderr, "%s %s", prefix, msg)
		if detail != "" {
			fmt.Fprintf(os.Stderr, " (%s)", detail)
		}
		fmt.Fprintln(os.Stderr)
	}
}

func logScanStart(opts Options)             { log(LogInfo, "scanner", "Starting system scan...", "", opts) }
func logScanSUID(count int, opts Options)   { log(LogInfo, "scanner", fmt.Sprintf("Found %d SUID binaries", count), "", opts) }
func logScanSudo(count int, opts Options)   { log(LogInfo, "scanner", fmt.Sprintf("Found %d sudo vectors", count), "", opts) }
func logScanCron(count int, opts Options)   { log(LogInfo, "scanner", fmt.Sprintf("Found %d writable cron jobs", count), "", opts) }
func logScanKernel(kernel string, opts Options) { log(LogInfo, "scanner", "Kernel version detected", kernel, opts) }
func logScanCreds(count int, opts Options)  { log(LogInfo, "scanner", fmt.Sprintf("Found %d credential vectors", count), "", opts) }
func logEnumStart(opts Options)             { log(LogInfo, "enum", "Enumerating exploit vectors...", "", opts) }
func logExploitStart(opts Options)          { log(LogInfo, "exploit", "Starting exploitation...", "", opts) }
func logExploitSkip(name string, opts Options) { log(LogWarn, "exploit", fmt.Sprintf("Skipped %s (risk exceeds max)", name), "", opts) }
func logExploitTry(name string, opts Options)  { log(LogInfo, "exploit", fmt.Sprintf("Attempting %s...", name), "", opts) }
func logExploitSuccess(name string, opts Options) { log(LogInfo, "exploit", fmt.Sprintf("Exploit succeeded: %s", name), "", opts) }
func logExploitFail(name string, err string, opts Options) { log(LogError, "exploit", fmt.Sprintf("Exploit failed: %s", name), err, opts) }
func logRootObtained(vector string, opts Options) { log(LogInfo, "exploit", "ROOT OBTAINED", vector, opts) }
func logDryRun(opts Options)                { log(LogWarn, "main", "Dry-run mode — exploitation skipped", "", opts) }
