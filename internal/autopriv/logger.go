package autopriv

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

// log writes to stderr so stdout stays clean for --json / --report parsing.
// It is silent unless --verbose or --log json is active (and always shows
// errors). --quiet suppresses everything below ERROR: the documented contract
// is "no output; exit code only", and a WARN like the exploit-skip line used
// to leak through and break it. Errors stay visible on purpose — an exploit
// failing in a quiet run with zero explanation anywhere is hostile; the exit
// code alone cannot say why.
func log(level LogLevel, module, msg, detail string, opts Options) {
	verbose := opts.Verbose || opts.LogFormat == "json"
	if !verbose && level < LogWarn {
		return
	}
	if opts.Quiet && level < LogError {
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
		data, _ := marshalJSON(entry)
		if data == nil {
			data, _ = json.Marshal(entry)
		}
		fmt.Fprintln(os.Stderr, string(data))
		return
	}

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
	// One atomic write per log line: composing prefix + msg + detail
	// + newline into a single Write keeps piped stderr from interleaving
	// with stdout mid-line (observed as "[WARN] ain] ..." under 2>&1).
	line := prefix + " " + msg
	if detail != "" {
		line += " (" + detail + ")"
	}
	fmt.Fprint(os.Stderr, line+"\n")
}

func logScanStart(opts Options) { log(LogInfo, "scanner", "Starting system scan...", "", opts) }

// logScanDone reports one scanner's wall-clock duration at DEBUG level:
// visible only with --verbose (or --log json), silent everywhere else. In
// --parallel mode the lines interleave by completion order — that IS the
// information (which scanner finished when), the merged findings stay
// ordered by scannerOrder regardless.
func logScanDone(name string, d time.Duration, opts Options) {
	log(LogDebug, "scanner", fmt.Sprintf("Scanner %s finished in %s", name, d.Round(100*time.Microsecond)), "", opts)
}
func logEnumStart(opts Options)    { log(LogInfo, "enum", "Enumerating exploit vectors...", "", opts) }
func logExploitStart(opts Options) { log(LogInfo, "exploit", "Starting exploitation...", "", opts) }
func logExploitSkip(name string, opts Options) {
	log(LogWarn, "exploit", fmt.Sprintf("Skipped %s (risk exceeds max)", name), "", opts)
}
func logExploitTry(name string, opts Options) {
	log(LogInfo, "exploit", fmt.Sprintf("Attempting %s...", name), "", opts)
}
func logExploitSuccess(name string, opts Options) {
	log(LogInfo, "exploit", fmt.Sprintf("Exploit succeeded: %s", name), "", opts)
}
func logExploitFail(name string, err string, opts Options) {
	log(LogError, "exploit", fmt.Sprintf("Exploit failed: %s", name), err, opts)
}
func logRootObtained(vector string, opts Options) {
	log(LogInfo, "exploit", "ROOT OBTAINED", vector, opts)
}
func logDryRun(opts Options) { log(LogWarn, "main", "Dry-run mode — exploitation skipped", "", opts) }
