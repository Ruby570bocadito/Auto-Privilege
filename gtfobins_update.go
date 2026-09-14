package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const gtfobinsURL = "https://gtfobins.github.io/gtfobins.json"

// storedEntry is the on-disk shape of one GTFOBins technique.
type storedEntry struct {
	Cmd     string `json:"cmd"`
	Shell   bool   `json:"shell"`
	SgidCmd string `json:"sgid_cmd,omitempty"`
}

// dbPath returns where the refreshed database is persisted:
// $AUTOPRIV_DB_DIR/gtfobins.json or ~/.autoprivilege/gtfobins.json.
func dbPath() (string, bool) {
	dir := os.Getenv("AUTOPRIV_DB_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", false
		}
		dir = filepath.Join(home, ".autoprivilege")
	}
	return filepath.Join(dir, "gtfobins.json"), true
}

// loadPersistedGTFO merges a previously refreshed database (if any) over the
// embedded one. Runs before main via init.
func loadPersistedGTFO() {
	path, ok := dbPath()
	if !ok {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var stored map[string]storedEntry
	if json.Unmarshal(data, &stored) != nil {
		return
	}
	for name, entry := range stored {
		if entry.Cmd == "" && entry.SgidCmd == "" {
			continue
		}
		if entry.Cmd != "" {
			gtfoLookup[name] = entry.Cmd
			if entry.Shell {
				suidShellBins[name] = true
			}
			if _, known := gtfoCategory[name]; !known {
				if entry.Shell {
					gtfoCategory[name] = "suid-shell"
				} else {
					gtfoCategory[name] = "sudo"
				}
			}
		}
		if entry.SgidCmd != "" {
			sgidLookup[name] = entry.SgidCmd
		}
	}
}

func init() {
	loadPersistedGTFO()
}

// gtfocapture is what one upstream entry yields: the main technique (first
// of shell/sudo/command with usable code — the historical priority) and the
// sgid technique (first sgid entry with usable code), which used to be
// dropped entirely (R25).
type gtfocapture struct {
	MainCmd     string
	MainIsShell bool
	SgidCmd     string
}

// captureGTFOFunctions extracts the techniques of one upstream entry. Pure
// (name + functions in, struct out): testable without network and without
// touching the package-level lookups.
func captureGTFOFunctions(name string, functions []interface{}) gtfocapture {
	var captured gtfocapture
	for _, fn := range functions {
		fnMap, ok := fn.(map[string]interface{})
		if !ok {
			continue
		}
		fnName, _ := fnMap["function"].(string)
		codes, _ := fnMap["code"].([]interface{})
		if len(codes) == 0 {
			continue
		}
		raw, _ := codes[0].(string)
		if fnName == "shell" || fnName == "sudo" || fnName == "command" {
			if captured.MainCmd != "" {
				continue // first match keeps the priority
			}
			if cmd := cleanGTFOCmd(raw, name); cmd != "" {
				captured.MainCmd = cmd
				captured.MainIsShell = fnName == "shell"
			}
			continue
		}
		if fnName == "sgid" && captured.SgidCmd == "" {
			captured.SgidCmd = cleanGTFOCmd(raw, name)
		}
	}
	return captured
}

// updateGTFOBins fetches the upstream GTFOBins JSON, merges unknown binaries
// into the in-memory lookup and PERSISTS the result — the old code only
// mutated memory and wrote a metadata stub, so the "update" evaporated on exit.
func updateGTFOBins(opts Options) error {
	if !opts.Quiet && opts.LogFormat != "json" {
		fmt.Println(colorize("  [*] Fetching GTFOBins database from upstream...", AnsiCyan))
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(gtfobinsURL)
	if err != nil {
		return fmt.Errorf("failed to fetch GTFOBins: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GTFOBins returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var bins map[string]interface{}
	if err := json.Unmarshal(data, &bins); err != nil {
		return fmt.Errorf("failed to parse GTFOBins JSON: %w", err)
	}

	stored := map[string]storedEntry{}
	if path, ok := dbPath(); ok {
		if raw, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(raw, &stored)
		}
	}

	newMain, newSgid := 0, 0
	for name, entry := range bins {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		functions, ok := entryMap["functions"].([]interface{})
		if !ok {
			continue
		}

		captured := captureGTFOFunctions(name, functions)
		se := stored[name]

		if captured.MainCmd != "" {
			if _, exists := gtfoLookup[name]; !exists {
				gtfoLookup[name] = captured.MainCmd
				gtfoCategory[name] = map[bool]string{true: "suid-shell", false: "sudo"}[captured.MainIsShell]
				suidShellBins[name] = captured.MainIsShell
				newMain++
			}
			if se.Cmd == "" {
				se.Cmd = captured.MainCmd
				se.Shell = captured.MainIsShell
			}
		}
		if captured.SgidCmd != "" {
			if _, exists := sgidLookup[name]; !exists {
				sgidLookup[name] = captured.SgidCmd
				newSgid++
			}
			if se.SgidCmd == "" {
				se.SgidCmd = captured.SgidCmd
			}
		}
		if se != (storedEntry{}) {
			stored[name] = se
		}
	}

	// R31: main and sgid techniques are counted separately — new_entries
	// keeps its original (main-only) semantics and new_sgid_entries adds
	// the sgid slice, so an operator can tell what each refresh brought.

	// Persist so future runs load the refreshed database.
	saved := "not persisted (no home dir)"
	if path, ok := dbPath(); ok {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err == nil {
			data, err := marshalJSON(stored)
			if err == nil && os.WriteFile(path, data, 0600) == nil {
				saved = path
			}
		}
	}

	updateInfo := GTFOBinsUpdate{
		LastUpdate:     time.Now().Format(time.RFC3339),
		Entries:        len(gtfoLookup),
		NewEntries:     newMain,
		NewSgidEntries: newSgid,
		EntriesSgid:    len(sgidLookup),
	}

	if opts.LogFormat == "json" {
		infoData, _ := marshalJSON(updateInfo)
		fmt.Println(string(infoData))
	} else if !opts.Quiet {
		fmt.Printf(colorize("  [+] GTFOBins updated: %d new entries (+%d sgid), %d total\n", AnsiGreen), newMain, newSgid, len(gtfoLookup))
		fmt.Printf(colorize("  [+] Database saved to: %s\n", AnsiGrey), saved)
	}

	return nil
}

type GTFOBinsUpdate struct {
	LastUpdate     string `json:"last_update"`
	Entries        int    `json:"entries"`
	NewEntries     int    `json:"new_entries"`
	NewSgidEntries int    `json:"new_sgid_entries"`
	EntriesSgid    int    `json:"entries_sgid"`
}

func cleanGTFOCmd(cmd, bin string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	cmd = strings.ReplaceAll(cmd, "{{BIN}}", bin)
	cmd = strings.ReplaceAll(cmd, "{{CMD}}", "/bin/sh")
	cmd = strings.ReplaceAll(cmd, "{{FILE}}", "/etc/passwd")
	return cmd
}
