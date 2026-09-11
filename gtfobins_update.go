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
	Cmd   string `json:"cmd"`
	Shell bool   `json:"shell"`
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
		if entry.Cmd == "" {
			continue
		}
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
}

func init() {
	loadPersistedGTFO()
}

type GTFOBinsUpdate struct {
	LastUpdate string `json:"last_update"`
	Entries    int    `json:"entries"`
	NewEntries int    `json:"new_entries"`
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

	newEntries := 0
	for name, entry := range bins {
		if _, exists := gtfoLookup[name]; exists {
			continue
		}
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		functions, ok := entryMap["functions"].([]interface{})
		if !ok {
			continue
		}

		for _, fn := range functions {
			fnMap, ok := fn.(map[string]interface{})
			if !ok {
				continue
			}
			fnName, _ := fnMap["function"].(string)
			if fnName == "shell" || fnName == "sudo" || fnName == "command" {
				codes, _ := fnMap["code"].([]interface{})
				if len(codes) > 0 {
					cmd, _ := codes[0].(string)
					cmd = cleanGTFOCmd(cmd, name)
					if cmd != "" {
						isShell := fnName == "shell"
						gtfoLookup[name] = cmd
						gtfoCategory[name] = map[bool]string{true: "suid-shell", false: "sudo"}[isShell]
						suidShellBins[name] = isShell
						stored[name] = storedEntry{Cmd: cmd, Shell: isShell}
						newEntries++
					}
				}
				break
			}
		}
	}

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
		LastUpdate: time.Now().Format(time.RFC3339),
		Entries:    len(gtfoLookup),
		NewEntries: newEntries,
	}

	if opts.LogFormat == "json" {
		infoData, _ := marshalJSON(updateInfo)
		fmt.Println(string(infoData))
	} else if !opts.Quiet {
		fmt.Printf(colorize("  [+] GTFOBins updated: %d new entries, %d total\n", AnsiGreen), newEntries, len(gtfoLookup))
		fmt.Printf(colorize("  [+] Database saved to: %s\n", AnsiGrey), saved)
	}

	return nil
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
