package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type GTFOBinsUpdate struct {
	LastUpdate string `json:"last_update"`
	Entries    int    `json:"entries"`
}

func updateGTFOBins(opts Options) error {
	if !opts.Quiet && opts.LogFormat != "json" {
		fmt.Println(colorize("  [*] Fetching GTFOBins database from upstream...", AnsiCyan))
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://gtfobins.github.io/gtfobins.json")
	if err != nil {
		return fmt.Errorf("failed to fetch GTFOBins: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GTFOBins returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var bins map[string]interface{}
	if err := json.Unmarshal(data, &bins); err != nil {
		return fmt.Errorf("failed to parse GTFOBins JSON: %w", err)
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
			if fnName == "shell" || fnName == "command" || fnName == "sudo" {
				codes, _ := fnMap["code"].([]interface{})
				if len(codes) > 0 {
					cmd, _ := codes[0].(string)
					cmd = cleanGTFOCmd(cmd, name)
					if cmd != "" {
						gtfoLookup[name] = cmd
						suidShellBins[name] = (fnName == "shell")
						newEntries++
					}
				}
				break
			}
		}
	}

	updateInfo := GTFOBinsUpdate{
		LastUpdate: time.Now().Format(time.RFC3339),
		Entries:    len(gtfoLookup),
	}

	infoData, _ := json.MarshalIndent(updateInfo, "", "  ")
	os.WriteFile("gtfobins_update.json", infoData, 0644)

	if !opts.Quiet && opts.LogFormat != "json" {
		fmt.Printf(colorize("  [+] GTFOBins updated: %d new entries, %d total\n", AnsiGreen), newEntries, len(gtfoLookup))
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
	if strings.Contains(cmd, "sudo") && !strings.HasPrefix(cmd, "sudo") {
		return cmd
	}
	return cmd
}
