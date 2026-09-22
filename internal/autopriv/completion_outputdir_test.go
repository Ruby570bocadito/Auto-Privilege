package autopriv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ================================================================
// Completion value lists, fail-fast output directories
// ================================================================

// TestCompletionValuesFromBinaryTables pins the value lists to the binary's
// own tables — the completion must never drift from what run() validates.
func TestCompletionValuesFromBinaryTables(t *testing.T) {
	vec, ok := completionValues["vector"]
	if !ok {
		t.Fatal("vector values missing")
	}
	if len(vec) != len(vectorCatalogOrder)+1 || vec[len(vec)-1] != "all" {
		t.Errorf("vector values = %v, want catalog + all", vec)
	}
	src, ok := completionValues["explain"]
	if !ok || len(src) != len(validSources)+1 || src[0] != "all" {
		t.Errorf("explain values = %v, want all + validSources", src)
	}
	for _, name := range []string{"risk", "fail-on", "fail-on-new", "log", "completion"} {
		if _, ok := completionValues[name]; !ok {
			t.Errorf("value list for --%s missing", name)
		}
	}
}

// TestCompletionValuesReachScripts: the value lists surface in each shell
// dialect with its own syntax — bash case branches, zsh :name:(values),
// fish -a 'values'.
func TestCompletionValuesReachScripts(t *testing.T) {
	bash, err := completionScriptFor("bash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bash, "--risk) COMPREPLY=( $(compgen -W \"safe low medium high danger\"") {
		t.Errorf("bash: --risk value completion missing")
	}
	if !strings.Contains(bash, "case \"$prev\" in") {
		t.Errorf("bash: value-completion case block missing")
	}
	zsh, err := completionScriptFor("zsh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(zsh, ":risk:(safe low medium high danger)") {
		t.Errorf("zsh: --risk value completion missing")
	}
	fish, err := completionScriptFor("fish")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fish, "-l risk -x -a 'safe low medium high danger'") {
		t.Errorf("fish: --risk value completion missing")
	}
	// a vector name must reach every script (they come from the catalog)
	for _, script := range []string{bash, zsh, fish} {
		if !strings.Contains(script, "sudoers") {
			t.Errorf("vector value 'sudoers' missing from a completion script")
		}
	}
}

// TestCompletionDeterministic: the same shell renders byte-identical scripts
// across calls — map iteration must never leak into the output.
func TestCompletionDeterministic(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		a, err := completionScriptFor(shell)
		if err != nil {
			t.Fatal(err)
		}
		b, err := completionScriptFor(shell)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Errorf("completion %s is not deterministic (map iteration leaked)", shell)
		}
	}
}

// TestEnsureOutputDir: creates nested parents with 0700, accepts existing
// directories, refuses a non-directory file in the way, and ignores paths
// without a directory component.
func TestEnsureOutputDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "report.html")
	if err := ensureOutputDir(nested); err != nil {
		t.Fatalf("ensureOutputDir(nested): %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "a", "b"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("nested dir not created: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0700 {
		t.Errorf("created dir perms = %v, want 0700", got)
	}
	// existing dir is fine
	if err := ensureOutputDir(filepath.Join(dir, "a", "b", "x.json")); err != nil {
		t.Errorf("existing dir rejected: %v", err)
	}
	// a file in the way is an error, not a silent overwrite
	fileInTheWay := filepath.Join(dir, "blocker")
	if err := os.WriteFile(fileInTheWay, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureOutputDir(filepath.Join(fileInTheWay, "report.html")); err == nil {
		t.Error("file in the way must be an error")
	}
	// bare filename (no dir component) and empty path are no-ops
	if err := ensureOutputDir("report.html"); err != nil {
		t.Errorf("bare filename rejected: %v", err)
	}
	if err := ensureOutputDir(""); err != nil {
		t.Errorf("empty path rejected: %v", err)
	}
}
